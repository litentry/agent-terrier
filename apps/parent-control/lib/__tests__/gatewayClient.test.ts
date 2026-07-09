import { afterEach, describe, expect, it, vi } from 'vitest';
import { gatewayClient, gatewayNotConfigured, isTerminalLoginStatus } from '../gatewayClient';

// The gateway client is a thin typed forwarder to the daemon proxy; the tests
// pin (a) the daemon paths + methods, (b) the error-envelope decoding the UI
// relies on, and (c) the terminal-status set the connect poll loop stops on.

function mockFetch(status: number, body: unknown, capture?: (url: string, init?: RequestInit) => void) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    capture?.(url, init);
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    } as Response;
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('gatewayClient', () => {
  it('GET status hits the daemon proxy path and unwraps the typed body', async () => {
    let seenUrl = '';
    let seenMethod = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, transport: 'ilink', online: true, bot_id: 'x@im.bot', bound_contacts: 2, open_invites: 0, pending_binds: 1 }, (u, i) => {
        seenUrl = u;
        seenMethod = i?.method ?? 'GET';
      }),
    );
    const r = await gatewayClient.status();
    expect(seenUrl).toMatch(/\/v1\/master\/gateway\/status$/);
    expect(seenMethod).toBe('GET');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.online).toBe(true);
      expect(r.value.bound_contacts).toBe(2);
    }
  });

  it('POST bind/invite sends the request body as JSON', async () => {
    let seenBody = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, bind_code: 'AK-ABC123', send_text: '绑定 AK-ABC123' }, (_u, i) => {
        seenBody = (i?.body as string) ?? '';
      }),
    );
    const r = await gatewayClient.bindInvite({ contact_id: 'c-1', display_name: '奶奶', tier: 'elder', reach: ['chef'] });
    expect(JSON.parse(seenBody)).toMatchObject({ contact_id: 'c-1', tier: 'elder', reach: ['chef'] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.bind_code).toBe('AK-ABC123');
  });

  it('decodes an {ok:false, reason, detail} error envelope even on a 200', async () => {
    vi.stubGlobal('fetch', mockFetch(200, { ok: false, reason: 'bind_not_claimed', detail: 'no one sent it yet' }));
    const r = await gatewayClient.bindApprove({ bind_code: 'AK-X', tier: null, reach: null });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('bind_not_claimed');
      expect(r.detail).toBe('no one sent it yet');
    }
  });

  it('surfaces an HTTP error status + reason', async () => {
    vi.stubGlobal('fetch', mockFetch(503, { ok: false, reason: 'gateway-not-configured' }));
    const r = await gatewayClient.contacts();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(503);
      expect(r.reason).toBe('gateway-not-configured');
    }
  });

  it('reports daemon_unreachable when fetch throws (no silent swallow)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('ECONNREFUSED'); }));
    const r = await gatewayClient.status();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('daemon_unreachable');
  });

  it('login/status encodes the login id into the query', async () => {
    let seenUrl = '';
    vi.stubGlobal('fetch', mockFetch(200, { ok: true, status: 'wait', bot_id: null, scanned_by: null, detail: null }, (u) => { seenUrl = u; }));
    await gatewayClient.loginStatus('login abc/1');
    expect(seenUrl).toContain('login_id=login%20abc%2F1');
  });

  it('terminal statuses stop the poll loop; transient ones do not', () => {
    for (const t of ['connected', 'already_bound', 'expired', 'verify_code_blocked', 'failed']) {
      expect(isTerminalLoginStatus(t)).toBe(true);
    }
    for (const t of ['wait', 'scaned', 'need_verifycode']) {
      expect(isTerminalLoginStatus(t)).toBe(false);
    }
  });

  it('surfaces the daemon pairing_err {error} body (not a bare http_503)', async () => {
    // The daemon proxy short-circuits with {error}, not {reason} — the UI must
    // still show the actionable message.
    vi.stubGlobal('fetch', mockFetch(503, { error: 'gateway-not-configured — set AGENTKEYS_WORKER_WEIXIN_URL' }));
    const r = await gatewayClient.status();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain('gateway-not-configured');
      expect(r.reason).not.toBe('http_503');
      expect(gatewayNotConfigured(r)).toBe(true);
    }
  });

  it('gatewayNotConfigured distinguishes "not set up" from a real error / daemon-down', () => {
    expect(gatewayNotConfigured({ reason: 'admin_disabled', status: 503 })).toBe(true);
    expect(gatewayNotConfigured({ reason: 'gateway-not-configured — set X', status: 503 })).toBe(true);
    expect(gatewayNotConfigured({ reason: 'daemon_unreachable', status: 0 })).toBe(false);
    expect(gatewayNotConfigured({ reason: 'bind_not_claimed', status: 409 })).toBe(false);
  });
});
