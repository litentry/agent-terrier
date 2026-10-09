import { afterEach, describe, expect, it, vi } from 'vitest';
import { gatewayClient, gatewayNotConfigured, isTerminalLoginStatus, setHostedGatewayAccess, type HostedGatewayAccess, type GatewayResult } from '../gatewayClient';
import type { HostedGatewayRequest } from '../generated/HostedGatewayRequest';
import { normalizeRouterView } from '../routerView';

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
  setHostedGatewayAccess(null);
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('gatewayClient', () => {
  it('never contacts a local daemon from the hosted console', async () => {
    vi.stubEnv('NEXT_PUBLIC_AGENTKEYS_BACKEND', 'core');
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    expect(await gatewayClient.status()).toMatchObject({ ok: false, reason: 'master_session_required' });
    expect(fetch).not.toHaveBeenCalled();
  });

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
      mockFetch(200, { ok: true, bind_code: '123456', send_text: '绑定 123456' }, (_u, i) => {
        seenBody = (i?.body as string) ?? '';
      }),
    );
    const r = await gatewayClient.bindInvite({ contact_id: 'c-1', display_name: '奶奶', tier: 'elder', channels: [{ channel_id: 'family-chat', speak: true, read: true }] });
    expect(JSON.parse(seenBody)).toMatchObject({ contact_id: 'c-1', tier: 'elder', channels: [{ channel_id: 'family-chat', speak: true, read: true }] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.bind_code).toBe('123456');
  });

  it('GET channels reads the household channel documents from the daemon proxy', async () => {
    let seenUrl = '';
    let seenMethod = '';
    const doc = {
      id: 'family-chat',
      name: '家庭群',
      purpose: '',
      household_default: true,
      operator_of: null,
      members: [{ contact_id: 'c-1', speak: true, read: true }],
      apps: [{ alias: 'chef', slot: 'family_chat', description: '回答今晚吃什么', takes: ['text', 'image'], audience: ['owner', 'partner'] }],
      default_app: 'chef',
      updated_at: 1,
    };
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, channels: [doc] }, (u, i) => {
        seenUrl = u;
        seenMethod = i?.method ?? 'GET';
      }),
    );
    const r = await gatewayClient.channels();
    expect(seenUrl.endsWith('/v1/master/gateway/channels')).toBe(true);
    expect(seenMethod).toBe('GET');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.channels).toHaveLength(1);
      expect(r.value.channels[0].default_app).toBe('chef');
      expect(r.value.channels[0].apps[0].audience).toContain('partner');
    }
  });

  it('POST channels/update sends ONE channel write, never a whole-document replace', async () => {
    let seenUrl = '';
    let seenBody = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, changed: true }, (u, i) => {
        seenUrl = u;
        seenBody = (i?.body as string) ?? '';
      }),
    );
    const r = await gatewayClient.channelUpdate({ channel_id: 'family-chat', member: { contact_id: 'c-2', speak: false, read: true } });
    expect(seenUrl.endsWith('/v1/master/gateway/channels/update')).toBe(true);
    const body = JSON.parse(seenBody);
    expect(body).toMatchObject({ channel_id: 'family-chat', remove: false, member: { contact_id: 'c-2', speak: false, read: true } });
    // Fields left out stay out — the gate leaves them untouched.
    expect(body).not.toHaveProperty('name');
    expect(body).not.toHaveProperty('default_app');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.changed).toBe(true);
  });

  it('GET router reads the Route page view (per-member channel options + the last exchanges)', async () => {
    let seenUrl = '';
    let seenMethod = '';
    const view = {
      ok: true,
      engine: 'jev',
      model: 'kev-9b',
      default_model: 'kev-9b',
      compare: false,
      models: [
        { model: 'kev-9b', provider: 'kev', active: true, stack_default: true, server: { configured: true, status: 200 } },
        { model: 'jev-1.13.0', provider: 'jev', active: false, stack_default: false, server: { configured: false } },
      ],
      threshold: 0.5,
      continue_threshold: 0.7,
      ask_ttl_secs: 600,
      describe_photos: true,
      describe_prompt: '',
      guidance: { destination: '', unclear: '', continues: '', continues_yes: '', continues_no: '', addressee: '' },
      contacts: [
        {
          contact: '奶奶',
          tier: 'elder',
          options: [{ channel_id: 'family-chat', name: '家庭群', line: '', apps: [{ alias: 'chef', description: '', takes: ['text'] }], members: ['奶奶'], updated_at: 1 }],
          request: null,
        },
      ],
      recent: [
        {
          id: 1,
          ts_ms: 1,
          contact: '奶奶',
          tier: 'elder',
          text: '今晚吃什么',
          photo: false,
          request: null,
          probabilities: { 'family-chat/chef': 0.9 },
          verdict: 'route',
          routed_to: 'family-chat',
          addressee: 'chef',
          confidence: 0.9,
          answered_by: 'jev',
          total_ms: 120,
          delivered: true,
          compared: [],
        },
      ],
    };
    vi.stubGlobal(
      'fetch',
      mockFetch(200, view, (u, i) => {
        seenUrl = u;
        seenMethod = i?.method ?? 'GET';
      }),
    );
    const r = await gatewayClient.router();
    expect(seenUrl.endsWith('/v1/master/gateway/router')).toBe(true);
    expect(seenMethod).toBe('GET');
    expect(r.ok).toBe(true);
    if (r.ok) {
      const { view: read, legacy } = normalizeRouterView(r.value);
      expect(legacy).toBe(false);
      expect(read.contacts[0].options[0].channel_id).toBe('family-chat');
      expect(read.recent[0].routed_to).toBe('family-chat');
      expect(read.recent[0].addressee).toBe('chef');
    }
  });

  it('POST router/settings switches the decision model and compare mode', async () => {
    let seenUrl = '';
    let seenMethod = '';
    let seenBody: unknown;
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, model: 'jev-1.13.0', compare: true, changed: true }, (u, i) => {
        seenUrl = u;
        seenMethod = i?.method ?? 'GET';
        seenBody = JSON.parse(String(i?.body));
      }),
    );
    const r = await gatewayClient.routerSettings({ model: 'jev-1.13.0', compare: true });
    expect(seenUrl.endsWith('/v1/master/gateway/router/settings')).toBe(true);
    expect(seenMethod).toBe('POST');
    expect(seenBody).toEqual({ model: 'jev-1.13.0', compare: true });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.model).toBe('jev-1.13.0');
      expect(r.value.changed).toBe(true);
    }
    // A model the gate does not offer comes back as the gate's own reason.
    vi.stubGlobal(
      'fetch',
      mockFetch(400, { ok: false, reason: 'model_not_offered', detail: 'this contact gate offers kev-9b' }),
    );
    const refused = await gatewayClient.routerSettings({ model: 'gpt-4o' });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.reason).toBe('model_not_offered');
  });

  it('decodes an {ok:false, reason, detail} error envelope even on a 200', async () => {
    vi.stubGlobal('fetch', mockFetch(200, { ok: false, reason: 'bind_not_claimed', detail: 'no one sent it yet' }));
    const r = await gatewayClient.bindApprove({ bind_code: 'AK-X', tier: null, channels: null });
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

function hostedAccess(registry: unknown = { bound: [], pending: [], invites: [], channels: [] }, durable: unknown = null) {
  let durableValue = durable;
  let revision = 1;
  const operations: HostedGatewayRequest[] = [];
  const writes: { value: unknown; expectedRevision: string }[] = [];
  const access: HostedGatewayAccess = {
    sessionKey: () => 'fixture-session',
    request: vi.fn(async (request: HostedGatewayRequest): Promise<GatewayResult<unknown>> => {
      operations.push(request);
      return { ok: true, value: (request.operation === 'registry_export' ? registry : { ok: true, transport: 'ilink', contacts: [], channels: [] }) };
    }),
    readRegistry: vi.fn(async () => durableValue === null ? null : { value: durableValue, revision: `revision-${revision}` }),
    writeRegistry: vi.fn(async (value: unknown, expectedRevision: string) => {
      writes.push({ value, expectedRevision });
      durableValue = value;
      revision += 1;
    }),
  };
  setHostedGatewayAccess(access);
  vi.stubEnv('NEXT_PUBLIC_AGENTKEYS_BACKEND', 'core');
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  return { access, operations, writes, fetch };
}

describe('hosted gateway management', () => {
  it('uses the typed broker operation and never opens the laptop daemon', async () => {
    const fixture = hostedAccess();
    expect(await gatewayClient.status()).toMatchObject({ ok: true, value: { transport: 'ilink' } });
    expect(fixture.operations).toEqual([{ operation: 'status' }]);
    expect(fixture.fetch).not.toHaveBeenCalled();
  });

  it('preserves login identifiers as typed fields and never sends an operator identity', async () => {
    const fixture = hostedAccess();
    await gatewayClient.loginStart('owner-contact');
    await gatewayClient.loginStatus('login abc/1');
    expect(fixture.operations).toContainEqual({ operation: 'login_start', payload: { contact_id: 'owner-contact' } });
    expect(fixture.operations).toContainEqual({ operation: 'login_status', payload: { login_id: 'login abc/1' } });
    expect(JSON.stringify(fixture.operations)).not.toContain('operator_omni');
  });

  it('restores a missing local registry from the durable Config document before reading contacts', async () => {
    const durable = { bound: [{ contact_id: 'existing-contact' }], invites: [], pending: [], channels: [] };
    const fixture = hostedAccess(undefined, durable);
    expect((await gatewayClient.contacts()).ok).toBe(true);
    expect(fixture.operations.map(request => request.operation)).toEqual(['registry_export', 'registry_restore', 'contacts']);
    expect(fixture.operations[1]).toEqual({ operation: 'registry_restore', payload: { registry: durable } });
    expect(fixture.writes).toEqual([]);
  });

  it('treats channel-only state as existing data and never replaces it with an older backup', async () => {
    const registry = { bound: [], invites: [], pending: [], channels: [{ id: 'existing-channel' }] };
    const fixture = hostedAccess(registry, { bound: [{ contact_id: 'old' }] });
    expect((await gatewayClient.channels()).ok).toBe(true);
    expect(fixture.operations.some(request => request.operation === 'registry_restore')).toBe(false);
    expect(fixture.writes).toEqual([{ value: registry, expectedRevision: 'revision-1' }]);
  });

  it('writes a conditional durable snapshot after the gate confirms a contact mutation', async () => {
    const registry = { bound: [{ contact_id: 'kid' }], invites: [], pending: [], channels: [] };
    const fixture = hostedAccess(registry, registry);
    expect((await gatewayClient.contactsUpdate({ contact_id: 'kid', tier: 'guest', channels: null })).ok).toBe(true);
    expect(fixture.operations.map(request => request.operation)).toEqual(['registry_export', 'contacts_update', 'registry_export']);
    expect(fixture.writes.map(write => write.expectedRevision)).toEqual(['revision-1', 'revision-2']);
  });

  it('surfaces Config conflicts after a landed change without retrying the mutation', async () => {
    const fixture = hostedAccess();
    vi.mocked(fixture.access.writeRegistry).mockRejectedValueOnce(new Error('409 revision_conflict'));
    const result = await gatewayClient.contactsRevoke('kid');
    expect(result).toMatchObject({ ok: false, reason: 'gateway_backup_failed' });
    if (!result.ok) expect(result.detail).toContain('change was applied');
    expect(fixture.operations.filter(request => request.operation === 'contacts_revoke')).toHaveLength(1);
    expect((await gatewayClient.contacts()).ok).toBe(true);
    expect(fixture.operations.filter(request => request.operation === 'registry_export')).toHaveLength(3);
  });

  it('refreshes apps only after the channel mutation has a durable backup', async () => {
    const fixture = hostedAccess();
    fixture.access.afterMutation = vi.fn(async request => {
      expect(fixture.writes).toHaveLength(1);
      expect(request).toMatchObject({ operation: 'channels_update', payload: { channel_id: 'family-chat' } });
    });
    expect((await gatewayClient.channelUpdate({ channel_id: 'family-chat', default_app: 'chef' })).ok).toBe(true);
    expect(fixture.access.afterMutation).toHaveBeenCalledTimes(1);
  });

  it('never refreshes apps when backup failed', async () => {
    const fixture = hostedAccess();
    fixture.access.afterMutation = vi.fn();
    vi.mocked(fixture.access.writeRegistry).mockRejectedValueOnce(new Error('409 revision_conflict'));
    expect(await gatewayClient.channelUpdate({ channel_id: 'family-chat', default_app: 'chef' })).toMatchObject({ ok: false, reason: 'gateway_backup_failed' });
    expect(fixture.access.afterMutation).not.toHaveBeenCalled();
  });

  it('distinguishes runtime refresh failure from backup failure without replaying the mutation', async () => {
    const fixture = hostedAccess();
    fixture.access.afterMutation = vi.fn(async () => { throw new Error('runtime offline'); });
    expect(await gatewayClient.channelUpdate({ channel_id: 'family-chat', default_app: 'chef' })).toMatchObject({ ok: false, reason: 'gateway_followthrough_failed' });
    expect(fixture.writes).toHaveLength(1);
    expect(fixture.operations.filter(request => request.operation === 'channels_update')).toHaveLength(1);
  });

  it('rejects malformed later registry fields even when contacts are present', async () => {
    const fixture = hostedAccess({ bound: [{}], channels: 'invalid' });
    expect(await gatewayClient.contacts()).toMatchObject({ ok: false, reason: 'gateway_registry_unavailable' });
    expect(fixture.writes).toHaveLength(0);
  });

  it('does not mutate when the Config baseline cannot be read', async () => {
    const fixture = hostedAccess();
    vi.mocked(fixture.access.readRegistry).mockRejectedValue(new Error('Config unavailable'));
    expect(await gatewayClient.contactsRevoke('kid')).toMatchObject({ ok: false, reason: 'gateway_registry_unavailable' });
    expect(fixture.operations.some(request => request.operation === 'contacts_revoke')).toBe(false);
  });

  it('returns owner-denied errors unchanged without reading or writing another registry', async () => {
    const fixture = hostedAccess();
    vi.mocked(fixture.access.request).mockResolvedValue({ ok: false, reason: 'gateway_operator_mismatch', status: 403 });
    expect(await gatewayClient.contacts()).toEqual({ ok: false, reason: 'gateway_operator_mismatch', status: 403 });
    expect(fixture.access.readRegistry).not.toHaveBeenCalled();
    expect(fixture.access.writeRegistry).not.toHaveBeenCalled();
  });

  it('discards responses after logout and never writes their registry into a new session', async () => {
    const fixture = hostedAccess();
    let resolveRequest!: (value: GatewayResult<unknown>) => void;
    vi.mocked(fixture.access.request).mockImplementationOnce(() => new Promise(resolve => { resolveRequest = resolve; }));
    const pending = gatewayClient.contacts();
    await Promise.resolve();
    setHostedGatewayAccess(null);
    resolveRequest({ ok: true, value: { bound: [{ contact_id: 'old-owner' }] } });
    expect(await pending).toMatchObject({ ok: false, reason: 'master_session_required' });
    expect(fixture.access.readRegistry).not.toHaveBeenCalled();
    expect(fixture.access.writeRegistry).not.toHaveBeenCalled();
  });
});
