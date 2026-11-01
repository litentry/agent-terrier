import { afterEach, describe, expect, it, vi } from 'vitest';
import { DaemonBackend } from '../client/daemon';

// #717 — the rebind ceremony's client half (build → ONE Touch ID → submit): the
// daemon paths, the body the build carries (the changed slots only), and the
// pass-through of the signed op. The daemon + broker halves run headlessly in
// phase 8 (`agentkeys app rebind`).

function mockFetch(status: number, body: unknown, capture?: (url: string, init?: RequestInit) => void) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    capture?.(url, init);
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(body),
      json: async () => body,
    } as Response;
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('app rebind client (#717 — a commit, not a reinstall)', () => {
  it('build posts the changed slots to /v1/master/apps/<label>/rebind/build', async () => {
    let seenUrl = '';
    let seenBody = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { build: { user_op_hash: '0xabc' }, label: 'chef', changes: ['family_chat: family-chat-chef → family-chat'] }, (u, i) => {
        seenUrl = u;
        seenBody = String(i?.body ?? '');
      }),
    );
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appRebindBuild('chef', { slots: [{ slot: 'family_chat', channel_id: 'family-chat' }] });
    expect(seenUrl).toBe('http://127.0.0.1:3214/v1/master/apps/chef/rebind/build');
    expect(JSON.parse(seenBody)).toEqual({ slots: [{ slot: 'family_chat', channel_id: 'family-chat' }] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.changes).toEqual(['family_chat: family-chat-chef → family-chat']);
  });

  it('submit passes the signed op to /v1/master/apps/<label>/rebind/submit and surfaces the runtime outcome', async () => {
    let seenUrl = '';
    let seenBody = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, tx_hash: '0xtx', rebound: { runtime: { mode: 'resubscribed', detail: 'the running instance re-sourced its feeds in place' } } }, (u, i) => {
        seenUrl = u;
        seenBody = String(i?.body ?? '');
      }),
    );
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appRebindSubmit('chef', { user_op: { nonce: '1' }, assertion: { sig: 'x' } });
    expect(seenUrl).toBe('http://127.0.0.1:3214/v1/master/apps/chef/rebind/submit');
    expect(JSON.parse(seenBody)).toEqual({ user_op: { nonce: '1' }, assertion: { sig: 'x' } });
    expect(r.ok).toBe(true);
    if (r.ok) expect((r.data.rebound as { runtime: { mode: string } }).runtime.mode).toBe('resubscribed');
  });

  it('a refused build (unknown slot) comes back as a typed failure, never a throw', async () => {
    vi.stubGlobal('fetch', mockFetch(400, { error: 'template_bindings_invalid', rows: [{ code: 'binding_unknown_slot' }] }));
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appRebindBuild('chef', { slots: [{ slot: 'nope', channel_id: 'x' }] });
    expect(r.ok).toBe(false);
  });
});
