import { afterEach, describe, expect, it, vi } from 'vitest';
import { DaemonBackend } from '../client/daemon';

// The anchor's client half: "seal existing apps" (build → ONE Touch ID →
// submit) and "re-hydrate runtime contexts" hit the daemon paths with the
// bodies the daemon expects; the daemon + broker halves run headlessly in
// phase 8 (the install seals v1, the rebind v2, a re-hydrate verifies on chain).

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

describe('anchor client (the sealed context document)', () => {
  it('seal build posts the label filter to /v1/master/apps/anchors/seal/build', async () => {
    let seenUrl = '';
    let seenBody = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { build: { user_op_hash: '0xabc' }, labels: ['chef', 'agent-i'] }, (u, i) => {
        seenUrl = u;
        seenBody = String(i?.body ?? '');
      }),
    );
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appAnchorsSealBuild({});
    expect(seenUrl).toBe('http://127.0.0.1:3214/v1/master/apps/anchors/seal/build');
    expect(JSON.parse(seenBody)).toEqual({ labels: [] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.labels).toEqual(['chef', 'agent-i']);
  });

  it('seal submit passes the signed op to /v1/master/apps/anchors/seal/submit', async () => {
    let seenUrl = '';
    vi.stubGlobal('fetch', mockFetch(200, { ok: true, tx_hash: '0xtx', sealed: [{ label: 'chef', version: 1, context_storage: 'durable' }] }, (u) => { seenUrl = u; }));
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appAnchorsSealSubmit({ user_op: {}, assertion: {} });
    expect(seenUrl).toBe('http://127.0.0.1:3214/v1/master/apps/anchors/seal/submit');
    expect(r.ok).toBe(true);
    if (r.ok) expect((r.data.sealed as { label: string }[])[0].label).toBe('chef');
  });

  it('re-hydrate posts to /v1/master/apps/rehydrate and returns per-app results', async () => {
    let seenUrl = '';
    let seenBody = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { ok: true, results: [{ label: 'chef', status: 200, result: { row: 'current', sealed_index: 3 } }] }, (u, i) => {
        seenUrl = u;
        seenBody = String(i?.body ?? '');
      }),
    );
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appsRehydrate({ labels: ['chef'] });
    expect(seenUrl).toBe('http://127.0.0.1:3214/v1/master/apps/rehydrate');
    expect(JSON.parse(seenBody)).toEqual({ labels: ['chef'] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.results[0].status).toBe(200);
  });
});
