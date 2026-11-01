import { afterEach, describe, expect, it, vi } from 'vitest';
import { DaemonBackend } from '../client/daemon';

// The sealed context document on the operator surface: the client reads it
// from /v1/master/apps/<label>/context; the daemon builds the view from the
// stored bytes (phase 8 asserts it matches the seal after install + rebind).

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

describe('app context client', () => {
  it('reads the sealed document view from /v1/master/apps/<label>/context', async () => {
    let seenUrl = '';
    let seenMethod = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { label: 'chef', source: 'memory-plane', hash: '0xabc', matches_anchor: true, matches_row: true, doc: { version: 2, bound_channels: [] } }, (u, i) => {
        seenUrl = u;
        seenMethod = i?.method ?? 'GET';
      }),
    );
    const client = new DaemonBackend('http://127.0.0.1:3214');
    const r = await client.appContext('chef');
    expect(seenUrl).toBe('http://127.0.0.1:3214/v1/master/apps/chef/context');
    expect(seenMethod).toBe('GET');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.matches_anchor).toBe(true);
      expect(r.data.doc?.version).toBe(2);
    }
  });
});
