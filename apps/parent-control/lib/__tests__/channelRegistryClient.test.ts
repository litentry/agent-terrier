import { afterEach, describe, expect, it, vi } from 'vitest';

import { DaemonBackend } from '../client/daemon';
import { channelHolders, orphanedChannels, type Actor } from '../../app/_components/types';

// The channels page's "clear orphaned" button: (a) the client hits the ONE bulk
// daemon route (`POST /v1/channels/clear-orphaned`) and unwraps its receipt,
// (b) the page-side orphan set — display only, the daemon is the authority — is
// exactly the registry rows no actor holds a grant on.

/** Minimal actor — only `services` matters to the channel-holder helpers. */
const actor = (over: Partial<Actor>): Actor =>
  ({
    id: 'agent-x',
    omni: '0x' + 'a'.repeat(64),
    omniHex: '0x' + 'a'.repeat(64),
    label: 'agent',
    role: 'agent',
    derivation: '',
    device: '',
    devicePubkey: '',
    lastActive: '',
    status: 'ok',
    vendor: '',
    k11: false,
    ...over,
  }) as Actor;

function mockFetch(status: number, body: unknown, capture?: (url: string, init?: RequestInit) => void) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    capture?.(url, init);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    } as unknown as Response;
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('DaemonBackend.clearOrphanedChannels', () => {
  it('POSTs the bulk route and unwraps removed / kept / storage', async () => {
    let seenUrl = '';
    let seenMethod = '';
    vi.stubGlobal(
      'fetch',
      mockFetch(200, { removed: ['probe'], kept: ['cam-frontdoor'], storage: 'ok' }, (u, i) => {
        seenUrl = u;
        seenMethod = i?.method ?? 'GET';
      }),
    );
    const r = await new DaemonBackend('http://daemon.test').clearOrphanedChannels();
    expect(seenUrl).toBe('http://daemon.test/v1/channels/clear-orphaned');
    expect(seenMethod).toBe('POST');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.removed).toEqual(['probe']);
      expect(r.data.kept).toEqual(['cam-frontdoor']);
      expect(r.data.storage).toBe('ok');
    }
  });

  it('surfaces the daemon refusal (503 while the fleet is unreconciled) as a failed result', async () => {
    vi.stubGlobal('fetch', mockFetch(503, { error: 'actor fleet not yet reconciled from chain — nothing cleared' }));
    const r = await new DaemonBackend('http://daemon.test').clearOrphanedChannels();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status.detail).toContain('503');
  });
});

describe('orphanedChannels (page-side display set)', () => {
  const channels = [{ id: 'cam-frontdoor' }, { id: 'kitchen-display' }, { id: 'probe' }];
  const actors = [
    actor({ id: 'cam', services: ['channel-pub:cam-frontdoor'] }),
    actor({ id: 'display', services: [' Channel-Sub:Kitchen-Display '] }),
    actor({ id: 'chef', services: ['memory:family'] }),
  ];

  it('keeps every row some actor holds by name (case- and space-insensitive) and offers the rest', () => {
    expect(orphanedChannels(channels, actors).map((c) => c.id)).toEqual(['probe']);
    expect(channelHolders(actors, 'kitchen-display').map((a) => a.id)).toEqual(['display']);
    expect(channelHolders(actors, 'probe')).toEqual([]);
  });

  it('with no actors every row is orphaned — which is why the daemon refuses an unreconciled fleet', () => {
    expect(orphanedChannels(channels, []).length).toBe(3);
  });
});
