import { describe, expect, it, vi } from 'vitest';
import { LocalSandboxError, sandboxChat, sandboxHealthz } from '../localSandboxClient';

// #631 — the local test-twin client is a thin forwarder to the app's own
// /api/dev/local-sandbox proxy; pin (a) the proxy paths + wire shapes,
// (b) the down-state passthrough, (c) the error-envelope decoding.

function mockFetch(status: number, body: unknown, capture?: (url: string, init?: RequestInit) => void) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    capture?.(url, init);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

describe('localSandboxClient', () => {
  it('healthz hits the proxy and returns the bridge health body', async () => {
    let seenUrl = '';
    const f = mockFetch(200, { ok: true, engine: 'dsh', version: '0.1', model: 'mock-model', phase: 'ready' }, (u) => {
      seenUrl = u;
    });
    const h = await sandboxHealthz(f);
    expect(seenUrl).toBe('/api/dev/local-sandbox/healthz');
    expect(h.phase).toBe('ready');
  });

  it('healthz passes the 503 down/starting body through instead of throwing', async () => {
    const f = mockFetch(503, { ok: false, phase: 'down', error: 'local sandbox not running' });
    const h = await sandboxHealthz(f);
    expect(h.ok).toBe(false);
    expect(h.phase).toBe('down');
  });

  it('chat POSTs the bridge body shape {text, stream:false} and returns the reply', async () => {
    let seenUrl = '';
    let seenBody = '';
    const f = mockFetch(200, { reply: 'Baozi', trace: [], usage: { total_tokens: 42 } }, (u, i) => {
      seenUrl = u;
      seenBody = String(i?.body ?? '');
    });
    const r = await sandboxChat('What is the family dog’s name?', f);
    expect(seenUrl).toBe('/api/dev/local-sandbox/chat');
    expect(JSON.parse(seenBody)).toEqual({ text: 'What is the family dog’s name?', stream: false });
    expect(r.reply).toBe('Baozi');
    expect(r.usage.total_tokens).toBe(42);
  });

  it('chat surfaces the bridge error envelope as a typed error', async () => {
    const f = mockFetch(502, { error: 'agent error: no provider/model' });
    await expect(sandboxChat('hi', f)).rejects.toThrowError(LocalSandboxError);
    await expect(sandboxChat('hi', f)).rejects.toMatchObject({
      status: 502,
      message: 'agent error: no provider/model',
    });
  });
});
