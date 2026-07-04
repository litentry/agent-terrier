// #390 — the persona/context client surface + the per-kind inbox accept.
// Pins the DaemonBackend's routes + request bodies for the new endpoints
// against a mocked fetch (the field NAMES are compile-checked by the ts-rs
// types; this checks the runtime routing + body assembly, incl. the skill
// viewed-body watermark that must NOT be sent for knowledge accepts).
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DaemonBackend } from '../client/daemon';

type Call = { url: string; method: string; body?: unknown };

function mockFetch(responder: (call: Call) => unknown) {
  const calls: Call[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const call: Call = {
        url: String(url),
        method: init?.method ?? 'GET',
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      };
      calls.push(call);
      return {
        ok: true,
        status: 200,
        json: async () => responder(call),
        text: async () => JSON.stringify(responder(call)),
      } as Response;
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe('DaemonBackend persona + per-kind inbox surface (#390)', () => {
  const backend = () => new DaemonBackend('http://127.0.0.1:3114');

  it('routes persona get/edit/rollback with the delegate omni', async () => {
    const calls = mockFetch(() => ({ ok: true, version: 1, applied: false, apply_detail: 'x' }));
    const b = backend();
    await b.getPersona('0xAbCd1234');
    await b.editPersona('0xAbCd1234', 'Be warm.');
    await b.rollbackPersona('0xAbCd1234', 1);
    expect(calls[0].url).toBe('http://127.0.0.1:3114/v1/master/persona?delegate=0xAbCd1234');
    expect(calls[0].method).toBe('GET');
    expect(calls[1]).toMatchObject({
      url: 'http://127.0.0.1:3114/v1/master/persona',
      method: 'POST',
      body: { delegate_omni: '0xAbCd1234', body: 'Be warm.' },
    });
    expect(calls[2]).toMatchObject({
      url: 'http://127.0.0.1:3114/v1/master/persona/rollback',
      body: { delegate_omni: '0xAbCd1234', version: 1 },
    });
  });

  it('routes restart + live context view', async () => {
    const calls = mockFetch(() => ({ ok: true, restarted: true, configured: false, files: [] }));
    const b = backend();
    await b.restartAgent();
    await b.getAgentContext();
    expect(calls[0].url).toBe('http://127.0.0.1:3114/v1/master/agent/restart');
    expect(calls[0].method).toBe('POST');
    expect(calls[1].url).toBe('http://127.0.0.1:3114/v1/master/agent/context');
  });

  it('sends the skill watermark on accept only when provided (#390 §16.2 gate)', async () => {
    const calls = mockFetch(() => ({ ok: true, planted: 1, ns: 'n', key: 'k' }));
    const b = backend();
    // knowledge accept — NO confirm_content_hash key at all (the daemon treats
    // its presence as the watermark; a spurious one must not be fabricated).
    await b.acceptInbox('bots/x/inbox/y/z.enc');
    // skill accept — the viewed-body watermark rides along.
    await b.acceptInbox('bots/x/inbox/y/z.enc', '0xhash');
    expect(calls[0].body).toEqual({ s3_key: 'bots/x/inbox/y/z.enc' });
    expect(calls[1].body).toEqual({
      s3_key: 'bots/x/inbox/y/z.enc',
      confirm_content_hash: '0xhash',
    });
  });
});
