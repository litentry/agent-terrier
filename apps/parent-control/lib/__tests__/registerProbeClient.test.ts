// #435 — pin the register-probe client seam: the exact daemon URL + the
// fail-safe semantics tryRealEnroll relies on (probe:"error" must never be
// treated as unbound).
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

describe('DaemonBackend register probe (#435)', () => {
  const backend = () => new DaemonBackend('http://127.0.0.1:3114');

  it('GETs /v1/master/register/state and returns the probe verdict', async () => {
    const calls = mockFetch(() => ({
      operator_omni: `0x${'ab'.repeat(32)}`,
      bound: true,
      master_account: '0x1111111111111111111111111111111111111111',
      probe: 'chain',
    }));
    const r = await backend().getRegisterState();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('http://127.0.0.1:3114/v1/master/register/state');
    expect(calls[0].method).toBe('GET');
    if (!r.ok) throw new Error('expected ok');
    expect(r.data.bound).toBe(true);
    expect(r.data.probe).toBe('chain');
    expect(r.data.master_account).toMatch(/^0x/);
  });

  it('carries the error probe verdict through untouched (fail-safe input)', async () => {
    mockFetch(() => ({
      operator_omni: `0x${'ab'.repeat(32)}`,
      bound: false,
      probe: 'error',
      probe_error: 'rpc unreachable',
    }));
    const r = await backend().getRegisterState();
    if (!r.ok) throw new Error('expected ok');
    expect(r.data.bound).toBe(false);
    expect(r.data.probe).toBe('error');
    expect(r.data.probe_error).toContain('rpc');
  });
});
