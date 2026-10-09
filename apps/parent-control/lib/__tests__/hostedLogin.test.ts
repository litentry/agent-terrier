import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CoreBackend } from '../client/core';

const mocks = vi.hoisted(() => ({ emailRequest: vi.fn(), finishEmailLogin: vi.fn(), sessionInfo: vi.fn() }));
vi.mock('../client/wasm-module', () => ({ loadWasmModule: async () => ({ WebCore: class {
  emailRequest = mocks.emailRequest;
  finishEmailLogin = mocks.finishEmailLogin;
  sessionInfo = mocks.sessionInfo;
} }) }));

const session = { session_jwt: 'test-session', omni_account: 'existing-omni', wallet_address: 'existing-wallet', expires_at: Math.floor(Date.now() / 1000) + 600 };
const { session_jwt: _token, ...info } = session;

describe('hosted login session', () => {
  beforeEach(() => { vi.resetAllMocks(); });

  it('does not invent a verified session while email is pending', async () => {
    mocks.finishEmailLogin.mockResolvedValue(null);
    const client = new CoreBackend('https://pending.example.test');
    expect(await client.pollEmailLogin('pending')).toBeNull();
    expect(mocks.sessionInfo).not.toHaveBeenCalled();
    expect(await client.hostedSessionInfo()).toBeNull();
  });

  it('requires server validation, then clears the in-memory session on logout', async () => {
    mocks.finishEmailLogin.mockResolvedValue(session);
    mocks.sessionInfo.mockResolvedValue(info);
    const client = new CoreBackend('https://valid.example.test');
    expect(await client.pollEmailLogin('verified')).toEqual(info);
    expect(mocks.sessionInfo).toHaveBeenCalledWith('test-session');
    client.clearHostedSession();
    expect(await client.hostedSessionInfo()).toBeNull();
  });

  it('never falls back to a simulated login when the server denies admission', async () => {
    mocks.emailRequest.mockRejectedValue(new Error('403 not approved'));
    const client = new CoreBackend('https://denied.example.test');
    await expect(client.requestEmailLogin('unapproved@example.test')).rejects.toThrow('403');
    expect(await client.hostedSessionInfo()).toBeNull();
  });

  it('discards an in-flight login completed after cancellation', async () => {
    let finish!: (value: typeof session) => void;
    mocks.finishEmailLogin.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    mocks.sessionInfo.mockResolvedValue(info);
    const client = new CoreBackend('https://cancelled.example.test');
    const pending = client.pollEmailLogin('request');
    await vi.waitFor(() => expect(finish).toBeDefined());
    client.clearHostedSession();
    finish(session);
    await expect(pending).rejects.toThrow('cancelled');
    expect(await client.hostedSessionInfo()).toBeNull();
  });

  it('clears a session when the allowlist is later revoked', async () => {
    mocks.finishEmailLogin.mockResolvedValue(session);
    mocks.sessionInfo.mockResolvedValueOnce(info).mockRejectedValueOnce(new Error('403 removed'));
    const client = new CoreBackend('https://revoked.example.test');
    await client.pollEmailLogin('request');
    await expect(client.hostedSessionInfo()).rejects.toThrow('403');
    expect(await client.hostedSessionInfo()).toBeNull();
  });

  it('rejects an expired session and never shares sessions between broker clients', async () => {
    mocks.finishEmailLogin.mockResolvedValue(session);
    mocks.sessionInfo.mockResolvedValue({ ...info, expires_at: 1 });
    const first = new CoreBackend('https://first.example.test');
    await expect(first.pollEmailLogin('request')).rejects.toThrow('expired');
    expect(await new CoreBackend('https://second.example.test').hostedSessionInfo()).toBeNull();
  });
  it('expires a pending email request without polling it again', async () => {
    mocks.emailRequest.mockResolvedValue({ request_id: 'request', expires_in_seconds: 0 });
    const client = new CoreBackend('https://expired-request.example.test');
    expect((await client.startEmailVerify('approved@example.test')).ok).toBe(true);
    expect(await client.pollEmailVerify('request')).toMatchObject({ ok: false, status: { reason: 'unauthorized' } });
    expect(mocks.finishEmailLogin).not.toHaveBeenCalled();
  });

  it('does not let a stale session check clear a newer login', async () => {
    mocks.finishEmailLogin.mockResolvedValue(session);
    mocks.sessionInfo.mockResolvedValue(info);
    const client = new CoreBackend('https://session-race.example.test');
    await client.pollEmailLogin('old');
    let reject!: (reason: Error) => void;
    mocks.sessionInfo.mockImplementationOnce(() => new Promise((_resolve, rejectPromise) => { reject = rejectPromise; }));
    const oldCheck = client.hostedSessionInfo();
    await vi.waitFor(() => expect(reject).toBeDefined());
    await client.logout();
    await client.pollEmailLogin('new');
    reject(new Error('403 old session'));
    await expect(oldCheck).rejects.toThrow('403');
    expect(await client.hostedSessionInfo()).toEqual(info);
  });

  it('requires authenticated browser keys before data reads', async () => {
    const client = new CoreBackend('https://browser-only.example.test');
    expect(await client.listActors()).toMatchObject({ ok: false, status: { reason: 'unauthorized' } });
    expect(await client.listMemoryCategories()).toMatchObject({ ok: false, status: { reason: 'unauthorized' } });
  });

});
