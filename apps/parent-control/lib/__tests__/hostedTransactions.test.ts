import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CoreBackend } from '../client/core';

const mocks = vi.hoisted(() => ({ request: vi.fn(), configuration: vi.fn(), finishEmailLogin: vi.fn(), sessionInfo: vi.fn(), status: vi.fn() }));
vi.mock('../hostedIdentity', () => ({ listHostedIdentities: () => [], loadHostedIdentity: () => null }));
vi.mock('../client/wasm-module', () => ({ loadWasmModule: async () => ({
  WebCore: class { finishEmailLogin = mocks.finishEmailLogin; sessionInfo = mocks.sessionInfo; },
  ConsoleClient: class { request = mocks.request; },
  HostedSignerClient: class { status = mocks.status; free() {} },
  consoleConfiguration: mocks.configuration,
}) }));
class TestConsole extends CoreBackend {
  submit(path = '/v1/revoke/submit') { return this.postJson(path, { user_op: { sender: 'account', nonce: '1' }, assertion: { signature: 'approved' } }); }
}
const brokerUrl = 'https://transactions.example.test';
let client: TestConsole;
const pending = { pending: true, user_op_hash: 'operation-hash' };
const confirmed = { pending: false, user_op_hash: 'operation-hash', tx_hash: 'transaction-hash' };
async function authenticate() {
  const session = { session_jwt: 'test-session', omni_account: 'existing-omni', wallet_address: 'existing-wallet', expires_at: Math.floor(Date.now() / 1000) + 3600 };
  mocks.finishEmailLogin.mockResolvedValue(session);
  mocks.sessionInfo.mockResolvedValue(session);
  mocks.status.mockResolvedValue({ active: true, device_active: true });
  await client.pollEmailLogin('request');
  await client.activateHostedIdentity({ brokerUrl, omni: session.omni_account, credentialId: 'credential', deviceKeyHash: 'device', publicKeyX: 'x', publicKeyY: 'y', prfSalt: 'salt', secretHex: 'master-ram', consoleSecretHex: 'console-ram' });
}
async function flush() { await vi.advanceTimersByTimeAsync(0); }

describe('hosted transaction completion', () => {
  beforeEach(async () => {
    vi.useFakeTimers();
    vi.resetAllMocks();
    mocks.configuration.mockResolvedValue({});
    client = new TestConsole(brokerUrl);
    await authenticate();
  });
  afterEach(() => { client.clearHostedSession(); vi.useRealTimers(); });

  it('waits for a verified receipt and does not resubmit a pending revoke', async () => {
    mocks.request.mockResolvedValueOnce(pending).mockResolvedValueOnce(confirmed);
    let completed = false;
    const result = client.submit().then(value => { completed = true; return value; });
    await flush();
    expect(completed).toBe(false);
    expect(client.pendingTransactions()).toEqual([]);
    await vi.advanceTimersByTimeAsync(2000);
    expect(await result).toEqual({ ok: true, data: confirmed });
    expect(mocks.request.mock.calls.map(call => call[6])).toEqual(['/v1/revoke/submit', '/v1/accept/receipt']);
    expect(mocks.request.mock.calls[1][7]).toEqual({ user_op: { sender: 'account', nonce: '1' } });
  });

  it('keeps an overdue transaction available for confirmation without rebroadcast', async () => {
    mocks.request.mockResolvedValue(pending);
    const submission = client.submit();
    await vi.advanceTimersByTimeAsync(180_000);
    expect(await submission).toMatchObject({ ok: false, status: { detail: expect.stringContaining('still awaiting confirmation') } });
    const [id] = client.pendingTransactions();
    expect(id).toBeDefined();
    mocks.request.mockResolvedValueOnce(confirmed);
    expect(await client.confirmPendingTransaction(id)).toEqual({ ok: true, data: confirmed });
    expect(mocks.request.mock.calls.filter(call => call[6] === '/v1/revoke/submit')).toHaveLength(1);
    expect(client.pendingTransactions()).toEqual([]);
  });

  it('retries app metadata through its original finalizer after chain confirmation', async () => {
    mocks.request.mockRejectedValueOnce(new Error('{"chain_confirmed":true,"error":"metadata_save_failed"}'));
    expect(await client.submit('/v1/master/apps/install/submit')).toMatchObject({ ok: false });
    const [id] = client.pendingTransactions();
    mocks.request.mockResolvedValueOnce(confirmed);
    expect(await client.confirmPendingTransaction(id)).toMatchObject({ ok: true });
    expect(mocks.request.mock.calls.map(call => call[6])).toEqual(['/v1/master/apps/install/submit', '/v1/master/apps/install/submit']);
  });

  it('prevents concurrent checks for the same signed operation', async () => {
    let finish!: (value: typeof confirmed) => void;
    mocks.request.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const first = client.submit();
    await flush();
    expect(await client.submit()).toMatchObject({ ok: false, status: { detail: expect.stringContaining('already being checked') } });
    expect(mocks.request).toHaveBeenCalledTimes(1);
    finish(confirmed);
    expect(await first).toMatchObject({ ok: true });
  });

  it('stops confirmation requests when the user signs out', async () => {
    mocks.request.mockResolvedValue(pending);
    const first = client.submit();
    await flush();
    await client.logout();
    await vi.advanceTimersByTimeAsync(2000);
    expect(await first).toMatchObject({ ok: false });
    expect(mocks.request).toHaveBeenCalledTimes(1);
    expect(client.pendingTransactions()).toEqual([]);
  });

  it('does not send saved keys after sign-out while configuration is loading', async () => {
    let finish!: (value: object) => void;
    mocks.configuration.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const first = client.submit();
    await flush();
    await client.logout();
    finish({});
    expect(await first).toMatchObject({ ok: false });
    expect(mocks.request).not.toHaveBeenCalled();
  });
  it('retains an uncertain submission after connection loss and checks its receipt', async () => {
    mocks.request.mockRejectedValueOnce(new Error('transport: connection closed'));
    expect(await client.submit()).toMatchObject({ ok: false });
    const [id] = client.pendingTransactions();
    mocks.request.mockResolvedValueOnce(confirmed);
    expect(await client.confirmPendingTransaction(id)).toMatchObject({ ok: true });
    expect(mocks.request.mock.calls.map(call => call[6])).toEqual(['/v1/revoke/submit', '/v1/accept/receipt']);
  });

  it('does not treat failed runtime finalization as completed work', async () => {
    mocks.request.mockResolvedValueOnce({ ...confirmed, ceremony: { spawned: [{ sandbox: { error: 'offline' } }] } });
    expect(await client.submit('/v1/agent/spawn/submit')).toMatchObject({ ok: false });
    expect(client.pendingTransactions()).toHaveLength(1);
  });

  it('does not offer receipt recovery for an operation rejected before submission', async () => {
    mocks.request.mockRejectedValueOnce(new Error('HTTP 403 not allowed'));
    expect(await client.submit()).toMatchObject({ ok: false });
    expect(client.pendingTransactions()).toEqual([]);
  });

});
