import { afterEach, describe, expect, it, vi } from 'vitest';
import { DaemonBackend } from '../client/daemon';
import type { HostedSignerApproval } from '../generated/HostedSignerApproval';
import type { HostedSignerBuildRequest } from '../generated/HostedSignerBuildRequest';
import type { SubmitAcceptUserOpRequest } from '../generated/SubmitAcceptUserOpRequest';

const assertion = { authenticator_data: 'auth-data', client_data_json: 'client-data', signature: 'assertion-signature', credential_id: 'existing-passkey' };
const approval: HostedSignerApproval = {
  enrollment: {
    intent: { operator_omni: '0xoperator', account: '0xaccount', chain_id: 42, credential_id: 'new-browser-passkey', public_key_x: '0xx', public_key_y: '0xy', origin: 'https://console.example.test', rp_id: 'console.example.test', device_key_hash: '0xdevice', operator_nonce: '7', expires_at: 1000 },
    challenge: 'new-key-proof-challenge', recovery_challenge: 'existing-device-challenge', attesting_device_key_hash: '0xexisting-device',
  },
  proof: { ...assertion, credential_id: 'new-browser-passkey' },
  device_proof: 'new-device-proof',
};
const build: HostedSignerBuildRequest = { intent: approval.enrollment.intent, proof: approval.proof, device_proof: approval.device_proof, recovery_assertion: { attesting_device_key_hash: approval.enrollment.attesting_device_key_hash, assertion } };
const submit: SubmitAcceptUserOpRequest = { user_op: { sender: '0xaccount', nonce: '0x7', init_code: '0x', call_data: '0xcall', account_gas_limits: '0xgas', pre_verification_gas: '0x1', gas_fees: '0xfees', paymaster_and_data: '0xpaymaster', signature: '0x' }, assertion };
const client = () => new DaemonBackend('http://daemon.test');
afterEach(() => vi.unstubAllGlobals());

describe('existing console hosted-browser approval transport', () => {
  it.each([
    { path: '/v1/master/hosted-signer/prepare', body: approval, call: () => client().hostedApprovalPrepare(approval), response: approval.enrollment },
    { path: '/v1/master/hosted-signer/build', body: build, call: () => client().hostedApprovalBuild(build), response: { user_op: submit.user_op, user_op_hash: 'actual-signed-hash', chain_id: 42 } },
    { path: '/v1/master/hosted-signer/submit', body: submit, call: () => client().hostedApprovalSubmit(submit), response: { ok: true, tx_hash: '0xconfirmed' } },
    { path: '/v1/master/hosted-signer/dismiss', body: { id: 'request-id' }, call: () => client().hostedApprovalDismiss('request-id'), response: { ok: true } },
  ])('forwards the exact public ceremony body to $path', async ({ path, body, call, response }) => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(response), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    expect(await call()).toEqual({ ok: true, data: response });
    expect(fetch).toHaveBeenCalledExactlyOnceWith(`http://daemon.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  });

  it.each([
    { name: 'prepare', call: () => client().hostedApprovalPrepare(approval) },
    { name: 'build', call: () => client().hostedApprovalBuild(build) },
    { name: 'submit', call: () => client().hostedApprovalSubmit(submit) },
    { name: 'dismiss', call: () => client().hostedApprovalDismiss('request-id') },
  ])('propagates denial and connection failure from $name without fabricating success', async ({ call }) => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'account or request expired' }), { status: 403 }));
    vi.stubGlobal('fetch', fetch);
    const denied = await call();
    expect(denied.ok).toBe(false);
    expect(JSON.stringify(denied)).toContain('account or request expired');
    fetch.mockRejectedValue(new Error('connection refused'));
    const disconnected = await call();
    expect(disconnected.ok).toBe(false);
    expect(JSON.stringify(disconnected)).toContain('connection refused');
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
