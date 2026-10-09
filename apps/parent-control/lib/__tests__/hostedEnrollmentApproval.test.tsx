// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { HostedEnrollmentApproval } from '../../app/_components/HostedEnrollmentApproval';

const mocks = vi.hoisted(() => ({ assertion: vi.fn() }));
vi.mock('../webauthn', () => ({ getAssertionOverHash: mocks.assertion }));
const prepare = vi.fn();
const pending = vi.fn();
const dismiss = vi.fn();
const build = vi.fn();
const submit = vi.fn();
const enrollment = { intent: { operator_omni: '0x11', account: '0x1234', chain_id: 42, origin: 'https://console.example.test', device_key_hash: '0x22' }, recovery_challenge: 'trusted-recovery-hash', attesting_device_key_hash: 'existing-master' };
const assertion = { authenticator_data: 'auth', client_data_json: 'json', signature: 'sig', credential_id: 'existing-key' };
let container: HTMLDivElement;
let root: Root;
async function click(label: string) {
  const button = [...container.querySelectorAll('button')].find((candidate) => candidate.textContent === label);
  expect(button).toBeDefined();
  await act(async () => button!.click());
}
async function review() { await click('Review browser request'); }
beforeEach(async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  pending.mockReset().mockResolvedValue({ requests: [{ id: 'request-id', approval: { enrollment: { ...enrollment, recovery_challenge: 'untrusted-input-hash' }, proof: assertion, device_proof: 'proof' } }] });
  dismiss.mockReset().mockResolvedValue(undefined);
  prepare.mockReset().mockResolvedValue(enrollment);
  build.mockReset().mockResolvedValue({ user_op: { sender: '0x1234' }, user_op_hash: 'actual-operation-hash', chain_id: 42 });
  submit.mockReset().mockResolvedValue({ ok: true });
  mocks.assertion.mockReset().mockResolvedValue(assertion);
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
  await act(async () => root.render(<HostedEnrollmentApproval credentialId="existing-key" pending={pending} dismiss={dismiss} prepare={prepare} build={build} submit={submit} />));
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); });

it('verifies the transferred request before prompting, then signs exactly the recovery and built operation', async () => {
  await review();
  expect(mocks.assertion).not.toHaveBeenCalled();
  expect(container.textContent).toContain('https://console.example.test');
  await click('Approve this browser');
  expect(mocks.assertion.mock.calls).toEqual([['trusted-recovery-hash', ['existing-key']], ['actual-operation-hash', ['existing-key']]]);
  expect(submit).toHaveBeenCalledWith({ user_op: { sender: '0x1234' }, assertion });
  expect(container.textContent).toContain('Browser approved');
  expect(dismiss).toHaveBeenCalledWith('request-id');
  expect(container.querySelector('textarea')).toBeNull();
});
it('does not prompt Touch ID for a rejected or expired public request', async () => {
  prepare.mockRejectedValue(new Error('request expired'));
  await review();
  expect(mocks.assertion).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
  expect(container.textContent).toContain('request expired');
});
it('never signs or submits an operation for a different account', async () => {
  build.mockResolvedValue({ user_op: { sender: 'another-account' }, user_op_hash: 'bad-operation-hash', chain_id: 42 });
  await review(); await click('Approve this browser');
  expect(mocks.assertion).toHaveBeenCalledTimes(1); expect(submit).not.toHaveBeenCalled();
  expect(container.textContent).toContain('account or chain changed');
});

it('declines a pending browser request without a passkey prompt', async () => {
  await click('Decline');
  expect(dismiss).toHaveBeenCalledWith('request-id');
  expect(mocks.assertion).not.toHaveBeenCalled();
  expect(submit).not.toHaveBeenCalled();
});
