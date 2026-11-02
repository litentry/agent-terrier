// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LocalBrowserEnrollment } from '../../app/_components/LocalBrowserEnrollment';
import type { HostedBrowserIdentity } from '../hostedIdentity';
import type { HostedSignerStartRequest } from '../generated/HostedSignerStartRequest';

const mocks = vi.hoisted(() => ({ create: vi.fn(), sign: vi.fn(), assertion: vi.fn(), objectUrl: vi.fn(), revoke: vi.fn() }));
vi.mock('../hostedIdentity', () => ({ createHostedIdentity: mocks.create, signHostedEnrollment: mocks.sign }));
vi.mock('../webauthn', () => ({ getAssertionOverHash: mocks.assertion }));
const account = vi.fn(), start = vi.fn(), signIn = vi.fn(), ready = vi.fn();
const owner = '11'.repeat(32);
const accountAddress = `0x${'22'.repeat(20)}`;
const identity: HostedBrowserIdentity = { brokerUrl: 'http://localhost', omni: owner, credentialId: 'browser-key',
  deviceKeyHash: `0x${'33'.repeat(32)}`, secretHex: 'RAM-master-secret', consoleSecretHex: 'RAM-console-secret',
  publicKeyX: `0x${'44'.repeat(32)}`, publicKeyY: `0x${'55'.repeat(32)}`, prfSalt: 'public-salt' };
let container: HTMLDivElement, root: Root;

async function mount(initialOmni = owner) {
  await act(async () => root.render(<LocalBrowserEnrollment brokerUrl={identity.brokerUrl} initialOmni={initialOmni}
    account={account} start={start} signIn={signIn} onReady={ready} />));
}
async function click(label: string) {
  const button = [...container.querySelectorAll('button')].find((element) => element.textContent === label);
  expect(button).toBeDefined();
  await act(async () => button!.click());
}
async function enterOwner(value: string) {
  const input = container.querySelector<HTMLInputElement>('#local-owner-id')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const challenge = (request: HostedSignerStartRequest) => ({ challenge: `0x${'66'.repeat(32)}`,
  intent: { ...request, operator_omni: owner, account: accountAddress, chain_id: 31337, operator_nonce: '0', expires_at: Math.floor(Date.now() / 1000) + 600 } });

beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.stubGlobal('URL', Object.assign(class extends URL {}, { createObjectURL: mocks.objectUrl, revokeObjectURL: mocks.revoke }));
  mocks.objectUrl.mockReturnValue('blob:public-request');
  mocks.create.mockResolvedValue(identity); mocks.sign.mockResolvedValue('public-device-proof');
  mocks.assertion.mockResolvedValue({ credential_id: identity.credentialId, signature: 'public-passkey-proof' });
  account.mockResolvedValue(accountAddress); start.mockImplementation(async (requestOwner, request) => {
    expect(requestOwner).toBe(owner); return challenge(request);
  });
  signIn.mockRejectedValue(new Error('Browser access is not approved.'));
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); });

it('downloads public proofs and enters the console only after a successful passkey login', async () => {
  await mount(); await click('Create approval request');
  expect(account).toHaveBeenCalledWith(owner);
  expect(mocks.create.mock.invocationCallOrder[0]).toBeGreaterThan(account.mock.invocationCallOrder[0]);
  const link = container.querySelector<HTMLAnchorElement>('a[download]')!;
  expect(link.download).toBe('agent-terrier-browser.json');
  const publicBlob: Blob = mocks.objectUrl.mock.calls[0][0];
  const serialized = await new Promise<string>((resolve) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(publicBlob); });
  const approval = JSON.parse(serialized);
  expect(Object.keys(approval).sort()).toEqual(['device_proof', 'enrollment', 'proof']);
  expect(approval.enrollment.intent.device_key_hash).toBe(identity.deviceKeyHash);
  expect(serialized).not.toMatch(/RAM-|secretHex|consoleSecretHex|session_jwt/);
  expect(ready).not.toHaveBeenCalled();
  await click('Approved in CLI — sign in');
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('not approved');
  expect(ready).not.toHaveBeenCalled();
  signIn.mockResolvedValue(identity);
  await click('Approved in CLI — sign in');
  expect(signIn).toHaveBeenCalledWith(owner); expect(ready).toHaveBeenCalledWith(identity);
});

it('refuses an unknown owner before creating a passkey or signing a proof', async () => {
  account.mockRejectedValue(new Error('Owner is not registered.'));
  await mount(); await click('Create approval request');
  expect(container.textContent).toContain('not registered');
  expect(mocks.create).not.toHaveBeenCalled(); expect(mocks.sign).not.toHaveBeenCalled();
  expect(start).not.toHaveBeenCalled(); expect(ready).not.toHaveBeenCalled();
});

it.each(['operator_omni', 'account', 'origin', 'rp_id', 'credential_id', 'device_key_hash', 'public_key_x', 'public_key_y'])('rejects changed %s before signing either public proof', async (field) => {
  start.mockImplementation(async (_requestOwner, request) => {
    const result = challenge(request); return { ...result, intent: { ...result.intent, [field]: 'unexpected-value' } };
  });
  await mount(); await click('Create approval request');
  expect(container.querySelector('[role="alert"]')).not.toBeNull();
  expect(mocks.assertion).not.toHaveBeenCalled(); expect(mocks.sign).not.toHaveBeenCalled();
  expect(container.querySelector('a[download]')).toBeNull(); expect(ready).not.toHaveBeenCalled();
});

it('keeps cancelled passkey prompts outside the console', async () => {
  mocks.assertion.mockRejectedValue(new Error('Passkey prompt was cancelled.'));
  await mount(); await click('Create approval request');
  expect(container.textContent).toContain('cancelled');
  expect(mocks.sign).not.toHaveBeenCalled(); expect(ready).not.toHaveBeenCalled();
  expect(container.querySelector('a[download]')).toBeNull();
});

it('refreshes public requests with the same browser identity and revokes old download URLs', async () => {
  await mount(); await click('Create approval request'); await click('Refresh approval request');
  expect(mocks.create).toHaveBeenCalledTimes(1); expect(start).toHaveBeenCalledTimes(2);
  expect(mocks.revoke).toHaveBeenCalledWith('blob:public-request'); expect(ready).not.toHaveBeenCalled();
});

it('accepts a late saved owner suggestion without replacing an edited owner', async () => {
  await mount(''); await mount(owner);
  expect(container.querySelector<HTMLInputElement>('#local-owner-id')!.value).toBe(owner);
  const otherOwner = '77'.repeat(32);
  await enterOwner(otherOwner); await mount('88'.repeat(32));
  expect(container.querySelector<HTMLInputElement>('#local-owner-id')!.value).toBe(otherOwner);
});

it('does not create a passkey when an account preflight completes after unmount', async () => {
  let resolveAccount: (value: string) => void = () => {};
  account.mockReturnValue(new Promise<string>((resolve) => { resolveAccount = resolve; }));
  await mount(); await click('Create approval request');
  await act(async () => root.render(null));
  await act(async () => resolveAccount(accountAddress));
  expect(mocks.create).not.toHaveBeenCalled(); expect(ready).not.toHaveBeenCalled();
});
