// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { HostedBrowserEnrollment } from '../../app/_components/HostedBrowserEnrollment';
const mocks = vi.hoisted(() => ({ create: vi.fn(), sign: vi.fn(), assertion: vi.fn() }));
vi.mock('../hostedIdentity', () => ({ createHostedIdentity: mocks.create, signHostedEnrollment: mocks.sign }));
vi.mock('../webauthn', () => ({ getAssertionOverHash: mocks.assertion }));
const start = vi.fn(), status = vi.fn(), publish = vi.fn(), ready = vi.fn();
const identity = { credentialId: 'browser-key', deviceKeyHash: 'browser-device', secretHex: 'RAM-master-secret', consoleSecretHex: 'RAM-console-secret', publicKeyX: 'x', publicKeyY: 'y' };
let container: HTMLDivElement, root: Root;
async function click(label: string) { const button = [...container.querySelectorAll('button')].find((button) => button.textContent === label); expect(button).toBeDefined(); await act(async () => button!.click()); }
beforeEach(async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true); vi.stubGlobal('localStorage', { length: 0, setItem: vi.fn() });
  mocks.create.mockReset().mockResolvedValue(identity); mocks.sign.mockReset().mockResolvedValue('public-proof'); mocks.assertion.mockReset().mockResolvedValue({ credential_id: 'browser-key' });
  start.mockReset().mockResolvedValue({ challenge: 'challenge', intent: { expires_at: Date.now() / 1000 + 600, origin: 'https://console.test', device_key_hash: 'browser-device' } });
  status.mockReset().mockResolvedValue({ active: false, device_active: false });
  publish.mockReset().mockImplementation(async (approval) => ({ id: 'request', approval })); ready.mockReset();
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
  await act(async () => root.render(<HostedBrowserEnrollment brokerUrl="https://broker.test" omni="operator" start={start} status={status} publish={publish} onReady={ready} />));
});
afterEach(async () => { await act(async () => root?.unmount()); container?.remove(); vi.unstubAllGlobals(); });
it('publishes only public proofs and automatically continues after both chain bindings confirm', async () => {
  status.mockResolvedValueOnce({ active: false, device_active: false }).mockResolvedValueOnce({ active: true, device_active: true });
  await click('Set up browser access');
  expect(publish).toHaveBeenCalledTimes(1); expect(JSON.stringify(publish.mock.calls)).not.toContain('RAM-');
  expect(ready).toHaveBeenCalledWith(identity); expect(container.querySelector('textarea')).toBeNull(); expect(localStorage.length).toBe(0);
});
it('keeps access blocked until signer and master device are both confirmed', async () => {
  status.mockResolvedValue({ active: true, device_active: false });
  await click('Set up browser access');
  expect(ready).not.toHaveBeenCalled(); expect(container.textContent).toContain('Waiting for approval');
});
it('shows denied publication without exposing keys or entering the console', async () => {
  publish.mockRejectedValue(new Error('session expired'));
  await click('Set up browser access');
  expect(ready).not.toHaveBeenCalled(); expect(container.textContent).toContain('session expired');
  expect(container.textContent).not.toContain('RAM-'); expect(localStorage.length).toBe(0);
});
it('expires requests and can refresh them without creating another browser identity', async () => {
  start.mockResolvedValueOnce({ challenge: 'expired', intent: { expires_at: 1, origin: 'https://console.test', device_key_hash: 'browser-device' } });
  await click('Set up browser access');
  expect(container.textContent).toContain('request expired'); expect(ready).not.toHaveBeenCalled();
  await click('Refresh approval request');
  expect(mocks.create).toHaveBeenCalledTimes(1); expect(publish).toHaveBeenCalledTimes(2);
});
