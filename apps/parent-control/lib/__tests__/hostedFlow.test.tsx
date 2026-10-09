// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../../app/_components/App';
import { CoreBackend } from '../client/core';
import { resetActiveStackForTests } from '../identityStore';

const mocks = vi.hoisted(() => ({ emailRequest: vi.fn(), finishEmailLogin: vi.fn(), sessionInfo: vi.fn() }));
vi.mock('../client/wasm-module', () => ({ loadWasmModule: async () => ({ WebCore: class {
  emailRequest = mocks.emailRequest;
  finishEmailLogin = mocks.finishEmailLogin;
  sessionInfo = mocks.sessionInfo;
} }) }));
let client: CoreBackend;
vi.mock('../ClientProvider', () => ({
  useClient: () => client,
  useConnectionStatus: () => ({ kind: 'connected', via: 'broker', endpoint: 'https://broker.example.test' }),
}));
const session = { session_jwt: 'test-session', omni_account: 'existing-omni', wallet_address: 'existing-wallet', expires_at: Math.floor(Date.now() / 1000) + 600 };
const { session_jwt: _token, ...info } = session;
let container: HTMLDivElement;
let root: Root;

async function click(label: string) {
  const button = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.trim() === label);
  expect(button, `button ${label}`).toBeDefined();
  await act(async () => button!.click());
}
async function startLogin() {
  const input = container.querySelector<HTMLInputElement>('#ak-email');
  expect(input, 'the original parent-control email field').not.toBeNull();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, 'approved@example.test');
    input!.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await click('Continue →');
}
async function mount() { await act(async () => root.render(<App />)); }

describe('hosted parent-control flow', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.resetAllMocks();
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    const storageValues = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => storageValues.get(key) ?? null,
      setItem: (key: string, value: string) => storageValues.set(key, value),
      removeItem: (key: string) => storageValues.delete(key),
      clear: () => storageValues.clear(),
      toJSON: () => Object.fromEntries(storageValues),
    });
    localStorage.clear();
    resetActiveStackForTests();
    client = new CoreBackend('https://broker.example.test');
    mocks.emailRequest.mockResolvedValue({ request_id: 'approved-request', expires_in_seconds: 300 });
    mocks.finishEmailLogin.mockResolvedValue(null);
    mocks.sessionInfo.mockResolvedValue(info);
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });
  it('continues from the original email screen into parent control and signs out cleanly', async () => {
    await mount();
    await startLogin();
    expect(container.textContent).toContain('Check your inbox.');
    expect(container.querySelector('nav[aria-label="sections"]')).toBeNull();
    mocks.finishEmailLogin.mockResolvedValue(session);
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(container.querySelector('nav[aria-label="sections"]')).not.toBeNull();
    expect(container.textContent).toContain('parent control');
    expect(container.textContent).not.toContain('You are signed in.');
    expect(container.textContent).not.toContain('Bringing up your trust core');
    expect(container.textContent).not.toContain('daemon offline');
    expect(mocks.sessionInfo).toHaveBeenCalledWith('test-session');
    await click('log out');
    expect(container.querySelector('#ak-email')).not.toBeNull();
    expect(container.querySelector('nav')).toBeNull();
    expect(await client.hostedSessionInfo()).toBeNull();
    expect(JSON.stringify(localStorage)).not.toContain('test-session');
  });
  it('never uses a stale onboarding flag as a hosted session', async () => {
    localStorage.setItem('ak_onboarded', '1');
    await mount();
    expect(container.querySelector('#ak-email')).not.toBeNull();
    expect(container.querySelector('nav')).toBeNull();
  });
  it('keeps a denied address at login without demo verification', async () => {
    mocks.emailRequest.mockRejectedValue(new Error('403 not approved'));
    await mount();
    await startLogin();
    expect(container.textContent).toContain('not approved');
    expect(container.textContent).not.toContain('Bringing up your trust core');
    expect(mocks.finishEmailLogin).not.toHaveBeenCalled();
    expect(container.querySelector('nav')).toBeNull();
  });
  it('shows polling failure and allows a fresh request', async () => {
    mocks.finishEmailLogin.mockRejectedValue(new Error('401 expired'));
    await mount();
    await startLogin();
    expect(container.textContent).toContain('expired');
    await click('← use a different email');
    expect(container.querySelector('#ak-email')).not.toBeNull();
    expect(await client.hostedSessionInfo()).toBeNull();
  });
  it('returns to login when an approved session is revoked', async () => {
    mocks.finishEmailLogin.mockResolvedValue(session);
    await mount();
    await startLogin();
    expect(container.querySelector('nav')).not.toBeNull();
    mocks.sessionInfo.mockRejectedValue(new Error('403 removed'));
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(container.querySelector('nav')).toBeNull();
    expect(container.querySelector('#ak-email')).not.toBeNull();
    expect(await client.hostedSessionInfo()).toBeNull();
  });
});
