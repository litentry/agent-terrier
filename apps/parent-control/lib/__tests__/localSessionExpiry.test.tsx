// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { App } from '../../app/_components/App';
import { DaemonBackend } from '../client/daemon';
import { resetActiveStackForTests, setActiveStack, setMasterCredId } from '../identityStore';

const mocks = vi.hoisted(() => ({ assertion: vi.fn() }));
vi.mock('../webauthn', () => ({ getAssertionOverHash: mocks.assertion }));
let client: DaemonBackend;
vi.mock('../ClientProvider', () => ({
  useClient: () => client,
  useConnectionStatus: () => ({ kind: 'connected', via: 'daemon', endpoint: 'http://daemon.example.test' }),
}));
let container: HTMLDivElement;
let root: Root;
let approvalFetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
  const storageValues = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => storageValues.get(key) ?? null,
    setItem: (key: string, value: string) => storageValues.set(key, value),
    removeItem: (key: string) => storageValues.delete(key),
    clear: () => storageValues.clear(),
    toJSON: () => Object.fromEntries(storageValues),
  });
  resetActiveStackForTests();
  setActiveStack('test', 'https://broker.example.test');
  setMasterCredId('existing-passkey');
  client = new DaemonBackend('http://daemon.example.test');
  vi.spyOn(client, 'getChainList').mockResolvedValue({ ok: true, data: { chains: [], daemonChain: 'test', daemonBroker: 'https://broker.example.test' } });
  vi.spyOn(client, 'getOnboardingState').mockResolvedValue({ ok: true, data: { identity: 'verified', chain: 'master-registered', session: 'active', k11: 'enrolled' } });
  vi.spyOn(client, 'listMemoryCategories').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listConfigPresets').mockResolvedValue({ ok: true, data: { presets: [], defaultId: '' } });
  vi.spyOn(client, 'listCredentials').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listInbox').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listResources').mockResolvedValue({ ok: true, data: { items: [], storage: 'ok' } });
  vi.spyOn(client, 'listActors').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listRecentAuditEvents').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listChannels').mockResolvedValue({ ok: true, data: { channels: [], storage: 'ok' } });
  vi.spyOn(client, 'listPairingRequests').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'streamAudit').mockReturnValue(() => {});
  approvalFetch = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ error: 'ExpiredSignature' }), { status: 401 }));
  vi.stubGlobal('fetch', approvalFetch);
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('turns one approval 401 into Touch ID re-authentication and resumes polling after success', async () => {
  await act(async () => root.render(<App />));
  expect(container.textContent).toContain('session expired');
  expect(approvalFetch).toHaveBeenCalledTimes(1);
  await act(async () => { await vi.advanceTimersByTimeAsync(65000); });
  expect(approvalFetch).toHaveBeenCalledTimes(1);
  const challenge = 'account-bound-challenge';
  const assertion = { credential_id: 'existing-passkey', authenticator_data: 'auth', client_data_json: 'json', signature: 'signature' };
  mocks.assertion.mockResolvedValue(assertion);
  vi.spyOn(client, 'reloginStart').mockResolvedValue({ ok: true, data: { challenge, account: 'existing-account', email: 'master@example.test', omni: 'existing-omni' } });
  vi.spyOn(client, 'reloginFinish').mockResolvedValue({ ok: true, data: { omni: 'existing-omni' } });
  approvalFetch.mockImplementation(async () => new Response(JSON.stringify({ requests: [] }), { status: 200 }));
  const button = [...container.querySelectorAll('button')].find((candidate) => candidate.textContent?.includes('re-authenticate'));
  expect(button).toBeDefined();
  await act(async () => button!.click());
  expect(mocks.assertion).toHaveBeenCalledWith(challenge, ['existing-passkey']);
  expect(client.reloginFinish).toHaveBeenCalledWith(challenge, assertion);
  expect(container.textContent).not.toContain('session expired');
  expect(approvalFetch).toHaveBeenCalledTimes(2);
});

it('does not poll browser approvals when the daemon already reports an expired session', async () => {
  vi.mocked(client.getOnboardingState).mockResolvedValue({ ok: true, data: { identity: 'verified', chain: 'master-registered', session: 'expired', k11: 'enrolled' } });
  await act(async () => root.render(<App />));
  expect(container.textContent).toContain('session expired');
  await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
  expect(approvalFetch).not.toHaveBeenCalled();
});
