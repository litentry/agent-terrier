// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { App } from '../../app/_components/App';
import { DaemonBackend } from '../client/daemon';
import type { CredService, OnboardingState, Result } from '../client/types';
import { resetActiveStackForTests } from '../identityStore';

let client: DaemonBackend;
const connection = { kind: 'connected', via: 'daemon', endpoint: 'http://diagnostic.test' };
vi.mock('../ClientProvider', () => ({ useClient: () => client, useConnectionStatus: () => connection }));
let container: HTMLDivElement;
let root: Root;
const ready: OnboardingState = { identity: 'verified', omni: '11'.repeat(32), k11: 'none', chain: 'master-registered', session: 'active' };
let currentState: OnboardingState;
let protectedCalls: ReturnType<typeof vi.spyOn>[];

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
  const storageValues = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => storageValues.get(key) ?? null,
    setItem: (key: string, value: string) => storageValues.set(key, value),
    removeItem: (key: string) => storageValues.delete(key),
  });
  resetActiveStackForTests();
  currentState = { identity: 'none', k11: 'none', chain: 'none', session: 'none' };
  client = new DaemonBackend('http://diagnostic.test');
  vi.spyOn(client, 'getOnboardingState').mockImplementation(async () => ({ ok: true, data: currentState }));
  vi.spyOn(client, 'getRegisterState').mockResolvedValue({ ok: true, data: { operator_omni: ready.omni!, bound: true, probe: 'chain' } });
  vi.spyOn(client, 'getChainList').mockResolvedValue({ ok: true, data: { daemonChain: 'test', daemonBroker: 'http://diagnostic.test', chains: [] } });
  vi.spyOn(client, 'getChainInfo').mockResolvedValue({ ok: false, status: { kind: 'disconnected', reason: 'unsupported' } });
  vi.spyOn(client, 'streamAudit').mockReturnValue(() => {});
  vi.spyOn(client, 'listActors').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listRecentAuditEvents').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listMemoryCategories').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listConfigPresets').mockResolvedValue({ ok: true, data: { presets: [], defaultId: '' } });
  vi.spyOn(client, 'listCredentials').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listInbox').mockResolvedValue({ ok: true, data: [] });
  vi.spyOn(client, 'listResources').mockResolvedValue({ ok: true, data: { items: [], storage: 'ok' } });
  vi.spyOn(client, 'listApps').mockResolvedValue({ ok: true, data: { apps: [], storage: 'ok' } });
  vi.spyOn(client, 'listChannels').mockResolvedValue({ ok: true, data: { channels: [], storage: 'ok' } });
  vi.spyOn(client, 'hostedApprovalPending').mockResolvedValue({ ok: true, data: { requests: [] } });
  protectedCalls = ['listMemoryCategories', 'listCredentials', 'listInbox', 'listResources', 'listChannels']
    .map((method) => vi.mocked(client[method as keyof DaemonBackend]) as ReturnType<typeof vi.spyOn>);
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
async function mount() { await act(async () => root.render(<App />)); }
async function click(prefix: string) {
  const button = Array.from(container.querySelectorAll('button')).find((item) => item.textContent?.trim().startsWith(prefix));
  expect(button).toBeDefined();
  await act(async () => button!.click());
}

it('keeps a remembered local onboarding flag from sending protected reads without a session', async () => {
  localStorage.setItem('ak_onboarded', '1');
  await mount();
  expect(container.querySelector('nav[aria-label="sections"]')).toBeNull();
  for (const protectedCall of protectedCalls) expect(protectedCall).not.toHaveBeenCalled();
});
it('requires an active session after identity verification', async () => {
  currentState = { ...ready, session: 'none' };
  await mount();
  expect(container.querySelector('nav[aria-label="sections"]')).toBeNull();
  for (const protectedCall of protectedCalls) expect(protectedCall).not.toHaveBeenCalled();
});
it('requires the chain probe to confirm the current account before opening tabs', async () => {
  currentState = ready;
  vi.mocked(client.getRegisterState).mockResolvedValue({ ok: true, data: { operator_omni: '22'.repeat(32), bound: true, probe: 'chain' } });
  await mount();
  expect(container.querySelector('nav[aria-label="sections"]')).toBeNull();
  expect(container.textContent).toContain('account changed');
  for (const protectedCall of protectedCalls) expect(protectedCall).not.toHaveBeenCalled();
});
it('waits for the chain probe without sending protected reads', async () => {
  currentState = ready;
  let confirmBinding!: (value: Awaited<ReturnType<DaemonBackend['getRegisterState']>>) => void;
  vi.mocked(client.getRegisterState).mockReturnValue(new Promise((resolve) => { confirmBinding = resolve; }));
  await mount();
  expect(container.textContent).toContain('Restoring session');
  for (const protectedCall of protectedCalls) expect(protectedCall).not.toHaveBeenCalled();
  await act(async () => confirmBinding({ ok: true, data: { operator_omni: ready.omni!, bound: true, probe: 'chain' } }));
  expect(container.querySelector('nav[aria-label="sections"]')).not.toBeNull();
});
it('loads the selected page and shows an error instead of an empty credentials store', async () => {
  currentState = ready;
  vi.mocked(client.listCredentials).mockResolvedValue({ ok: false, status: { kind: 'disconnected', reason: 'unreachable', detail: 'vault worker unavailable' } });
  await mount();
  for (const protectedCall of protectedCalls) expect(protectedCall).not.toHaveBeenCalled();
  await click('credentials');
  expect(client.listCredentials).toHaveBeenCalledTimes(1);
  expect(container.textContent).toContain('vault worker unavailable');
  expect(container.textContent).not.toContain('No credentials vaulted yet.');
  await click('Retry');
  expect(client.listCredentials).toHaveBeenCalledTimes(2);
});
it('refreshes page data after a session expires and is restored on another tab', async () => {
  currentState = ready;
  await mount();
  await click('channels');
  expect(client.listChannels).toHaveBeenCalledTimes(1);
  currentState = { ...ready, session: 'expired' };
  await act(async () => { window.dispatchEvent(new Event('focus')); });
  expect(container.querySelector('nav[aria-label="sections"]')).toBeNull();
  currentState = ready;
  await act(async () => { window.dispatchEvent(new Event('focus')); });
  expect(client.listChannels).toHaveBeenCalledTimes(2);
});
it('does not replace recovered data with a late response from the previous session', async () => {
  currentState = ready;
  let finishOldRead!: (value: Result<CredService[]>) => void;
  vi.mocked(client.listCredentials).mockReturnValueOnce(new Promise((resolve) => { finishOldRead = resolve; }));
  await mount();
  await click('credentials');
  expect(container.textContent).toContain('Loading credentials');
  expect(container.textContent).not.toContain('No credentials vaulted yet.');
  currentState = { ...ready, session: 'expired' };
  await act(async () => { window.dispatchEvent(new Event('focus')); });
  currentState = ready;
  vi.mocked(client.listCredentials).mockResolvedValue({ ok: true, data: [{ service: 'existing-service', category: 'ai-services', sensitivity: 'safe' }] });
  await act(async () => { window.dispatchEvent(new Event('focus')); });
  expect(container.textContent).toContain('existing-service');
  await act(async () => finishOldRead({ ok: true, data: [] }));
  expect(container.textContent).toContain('existing-service');
  expect(container.textContent).not.toContain('No credentials vaulted yet.');
});
it('keeps knowledge registry failures visible and retries them', async () => {
  currentState = ready;
  vi.mocked(client.listResources).mockResolvedValueOnce({ ok: false, status: { kind: 'disconnected', reason: 'unreachable', detail: 'resource worker unavailable' } });
  await mount();
  await click('knowledge');
  expect(container.textContent).toContain('resource worker unavailable');
  expect(container.textContent).not.toContain('0 typed items');
  await click('Retry');
  expect(client.listResources).toHaveBeenCalledTimes(2);
  expect(container.textContent).not.toContain('resource worker unavailable');
});
