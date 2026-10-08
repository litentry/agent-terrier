import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { App } from '../../app/_components/App';
import { ChainBadge } from '../../app/_components/ChainBadge';
import { CoreBackend } from '../client/core';
import { EmptyBackend } from '../client/empty';
import type { AgentKeysClient } from '../client/types';

let selectedClient: AgentKeysClient;

vi.mock('../ClientProvider', () => ({
  useClient: () => selectedClient,
  useConnectionStatus: () => ({ kind: 'disconnected', reason: 'no-backend-configured' }),
}));

describe('hosted console preview', () => {
  beforeEach(() => {
    selectedClient = new CoreBackend('https://broker.example.test');
  });

  it('stops before onboarding instead of offering a simulated identity ceremony', () => {
    const markup = renderToStaticMarkup(<App />);
    expect(markup).toContain('Browser sign-in is not available yet.');
    expect(markup).not.toMatch(/<(?:input|form|button)\b/);
    expect(markup).not.toContain('Set up your master identity.');
    expect(markup).not.toContain('Email verified');
  });

  it('does not describe a browser-only preview as a broken local daemon', () => {
    expect(renderToStaticMarkup(<ChainBadge />)).toBe('');
  });

  it('preserves the existing local demo onboarding', () => {
    selectedClient = new EmptyBackend();
    const markup = renderToStaticMarkup(<App />);
    expect(markup).toContain('Set up your master identity.');
    expect(markup).toContain('id="ak-email"');
    expect(markup).not.toContain('Browser sign-in is not available yet.');
    expect(renderToStaticMarkup(<ChainBadge />)).toContain('daemon offline');
  });
});
