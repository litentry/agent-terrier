import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { App } from '../../app/_components/App';
import { ChainBadge } from '../../app/_components/ChainBadge';
import { OnboardingScreen } from '../../app/_components/ceremony';
import { CoreBackend } from '../client/core';
import { EmptyBackend } from '../client/empty';
import type { AgentKeysClient } from '../client/types';

let selectedClient: AgentKeysClient;

vi.mock('../ClientProvider', () => ({
  useClient: () => selectedClient,
  useConnectionStatus: () => ({ kind: 'disconnected', reason: 'no-backend-configured' }),
}));

describe('hosted console admission', () => {
  beforeEach(() => {
    selectedClient = new CoreBackend('https://broker.example.test');
  });

  it('offers email sign-in without exposing demo registration', () => {
    expect(renderToStaticMarkup(<App />)).toContain('Restoring session…');
    const markup = renderToStaticMarkup(<OnboardingScreen onComplete={() => {}} />);
    expect(markup).toContain('Welcome back.');
    expect(markup).toContain('Access is limited to approved email addresses');
    expect(markup).toContain('id="ak-email"');
    expect(markup).not.toContain('Set up your master identity.');
    expect(markup).not.toContain('Email verified');
  });

  it('does not describe a hosted login as a broken local daemon', () => {
    expect(renderToStaticMarkup(<ChainBadge />)).toBe('');
  });

  it('preserves the existing local demo onboarding', () => {
    selectedClient = new EmptyBackend();
    const markup = renderToStaticMarkup(<App />);
    expect(markup).toContain('Set up your master identity.');
    expect(markup).toContain('id="ak-email"');
    expect(markup).not.toContain('Welcome back.');
    expect(renderToStaticMarkup(<ChainBadge />)).toContain('daemon offline');
  });
});
