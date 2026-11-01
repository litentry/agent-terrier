import { afterEach, describe, expect, it, vi } from 'vitest';
import { BACKEND_CONFIGURATION_ID, DEFAULT_DAEMON_URL, browserBackendConfiguration,
  serializeBackendConfiguration, serverBackendConfiguration, validateBackendConfiguration } from '../backendConfiguration';

afterEach(() => vi.unstubAllGlobals());

describe('console runtime configuration', () => {
  it('exposes only the selected public origin and shares the native default', () => {
    expect(serverBackendConfiguration({})).toEqual({ kind: 'daemon', url: DEFAULT_DAEMON_URL });
    expect(serverBackendConfiguration({ AGENT_TERRIER_WEB_BACKEND: 'core',
      AGENT_TERRIER_WEB_BROKER_URL: 'http://127.0.0.1:12345/', PRIVATE_CANARY: 'synthetic-do-not-serialize' }))
      .toEqual({ kind: 'core', url: 'http://127.0.0.1:12345' });
    expect(serverBackendConfiguration({ AGENT_TERRIER_WEB_BACKEND: 'empty' })).toEqual({ kind: 'empty', url: null });
  });

  it('rejects ambiguous retired settings, missing core addresses and unknown backends', () => {
    expect(() => serverBackendConfiguration({ NEXT_PUBLIC_AGENTKEYS_BACKEND: 'daemon', AGENT_TERRIER_WEB_BACKEND: 'core' })).toThrow('Build-time');
    expect(() => serverBackendConfiguration({ AGENT_TERRIER_WEB_BACKEND: 'core' })).toThrow();
    expect(() => serverBackendConfiguration({ AGENT_TERRIER_WEB_BACKEND: 'unknown' })).toThrow();
  });

  it('rejects non-origin endpoints, cleartext remote addresses and embedded credentials', () => {
    for (const url of ['http://remote.example.test', 'https://user:synthetic@example.test', 'https://example.test/path',
      'https://example.test/?token=synthetic', 'https://example.test/#fragment', 'javascript:alert(1)', '']) {
      expect(() => validateBackendConfiguration({ kind: 'core', url })).toThrow();
    }
    expect(() => validateBackendConfiguration({ kind: 'core', url: 'https://example.test', bearer: 'synthetic' })).toThrow();
    expect(validateBackendConfiguration({ kind: 'core', url: 'http://[::1]:12345' }).url).toBe('http://[::1]:12345');
  });

  it('uses the same serialized page configuration and refuses absent or malformed data', () => {
    const configuration = { kind: 'core' as const, url: 'https://broker.example.test' };
    const getElementById = vi.fn(() => ({ textContent: serializeBackendConfiguration(configuration) }));
    vi.stubGlobal('document', { getElementById });
    expect(browserBackendConfiguration()).toEqual(configuration);
    expect(getElementById).toHaveBeenCalledWith(BACKEND_CONFIGURATION_ID);
    getElementById.mockReturnValue({ textContent: 'invalid' });
    expect(() => browserBackendConfiguration()).toThrow();
    getElementById.mockReturnValue({ textContent: '' });
    expect(() => browserBackendConfiguration()).toThrow('missing');
  });
});
