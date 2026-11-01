export type BackendConfiguration =
  | { kind: 'daemon' | 'core'; url: string }
  | { kind: 'empty'; url: null };

export const DEFAULT_DAEMON_URL = 'http://localhost:3114';
export const BACKEND_CONFIGURATION_ID = 'terrier-backend-configuration';

export function validateBackendConfiguration(value: unknown): BackendConfiguration {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid console backend configuration');
  const configuration = value as Record<string, unknown>;
  if (Object.keys(configuration).sort().join(',') !== 'kind,url') throw new Error('Unexpected console backend configuration fields');
  if (configuration.kind === 'empty' && configuration.url === null) return { kind: 'empty', url: null };
  if (!['daemon', 'core'].includes(String(configuration.kind)) || typeof configuration.url !== 'string') throw new Error('Invalid console backend configuration');
  let url: URL;
  try { url = new URL(configuration.url); } catch { throw new Error('Invalid console backend URL'); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      !(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    throw new Error('Console backend must be an HTTPS or loopback HTTP origin without credentials');
  }
  return { kind: configuration.kind as 'daemon' | 'core', url: url.origin };
}

export function serverBackendConfiguration(environment: Record<string, string | undefined>): BackendConfiguration {
  if (['BACKEND', 'BROKER_URL', 'DAEMON_URL'].some((name) => environment[`NEXT_PUBLIC_AGENTKEYS_${name}`] !== undefined)) {
    throw new Error('Build-time backend settings are unsupported; use AGENT_TERRIER_WEB_* at server startup');
  }
  const kind = environment.AGENT_TERRIER_WEB_BACKEND ?? 'daemon';
  const url = kind === 'empty' ? null : kind === 'core'
    ? environment.AGENT_TERRIER_WEB_BROKER_URL
    : environment.AGENT_TERRIER_WEB_DAEMON_URL ?? DEFAULT_DAEMON_URL;
  return validateBackendConfiguration({ kind, url });
}

export function serializeBackendConfiguration(configuration: BackendConfiguration): string {
  return JSON.stringify(validateBackendConfiguration(configuration)).replace(/</g, '\\u003c');
}

export function browserBackendConfiguration(): BackendConfiguration {
  if (typeof document === 'undefined') throw new Error('Console backend configuration is unavailable');
  const serialized = document.getElementById(BACKEND_CONFIGURATION_ID)?.textContent;
  if (!serialized) throw new Error('Console backend configuration is missing; reload the page');
  return validateBackendConfiguration(JSON.parse(serialized));
}
