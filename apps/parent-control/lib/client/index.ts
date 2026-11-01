import { CoreBackend } from './core';
import { DaemonBackend } from './daemon';
import { EmptyBackend } from './empty';
import type { AgentKeysClient } from './types';
import { validateBackendConfiguration, type BackendConfiguration } from '../backendConfiguration';

export function selectBackend(value: BackendConfiguration): AgentKeysClient {
  const configuration = validateBackendConfiguration(value);
  if (configuration.kind === 'core') return new CoreBackend(configuration.url);
  if (configuration.kind === 'daemon') return new DaemonBackend(configuration.url);
  return new EmptyBackend();
}

export * from './types';
export { EmptyBackend } from './empty';
export { DaemonBackend } from './daemon';
export { CoreBackend } from './core';
