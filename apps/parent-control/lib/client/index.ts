import { CoreBackend } from './core';
import { DaemonBackend } from './daemon';
import { EmptyBackend } from './empty';
import type { AgentKeysClient } from './types';

export type BackendKind = 'empty' | 'daemon' | 'core';

export function selectBackend(): AgentKeysClient {
  const kind = (process.env.NEXT_PUBLIC_AGENTKEYS_BACKEND ?? 'empty') as BackendKind;
  if (kind === 'core') {
    // Phone-first host: the WASM core talks to the broker directly (no daemon). X1.
    return new CoreBackend(
      process.env.NEXT_PUBLIC_AGENTKEYS_BROKER_URL ?? 'https://broker.litentry.org',
    );
  }
  if (kind === 'daemon') {
    return new DaemonBackend(process.env.NEXT_PUBLIC_AGENTKEYS_DAEMON_URL);
  }
  return new EmptyBackend();
}

export * from './types';
export { EmptyBackend } from './empty';
export { DaemonBackend } from './daemon';
export { CoreBackend } from './core';
