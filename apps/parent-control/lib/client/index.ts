import { CoreBackend } from './core';
import { DaemonBackend } from './daemon';
import { EmptyBackend } from './empty';
import type { AgentKeysClient } from './types';

export type BackendKind = 'empty' | 'daemon' | 'core';

export function selectBackend(): AgentKeysClient {
  // Default to the local daemon (the desktop host): the browser talks to
  // agentkeys-daemon --ui-bridge on :3114, which reaches the broker + chain.
  // Override with NEXT_PUBLIC_AGENTKEYS_BACKEND=core (phone-first) or =empty.
  const kind = (process.env.NEXT_PUBLIC_AGENTKEYS_BACKEND ?? 'daemon') as BackendKind;
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
