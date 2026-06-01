import { DaemonBackend } from './daemon';
import { EmptyBackend } from './empty';
import type { AgentKeysClient } from './types';

export type BackendKind = 'empty' | 'daemon';

export function selectBackend(): AgentKeysClient {
  const kind = (process.env.NEXT_PUBLIC_AGENTKEYS_BACKEND ?? 'empty') as BackendKind;
  if (kind === 'daemon') {
    return new DaemonBackend(process.env.NEXT_PUBLIC_AGENTKEYS_DAEMON_URL);
  }
  return new EmptyBackend();
}

export * from './types';
export { EmptyBackend } from './empty';
export { DaemonBackend } from './daemon';
