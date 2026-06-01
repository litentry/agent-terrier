'use client';

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { selectBackend } from './client';
import type { AgentKeysClient, ConnectionStatus } from './client/types';

const INITIAL_STATUS: ConnectionStatus = {
  kind: 'disconnected',
  reason: 'no-backend-configured',
  detail:
    'Set NEXT_PUBLIC_AGENTKEYS_BACKEND=daemon and AGENTKEYS_DAEMON_URL to a running agentkeys-daemon to populate this view.',
};

const ClientContext = createContext<AgentKeysClient | null>(null);
const StatusContext = createContext<ConnectionStatus>(INITIAL_STATUS);

export function ClientProvider({ children }: { children: ReactNode }) {
  const client = useMemo(() => selectBackend(), []);
  const [status, setStatus] = useState<ConnectionStatus>(INITIAL_STATUS);

  useEffect(() => {
    let cancelled = false;
    client.status().then((s) => {
      if (!cancelled) setStatus(s);
    });
    return () => {
      cancelled = true;
    };
  }, [client]);

  return (
    <ClientContext.Provider value={client}>
      <StatusContext.Provider value={status}>{children}</StatusContext.Provider>
    </ClientContext.Provider>
  );
}

export function useClient(): AgentKeysClient {
  const c = useContext(ClientContext);
  if (!c) throw new Error('useClient must be used inside <ClientProvider>');
  return c;
}

export function useConnectionStatus(): ConnectionStatus {
  return useContext(StatusContext);
}
