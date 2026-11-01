import { useCallback, useEffect, useRef, useState } from 'react';
import { CoreBackend } from './client/core';
import { EmptyBackend } from './client/empty';
import type { AgentKeysClient } from './client/types';
import { ensureActiveStack, getOnboardedFlag } from './identityStore';

const SESSION_CHECK_INTERVAL_MS = 60_000;
type ConsoleSession = {
  phase: 'checking' | 'login' | 'ready' | 'error';
  key: string | null;
  identity?: { email?: string; omni?: string };
  expired?: boolean;
  detail?: string;
};

export function useConsoleSession(client: AgentKeysClient) {
  const demo = client instanceof EmptyBackend;
  const [session, setSession] = useState<ConsoleSession>({ phase: demo ? 'login' : 'checking', key: null });
  const current = useRef(session);
  const requestVersion = useRef(0);
  const sessionGeneration = useRef(0);
  const pending = useRef<Promise<boolean> | null>(null);
  const requiresReauthentication = useRef(false);
  const publish = useCallback((next: ConsoleSession) => {
    current.current = next;
    setSession(next);
  }, []);
  const pause = useCallback((expired = false) => {
    requiresReauthentication.current = true;
    requestVersion.current += 1;
    pending.current = null;
    publish({ phase: 'login', key: null, expired });
  }, [publish]);
  const refresh = useCallback((force = false): Promise<boolean> => {
    if (requiresReauthentication.current && !force) return Promise.resolve(false);
    if (force) requiresReauthentication.current = false;
    if (pending.current && !force) return pending.current;
    const version = ++requestVersion.current;
    const operation = (async () => {
      try {
        await ensureActiveStack(async () => {
          const stack = await client.getChainList();
          return stack.ok ? { chain: stack.data.daemonChain, brokerUrl: stack.data.daemonBroker ?? null } : { chain: null, brokerUrl: null };
        });
        const result = await client.getOnboardingState();
        if (version !== requestVersion.current) return false;
        if (demo) {
          const ready = getOnboardedFlag();
          publish({ phase: ready ? 'ready' : 'login', key: ready ? 'demo' : null });
          return ready;
        }
        if (!result.ok) {
          publish({ phase: result.status.reason === 'unauthorized' ? 'login' : 'error', key: null, detail: result.status.detail ?? 'Unable to check your session.' });
          return false;
        }
        const snapshot = result.data;
        if (snapshot.identity !== 'verified' || snapshot.session !== 'active') {
          publish({ phase: 'login', key: null, expired: snapshot.session === 'expired' });
          return false;
        }
        if (!snapshot.omni) throw new Error('Your session has no account identity. Sign in again.');
        let registered = snapshot.chain === 'master-registered';
        if (!(client instanceof CoreBackend)) {
          const probe = await client.getRegisterState();
          if (version !== requestVersion.current) return false;
          if (!probe.ok) {
            if (probe.status.reason === 'unauthorized') {
              requiresReauthentication.current = true;
              publish({ phase: 'login', key: null, expired: true });
              return false;
            }
            throw new Error(probe.status.detail ?? 'Unable to verify your master binding.');
          }
          if (probe.data.probe !== 'chain') throw new Error(probe.data.probe_error ?? 'Unable to verify your master binding on chain.');
          const normalizeOmni = (omni: string) => omni.replace(/^0x/, '').toLowerCase();
          if (normalizeOmni(probe.data.operator_omni) !== normalizeOmni(snapshot.omni)) throw new Error('Your account changed while restoring the session. Retry to load the current account.');
          registered = probe.data.bound;
        }
        if (!registered) {
          publish({ phase: 'login', key: null });
          return false;
        }
        const previous = current.current;
        const sameAccount = previous.phase === 'ready' && previous.identity?.omni === snapshot.omni;
        const key = sameAccount ? previous.key : `${++sessionGeneration.current}:${snapshot.omni}`;
        publish({ phase: 'ready', key, identity: { email: snapshot.email, omni: snapshot.omni } });
        return true;
      } catch (error) {
        if (version === requestVersion.current) publish({ phase: 'error', key: null, detail: (error as Error).message });
        return false;
      } finally {
        if (version === requestVersion.current) pending.current = null;
      }
    })();
    pending.current = operation;
    return operation;
  }, [client, demo, publish]);

  useEffect(() => {
    publish({ phase: 'checking', key: null });
    void refresh();
    const check = () => { void refresh(); };
    const visible = () => { if (document.visibilityState === 'visible') check(); };
    const timer = setInterval(check, SESSION_CHECK_INTERVAL_MS);
    window.addEventListener('focus', check);
    document.addEventListener('visibilitychange', visible);
    return () => {
      requestVersion.current += 1;
      pending.current = null;
      clearInterval(timer);
      window.removeEventListener('focus', check);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [refresh, publish]);
  return { ...session, demo, refresh, pause };
}
