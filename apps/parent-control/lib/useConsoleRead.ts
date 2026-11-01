import { useEffect, useRef, useState } from 'react';
import type { Result } from './client/types';

type ReadState = { scope: string | null; kind: 'idle' | 'loading' | 'loaded' | 'error'; detail?: string };

export function useConsoleRead<T>(sessionKey: string | null, enabled: boolean, revision: number,
  load: () => Promise<Result<T>>, accept: (data: T) => void, onExpired: () => void) {
  const scope = sessionKey === null ? null : `${sessionKey}:${revision}`;
  const [state, setState] = useState<ReadState>({ scope: null, kind: 'idle' });
  const callbacks = useRef({ accept, onExpired });
  callbacks.current = { accept, onExpired };
  const generation = useRef(0);
  const started = useRef<string | null>(null);

  useEffect(() => {
    generation.current += 1;
    started.current = null;
    return () => { generation.current += 1; started.current = null; };
  }, [scope]);
  useEffect(() => {
    if (!scope || !enabled || started.current === scope) return;
    started.current = scope;
    const requestGeneration = generation.current;
    setState({ scope, kind: 'loading' });
    void (async () => {
      try {
        const result = await load();
        if (requestGeneration !== generation.current) return;
        if (result.ok) {
          callbacks.current.accept(result.data);
          setState({ scope, kind: 'loaded' });
        } else {
          const detail = result.status.detail ?? 'This data could not be loaded.';
          setState({ scope, kind: 'error', detail });
          if (result.status.reason === 'unauthorized' || /session expired|re-?authenticate/i.test(detail)) callbacks.current.onExpired();
        }
      } catch (error) {
        if (requestGeneration === generation.current) setState({ scope, kind: 'error', detail: (error as Error).message });
      }
    })();
  }, [scope, enabled, load]);
  return state.scope === scope ? state : { scope, kind: enabled ? 'loading' as const : 'idle' as const };
}
