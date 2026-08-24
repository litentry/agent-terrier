'use client';

// #631 — dev-only chat surface for the LOCAL dsh test twin
// (docker/dsh-sandbox/run-local.sh). Deliberately OUTSIDE the app shell: no
// daemon, no broker, no identity — it speaks the sandbox bridge contract
// directly through the server-side proxy, so an operator can poke the local
// container from a browser before any remote cycle.

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  LocalSandboxError,
  sandboxChat,
  sandboxHealthz,
  type SandboxHealth,
} from '@/lib/localSandboxClient';

interface Turn {
  role: 'you' | 'twin' | 'error';
  text: string;
  tokens?: number;
}

export default function LocalSandboxPage() {
  const [health, setHealth] = useState<SandboxHealth | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const refreshHealth = useCallback(async () => {
    try {
      setHealth(await sandboxHealthz());
    } catch {
      setHealth(null);
    }
  }, []);

  useEffect(() => {
    void refreshHealth();
    const t = setInterval(() => void refreshHealth(), 5_000);
    return () => clearInterval(t);
  }, [refreshHealth]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [turns]);

  const send = async () => {
    const text = draft.trim();
    if (!text || busy) return;
    setDraft('');
    setTurns((ts) => [...ts, { role: 'you', text }]);
    setBusy(true);
    try {
      const res = await sandboxChat(text);
      setTurns((ts) => [...ts, { role: 'twin', text: res.reply, tokens: res.usage.total_tokens }]);
    } catch (e) {
      const msg = e instanceof LocalSandboxError ? e.message : String(e);
      setTurns((ts) => [...ts, { role: 'error', text: msg }]);
    } finally {
      setBusy(false);
      void refreshHealth();
    }
  };

  const phase = health?.phase ?? 'down';
  const pill =
    phase === 'ready' ? 'var(--ok)' : phase === 'starting' ? 'var(--accent)' : 'var(--danger)';

  return (
    <main style={{ maxWidth: 760, margin: '0 auto', padding: '24px 16px' }}>
      <div className="page-head">
        <div>
          <div className="crumb">dev · local test twin</div>
          <h1 style={{ margin: '4px 0' }}>Local dsh sandbox</h1>
          <div className="desc">
            Chats with the <code>docker/dsh-sandbox</code> container on this machine over the
            sandbox bridge contract — no daemon, no broker, no identity. Dev-time only (#631).
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <span>
            <span
              aria-hidden
              style={{
                display: 'inline-block',
                width: 10,
                height: 10,
                borderRadius: 999,
                background: pill,
                marginRight: 8,
              }}
            />
            {phase === 'down' ? (
              <>sandbox down — start it: <code>bash docker/dsh-sandbox/run-local.sh</code></>
            ) : (
              <>
                {phase} · engine {health?.engine} · model <code>{health?.model}</code>
              </>
            )}
          </span>
        </div>
        <div className="panel-body">
          <div
            ref={logRef}
            style={{
              minHeight: 220,
              maxHeight: 420,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
              padding: '4px 0',
            }}
          >
            {turns.length === 0 && (
              <div className="desc">
                Try: <em>What is the family dog&apos;s name?</em> (after{' '}
                <code>run-local.sh --seed</code>) — the reply proves recall + the LLM leg.
              </div>
            )}
            {turns.map((t, i) => (
              <div key={i} style={{ display: 'flex', gap: 8 }}>
                <strong style={{ minWidth: 42, color: t.role === 'error' ? 'var(--danger)' : 'var(--ink-dim)' }}>
                  {t.role}
                </strong>
                <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {t.text}
                  {t.tokens !== undefined && (
                    <span className="desc" style={{ marginLeft: 8 }}>
                      ({t.tokens} tokens)
                    </span>
                  )}
                </span>
              </div>
            ))}
            {busy && <div className="desc">thinking… (a real-Ark turn with recall can take a while)</div>}
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void send();
            }}
            style={{ display: 'flex', gap: 8, marginTop: 12 }}
          >
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={phase === 'ready' ? 'message the local twin…' : 'sandbox not ready…'}
              disabled={busy}
              style={{ flex: 1, padding: '8px 10px' }}
            />
            <button type="submit" disabled={busy || !draft.trim()}>
              send
            </button>
          </form>
        </div>
      </div>
    </main>
  );
}
