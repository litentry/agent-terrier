'use client';
// #430 (epic #425 S4) — the direct operator chat surface: the transcript IS
// the delegate's operator-owned duplex feed (D8; D13: operator session only —
// the daemon proxy refuses anything else). Sends publish `direction: in`;
// the delegate's in-sandbox loop replies `direction: out`; an NRT long-poll
// keeps the transcript live (§14.12 — sub-second on the awake path).

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ApiChatEvent } from '@/lib/generated/ApiChatEvent';
import { useClient } from '@/lib/ClientProvider';

export function ChatPanel({
  channelId,
  readOnly = false,
  emptyHint,
}: {
  channelId: string;
  /** #431 Feeds tab reuses this as the history browser (no composer). */
  readOnly?: boolean;
  emptyHint?: string;
}) {
  const api = useClient();
  const [events, setEvents] = useState<ApiChatEvent[]>([]);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const cursorRef = useRef('');
  const scrollRef = useRef<HTMLDivElement | null>(null);

  // A publish and a reply are two INDEPENDENT halves: the send writes to the
  // feed, a delegate has to be alive, subscribed, and willing to answer for
  // anything to come back. When a message just sat there with a silent panel
  // you could not tell which half failed. These few lines separate them; the
  // poll ticks themselves are deliberately NOT logged (pure noise).
  const [log, setLog] = useState<{ at: string; line: string }[]>([]);
  const addLog = useCallback((line: string) => {
    const at = new Date().toLocaleTimeString();
    setLog((prev) => [...prev.slice(-11), { at, line }]);
  }, []);
  /** Unix ms of the last send still awaiting a reply (ref: the poll loop is a
   *  long-lived closure and would capture stale state). */
  const awaitingRef = useRef<number | null>(null);

  // The poll loop: first call drains history (wait 0), then long-polls.
  useEffect(() => {
    let stopped = false;
    cursorRef.current = '';
    setEvents([]);
    setError(null);
    (async () => {
      let first = true;
      while (!stopped) {
        const r = await api.chatPoll(channelId, cursorRef.current, first ? 0 : 25);
        if (stopped) return;
        if (!r.ok) {
          const detail = r.status?.detail ?? 'chat poll failed';
          setError(detail);
          addLog(`poll failed — ${detail}`);
          await new Promise((res) => setTimeout(res, 5000));
          continue;
        }
        setError(null);
        first = false;
        if (r.data.cursor) cursorRef.current = r.data.cursor;
        if (r.data.events.length > 0) {
          setEvents((prev) => {
            const seen = new Set(prev.map((e) => e.event_id));
            const fresh = r.data.events.filter((e) => !seen.has(e.event_id));
            return fresh.length ? [...prev, ...fresh] : prev;
          });
          if (awaitingRef.current && r.data.events.some((e) => e.direction === 'out')) {
            const secs = ((Date.now() - awaitingRef.current) / 1000).toFixed(1);
            awaitingRef.current = null;
            addLog(`agent replied (${secs}s)`);
          }
        }
        // Publish worked, polling works, still nothing back: the missing piece
        // is a LISTENER, not the plumbing. Say so once rather than leaving the
        // panel silent — this is the state a message sits in forever.
        if (awaitingRef.current && Date.now() - awaitingRef.current > 30_000) {
          awaitingRef.current = null;
          addLog(
            'no agent reply after 30s — the message IS in the feed; check a delegate is running and holds channel-sub on this channel',
          );
        }
      }
    })();
    return () => {
      stopped = true;
    };
  }, [api, channelId, addLog]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [events.length]);

  const send = useCallback(async () => {
    const text = draft.trim();
    if (!text || sending) return;
    setSending(true);
    const r = await api.chatSend(channelId, text);
    setSending(false);
    if (!r.ok) {
      const detail = r.status?.detail ?? 'send failed';
      setError(detail);
      addLog(`send failed — ${detail}`);
      return;
    }
    addLog(`sent → ${channelId} (event ${r.data.event_id.slice(0, 12)}…)`);
    awaitingRef.current = Date.now();
    setDraft('');
  }, [api, channelId, draft, sending, addLog]);

  return (
    <div className="chat-panel" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {error && (
        <div className="callout warn" role="alert">
          {error}
        </div>
      )}
      <div
        ref={scrollRef}
        style={{
          maxHeight: 360,
          minHeight: 160,
          overflowY: 'auto',
          border: '1px solid var(--rule)',
          borderRadius: 8,
          padding: 10,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        {events.length === 0 && (
          <div className="muted" style={{ fontSize: 13 }}>
            {emptyHint ?? 'No messages yet — say hello. The full history lives in this durable feed.'}
          </div>
        )}
        {events.map((e) => (
          <div
            key={e.event_id}
            style={{
              alignSelf: e.direction === 'in' ? 'flex-end' : 'flex-start',
              maxWidth: '82%',
              padding: '6px 10px',
              borderRadius: 10,
              background: e.direction === 'in' ? 'var(--accent)' : 'var(--bg)',
              border: '1px solid var(--rule)',
              whiteSpace: 'pre-wrap',
              fontSize: 14,
            }}
            title={`${e.direction === 'in' ? 'you' : 'agent'} · ${new Date(e.ts_millis).toLocaleString()}`}
          >
            {e.text}
          </div>
        ))}
      </div>
      {!readOnly && (
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void send();
              }
            }}
            placeholder="Message the agent…"
            style={{ flex: 1 }}
          />
          <button className="btn primary" onClick={() => void send()} disabled={sending || !draft.trim()}>
            {sending ? 'Sending…' : 'Send'}
          </button>
        </div>
      )}
      {!readOnly && log.length > 0 && (
        <details open>
          <summary className="muted" style={{ fontSize: 11.5, cursor: 'pointer' }}>
            log · send + reply path
          </summary>
          <div
            className="mono"
            style={{
              marginTop: 4,
              padding: '6px 8px',
              border: '1px solid var(--rule)',
              borderRadius: 6,
              fontSize: 11,
              lineHeight: 1.5,
              maxHeight: 120,
              overflowY: 'auto',
            }}
          >
            {log.map((l, i) => (
              <div key={`${l.at}-${i}`}>
                <span className="muted">{l.at}</span> {l.line}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
