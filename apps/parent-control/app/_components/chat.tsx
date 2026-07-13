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
          setError(r.status?.detail ?? 'chat poll failed');
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
        }
      }
    })();
    return () => {
      stopped = true;
    };
  }, [api, channelId]);

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
      setError(r.status?.detail ?? 'send failed');
      return;
    }
    setDraft('');
  }, [api, channelId, draft, sending]);

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
    </div>
  );
}
