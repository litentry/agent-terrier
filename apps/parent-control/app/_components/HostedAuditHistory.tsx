"use client";

import { useEffect, useRef, useState, type ComponentProps } from 'react';
import type { AgentKeysClient } from '@/lib/client/types';
import type { AuditEvent } from './types';
import { AuditFeed } from './dashboard';

const AUDIT_REFRESH_INTERVAL_MS = 30_000;

function mergeEvents(newer: AuditEvent[], older: AuditEvent[]): AuditEvent[] {
  return [...new Map([...older, ...newer].map((event) => [event.id, event])).values()]
    .sort((first, second) => second.ts.localeCompare(first.ts) || second.id.localeCompare(first.id, undefined, { numeric: true }));
}

export function HostedAuditHistory({ client, ...feed }: ComponentProps<typeof AuditFeed> & { client: AgentKeysClient }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const paused = useRef(feed.paused);
  paused.current = feed.paused;
  const [reload, setReload] = useState(0);
  const actorId = feed.actorFilter === 'all' ? undefined : feed.actorFilter;

  useEffect(() => {
    const current = ++generation.current;
    let initialized = false;
    let reading = false;
    setEvents([]);
    setCursor(null);
    setError(null);
    setLoading(true);
    setLoadingOlder(false);
    const read = async () => {
      if (reading) return;
      reading = true;
      const result = await client.listAuditPage({ actorId, limit: 100 });
      reading = false;
      if (current !== generation.current) return;
      setLoading(false);
      if (result.ok) {
        setEvents((previous) => mergeEvents(result.data.events, previous));
        if (!initialized) setCursor(result.data.nextCursor);
        initialized = true;
        setError(null);
      } else {
        setError(result.status.detail ?? 'Could not load audit activity.');
      }
    };
    void read();
    const interval = setInterval(() => { if (!paused.current) void read(); }, AUDIT_REFRESH_INTERVAL_MS);
    return () => { generation.current++; clearInterval(interval); };
  }, [client, actorId, reload]);

  const loadOlder = async () => {
    if (!cursor || loading || loadingOlder) return;
    const current = generation.current;
    setLoadingOlder(true);
    const result = await client.listAuditPage({ actorId, limit: 100, cursor });
    if (current !== generation.current) return;
    setLoadingOlder(false);
    if (result.ok) {
      setEvents((previous) => mergeEvents(previous, result.data.events));
      setCursor(result.data.nextCursor);
      setError(null);
    } else {
      setError(result.status.detail ?? 'Could not load older audit activity.');
    }
  };

  return <>
    {error && <div role="alert"><p>{error}</p>{!cursor && <button type="button" className="btn" onClick={() => setReload((value) => value + 1)}>Retry activity</button>}</div>}
    {loading && <p role="status">Loading audit activity…</p>}
    <AuditFeed {...feed} source="chain" events={events} actorRows={loading ? null : events} />
    {cursor && <button type="button" className="btn btn-secondary" disabled={loadingOlder} onClick={() => void loadOlder()}>
      {loadingOlder ? 'Loading older activity…' : 'Load older activity'}
    </button>}
  </>;
}
