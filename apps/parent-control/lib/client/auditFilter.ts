import type { Actor, AuditEvent } from '@/app/_components/types';

export interface AuditActorOption {
  id: string;
  label: string;
}

/** #693 — who the audit feed can be filtered to: every delegate (its filter
 *  also brings the delegate's pull passes), then any other actor with a row in
 *  the loaded window. Devices are never delegates. */
export function auditActorOptions(actors: Actor[], events: AuditEvent[]): AuditActorOption[] {
  const options = actors
    .filter((a) => a.role === 'agent' && a.kind !== 'device')
    .map((a) => ({ id: a.id, label: a.label }));
  const seen = new Set(options.map((o) => o.id));
  for (const e of events) {
    if (seen.has(e.actorId)) continue;
    seen.add(e.actorId);
    options.push({ id: e.actorId, label: e.actor });
  }
  return options;
}

/** One actor's rows: its rows from the live stream the last fetch has not seen
 *  yet, then the fetched rows (the daemon's rows for the actor and, for a
 *  delegate, one row per pull pass) — each row once. */
export function actorAuditRows(fetched: AuditEvent[], live: AuditEvent[], actorId: string): AuditEvent[] {
  const ids = new Set(fetched.map((e) => e.id));
  return [...live.filter((e) => e.actorId === actorId && !ids.has(e.id)), ...fetched];
}
