import { describe, expect, it } from 'vitest';
import type { Actor, AuditEvent } from '@/app/_components/types';
import { actorAuditRows, auditActorOptions } from '../client/auditFilter';

const actor = (id: string, label: string, role: Actor['role'], kind?: string): Actor =>
  ({ id, label, role, kind }) as Actor;

const row = (id: string, actorId: string, actorLabel = actorId): AuditEvent => ({
  id,
  ts: '10:00:00',
  actorId,
  actor: actorLabel,
  kind: 'delegate.lifecycle',
  detail: 'pull pass',
  chip: 'memory',
  sev: 'ok',
});

describe('audit feed actor filter (#693)', () => {
  it('lists every delegate, then the other actors that wrote a row, never a device as a delegate', () => {
    const actors = [
      actor('master', 'owner', 'master'),
      actor('agent-chef', 'chef', 'agent', 'delegate'),
      actor('agent-cam', 'cam', 'agent', 'device'),
      actor('agent-old', 'old', 'agent'),
    ];
    const events = [row('e1', 'master', 'owner'), row('e2', 'agent-chef', 'chef'), row('e3', 'agent-cam', 'cam')];
    expect(auditActorOptions(actors, events)).toEqual([
      { id: 'agent-chef', label: 'chef' },
      { id: 'agent-old', label: 'old' },
      { id: 'master', label: 'owner' },
      { id: 'agent-cam', label: 'cam' },
    ]);
  });

  it('shows the live rows the fetch has not seen first, each row once, only for that actor', () => {
    const fetched = [row('pass-2', 'agent-chef'), row('pass-1', 'agent-chef')];
    const live = [row('e-new', 'agent-chef'), row('e-other', 'agent-cam'), row('pass-2', 'agent-chef')];
    expect(actorAuditRows(fetched, live, 'agent-chef').map((e) => e.id)).toEqual(['e-new', 'pass-2', 'pass-1']);
  });
});
