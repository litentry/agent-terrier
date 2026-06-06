'use client';

import { useState } from 'react';
import { CHIP_STYLES, NAMESPACES } from '@/lib/constants';
import type { ConnectionStatus } from '@/lib/client/types';
import { AutoDistributePanel, PermissionList } from './permissions';
import type { ProposedScope } from '@/lib/client/types';
import { ActorTree, Chip, Dot, EmptyState, PageHead, Panel } from './shared';
import type { Actor, AuditEvent, ChipKind, Namespace, ScopeBits } from './types';

// ─── Actors list ─────────────────────────────────────────────────
export function ActorsList({ actors, status, onPick }: { actors: Actor[]; status: ConnectionStatus; onPick: (id: string) => void }) {
  const master = actors.find((a) => a.role === 'master');
  const agents = actors.filter((a) => a.role === 'agent');
  const active = agents.filter((a) => a.lastActive === 'now' || a.lastActive.endsWith('m ago')).length;

  if (actors.length === 0) {
    return (
      <>
        <PageHead
          crumb="actor tree · O_master"
          title={<><span className="muted serif">/</span> actors</>}
          desc="Devices and agents bound to your actor tree. Each row is an HDKD child of your master — its own omni, its own scope, its own wallet."
        />
        <EmptyState
          status={status}
          title="no actors yet"
          hint="Actors load from the daemon (GET /v1/actors). Your master device and any paired agents appear here once a daemon is connected."
        />
      </>
    );
  }

  return (
    <>
      <PageHead
        crumb="actor tree · O_master"
        title={<><span className="muted serif">/</span> actors</>}
        desc="Devices and agents bound to your actor tree. Each row is an HDKD child of your master — its own omni, its own scope, its own wallet."
      />
      <div className="stats">
        <div className="stat"><div className="v">{agents.length}</div><div className="k">agents bound</div></div>
        <div className="stat"><div className="v">{active}</div><div className="k">active now</div></div>
      </div>

      <Panel title="── actor tree" flush>
        <div style={{ padding: '18px 22px' }}>
          {master && <ActorTree actors={actors} onPick={onPick} />}
        </div>
      </Panel>

      <Panel title="── devices · agents" flush>
        <table className="tab">
          <thead>
            <tr><th style={{ width: 32 }} /><th>actor</th><th>derivation</th><th>vendor</th><th>device</th><th>last active</th><th /></tr>
          </thead>
          <tbody>
            {master && (
              <tr className="clickable" onClick={() => onPick(master.id)}>
                <td><Dot status="ok" /></td>
                <td>
                  <span className="serif" style={{ fontStyle: 'italic', fontSize: 14 }}>{master.label}</span>
                  <div className="secondary">{master.omni} · {master.omniHex}</div>
                </td>
                <td className="mono muted">/ (root)</td>
                <td className="muted">self</td>
                <td>{master.device}</td>
                <td className="muted">now</td>
                <td><Chip kind="default">master</Chip></td>
              </tr>
            )}
            {agents.map((a) => (
              <tr key={a.id} className="clickable" onClick={() => onPick(a.id)}>
                <td><Dot status={a.status} pulse={a.lastActive.endsWith('m ago')} /></td>
                <td>
                  <span style={{ fontWeight: 500 }}>{a.label}</span>
                  <div className="secondary">{a.omni}</div>
                </td>
                <td className="mono">{a.derivation}</td>
                <td>{a.vendor}</td>
                <td>{a.device}</td>
                <td className="muted">{a.lastActive}</td>
                <td><button className="btn sm" onClick={(e) => { e.stopPropagation(); onPick(a.id); }}>manage →</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </>
  );
}

// ─── Actor detail — uses the mobile PermissionList (no tables) ────
export function ActorDetail({
  actor,
  onBack,
  onUpdate,
  onRevoke,
  recentEvents,
  proposals,
  proposing,
  onPropose,
  onConfirmProposal,
  onConfirmSafe,
}: {
  actor: Actor;
  onBack: () => void;
  onUpdate: (id: string, patch: Partial<Actor>) => void;
  onRevoke: (a: Actor) => void;
  recentEvents: AuditEvent[];
  proposals: ProposedScope[] | null;
  proposing: boolean;
  onPropose: (a: Actor) => void;
  onConfirmProposal: (a: Actor, p: ProposedScope) => void;
  onConfirmSafe: (a: Actor, ps: ProposedScope[]) => void;
}) {
  const events = recentEvents.filter((e) => e.actorId === actor.id).slice(0, 6);
  const isMaster = actor.role === 'master';

  const setScope = (ns: Namespace | '__email', v: ScopeBits | boolean) => {
    if (ns === '__email') {
      const services = new Set(actor.services ?? []);
      if (v) services.add('email'); else services.delete('email');
      onUpdate(actor.id, { services: [...services] });
      return;
    }
    onUpdate(actor.id, { scope: { ...(actor.scope as Record<Namespace, ScopeBits>), [ns]: v as ScopeBits } });
  };

  return (
    <>
      <PageHead
        crumb={<><a onClick={onBack} style={{ cursor: 'pointer' }}>actors</a> <span className="muted">/</span> {actor.derivation}</>}
        title={<><span className="muted serif">/</span> {actor.label}</>}
        desc={`Bound at ${actor.omni}. All scope + payment-cap settings are master-mutations — each save triggers K11 + chain commit.`}
        actions={
          <>
            <button className="btn" onClick={onBack}>← back</button>
            {!isMaster && <button className="btn danger" onClick={() => onRevoke(actor)}>revoke device</button>}
          </>
        }
      />

      <Panel title="── binding">
        <dl className="kvs">
          <dt>actor_omni</dt><dd className="mono">{actor.omni} <span className="muted">({actor.omniHex})</span></dd>
          <dt>derivation</dt><dd className="mono">{actor.derivation} <span className="muted">(hard / HDKD)</span></dd>
          <dt>device pubkey</dt><dd className="mono">{actor.devicePubkey} <span className="muted">· K10 secp256k1</span></dd>
          <dt>vendor</dt><dd>{actor.vendor}</dd>
          <dt>device</dt><dd>{actor.device}</dd>
          <dt>K11 user-presence</dt><dd>{actor.k11 ? 'enrolled (master device)' : <span className="muted">none · agents cannot hold K11</span>}</dd>
          <dt>last active</dt><dd>{actor.lastActive}</dd>
        </dl>
      </Panel>

      {!isMaster && (
        <Panel title="── permissions · scoped (mobile-style)">
          <div className="muted" style={{ fontSize: 11, marginBottom: 12 }}>
            Maps to ScopeContract[O_master][{actor.omni}]. Changes commit to chain via master K11.
          </div>
          <PermissionList actor={actor} editable onScopeChange={setScope} />
        </Panel>
      )}

      {!isMaster && (
        <AutoDistributePanel
          actor={actor}
          proposals={proposals}
          proposing={proposing}
          onPropose={() => onPropose(actor)}
          onConfirm={(p) => onConfirmProposal(actor, p)}
          onConfirmSafe={(ps) => onConfirmSafe(actor, ps)}
        />
      )}

      <Panel title={`── recent activity · ${actor.label}`} flush>
        {events.length === 0 ? (
          <div style={{ padding: 20 }} className="muted">no activity in this window.</div>
        ) : (
          events.map((e) => (
            <div key={e.id} className="feed-row">
              <span className="ts">{e.ts}</span>
              <span className="actor">{e.actor}</span>
              <span className="msg"><span style={{ fontWeight: 500 }}>{e.kind}</span><span className="arg"> · {e.detail}</span></span>
              <Chip kind={e.chip}>{e.chip}</Chip>
            </div>
          ))
        )}
      </Panel>
    </>
  );
}

// ─── Audit feed — click any row → tx-decode modal (step 9) ────────
export function AuditFeed({
  events,
  status,
  onPick,
  paused,
  onPause,
}: {
  events: AuditEvent[];
  status: ConnectionStatus;
  onPick: (e: AuditEvent) => void;
  paused: boolean;
  onPause: () => void;
}) {
  const [filter, setFilter] = useState<string>('all');
  const filtered = filter === 'all' ? events : events.filter((e) => e.chip === filter);
  const filters: (ChipKind | 'all')[] = ['all', 'memory', 'creds', 'payment', 'audit', 'chain', 'broker'];

  if (events.length === 0) {
    return (
      <>
        <PageHead
          crumb="tier-1 · sse · audit-service · decodable on click"
          title={<><span className="muted serif">/</span> audit feed</>}
          desc="Real-time stream from the audit-service worker. Tier-1 is off-chain SSE; tier-2 anchors a Merkle root on chain every 2 min. Click any row to decode its Heima transaction."
        />
        <EmptyState
          status={status}
          title="no audit events"
          hint="The feed streams from the daemon (GET /v1/audit + SSE). Events appear here once a daemon is connected and actors are active."
        />
      </>
    );
  }

  return (
    <>
      <PageHead
        crumb="tier-1 · sse · audit-service · decodable on click"
        title={<><span className="muted serif">/</span> audit feed</>}
        desc="Real-time stream from the audit-service worker. Tier-1 is off-chain SSE; tier-2 anchors a Merkle root on chain every 2 min. Click any row to decode its Heima transaction."
        actions={<button className="btn sm" onClick={onPause}>{paused ? '▶ resume' : '❚❚ pause'}</button>}
      />
      <Panel
        title="── stream · newest first · click to decode"
        right={
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {filters.map((f) => (
              <button key={f} className={`btn sm ${filter === f ? 'primary' : ''}`} onClick={() => setFilter(f)}>{f}</button>
            ))}
          </div>
        }
        flush
      >
        <div className="feed">
          {filtered.map((e) => (
            <div key={e.id} className={`feed-row ${e._isNew ? 'new' : ''}`} onClick={() => onPick(e)}>
              <span className="ts">{e.ts}</span>
              <span className="actor">{e.actor}</span>
              <span className="msg"><span style={{ fontWeight: 500 }}>{e.kind}</span><span className="arg"> · {e.detail}</span></span>
              <span className={CHIP_STYLES[e.chip] ?? 'chip'}>{e.chip}</span>
            </div>
          ))}
          {filtered.length === 0 && <div style={{ padding: 40, textAlign: 'center' }} className="muted">no events match this filter.</div>}
        </div>
      </Panel>
    </>
  );
}
