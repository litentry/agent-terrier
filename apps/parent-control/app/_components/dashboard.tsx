'use client';

import { useEffect, useState } from 'react';
import { CHIP_STYLES, NAMESPACES } from '@/lib/constants';
import type { ConnectionStatus } from '@/lib/client/types';
import { AgentTabsPanel } from './agent_tabs';
import { AutoDistributePanel, PermissionList } from './permissions';
import type { ProposedScope } from '@/lib/client/types';
import { ActorTree, Chip, Dot, EmptyState, PageHead, Panel } from './shared';
import type { Actor, AuditEvent, ChipKind, Namespace, ScopeBits } from './types';
import { actorIsChannelEndpoint, isChannelService } from './types';

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
                  {/* #404 D6 — channel-endpoint devices are visibly a different
                      kind from sandbox delegates (no runtime, channel grants only). */}
                  {actorIsChannelEndpoint(a) && <Chip kind="device">device</Chip>}
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
  onCommitScope,
  onRevoke,
  recentEvents,
  proposals,
  proposing,
  onPropose,
  onConfirmProposal,
  onConfirmSafe,
  onResetMaster,
}: {
  actor: Actor;
  onBack: () => void;
  onUpdate: (id: string, patch: Partial<Actor>) => void;
  /** #248: commit the staged memory grant on chain — ONE setScope UserOp signed
   *  by the master K11 (Touch ID). Resolves true on success (clears staging). */
  onCommitScope: (a: Actor, services: string[], readOnly: boolean) => Promise<boolean>;
  onRevoke: (a: Actor) => void;
  recentEvents: AuditEvent[];
  proposals: ProposedScope[] | null;
  proposing: boolean;
  onPropose: (a: Actor) => void;
  onConfirmProposal: (a: Actor, p: ProposedScope) => void;
  onConfirmSafe: (a: Actor, ps: ProposedScope[]) => void;
  /** #225 E7: unbind the master (local + on-chain) so a fresh passkey re-binds. Master only. */
  onResetMaster?: () => void;
}) {
  const events = recentEvents.filter((e) => e.actorId === actor.id).slice(0, 6);
  const isMaster = actor.role === 'master';
  // #404 D6 — a channel-endpoint device: binding + channel grants only (no
  // persona, no memory scopes, no auto-distribution — those are delegate/runtime
  // concepts a conduit cannot hold).
  const isDevice = actorIsChannelEndpoint(actor);

  // #248 — memory toggles STAGE locally (the chain mirror would overwrite an
  // optimistic write on the next refetch); the commit bar lands them on chain
  // with one Touch ID. `null` = no staged changes (panel shows the chain truth).
  const [stagedScope, setStagedScope] = useState<Record<Namespace, ScopeBits> | null>(null);
  const [committing, setCommitting] = useState(false);
  useEffect(() => {
    setStagedScope(null); // switching actors drops any uncommitted staging
  }, [actor.id]);

  const chainScope = (actor.scope ?? {}) as Record<Namespace, ScopeBits>;
  const effectiveScope = stagedScope ?? chainScope;

  const setScope = (ns: Namespace | '__email', v: ScopeBits | boolean) => {
    if (ns === '__email') {
      const services = new Set(actor.services ?? []);
      if (v) services.add('email'); else services.delete('email');
      onUpdate(actor.id, { services: [...services] });
      return;
    }
    setStagedScope({ ...effectiveScope, [ns]: v as ScopeBits });
  };

  // The staged grant as on-chain services: every namespace with read or write.
  // The chain grant carries ONE read-only bit for the whole set, so any staged
  // r+w commits the set as read+write (the bar says which before Touch ID).
  // #339 — two INDEPENDENT grants per namespace: read → memory:<ns> (read the
  // master's shared memory), write → inbox:<ns> (write/suggest into the master's
  // inbox). No direct shared-memory write exists, so there is no r+w ladder.
  const stagedRead = stagedScope
    ? NAMESPACES.filter((ns) => stagedScope[ns]?.read)
    : [];
  const stagedWrite = stagedScope
    ? NAMESPACES.filter((ns) => stagedScope[ns]?.write)
    : [];
  const stagedDirty =
    stagedScope !== null &&
    NAMESPACES.some((ns) => {
      const a = chainScope[ns] ?? { read: false, write: false };
      const b = stagedScope[ns] ?? { read: false, write: false };
      return a.read !== b.read || a.write !== b.write;
    });

  const commitStaged = async () => {
    if (!stagedScope || committing) return;
    setCommitting(true);
    const ok = await onCommitScope(
      actor,
      [
        ...stagedRead.map((ns) => `memory:${ns}`),
        ...stagedWrite.map((ns) => `inbox:${ns}`),
      ],
      // The on-chain readOnly bit is a dead flag (isServiceInScope ignores it);
      // shared memory is read-only to a delegate and contribution is via the inbox
      // grant, so pass a fixed value rather than surface a toggle for it.
      true,
    );
    setCommitting(false);
    if (ok) setStagedScope(null); // the refetched chain mirror now shows the grant
  };

  return (
    <>
      <PageHead
        crumb={<><a onClick={onBack} style={{ cursor: 'pointer' }}>actors</a> <span className="muted">/</span> {actor.derivation}</>}
        title={<><span className="muted serif">/</span> {actor.label}</>}
        desc={`Bound at ${actor.omni}. Memory scope changes stage locally, then commit on chain with one master Touch ID (setScope · K11).`}
        actions={
          <>
            <button className="btn" onClick={onBack}>← back</button>
            {!isMaster && <button className="btn danger" onClick={() => onRevoke(actor)}>revoke device</button>}
            {isMaster && onResetMaster && (
              <button
                className="btn danger"
                title="Unbind the master so you can re-onboard a fresh passkey (e.g. after deleting the master passkey in your OS password manager). Clears BOTH the local binding AND the on-chain operatorMasterWallet (owner-gated resetMaster). Does NOT delete the OS passkey — do that manually."
                onClick={() => {
                  if (window.confirm('Unbind the master so you can re-onboard a fresh passkey?\n\n• Clears the local binding AND the on-chain operatorMasterWallet (so a fresh passkey can re-bind)\n• Does NOT delete the OS passkey — delete it in System Settings ▸ Passwords\n\nContinue?')) onResetMaster();
                }}
              >
                reset master
              </button>
            )}
          </>
        }
      />

      <Panel title="── binding">
        <dl className="kvs">
          <dt>actor_omni</dt><dd className="mono">{actor.omni} <span className="muted">({actor.omniHex})</span></dd>
          {actor.role === 'master' && (
            <>
              <dt>account</dt>
              <dd className="mono">
                {actor.accountType === 'p256account' && actor.accountAddress ? (
                  <>{actor.accountAddress} <span className="muted">· passkey P256Account (ERC-4337 · operatorMasterWallet)</span></>
                ) : (
                  <span className="muted">not yet bound on chain — complete onboarding to register your master P256Account</span>
                )}
              </dd>
            </>
          )}
          <dt>derivation</dt><dd className="mono">{actor.derivation} <span className="muted">(hard / HDKD)</span></dd>
          <dt>device pubkey</dt><dd className="mono">{actor.devicePubkey} <span className="muted">· K10 secp256k1</span></dd>
          <dt>vendor</dt><dd>{actor.vendor}</dd>
          <dt>device</dt><dd>{actor.device}</dd>
          <dt>K11 user-presence</dt><dd>{actor.k11 ? 'enrolled (master device)' : <span className="muted">none · agents cannot hold K11</span>}</dd>
          <dt>last active</dt><dd>{actor.lastActive}</dd>
        </dl>
      </Panel>

      {/* #404 D6 — a channel-endpoint DEVICE has no runtime: no persona, no
          memory scopes, no auto-distribution. Its page is binding + channel
          grants (managed on the devices page) + activity + revoke. */}
      {isDevice && (
        <Panel title="── channels · this device's grants">
          <div className="muted" style={{ fontSize: 11, marginBottom: 10 }}>
            A device is a conduit — it holds ONLY channel grants (D6), never memory, credentials, or a persona.
            Edit its channels (add / remove / re-direction) on the <strong>devices</strong> page; every change is one on-chain setScope (Touch ID) with an audit receipt.
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(actor.services ?? []).filter(isChannelService).map((s) => (
              <span key={s} className="chip mono">{s}</span>
            ))}
            {(actor.services ?? []).filter(isChannelService).length === 0 && (
              <span className="muted" style={{ fontSize: 11.5 }}>grants on chain — names return once the ids are in the channel registry</span>
            )}
          </div>
        </Panel>
      )}

      {/* #390 — the bound agent's persona editor + live context files. Sandbox
          DELEGATES only: a master has no SOUL.md (it is the hub, not a runtime)
          and a DEVICE has no runtime at all (#404 D6 — personas are a delegate
          concept; a camera cannot hold one). */}
      {!isMaster && !isDevice && <AgentTabsPanel actor={actor} />}

      {!isMaster && !isDevice && (
        <Panel title="── permissions · scoped (mobile-style)">
          <div className="muted" style={{ fontSize: 11, marginBottom: 12 }}>
            Maps to ScopeContract[O_master][{actor.omni}]. Memory toggles stage below; <strong>commit · Touch ID</strong> lands
            them on chain (one setScope, master K11) — until then the chain grant is unchanged.
          </div>
          <PermissionList actor={{ ...actor, scope: effectiveScope }} editable onScopeChange={setScope} />
          {stagedDirty && (
            <div
              className="banner"
              style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
            >
              <span className="lbl">staged</span>
              <span style={{ fontSize: 11.5, flex: '1 1 auto' }}>
                {stagedRead.length === 0 && stagedWrite.length === 0
                  ? 'Revokes every memory + inbox grant (credential / email grants are unchanged).'
                  : [
                      stagedRead.length > 0
                        ? `Reads ${stagedRead.map((ns) => `memory:${ns}`).join(' · ')}.`
                        : '',
                      stagedWrite.length > 0
                        ? `Suggests ${stagedWrite.map((ns) => `inbox:${ns}`).join(' · ')}.`
                        : '',
                    ].filter(Boolean).join(' ')}
                {' '}One on-chain setScope (master K11).
              </span>
              <span style={{ display: 'flex', gap: 8 }}>
                <button className="btn" disabled={committing} onClick={() => setStagedScope(null)}>discard</button>
                <button className="btn primary" disabled={committing} onClick={commitStaged}>
                  {committing ? 'committing…' : 'commit · Touch ID'}
                </button>
              </span>
            </div>
          )}
        </Panel>
      )}

      {!isMaster && !isDevice && (
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
          desc="Real-time stream from the audit-service worker. Tier-1 is off-chain SSE; tier-2 anchors a Merkle root on chain every 2 min. Click any row to decode its on-chain transaction."
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
        desc="Real-time stream from the audit-service worker. Tier-1 is off-chain SSE; tier-2 anchors a Merkle root on chain every 2 min. Click any row to decode its on-chain transaction."
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
