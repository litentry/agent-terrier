'use client';

import { useEffect, useState, type ReactNode } from 'react';
import { NAMESPACES } from '@/lib/constants';
import { Dot, Panel } from './shared';
import type { Actor, Namespace, ScopeBits, VaultItem } from './types';
import { capabilityGrantCommit, isCapabilityService, isChannelService, isPluginService, TOOL_CLASSES, toolService, type ToolClass } from './types';
import type { ProposedScope } from '@/lib/client/types';

// Segmented control: deny | read | read+write
export function PermSeg({
  value,
  onChange,
  disabled,
}: {
  value: ScopeBits;
  onChange: (v: ScopeBits) => void;
  disabled?: boolean;
}) {
  const state = value.write ? 'rw' : value.read ? 'r' : 'off';
  const set = (s: 'off' | 'r' | 'rw') => {
    if (disabled) return;
    if (s === 'off') onChange({ read: false, write: false });
    else if (s === 'r') onChange({ read: true, write: false });
    else onChange({ read: true, write: true });
  };
  return (
    <div className="perm-seg">
      <button className={`deny ${state === 'off' ? 'on' : ''}`} disabled={disabled} onClick={() => set('off')}>deny</button>
      <button className={state === 'r' ? 'on' : ''} disabled={disabled} onClick={() => set('r')}>read</button>
      <button className={state === 'rw' ? 'on' : ''} disabled={disabled} onClick={() => set('rw')}>r+w</button>
    </div>
  );
}

export function PermSwitch({ on, onToggle, locked }: { on: boolean; onToggle?: (v: boolean) => void; locked?: boolean }) {
  return (
    <button
      className={`perm-switch ${on ? 'on' : ''} ${locked ? 'locked' : ''}`}
      onClick={() => !locked && onToggle && onToggle(!on)}
      aria-pressed={on}
      aria-label="toggle permission"
    />
  );
}

function PermRow({
  icon, title, why, state, risk, granted, control, onClick,
}: {
  icon: string;
  title: string;
  why?: string;
  state?: string;
  risk?: 'low' | 'medium' | 'high';
  granted: boolean;
  control: ReactNode;
  onClick?: () => void;
}) {
  return (
    <div className={`perm-row ${granted ? 'granted' : 'denied'} ${onClick ? 'tappable' : ''}`} onClick={onClick}>
      <div className="perm-icon">{icon}</div>
      <div className="perm-body">
        <div className="perm-title">
          {title}
          {risk && risk !== 'low' && <span className={`perm-risk ${risk}`}>{risk}</span>}
        </div>
        {why && <div className="perm-why">{why}</div>}
        {state && <div className="perm-state">{state}</div>}
      </div>
      {control}
    </div>
  );
}

function PermSection({ title, summary, children }: { title: string; summary?: string; children: ReactNode }) {
  return (
    <div className="perm-section">
      <div className="perm-section-head">
        <span className="ttl">{title}</span>
        {summary && <span className="summary">{summary}</span>}
      </div>
      <div className="perm-rows">{children}</div>
    </div>
  );
}

const NS_ICON: Record<Namespace, string> = { personal: 'p', family: 'f', work: 'w', travel: 't' };
const NS_WHY: Record<Namespace, string> = {
  personal: 'Private memories — diaries, preferences, individual profile',
  family: 'Shared household memories — schedules, lists, routines',
  work: 'Work context — projects, calendars, credentials',
  travel: 'Trip context — locations, bookings, itineraries',
};

// Mobile-style scoped permission list (replaces the table view). The "tables won't scale" ask.
// #617 — owner-language labels for the tool classes. The rows say what the
// delegate may DO, never how the runtime enforces it (the state line carries
// the service string for operators who want it).
const CAP_ICON: Record<string, string> = { web: '\u2601', code: '\u2328', schedule: '\u23f1' };
const CAP_TITLE: Record<string, string> = {
  web: 'Web access',
  code: 'Code execution',
  schedule: 'Scheduled reports',
};
const CAP_WHY: Record<string, string> = {
  web: 'let it fetch pages and search the web while working on your task',
  code: 'let it run code and shell commands inside its own sandbox',
  schedule: 'let it run on a schedule (a daily report) without you asking each time',
};

export function PermissionList({
  actor,
  editable,
  vaultItems = [],
  onScopeChange,
  onPaymentTap,
  onCredTap,
  onCapabilityChange,
}: {
  actor: Actor;
  editable: boolean;
  vaultItems?: VaultItem[];
  onScopeChange?: (ns: Namespace | '__email', v: ScopeBits | boolean) => void;
  onPaymentTap?: () => void;
  onCredTap?: (v: VaultItem) => void;
  /** #617 — a capability toggle IS a grant: the handler runs the same setScope
   *  ceremony the memory toggles do. Absent ⇒ the section renders read-only. */
  onCapabilityChange?: (svc: string, granted: boolean) => void;
}) {
  const scope = actor.scope ?? ({} as Record<Namespace, ScopeBits>);
  const services = actor.services ?? [];
  const memGranted = NAMESPACES.filter((ns) => scope[ns] && (scope[ns].read || scope[ns].write));
  const vaultForActor = vaultItems.filter((v) => v.actor === actor.id);
  const hasEmail = services.includes('email');
  const hasPay = (actor.paymentCap?.perTx ?? 0) > 0;
  // #408 D2 — per-direction channel grants (channel-pub:<id> = produce into,
  // channel-sub:<id> = consume from). Shown read-only here for a CONSISTENT
  // permission picture; grant edits live on the channels page (devices) / the
  // staged scope commit (delegates).
  const channelGrants = services.filter(isChannelService);
  // #614 — capability grants (`tool:<class>` / `plugin:<id>`): what the delegate's
  // runtime may ATTEMPT (guard/preset-compiled), never a data-plane grant. Shown
  // read-only here; the grant/revoke editor ships with the runtime UI (#617).
  const capabilityGrants = services.filter(isCapabilityService);
  // #617 — the two halves render differently BECAUSE they mean different things:
  // a tool class is a live policy the owner controls; a plugin mount is a fact of
  // what the app was built from (install-batch, iOS-framework-like) and is
  // disclosure only. Never offer a toggle that cannot take effect.
  const grantedTools = new Set(
    capabilityGrants.filter((s) => !isPluginService(s)).map((s) => s.toLowerCase()),
  );
  const pluginGrants = capabilityGrants.filter(isPluginService);

  return (
    <div className="perm-list">
      {/* CHANNELS */}
      {channelGrants.length > 0 && (
        <PermSection title="Channels" summary={`${channelGrants.length} grant${channelGrants.length === 1 ? '' : 's'}`}>
          {channelGrants.map((svc) => {
            const pub = svc.toLowerCase().startsWith('channel-pub:');
            const id = svc.split(':').slice(1).join(':');
            return (
              <PermRow
                key={svc}
                icon={pub ? '↥' : '↧'}
                title={id}
                why={pub ? 'publish — this actor produces events into the channel feed' : 'subscribe — this actor consumes events from the channel feed'}
                state={`${svc} · cap-gated · worker chain re-verify (§17.5)`}
                granted={true}
                control={<span className="perm-readonly on">{pub ? 'pub' : 'sub'}</span>}
              />
            );
          })}
        </PermSection>
      )}
      {/* CAPABILITIES (#614 vocabulary, #617 owner control) */}
      {(editable || capabilityGrants.length > 0) && (
        <PermSection
          title="Capabilities"
          summary={`${grantedTools.size} of ${TOOL_CLASSES.length} tool classes`}
        >
          {TOOL_CLASSES.map((cls: ToolClass) => {
            const svc = toolService(cls);
            const on = grantedTools.has(svc.toLowerCase());
            return (
              <PermRow
                key={svc}
                icon={CAP_ICON[cls]}
                title={CAP_TITLE[cls]}
                why={CAP_WHY[cls]}
                state={`${svc} · in-loop guard · never cap-mintable`}
                granted={on}
                control={
                  editable && onCapabilityChange ? (
                    <PermSwitch on={on} onToggle={(v) => onCapabilityChange(svc, v)} />
                  ) : (
                    <span className={`perm-readonly ${on ? 'on' : ''}`}>{on ? 'on' : 'off'}</span>
                  )
                }
              />
            );
          })}
          {pluginGrants.map((svc) => (
            <PermRow
              key={svc}
              icon="▦"
              title={svc.split(':').slice(1).join(':')}
              why="built with — a capability provider this app is composed from, granted with the install batch"
              state={`${svc} · disclosure, not a switch`}
              granted={true}
              control={<span className="perm-readonly on">built in</span>}
            />
          ))}
        </PermSection>
      )}
      {/* MEMORY */}
      <PermSection title="Knowledge access" summary={`${memGranted.length} of ${NAMESPACES.length} namespaces`}>
        {NAMESPACES.map((ns) => {
          const s = scope[ns] || { read: false, write: false };
          const granted = s.read || s.write;
          const lvl = s.read && s.write ? 'reads shared · suggests'
            : s.read ? 'reads shared'
            : s.write ? 'suggests to inbox'
            : 'no access';
          return (
            <PermRow
              key={ns}
              icon={NS_ICON[ns]}
              title={ns}
              why={NS_WHY[ns]}
              state={`scope · ${lvl}`}
              granted={granted}
              control={
                editable ? (
                  // Two INDEPENDENT grants per namespace (#339), not a deny/read/r+w
                  // ladder: read = knowledge:<ns> (read the master's shared memory) ·
                  // write = proposal:<ns> (write/suggest into the master's inbox, which
                  // the master curates — NEVER a direct shared-memory write).
                  <div className="perm-rw">
                    <button
                      type="button"
                      className={`perm-tog ${s.read ? 'on' : ''}`}
                      aria-pressed={s.read}
                      title="READ — let this delegate read your shared knowledge for this namespace (knowledge:<ns>)."
                      onClick={() => onScopeChange && onScopeChange(ns, { read: !s.read, write: s.write })}
                    >read</button>
                    <button
                      type="button"
                      className={`perm-tog ${s.write ? 'on' : ''}`}
                      aria-pressed={s.write}
                      title="WRITE — let this delegate write/suggest into your inbox for this namespace (proposal:<ns>); you curate each one. The delegate never writes your shared knowledge directly."
                      onClick={() => onScopeChange && onScopeChange(ns, { read: s.read, write: !s.write })}
                    >write</button>
                  </div>
                ) : (
                  <span className="perm-rw perm-rw-ro">
                    <span className={`perm-tog ${s.read ? 'on' : ''}`}>read</span>
                    <span className={`perm-tog ${s.write ? 'on' : ''}`}>write</span>
                  </span>
                )
              }
            />
          );
        })}
      </PermSection>

      {/* CREDENTIALS */}
      <PermSection title="Credentials" summary={`${vaultForActor.length} vaulted`}>
        {vaultForActor.length === 0 && (
          <PermRow icon="$" title="No credentials" why="This agent holds no API credentials in the vault." granted={false} control={<span className="perm-readonly off">none</span>} />
        )}
        {vaultForActor.map((v) => (
          <PermRow
            key={v.service}
            icon="$"
            title={v.service}
            why={`Class-B bearer token · decrypt-on-read · ${v.readCount} reads (24h)`}
            state={`s3 envelope ${v.version} · ${v.bytes} bytes`}
            risk="medium"
            granted={v.status === 'ok'}
            onClick={onCredTap ? () => onCredTap(v) : undefined}
            control={<span className={`perm-readonly ${v.status === 'ok' ? 'on' : 'off'}`}>{v.status === 'ok' ? 'cred:r' : 'stale'}</span>}
          />
        ))}
      </PermSection>

      {/* PAYMENTS */}
      <PermSection title="Payments" summary={hasPay ? `≤ $${actor.paymentCap!.perTx}/tx` : 'disabled'}>
        <PermRow
          icon="¤"
          title="Spend on your behalf"
          why={hasPay ? 'Class-C one-shot CAS-burn cap. Above per-tx limit requires your Touch ID.' : 'This agent cannot initiate any payment.'}
          state={hasPay
            ? `per-tx ≤ ${actor.paymentCap!.perTx} ${actor.paymentCap!.currency} · daily ≤ ${actor.paymentCap!.daily} · ${actor.timeWindow?.start}–${actor.timeWindow?.end}`
            : 'no payment cap minted'}
          risk="high"
          granted={hasPay}
          onClick={editable && onPaymentTap ? onPaymentTap : undefined}
          control={
            editable
              ? <span className="perm-readonly">{hasPay ? 'edit caps' : 'set cap'}</span>
              : <span className={`perm-readonly ${hasPay ? 'on' : 'off'}`}>{hasPay ? 'capped' : 'off'}</span>
          }
        />
      </PermSection>

      {/* COMMUNICATION */}
      <PermSection title="Communication" summary={hasEmail ? 'email enabled' : 'disabled'}>
        <PermRow
          icon="@"
          title="Send + receive email"
          why="Outbound via your operator domain (DKIM). Inbound to a per-actor sub-address."
          state={hasEmail ? 'mail:send · mail:inbox granted' : 'no mail scope'}
          risk="high"
          granted={hasEmail}
          control={
            editable
              ? <PermSwitch on={hasEmail} onToggle={(v) => onScopeChange && onScopeChange('__email', v)} />
              : <span className={`perm-readonly ${hasEmail ? 'on' : 'off'}`}>{hasEmail ? 'on' : 'off'}</span>
          }
        />
      </PermSection>

      {/* SYSTEM */}
      <PermSection title="System" summary="required">
        <PermRow
          icon="◈"
          title="Write its own audit log"
          why="Append-only tamper-evident log. Required for every actor — cannot be disabled."
          state="audit:append · tier-1 SSE + tier-2 anchor"
          granted={true}
          control={<PermSwitch on={true} locked />}
        />
      </PermSection>
    </div>
  );
}

// #207 items 5 + 7 — connect-time auto-distribution. Classify the agent's
// surface (the cred services it uses) → categories, then PROPOSE scopes tiered by
// the catalog's sensitivity: `auto` (Safe → auto-confirm + daily review) vs `k11`
// (Sensitive → explicit per-grant Touch ID). The proposal writes NOTHING; the
// master confirms, and only the K11-gated grant path writes scope — so an
// unconfirmed sensitive category never becomes a grant (the load-bearing invariant).
export function AutoDistributePanel({
  actor,
  proposals,
  proposing,
  onPropose,
  onConfirm,
  onConfirmSafe,
}: {
  actor: Actor;
  proposals: ProposedScope[] | null;
  proposing: boolean;
  onPropose: () => void;
  onConfirm: (p: ProposedScope) => void;
  onConfirmSafe: (ps: ProposedScope[]) => void;
}) {
  const safe = (proposals ?? []).filter((p) => p.gating === 'auto');
  const sensitive = (proposals ?? []).filter((p) => p.gating === 'k11');

  return (
    <Panel title="── connect-time auto-distribution">
      <div className="muted" style={{ fontSize: 11, marginBottom: 12 }}>
        The classifier tags this agent&apos;s surface — the master <strong>knowledge namespaces</strong> it can inherit and the{' '}
        <strong>credential services</strong> it uses — into categories and proposes scopes. <strong>Safe</strong> categories
        auto-confirm into your daily review; <strong>sensitive</strong> ones (payments, access-control, health, finance,
        credentials) need an explicit Touch ID per grant — the tier comes from the catalog, so a vendor can&apos;t downgrade it.
      </div>

      {proposals === null ? (
        <button className="btn primary" disabled={proposing} onClick={onPropose}>
          {proposing ? 'classifying…' : '▷ classify agent surface'}
        </button>
      ) : (
        <>
          {safe.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 11.5, fontWeight: 600 }}>Safe · auto-confirm ({safe.length})</span>
                <button className="btn sm" onClick={() => onConfirmSafe(safe)}>confirm reviewed set</button>
              </div>
              {safe.map((p) => <ProposalRow key={p.service} p={p} onConfirm={() => onConfirm(p)} />)}
            </div>
          )}
          {sensitive.length > 0 && (
            <div>
              <div style={{ fontSize: 11.5, fontWeight: 600, marginBottom: 6 }}>
                Sensitive · explicit Touch ID per grant ({sensitive.length})
              </div>
              {sensitive.map((p) => <ProposalRow key={p.service} p={p} onConfirm={() => onConfirm(p)} sensitive />)}
            </div>
          )}
          {safe.length === 0 && sensitive.length === 0 && (
            <div className="muted" style={{ fontSize: 11.5 }}>No proposable scopes for this agent.</div>
          )}
        </>
      )}
    </Panel>
  );
}

function ProposalRow({ p, onConfirm, sensitive }: { p: ProposedScope; onConfirm: () => void; sensitive?: boolean }) {
  return (
    <div className={`perm-row ${sensitive ? 'denied' : 'granted'}`} style={{ alignItems: 'center' }}>
      <div className="perm-icon">{p.dataClass === 'memory' ? '◇' : '$'}</div>
      <div className="perm-body">
        <div className="perm-title">
          {p.entity}
          <span className={`perm-risk ${sensitive ? 'high' : 'low'}`} style={{ marginLeft: 8 }}>{p.category}</span>
        </div>
        <div className="perm-state mono">{p.service} · {p.sensitivity} · conf {p.confidence.toFixed(2)}</div>
      </div>
      <button className={`btn sm ${sensitive ? '' : ''}`} onClick={onConfirm}>
        {sensitive ? '⊕ confirm · Touch ID' : '⊕ grant'}
      </button>
    </div>
  );
}

// Pairing permission view: agent picker + read-only mobile permission list.
/** #248/#617 — the ONE staged permission editor (memory + capability grants),
 *  shared by the actor detail page and the delegates page's permission view so
 *  the two surfaces cannot drift (owner request, 2026-08-31). Toggles STAGE
 *  locally (the chain mirror would overwrite an optimistic write on the next
 *  refetch); the commit bar lands BOTH halves in ONE on-chain setScope under
 *  one master Touch ID. `null` staged state = the panel shows the chain truth. */
export function StagedPermissionEditor({
  actor,
  onCommitScope,
  onEmailChange,
}: {
  actor: Actor;
  /** #248: commit the staged grant on chain — ONE setScope UserOp signed by
   *  the master K11 (Touch ID). Resolves true on success (clears staging). */
  onCommitScope: (
    a: Actor,
    services: string[],
    readOnly: boolean,
    preserveOverride?: string[],
  ) => Promise<boolean>;
  /** The email service toggle commits immediately (it is not a scope bit);
   *  absent = the email row stays read-only. */
  onEmailChange?: (granted: boolean) => void;
}) {
  const [stagedScope, setStagedScope] = useState<Record<Namespace, ScopeBits> | null>(null);
  // #617 — capability grants stage the SAME way and commit in the SAME setScope:
  // a toggle IS a grant, and there is exactly one way authority ever changes, so
  // memory + capability changes land together under one Touch ID rather than
  // asking the owner to sign twice for one intent. `null` = nothing staged.
  const [stagedTools, setStagedTools] = useState<string[] | null>(null);
  const [committing, setCommitting] = useState(false);
  useEffect(() => {
    setStagedScope(null); // switching actors drops any uncommitted staging
    setStagedTools(null);
  }, [actor.id]);

  const chainScope = (actor.scope ?? {}) as Record<Namespace, ScopeBits>;
  const effectiveScope = stagedScope ?? chainScope;

  // The capability grants as the chain currently holds them (names only — the
  // daemon recovers `tool:<class>` names from their hashes; see #614).
  const chainTools = (actor.services ?? []).filter(
    (svc) => isCapabilityService(svc) && !isPluginService(svc),
  );
  const effectiveTools = stagedTools ?? chainTools;
  const setCapability = (svc: string, granted: boolean) => {
    const next = new Set(effectiveTools.map((s) => s.toLowerCase()));
    if (granted) next.add(svc.toLowerCase()); else next.delete(svc.toLowerCase());
    setStagedTools([...next]);
  };

  const setScope = (ns: Namespace | '__email', v: ScopeBits | boolean) => {
    if (ns === '__email') {
      onEmailChange?.(Boolean(v));
      return;
    }
    setStagedScope({ ...effectiveScope, [ns]: v as ScopeBits });
  };

  // The staged grant as on-chain services: every namespace with read or write.
  // #339 — two INDEPENDENT grants per namespace: read → knowledge:<ns>, write →
  // proposal:<ns> (suggest into the master's inbox). No direct shared write exists.
  const stagedRead = stagedScope ? NAMESPACES.filter((ns) => stagedScope[ns]?.read) : [];
  const stagedWrite = stagedScope ? NAMESPACES.filter((ns) => stagedScope[ns]?.write) : [];
  const memoryDirty =
    stagedScope !== null &&
    NAMESPACES.some((ns) => {
      const a = chainScope[ns] ?? { read: false, write: false };
      const b = stagedScope[ns] ?? { read: false, write: false };
      return a.read !== b.read || a.write !== b.write;
    });
  const toolsDirty =
    stagedTools !== null &&
    (stagedTools.length !== chainTools.length ||
      stagedTools.some((t) => !chainTools.some((c) => c.toLowerCase() === t.toLowerCase())));
  const stagedDirty = memoryDirty || toolsDirty;

  const commitStaged = async () => {
    if (!stagedDirty || committing) return;
    setCommitting(true);
    // #617 — ONE set-replace carrying BOTH halves. `scopeUnknownServiceIds`
    // deliberately still holds the capability hashes (so a memory commit cannot
    // wipe them); the preserve set must SUBTRACT them here or a switch-OFF
    // would be re-added. Memory names come from the STAGED scope.
    const stagedMemoryNames = [
      ...stagedRead.map((ns) => `knowledge:${ns}`),
      ...stagedWrite.map((ns) => `proposal:${ns}`),
    ];
    const { services: capServices, preserve } = capabilityGrantCommit(
      { ...actor, scope: (stagedScope ?? chainScope) as Actor['scope'] },
      effectiveTools,
    );
    const services = Array.from(new Set([...capServices, ...stagedMemoryNames]));
    // The on-chain readOnly bit is a dead flag (isServiceInScope ignores it).
    const ok = await onCommitScope(actor, services, true, preserve);
    setCommitting(false);
    if (ok) {
      setStagedScope(null); // the refetched chain mirror now shows the grant
      setStagedTools(null);
    }
  };

  return (
    <>
      <PermissionList
        actor={{
          ...actor,
          scope: effectiveScope,
          services: [
            ...(actor.services ?? []).filter((sv) => !isCapabilityService(sv) || isPluginService(sv)),
            ...effectiveTools,
          ],
        }}
        editable
        onScopeChange={setScope}
        onCapabilityChange={setCapability}
      />
      {stagedDirty && (
        <div
          className="banner"
          style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        >
          <span className="lbl">staged</span>
          <span style={{ fontSize: 11.5, flex: '1 1 auto' }}>
            {stagedRead.length === 0 && stagedWrite.length === 0
              ? 'Revokes every knowledge + inbox grant (credential / email grants are unchanged).'
              : [
                  stagedRead.length > 0
                    ? `Reads ${stagedRead.map((ns) => `knowledge:${ns}`).join(' · ')}.`
                    : '',
                  stagedWrite.length > 0
                    ? `Suggests ${stagedWrite.map((ns) => `proposal:${ns}`).join(' · ')}.`
                    : '',
                ].filter(Boolean).join(' ')}
            {' '}One on-chain setScope (master K11).
          </span>
          <span style={{ display: 'flex', gap: 8 }}>
            <button className="btn" disabled={committing} onClick={() => { setStagedScope(null); setStagedTools(null); }}>discard</button>
            <button className="btn primary" disabled={committing} onClick={commitStaged}>
              {committing ? 'committing…' : 'commit · Touch ID'}
            </button>
          </span>
        </div>
      )}
    </>
  );
}

export function PermissionView({ agents, onManage, onCommitScope }: { agents: Actor[]; onManage?: (id: string) => void; onCommitScope?: (a: Actor, services: string[], readOnly: boolean, preserveOverride?: string[]) => Promise<boolean> }) {
  const [pick, setPick] = useState<string | null>(agents[0] ? agents[0].id : null);
  const actor = agents.find((a) => a.id === pick);
  if (!actor) {
    return (
      <div className="banner">
        <span className="lbl">empty</span>
        <span>No agents paired yet.</span>
      </div>
    );
  }
  return (
    <>
      <div className="perm-agent-pick">
        {agents.map((a) => (
          <button key={a.id} className={pick === a.id ? 'on' : ''} onClick={() => setPick(a.id)}>
            <Dot status={a.status} />
            {a.label.replace(' (revoked)', '')}
          </button>
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div className="muted" style={{ fontSize: 11.5 }}>{actor.omni} · granted scope as on-chain cap-tokens</div>
        {onManage && <button className="btn sm" onClick={() => onManage(actor.id)}>manage in actor →</button>}
      </div>
      {onCommitScope ? (
        <StagedPermissionEditor actor={actor} onCommitScope={onCommitScope} />
      ) : (
        <PermissionList actor={actor} editable={false} />
      )}
    </>
  );
}
