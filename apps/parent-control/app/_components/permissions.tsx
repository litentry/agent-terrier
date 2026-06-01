'use client';

import { useState, type ReactNode } from 'react';
import { NAMESPACES } from '@/lib/constants';
import { Dot } from './shared';
import type { Actor, Namespace, ScopeBits, VaultItem } from './types';

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
export function PermissionList({
  actor,
  editable,
  vaultItems = [],
  onScopeChange,
  onPaymentTap,
  onCredTap,
}: {
  actor: Actor;
  editable: boolean;
  vaultItems?: VaultItem[];
  onScopeChange?: (ns: Namespace | '__email', v: ScopeBits | boolean) => void;
  onPaymentTap?: () => void;
  onCredTap?: (v: VaultItem) => void;
}) {
  const scope = actor.scope ?? ({} as Record<Namespace, ScopeBits>);
  const services = actor.services ?? [];
  const memGranted = NAMESPACES.filter((ns) => scope[ns] && (scope[ns].read || scope[ns].write));
  const vaultForActor = vaultItems.filter((v) => v.actor === actor.id);
  const hasEmail = services.includes('email');
  const hasPay = (actor.paymentCap?.perTx ?? 0) > 0;

  return (
    <div className="perm-list">
      {/* MEMORY */}
      <PermSection title="Memory access" summary={`${memGranted.length} of ${NAMESPACES.length} namespaces`}>
        {NAMESPACES.map((ns) => {
          const s = scope[ns] || { read: false, write: false };
          const granted = s.read || s.write;
          const lvl = s.write ? 'read + write' : s.read ? 'read only' : 'no access';
          return (
            <PermRow
              key={ns}
              icon={NS_ICON[ns]}
              title={ns}
              why={NS_WHY[ns]}
              state={`scope · ${lvl}`}
              granted={granted}
              control={
                editable
                  ? <PermSeg value={s} onChange={(v) => onScopeChange && onScopeChange(ns, v)} />
                  : <span className={`perm-readonly ${granted ? 'on' : 'off'}`}>{s.write ? 'r+w' : s.read ? 'read' : 'deny'}</span>
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

// Pairing permission view: agent picker + read-only mobile permission list.
export function PermissionView({ agents, onManage }: { agents: Actor[]; onManage?: (id: string) => void }) {
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
      <PermissionList actor={actor} editable={false} />
    </>
  );
}
