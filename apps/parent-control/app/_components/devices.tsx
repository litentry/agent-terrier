'use client';

// #404/#408 — AI devices as CHANNEL ENDPOINTS (spec docs/spec/agent-channel-decoupling.md
// D6/D9/§14.10), the device half of the decoupled pairing UX:
//
//   delegates page = sandbox DELEGATES (memory/context scopes; spawns a runtime)
//   devices page   = DEVICES (camera, display, console) — this file. A device
//                    claim attaches ≥1 channel, never a runtime: accepting
//                    NEVER spawns a sandbox (D9), and the accept card HARD-
//                    enforces the ≥1-channel rule (§14.10 — broker only warns).
//
// Channels are SELECTED from the master's channel registry (the channels page
// owns create/rename/delete; the id is the immutable on-chain anchor). Pairing
// NEVER creates a channel silently — the inline "new channel" affordance goes
// through the registry create endpoint explicitly, then selects the result.
//
// Every mutating action here is the SAME on-chain ceremony as delegate pairing
// (one Touch ID → sponsored executeBatch(registerAgentDevice + setScope) →
// #97 audit receipts), so devices and delegates stay auditable identically.
import { useMemo, useState, type CSSProperties } from 'react';

import { Dot, PageHead } from './shared';
import { ExpiryCountdown } from './pairing';
import type { Actor, PairingRequest } from './types';
import { isChannelService } from './types';
import type { ChannelDef } from '@/lib/client/types';

// ── channel attachment model ────────────────────────────────────────────────
// One row per SELECTED registry channel; direction is per-direction service ids
// (D2): publish = device → agents (camera), subscribe = agents → device
// (display), both = duplex (the console's chat session).
export interface ChannelAttachment {
  id: string;
  pub: boolean;
  sub: boolean;
}

export const attachmentsToServices = (rows: ChannelAttachment[]): string[] => {
  const services: string[] = [];
  for (const r of rows) {
    const id = r.id.trim().toLowerCase();
    if (!id) continue;
    if (r.pub) services.push(`channel-pub:${id}`);
    if (r.sub) services.push(`channel-sub:${id}`);
  }
  return Array.from(new Set(services));
};

export const servicesToAttachments = (services: string[]): ChannelAttachment[] => {
  const byId = new Map<string, ChannelAttachment>();
  for (const svc of services.filter(isChannelService)) {
    const [prefix, ...rest] = svc.trim().toLowerCase().split(':');
    const id = rest.join(':');
    if (!id) continue;
    const row = byId.get(id) ?? { id, pub: false, sub: false };
    if (prefix === 'channel-pub') row.pub = true;
    if (prefix === 'channel-sub') row.sub = true;
    byId.set(id, row);
  }
  return Array.from(byId.values());
};

const INPUT: CSSProperties = {
  padding: '7px 9px',
  fontSize: 12.5,
  fontFamily: 'var(--mono)',
  border: '1px solid var(--rule)',
  background: 'var(--bg)',
  color: 'var(--ink)',
};

// ── registry-backed channel selector (claim row, accept card, bound editor) ──
// Each row picks a channel FROM THE REGISTRY (never free text — the id is the
// immutable anchor, minted on the channels page) + its direction. The inline
// "new channel" mini-form is the one explicit creation affordance: it calls the
// registry create endpoint, then selects the fresh channel.
export function ChannelAttachSelector({
  rows,
  onChange,
  channels,
  onCreateChannel,
}: {
  rows: ChannelAttachment[];
  onChange: (rows: ChannelAttachment[]) => void;
  channels: ChannelDef[];
  onCreateChannel?: (input: { id: string; name: string }) => Promise<ChannelDef | null>;
}) {
  const [adding, setAdding] = useState(false);
  const [newId, setNewId] = useState('');
  const [newName, setNewName] = useState('');
  const [creating, setCreating] = useState(false);
  const byId = useMemo(() => new Map(channels.map((c) => [c.id, c])), [channels]);
  const usedIds = new Set(rows.map((r) => r.id).filter(Boolean));
  const selectable = (current: string) => channels.filter((c) => c.id === current || !usedIds.has(c.id));

  const update = (i: number, patch: Partial<ChannelAttachment>) => {
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  };
  const createInline = async () => {
    if (!onCreateChannel || creating) return;
    const id = newId.trim().toLowerCase();
    const name = newName.trim() || id;
    if (!id) return;
    setCreating(true);
    const created = await onCreateChannel({ id, name });
    setCreating(false);
    if (!created) return; // the handler already surfaced the reason
    onChange([...rows.filter((r) => r.id !== ''), { id: created.id, pub: true, sub: false }]);
    setAdding(false);
    setNewId('');
    setNewName('');
  };

  return (
    <div style={{ display: 'grid', gap: 6 }}>
      {rows.map((r, i) => {
        const known = byId.get(r.id);
        return (
          <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="chip mono" style={{ opacity: 0.7 }}>channel</span>
            {known || r.id === '' ? (
              <select
                value={r.id}
                onChange={(e) => update(i, { id: e.target.value })}
                style={{ ...INPUT, flex: '1 1 200px' }}
              >
                <option value="" disabled>
                  {channels.length === 0 ? 'no channels yet — create one below' : 'select a channel…'}
                </option>
                {selectable(r.id).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.id})
                  </option>
                ))}
              </select>
            ) : (
              // A grant on an id the registry doesn't name — keep it visible +
              // direction-editable, never hidden (register the id to name it).
              <span className="chip mono" title="grant id not in the channel registry">{r.id} · not in registry</span>
            )}
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11.5 }}>
              <input type="checkbox" checked={r.pub} onChange={() => update(i, { pub: !r.pub })} style={{ accentColor: 'var(--ink)' }} />
              publish <span className="muted">(device → agents)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11.5 }}>
              <input type="checkbox" checked={r.sub} onChange={() => update(i, { sub: !r.sub })} style={{ accentColor: 'var(--ink)' }} />
              subscribe <span className="muted">(agents → device)</span>
            </label>
            {rows.length > 1 && (
              <button className="btn sm" onClick={() => onChange(rows.filter((_, j) => j !== i))}>✕</button>
            )}
          </div>
        );
      })}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {rows.length < channels.length && (
          <button className="btn sm" onClick={() => onChange([...rows, { id: '', pub: true, sub: false }])}>
            ⊕ attach another channel
          </button>
        )}
        {onCreateChannel && !adding && (
          <button className="btn sm" onClick={() => setAdding(true)}>⊕ new channel…</button>
        )}
      </div>
      {adding && onCreateChannel && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', padding: '6px 8px', border: '1px dashed var(--rule)' }}>
          <span className="muted" style={{ fontSize: 11 }}>new channel (registered explicitly — the id is the immutable anchor):</span>
          <input placeholder="id (e.g. cam-frontdoor)" value={newId} onChange={(e) => setNewId(e.target.value)} style={{ ...INPUT, flex: '1 1 150px' }} />
          <input placeholder="display name" value={newName} onChange={(e) => setNewName(e.target.value)} style={{ ...INPUT, flex: '1 1 140px', fontFamily: 'inherit' }} />
          <button className="btn sm primary" disabled={creating || !newId.trim()} onClick={() => void createInline()}>
            {creating ? 'creating…' : 'create + select'}
          </button>
          <button className="btn sm" onClick={() => setAdding(false)}>cancel</button>
        </div>
      )}
    </div>
  );
}

export interface DevicePanelProps {
  /** Pending DEVICE claims (isDevice === true) awaiting the on-chain accept. */
  requests: PairingRequest[];
  /** Bound channel-endpoint actors (all known grants are channel-pub/-sub). */
  actors: Actor[];
  /** The channel registry (channels page owns CRUD; pairing SELECTS). */
  channels: ChannelDef[];
  claiming: boolean;
  onClaim: (input: { code: string; label: string; channels: string[] }) => void;
  onAccept: (req: PairingRequest, services: string[]) => void;
  onDecline: (id: string) => void;
  onRefresh: () => void;
  onUnpair: (a: Actor) => void;
  onManage: (id: string) => void;
  /** Explicit registry create (used by the selector's inline mini-form). */
  onCreateChannel: (input: { id: string; name: string }) => Promise<ChannelDef | null>;
  onGoChannels: () => void;
  /** The #248 set-replace scope commit (Touch ID). For devices the grant set is
   *  channel-only by construction (D6), so the editor commits the FULL staged
   *  channel list with an empty preserve set. */
  onCommitChannels: (actor: Actor, services: string[], readOnly: boolean, preserveOverride?: string[]) => Promise<boolean>;
}

// ── the devices page (household / devices) ──────────────────────────────────
export function DevicesPage({ devices }: { devices: DevicePanelProps }) {
  return (
    <>
      <PageHead
        crumb="household / devices"
        title="Devices"
        desc="AI devices as channel endpoints — a camera publishes into a channel, a display subscribes, the console does both. A device never runs an agent and pairing it never spawns a sandbox. Channels are selected from the registry (channels page) — pairing never creates one silently."
        actions={<button className="btn sm" onClick={devices.onRefresh}>↻ check for codes</button>}
      />
      {devices.channels.length === 0 && (
        <div className="banner" style={{ marginBottom: 14 }}>
          <span className="lbl">i</span>
          <span>
            No channels registered yet — a device claim must attach at least one. Create channels on the <strong>channels</strong> page (or inline below).
          </span>
          <button className="btn sm" style={{ marginLeft: 'auto' }} onClick={devices.onGoChannels}>open channels →</button>
        </div>
      )}
      <DeviceClaimRow devices={devices} />
      {devices.requests.map((req) => (
        <DeviceRequestCard key={req.id} req={req} devices={devices} />
      ))}
      <BoundDevicesGrid devices={devices} />
    </>
  );
}

// ── claim a device code ──────────────────────────────────────────────────────
function DeviceClaimRow({ devices }: { devices: DevicePanelProps }) {
  const [code, setCode] = useState('');
  const [label, setLabel] = useState('');
  const [rows, setRows] = useState<ChannelAttachment[]>([{ id: '', pub: true, sub: false }]);
  const services = attachmentsToServices(rows);
  const ready = code.trim().length > 0 && label.trim().length > 0 && services.length > 0;
  const submit = () => {
    if (!ready) return;
    devices.onClaim({ code: code.trim(), label: label.trim(), channels: services });
    setCode('');
  };
  return (
    <div style={{ display: 'grid', gap: 8, padding: '10px 0 16px', borderBottom: '1px solid var(--rule)', marginBottom: 14 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <span className="pair-k" style={{ marginRight: 4 }}>claim a device</span>
        <input placeholder="pairing code (shown by the device)" value={code} onChange={(e) => setCode(e.target.value)} style={{ ...INPUT, flex: '1 1 220px', letterSpacing: '0.05em' }} />
        <input placeholder="device label (e.g. cam-frontdoor)" value={label} onChange={(e) => setLabel(e.target.value)} style={{ ...INPUT, flex: '1 1 170px', fontFamily: 'inherit' }} />
        <button className="btn primary" disabled={devices.claiming || !ready} title={services.length === 0 ? 'attach at least one channel (§14.10)' : undefined} onClick={submit}>
          {devices.claiming ? 'claiming…' : `⊕ claim device · ${services.length} channel${services.length === 1 ? '' : 's'}`}
        </button>
      </div>
      <ChannelAttachSelector rows={rows} onChange={setRows} channels={devices.channels} onCreateChannel={devices.onCreateChannel} />
      <div className="muted" style={{ fontSize: 11 }}>
        the claim declares the channel attachment; you still review + approve with one Touch ID below — a device with no channel cannot be claimed (a channel-less device is inert)
      </div>
    </div>
  );
}

// ── pending device accept card ───────────────────────────────────────────────
function DeviceRequestCard({ req, devices }: { req: PairingRequest; devices: DevicePanelProps }) {
  // Preseed from the claim's channel tokens (cap "channel-pub"/"channel-sub",
  // ns[0] = channel id — the daemon splits on the FIRST colon).
  const requestedServices = useMemo(
    () => req.requested.flatMap((p) => (p.ns.length > 0 ? [`${p.cap}:${p.ns[0]}`] : [])).filter(isChannelService),
    [req.requested],
  );
  const [rows, setRows] = useState<ChannelAttachment[]>(() => {
    const seeded = servicesToAttachments(requestedServices);
    return seeded.length > 0 ? seeded : [{ id: '', pub: true, sub: false }];
  });
  const services = attachmentsToServices(rows);
  return (
    <div className="pair-req">
      <div className="pair-req-head">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Dot status="warn" pulse />
          <div>
            <div style={{ fontWeight: 600, fontSize: 14 }}>
              Device claim · <span className="serif" style={{ fontStyle: 'italic' }}>{req.agent}</span>
            </div>
            <div className="muted" style={{ fontSize: 11.5 }}>
              channel endpoint · requested {req.requestedAt ? new Date(req.requestedAt * 1000).toLocaleString() : '—'} · <ExpiryCountdown expiresAt={req.expiresAt} />
            </div>
          </div>
        </div>
        <span className="chip warn">action required</span>
      </div>

      <div className="pair-req-grid">
        <div>
          <div className="pair-k" style={{ fontStyle: 'italic', opacity: 0.85, marginBottom: 6, color: 'var(--warn, #b8860b)' }}>
            ⚠ a device is a conduit — it never runs an agent, never touches memory or credentials, and accepting it spawns NOTHING
          </div>
          <div className="pair-k">kind</div>
          <div className="pair-v">{req.device}</div>
          <div className="pair-k">derivation</div>
          <div className="pair-v mono">O_master{req.derivation}</div>
        </div>
        <div>
          <div className="pair-k" style={{ fontStyle: 'italic', opacity: 0.85, marginBottom: 6 }}>
            ✓ attested cryptographic identity · cross-check on the device
          </div>
          <div className="pair-k">device key hash · verify on device</div>
          <div className="pair-v mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{req.deviceKeyHash || req.deviceKeyHashShort}</div>
          <div className="pair-k">device public address · verify on device</div>
          <div className="pair-v mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{req.dpubFull || req.dpub}</div>
          <div className="pair-k">pairing code · matches the device</div>
          <div className="pair-v mono" style={{ fontSize: 13, letterSpacing: '0.04em', wordBreak: 'break-all' }}>{req.pairCode || '—'}</div>
        </div>
      </div>

      <div className="pair-perms">
        <div className="pair-k" style={{ marginBottom: 8 }}>
          channel attachment · {services.length} grant{services.length === 1 ? '' : 's'} — a device claim must attach ≥1 channel
        </div>
        <ChannelAttachSelector rows={rows} onChange={setRows} channels={devices.channels} onCreateChannel={devices.onCreateChannel} />
      </div>

      <div className="pair-req-foot">
        <div className="muted" style={{ fontSize: 10.5 }}>{req.attestation}</div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => devices.onDecline(req.id)}>decline</button>
          <button
            className="btn primary"
            disabled={services.length === 0}
            title={services.length === 0 ? 'a device claim must attach ≥1 channel (§14.10)' : undefined}
            onClick={() => devices.onAccept(req, services)}
          >
            accept device · Touch ID · {services.length} channel{services.length === 1 ? '' : 's'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── bound devices grid + per-device channel editor ──────────────────────────
function BoundDevicesGrid({ devices }: { devices: DevicePanelProps }) {
  if (devices.actors.length === 0) {
    return (
      <div className="banner">
        <span className="lbl">idle</span>
        <span>No devices bound yet. A camera publishes into a channel; a display subscribes; the console does both. Claim a device code above to start.</span>
      </div>
    );
  }
  return (
    <div className="device-grid">
      {devices.actors.map((a) => (
        <BoundDeviceCard key={a.id} actor={a} devices={devices} />
      ))}
    </div>
  );
}

function BoundDeviceCard({ actor, devices }: { actor: Actor; devices: DevicePanelProps }) {
  const channelServices = (actor.services ?? []).filter(isChannelService);
  const [editing, setEditing] = useState(false);
  const [rows, setRows] = useState<ChannelAttachment[]>(() => servicesToAttachments(channelServices));
  const [committing, setCommitting] = useState(false);
  const staged = attachmentsToServices(rows);
  const dirty = JSON.stringify([...staged].sort()) !== JSON.stringify([...channelServices].sort());

  const commit = async () => {
    if (staged.length === 0) {
      // §14.10 mirror at re-grant time: an empty channel set makes the device
      // inert. Deliberate removal goes through unpair, not a zero-grant commit.
      window.alert('A device must keep ≥1 channel — to remove the device entirely, unpair it instead.');
      return;
    }
    if (
      !window.confirm(
        `Commit ${staged.length} channel grant(s) for ${actor.label}?\n\nThis REPLACES the device's on-chain grant set (devices hold only channel grants — D6). One Touch ID.`,
      )
    )
      return;
    setCommitting(true);
    // Devices hold ONLY channel grants (D6): the staged set IS the full grant
    // set, so nothing is blind-preserved (an empty preserve override).
    const ok = await devices.onCommitChannels(actor, staged, false, []);
    setCommitting(false);
    if (ok) setEditing(false);
  };

  return (
    <div className={`device-card ${actor.status === 'bad' ? 'revoked' : ''}`}>
      <div className="device-card-head">
        <Dot status={actor.status} pulse={actor.lastActive.endsWith('m ago')} />
        <span style={{ fontWeight: 600 }}>{actor.label.replace(' (revoked)', '')}</span>
        <span className="chip" style={{ marginLeft: 'auto' }}>device</span>
        {actor.justPaired && <span className="chip ok">new</span>}
      </div>
      <dl className="device-kvs">
        <dt>actor</dt><dd className="mono">{actor.omni}</dd>
        <dt>channels</dt>
        <dd>
          {channelServices.length > 0
            ? channelServices.map((s) => <span key={s} className="chip mono" style={{ marginRight: 4 }}>{s}</span>)
            : <span className="muted">grants on chain — names return once the ids are in the channel registry</span>}
        </dd>
        <dt>active</dt><dd className="muted">{actor.lastActive}</dd>
      </dl>
      {actor.status !== 'bad' && (
        <div style={{ display: 'grid', gap: 6, marginTop: 10 }}>
          {editing && (
            <>
              <ChannelAttachSelector rows={rows} onChange={setRows} channels={devices.channels} onCreateChannel={devices.onCreateChannel} />
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn primary" style={{ flex: 1, fontSize: 11.5 }} disabled={committing || !dirty || staged.length === 0} onClick={() => void commit()}>
                  {committing ? 'committing…' : `commit channels · Touch ID · ${staged.length}`}
                </button>
                <button className="btn" style={{ fontSize: 11.5 }} onClick={() => { setEditing(false); setRows(servicesToAttachments(channelServices)); }}>
                  discard
                </button>
              </div>
            </>
          )}
          {!editing && (
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn" style={{ flex: 1, fontSize: 11.5 }} disabled={channelServices.length === 0} title={channelServices.length === 0 ? 'channel names unknown — register the ids on the channels page, then refresh' : undefined} onClick={() => setEditing(true)}>
                edit channels
              </button>
              <button className="btn" style={{ fontSize: 11.5 }} onClick={() => devices.onManage(actor.id)}>manage</button>
              <button className="btn" style={{ fontSize: 11.5 }} onClick={() => devices.onUnpair(actor)}>unpair</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
