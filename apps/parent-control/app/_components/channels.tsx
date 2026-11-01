'use client';

// #404 — the CHANNEL REGISTRY page (household / channels): the ONE place
// channels are created, renamed (display name only), annotated, and deleted.
//
//   • The channel id is the IMMUTABLE ANCHOR — it is the exact string the
//     on-chain `channel-pub:<id>` / `channel-sub:<id>` grants hash, so it can
//     never change; even when the display name changes, the id stays.
//   • Device pairing (devices page) SELECTS from this registry — a channel is
//     never created silently as a side effect of pairing.
//   • Delete is refused while any actor still holds a grant on the id (revoke
//     from the devices/actor pages first) — the daemon returns the holders.
//   • "clear orphaned" drops every definition NO actor holds a grant on in ONE
//     daemon write (`POST /v1/channels/clear-orphaned`); rows in use are kept.
//
// The registry is a master-only, signer-encrypted Config-class doc
// (`config/channel-registry.enc`). The contact gate keeps the CHANNEL DOCUMENT
// for each id — what the channel is for, the apps bound to it (each with its
// binding's description), the members' rows, the default app — which is the
// router's only input; this page edits those documents live (no Touch ID: a
// document grants nothing). The WeChat contact gate + family live on the
// Contacts page.
import { useCallback, useEffect, useState, type CSSProperties } from 'react';

import { useClient } from '@/lib/ClientProvider';
import { gatewayClient } from '@/lib/gatewayClient';
import type { ChannelDoc } from '@/lib/generated/ChannelDoc';
import type { ContactSummary } from '@/lib/generated/ContactSummary';
import { ChatPanel } from './chat';
import { PageHead, Panel } from './shared';
import type { Actor } from './types';
import { channelHolders, isChannelService, orphanedChannels } from './types';
import type { ChannelDef } from '@/lib/client/types';

const INPUT: CSSProperties = {
  padding: '7px 9px',
  fontSize: 12.5,
  border: '1px solid var(--rule)',
  background: 'var(--bg)',
  color: 'var(--ink)',
};

export interface ChannelRegistryProps {
  channels: ChannelDef[];
  /** "ok" = durable config-class doc · "cached" = dev-only (no config worker). */
  storage: string;
  actors: Actor[];
  /** The actor tree is being re-read (after an install, a refresh) — holders
   *  are not known yet, so nothing reads as orphaned meanwhile. */
  actorsSyncing?: boolean;
  onCreate: (input: { id: string; name: string; note?: string }) => Promise<ChannelDef | null>;
  onUpdate: (id: string, input: { name?: string; note?: string }) => Promise<boolean>;
  onDelete: (id: string) => Promise<boolean>;
  /** Drop every registry entry no actor holds a grant on — one daemon write. */
  onClearOrphaned: () => Promise<boolean>;
  onRefresh: () => void;
  onGoDevices: () => void;
}

export function ChannelRegistryPage({ registry }: { registry: ChannelRegistryProps }) {
  const [clearing, setClearing] = useState(false);
  const syncing = registry.actorsSyncing === true;
  const orphaned = syncing ? [] : orphanedChannels(registry.channels, registry.actors);
  const clearOrphaned = async () => {
    if (clearing || syncing || orphaned.length === 0) return;
    const ids = orphaned.map((c) => c.id);
    if (!window.confirm(`Clear ${ids.length} orphaned channel${ids.length === 1 ? '' : 's'}?\n\n${ids.join('\n')}\n\nNo device or agent holds a grant on them, so nothing on chain changes — this only removes the registry entries. Channels still in use are kept.`)) return;
    setClearing(true);
    await registry.onClearOrphaned();
    setClearing(false);
  };
  return (
    <>
      <PageHead
        crumb="household / channels"
        title="Channels"
        desc="The conduits your agents and devices meet through. Create channels here, then attach them when pairing a device — the id is the immutable anchor (it is what the on-chain grants hash; display names can change, ids never do). The WeChat contact gate and family contacts live on the Contacts page."
        actions={
          <>
            <button
              className="btn sm danger"
              disabled={clearing || syncing || orphaned.length === 0}
              title={syncing ? 'checking which device or agent holds each channel…' : orphaned.length === 0 ? 'nothing orphaned — every entry is held by a device or agent' : `remove ${orphaned.length} entr${orphaned.length === 1 ? 'y' : 'ies'} no device or agent holds a grant on`}
              onClick={() => void clearOrphaned()}
            >
              {clearing ? 'clearing…' : `⌫ clear orphaned${orphaned.length ? ` (${orphaned.length})` : ''}`}
            </button>
            <button className="btn sm" onClick={registry.onRefresh} disabled={syncing} title="re-read the registry and the actor tree (who holds a grant on each channel)">{syncing ? 'checking grants…' : '↻ recheck'}</button>
          </>
        }
      />
      {registry.storage === 'cached' && (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">⚠</span>
          <span>No config worker configured — the registry is in-memory only (dev). Definitions will not survive a daemon restart.</span>
        </div>
      )}
      <CreateChannelPanel onCreate={registry.onCreate} />
      <ChannelList registry={registry} />
    </>
  );
}

function CreateChannelPanel({ onCreate }: { onCreate: ChannelRegistryProps['onCreate'] }) {
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const idOk = /^[a-z0-9][a-z0-9-]{0,47}$/.test(id.trim().toLowerCase()) && !id.trim().endsWith('-');
  const submit = async () => {
    if (busy || !idOk) return;
    setBusy(true);
    const created = await onCreate({
      id: id.trim().toLowerCase(),
      name: name.trim() || id.trim().toLowerCase(),
      note: note.trim() || undefined,
    });
    setBusy(false);
    if (created) {
      setId('');
      setName('');
      setNote('');
    }
  };
  return (
    <Panel title="── new channel">
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input placeholder="id · immutable anchor (e.g. cam-frontdoor)" value={id} onChange={(e) => setId(e.target.value)} style={{ ...INPUT, flex: '1 1 210px', fontFamily: 'var(--mono)' }} />
        <input placeholder="display name (e.g. Front-door camera)" value={name} onChange={(e) => setName(e.target.value)} style={{ ...INPUT, flex: '1 1 190px' }} />
        <input placeholder="note (optional)" value={note} onChange={(e) => setNote(e.target.value)} style={{ ...INPUT, flex: '2 1 220px' }} />
        <button className="btn primary" disabled={busy || !idOk} title={!idOk && id.trim() ? 'id: 1-48 chars of a-z 0-9 hyphen, no edge hyphens' : undefined} onClick={() => void submit()}>
          {busy ? 'creating…' : '⊕ create channel'}
        </button>
      </div>
      <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
        the id becomes the on-chain anchor (`channel-pub:&lt;id&gt;` / `channel-sub:&lt;id&gt;`) and can never be renamed — pick it like a hostname; the display name is free to change later
      </div>
    </Panel>
  );
}

function ChannelList({ registry }: { registry: ChannelRegistryProps }) {
  // The contact gate's device actor: a messaging channel an app holds that the
  // gate holds no grant on is readable here but delivered to nobody — say so.
  const client = useClient();
  const [gate, setGate] = useState<GateFacts | null>(null);
  // The channel documents + the contacts (for the members' names), from the
  // contact gate; absent when no gate is wired (a dev daemon).
  const [docs, setDocs] = useState<ChannelDoc[]>([]);
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const loadDocs = useCallback(async () => {
    const [d, c] = await Promise.all([gatewayClient.channels(), gatewayClient.contacts()]);
    if (d.ok) setDocs(d.value.channels);
    if (c.ok) setContacts(c.value.contacts);
  }, []);
  useEffect(() => {
    void loadDocs();
  }, [loadDocs, registry.channels]);
  useEffect(() => {
    if (!client.gatewayDeviceStatus) return;
    let alive = true;
    void client.gatewayDeviceStatus().then((r) => {
      if (alive && r.ok && r.data.configured) setGate({ transport: r.data.transport.toLowerCase(), actorOmni: r.data.actor_omni ?? null });
    });
    return () => {
      alive = false;
    };
  }, [client]);
  if (registry.channels.length === 0) {
    return (
      <div className="banner">
        <span className="lbl">idle</span>
        <span>No channels registered yet. Create one above, then pair a device against it — a camera publishes into a channel, a display subscribes, the console does both.</span>
      </div>
    );
  }
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      {registry.channels.map((c) => (
        <ChannelRow key={c.id} channel={c} registry={registry} gate={gate} doc={docs.find((d) => d.id === c.id) ?? null} contacts={contacts} onDocChanged={loadDocs} />
      ))}
      {docs.filter((d) => !registry.channels.some((c) => c.id === d.id)).map((d) => (
        <div key={`doc-${d.id}`} className="pair-req" style={{ padding: 14 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="chip mono">{d.id}</span>
            <span style={{ fontWeight: 600 }}>{d.name}</span>
            <span className="muted" style={{ fontSize: 11.5 }}>a document the contact gate holds with no registry row here (an operator channel, or a channel registered on another console)</span>
          </div>
          <DocumentPanel doc={d} contacts={contacts} onChanged={loadDocs} />
        </div>
      ))}
    </div>
  );
}

/** The configured contact gate, as the channels page needs it. */
type GateFacts = { transport: string; actorOmni: string | null };

const normOmni = (s: string | null | undefined): string => (s ?? '').trim().toLowerCase().replace(/^0x/, '');

function ChannelRow({ channel, registry, gate, doc, contacts, onDocChanged }: { channel: ChannelDef; registry: ChannelRegistryProps; gate: GateFacts | null; doc: ChannelDoc | null; contacts: ContactSummary[]; onDocChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(channel.name);
  const [note, setNote] = useState(channel.note ?? '');
  const [busy, setBusy] = useState(false);
  const [showFeed, setShowFeed] = useState(false);
  const holders = channelHolders(registry.actors, channel.id);
  const inUse = holders.length > 0;
  // The operator chat is the one feed the master writes into from here (D13);
  // every other feed is read-only on this page.
  const isOpchat = channel.id.startsWith('opchat-');
  // 2026-09-22: the bound channel IS the feed — the gate relays whichever
  // channel an app's messaging slot binds, once the gate holds a grant on it.
  const gateHolds = !!gate?.actorOmni && holders.some((h) => normOmni(h.omniHex) === normOmni(gate.actorOmni) || normOmni(h.omni) === normOmni(gate.actorOmni));
  const unservedMessaging = channel.kind === 'messaging' && inUse && !!gate && !gateHolds;

  const save = async () => {
    if (busy) return;
    setBusy(true);
    const ok = await registry.onUpdate(channel.id, { name: name.trim(), note: note.trim() });
    setBusy(false);
    if (ok) setEditing(false);
  };
  const del = async () => {
    if (busy || inUse) return;
    if (!window.confirm(`Delete channel definition "${channel.name}" (${channel.id})?\n\nNo actor holds a grant on it, so nothing on chain changes — this only removes the registry entry.`)) return;
    setBusy(true);
    await registry.onDelete(channel.id);
    setBusy(false);
  };

  return (
    <div className="pair-req" style={{ padding: 14 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <span className="chip mono" title="immutable on-chain anchor">{channel.id}</span>
        {!editing ? (
          <>
            <span style={{ fontWeight: 600 }}>{channel.name}</span>
            {channel.note && <span className="muted" style={{ fontSize: 11.5 }}>{channel.note}</span>}
          </>
        ) : (
          <>
            <input value={name} onChange={(e) => setName(e.target.value)} style={{ ...INPUT, flex: '1 1 170px' }} />
            <input value={note} placeholder="note" onChange={(e) => setNote(e.target.value)} style={{ ...INPUT, flex: '2 1 200px' }} />
          </>
        )}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          {inUse ? (
            holders.map((h) => (
              <span key={h.id} className="chip ok" title={`holds a grant on ${channel.id}`}>{h.label.replace(' (revoked)', '')}</span>
            ))
          ) : registry.actorsSyncing ? (
            <span className="muted" style={{ fontSize: 11, fontStyle: 'italic' }} title="the actor tree is being re-read — holders show once it lands">checking grants…</span>
          ) : (
            <span className="muted" style={{ fontSize: 11 }} title={'no device or agent holds a grant on it — "clear orphaned" removes it'}>orphaned</span>
          )}
          {!editing ? (
            <>
              <button className="btn sm" onClick={() => setShowFeed((v) => !v)} title={isOpchat ? 'the operator chat — you can write here' : 'the feed, read-only'}>
                {showFeed ? 'hide feed' : 'feed'}
              </button>
              <button className="btn sm" onClick={() => { setEditing(true); setName(channel.name); setNote(channel.note ?? ''); }}>rename</button>
              <button
                className="btn sm"
                disabled={inUse || busy || registry.actorsSyncing === true}
                title={inUse ? 'in use — revoke the holders\' grants first (devices page / actor page)' : registry.actorsSyncing ? 'checking who holds a grant on it…' : undefined}
                onClick={() => void del()}
              >
                delete
              </button>
            </>
          ) : (
            <>
              <button className="btn sm primary" disabled={busy || !name.trim()} onClick={() => void save()}>{busy ? 'saving…' : 'save'}</button>
              <button className="btn sm" onClick={() => setEditing(false)}>cancel</button>
            </>
          )}
        </span>
      </div>
      {channel.kind && <div style={{ marginTop: 6 }}><span className="chip">{channel.kind}</span>{doc?.household_default && <span className="chip ok" style={{ marginLeft: 6 }}>household default</span>}{doc?.operator_of && <span className="chip" style={{ marginLeft: 6 }}>operator channel of {doc.operator_of}</span>}</div>}
      {doc && <DocumentPanel doc={doc} contacts={contacts} onChanged={onDocChanged} />}
      {!doc && channel.kind === 'messaging' && <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>No channel document on the contact gate yet — an app installed on it, or a member added to it, writes one.</div>}
      {unservedMessaging && (
        <div className="banner warn" style={{ marginTop: 8 }}>
          <span className="lbl">not relayed</span>
          <span>
            An app holds this messaging channel but the contact gate holds no grant on it, so what the app writes here is readable below and reaches nobody. Rebind the app&apos;s messaging slot to this channel from its application page — one Touch ID enrolls the gate on it — and the family reaches it.
          </span>
        </div>
      )}
      {showFeed && (
        <div style={{ marginTop: 10 }}>
          <ChatPanel
            channelId={channel.id}
            readOnly={!isOpchat}
            emptyHint={isOpchat ? `Direct chat on ${channel.id} — the transcript IS the durable feed.` : `Nothing on ${channel.id} yet — this page shows the feed read-only.`}
          />
        </div>
      )}
      <div className="muted" style={{ fontSize: 10.5, marginTop: 6 }}>
        created {channel.createdAt ? new Date(channel.createdAt * 1000).toLocaleString() : '—'} · grants: <span className="mono">channel-pub:{channel.id}</span> · <span className="mono">channel-sub:{channel.id}</span>
      </div>
    </div>
  );
}

/** The channel document as the contact gate holds it — what the router
 *  reads: the purpose, the apps bound here with their binding descriptions,
 *  the members' rows, the default app. Every edit is live (no Touch ID). */
function DocumentPanel({ doc, contacts, onChanged }: { doc: ChannelDoc; contacts: ContactSummary[]; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [purpose, setPurpose] = useState(doc.purpose);
  useEffect(() => setPurpose(doc.purpose), [doc.purpose, doc.updated_at]);
  const name = (id: string) => contacts.find((c) => c.contact_id === id)?.display_name ?? id;
  const write = async (what: string, req: Parameters<typeof gatewayClient.channelUpdate>[0]) => {
    setBusy(what);
    const r = await gatewayClient.channelUpdate(req);
    setBusy(null);
    if (!r.ok) window.alert(`${what} failed: ${r.reason}${r.detail ? ` — ${r.detail}` : ''}`);
    onChanged();
  };
  const rowOf = (m: { speak: boolean; read: boolean }) => (m.speak ? 'speaks' : m.read ? 'reads' : '—');
  const others = contacts.filter((c) => !doc.members.some((m) => m.contact_id === c.contact_id));
  return (
    <div style={{ marginTop: 10, display: 'grid', gap: 8, fontSize: 12.5 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <span className="muted" style={{ minWidth: 70 }}>purpose</span>
        <input value={purpose} placeholder="what this channel is for — the first line the router reads" onChange={(e) => setPurpose(e.target.value)} style={{ ...INPUT, flex: '1 1 260px' }} />
        {purpose.trim() !== doc.purpose && (
          <button className="btn sm primary" disabled={!!busy} onClick={() => void write('purpose', { channel_id: doc.id, purpose: purpose.trim() })}>save</button>
        )}
        {!doc.operator_of && (
          <label className="muted" style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
            <input type="checkbox" checked={doc.household_default} disabled={!!busy} onChange={(e) => void write('household default', { channel_id: doc.id, household_default: e.target.checked })} /> household default
          </label>
        )}
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <span className="muted" style={{ minWidth: 70 }}>apps</span>
        <div style={{ flex: 1 }}>
          {doc.apps.length === 0 && <span className="muted">none bound here</span>}
          {doc.apps.map((a) => (
            <div key={a.alias} style={{ marginBottom: 2 }}>
              <code>{a.alias}</code> <span className="muted">· {a.slot || '—'}</span>{doc.default_app === a.alias && <span className="chip ok" style={{ marginLeft: 6 }}>default</span>}
              <div className="muted" style={{ fontSize: 11.5 }}>{a.description || 'no description — set it under the app’s bindings'}{a.takes.length ? ` · takes ${a.takes.join(', ')}` : ''}</div>
            </div>
          ))}
          {doc.apps.length > 1 && (
            <div style={{ marginTop: 4 }}>
              <span className="muted">unaddressed events go to </span>
              <select value={doc.default_app ?? ''} disabled={!!busy} onChange={(e) => void write('default app', { channel_id: doc.id, default_app: e.target.value })} style={INPUT}>
                <option value="">(none)</option>
                {doc.apps.map((a) => <option key={a.alias} value={a.alias}>{a.alias}</option>)}
              </select>
            </div>
          )}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <span className="muted" style={{ minWidth: 70 }}>members</span>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {doc.members.length === 0 && <span className="muted">nobody yet</span>}
          {doc.members.map((m) => (
            <span key={m.contact_id} className="chip" title="tap to change: speaks → reads → out">
              <button type="button" className="btn sm" disabled={!!busy} onClick={() => void write('member', { channel_id: doc.id, member: { contact_id: m.contact_id, speak: false, read: m.speak } })}>
                {name(m.contact_id)} · {rowOf(m)}
              </button>
            </span>
          ))}
          {others.length > 0 && (
            <select value="" disabled={!!busy} onChange={(e) => { if (e.target.value) void write('member', { channel_id: doc.id, member: { contact_id: e.target.value, speak: true, read: true } }); }} style={INPUT}>
              <option value="">+ add a member (speaks)</option>
              {others.map((c) => <option key={c.contact_id} value={c.contact_id}>{c.display_name} · {c.tier}</option>)}
            </select>
          )}
        </div>
      </div>
      <div className="muted" style={{ fontSize: 10.5 }}>document v{doc.updated_at} · the router reads exactly this: purpose, the apps and what each does here, who is in it</div>
    </div>
  );
}

/** Convenience for App: bound actors whose grants include a given channel —
 *  exported for potential reuse by the actor page. */
export const channelUsage = (actors: Actor[]): Map<string, number> => {
  const map = new Map<string, number>();
  for (const a of actors) {
    for (const s of (a.services ?? []).filter(isChannelService)) {
      const id = s.split(':').slice(1).join(':');
      map.set(id, (map.get(id) ?? 0) + 1);
    }
  }
  return map;
};
