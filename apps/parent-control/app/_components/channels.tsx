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
//
// The registry is a master-only, signer-encrypted Config-class doc
// (`config/channel-registry.enc`); the WeChat gateway + family live on the
// Contacts page.
import { useState, type CSSProperties } from 'react';

import { PageHead, Panel } from './shared';
import type { Actor } from './types';
import { isChannelService } from './types';
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
  onCreate: (input: { id: string; name: string; note?: string }) => Promise<ChannelDef | null>;
  onUpdate: (id: string, input: { name?: string; note?: string }) => Promise<boolean>;
  onDelete: (id: string) => Promise<boolean>;
  onRefresh: () => void;
  onGoDevices: () => void;
}

/** Actors holding a grant on channel `id` — by NAME (the daemon re-names
 *  on-chain hashes from this same registry, so names are the durable view). */
const holdersOf = (actors: Actor[], id: string): Actor[] => {
  const pub = `channel-pub:${id}`;
  const sub = `channel-sub:${id}`;
  return actors.filter((a) =>
    (a.services ?? []).some((s) => {
      const l = s.toLowerCase();
      return l === pub || l === sub;
    }),
  );
};

export function ChannelRegistryPage({ registry }: { registry: ChannelRegistryProps }) {
  return (
    <>
      <PageHead
        crumb="household / channels"
        title="Channels"
        desc="The conduits your agents and devices meet through. Create channels here, then attach them when pairing a device — the id is the immutable anchor (it is what the on-chain grants hash; display names can change, ids never do). The WeChat gateway and family contacts live on the Contacts page."
        actions={<button className="btn sm" onClick={registry.onRefresh}>↻ refresh</button>}
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
        <ChannelRow key={c.id} channel={c} registry={registry} />
      ))}
    </div>
  );
}

function ChannelRow({ channel, registry }: { channel: ChannelDef; registry: ChannelRegistryProps }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(channel.name);
  const [note, setNote] = useState(channel.note ?? '');
  const [busy, setBusy] = useState(false);
  const holders = holdersOf(registry.actors, channel.id);
  const inUse = holders.length > 0;

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
          ) : (
            <span className="muted" style={{ fontSize: 11 }}>unused</span>
          )}
          {!editing ? (
            <>
              <button className="btn sm" onClick={() => { setEditing(true); setName(channel.name); setNote(channel.note ?? ''); }}>rename</button>
              <button
                className="btn sm"
                disabled={inUse || busy}
                title={inUse ? 'in use — revoke the holders\' grants first (devices page / actor page)' : undefined}
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
      <div className="muted" style={{ fontSize: 10.5, marginTop: 6 }}>
        created {channel.createdAt ? new Date(channel.createdAt * 1000).toLocaleString() : '—'} · grants: <span className="mono">channel-pub:{channel.id}</span> · <span className="mono">channel-sub:{channel.id}</span>
      </div>
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
