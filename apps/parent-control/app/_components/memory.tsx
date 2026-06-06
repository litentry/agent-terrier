'use client';

import { useState } from 'react';
import type { ConfigPreset, ConnectionStatus, MemoryCategory } from '@/lib/client/types';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import { CeremonyRunner } from './ceremony';
import { EmptyState, PageHead, Panel } from './shared';
import type { CeremonyStep, PreservedMemory } from './types';

const PLANT_STEPS: CeremonyStep[] = [
  { label: 'Read prepared archive', sub: `${PREPARED_MEMORY.length} entries · travel / personal / family`, onchain: false },
  { label: 'Dedupe against existing', sub: 'content-hash compare · server-side (re-plant is a no-op)', onchain: false },
  { label: 'Encrypt envelopes', sub: 'AES-256-GCM under K3 epoch v1 KEK · per-namespace JSON array', onchain: false },
  { label: 'Write memory + taxonomy', sub: 'POST /v1/master/memory/plant → memory:<ns> blobs + config/memory-taxonomy', onchain: false },
  { label: 'Index + audit', sub: 'CredentialAudit.append(op=memory.plant) · tier-1 + anchor', onchain: true, fn: 'append(bytes32,bytes32,bytes32)' },
];

// #207 item 1A — config-init entry point A: author the memory-types taxonomy
// from a bundled default preset (master-only Config; writes the category index,
// not scope grants — so no K11, same posture as the plant's taxonomy reconcile).
const INIT_STEPS: CeremonyStep[] = [
  { label: 'Read default profile', sub: 'bundled preset · role-aware category tree', onchain: false },
  { label: 'Merge taxonomy', sub: 'union into config/memory-taxonomy (never clobbers existing)', onchain: false },
  { label: 'Encrypt + store', sub: 'AES-256-GCM under K3 epoch v1 · DataClass::Config (master-only)', onchain: false },
  { label: 'Index + audit', sub: 'CredentialAudit.append(op=config.taxonomy) · tier-1 + anchor', onchain: true, fn: 'append(bytes32,bytes32,bytes32)' },
];

// #201 Phase 4 lazy detail: undefined = not opened, 'loading' = decrypting,
// array = decrypted entries for the namespace.
type NsEntries = PreservedMemory[] | 'loading' | undefined;

// Workflow 2: see the master's real memory. The LIST is CATEGORIES, resolved
// from the durable, master-only Config taxonomy (no memory decryption, survives
// daemon restarts). Opening a category decrypts that namespace's entries ON
// DEMAND. When connected + empty, the operator can plant the PREPARED archive
// (real data, content-hash dedup). Disconnected → empty state.
export function MemoryPage({
  categories,
  entriesByNs,
  status,
  presets,
  defaultPresetId,
  initializing,
  planting,
  onInitDefault,
  onInitDone,
  onPlant,
  onPlantDone,
  onLoadCategory,
  onView,
}: {
  categories: MemoryCategory[];
  entriesByNs: Record<string, NsEntries>;
  status: ConnectionStatus;
  presets: ConfigPreset[];
  defaultPresetId: string;
  initializing: boolean;
  planting: boolean;
  onInitDefault: (presetId: string) => void;
  onInitDone: () => void;
  onPlant: () => void;
  onPlantDone: () => void;
  onLoadCategory: (ns: string) => void;
  onView: (m: PreservedMemory) => void;
}) {
  const hasMemory = categories.length > 0;
  const connected = status.kind === 'connected';
  const busy = planting || initializing;

  return (
    <>
      <PageHead
        crumb="memory · per-namespace · agentmemory-compatible"
        title={<><span className="muted serif">/</span> memory</>}
        desc="Your portable memory namespace — the spine agents read from and write to. Categories resolve from your master-only memory-types config (no decryption); an entry's detail is decrypted only when you open its category. Agents see only the namespaces their scope grants (memory:<ns>), and the configured engine ranks what's injected per query — never widening past the gate."
      />

      {!hasMemory && !busy && (
        connected ? (
          <TaxonomySetup
            presets={presets}
            defaultPresetId={defaultPresetId}
            onInitDefault={onInitDefault}
            onPlant={onPlant}
          />
        ) : (
          <EmptyState
            status={status}
            title="memory unavailable"
            hint="Master memory is authored + read through the daemon (GET/POST /v1/master/config, /v1/master/memory). Connect a daemon to initialize your categories and populate this view."
          />
        )
      )}

      {initializing && (
        <Panel title="── authoring taxonomy">
          <CeremonyRunner steps={INIT_STEPS} onDone={onInitDone} stepMs={560} />
        </Panel>
      )}

      {planting && (
        <Panel title="── planting prepared memory">
          <CeremonyRunner steps={PLANT_STEPS} onDone={onPlantDone} stepMs={620} />
        </Panel>
      )}

      {hasMemory && (
        <>
          <div className="stats">
            <div className="stat"><div className="v">{categories.length}</div><div className="k">categories</div></div>
            <div className="stat"><div className="v">lazy</div><div className="k">detail load</div></div>
            <div className="stat"><div className="v">k3 v1</div><div className="k">epoch (kek)</div></div>
          </div>

          <div className="banner">
            <span className="lbl">✓ taxonomy</span>
            <span>
              Categories come from your master-only taxonomy — <strong>no memory is decrypted</strong> to list them.
              Open a category to decrypt its entries on demand; an authored category with no entries yet stays empty
              until memory is classified into it. Agents read this per their granted <code>memory:&lt;ns&gt;</code> scope.
              <button className="btn ghost sm" style={{ marginLeft: 10 }} onClick={onPlant}>＋ plant demo archive</button>
            </span>
          </div>

          {categories.map((c) => (
            <CategoryPanel
              key={c.ns}
              category={c}
              entries={entriesByNs[c.ns]}
              onLoad={onLoadCategory}
              onView={onView}
            />
          ))}
        </>
      )}
    </>
  );
}

// #207 item 1A — the two config-init entry points the master sees on an empty
// store. A (default preset) is LIVE: pick a bundled role profile, preview its
// categories, author the taxonomy. B (NL → COMPILE) is a deferred placeholder
// (#207 item 1B). The prepared demo archive (the test-only plant seed) is a
// secondary action below.
function TaxonomySetup({
  presets,
  defaultPresetId,
  onInitDefault,
  onPlant,
}: {
  presets: ConfigPreset[];
  defaultPresetId: string;
  onInitDefault: (presetId: string) => void;
  onPlant: () => void;
}) {
  const [selected, setSelected] = useState(defaultPresetId);
  const hasPresets = presets.length > 0;
  const chosen = presets.find((p) => p.id === selected) ?? presets[0];

  const card: React.CSSProperties = {
    border: '1px solid var(--rule-soft, #e6e0d4)', borderRadius: 8,
    padding: '16px 18px', textAlign: 'left', background: 'var(--bg-elev, #fff)',
  };
  const head: React.CSSProperties = {
    fontSize: 12, fontWeight: 600, letterSpacing: '0.02em', marginBottom: 10,
    display: 'flex', alignItems: 'center', gap: 8,
  };

  return (
    <div className="empty-memory" style={{ maxWidth: 560 }}>
      <div className="serif" style={{ fontSize: 40, fontStyle: 'italic', color: 'var(--ink-faint)', marginBottom: 4 }}>∅</div>
      <h2 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 8px' }}>Set up your categories</h2>
      <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', margin: '0 auto 20px' }}>
        Author your <strong>category taxonomy</strong> — the vocabulary agentKeys uses to scope what an agent can access:
        the memory it reads, the credentials it uses, and more data classes as you add them. Two ways to start:
      </p>

      <div style={{ display: 'grid', gap: 12 }}>
        {/* A · default preset (LIVE) */}
        <div style={card}>
          <div style={head}>A · Start from a profile</div>
          {hasPresets ? (
            <>
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                style={{ width: '100%', padding: '7px 9px', fontSize: 12.5, marginBottom: 8 }}
              >
                {presets.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
              <p className="muted" style={{ fontSize: 11.5, margin: '0 0 10px' }}>{chosen?.description}</p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 12 }}>
                {chosen?.categories.map((c) => (
                  <span key={c.ns} className="chip">{c.label}</span>
                ))}
              </div>
              <button className="btn primary" onClick={() => onInitDefault(selected)}>⊕ initialize categories</button>
            </>
          ) : (
            <p className="muted" style={{ fontSize: 11.5, margin: 0 }}>Loading presets…</p>
          )}
        </div>

        {/* B · NL → COMPILE (deferred placeholder, #207 item 1B) */}
        <div style={{ ...card, opacity: 0.6 }}>
          <div style={head}>
            B · Describe in your own words
            <span className="badge">soon</span>
          </div>
          <textarea
            disabled
            placeholder="e.g. “I run a small bakery, have two kids, and invest on the side.”"
            style={{ width: '100%', minHeight: 56, padding: '8px 9px', fontSize: 12, resize: 'none' }}
          />
          <p className="muted" style={{ fontSize: 11, margin: '8px 0 0' }}>
            Natural-language → COMPILE compiles a sentence into taxonomy + policy. Lands in a follow-up (#207 item 1B).
          </p>
        </div>
      </div>

      <div style={{ fontSize: 11, color: 'var(--ink-faint)', margin: '18px 0 8px' }}>— or seed the demo —</div>
      <button className="btn ghost sm" onClick={onPlant}>plant prepared demo archive · {PREPARED_MEMORY.length} entries</button>
    </div>
  );
}

// One memory category: a collapsed header that decrypts + reveals its namespace
// entries on first open (lazy). Re-opening is a no-op (parent caches the result).
function CategoryPanel({
  category,
  entries,
  onLoad,
  onView,
}: {
  category: MemoryCategory;
  entries: NsEntries;
  onLoad: (ns: string) => void;
  onView: (m: PreservedMemory) => void;
}) {
  const [open, setOpen] = useState(false);
  const loaded = Array.isArray(entries);
  const loading = entries === 'loading';
  const count = loaded ? entries.length : null;

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && entries === undefined) onLoad(category.ns);
  };

  return (
    <Panel title={`── ${category.label} · ${category.ns}`} flush>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px' }}>
        <span className="muted" style={{ fontSize: 11.5 }}>
          {count !== null ? `${count} ${count === 1 ? 'entry' : 'entries'}` : loading ? 'decrypting…' : 'detail decrypts on open'}
        </span>
        <button className="btn sm" onClick={toggle}>{open ? 'hide' : 'open'}</button>
      </div>

      {open && loading && (
        <div className="muted" style={{ padding: '0 12px 12px', fontSize: 11.5 }}>decrypting memory:{category.ns}…</div>
      )}
      {open && loaded && count === 0 && (
        <div className="muted" style={{ padding: '0 12px 12px', fontSize: 11.5 }}>no entries in this namespace</div>
      )}
      {open && loaded && count !== null && count > 0 && (
        <table className="tab">
          <thead>
            <tr>
              <th>entry</th>
              <th>preview</th>
              <th className="right">bytes</th>
              <th>updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(entries as PreservedMemory[]).map((m) => (
              <tr key={m.ns + m.key} className="clickable" onClick={() => onView(m)}>
                <td>
                  <span className="mono" style={{ fontWeight: 500 }}>{m.title}</span>
                  <div className="secondary">{m.ns}/{m.key}</div>
                </td>
                <td className="muted" style={{ maxWidth: 360 }}>{m.preview}</td>
                <td className="right mono">{m.bytes}</td>
                <td className="muted">{m.updated}</td>
                <td className="right"><button className="btn sm" onClick={(e) => { e.stopPropagation(); onView(m); }}>open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
