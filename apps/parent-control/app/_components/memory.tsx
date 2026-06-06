'use client';

import { useState } from 'react';
import type { ConnectionStatus, MemoryCategory } from '@/lib/client/types';
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
  planting,
  onPlant,
  onPlantDone,
  onLoadCategory,
  onView,
}: {
  categories: MemoryCategory[];
  entriesByNs: Record<string, NsEntries>;
  status: ConnectionStatus;
  planting: boolean;
  onPlant: () => void;
  onPlantDone: () => void;
  onLoadCategory: (ns: string) => void;
  onView: (m: PreservedMemory) => void;
}) {
  const hasMemory = categories.length > 0;
  const connected = status.kind === 'connected';

  return (
    <>
      <PageHead
        crumb="memory · per-namespace · agentmemory-compatible"
        title={<><span className="muted serif">/</span> memory</>}
        desc="Your portable memory namespace — the spine agents read from and write to. Categories resolve from your master-only memory-types config (no decryption); an entry's detail is decrypted only when you open its category. Agents see only the namespaces their scope grants (memory:<ns>), and the configured engine ranks what's injected per query — never widening past the gate."
      />

      {!hasMemory && !planting && (
        connected ? (
          <div className="empty-memory">
            <div className="serif" style={{ fontSize: 40, fontStyle: 'italic', color: 'var(--ink-faint)', marginBottom: 4 }}>∅</div>
            <h2 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 8px' }}>No memory planted yet.</h2>
            <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', maxWidth: 440, margin: '0 auto 22px' }}>
              Plant your prepared memory archive to give every paired agent the same context — your trip, your
              profile, your routines. This is a one-time import through the real memory store; duplicates are detected
              by content-hash and skipped automatically.
            </p>
            <button className="btn primary" style={{ padding: '12px 22px' }} onClick={onPlant}>
              ⊕ plant prepared memory
            </button>
            <div style={{ fontSize: 10.5, color: 'var(--ink-faint)', marginTop: 14 }}>
              prepared archive · {PREPARED_MEMORY.length} entries · idempotent (content-hash dedup)
            </div>
          </div>
        ) : (
          <EmptyState
            status={status}
            title="memory unavailable"
            hint="Master memory is read + planted through the daemon (GET / POST /v1/master/memory). Connect a daemon to plant the prepared archive and populate this view."
          />
        )
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
            <span className="lbl">✓ planted</span>
            <span>
              Categories come from your master-only taxonomy — <strong>no memory is decrypted</strong> to list them.
              Open a category to decrypt its entries on demand. The <strong>plant</strong> action is hidden; re-planting
              is a server-side no-op (content-hash match). Agents read this per their granted <code>memory:&lt;ns&gt;</code> scope.
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
