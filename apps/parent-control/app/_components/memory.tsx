'use client';

import { NAMESPACES } from '@/lib/constants';
import type { ConnectionStatus } from '@/lib/client/types';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import { CeremonyRunner } from './ceremony';
import { EmptyState, PageHead, Panel } from './shared';
import type { CeremonyStep, PreservedMemory } from './types';

const PLANT_STEPS: CeremonyStep[] = [
  { label: 'Read prepared archive', sub: `${PREPARED_MEMORY.length} entries · travel / personal / family`, onchain: false },
  { label: 'Dedupe against existing', sub: 'content-hash compare · server-side (re-plant is a no-op)', onchain: false },
  { label: 'Encrypt envelopes', sub: 'AES-256-GCM under K3 epoch v1 KEK · per (actor, key)', onchain: false },
  { label: 'Write to memory store', sub: 'POST /v1/master/memory/plant → master memory store', onchain: false },
  { label: 'Index + audit', sub: 'CredentialAudit.append(op=memory.plant) · tier-1 + anchor', onchain: true, fn: 'append(bytes32,bytes32,bytes32)' },
];

// Workflow 2: see the master's real memory. Entries come from the client seam
// (`listMasterMemory`). When connected + empty, the operator can plant the
// PREPARED archive (real data, through `plantMemory` → daemon, content-hash
// dedup). Disconnected → empty state (no daemon to plant into).
export function MemoryPage({
  memories,
  status,
  planting,
  onPlant,
  onPlantDone,
  onView,
}: {
  memories: PreservedMemory[];
  status: ConnectionStatus;
  planting: boolean;
  onPlant: () => void;
  onPlantDone: () => void;
  onView: (m: PreservedMemory) => void;
}) {
  const hasMemory = memories.length > 0;
  const connected = status.kind === 'connected';
  const byNs = NAMESPACES.map((ns) => ({ ns, items: memories.filter((m) => m.ns === ns) })).filter((g) => g.items.length > 0);
  const totalBytes = memories.reduce((a, m) => a + m.bytes, 0);

  return (
    <>
      <PageHead
        crumb="memory · per-namespace · agentmemory-compatible"
        title={<><span className="muted serif">/</span> memory</>}
        desc="Your portable memory namespace — the spine agents read from and write to. It follows you across every vendor device. Stored encrypted; agents see only the namespaces their scope grants (memory:<ns>), and the configured engine ranks what's injected per query — never widening past the gate."
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
            <div className="stat"><div className="v">{memories.length}</div><div className="k">memory entries</div></div>
            <div className="stat"><div className="v">{byNs.length}</div><div className="k">namespaces</div></div>
            <div className="stat"><div className="v">{(totalBytes / 1024).toFixed(1)}<span style={{ fontSize: 13 }}>KB</span></div><div className="k">total size</div></div>
            <div className="stat"><div className="v">k3 v1</div><div className="k">epoch (kek)</div></div>
          </div>

          <div className="banner">
            <span className="lbl">✓ planted</span>
            <span>
              Prepared memory is live. The <strong>plant</strong> action is hidden — re-planting is a server-side no-op
              (content-hash match). Agents read this per their granted <code>memory:&lt;ns&gt;</code> scope, query-ranked by the configured engine.
            </span>
          </div>

          {byNs.map((g) => (
            <Panel key={g.ns} title={`── ${g.ns} · ${g.items.length}`} flush>
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
                  {g.items.map((m) => (
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
            </Panel>
          ))}
        </>
      )}
    </>
  );
}
