'use client';
// #429 (epic #425) — the delegate SPAWN + ARCHIVE ceremonies, parent-control
// face. Zero rendezvous (no QR, no request/approve): pick a preset → name it →
// choose the memory namespace (fresh | inherit an archived delegate's kept
// namespace, #425 O2) → ONE Touch ID. The archive dialog is the O4 twin: the
// destructive branch names exactly what is destroyed; the slot returns either
// way; manifest + audit rows are always retained.

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { AgentKeysClient, InheritableNamespace } from '@/lib/client/types';
import type { Actor } from './types';
import type { PresetSummary } from '@/lib/generated/PresetSummary';
import { getAssertionOverHash } from '@/lib/webauthn';
import { getMasterCredId } from '@/lib/identityStore';
import { akLog } from '@/lib/debug';
import { Modal } from './shared';

const LABEL_RE = /^[a-z0-9-]{1,32}$/;

/** The broker's loud business-gate error body (409 agent_slot_allowance_exhausted). */
function allowanceDetail(detail: string | undefined): string | null {
  if (!detail) return null;
  return detail.includes('agent_slot_allowance_exhausted') || detail.includes('allowance exhausted')
    ? detail
    : null;
}

export function SpawnAgentModal({
  client,
  onClose,
  onSpawned,
  showToast,
}: {
  client: AgentKeysClient;
  onClose: () => void;
  /** Called after a CONFIRMED spawn so the caller refreshes the actor list. */
  onSpawned: () => void;
  showToast: (msg: string, sticky?: boolean) => void;
}) {
  const [presets, setPresets] = useState<PresetSummary[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [presetId, setPresetId] = useState<string>('default-assistant');
  const [label, setLabel] = useState('');
  const [memoryMode, setMemoryMode] = useState<'fresh' | 'inherit'>('fresh');
  const [inheritable, setInheritable] = useState<InheritableNamespace[]>([]);
  const [inheritNs, setInheritNs] = useState<string>('');
  const [busy, setBusy] = useState<string | null>(null);
  const [gateError, setGateError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const cat = await client.presetCatalog();
      if (cat.ok) {
        setPresets(cat.data.presets);
        if (!cat.data.presets.some((p) => p.id === 'default-assistant') && cat.data.presets[0]) {
          setPresetId(cat.data.presets[0].id);
        }
      } else {
        setCatalogError(cat.status?.detail ?? 'preset catalog unavailable');
        setPresets([]);
      }
      const inh = await client.inheritableNamespaces();
      if (inh.ok) setInheritable(inh.data);
    })();
  }, [client]);

  const selected = useMemo(
    () => presets?.find((p) => p.id === presetId),
    [presets, presetId],
  );
  const labelOk = LABEL_RE.test(label);
  const canSpawn = labelOk && !busy && (memoryMode === 'fresh' || inheritNs.length > 0);

  const spawn = useCallback(async () => {
    setGateError(null);
    setBusy('Building the spawn ceremony…');
    const built = await client.spawnBuild({
      label,
      presetId,
      memoryNs: memoryMode === 'inherit' ? inheritNs : undefined,
      memoryInherited: memoryMode === 'inherit',
    });
    if (!built.ok) {
      setBusy(null);
      const gate = allowanceDetail(built.status?.detail);
      if (gate) {
        // The #425 business gate — loud + actionable, with the extend affordance.
        setGateError(gate);
        return;
      }
      showToast(`Spawn build failed — ${built.status?.detail ?? 'check master session + chain'}`);
      return;
    }
    akLog('spawn: built UserOp', {
      actorOmni: built.data.actor_omni,
      deviceKeyHash: built.data.device_key_hash,
      services: built.data.services,
      slots: `${built.data.slots_used}/${built.data.slots_total}`,
    });
    setBusy(
      `Slot ${built.data.slots_used + 1} of ${built.data.slots_total} — approve with Touch ID…`,
    );
    let assertion;
    try {
      const masterCred = getMasterCredId() || null;
      assertion = await getAssertionOverHash(
        built.data.user_op_hash,
        masterCred ? [masterCred] : undefined,
      );
    } catch {
      setBusy(null);
      showToast('Touch ID cancelled — nothing was spawned (no slot consumed).');
      return;
    }
    setBusy('Submitting on chain…');
    const submitted = await client.spawnSubmit({ user_op: built.data.user_op, assertion });
    setBusy(null);
    if (!submitted.ok) {
      showToast(`Spawn submit failed — ${submitted.status?.detail ?? 'handleOps error'}`, true);
      return;
    }
    const ceremony = submitted.data.ceremony as
      | { spawned?: { gate?: { status?: string }; sandbox?: { sandbox_id?: string | null } }[] }
      | undefined;
    const spawned = ceremony?.spawned?.[0];
    akLog('spawn: confirmed', {
      txHash: submitted.data.tx_hash,
      ceremony: submitted.data.ceremony,
    });
    showToast(
      `${label} spawned — chat channel + memory ready${
        spawned?.sandbox?.sandbox_id ? '; sandbox starting' : ''
      }.`,
    );
    onSpawned();
    onClose();
  }, [client, label, presetId, memoryMode, inheritNs, onClose, onSpawned, showToast]);

  return (
    <Modal
      title="New agent"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={!!busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={spawn} disabled={!canSpawn}>
            {busy ?? 'Spawn · Touch ID'}
          </button>
        </>
      }
    >
      {gateError && (
        <div className="callout warn" role="alert">
          <strong>Agent-slot allowance exhausted.</strong>
          <div style={{ marginTop: 4 }}>{gateError}</div>
          <div style={{ marginTop: 4 }}>
            Archive an agent to free a slot, or extend the allowance (platform action).
          </div>
        </div>
      )}
      <div className="field">
        <label>Preset — the agent&apos;s soul + skills (content, never authority)</label>
        {presets === null && <div className="muted">Loading catalog…</div>}
        {catalogError && <div className="muted">Catalog unavailable: {catalogError} — spawning blank.</div>}
        <div className="preset-gallery" style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))' }}>
          {(presets ?? []).map((p) => (
            <button
              key={p.id}
              className={`preset-card ${p.id === presetId ? 'selected' : ''}`}
              style={{
                textAlign: 'left',
                padding: 10,
                border: p.id === presetId ? '2px solid var(--accent)' : '1px solid var(--rule)',
                borderRadius: 8,
                background: 'transparent',
                cursor: 'pointer',
              }}
              onClick={() => setPresetId(p.id)}
            >
              <div style={{ fontWeight: 600 }}>
                {p.name} · {p.name_zh}
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {p.description}
              </div>
            </button>
          ))}
        </div>
        {selected && (selected.suggested_channels.length > 0 || selected.suggested_context.length > 0) && (
          <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            Suggests {selected.suggested_channels.map((c) => `channel ${c.id}`).join(', ')}
            {selected.suggested_channels.length > 0 && selected.suggested_context.length > 0 ? ' · ' : ''}
            {selected.suggested_context.map((c) => `context ${c.ns}`).join(', ')} — nothing is
            granted until you approve it later.
          </div>
        )}
      </div>
      <div className="field" style={{ marginTop: 12 }}>
        <label>Name (a–z, 0–9, dashes — becomes its identity + chat channel)</label>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value.toLowerCase())}
          placeholder="e.g. watchdog-1"
          maxLength={32}
        />
        {!labelOk && label.length > 0 && (
          <div className="muted" style={{ fontSize: 12 }}>
            lowercase letters, digits and dashes only (max 32)
          </div>
        )}
      </div>
      <div className="field" style={{ marginTop: 12 }}>
        <label>Memory</label>
        <div style={{ display: 'flex', gap: 12 }}>
          <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input
              type="radio"
              checked={memoryMode === 'fresh'}
              onChange={() => setMemoryMode('fresh')}
            />
            Fresh empty namespace{label ? ` (memory:${label})` : ''}
          </label>
          <label
            style={{
              display: 'flex',
              gap: 6,
              alignItems: 'center',
              opacity: inheritable.length === 0 ? 0.5 : 1,
            }}
          >
            <input
              type="radio"
              disabled={inheritable.length === 0}
              checked={memoryMode === 'inherit'}
              onChange={() => setMemoryMode('inherit')}
            />
            Inherit from an archived agent
          </label>
        </div>
        {memoryMode === 'inherit' && (
          <select value={inheritNs} onChange={(e) => setInheritNs(e.target.value)} style={{ marginTop: 6 }}>
            <option value="">choose a kept namespace…</option>
            {inheritable.map((n) => (
              <option key={n.ns} value={n.ns}>
                memory:{n.ns} — kept from “{n.fromLabel}”
              </option>
            ))}
          </select>
        )}
        {memoryMode === 'inherit' && inheritable.length === 0 && (
          <div className="muted" style={{ fontSize: 12 }}>
            No inheritable namespaces — archive an agent with “keep its resources” first.
          </div>
        )}
      </div>
      <div className="muted" style={{ fontSize: 12, marginTop: 12 }}>
        One Touch ID binds the agent on chain, consumes one agent slot, grants ONLY its chat
        channel + memory namespace, provisions its metered LLM key, and boots its sandbox with
        the preset persona.
      </div>
    </Modal>
  );
}

export function ArchiveAgentDialog({
  client,
  actor,
  onClose,
  onArchived,
  showToast,
}: {
  client: AgentKeysClient;
  actor: Actor;
  onClose: () => void;
  onArchived: () => void;
  showToast: (msg: string, sticky?: boolean) => void;
}) {
  const [keep, setKeep] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const ns = actor.memoryNs ?? actor.label;

  const archive = useCallback(async () => {
    if (!actor.deviceKeyHash) {
      showToast('This agent has no on-chain device key hash — cannot archive.');
      return;
    }
    setBusy('Building the archive ceremony…');
    const built = await client.archiveBuild({
      deviceKeyHash: actor.deviceKeyHash,
      resourcesKept: keep,
      memoryNs: ns,
    });
    if (!built.ok) {
      setBusy(null);
      showToast(`Archive build failed — ${built.status?.detail ?? 'check master session'}`);
      return;
    }
    setBusy('Approve with Touch ID…');
    let assertion;
    try {
      const masterCred = getMasterCredId() || null;
      assertion = await getAssertionOverHash(
        built.data.user_op_hash,
        masterCred ? [masterCred] : undefined,
      );
    } catch {
      setBusy(null);
      showToast('Touch ID cancelled — the agent was NOT archived.');
      return;
    }
    setBusy('Submitting on chain…');
    const submitted = await client.archiveSubmit({ user_op: built.data.user_op, assertion });
    setBusy(null);
    if (!submitted.ok) {
      showToast(`Archive submit failed — ${submitted.status?.detail ?? 'handleOps error'}`, true);
      return;
    }
    akLog('archive: confirmed', { txHash: submitted.data.tx_hash, ceremony: submitted.data.ceremony });
    showToast(
      keep
        ? `${actor.label} archived — its slot is free and memory:${ns} stays inheritable.`
        : `${actor.label} archived — its slot is free; memory:${ns} is marked deleted.`,
    );
    onArchived();
    onClose();
  }, [actor, client, keep, ns, onArchived, onClose, showToast]);

  return (
    <Modal
      title={`Archive ${actor.label}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={!!busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={archive} disabled={!!busy}>
            {busy ?? 'Archive · Touch ID'}
          </button>
        </>
      }
    >
      <p>
        Archiving revokes this agent on chain and returns its agent slot. Its chat history keeps
        the channel retention defaults; the manifest + audit records are always retained.
      </p>
      <div className="field" style={{ marginTop: 8 }}>
        <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <input type="radio" checked={keep} onChange={() => setKeep(true)} />
          <span>
            <strong>Keep its resources</strong> — <code>memory:{ns}</code> stays inheritable by a
            future agent (at most one at a time).
          </span>
        </label>
        <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start', marginTop: 6 }}>
          <input type="radio" checked={!keep} onChange={() => setKeep(false)} />
          <span>
            <strong>Delete its resources</strong> — destroys <code>memory:{ns}</code> (every memory
            this agent stored). This cannot be undone; nothing will be inheritable.
          </span>
        </label>
      </div>
    </Modal>
  );
}
