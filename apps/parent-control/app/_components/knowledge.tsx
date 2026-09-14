'use client';

// The KNOWLEDGE page (owner decision 2026-09-13): ONE surface for everything
// the household's assistants may know — the master's canonical memory
// namespaces AND the curated, app-bindable items (arch.md §5 `resource item`)
// that used to sit on two pages ("memory" and "resources"). The wire is
// unchanged: entries live in `knowledge:<ns>`, a curated item is a registry row
// over one of those entries, and an app reads a namespace through the
// read-only `knowledge:<ns>` grant its install minted. What changed is the view:
// by namespace (the grant unit — each namespace names who reads it) or grouped
// by type / sensitivity / tag; one add-or-upload modal (shared with the
// install wizard); curate-in-place for a plain note.

import { Fragment, useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';
import type { AppInstanceRow } from '@/lib/generated/AppInstanceRow';
import type { ResourceItemRow } from '@/lib/generated/ResourceItemRow';
import type { ResourceKind } from '@/lib/generated/ResourceKind';
import type { AgentKeysClient, ConfigPreset, ConnectionStatus, MemoryCategory } from '@/lib/client/types';
import {
  buildKnowledgeItems,
  filterKnowledge,
  groupKnowledge,
  itemReaders,
  knowledgeNamespaces,
  type KnowledgeEntry,
  type KnowledgeGroupBy,
  type KnowledgeItem,
  type KnowledgeNamespace,
  type NamespaceReaders,
} from '@/lib/client/knowledge';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import { CeremonyRunner } from './ceremony';
import { Chip, EmptyState, Modal, PageHead, Panel, Tabs } from './shared';
import type { Actor, CeremonyStep, PreservedMemory } from './types';

const PLANT_STEPS: CeremonyStep[] = [
  { label: 'Read prepared archive', sub: `${PREPARED_MEMORY.length} entries · travel / personal / family`, onchain: false },
  { label: 'Dedupe against existing', sub: 'content-hash compare · server-side (re-plant is a no-op)', onchain: false },
  { label: 'Encrypt envelopes', sub: 'AES-256-GCM under K3 epoch v1 KEK · per-namespace JSON array', onchain: false },
  { label: 'Write memory + taxonomy', sub: 'POST /v1/master/memory/plant → knowledge:<ns> blobs + config/memory-taxonomy', onchain: false },
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

const INPUT: CSSProperties = { padding: '7px 9px', fontSize: 12.5, border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)', width: '100%' };
const ID_RE = /^[a-z0-9-]{1,48}$/;
const KINDS: ResourceKind[] = ['document', 'profile', 'dataset', 'gallery'];

type ItemMeta = { id: string; name: string; name_zh: string; kind: ResourceKind; tags: string[]; sensitivity: 'safe' | 'sensitive'; ns: string };
export type KnowledgeAddInput = ItemMeta & { body: string };
export type KnowledgeUploadInput = ItemMeta & { filename: string; content_type: string; content_b64: string };

export function KnowledgePage({
  client,
  showToast,
  reloadKey = 0,
  categories,
  entriesByNs,
  actors,
  status,
  presets,
  defaultPresetId,
  initializing,
  planting,
  inbox,
  inboxBusy,
  onInitDefault,
  onInitDone,
  onPlant,
  onPlantDone,
  onLoadCategory,
  onReloadNamespace,
  onView,
  onAcceptInbox,
  onRejectInbox,
  onRefreshInbox,
  onViewInboxBody,
}: {
  client: AgentKeysClient;
  showToast: (msg: string, sticky?: boolean) => void;
  /** Bumped by the shell after an install / uninstall — the reader chips re-read the app registry. */
  reloadKey?: number;
  categories: MemoryCategory[];
  entriesByNs: Record<string, NsEntries>;
  /** All actors — which delegates can READ each namespace (a delegate's `knowledge:<ns>` grant). */
  actors: Actor[];
  status: ConnectionStatus;
  presets: ConfigPreset[];
  defaultPresetId: string;
  initializing: boolean;
  planting: boolean;
  /** #339 P2 — absorption-inbox curate queue (delegate proposals). */
  inbox: ApiInboxItem[];
  inboxBusy: boolean;
  onInitDefault: (presetId: string) => void;
  onInitDone: () => void;
  onPlant: () => void;
  onPlantDone: () => void;
  onLoadCategory: (ns: string) => void;
  /** Re-decrypt one namespace after this page changed it (add / edit / remove / curate). */
  onReloadNamespace: (ns: string) => Promise<void>;
  onView: (m: PreservedMemory) => void;
  onAcceptInbox: (s3Key: string, confirmContentHash?: string) => void;
  onRejectInbox: (s3Key: string) => void;
  onRefreshInbox: () => void;
  /** #339 P2 — lazily fetch one proposal's full body for review. */
  onViewInboxBody: (s3Key: string) => Promise<string>;
}) {
  const connected = status.kind === 'connected';
  const busy = planting || initializing;
  const [resources, setResources] = useState<ResourceItemRow[]>([]);
  const [apps, setApps] = useState<AppInstanceRow[]>([]);
  const [registry, setRegistry] = useState('ok');
  const [groupBy, setGroupBy] = useState<KnowledgeGroupBy>('namespace');
  const [query, setQuery] = useState('');
  const [bindableOnly, setBindableOnly] = useState(false);
  // null = closed; `edit` pre-fills a curated item (saves as the next version);
  // `curate` promotes a plain note into a typed, bindable item under its own key.
  const [modal, setModal] = useState<null | { edit?: ResourceItemRow; curate?: KnowledgeEntry }>(null);

  const refresh = useCallback(async () => {
    if (client.listResources) {
      const r = await client.listResources();
      if (r.ok) {
        setResources(r.data.items);
        setRegistry(r.data.storage);
      }
    }
    if (client.listApps) {
      const a = await client.listApps();
      if (a.ok) setApps(a.data.apps);
    }
  }, [client]);
  useEffect(() => {
    if (connected) void refresh();
  }, [connected, refresh, reloadKey]);

  const namespaces = useMemo(() => knowledgeNamespaces(categories, resources, entriesByNs, apps, actors), [categories, resources, entriesByNs, apps, actors]);
  const items = useMemo(() => buildKnowledgeItems(resources, entriesByNs), [resources, entriesByNs]);
  const shown = useMemo(() => filterKnowledge(items, query, bindableOnly), [items, query, bindableOnly]);
  const groups = useMemo(() => groupKnowledge(shown, groupBy, namespaces), [shown, groupBy, namespaces]);
  const hasAnything = categories.length > 0 || resources.length > 0;
  const unopened = namespaces.filter((n) => n.notes === null);
  const readingApps = new Set(namespaces.flatMap((n) => n.readers.apps)).size;
  const canCurate = !!client.resourceAdd && connected;

  // A change to a namespace this page already decrypted must re-decrypt it, or
  // the shell's cache keeps showing the pre-change entry.
  const settle = async (ns: string) => {
    await refresh();
    if (entriesByNs[ns] !== undefined) await onReloadNamespace(ns);
  };

  const openItem = async (it: KnowledgeItem) => {
    if (it.entry) {
      onView(it.entry);
      return;
    }
    const r = await client.getMemoryEntries(it.ns, it.key);
    const hit = r.ok ? (r.data.find((e) => e.key === it.key) ?? r.data[0]) : undefined;
    if (!hit) {
      showToast(`Couldn't open ${it.ns}/${it.key} — ${r.ok ? 'no entry under that key' : (r.status?.detail ?? 'error')}`, true);
      return;
    }
    onView(hit);
  };

  const removeItem = async (it: KnowledgeItem) => {
    const row = it.curated;
    if (!row || !client.resourceRemove) return;
    const readers = itemReaders(it, apps);
    const q = readers.bound.length > 0
      ? `Remove "${row.name}"? ${readers.bound.join(', ')} ${readers.bound.length === 1 ? 'is' : 'are'} bound to it — the binding stays, the item is gone. Remove anyway?`
      : `Remove "${row.name}" (v${row.version}) from the household's knowledge?`;
    if (!window.confirm(q)) return;
    const r = await client.resourceRemove({ id: row.id, force: readers.bound.length > 0 });
    if (!r.ok) {
      showToast(`remove failed — ${r.status?.detail ?? 'error'}`, true);
      return;
    }
    showToast(r.data.removed ? `removed ${row.id} — its entry is gone from knowledge:${row.ns}` : `${row.id} was already gone`);
    await settle(row.ns);
  };

  const add = async (input: KnowledgeAddInput): Promise<boolean> => {
    if (!client.resourceAdd) return false;
    const r = await client.resourceAdd(input);
    if (!r.ok) {
      showToast(`add failed — ${r.status?.detail ?? 'error'}`, true);
      return false;
    }
    showToast(`${input.id} v${r.data.version} planted into knowledge:${input.ns} (${r.data.storage})`);
    await settle(input.ns);
    return true;
  };

  const upload = async (input: KnowledgeUploadInput): Promise<boolean> => {
    if (!client.resourceUpload) return false;
    const r = await client.resourceUpload(input);
    if (!r.ok) {
      showToast(`upload failed — ${r.status?.detail ?? 'error'}`, true);
      return false;
    }
    const kept = r.data.raw_stored === true ? 'file kept' : r.data.raw_stored === false ? 'file not kept — no durable memory plane on this console' : 'no file';
    showToast(`${input.filename} → ${input.id} v${r.data.version}: ${r.data.extracted_bytes} B of text in knowledge:${input.ns} (${kept})`, r.data.raw_stored === false);
    await settle(input.ns);
    return true;
  };

  return (
    <>
      <PageHead
        crumb="household · knowledge"
        title="Knowledge"
        desc="Everything your household's assistants may know, kept once per namespace. An app reads a namespace only through the read-only grant you sign at install; its sandbox keeps a derived copy the daemon refreshes every few minutes and can never write back here."
        actions={
          <>
            <button className="btn primary" disabled={!canCurate} onClick={() => setModal({})}>+ add knowledge</button>
            <button className="btn" onClick={() => void refresh()}>refresh</button>
          </>
        }
      />

      {/* #339 P2 — absorption-inbox curate queue: delegate proposals (the
          master-hub "push" channel) awaiting accept-into-canonical or reject. */}
      {connected && inbox.length > 0 && (
        <InboxPanel
          inbox={inbox}
          busy={inboxBusy}
          onAccept={onAcceptInbox}
          onReject={onRejectInbox}
          onRefresh={onRefreshInbox}
          onViewBody={onViewInboxBody}
        />
      )}

      {registry !== 'ok' && connected && (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">{registry}</span>
          <span>The item registry is not durable on this daemon (no config worker) — curated items are recorded in RAM only.</span>
        </div>
      )}

      {!hasAnything && !busy && (
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
            title="knowledge unavailable"
            hint="Knowledge is authored + read through the daemon (GET/POST /v1/master/config, /v1/master/memory, /v1/master/resources). Connect a daemon to initialize your categories and populate this view."
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

      {hasAnything && (
        <>
          <div className="stats">
            <div className="stat"><div className="v">{namespaces.length}</div><div className="k">namespaces</div></div>
            <div className="stat"><div className="v">{resources.length}</div><div className="k">bindable items</div></div>
            <div className="stat"><div className="v">{readingApps}</div><div className="k">apps reading</div></div>
          </div>

          <div className="banner">
            <span className="lbl">namespace = the grant</span>
            <span>
              Binding one item to an app grants the app <strong>its whole namespace</strong>; the same namespace bound to several apps is stored once, never copied.
              A plain note is knowledge an app cannot be bound to yet — <strong>curate</strong> it to give it a type and make it bindable.
              <button className="btn ghost sm" style={{ marginLeft: 10 }} onClick={onPlant}>＋ plant demo archive</button>
            </span>
          </div>

          <Tabs<KnowledgeGroupBy>
            items={[
              { key: 'namespace', label: 'by namespace', badge: namespaces.length },
              { key: 'type', label: 'by type' },
              { key: 'sensitivity', label: 'by sensitivity' },
              { key: 'tag', label: 'by tag' },
            ]}
            active={groupBy}
            onChange={setGroupBy}
            right={
              <span style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <input style={{ ...INPUT, width: 180, padding: '4px 8px' }} placeholder="filter…" value={query} onChange={(e) => setQuery(e.target.value)} />
                <label className="muted" style={{ display: 'flex', gap: 5, alignItems: 'center', fontSize: 12 }}>
                  <input type="checkbox" checked={bindableOnly} onChange={(e) => setBindableOnly(e.target.checked)} /> bindable only
                </label>
              </span>
            }
          />

          {groupBy !== 'namespace' && unopened.length > 0 && (
            <div className="muted" style={{ fontSize: 11.5, margin: '10px 0' }}>
              {unopened.length} namespace{unopened.length === 1 ? '' : 's'} not opened yet — {unopened.length === 1 ? 'its' : 'their'} notes are not grouped here.{' '}
              <button className="btn ghost sm" onClick={() => unopened.forEach((n) => onLoadCategory(n.ns))}>open all</button>
            </div>
          )}

          {groups.length === 0 && <div className="muted" style={{ padding: 16 }}>Nothing matches.</div>}

          {groups.map((g) => {
            const n = groupBy === 'namespace' ? namespaces.find((x) => x.ns === g.key) : undefined;
            return (
              <Panel key={g.key} title={`── ${g.label}${n ? '' : ` · ${g.items.length}`}`} flush right={n ? <Readers readers={n.readers} /> : undefined}>
                {g.items.map((it) => (
                  <KnowledgeRow
                    key={`${it.ns}/${it.key}`}
                    item={it}
                    showNs={!n}
                    readers={itemReaders(it, apps)}
                    onOpen={() => void openItem(it)}
                    onEdit={it.curated ? () => setModal({ edit: it.curated! }) : it.entry && canCurate ? () => setModal({ curate: it.entry! }) : undefined}
                    onRemove={it.curated && client.resourceRemove ? () => void removeItem(it) : undefined}
                  />
                ))}
                {n && (
                  <div className="muted" style={{ padding: '8px 16px', fontSize: 11.5, display: 'flex', gap: 10, alignItems: 'center' }}>
                    {n.notes === null ? (
                      <>
                        <span>{n.curated} bindable · notes decrypt on open</span>
                        <button className="btn sm" onClick={() => onLoadCategory(n.ns)}>open notes</button>
                      </>
                    ) : n.notes === 'loading' ? (
                      <span>decrypting knowledge:{n.ns}…</span>
                    ) : (
                      <span>{n.curated} bindable · {n.notes} note{n.notes === 1 ? '' : 's'}</span>
                    )}
                  </div>
                )}
              </Panel>
            );
          })}
        </>
      )}

      {modal && (
        <KnowledgeItemModal
          client={client}
          edit={modal.edit}
          curate={modal.curate}
          namespaces={namespaces}
          onClose={() => setModal(null)}
          onAdd={add}
          onUpload={upload}
        />
      )}
    </>
  );
}

function Readers({ readers }: { readers: NamespaceReaders }) {
  const none = readers.apps.length === 0 && readers.delegates.length === 0;
  return (
    <span style={{ display: 'flex', gap: 5, flexWrap: 'wrap', alignItems: 'center', fontSize: 11 }}>
      <span className="muted" title="Who reads this namespace: apps through the read-only knowledge:<ns> grant their install minted, delegates through a scope bit granted on their actor page.">read by</span>
      {none && <span className="muted" style={{ fontStyle: 'italic' }}>no one yet</span>}
      {readers.apps.map((l) => <Chip key={`a-${l}`} kind="ok">{l}</Chip>)}
      {readers.delegates.map((l) => <Chip key={`d-${l}`}>{l}</Chip>)}
    </span>
  );
}

function KnowledgeRow({
  item,
  showNs,
  readers,
  onOpen,
  onEdit,
  onRemove,
}: {
  item: KnowledgeItem;
  showNs: boolean;
  readers: { bound: string[]; namespace: string[] };
  onOpen: () => void;
  onEdit?: () => void;
  onRemove?: () => void;
}) {
  const row = item.curated;
  return (
    <div className="feed-row" style={{ padding: '10px 16px', display: 'grid', gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr) auto', gap: 12, alignItems: 'start' }}>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontWeight: 600, display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="clickable" style={{ cursor: 'pointer' }} onClick={onOpen}>{item.name}</span>
          <Chip kind={row ? 'ok' : 'default'}>{item.kind}</Chip>
          {item.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>}
          {!row && <span className="muted" style={{ fontSize: 11, fontWeight: 400 }}>not bindable yet</span>}
        </div>
        <div className="muted" style={{ fontSize: 11 }}>
          <code>{showNs ? `${item.ns}/` : ''}{item.key}</code> · {item.version} · {item.bytes} B · {item.updated}
          {row?.filename ? <> · from <code>{row.filename}</code>{row.raw_object_key ? ' · file kept' : ' · file not kept'}</> : null}
        </div>
        {(item.tags.length > 0 || row?.name_zh) && (
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4, fontSize: 11 }}>
            {row?.name_zh && <span className="muted">{row.name_zh}</span>}
            {item.tags.map((t) => <span key={t} className="chip">{t}</span>)}
          </div>
        )}
        {item.preview && <div className="muted" style={{ fontSize: 11.5, marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.preview}</div>}
      </div>
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', fontSize: 12, alignItems: 'center' }}>
        {readers.bound.length === 0 && readers.namespace.length === 0 && <span className="muted" style={{ fontSize: 11.5 }}>no app reads it</span>}
        {readers.bound.map((l) => <Chip key={`b-${l}`} kind="ok">{l} · bound</Chip>)}
        {readers.namespace.map((l) => <Chip key={`n-${l}`}>{l} · via namespace</Chip>)}
      </div>
      <div style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
        <button className="btn sm" onClick={onOpen}>open</button>
        {onEdit && <>{' '}<button className="btn sm" onClick={onEdit}>{row ? 'edit' : 'curate'}</button></>}
        {onRemove && <>{' '}<button className="btn sm" style={{ color: 'var(--danger)' }} onClick={onRemove}>remove</button></>}
      </div>
    </div>
  );
}

/** The one add / upload / edit / curate modal — this page's and the install
 *  wizard's (an empty slot opens it pre-set to the slot's kind). A saved item
 *  is planted as read-only canonical memory under `knowledge:<ns>` and registered
 *  as a typed, bindable item. */
export function KnowledgeItemModal({
  client,
  initialKind,
  edit,
  curate,
  namespaces,
  onClose,
  onAdd,
  onUpload,
}: {
  client: AgentKeysClient;
  initialKind?: ResourceKind;
  edit?: ResourceItemRow;
  curate?: KnowledgeEntry;
  /** For the namespace hint: who already reads the namespace being typed. */
  namespaces?: KnowledgeNamespace[];
  onClose: () => void;
  onAdd: (input: KnowledgeAddInput) => Promise<boolean>;
  onUpload: (input: KnowledgeUploadInput) => Promise<boolean>;
}) {
  const [mode, setMode] = useState<'paste' | 'upload'>('paste');
  const [id, setId] = useState(edit?.id ?? curate?.key ?? '');
  const [name, setName] = useState(edit?.name ?? curate?.title ?? '');
  const [nameZh, setNameZh] = useState(edit?.name_zh ?? '');
  const [kind, setKind] = useState<ResourceKind>(edit?.kind ?? initialKind ?? 'document');
  const [tags, setTags] = useState(edit?.tags.join(', ') ?? '');
  const [sensitivity, setSensitivity] = useState<'safe' | 'sensitive'>(edit?.sensitivity ?? 'safe');
  const [ns, setNs] = useState(edit?.ns ?? curate?.ns ?? 'household');
  const [body, setBody] = useState(curate?.body ?? '');
  const [loadingBody, setLoadingBody] = useState(!!edit);
  const [file, setFile] = useState<{ name: string; type: string; size: number; b64: string } | null>(null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Editing: pre-fill the current text from the namespace (the entry keyed by the id).
  useEffect(() => {
    if (!edit) return;
    let alive = true;
    void (async () => {
      const r = await client.getMemoryEntries(edit.ns, edit.object_key);
      if (!alive) return;
      if (r.ok) {
        const hit = r.data.find((e) => e.key === edit.object_key) ?? r.data[0];
        if (hit) setBody(hit.body);
      }
      setLoadingBody(false);
    })();
    return () => {
      alive = false;
    };
  }, [client, edit]);
  const MAX = 5 * 1024 * 1024;
  const pickFile = (f: File | undefined) => {
    setFileErr(null);
    setFile(null);
    if (!f) return;
    if (f.size > MAX) {
      setFileErr(`${f.name} is ${(f.size / 1048576).toFixed(1)} MB — the cap is 5 MB`);
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => setFileErr(`could not read ${f.name}`);
    reader.onload = () => {
      const buf = new Uint8Array(reader.result as ArrayBuffer);
      let bin = '';
      for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
      setFile({ name: f.name, type: f.type, size: f.size, b64: btoa(bin) });
      if (!name.trim()) setName(f.name.replace(/\.[^.]+$/, ''));
      if (!id) setId(f.name.replace(/\.[^.]+$/, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48));
      if (f.type.startsWith('image/')) setKind('gallery');
    };
    reader.readAsArrayBuffer(f);
  };
  const idOk = ID_RE.test(id) && !id.startsWith('-') && !id.endsWith('-');
  const ok = idOk && name.trim() && ns.trim() && (mode === 'paste' ? body.trim() : !!file);
  const meta = (): ItemMeta => ({ id, name: name.trim(), name_zh: nameZh.trim(), kind, tags: tags.split(',').map((t) => t.trim()).filter(Boolean), sensitivity, ns: ns.trim() });
  const nsInfo = namespaces?.find((n) => n.ns === ns.trim());
  const nsReaders = nsInfo ? [...nsInfo.readers.apps, ...nsInfo.readers.delegates] : [];
  const title = edit
    ? `Edit ${edit.id} (saves as v${edit.version + 1})`
    : curate
      ? `Curate ${curate.key} as a bindable item`
      : 'Add knowledge — paste text or upload a file';
  const cta = busy
    ? (mode === 'upload' ? 'uploading…' : 'planting…')
    : edit
      ? 'save as next version'
      : curate
        ? 'curate'
        : mode === 'upload'
          ? 'upload'
          : 'add';
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>cancel</button>
          <button
            className="btn primary"
            disabled={!ok || busy || loadingBody}
            onClick={async () => {
              setBusy(true);
              const done = mode === 'paste' || !file
                ? await onAdd({ ...meta(), body })
                : await onUpload({ ...meta(), filename: file.name, content_type: file.type, content_b64: file.b64 });
              setBusy(false);
              if (done) onClose();
            }}
          >
            {cta}
          </button>
        </>
      }
    >
      {!edit && !curate && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
          <button className={`btn sm${mode === 'paste' ? ' primary' : ''}`} onClick={() => setMode('paste')}>paste text</button>
          <button className={`btn sm${mode === 'upload' ? ' primary' : ''}`} onClick={() => setMode('upload')}>upload a file</button>
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <label className="muted" style={{ fontSize: 12 }}>id<input style={INPUT} value={id} disabled={!!edit} onChange={(e) => setId(e.target.value.trim().toLowerCase())} placeholder="food-preferences" /></label>
        <label className="muted" style={{ fontSize: 12 }}>namespace<input style={INPUT} value={ns} disabled={!!edit || !!curate} onChange={(e) => setNs(e.target.value)} /></label>
        <label className="muted" style={{ fontSize: 12 }}>name<input style={INPUT} value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="muted" style={{ fontSize: 12 }}>名称 (中文)<input style={INPUT} value={nameZh} onChange={(e) => setNameZh(e.target.value)} /></label>
        <label className="muted" style={{ fontSize: 12 }}>type
          <select style={INPUT} value={kind} onChange={(e) => setKind(e.target.value as ResourceKind)}>
            {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </label>
        <label className="muted" style={{ fontSize: 12 }}>sensitivity
          <select style={INPUT} value={sensitivity} onChange={(e) => setSensitivity(e.target.value as typeof sensitivity)}>
            <option value="safe">safe</option>
            <option value="sensitive">sensitive</option>
          </select>
        </label>
        <label className="muted" style={{ fontSize: 12, gridColumn: '1 / -1' }}>tags (comma-separated)<input style={INPUT} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="food, allergies" /></label>
        {mode === 'paste' ? (
          <label className="muted" style={{ fontSize: 12, gridColumn: '1 / -1' }}>
            content{loadingBody ? ' (loading the current text…)' : ''}
            <textarea style={{ ...INPUT, minHeight: 140, fontFamily: 'inherit' }} value={body} onChange={(e) => setBody(e.target.value)} />
          </label>
        ) : (
          <label className="muted" style={{ fontSize: 12, gridColumn: '1 / -1' }}>
            file (txt · md · csv · json · pdf · image, up to 5 MB)
            <input type="file" accept=".txt,.md,.markdown,.csv,.tsv,.json,.yaml,.yml,.pdf,image/*" style={{ ...INPUT, padding: 6 }} onChange={(e) => pickFile(e.target.files?.[0])} />
            {file && <span style={{ display: 'block', marginTop: 4 }}>{file.name} · {file.type || 'unknown type'} · {(file.size / 1024).toFixed(1)} KB — the text is extracted on save; an image becomes a gallery caption.</span>}
            {fileErr && <span style={{ display: 'block', marginTop: 4, color: 'var(--danger)' }}>⚠ {fileErr}</span>}
          </label>
        )}
      </div>
      <p className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
        {namespaces === undefined
          ? <>Apps read it through the read-only <code>memory:&lt;ns&gt;</code> grant — the grant covers the whole namespace, never one item.</>
          : nsInfo
            ? nsReaders.length > 0
              ? <>Namespace <code>{nsInfo.ns}</code> is already read by <strong>{nsReaders.join(', ')}</strong> — they will read this item too (the grant is the namespace, never one item).</>
              : <>No app reads namespace <code>{nsInfo.ns}</code> yet; an install that binds this item is granted the whole namespace.</>
            : <>A new namespace: the first app you bind this item to is granted all of it. Use a namespace of its own for something only one app should read.</>}
        {curate && idOk && id === curate.key && <> Keeping the note&apos;s key as the id replaces the note in place.</>}
        {curate && idOk && id !== curate.key && <> A different id adds a curated copy beside the note.</>}
        {edit && <> Saving bumps the version and replaces the previous text for every app that reads it.</>}
      </p>
    </Modal>
  );
}

// #339 P2 — the absorption-inbox curate queue. Each row is a delegate's PROPOSAL
// (master-hub "push"): a learning a delegate pushed into the master's staging
// inbox, awaiting the master's review. `source` + `ns` are worker-stamped (the
// delegate cannot forge its own attribution, §8). Accept curates it INTO
// canonical memory (the PR-merge); reject discards it. Nothing here is canonical
// until accepted — this is staging, never a blind write.
function InboxPanel({
  inbox,
  busy,
  onAccept,
  onReject,
  onRefresh,
  onViewBody,
}: {
  inbox: ApiInboxItem[];
  busy: boolean;
  /** #390 — skill accepts carry the viewed-body watermark (the item's content_hash). */
  onAccept: (s3Key: string, confirmContentHash?: string) => void;
  onReject: (s3Key: string) => void;
  onRefresh: () => void;
  onViewBody: (s3Key: string) => Promise<string>;
}) {
  // Lazy body view: presence in `bodies` = expanded. 'loading' while fetching,
  // the string when decrypted, {error} on failure. The list carries only metadata
  // (#339 P2), so the full proposal body is fetched on demand via inbox-get.
  const [bodies, setBodies] = useState<Record<string, string | 'loading' | { error: string }>>({});
  const toggleBody = (s3Key: string) => {
    if (bodies[s3Key] !== undefined) {
      setBodies((p) => {
        const n = { ...p };
        delete n[s3Key];
        return n;
      });
      return;
    }
    setBodies((p) => ({ ...p, [s3Key]: 'loading' }));
    onViewBody(s3Key)
      .then((body) => setBodies((p) => ({ ...p, [s3Key]: body })))
      .catch((e: Error) => setBodies((p) => ({ ...p, [s3Key]: { error: e.message } })));
  };
  const shortOmni = (o: string) => {
    const h = o.replace(/^0x/, '');
    return h.length > 12 ? `${h.slice(0, 6)}…${h.slice(-4)}` : h;
  };
  const age = (ts: number) => {
    if (!ts) return '—';
    const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  };

  return (
    <Panel title={`── inbox · ${inbox.length} pending`} flush>
      <div className="banner" style={{ margin: '8px 12px' }}>
        <span className="lbl">↦ absorption</span>
        <span>
          Learnings your delegates <strong>pushed</strong> for review (master-hub absorption). Each is staged in your
          inbox — <strong>not yet canonical</strong>. <strong>Accept</strong> curates it into the named namespace
          (a content-hash-deduped merge); <strong>reject</strong> discards it. Provenance is stamped by the worker,
          so a delegate can&apos;t fake who proposed what.
          <button className="btn ghost sm" style={{ marginLeft: 10 }} onClick={onRefresh} disabled={busy}>↻ refresh</button>
        </span>
      </div>
      <table className="tab">
        <thead>
          <tr>
            <th>proposal</th>
            <th>from delegate</th>
            <th>age</th>
            <th className="right">bytes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {inbox.map((it) => {
            const b = bodies[it.s3_key];
            const expanded = b !== undefined;
            // #390 §16.2 — the per-kind adoption gate, mirrored in the UI:
            // knowledge = plain accept; skill = accept DISABLED until the body
            // was viewed (the accept then carries the content_hash watermark);
            // persona = never inbox-adoptable (master-authored — Agent panel).
            const kind = it.kind ?? 'knowledge';
            const bodyViewed = typeof b === 'string';
            const skillBlocked = kind === 'skill' && !bodyViewed;
            return (
              <Fragment key={it.s3_key}>
                <tr>
                  <td>
                    <span className="mono" style={{ fontWeight: 500 }}>{it.key}</span>
                    <div className="secondary">
                      knowledge:{it.ns}
                      {kind !== 'knowledge' && (
                        <span className="count" style={{ marginLeft: 6, textTransform: 'uppercase' }}>{kind}</span>
                      )}
                    </div>
                  </td>
                  <td className="mono muted" title={it.source_delegate_omni}>{shortOmni(it.source_delegate_omni)}</td>
                  <td className="muted">{age(it.ts)}</td>
                  <td className="right mono">{it.bytes}</td>
                  <td className="right" style={{ whiteSpace: 'nowrap' }}>
                    <button className="btn sm" onClick={() => toggleBody(it.s3_key)}>{expanded ? 'hide' : 'view'}</button>
                    {kind === 'persona' ? (
                      <span className="muted" style={{ marginLeft: 6, fontSize: 11 }} title="Persona is master-authored — edit it in the delegate's Agent panel. Delegate persona proposals are never adoptable.">
                        not adoptable
                      </span>
                    ) : (
                      <button
                        className="btn primary sm"
                        style={{ marginLeft: 6 }}
                        disabled={busy || skillBlocked}
                        title={skillBlocked ? 'Skills must be reviewed before adoption — view the body first.' : undefined}
                        onClick={() => onAccept(it.s3_key, kind === 'skill' ? it.content_hash : undefined)}
                      >
                        accept
                      </button>
                    )}
                    <button className="btn ghost sm" style={{ marginLeft: 6 }} disabled={busy} onClick={() => onReject(it.s3_key)}>reject</button>
                  </td>
                </tr>
                {expanded && (
                  <tr>
                    <td colSpan={5} style={{ background: 'var(--bg-elev, #faf8f2)' }}>
                      {b === 'loading' ? (
                        <span className="muted" style={{ fontSize: 11.5 }}>decrypting proposal…</span>
                      ) : typeof b === 'object' ? (
                        <span className="muted" style={{ fontSize: 11.5, color: 'var(--err, #b3261e)' }}>couldn&apos;t load body — {b.error}</span>
                      ) : (
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, lineHeight: 1.5 }}>{b}</pre>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </Panel>
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

  const card: CSSProperties = {
    border: '1px solid var(--rule-soft, #e6e0d4)', borderRadius: 8,
    padding: '16px 18px', textAlign: 'left', background: 'var(--bg-elev, #fff)',
  };
  const head: CSSProperties = {
    fontSize: 12, fontWeight: 600, letterSpacing: '0.02em', marginBottom: 10,
    display: 'flex', alignItems: 'center', gap: 8,
  };

  return (
    <div className="empty-memory" style={{ maxWidth: 560 }}>
      <div className="serif" style={{ fontSize: 40, fontStyle: 'italic', color: 'var(--ink-faint)', marginBottom: 4 }}>∅</div>
      <h2 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 8px' }}>Set up your categories</h2>
      <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', margin: '0 auto 20px' }}>
        Author your <strong>category taxonomy</strong> — the vocabulary agentKeys uses to scope what an agent can access:
        the knowledge it reads, the credentials it uses, and more data classes as you add them. Two ways to start:
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
