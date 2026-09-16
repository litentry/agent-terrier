'use client';

// The KNOWLEDGE page, shaped like a code host (#695 step F2, plan §9): every
// namespace is a REPOSITORY — the grant unit, stored once on origin (the
// master's canonical memory), cloned read-only into each reader's sandbox.
// The list page is the repository list (name, visibility = the highest tier
// inside, who reads it, updated, pending proposals) plus an "all items" view
// grouped by type / sensitivity / tag and the proposals queue. A repository
// opens to its tabs: Files (the items — typed items are registry rows over
// canonical entries, an older untyped note gets its row from "give it a
// type"), Proposals (what delegates pushed for THIS namespace; accept =
// merge), History (#695 step G — every text a commit replaced, with diffs and
// "restore as next version"), Access (who reads it and through which grant),
// Sync (each clone's launch / pull stage, with "sync now"). The wire is
// unchanged: entries live in `knowledge:<ns>`, an app reads a namespace only
// through the read-only grant its install minted.

import { Fragment, useCallback, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';
import type { AppInstanceRow } from '@/lib/generated/AppInstanceRow';
import type { KnowledgeHistory } from '@/lib/generated/KnowledgeHistory';
import type { ResourceItemRow } from '@/lib/generated/ResourceItemRow';
import type { ResourceKind } from '@/lib/generated/ResourceKind';
import type { AgentKeysClient, ConfigPreset, ConnectionStatus, MemoryCategory } from '@/lib/client/types';
import {
  buildKnowledgeItems,
  filterKnowledge,
  filterNamespaces,
  groupKnowledge,
  itemReaders,
  knowledgeNamespaces,
  liveApps,
  namespaceSummaries,
  proposalsIn,
  type KnowledgeEntry,
  type KnowledgeGroupBy,
  type KnowledgeItem,
  type KnowledgeNamespace,
  type NamespaceReaders,
  type NamespaceSummary,
} from '@/lib/client/knowledge';
import { knowledgeService } from '@/lib/constants';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import { CeremonyRunner } from './ceremony';
import { Chip, DiffView, EmptyState, LifecycleChip, Modal, PageHead, Panel, Tabs } from './shared';
import { errorJson } from '@/lib/client/diff';
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
const KINDS: ResourceKind[] = ['note', 'document', 'profile', 'dataset', 'gallery'];

type ItemMeta = { id: string; name: string; name_zh: string; kind: ResourceKind; tags: string[]; sensitivity: 'safe' | 'sensitive'; ns: string };
/** D-K5 — the row's `content_hash` an edit started from rides along; the daemon refuses a changed row. */
export type KnowledgeAddInput = ItemMeta & { body: string; base_content_hash?: string };
export type KnowledgeUploadInput = ItemMeta & { filename: string; content_type: string; content_b64: string; base_content_hash?: string };
/** `stale` = the daemon refused a stale base — the modal shows the diff and lets the owner reload or overwrite. */
export type KnowledgeSaveOutcome = 'ok' | 'stale' | 'error';

type ListTab = 'repositories' | 'items' | 'proposals';
type NsTab = 'files' | 'proposals' | 'history' | 'access' | 'sync';
type View = { kind: 'list'; tab: ListTab } | { kind: 'ns'; ns: string; tab: NsTab };

/** A stored previous text to save again as the next version (History → restore). */
type Restore = { body: string; label: string };
type ModalState = { edit?: ResourceItemRow; curate?: KnowledgeEntry; ns?: string; restore?: Restore };

const ageOf = (ts: number): string => {
  if (!ts) return '—';
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
};

const shortOmni = (o: string): string => {
  const h = o.replace(/^0x/, '');
  return h.length > 12 ? `${h.slice(0, 6)}…${h.slice(-4)}` : h;
};

/** The delegate chat feed a delegate actor's lifecycle rides (the same id the
 *  Delegates page polls). */
const delegateFeed = (label: string): string => `opchat-${label.replace(' (revoked)', '')}`;

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
  onOpenActor,
  onOpenApps,
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
  /** Access tab — a delegate's grants are edited on its actor page. */
  onOpenActor?: (id: string) => void;
  /** Access tab — an app's grants are its install sheet, on the Applications page. */
  onOpenApps?: () => void;
}) {
  const connected = status.kind === 'connected';
  const busy = planting || initializing;
  const [resources, setResources] = useState<ResourceItemRow[]>([]);
  const [apps, setApps] = useState<AppInstanceRow[]>([]);
  const [registry, setRegistry] = useState('ok');
  const [view, setView] = useState<View>({ kind: 'list', tab: 'repositories' });
  const [groupBy, setGroupBy] = useState<KnowledgeGroupBy>('type');
  const [query, setQuery] = useState('');
  const [nsQuery, setNsQuery] = useState('');
  const [typedOnly, setTypedOnly] = useState(false);
  // null = closed; `edit` pre-fills a curated item (saves as the next version);
  // `curate` registers an older untyped note as a typed item under its own key;
  // `ns` pre-sets the namespace of a new item; `restore` carries an old text.
  const [modal, setModal] = useState<null | ModalState>(null);

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
  // Re-read the registry on connect, after an install / uninstall, and after a
  // plant (D-K2: a plant registers note rows for what it planted).
  useEffect(() => {
    if (connected && !planting) void refresh();
  }, [connected, planting, refresh, reloadKey]);

  const namespaces = useMemo(() => knowledgeNamespaces(categories, resources, entriesByNs, apps, actors), [categories, resources, entriesByNs, apps, actors]);
  const items = useMemo(() => buildKnowledgeItems(resources, entriesByNs), [resources, entriesByNs]);
  const summaries = useMemo(() => namespaceSummaries(namespaces, items, inbox), [namespaces, items, inbox]);
  const shown = useMemo(() => filterKnowledge(items, query, typedOnly), [items, query, typedOnly]);
  const groups = useMemo(() => groupKnowledge(shown, groupBy, namespaces), [shown, groupBy, namespaces]);
  const hasAnything = categories.length > 0 || resources.length > 0;
  const unopened = namespaces.filter((n) => n.notes === null);
  const readingApps = new Set(namespaces.flatMap((n) => n.readers.apps)).size;
  const canCurate = !!client.resourceAdd && connected;

  const openNs = view.kind === 'ns' ? summaries.find((n) => n.ns === view.ns) : undefined;
  const nsItems = useMemo(() => (view.kind === 'ns' ? filterKnowledge(items.filter((it) => it.ns === view.ns), query, typedOnly) : []), [view, items, query, typedOnly]);
  const nsProposals = view.kind === 'ns' ? proposalsIn(inbox, view.ns) : [];

  // Opening a repository decrypts its notes once (the shell's lazy cache).
  useEffect(() => {
    if (view.kind === 'ns' && connected && entriesByNs[view.ns] === undefined) onLoadCategory(view.ns);
  }, [view, connected, entriesByNs, onLoadCategory]);

  const goList = (tab: ListTab = 'repositories') => setView({ kind: 'list', tab });
  const goNs = (ns: string, tab: NsTab = 'files') => setView({ kind: 'ns', ns, tab });

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
      : `Remove "${row.name}" (v${row.version}) from the household's knowledge? Its text stays in History.`;
    if (!window.confirm(q)) return;
    const r = await client.resourceRemove({ id: row.id, force: readers.bound.length > 0 });
    if (!r.ok) {
      showToast(`remove failed — ${r.status?.detail ?? 'error'}`, true);
      return;
    }
    showToast(r.data.removed ? `removed ${row.id} — its entry is gone from knowledge:${row.ns} (kept in History)` : `${row.id} was already gone`);
    await settle(row.ns);
  };

  const add = async (input: KnowledgeAddInput): Promise<KnowledgeSaveOutcome> => {
    if (!client.resourceAdd) return 'error';
    const r = await client.resourceAdd(input);
    if (!r.ok) {
      if (errorJson(r.status?.detail)?.error === 'stale_base') return 'stale';
      showToast(`add failed — ${r.status?.detail ?? 'error'}`, true);
      return 'error';
    }
    showToast(`${input.id} v${r.data.version} planted into knowledge:${input.ns} (${r.data.storage})`);
    await settle(input.ns);
    return 'ok';
  };

  const upload = async (input: KnowledgeUploadInput): Promise<KnowledgeSaveOutcome> => {
    if (!client.resourceUpload) return 'error';
    const r = await client.resourceUpload(input);
    if (!r.ok) {
      if (errorJson(r.status?.detail)?.error === 'stale_base') return 'stale';
      showToast(`upload failed — ${r.status?.detail ?? 'error'}`, true);
      return 'error';
    }
    const kept = r.data.raw_stored === true ? 'file kept' : r.data.raw_stored === false ? 'file not kept — no durable memory plane on this console' : 'no file';
    showToast(`${input.filename} → ${input.id} v${r.data.version}: ${r.data.extracted_bytes} B of text in knowledge:${input.ns} (${kept})`, r.data.raw_stored === false);
    await settle(input.ns);
    return 'ok';
  };

  const editOf = (it: KnowledgeItem): (() => void) | undefined =>
    it.curated ? () => setModal({ edit: it.curated! }) : it.entry && canCurate ? () => setModal({ curate: it.entry! }) : undefined;

  const restoreOf = (it: KnowledgeItem, restore: Restore) => {
    if (it.curated) setModal({ edit: it.curated, restore });
    else if (it.entry) setModal({ curate: it.entry, restore });
  };

  const filterBox = (
    <span style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
      <input style={{ ...INPUT, width: 180, padding: '4px 8px' }} placeholder="filter items…" value={query} onChange={(e) => setQuery(e.target.value)} />
      <label className="muted" style={{ display: 'flex', gap: 5, alignItems: 'center', fontSize: 12 }}>
        <input type="checkbox" checked={typedOnly} onChange={(e) => setTypedOnly(e.target.checked)} /> typed only
      </label>
    </span>
  );

  const listBody = (
    <>
      <PageHead
        crumb="household · knowledge"
        title="Knowledge"
        desc="Every namespace is a repository: kept once on origin, cloned read-only into each app or delegate you grant it to, refreshed every few minutes. Open one for its files, proposals, history, access and sync."
        actions={
          <>
            <button className="btn primary" disabled={!canCurate} onClick={() => setModal({})}>+ add knowledge</button>
            <button className="btn" onClick={() => void refresh()}>refresh</button>
          </>
        }
      />

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
        <Panel title="authoring taxonomy">
          <CeremonyRunner steps={INIT_STEPS} onDone={onInitDone} stepMs={560} />
        </Panel>
      )}

      {planting && (
        <Panel title="planting prepared memory">
          <CeremonyRunner steps={PLANT_STEPS} onDone={onPlantDone} stepMs={620} />
        </Panel>
      )}

      {hasAnything && view.kind === 'list' && (
        <>
          <div className="stats">
            <div className="stat"><div className="v">{summaries.length}</div><div className="k">repositories</div></div>
            <div className="stat"><div className="v">{resources.length}</div><div className="k">typed items</div></div>
            <div className="stat"><div className="v">{readingApps}</div><div className="k">apps reading</div></div>
            <div className="stat"><div className="v">{inbox.length}</div><div className="k">proposals pending</div></div>
          </div>

          <Tabs<ListTab>
            items={[
              { key: 'repositories', label: 'repositories', badge: summaries.length },
              { key: 'items', label: 'all items', badge: items.length },
              { key: 'proposals', label: 'proposals', badge: inbox.length || undefined, attention: inbox.length > 0 },
            ]}
            active={view.tab}
            onChange={(t) => goList(t)}
            right={
              view.tab === 'repositories'
                ? <input style={{ ...INPUT, width: 200, padding: '4px 8px' }} placeholder="find a repository…" value={nsQuery} onChange={(e) => setNsQuery(e.target.value)} />
                : view.tab === 'items' ? filterBox : undefined
            }
          />

          {view.tab === 'repositories' && (
            <>
              <RepoList summaries={filterNamespaces(summaries, nsQuery)} onOpen={(ns) => goNs(ns)} />
              <div className="muted" style={{ fontSize: 11.5, marginTop: 10, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <span>Binding one item to an app grants the app its <strong>whole repository</strong>; the same repository bound to several apps is stored once, never copied.</span>
                <button className="btn ghost sm" onClick={onPlant}>＋ plant demo archive</button>
              </div>
            </>
          )}

          {view.tab === 'items' && (
            <>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '12px 0 10px', flexWrap: 'wrap' }}>
                <span className="muted" style={{ fontSize: 11.5 }}>group by</span>
                {(['type', 'sensitivity', 'tag', 'namespace'] as KnowledgeGroupBy[]).map((g) => (
                  <button key={g} className={`btn sm${groupBy === g ? ' primary' : ''}`} onClick={() => setGroupBy(g)}>{g}</button>
                ))}
                {unopened.length > 0 && (
                  <span className="muted" style={{ fontSize: 11.5, marginLeft: 8 }}>
                    {unopened.length} repositor{unopened.length === 1 ? 'y' : 'ies'} not opened yet — {unopened.length === 1 ? 'its' : 'their'} notes are not listed.{' '}
                    <button className="btn ghost sm" onClick={() => unopened.forEach((n) => onLoadCategory(n.ns))}>open all</button>
                  </span>
                )}
              </div>
              {groups.length === 0 && <div className="muted" style={{ padding: 16 }}>Nothing matches.</div>}
              {groups.map((g) => (
                <Panel key={g.key} title={`${g.label} · ${g.items.length}`} flush>
                  {g.items.map((it) => (
                    <KnowledgeRow
                      key={`${it.ns}/${it.key}`}
                      item={it}
                      showNs
                      readers={itemReaders(it, apps)}
                      onOpen={() => void openItem(it)}
                      onOpenNs={() => goNs(it.ns)}
                      onEdit={editOf(it)}
                      onRemove={it.curated && client.resourceRemove ? () => void removeItem(it) : undefined}
                    />
                  ))}
                </Panel>
              ))}
            </>
          )}

          {view.tab === 'proposals' && (
            inbox.length > 0 ? (
              <InboxPanel
                inbox={inbox}
                busy={inboxBusy}
                onAccept={onAcceptInbox}
                onReject={onRejectInbox}
                onRefresh={onRefreshInbox}
                onViewBody={onViewInboxBody}
                onOpenNs={(ns) => goNs(ns, 'proposals')}
              />
            ) : (
              <div className="muted" style={{ padding: 16, fontSize: 12.5 }}>
                No proposals pending. A delegate that learns something pushes it here as a proposal for you to merge or reject — nothing enters a repository without you.{' '}
                <button className="btn ghost sm" onClick={onRefreshInbox} disabled={inboxBusy}>↻ refresh</button>
              </div>
            )
          )}
        </>
      )}
    </>
  );

  const nsBody = view.kind === 'ns' && (
    <>
      <PageHead
        crumb={
          <>
            <span className="clickable" style={{ cursor: 'pointer', color: 'var(--accent)' }} onClick={() => goList()}>knowledge</span>
            {' / '}
            <code>{view.ns}</code>
          </>
        }
        title={openNs?.label ?? view.ns}
        desc={
          openNs
            ? <>
                <code>knowledge:{openNs.ns}</code> · {openNs.curated} typed · {openNs.notes === null ? 'notes not opened' : openNs.notes === 'loading' ? 'decrypting notes…' : `${openNs.notes} untyped note${openNs.notes === 1 ? '' : 's'}`} · visibility <strong>{openNs.visibility}</strong> · updated {openNs.updated}
              </>
            : <>This repository is not in the taxonomy and holds no item — open it from the list once something is planted.</>
        }
        actions={
          <>
            <button className="btn primary" disabled={!canCurate} onClick={() => setModal({ ns: view.ns })}>+ add to {view.ns}</button>
            <button className="btn" onClick={() => void refresh()}>refresh</button>
            <button className="btn" onClick={() => goList()}>← all repositories</button>
          </>
        }
      />

      <Tabs<NsTab>
        items={[
          { key: 'files', label: 'files', badge: nsItems.length },
          { key: 'proposals', label: 'proposals', badge: nsProposals.length || undefined, attention: nsProposals.length > 0 },
          { key: 'history', label: 'history' },
          { key: 'access', label: 'access', badge: openNs ? openNs.readers.apps.length + openNs.readers.delegates.length : 0 },
          { key: 'sync', label: 'sync' },
        ]}
        active={view.tab}
        onChange={(t) => goNs(view.ns, t)}
        right={view.tab === 'files' ? filterBox : undefined}
      />

      {view.tab === 'files' && (
        <Panel flush>
          {nsItems.map((it) => (
            <KnowledgeRow
              key={`${it.ns}/${it.key}`}
              item={it}
              showNs={false}
              readers={itemReaders(it, apps)}
              onOpen={() => void openItem(it)}
              onEdit={editOf(it)}
              onRemove={it.curated && client.resourceRemove ? () => void removeItem(it) : undefined}
            />
          ))}
          {nsItems.length === 0 && (
            <div className="muted" style={{ padding: 16, fontSize: 12.5 }}>
              {openNs?.notes === 'loading' ? `decrypting knowledge:${view.ns}…` : query ? 'Nothing matches.' : 'Nothing in this repository yet — add an item, or accept a proposal.'}
            </div>
          )}
          {openNs && openNs.notes === null && (
            <div className="muted" style={{ padding: '8px 16px', fontSize: 11.5, display: 'flex', gap: 10, alignItems: 'center' }}>
              <span>{openNs.curated} typed · notes decrypt on open</span>
              <button className="btn sm" onClick={() => onLoadCategory(view.ns)}>open notes</button>
            </div>
          )}
        </Panel>
      )}

      {view.tab === 'proposals' && (
        nsProposals.length > 0 ? (
          <InboxPanel
            inbox={nsProposals}
            busy={inboxBusy}
            onAccept={onAcceptInbox}
            onReject={onRejectInbox}
            onRefresh={onRefreshInbox}
            onViewBody={onViewInboxBody}
          />
        ) : (
          <div className="muted" style={{ padding: 16, fontSize: 12.5 }}>
            No proposals for <code>{view.ns}</code>. When a delegate that reads this repository learns something, it lands here for you to merge or reject.{' '}
            <button className="btn ghost sm" onClick={onRefreshInbox} disabled={inboxBusy}>↻ refresh</button>
          </div>
        )
      )}

      {view.tab === 'history' && (
        <HistoryTab client={client} ns={view.ns} items={items.filter((it) => it.ns === view.ns)} onRestore={restoreOf} />
      )}

      {view.tab === 'access' && openNs && (
        <AccessTab ns={view.ns} apps={apps} actors={actors} onOpenActor={onOpenActor} onOpenApps={onOpenApps} />
      )}

      {view.tab === 'sync' && (
        <SyncTab ns={view.ns} apps={apps} actors={actors} />
      )}
    </>
  );

  return (
    <>
      {view.kind === 'list' ? listBody : nsBody}

      {modal && (
        <KnowledgeItemModal
          client={client}
          edit={modal.edit}
          curate={modal.curate}
          initialNs={modal.ns}
          restore={modal.restore}
          namespaces={namespaces}
          onClose={() => setModal(null)}
          onAdd={add}
          onUpload={upload}
        />
      )}
    </>
  );
}

/** The repository list — one row per namespace, the way a code host lists
 *  repositories: name, visibility (the highest tier inside), who reads it,
 *  what is pending, when it last changed. */
function RepoList({ summaries, onOpen }: { summaries: NamespaceSummary[]; onOpen: (ns: string) => void }) {
  if (summaries.length === 0) return <div className="muted" style={{ padding: 16 }}>No repository matches.</div>;
  return (
    <Panel flush>
      {summaries.map((n) => (
        <div key={n.ns} className="feed-row" style={{ padding: '12px 16px', display: 'grid', gridTemplateColumns: 'minmax(0, 1.6fr) minmax(0, 1fr) auto', gap: 12, alignItems: 'start' }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="clickable" style={{ fontWeight: 600, color: 'var(--accent)', cursor: 'pointer', fontSize: 14 }} onClick={() => onOpen(n.ns)}>{n.label}</span>
              <code className="muted" style={{ fontSize: 11 }}>knowledge:{n.ns}</code>
              <Chip kind={n.visibility === 'sensitive' ? 'bad' : n.visibility === 'safe' ? 'ok' : 'default'}>{n.visibility}</Chip>
              {n.proposals > 0 && <Chip kind="warn">{n.proposals} proposal{n.proposals === 1 ? '' : 's'}</Chip>}
            </div>
            <div className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>
              {n.curated} typed · {n.notes === null ? 'notes not opened' : n.notes === 'loading' ? 'decrypting…' : `${n.notes} untyped note${n.notes === 1 ? '' : 's'}`} · updated {n.updated}
            </div>
          </div>
          <Readers readers={n.readers} />
          <button className="btn sm" onClick={() => onOpen(n.ns)}>open →</button>
        </div>
      ))}
    </Panel>
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
  onOpenNs,
  onEdit,
  onRemove,
}: {
  item: KnowledgeItem;
  showNs: boolean;
  readers: { bound: string[]; namespace: string[] };
  onOpen: () => void;
  onOpenNs?: () => void;
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
          {!row && <span className="muted" style={{ fontSize: 11, fontWeight: 400 }}>untyped</span>}
        </div>
        <div className="muted" style={{ fontSize: 11 }}>
          {showNs && (
            <>
              <span className="clickable" style={{ cursor: onOpenNs ? 'pointer' : undefined, color: onOpenNs ? 'var(--accent)' : undefined }} onClick={onOpenNs}>{item.ns}</span>
              {' / '}
            </>
          )}
          <code>{item.key}</code> · {item.version} · {item.bytes} B · {item.updated}
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
        {onEdit && <>{' '}<button className="btn sm" onClick={onEdit}>{row ? 'edit' : 'give it a type'}</button></>}
        {onRemove && <>{' '}<button className="btn sm" style={{ color: 'var(--danger)' }} onClick={onRemove}>remove</button></>}
      </div>
    </div>
  );
}

// ── History (#695 step G) ────────────────────────────────────────────────────
// Every text a commit replaced — an edit, a merge, a removal, a re-plant — is
// kept on origin as a keyed object (a ring of N per item); the daemon lists
// them newest first. A diff is against the CURRENT text; "restore" opens the
// edit modal with the old text, so the restore is itself a commit (the next
// version), refused like any edit if the item changed meanwhile (D-K5).

function HistoryTab({
  client,
  ns,
  items,
  onRestore,
}: {
  client: AgentKeysClient;
  ns: string;
  items: KnowledgeItem[];
  onRestore: (item: KnowledgeItem, restore: Restore) => void;
}) {
  const [key, setKey] = useState<string>(items[0]?.key ?? '');
  useEffect(() => {
    if (!items.some((i) => i.key === key)) setKey(items[0]?.key ?? '');
  }, [items, key]);
  const item = items.find((i) => i.key === key);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 240px) minmax(0, 1fr)', gap: 14, alignItems: 'start' }}>
      <Panel title="items" flush>
        {items.map((it) => (
          <button
            key={it.key}
            type="button"
            onClick={() => setKey(it.key)}
            style={{
              display: 'block', width: '100%', textAlign: 'left', background: it.key === key ? 'var(--bg-elev)' : 'none', border: 0,
              borderBottom: '1px solid var(--rule-hair)', padding: '8px 14px', font: 'inherit', fontSize: 12.5, cursor: 'pointer', color: 'var(--ink)',
              fontWeight: it.key === key ? 600 : 400,
            }}
          >
            {it.name}
            <span className="muted" style={{ fontSize: 11, marginLeft: 6 }}>{it.version}</span>
          </button>
        ))}
        {items.length === 0 && <div className="muted" style={{ padding: 14, fontSize: 12 }}>Nothing in this repository yet.</div>}
      </Panel>
      {item ? (
        <HistoryPanel key={item.key} client={client} ns={ns} item={item} onRestore={(restore) => onRestore(item, restore)} />
      ) : (
        <div className="muted" style={{ padding: 16, fontSize: 12.5 }}>Pick an item to see the texts it had before.</div>
      )}
    </div>
  );
}

type Opened = Record<number, string | 'loading' | { error: string }>;

function HistoryPanel({
  client,
  ns,
  item,
  onRestore,
}: {
  client: AgentKeysClient;
  ns: string;
  item: KnowledgeItem;
  onRestore: (restore: Restore) => void;
}) {
  const [hist, setHist] = useState<KnowledgeHistory | 'loading' | { error: string }>('loading');
  const [current, setCurrent] = useState<string | null>(item.entry?.body ?? null);
  const [opened, setOpened] = useState<Opened>({});
  const load = useCallback(async () => {
    if (!client.knowledgeHistory) {
      setHist({ error: 'this backend keeps no history' });
      return;
    }
    setHist('loading');
    const r = await client.knowledgeHistory(ns, item.key);
    setHist(r.ok ? r.data : { error: r.status?.detail ?? 'error' });
  }, [client, ns, item.key]);
  useEffect(() => {
    let alive = true;
    void load();
    if (current === null) {
      void client.getMemoryEntries(ns, item.key).then((r) => {
        if (alive && r.ok) setCurrent(r.data.find((e) => e.key === item.key)?.body ?? r.data[0]?.body ?? '');
      });
    }
    return () => {
      alive = false;
    };
    // the current text is fetched once per item; `current` is deliberately not a dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, ns, item.key, load]);

  const toggle = async (n: number) => {
    if (opened[n] !== undefined) {
      setOpened((p) => {
        const c = { ...p };
        delete c[n];
        return c;
      });
      return;
    }
    if (!client.knowledgeVersion) return;
    setOpened((p) => ({ ...p, [n]: 'loading' }));
    const r = await client.knowledgeVersion(ns, item.key, n);
    setOpened((p) => ({ ...p, [n]: r.ok ? r.data.body : { error: r.status?.detail ?? 'error' } }));
  };

  const byLabel = (by: string): ReactNode =>
    by === 'edit' ? 'you edited it'
      : by === 'remove' ? 'you removed it'
        : by === 'plant' ? 'a plant replaced it'
          : by.startsWith('merge:') ? <>merged a proposal from <code>{by.slice(6)}</code></>
            : by;

  return (
    <Panel
      title={`history · ${item.name}`}
      right={hist !== 'loading' && !('error' in hist) ? <span className="muted" style={{ fontSize: 11 }}>{hist.versions.length} of at most {hist.keep} kept · current {item.version}</span> : undefined}
      flush
    >
      {hist === 'loading' && <div className="muted" style={{ padding: 14, fontSize: 12 }}>reading history…</div>}
      {hist !== 'loading' && 'error' in hist && (
        <div className="banner warn" style={{ margin: 12 }}>
          <span className="lbl">history</span>
          <span>couldn&apos;t read it — {hist.error} <button className="btn ghost sm" style={{ marginLeft: 8 }} onClick={() => void load()}>retry</button></span>
        </div>
      )}
      {hist !== 'loading' && !('error' in hist) && hist.storage !== 'durable' && (
        <div className="banner warn" style={{ margin: 12 }}>
          <span className="lbl">not kept</span>
          <span>This daemon has no durable memory plane, so previous versions are not stored.</span>
        </div>
      )}
      {hist !== 'loading' && !('error' in hist) && hist.storage === 'durable' && hist.versions.length === 0 && (
        <div className="muted" style={{ padding: 14, fontSize: 12.5 }}>
          No previous versions yet. Every edit, merge or removal that replaces this item&apos;s text keeps the old text here — the last {hist.keep} of them.
        </div>
      )}
      {hist !== 'loading' && !('error' in hist) && hist.versions.length > 0 && (
        <table className="tab">
          <thead>
            <tr>
              <th>version</th>
              <th>replaced when</th>
              <th className="right">bytes</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {hist.versions.map((v) => {
              const o = opened[v.n];
              return (
                <Fragment key={v.n}>
                  <tr>
                    <td>
                      <span style={{ fontWeight: 600 }}>{v.label || `#${v.n}`}</span>
                      <span className="muted" style={{ marginLeft: 6, fontSize: 11 }}>commit {v.n}</span>
                      <div className="secondary" style={{ fontSize: 11.5 }}>{byLabel(v.by)}</div>
                    </td>
                    <td className="muted" title={new Date(v.ts * 1000).toLocaleString()}>{ageOf(v.ts)}</td>
                    <td className="right mono">{v.bytes}</td>
                    <td className="right" style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn sm" onClick={() => void toggle(v.n)}>{o !== undefined ? 'hide' : 'diff'}</button>
                      {typeof o === 'string' && (
                        <button className="btn sm" style={{ marginLeft: 6 }} onClick={() => onRestore({ body: o, label: v.label || `#${v.n}` })}>restore as next version</button>
                      )}
                    </td>
                  </tr>
                  {o !== undefined && (
                    <tr>
                      <td colSpan={4} style={{ background: 'var(--bg-elev)' }}>
                        {o === 'loading' ? (
                          <span className="muted" style={{ fontSize: 11.5 }}>decrypting the stored text…</span>
                        ) : typeof o === 'object' ? (
                          <span className="muted" style={{ fontSize: 11.5, color: 'var(--danger)' }}>couldn&apos;t load it — {o.error}</span>
                        ) : (
                          <>
                            <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>the stored text (−) against the current text (+)</div>
                            <DiffView before={o} after={current ?? ''} />
                          </>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

// ── Access ───────────────────────────────────────────────────────────────────
// Who reads the repository and through which grant. The grant is the
// namespace: an app's install sheet (`knowledge:<ns>`, read-only) or a scope
// bit on a delegate's actor page — both on chain, both edited where they were
// signed (the audience editor of #674 lands here).

/** An actor's scope bits for a namespace the taxonomy may not name (the scope map is keyed by the known namespaces). */
const scopeBits = (a: Actor, ns: string): { read?: boolean; write?: boolean } | undefined =>
  (a.scope as Record<string, { read?: boolean; write?: boolean }> | undefined)?.[ns];

function nsReaders(ns: string, apps: AppInstanceRow[], actors: Actor[]) {
  const service = knowledgeService(ns);
  const appRows = liveApps(apps).filter((a) => a.services.includes(service) || a.bindings.resources.some((rb) => rb.ns === ns));
  const delegates = actors.filter((a) => a.role === 'agent' && scopeBits(a, ns)?.read === true && !appRows.some((x) => x.label === a.label));
  return { service, appRows, delegates };
}

function AccessTab({
  ns,
  apps,
  actors,
  onOpenActor,
  onOpenApps,
}: {
  ns: string;
  apps: AppInstanceRow[];
  actors: Actor[];
  onOpenActor?: (id: string) => void;
  onOpenApps?: () => void;
}) {
  const { service, appRows, delegates } = nsReaders(ns, apps, actors);
  const none = appRows.length === 0 && delegates.length === 0;
  return (
    <Panel title="who reads this repository" flush>
      {none && (
        <div className="muted" style={{ padding: 16, fontSize: 12.5 }}>
          No one yet. A reader is granted the whole repository: bind one of its items in an app install, or set the <code>{service}</code> scope bit on a delegate&apos;s actor page.
        </div>
      )}
      {!none && (
        <table className="tab">
          <thead>
            <tr>
              <th>reader</th>
              <th>kind</th>
              <th>through</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {appRows.map((a) => {
              const bound = a.bindings.resources.filter((rb) => rb.ns === ns);
              return (
                <tr key={`a-${a.label}`}>
                  <td style={{ fontWeight: 600 }}>{a.label}<div className="secondary">{a.template_id} · {a.status}</div></td>
                  <td><Chip kind="ok">app</Chip></td>
                  <td>
                    {a.services.includes(service)
                      ? <>install sheet · <code>{service}</code> (read-only)</>
                      : <>a binding in this namespace</>}
                    {bound.length > 0 && <div className="secondary">bound: {bound.map((rb) => rb.item_id).join(', ')}</div>}
                  </td>
                  <td className="right">{onOpenApps && <button className="btn sm" onClick={onOpenApps}>applications →</button>}</td>
                </tr>
              );
            })}
            {delegates.map((d) => (
              <tr key={`d-${d.id}`}>
                <td style={{ fontWeight: 600 }}>{d.label}<div className="secondary mono">{shortOmni(d.omniHex)}</div></td>
                <td><Chip>delegate</Chip></td>
                <td>scope bit on chain · <code>{service}</code>{scopeBits(d, ns)?.write ? ' · write' : ' · read'}</td>
                <td className="right">{onOpenActor && <button className="btn sm" onClick={() => onOpenActor(d.id)}>actor page →</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="muted" style={{ padding: '10px 16px', fontSize: 11.5, borderTop: '1px solid var(--rule-hair)' }}>
        Revoking is where the grant was signed: uninstall the app, or clear the scope bit on the actor page — one Touch ID each. A reader&apos;s sandbox keeps a derived copy that the daemon refreshes every few minutes and can never write back here.
      </div>
    </Panel>
  );
}

// ── Sync ─────────────────────────────────────────────────────────────────────
// Each reader runs a CLONE of the repository in its sandbox: seeded from the
// checkpoint, pulled from origin every few minutes (delete-through). The chip
// is the clone's own launch / pull stage (#693); "sync now" asks for a pull.

function SyncTab({ ns, apps, actors }: { ns: string; apps: AppInstanceRow[]; actors: Actor[] }) {
  const { appRows, delegates } = nsReaders(ns, apps, actors);
  const none = appRows.length === 0 && delegates.length === 0;
  return (
    <Panel title="clones" flush>
      {none && <div className="muted" style={{ padding: 16, fontSize: 12.5 }}>No clone — nothing reads this repository yet.</div>}
      {!none && (
        <table className="tab">
          <thead>
            <tr>
              <th>clone</th>
              <th>stage</th>
            </tr>
          </thead>
          <tbody>
            {appRows.map((a) => (
              <tr key={`a-${a.label}`}>
                <td style={{ fontWeight: 600 }}>{a.label}<div className="secondary">app · {a.template_id}</div></td>
                <td><LifecycleChip channelId={a.chat_channel_id} sync /></td>
              </tr>
            ))}
            {delegates.map((d) => (
              <tr key={`d-${d.id}`}>
                <td style={{ fontWeight: 600 }}>{d.label}<div className="secondary">delegate</div></td>
                <td>{d.status === 'bad' ? <span className="muted">revoked</span> : <LifecycleChip channelId={delegateFeed(d.label)} sync />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="muted" style={{ padding: '10px 16px', fontSize: 11.5, borderTop: '1px solid var(--rule-hair)' }}>
        A clone is read-only and derived: what you commit here reaches it on its next pull (every few minutes, or right away with <strong>sync now</strong>); what a clone learns comes back only as a proposal. A chip that stays empty means the clone has not published a stage yet (an older image, or nothing running).
      </div>
    </Panel>
  );
}

/** The one add / upload / edit / curate modal — this page's and the install
 *  wizard's (an empty slot opens it pre-set to the slot's kind). A saved item
 *  is planted as read-only canonical memory under `knowledge:<ns>` and registered
 *  as a typed item. `restore` pre-fills an older text (History): the save is a
 *  normal next version, refused like any edit if the item changed meanwhile. */
export function KnowledgeItemModal({
  client,
  initialKind,
  initialNs,
  edit,
  curate,
  restore,
  namespaces,
  onClose,
  onAdd,
  onUpload,
}: {
  client: AgentKeysClient;
  initialKind?: ResourceKind;
  initialNs?: string;
  edit?: ResourceItemRow;
  curate?: KnowledgeEntry;
  restore?: Restore;
  /** For the namespace hint: who already reads the namespace being typed. */
  namespaces?: KnowledgeNamespace[];
  onClose: () => void;
  onAdd: (input: KnowledgeAddInput) => Promise<KnowledgeSaveOutcome>;
  onUpload: (input: KnowledgeUploadInput) => Promise<KnowledgeSaveOutcome>;
}) {
  const [mode, setMode] = useState<'paste' | 'upload'>('paste');
  const [id, setId] = useState(edit?.id ?? curate?.key ?? '');
  const [name, setName] = useState(edit?.name ?? curate?.title ?? '');
  const [nameZh, setNameZh] = useState(edit?.name_zh ?? '');
  const [kind, setKind] = useState<ResourceKind>(edit?.kind ?? initialKind ?? (curate ? 'note' : 'document'));
  const [tags, setTags] = useState(edit?.tags.join(', ') ?? '');
  const [sensitivity, setSensitivity] = useState<'safe' | 'sensitive'>(edit?.sensitivity ?? 'safe');
  const [ns, setNs] = useState(edit?.ns ?? curate?.ns ?? initialNs ?? 'household');
  const [body, setBody] = useState(restore?.body ?? curate?.body ?? '');
  const [loadingBody, setLoadingBody] = useState(!!edit && !restore);
  const [file, setFile] = useState<{ name: string; type: string; size: number; b64: string } | null>(null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // D-K5 — the row this edit started from; a save names it so a row that
  // changed meanwhile is refused, and the modal shows the diff.
  const [baseHash, setBaseHash] = useState<string | undefined>(edit?.content_hash);
  const [stale, setStale] = useState<{ current: string; currentHash: string } | null>(null);
  // Editing: pre-fill the current text from the namespace (the entry keyed by
  // the id) — unless an older text is being restored.
  useEffect(() => {
    if (!edit || restore) return;
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
  }, [client, edit, restore]);
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
  const submit = async (force: boolean) => {
    setBusy(true);
    const base = force ? undefined : baseHash;
    const done = mode === 'paste' || !file
      ? await onAdd({ ...meta(), body, base_content_hash: base })
      : await onUpload({ ...meta(), filename: file.name, content_type: file.type, content_b64: file.b64, base_content_hash: base });
    setBusy(false);
    if (done === 'ok') onClose();
    if (done === 'stale') {
      // the daemon refused: load what is there now and show the difference
      const r = await client.getMemoryEntries(ns.trim(), id);
      const hit = r.ok ? (r.data.find((e) => e.key === id) ?? r.data[0]) : undefined;
      const list = await client.listResources?.();
      const row = list?.ok ? list.data.items.find((it) => it.id === id) : undefined;
      setStale({ current: hit?.body ?? '', currentHash: row?.content_hash ?? '' });
    }
  };
  const nsInfo = namespaces?.find((n) => n.ns === ns.trim());
  const nsReadersList = nsInfo ? [...nsInfo.readers.apps, ...nsInfo.readers.delegates] : [];
  const title = restore && edit
    ? `Restore ${edit.id} ${restore.label} (saves as v${edit.version + 1})`
    : restore && curate
      ? `Restore ${curate.key} ${restore.label} as a typed item`
      : edit
        ? `Edit ${edit.id} (saves as v${edit.version + 1})`
        : curate
          ? `Give ${curate.key} a type`
          : 'Add knowledge — paste text or upload a file';
  const cta = busy
    ? (mode === 'upload' ? 'uploading…' : 'planting…')
    : restore
      ? 'restore as next version'
      : edit
        ? 'save as next version'
        : curate
          ? 'register'
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
            disabled={!ok || busy || loadingBody || !!stale}
            onClick={() => void submit(false)}
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
            content{loadingBody ? ' (loading the current text…)' : restore ? ` (the text of ${restore.label})` : ''}
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
      {stale && (
        <div style={{ marginTop: 10 }}>
          <div className="banner warn" style={{ marginBottom: 8 }}>
            <span className="lbl">changed meanwhile</span>
            <span>
              This item was saved by someone else since you opened it. Below: the current text against yours (struck through = current lines your text drops).
              <button className="btn sm" style={{ marginLeft: 8 }} onClick={() => { setBody(stale.current); setBaseHash(stale.currentHash); setStale(null); }}>load the current text</button>
              <button className="btn sm" style={{ marginLeft: 6, color: 'var(--danger)' }} onClick={() => { setStale(null); void submit(true); }}>overwrite anyway</button>
            </span>
          </div>
          <DiffView before={stale.current} after={mode === 'paste' ? body : `(the uploaded file ${file?.name ?? ''})`} />
        </div>
      )}
      <p className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
        {namespaces === undefined
          ? <>Apps read it through the read-only <code>knowledge:&lt;ns&gt;</code> grant — the grant covers the whole namespace, never one item.</>
          : nsInfo
            ? nsReadersList.length > 0
              ? <>Repository <code>{nsInfo.ns}</code> is already read by <strong>{nsReadersList.join(', ')}</strong> — they will read this item too (the grant is the namespace, never one item).</>
              : <>No app reads repository <code>{nsInfo.ns}</code> yet; an install that binds this item is granted the whole namespace.</>
            : <>A new repository: the first app you bind this item to is granted all of it. Use a namespace of its own for something only one app should read.</>}
        {curate && idOk && id === curate.key && <> Keeping the note&apos;s key as the id replaces the note in place.</>}
        {curate && idOk && id !== curate.key && <> A different id adds a typed copy beside the note.</>}
        {edit && !restore && <> Saving bumps the version and replaces the previous text for every app that reads it — the previous text stays in History.</>}
        {restore && <> Restoring is a commit: the old text becomes the next version, and the text it replaces is kept in History.</>}
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
  onOpenNs,
}: {
  inbox: ApiInboxItem[];
  busy: boolean;
  /** #390 — skill accepts carry the viewed-body watermark (the item's content_hash). */
  onAccept: (s3Key: string, confirmContentHash?: string) => void;
  onReject: (s3Key: string) => void;
  onRefresh: () => void;
  onViewBody: (s3Key: string) => Promise<string>;
  /** On the list page: the namespace cell opens that repository's proposals. */
  onOpenNs?: (ns: string) => void;
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

  return (
    <Panel title={`proposals · ${inbox.length} pending`} flush>
      <div className="banner" style={{ margin: '8px 12px' }}>
        <span className="lbl">↦ proposals</span>
        <span>
          Learnings your delegates <strong>pushed</strong> for review. Each is staged in your
          inbox — <strong>not yet in the repository</strong>. <strong>Accept</strong> merges it into the named namespace
          (a content-hash-deduped merge; a colliding key asks you first); <strong>reject</strong> discards it. Provenance is stamped by the worker,
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
                      {onOpenNs
                        ? <span className="clickable" style={{ cursor: 'pointer', color: 'var(--accent)' }} onClick={() => onOpenNs(it.ns)}>knowledge:{it.ns}</span>
                        : <>knowledge:{it.ns}</>}
                      {kind !== 'knowledge' && (
                        <span className="count" style={{ marginLeft: 6, textTransform: 'uppercase' }}>{kind}</span>
                      )}
                    </div>
                  </td>
                  <td className="mono muted" title={it.source_delegate_omni}>{shortOmni(it.source_delegate_omni)}</td>
                  <td className="muted">{ageOf(it.ts)}</td>
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
