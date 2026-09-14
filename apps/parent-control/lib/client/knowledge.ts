// The Knowledge page's view logic (owner decision 2026-09-13): the console
// shows the master's canonical memory AND the curated resource items as ONE
// "Knowledge" surface — the wire spellings stay `knowledge:<ns>` / `resource
// item` (arch.md §5). Everything here is a pure function over the daemon's
// rows, so the grouping, the reader indexes and the edit-impact notice are
// unit-tested without React.

import type { AppInstanceRow } from '../generated/AppInstanceRow';
import type { ContextKind } from '../generated/ContextKind';
import type { ResourceItemRow } from '../generated/ResourceItemRow';
import type { ResourceKind } from '../generated/ResourceKind';
import type { Sensitivity } from '../generated/Sensitivity';
import { knowledgeService } from '../constants';

/** The page's type vocabulary: the registry's closed resource kinds plus the
 *  context kinds a plain canonical entry carries. The `knowledge` context kind
 *  shows as a `note` (the page itself is called Knowledge). */
export type KnowledgeKind = ResourceKind | 'note' | 'skill' | 'persona';
export type KnowledgeGroupBy = 'namespace' | 'type' | 'sensitivity' | 'tag';

/** One decrypted canonical entry (the shell's `PreservedMemory` shape). */
export interface KnowledgeEntry {
  ns: string;
  key: string;
  title: string;
  bytes: number;
  version: string;
  updated: string;
  preview: string;
  body: string;
  kind?: ContextKind;
}

/** The shell's lazy per-namespace cache: undefined = never opened. */
export type EntriesByNs = Record<string, KnowledgeEntry[] | 'loading' | undefined>;

export interface KnowledgeItem {
  ns: string;
  key: string;
  name: string;
  kind: KnowledgeKind;
  /** `null` for a plain entry — only a curated item carries a tier. */
  sensitivity: Sensitivity | null;
  tags: string[];
  version: string;
  updated: string;
  bytes: number;
  preview: string;
  /** The registry row when the item is typed (addressable by the install wizard). */
  curated: ResourceItemRow | null;
  /** The decrypted entry once its namespace has been opened. */
  entry: KnowledgeEntry | null;
}

export interface ActorScopeLike {
  label: string;
  role: string;
  scope?: Record<string, { read?: boolean; write?: boolean }>;
}

export interface NamespaceReaders {
  /** Installed apps granted `knowledge:<ns>` — by a binding or by their sheet. */
  apps: string[];
  /** Other delegates whose on-chain scope bit reads the namespace. */
  delegates: string[];
}

export interface KnowledgeNamespace {
  ns: string;
  label: string;
  curated: number;
  /** Plain entries once opened; `null` = not opened yet. */
  notes: number | 'loading' | null;
  readers: NamespaceReaders;
}

export interface KnowledgeGroup {
  key: string;
  label: string;
  items: KnowledgeItem[];
}

export const KIND_ORDER: KnowledgeKind[] = ['profile', 'document', 'dataset', 'gallery', 'note', 'skill', 'persona'];

export const liveApps = (apps: AppInstanceRow[]): AppInstanceRow[] => apps.filter((a) => a.status !== 'uninstalled');

export const kindOfEntry = (kind?: ContextKind): KnowledgeKind =>
  kind === 'skill' ? 'skill' : kind === 'persona' ? 'persona' : kind === 'resource' ? 'document' : 'note';

const isoDay = (secs: number): string => (secs ? new Date(Number(secs) * 1000).toISOString().slice(0, 10) : '—');

function fromCurated(row: ResourceItemRow, entry: KnowledgeEntry | null): KnowledgeItem {
  return {
    ns: row.ns,
    key: row.object_key,
    name: row.name,
    kind: row.kind,
    sensitivity: row.sensitivity,
    tags: row.tags,
    version: `v${row.version}`,
    updated: isoDay(row.updated_at),
    bytes: row.bytes,
    preview: entry?.preview ?? '',
    curated: row,
    entry,
  };
}

function fromEntry(e: KnowledgeEntry): KnowledgeItem {
  return {
    ns: e.ns,
    key: e.key,
    name: e.title,
    kind: kindOfEntry(e.kind),
    sensitivity: null,
    tags: [],
    version: e.version,
    updated: e.updated,
    bytes: e.bytes,
    preview: e.preview,
    curated: null,
    entry: e,
  };
}

const loadedEntries = (entriesByNs: EntriesByNs, ns: string): KnowledgeEntry[] => {
  const v = entriesByNs[ns];
  return Array.isArray(v) ? v : [];
};

/** Every item the page knows: each registry row (always listed — the registry
 *  is cheap to read), plus each decrypted entry of an opened namespace that no
 *  registry row claims. A curated item's entry attaches once its namespace is
 *  open. */
export function buildKnowledgeItems(resources: ResourceItemRow[], entriesByNs: EntriesByNs): KnowledgeItem[] {
  const items: KnowledgeItem[] = resources.map((row) =>
    fromCurated(row, loadedEntries(entriesByNs, row.ns).find((e) => e.key === row.object_key) ?? null),
  );
  const claimed = new Set(resources.map((r) => `${r.ns}/${r.object_key}`));
  for (const ns of Object.keys(entriesByNs)) {
    for (const e of loadedEntries(entriesByNs, ns)) {
      if (!claimed.has(`${e.ns}/${e.key}`)) items.push(fromEntry(e));
    }
  }
  return items.sort((a, b) => a.ns.localeCompare(b.ns) || a.name.localeCompare(b.name));
}

/** Who reads a namespace: the grant unit IS the namespace, so an app bound to
 *  one item in it reads every item in it. Apps come from their minted sheet
 *  (`services`) or their bindings; delegates from the on-chain scope bit an
 *  app's own delegate is not listed twice. */
export function readersOfNamespace(ns: string, apps: AppInstanceRow[], actors: ActorScopeLike[]): NamespaceReaders {
  const service = knowledgeService(ns);
  const appLabels = liveApps(apps)
    .filter((a) => a.services.includes(service) || a.bindings.resources.some((rb) => rb.ns === ns))
    .map((a) => a.label);
  const delegates = actors
    .filter((a) => a.role === 'agent' && a.scope?.[ns]?.read === true && !appLabels.includes(a.label))
    .map((a) => a.label);
  return { apps: appLabels, delegates };
}

/** The namespace list: the taxonomy's categories in their order, then any
 *  namespace a curated item lives in that the taxonomy does not name. */
export function knowledgeNamespaces(
  categories: { ns: string; label: string }[],
  resources: ResourceItemRow[],
  entriesByNs: EntriesByNs,
  apps: AppInstanceRow[],
  actors: ActorScopeLike[],
): KnowledgeNamespace[] {
  const seen = new Set<string>();
  const out: KnowledgeNamespace[] = [];
  const push = (ns: string, label: string) => {
    if (seen.has(ns)) return;
    seen.add(ns);
    const v = entriesByNs[ns];
    const curatedKeys = new Set(resources.filter((r) => r.ns === ns).map((r) => r.object_key));
    const notes = v === 'loading' ? 'loading' : Array.isArray(v) ? v.filter((e) => !curatedKeys.has(e.key)).length : null;
    out.push({ ns, label, curated: curatedKeys.size, notes, readers: readersOfNamespace(ns, apps, actors) });
  };
  for (const c of categories) push(c.ns, c.label);
  for (const r of [...resources].sort((a, b) => a.ns.localeCompare(b.ns))) push(r.ns, r.ns);
  return out;
}

/** Who reads one item: the apps bound to it by id, and the apps that read its
 *  whole namespace anyway. */
export function itemReaders(item: Pick<KnowledgeItem, 'ns' | 'curated'>, apps: AppInstanceRow[]): { bound: string[]; namespace: string[] } {
  const id = item.curated?.id;
  const bound = id ? liveApps(apps).filter((a) => a.bindings.resources.some((rb) => rb.item_id === id)).map((a) => a.label) : [];
  const namespace = readersOfNamespace(item.ns, apps, []).apps.filter((l) => !bound.includes(l));
  return { bound, namespace };
}

/** The other apps an edit reaches — the "also read by" notice on the
 *  Applications page. Empty = the edit touches no other app. */
export function editReaches(item: Pick<KnowledgeItem, 'ns' | 'curated'>, apps: AppInstanceRow[], except?: string): string[] {
  const r = itemReaders(item, apps);
  return [...r.bound, ...r.namespace].filter((l) => l !== except);
}

export function filterKnowledge(items: KnowledgeItem[], query: string, typedOnly: boolean): KnowledgeItem[] {
  const q = query.trim().toLowerCase();
  return items.filter((it) => {
    if (typedOnly && !it.curated) return false;
    if (!q) return true;
    const hay = [it.name, it.key, it.ns, it.kind, it.preview, ...it.tags, it.curated?.name_zh ?? '', it.curated?.filename ?? '']
      .join(' ')
      .toLowerCase();
    return hay.includes(q);
  });
}

export function groupKnowledge(items: KnowledgeItem[], by: KnowledgeGroupBy, namespaces: KnowledgeNamespace[]): KnowledgeGroup[] {
  const groups = new Map<string, KnowledgeGroup>();
  const add = (key: string, label: string, it: KnowledgeItem) => {
    const g = groups.get(key) ?? { key, label, items: [] };
    g.items.push(it);
    groups.set(key, g);
  };
  if (by === 'namespace') {
    for (const n of namespaces) groups.set(n.ns, { key: n.ns, label: n.label === n.ns ? n.ns : `${n.label} · ${n.ns}`, items: [] });
    for (const it of items) add(it.ns, it.ns, it);
    return [...groups.values()];
  }
  if (by === 'type') {
    for (const it of items) add(it.kind, it.kind, it);
    return [...groups.values()].sort((a, b) => KIND_ORDER.indexOf(a.key as KnowledgeKind) - KIND_ORDER.indexOf(b.key as KnowledgeKind));
  }
  if (by === 'sensitivity') {
    const order = ['sensitive', 'safe', 'unrated'];
    for (const it of items) add(it.sensitivity ?? 'unrated', it.sensitivity ?? 'unrated', it);
    return [...groups.values()].sort((a, b) => order.indexOf(a.key) - order.indexOf(b.key));
  }
  for (const it of items) {
    if (it.tags.length === 0) add('', 'untagged', it);
    for (const t of it.tags) add(t, t, it);
  }
  return [...groups.values()].sort((a, b) => (a.key === '' ? 1 : b.key === '' ? -1 : a.key.localeCompare(b.key)));
}
