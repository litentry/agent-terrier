// The header search (#695 §9 "a top bar (household, search, owner)"): one
// box that finds a page, a repository (knowledge namespace), an actor, a
// channel or a credential by name and jumps there. Pure ranking here, so the
// order is unit-tested without React: an exact label first, then a label
// prefix, a word prefix, a substring, and only then the hidden keywords.

export type SearchKind = 'page' | 'repository' | 'actor' | 'channel' | 'credential';

export interface SearchEntry {
  kind: SearchKind;
  /** Unique within its kind — what the shell navigates with. */
  id: string;
  label: string;
  /** Secondary text, dimmed (a namespace code, a role, a note). */
  hint?: string;
  /** Extra words the query may match without being shown. */
  keywords?: string[];
}

const KIND_ORDER: SearchKind[] = ['page', 'repository', 'actor', 'channel', 'credential'];
const SPLIT = /[\s·/:_.,()-]+/;

/** 0 = no match; higher = better. */
export function scoreEntry(e: SearchEntry, q: string): number {
  const label = e.label.toLowerCase();
  if (label === q) return 100;
  if (label.startsWith(q)) return 80;
  if (label.split(SPLIT).some((w) => w.startsWith(q))) return 60;
  if (label.includes(q)) return 40;
  const hidden = [e.id, e.hint ?? '', ...(e.keywords ?? [])].join(' ').toLowerCase();
  if (hidden.split(SPLIT).some((w) => w.startsWith(q))) return 30;
  if (hidden.includes(q)) return 20;
  return 0;
}

/** The best `limit` entries for a query: by score, then by kind (pages before
 *  repositories before actors …), then alphabetically. An empty query = nothing. */
export function searchEntries(entries: SearchEntry[], query: string, limit = 12): SearchEntry[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return entries
    .map((e) => ({ e, s: scoreEntry(e, q) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || KIND_ORDER.indexOf(a.e.kind) - KIND_ORDER.indexOf(b.e.kind) || a.e.label.localeCompare(b.e.label))
    .slice(0, limit)
    .map((x) => x.e);
}

/** The console's sections, searchable by name and by the words people use. */
export const PAGE_ENTRIES: SearchEntry[] = [
  { kind: 'page', id: 'actors', label: 'actors', hint: 'the actor tree', keywords: ['tree', 'master'] },
  { kind: 'page', id: 'knowledge', label: 'knowledge', hint: 'repositories', keywords: ['memory', 'resources', 'notes', 'history'] },
  { kind: 'page', id: 'credentials', label: 'credentials', hint: 'the vault', keywords: ['vault', 'secrets'] },
  { kind: 'page', id: 'delegates', label: 'delegates', hint: 'pairing · sandboxes', keywords: ['agents', 'pairing', 'sandbox'] },
  { kind: 'page', id: 'devices', label: 'devices', hint: 'channel endpoints', keywords: ['camera', 'display', 'esp32'] },
  { kind: 'page', id: 'channels', label: 'channels', hint: 'the registry', keywords: ['feeds'] },
  { kind: 'page', id: 'contacts', label: 'contacts', hint: 'WeChat · family', keywords: ['wechat', 'weixin', 'family', 'bot', 'gate'] },
  { kind: 'page', id: 'applications', label: 'applications', hint: 'installed apps · catalog', keywords: ['apps', 'install', 'chef'] },
  { kind: 'page', id: 'audit', label: 'audit feed', hint: 'tier-1 stream', keywords: ['events', 'log', 'decode'] },
  { kind: 'page', id: 'chain', label: 'chain', hint: 'contracts · anchors', keywords: ['heima', 'rpc', 'contracts'] },
];
