import { describe, expect, it } from 'vitest';
import type { AppInstanceRow } from '../generated/AppInstanceRow';
import type { ResourceItemRow } from '../generated/ResourceItemRow';
import type { ResourceKind } from '../generated/ResourceKind';
import {
  buildKnowledgeItems,
  editReaches,
  filterKnowledge,
  groupKnowledge,
  itemReaders,
  kindOfEntry,
  knowledgeNamespaces,
  readersOfNamespace,
  type KnowledgeEntry,
} from '../client/knowledge';

const row = (id: string, ns: string, kind: ResourceKind, tags: string[] = [], sensitivity: 'safe' | 'sensitive' = 'safe'): ResourceItemRow => ({
  id, name: id.replace(/-/g, ' '), name_zh: '', ns, object_key: id, kind, tags, sensitivity, version: 2, content_hash: 'h', bytes: 120,
  created_at: 1_757_700_000, updated_at: 1_757_750_000, filename: '', content_type: '', raw_object_key: '', raw_bytes: 0,
});

const entry = (ns: string, key: string, kind?: KnowledgeEntry['kind']): KnowledgeEntry => ({
  ns, key, title: key, bytes: 40, version: 'v1', updated: '2026-09-13', preview: `${key} preview`, body: `${key} body`, kind,
});

const app = (label: string, services: string[], resources: { name: string; item_id: string; ns: string }[], status: AppInstanceRow['status'] = 'installed'): AppInstanceRow => ({
  label, template_id: 'chef', template_version: '1', template_schema: 1, actor_omni: '0xabc', device_key_hash: '0xdef', memory_ns: `app-${label}`,
  chat_channel_id: `opchat-${label}`, bindings: { slots: [], resources: resources.map((r) => ({ ...r, kind: 'profile' as const, sensitivity: 'safe' as const })), audience: [], tz_offset_minutes: 480 },
  bound_channels: [], services, availability: 'always-on', status, installed_at: 1_757_700_000, reach_aliases: [label],
});

const food = row('food-preferences', 'household', 'profile', ['food', 'allergies']);
const gene = row('gene-report', 'health', 'document', ['health'], 'sensitive');
const chef = app('chef', ['knowledge:household', 'knowledge:health'], [{ name: 'preferences', item_id: 'food-preferences', ns: 'household' }]);
const tutor = app('tutor', ['knowledge:household'], []);
const gone = app('old-chef', ['knowledge:household'], [{ name: 'preferences', item_id: 'food-preferences', ns: 'household' }], 'uninstalled');

describe('knowledge items', () => {
  it('lists every curated row, attaches its entry once the namespace is open, and adds the plain notes', () => {
    const items = buildKnowledgeItems([food, gene], { household: [entry('household', 'food-preferences'), entry('household', 'wifi-note')] });
    expect(items.map((i) => `${i.ns}/${i.key}`)).toEqual(['health/gene-report', 'household/food-preferences', 'household/wifi-note']);
    const curated = items.find((i) => i.key === 'food-preferences')!;
    expect(curated.entry?.preview).toBe('food-preferences preview');
    expect(curated.version).toBe('v2');
    expect(curated.sensitivity).toBe('safe');
    const note = items.find((i) => i.key === 'wifi-note')!;
    expect(note.kind).toBe('note');
    expect(note.curated).toBeNull();
    expect(note.sensitivity).toBeNull();
    expect(items.find((i) => i.key === 'gene-report')!.entry).toBeNull();
  });

  it('maps context kinds onto the page vocabulary', () => {
    expect(kindOfEntry(undefined)).toBe('note');
    expect(kindOfEntry('knowledge')).toBe('note');
    expect(kindOfEntry('skill')).toBe('skill');
    expect(kindOfEntry('persona')).toBe('persona');
    expect(kindOfEntry('resource')).toBe('document');
  });
});

describe('namespaces and readers', () => {
  it('unions the taxonomy with the namespaces curated items live in, counting notes only once opened', () => {
    const ns = knowledgeNamespaces([{ ns: 'personal', label: 'Personal' }], [food, gene], { household: [entry('household', 'food-preferences'), entry('household', 'wifi-note')], health: 'loading' }, [chef], []);
    expect(ns.map((n) => n.ns)).toEqual(['personal', 'health', 'household']);
    expect(ns[0]).toMatchObject({ label: 'Personal', curated: 0, notes: null });
    expect(ns[1]).toMatchObject({ label: 'health', curated: 1, notes: 'loading' });
    expect(ns[2]).toMatchObject({ label: 'household', curated: 1, notes: 1 });
  });

  it('reads the namespace audience from the apps sheets and the delegates scope bits, never listing an app twice', () => {
    const actors = [
      { label: 'chef', role: 'agent', scope: { household: { read: true } } },
      { label: 'agent-i', role: 'agent', scope: { household: { read: true, write: true } } },
      { label: 'watcher', role: 'agent', scope: { household: { write: true } } },
      { label: 'kitchen-tablet', role: 'device', scope: { household: { read: true } } },
    ];
    expect(readersOfNamespace('household', [chef, tutor, gone], actors)).toEqual({ apps: ['chef', 'tutor'], delegates: ['agent-i'] });
    expect(readersOfNamespace('health', [chef, tutor], actors)).toEqual({ apps: ['chef'], delegates: [] });
  });

  it('tells an item bound by id apart from an app that reads the whole namespace', () => {
    const items = buildKnowledgeItems([food], {});
    expect(itemReaders(items[0], [chef, tutor, gone])).toEqual({ bound: ['chef'], namespace: ['tutor'] });
    expect(itemReaders({ ns: 'household', curated: null }, [chef, tutor])).toEqual({ bound: [], namespace: ['chef', 'tutor'] });
  });

  it('names the other apps an edit reaches', () => {
    const items = buildKnowledgeItems([food], {});
    expect(editReaches(items[0], [chef, tutor], 'chef')).toEqual(['tutor']);
    expect(editReaches(items[0], [chef], 'chef')).toEqual([]);
  });
});

describe('grouping and filtering', () => {
  const items = buildKnowledgeItems([food, gene], { household: [entry('household', 'wifi-note'), entry('household', 'summarize', 'skill')] });
  const namespaces = knowledgeNamespaces([{ ns: 'personal', label: 'Personal' }], [food, gene], {}, [], []);

  it('keeps an empty namespace visible in the namespace view', () => {
    const g = groupKnowledge(items, 'namespace', namespaces);
    expect(g.map((x) => [x.key, x.items.length])).toEqual([['personal', 0], ['health', 1], ['household', 3]]);
    expect(g[0].label).toBe('Personal · personal');
  });

  it('orders types profile → document → note → skill', () => {
    expect(groupKnowledge(items, 'type', namespaces).map((x) => x.key)).toEqual(['profile', 'document', 'note', 'skill']);
  });

  it('puts sensitive first and unrated notes last', () => {
    expect(groupKnowledge(items, 'sensitivity', namespaces).map((x) => [x.key, x.items.length])).toEqual([['sensitive', 1], ['safe', 1], ['unrated', 2]]);
  });

  it('groups by tag with untagged last and a multi-tag item in each of its tags', () => {
    const g = groupKnowledge(items, 'tag', namespaces);
    expect(g.map((x) => x.label)).toEqual(['allergies', 'food', 'health', 'untagged']);
    expect(g[0].items[0].key).toBe('food-preferences');
    expect(g[1].items[0].key).toBe('food-preferences');
  });

  it('filters by text across name, tags and namespace, and hides notes when only bindable items are wanted', () => {
    expect(filterKnowledge(items, 'allerg', false).map((i) => i.key)).toEqual(['food-preferences']);
    expect(filterKnowledge(items, 'household', true).map((i) => i.key)).toEqual(['food-preferences']);
    expect(filterKnowledge(items, '', true)).toHaveLength(2);
    expect(filterKnowledge(items, '', false)).toHaveLength(4);
  });
});
