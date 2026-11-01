import { describe, expect, it } from 'vitest';
import { PAGE_ENTRIES, scoreEntry, searchEntries, type SearchEntry } from '../client/search';

const entries: SearchEntry[] = [
  ...PAGE_ENTRIES,
  { kind: 'repository', id: 'household', label: 'Household', hint: 'knowledge:household', keywords: ['household'] },
  { kind: 'repository', id: 'health', label: 'Health', hint: 'knowledge:health', keywords: ['health'] },
  { kind: 'actor', id: 'a-chef', label: 'chef', hint: 'agent · m/44/1', keywords: ['0xabc'] },
  { kind: 'actor', id: 'a-cam', label: 'console-mac-lan', hint: 'agent · device', keywords: ['0xdef'] },
  { kind: 'channel', id: 'family-chat', label: 'Family chat', hint: 'family-chat', keywords: ['the household group'] },
  { kind: 'credential', id: 'openai', label: 'openai', hint: 'work · sensitive' },
];

describe('header search', () => {
  it('returns nothing for an empty query', () => {
    expect(searchEntries(entries, '')).toEqual([]);
    expect(searchEntries(entries, '   ')).toEqual([]);
  });

  it('ranks an exact label over a prefix over a word prefix over a substring over hidden words', () => {
    expect(scoreEntry({ kind: 'page', id: 'chain', label: 'chain' }, 'chain')).toBe(100);
    expect(scoreEntry({ kind: 'page', id: 'channels', label: 'channels' }, 'cha')).toBe(80);
    expect(scoreEntry({ kind: 'page', id: 'audit', label: 'audit feed' }, 'feed')).toBe(60);
    expect(scoreEntry({ kind: 'actor', id: 'x', label: 'console-mac-lan' }, 'e-mac')).toBe(40);
    expect(scoreEntry({ kind: 'page', id: 'knowledge', label: 'knowledge', keywords: ['memory'] }, 'mem')).toBe(30);
    expect(scoreEntry({ kind: 'channel', id: 'c', label: 'Family chat', keywords: ['the household group'] }, 'ehold')).toBe(20);
    expect(scoreEntry({ kind: 'page', id: 'chain', label: 'chain' }, 'zzz')).toBe(0);
  });

  it('finds a repository by its namespace code and an actor by its omni', () => {
    expect(searchEntries(entries, 'knowledge:hea').map((e) => e.id)).toEqual(['health']);
    expect(searchEntries(entries, '0xabc').map((e) => e.id)).toEqual(['a-chef']);
  });

  it('puts the page first when a word names both a page and a repository, and caps the list', () => {
    const hits = searchEntries(entries, 'h', 3);
    expect(hits).toHaveLength(3);
    // 'health'/'household' (prefix, 80) outrank pages matched only by hidden words
    expect(hits.map((e) => e.kind)).toEqual(['repository', 'repository', 'page']);
    // label prefixes (80), the word prefix (60), a hidden word prefix ('channel
    // endpoints' on devices, 30), a hidden substring ('wechat' on contacts, 20)
    const chan = searchEntries(entries, 'cha');
    expect(chan.map((e) => e.id)).toEqual(['chain', 'channels', 'family-chat', 'devices', 'contacts']);
  });

  it('is case-insensitive and tolerant of surrounding spaces, the label hit before a keyword hit', () => {
    // 'chef' is the actor's label (80) and a hidden keyword of the applications page (30)
    expect(searchEntries(entries, '  CHEF ').map((e) => e.id)).toEqual(['a-chef', 'applications']);
  });
});
