import { describe, expect, it } from 'vitest';
import type { ChannelDef } from '../client/types';
import { FEED_ID_RE, partitionResourceOptions, partitionSlotOptions, suggestedFeedId } from '../client/slotOptions';

const ch = (id: string, kind?: ChannelDef["kind"], name = id): ChannelDef => ({ id, name, kind, createdAt: 0 });

describe('install wizard slot options', () => {
  const channels: ChannelDef[] = [
    ch('opchat-test9', 'chat', 'Chat · test9'),
    ch('weixin', 'messaging', 'WeChat'),
    ch('probe', undefined, 'Probe'),
    ch('telegram', 'messaging', 'Telegram'),
    ch('kitchen-display', 'display', 'Kitchen display'),
  ];

  it('exact-kind matches come first, sorted by name; everything else folds', () => {
    const { matching, others } = partitionSlotOptions(channels, 'messaging');
    expect(matching.map((c) => c.id)).toEqual(['telegram', 'weixin']);
    expect(others.map((c) => c.id)).toEqual(['opchat-test9', 'kitchen-display', 'probe']);
    // an unkinded channel never counts as a match — it used to be offered for EVERY slot
    expect(partitionSlotOptions(channels, 'display').matching.map((c) => c.id)).toEqual(['kitchen-display']);
  });

  it('the filter narrows both lists by id, name or kind', () => {
    expect(partitionSlotOptions(channels, 'display', 'kit').matching.map((c) => c.id)).toEqual(['kitchen-display']);
    expect(partitionSlotOptions(channels, 'display', 'kit').others).toEqual([]);
    expect(partitionSlotOptions(channels, 'messaging', 'CHAT').others.map((c) => c.id)).toEqual(['opchat-test9']);
    expect(partitionSlotOptions(channels, 'messaging', 'nothing-here')).toEqual({ matching: [], others: [] });
  });

  it('suggested feed ids are kebab-case and valid', () => {
    expect(suggestedFeedId('kitchen_screen')).toBe('kitchen-screen');
    expect(suggestedFeedId('  Family Chat!! ')).toBe('family-chat');
    for (const s of ['kitchen_screen', 'family_chat', 'x'.repeat(50)]) expect(FEED_ID_RE.test(suggestedFeedId(s))).toBe(true);
    expect(FEED_ID_RE.test('Kitchen')).toBe(false);
  });
});

describe('install wizard item options (D-K2: the type is metadata)', () => {
  const items = [
    { id: 'gene-report', name: 'Gene report', kind: 'document' },
    { id: 'wifi-note', name: 'Wifi', kind: 'note' },
    { id: 'allergies', name: 'Allergies', kind: 'profile' },
    { id: 'food-prefs', name: 'Food preferences', kind: 'profile' },
  ];

  it('lists the slot kind first and folds every other item behind a retype', () => {
    const { matching, others } = partitionResourceOptions(items, 'profile');
    expect(matching.map((i) => i.id)).toEqual(['allergies', 'food-prefs']);
    expect(others.map((i) => i.id)).toEqual(['gene-report', 'wifi-note']);
  });

  it('offers a plain note to any slot', () => {
    const { matching, others } = partitionResourceOptions(items, 'dataset');
    expect(matching).toEqual([]);
    expect(others).toHaveLength(4);
  });
});
