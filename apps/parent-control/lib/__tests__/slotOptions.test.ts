import { describe, expect, it } from 'vitest';
import type { ChannelDef } from '../client/types';
import { FEED_ID_RE, bindingDescriptionDefault, gateRelayNote, partitionResourceOptions, partitionSlotOptions, suggestedFeedId } from '../client/slotOptions';

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

describe('the relay note under a messaging slot (2026-09-22: the bound channel IS the feed)', () => {
  it('says the gate relays the picked channel, and whether it still has to enroll', () => {
    expect(gateRelayNote({ configured: true, enrolled: true, transport: 'weixin' }, 'chef')).toBe(
      'the 微信 · WeChat contact gate relays whichever channel you pick here for `chef`, both ways.',
    );
    expect(gateRelayNote({ configured: true, enrolled: false, transport: 'telegram' }, '')).toContain('enrolls with this install');
  });
  it('says plainly when no gate exists', () => {
    expect(gateRelayNote(null, 'chef')).toContain('no contact gate is configured');
    expect(gateRelayNote({ configured: false, enrolled: false, transport: 'weixin' }, 'chef')).toContain('still works as a feed');
  });
});

describe('binding description default (the daemon\'s seed rule, mirrored)', () => {
  // The vectors are agentkeys-protocol's `a_binding_description_is_seeded_from_the_slot_reason_and_the_route_examples`.
  const ex = ['今晚吃什么', ' ', '冰箱里还有什么菜'];
  it('slot reason (中文 first, trailing 。 dropped) + the route examples', () => {
    expect(bindingDescriptionDefault({ reason_zh: '饭菜的照片从这里发来。', reason: 'Meal photos' }, { description: '', description_zh: '', route_examples: ex }))
      .toBe('饭菜的照片从这里发来 例如：「今晚吃什么」、「冰箱里还有什么菜」');
  });
  it('falls back to the template description; examples alone stand on their own', () => {
    expect(bindingDescriptionDefault({ reason_zh: '', reason: '' }, { description: 'Tracks meals', description_zh: '跟踪全家的饮食。', route_examples: [] })).toBe('跟踪全家的饮食');
    expect(bindingDescriptionDefault({ reason_zh: '', reason: '' }, { description: '', description_zh: '', route_examples: ex })).toBe('例如：「今晚吃什么」、「冰箱里还有什么菜」');
    expect(bindingDescriptionDefault({ reason_zh: '', reason: '' }, { description: '', route_examples: [] })).toBe('');
  });
});

describe('messaging slots list the household channels first (#734)', () => {
  const rows: ChannelDef[] = [
    { id: 'weixin', name: '微信 · WeChat', kind: 'messaging', createdAt: 5, endpointActorOmni: '0xabc' },
    { id: 'family-chat', name: 'family-chat', createdAt: 6 },
    { id: 'opchat-chef', name: 'Chat · chef', createdAt: 3 },
    { id: 'stories', name: 'stories', createdAt: 7 },
    { id: 'legacy-feed', name: 'legacy-feed', kind: 'messaging', createdAt: 1 },
    { id: 'kitchen-screen', name: 'kitchen-screen', kind: 'display', createdAt: 2 },
  ];
  const docs = [
    { id: 'stories', name: '故事', purpose: '睡前故事', household_default: false, operator_of: undefined, members: [{}] },
    { id: 'family-chat', name: '家庭群', purpose: '', household_default: true, operator_of: undefined, members: [{}, {}] },
    { id: 'opchat-chef', name: 'chef·操作', purpose: '对 chef 的指令', household_default: false, operator_of: 'chef', members: [{}] },
  ];
  it('documented channels come first — the household default, the family channels, then operator channels, then plain messaging rows', () => {
    const { matching, others } = partitionSlotOptions(rows, 'messaging', '', docs);
    expect(matching.map((c) => c.id)).toEqual(['family-chat', 'stories', 'opchat-chef', 'legacy-feed']);
    // a display row is another kind; the gate's transport row is not a channel at all — never offered
    expect(others.map((c) => c.id)).toEqual(['kitchen-screen']);
  });
  it('the filter also matches a document\'s name and purpose', () => {
    expect(partitionSlotOptions(rows, 'messaging', '故事', docs).matching.map((c) => c.id)).toEqual(['stories']);
    expect(partitionSlotOptions(rows, 'messaging', '家庭', docs).matching.map((c) => c.id)).toEqual(['family-chat']);
  });
  it('without documents (no gate) the kind match stands; the transport row is still not a channel', () => {
    const { matching, others } = partitionSlotOptions(rows, 'messaging');
    expect(matching.map((c) => c.id)).toEqual(['legacy-feed']);
    expect(others.map((c) => c.id)).not.toContain('weixin');
    expect(matching.map((c) => c.id)).not.toContain('weixin');
  });
  it('other kinds keep the plain kind partition; the transport row is not offered to them either', () => {
    const { matching, others } = partitionSlotOptions(rows, 'display', '', docs);
    expect(matching.map((c) => c.id)).toEqual(['kitchen-screen']);
    expect(others.map((c) => c.id)).not.toContain('weixin');
    expect(others.map((c) => c.id)).toContain('family-chat');
  });
});
