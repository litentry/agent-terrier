import { describe, expect, it } from 'vitest';
import type { ContactSummary } from '../generated/ContactSummary';
import type { GatewayPendingBindView } from '../generated/GatewayPendingBindView';
import type { ChannelDoc } from '../generated/ChannelDoc';
import { SELF_CONTACT_ID, defaultTab, describeGrants, inviteState, nextStepHint, scanTransport, selfState, sendText, suggestedGrants } from '../client/contactFlow';

const pend = (contact_id: string, tier: GatewayPendingBindView['tier'], claimed: boolean): GatewayPendingBindView => ({
  bind_code: '123456', contact_id, display_name: contact_id, tier, channels: [], claimed,
});
const bound = (contact_id: string, tier: ContactSummary['tier']): ContactSummary => ({ contact_id, display_name: contact_id, tier, channels: [], connected: false, welcomed: true });

describe('contacts flow', () => {
  const doc = (id: string, extra: Partial<ChannelDoc>): ChannelDoc => ({ id, name: id, purpose: '', household_default: false, members: [], apps: [], updated_at: 0, ...extra });
  const docs: ChannelDoc[] = [
    doc('opchat-chef', { operator_of: 'chef', apps: [{ alias: 'chef', slot: 'opchat', description: '', takes: [], audience: ['owner'] }] }),
    doc('stories', { apps: [{ alias: 'storyteller', slot: 'story_chat', description: '', takes: [], audience: ['owner', 'kid'] }] }),
    doc('family-chat', { name: '家庭群', household_default: true, apps: [{ alias: 'chef', slot: 'family_chat', description: '', takes: [], audience: ['owner', 'partner', 'elder', 'helper'] }] }),
  ];

  it('suggested rows: owner speaks everywhere; a tier speaks where an app admits it and reads the default otherwise; guest nothing; operator channels never proposed', () => {
    expect(suggestedGrants('owner', docs).map((g) => g.channel_id)).toEqual(['family-chat', 'stories', 'opchat-chef']);
    expect(suggestedGrants('partner', docs)).toEqual([{ channel_id: 'family-chat', speak: true, read: true }]);
    expect(suggestedGrants('kid', docs)).toEqual([
      { channel_id: 'family-chat', speak: false, read: true },
      { channel_id: 'stories', speak: true, read: true },
    ]);
    expect(suggestedGrants('elder', docs)).toEqual([{ channel_id: 'family-chat', speak: true, read: true }]);
    expect(suggestedGrants('guest', docs)).toEqual([]);
    expect(describeGrants(suggestedGrants('kid', docs), docs)).toBe('家庭群 (read only), stories');
    expect(describeGrants([], docs)).toBe('—');
  });

  it('the owner bind walks none → minted → claimed → bound, and the page follows it', () => {
    expect(selfState([], [])).toBe('none');
    expect(selfState([pend(SELF_CONTACT_ID, 'owner', false)], [])).toBe('minted');
    expect(selfState([pend(SELF_CONTACT_ID, 'owner', true)], [])).toBe('claimed');
    expect(selfState([], [bound('me', 'owner')])).toBe('bound');
    // a family invite does not count as the owner's own
    expect(selfState([pend('grandma-1', 'elder', true)], [])).toBe('none');
  });

  it('the default tab follows the flow; the next-step hint names the tab it lives on', () => {
    expect(defaultTab(false, 'bound', 0)).toBe('connection');
    expect(defaultTab(true, 'minted', 2)).toBe('connection');
    expect(defaultTab(true, 'bound', 2)).toBe('invitations');
    expect(defaultTab(true, 'bound', 0)).toBe('contacts');
    expect(nextStepHint(false, 'none', true, 0, 0, false)?.tab).toBe('connection');
    expect(nextStepHint(true, 'minted', true, 0, 0, false)?.tab).toBe('connection');
    // bound, but the owner's own WeChat has no clawbot yet (the legacy spare bot serves them)
    expect(nextStepHint(true, 'bound', true, 0, 0, false)?.text).toContain('your own WeChat');
    expect(nextStepHint(true, 'bound', true, 1, 0, true)?.tab).toBe('invitations');
    expect(nextStepHint(true, 'bound', true, 0, 0, true)?.text).toContain('first family member');
    expect(nextStepHint(true, 'bound', true, 0, 2, true)).toBeNull();
    // the code transports never ask for the owner's own clawbot
    expect(nextStepHint(true, 'bound', false, 0, 2, false)).toBeNull();
  });

  it('iLink binds by scan; 公众号/Telegram by code; unknown (gate unreachable) reads as the household default', () => {
    expect(scanTransport('ilink')).toBe(true);
    for (const t of ['oa', 'telegram']) expect(scanTransport(t)).toBe(false);
    for (const t of ['', null, undefined]) expect(scanTransport(t)).toBe(true);
  });

  it('invite rows and the send grammar', () => {
    expect(inviteState(pend('a', 'kid', false))).toBe('minted');
    expect(inviteState(pend('a', 'kid', true))).toBe('claimed');
    expect(sendText('482913')).toBe('绑定 482913');
  });
});
