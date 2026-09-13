import { describe, expect, it } from 'vitest';
import type { ContactSummary } from '../generated/ContactSummary';
import type { GatewayPendingBindView } from '../generated/GatewayPendingBindView';
import { SELF_CONTACT_ID, appAudiences, defaultTab, inviteState, nextStepHint, scanTransport, selfState, sendText, suggestedReach } from '../client/contactFlow';

const pend = (contact_id: string, tier: GatewayPendingBindView['tier'], claimed: boolean): GatewayPendingBindView => ({
  bind_code: '123456', contact_id, display_name: contact_id, tier, reach: [], claimed,
});
const bound = (contact_id: string, tier: ContactSummary['tier']): ContactSummary => ({ contact_id, display_name: contact_id, tier, reach: [], connected: false, welcomed: true });

describe('contacts flow', () => {
  const apps = appAudiences([
    { label: 'Family chef', reach_aliases: ['chef'], bindings: { audience: [{ slot: 'family_chat', tiers: ['owner', 'partner', 'elder', 'helper'] }] }, bound_channels: [{ kind: 'messaging' }, { kind: 'display' }] },
    { label: 'storyteller', bindings: { audience: [{ slot: 'chat', tiers: ['owner', 'kid'] }] }, bound_channels: [{ kind: 'messaging' }] },
    { label: 'watchdog', bindings: { audience: [{ slot: 'x', tiers: ['owner'] }] }, bound_channels: [{ kind: 'camera' }] }, // no messaging endpoint
  ]);

  it('only apps with a messaging endpoint have an audience; the pre-fill vocabulary is the install\'s reach aliases', () => {
    expect(apps.map((a) => a.label)).toEqual(['Family chef', 'storyteller']);
    expect(apps.map((a) => a.aliases)).toEqual([['chef'], ['storyteller']]);
  });

  it('suggested reach: owner = every agent today; tiers = the apps that admit them; guest = nothing', () => {
    const agents = ['chef', 'storyteller', 'agent-i', 'chef'];
    expect(suggestedReach('owner', agents, apps)).toEqual(['chef', 'storyteller', 'agent-i']);
    expect(suggestedReach('partner', agents, apps)).toEqual(['chef']);
    expect(suggestedReach('kid', agents, apps)).toEqual(['storyteller']);
    expect(suggestedReach('elder', agents, apps)).toEqual(['chef']);
    expect(suggestedReach('guest', agents, apps)).toEqual([]);
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
