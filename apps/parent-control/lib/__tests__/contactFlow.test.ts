import { describe, expect, it } from 'vitest';
import type { ContactSummary } from '../generated/ContactSummary';
import type { GatewayPendingBindView } from '../generated/GatewayPendingBindView';
import { SELF_CONTACT_ID, appAudiences, flowStep, inviteState, scanTransport, selfState, sendText, suggestedReach } from '../client/contactFlow';

const pend = (contact_id: string, tier: GatewayPendingBindView['tier'], claimed: boolean): GatewayPendingBindView => ({
  bind_code: '123456', contact_id, display_name: contact_id, tier, reach: [], claimed,
});
const bound = (contact_id: string, tier: ContactSummary['tier']): ContactSummary => ({ contact_id, display_name: contact_id, tier, reach: [], connected: false });

describe('contacts flow', () => {
  const apps = appAudiences([
    { label: 'chef', bindings: { audience: [{ slot: 'family_chat', tiers: ['owner', 'partner', 'elder', 'helper'] }] }, bound_channels: [{ kind: 'messaging' }, { kind: 'display' }] },
    { label: 'storyteller', bindings: { audience: [{ slot: 'chat', tiers: ['owner', 'kid'] }] }, bound_channels: [{ kind: 'messaging' }] },
    { label: 'watchdog', bindings: { audience: [{ slot: 'x', tiers: ['owner'] }] }, bound_channels: [{ kind: 'camera' }] }, // no messaging endpoint
  ]);

  it('only apps with a messaging endpoint have an audience', () => {
    expect(apps.map((a) => a.label)).toEqual(['chef', 'storyteller']);
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
    expect(flowStep(false, 'bound')).toBe(1);
    expect(flowStep(true, 'minted')).toBe(2);
    expect(flowStep(true, 'bound')).toBe(3);
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
