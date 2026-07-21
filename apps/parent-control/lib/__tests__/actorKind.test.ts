import { describe, expect, it } from 'vitest';

import {
  actorHoldsChannelGrant,
  actorIsChannelEndpoint,
  actorTypeIsUnknown,
  agentChatChannelId,
  channelGrantCommit,
  type Actor,
} from '../../app/_components/types';

/** Minimal actor — only the fields the type predicates read. */
const actor = (over: Partial<Actor>): Actor =>
  ({
    id: 'agent-x',
    omni: '0x' + 'a'.repeat(64),
    omniHex: '0x' + 'a'.repeat(64),
    label: 'agent 0xaaaaaaaa…',
    role: 'agent',
    derivation: '',
    device: 'restored from chain',
    devicePubkey: '',
    lastActive: 'restored from chain',
    status: 'ok',
    vendor: '',
    k11: false,
    ...over,
  }) as Actor;

describe('actor type comes from the BINDING, not the current scope', () => {
  // The regression: device-ness used to be inferred from "every grant is a
  // channel grant". Revoking a device's grants emptied its scope, so a real
  // paired device silently became a "delegate" and moved to the Delegates page,
  // while an unrelated agent holding only channel grants was shown as the device.
  it('keeps a device a device after its grants are revoked', () => {
    const stripped = actor({ kind: 'device', services: [] });
    expect(actorIsChannelEndpoint(stripped)).toBe(true);
    expect(actorTypeIsUnknown(stripped)).toBe(false);
  });

  it('does not promote a delegate that happens to hold only channel grants', () => {
    const delegate = actor({
      kind: 'delegate',
      services: ['channel-pub:opchat-test1', 'channel-sub:opchat-test1'],
    });
    expect(actorIsChannelEndpoint(delegate)).toBe(false);
  });

  it('NEVER infers a device from the shape of its grants', () => {
    // The deleted heuristic said "every grant is a channel grant ⇒ device".
    // Live counter-example (VE stack): the DELEGATE `test1` held exactly
    // channel-pub + channel-sub and nothing else, so it read as a device —
    // while the real device sat next to it, also "device". The chain (tier 2
    // vs 3) separates them; grant shape never can.
    const delegateWithOnlyChannels = actor({
      kind: 'delegate',
      services: ['channel-pub:opchat-test1', 'channel-sub:opchat-test1'],
    });
    expect(actorIsChannelEndpoint(delegateWithOnlyChannels)).toBe(false);

    // …and with no chain answer at all, shape still proves nothing.
    const noKind = actor({ services: ['channel-pub:opchat-test1'] });
    expect(actorIsChannelEndpoint(noKind)).toBe(false);
    expect(actorTypeIsUnknown(noKind)).toBe(true);
  });

  it('reports UNKNOWN — never a guess — when neither chain nor manifest knows', () => {
    // A pre-#427 registry row (tier 0) with no manifest entry. The UI must say
    // "unknown" rather than assert a type.
    const blank = actor({ services: [] });
    expect(actorTypeIsUnknown(blank)).toBe(true);
    expect(actorIsChannelEndpoint(blank)).toBe(false);
  });
});

describe("an agent's chat channel comes from its grant, not its label", () => {
  // The exact failure: the manifest was lost, so the label fell back to the
  // placeholder "agent 0x346391ed…". `opchat-${label}` then contained a space
  // and an ellipsis, and every poll/send returned 400 invalid channel_id.
  it('uses the granted channel even when the label cannot form an id', () => {
    const a = actor({
      label: 'agent 0x346391ed…',
      services: ['channel-pub:opchat-test1', 'channel-sub:opchat-test1'],
    });
    expect(agentChatChannelId(a)).toBe('opchat-test1');
  });

  it('never emits an id the daemon would reject', () => {
    const a = actor({ label: 'agent 0x346391ed…', services: [] });
    // No grant and an unusable label ⇒ null, so the UI explains instead of
    // firing a request that can only 400.
    expect(agentChatChannelId(a)).toBeNull();
  });

  it('falls back to the label only when it is actually a valid id', () => {
    expect(agentChatChannelId(actor({ label: 'test1', services: [] }))).toBe('opchat-test1');
    // Uppercase / spaces / unicode are all rejected by the daemon's rule.
    expect(agentChatChannelId(actor({ label: 'Test One', services: [] }))).toBeNull();
  });

  it('prefers the publish grant (chat writes) over the subscribe grant', () => {
    const a = actor({ label: 'x', services: ['channel-sub:feed-b', 'channel-pub:feed-a'] });
    expect(agentChatChannelId(a)).toBe('feed-a');
  });
});

describe('the chat tab warns when the DELEGATE cannot hear a channel', () => {
  // The authority (master session) can always pub/sub on a master-owned
  // channel — ownership without participation (§22e). What the warning tracks
  // is whether the DELEGATE holds a grant there, i.e. whether a reply is even
  // possible. This is the exact live case: the DEVICE held opchat-test1 but
  // the delegate held nothing, so chat looked "sent" with no reply forthcoming.
  it('detects a grant in either direction, exact-match only', () => {
    const a = actor({ services: ['channel-sub:opchat-test1', 'memory:test1'] });
    expect(actorHoldsChannelGrant(a, 'opchat-test1')).toBe(true);
    expect(actorHoldsChannelGrant(a, 'opchat-test')).toBe(false);
    expect(actorHoldsChannelGrant(a, 'opchat-test12')).toBe(false);
  });

  it('reports no-grant for an empty scope (the debug-override case)', () => {
    expect(actorHoldsChannelGrant(actor({ services: [] }), 'opchat-test1')).toBe(false);
    expect(actorHoldsChannelGrant(actor({}), 'opchat-test1')).toBe(false);
  });
});

describe('a channel-grant commit restates the whole set without collateral damage', () => {
  // setScope is set-replace, so these inputs ARE the actor's resulting on-chain
  // grants. Getting them wrong silently revokes real access, which is why the
  // math is a pure function with its own tests rather than inline in the panel.
  const CHAN_HASH = '0x88e9bf9e'; // keccak("channel-pub:opchat-test1"), abbreviated
  const CRED_HASH = '0xe7b71835'; // some cred:<service> from the accept

  it('drops the channel hashes from preserve so a REMOVAL is not undone', () => {
    // The exact trap: scopeUnknownServiceIds deliberately still lists the
    // channel hash (so a MEMORY commit can't wipe it). Echoing it here would
    // re-add the grant the operator just removed.
    const a = actor({
      services: ['channel-pub:opchat-test1'],
      scopeUnknownServiceIds: [CHAN_HASH, CRED_HASH],
      scopeChannelServiceIds: [CHAN_HASH],
    });
    const { services, preserve } = channelGrantCommit(a, []);
    expect(services).toEqual([]);
    expect(preserve).toEqual([CRED_HASH]); // cred survives, channel does not
  });

  it('keeps memory + inbox grants, which live in scope and not in services', () => {
    const a = actor({
      services: ['channel-pub:opchat-test1'],
      scope: {
        family: { read: true, write: true },
        work: { read: true, write: false },
        personal: { read: false, write: false },
      } as Actor['scope'],
      scopeUnknownServiceIds: [CHAN_HASH],
      scopeChannelServiceIds: [CHAN_HASH],
    });
    const { services } = channelGrantCommit(a, ['channel-sub:opchat-test1']);
    expect(services).toContain('memory:family');
    expect(services).toContain('inbox:family');
    expect(services).toContain('memory:work');
    expect(services).not.toContain('inbox:work'); // write=false
    expect(services).not.toContain('memory:personal');
    expect(services).toContain('channel-sub:opchat-test1');
    expect(services).not.toContain('channel-pub:opchat-test1'); // replaced
  });

  it('is hash-case-insensitive and de-duplicates names', () => {
    const a = actor({
      services: ['channel-pub:opchat-test1', 'cred:openai'],
      scopeUnknownServiceIds: ['0X88E9BF9E', CRED_HASH],
      scopeChannelServiceIds: [CHAN_HASH],
    });
    const { services, preserve } = channelGrantCommit(a, [
      'channel-pub:opchat-test1',
      'channel-pub:opchat-test1',
    ]);
    expect(preserve).toEqual([CRED_HASH]);
    expect(services.filter((s) => s === 'channel-pub:opchat-test1')).toHaveLength(1);
    expect(services).toContain('cred:openai'); // known non-channel name kept
  });

  it('adds a first grant to an actor that has none', () => {
    const a = actor({ services: [] });
    const { services, preserve } = channelGrantCommit(a, [
      'channel-pub:opchat-test1',
      'channel-sub:opchat-test1',
    ]);
    expect(services).toEqual(['channel-pub:opchat-test1', 'channel-sub:opchat-test1']);
    expect(preserve).toEqual([]);
  });
});
