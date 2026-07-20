import { describe, expect, it } from 'vitest';

import {
  actorIsChannelEndpoint,
  actorTypeIsUnknown,
  agentChatChannelId,
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

  it('still reads a device from scope shape when the binding is unknown', () => {
    // Pre-manifest / chain-rebuilt actors have no `kind`; a non-empty
    // channel-only scope is real evidence, so the fallback stays.
    const inferred = actor({ services: ['channel-pub:opchat-test1'] });
    expect(actorIsChannelEndpoint(inferred)).toBe(true);
    expect(actorTypeIsUnknown(inferred)).toBe(false);
  });

  it('a mixed scope is a delegate, not a device', () => {
    const mixed = actor({ services: ['channel-pub:opchat-test1', 'memory:test1'] });
    expect(actorIsChannelEndpoint(mixed)).toBe(false);
  });

  it('reports UNKNOWN — never delegate — with no binding and no scope', () => {
    // This is the exact state of a device rebuilt from chain whose grants were
    // lost: we have no evidence either way, so the UI must say so instead of
    // asserting a type.
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
