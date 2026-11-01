import type { AppSlot } from '../generated/AppSlot';
import type { ChannelDoc } from '../generated/ChannelDoc';
import type { PresetSummary } from '../generated/PresetSummary';
import type { ChannelDef } from './types';

// The install wizard's slot chooser (#660 / #674): a slot asks for ONE channel
// of its kind, so the channels of exactly that kind come first, sorted by name;
// everything else (unkinded rows, delegate chats, other kinds) folds behind a
// "show N other channels" button, and a query filters both lists by id / name
// / kind. Pure, so the ranking is unit-tested without React.

export interface SlotOptions {
  matching: ChannelDef[];
  others: ChannelDef[];
}

/** The household's channel documents, as the chooser needs them: id, the name
 *  members see, whether it is the household default, and who is on it. */
export type HouseholdChannel = Pick<ChannelDoc, 'id' | 'name' | 'purpose' | 'household_default' | 'operator_of'> & { members: unknown[] };

/** A MESSAGING slot binds a household channel — one the contact gate holds a
 *  document for (its purpose, its members, the apps on it). The registry rows
 *  the install / rebind paths auto-registered before #734 carried no kind, so
 *  a household channel used to fold under "other channels" while the gate's
 *  transport row (`weixin`: the #667 endpoint row named after the transport)
 *  stood alone as the only option. Now: documented household channels first
 *  (the default first, then by name), then the plain `messaging`-kinded rows.
 *  A transport is not a channel (owner rule 2026-09-26: the gate relays the
 *  household's channels and owns none), so a row carrying the gate's device
 *  actor is not offered at all — the daemon retires such rows. Other kinds keep
 *  the plain kind match. */
export function partitionSlotOptions(channels: ChannelDef[], kind: string, query = '', docs: HouseholdChannel[] = []): SlotOptions {
  const q = query.trim().toLowerCase();
  const docOf = (c: ChannelDef) => docs.find((d) => d.id === c.id);
  const hit = (c: ChannelDef) => {
    if (!q) return true;
    const doc = docOf(c);
    return (
      c.id.toLowerCase().includes(q) ||
      c.name.toLowerCase().includes(q) ||
      (c.kind ?? '').includes(q) ||
      (doc?.name ?? '').toLowerCase().includes(q) ||
      (doc?.purpose ?? '').toLowerCase().includes(q)
    );
  };
  const byName = (a: ChannelDef, b: ChannelDef) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
  const isEndpoint = (c: ChannelDef) => !!c.endpointActorOmni;
  // The transport row's signature (the #667 endpoint row: messaging kind, the
  // gate's device actor on it) — not a channel for ANY slot kind.
  const isTransportRow = (c: ChannelDef) => c.kind === 'messaging' && isEndpoint(c);
  if (kind !== 'messaging') {
    return {
      matching: channels.filter((c) => c.kind === kind && hit(c)).sort(byName),
      others: channels.filter((c) => c.kind !== kind && !isTransportRow(c) && hit(c)).sort(byName),
    };
  }
  const household = (c: ChannelDef) => !isEndpoint(c) && (!!docOf(c) || c.kind === 'messaging');
  const rank = (c: ChannelDef) => {
    const doc = docOf(c);
    if (doc?.household_default) return 0;
    if (doc && !doc.operator_of) return 1;
    if (doc) return 2;
    return 3;
  };
  const byHousehold = (a: ChannelDef, b: ChannelDef) => rank(a) - rank(b) || byName(a, b);
  return {
    matching: channels.filter((c) => household(c) && hit(c)).sort(byHousehold),
    others: channels.filter((c) => !household(c) && !isEndpoint(c) && hit(c)).sort(byName),
  };
}

/** The install wizard's item picker for a resource slot (D-K2): items of the
 *  slot's kind first, then every other item — a pick there retypes the item on
 *  bind, since the type is metadata. Both halves sorted by name. */
export function partitionResourceOptions<T extends { id: string; name: string; kind: string }>(items: T[], kind: string): { matching: T[]; others: T[] } {
  const byName = (a: T, b: T) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
  return {
    matching: items.filter((i) => i.kind === kind).sort(byName),
    others: items.filter((i) => i.kind !== kind).sort(byName),
  };
}

/** A channel / feed id: lowercase, digits, dashes; 1–32 chars. */
export const FEED_ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** The id the wizard suggests for a fresh feed of a slot: the slot name, kebab-cased. */
export function suggestedFeedId(slot: string): string {
  return slot
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
}

/** What the contact gate does with the channel a messaging slot binds (owner
 *  decision 2026-09-22: the bound channel IS the feed — the gate learns
 *  `<app> → <channel>` at install / rebind and relays it both ways). */
export function gateRelayNote(
  gateway: { configured: boolean; enrolled: boolean; transport: string } | null | undefined,
  label: string,
): string {
  const app = label.trim() || '<app>';
  if (!gateway?.configured) {
    return `no contact gate is configured — the family cannot reach \`${app}\` on this channel until one is set up; the channel still works as a feed.`;
  }
  const name = gateway.transport === 'weixin' ? '微信 · WeChat' : gateway.transport === 'telegram' ? 'Telegram' : gateway.transport;
  return `the ${name} contact gate relays whichever channel you pick here for \`${app}\`, both ways${gateway.enrolled ? '' : ' (the gate enrolls with this install — same Touch ID)'}.`;
}

/** The description a messaging binding gets when the owner wrote none: the
 *  daemon's `seed_binding_description` rule (agentkeys-protocol), mirrored so
 *  the bindings panel can show what the next commit writes onto the channel
 *  document — the slot's reason (中文 first), else the template's description,
 *  with the template's route examples appended. An app installed before the
 *  rule existed carries no description until its next commit. */
export function bindingDescriptionDefault(
  slot: Pick<AppSlot, 'reason' | 'reason_zh'>,
  template: Pick<PresetSummary, 'description' | 'route_examples'> & { description_zh?: string | null },
): string {
  const base = [slot.reason_zh, slot.reason, template.description_zh ?? '', template.description]
    .map((t) => (t ?? '').trim())
    .find((t) => t.length > 0) ?? '';
  const lead = base.replace(/。+$/u, '');
  const examples = template.route_examples.map((e) => e.trim()).filter((e) => e.length > 0).map((e) => `「${e}」`);
  if (examples.length === 0) return lead;
  const tail = `例如：${examples.join('、')}`;
  return lead ? `${lead} ${tail}` : tail;
}
