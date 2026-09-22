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

export function partitionSlotOptions(channels: ChannelDef[], kind: string, query = ''): SlotOptions {
  const q = query.trim().toLowerCase();
  const hit = (c: ChannelDef) =>
    !q || c.id.toLowerCase().includes(q) || c.name.toLowerCase().includes(q) || (c.kind ?? '').includes(q);
  const byName = (a: ChannelDef, b: ChannelDef) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
  return {
    matching: channels.filter((c) => c.kind === kind && hit(c)).sort(byName),
    others: channels.filter((c) => c.kind !== kind && hit(c)).sort(byName),
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
