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
