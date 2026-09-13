import type { ContactSummary } from '../generated/ContactSummary';
import type { ContactTier } from '../generated/ContactTier';
import type { GatewayPendingBindView } from '../generated/GatewayPendingBindView';

// The Contacts page's flow, as pure functions (unit-tested without React):
// one bot per household connected ONCE; every member — the owner first —
// binds by texting an invite code to that bot; the owner approves each bind.

/** The owner's own invite uses a FIXED contact id so re-minting replaces it. */
export const SELF_CONTACT_ID = 'self-owner';
export const SELF_DISPLAY_NAME = '我自己';

export const TIER_ORDER: ContactTier[] = ['owner', 'partner', 'elder', 'kid', 'helper', 'guest'];

/** What each tier means, in the words a parent would use. */
export const TIER_INFO: Record<ContactTier, { zh: string; blurb: string }> = {
  owner: { zh: '拥有者', blurb: 'You. Every agent, money/usage ones included; every app you install later adds itself.' },
  partner: { zh: '配偶', blurb: 'Your spouse. The family agents; apps that admit partners add themselves.' },
  elder: { zh: '长辈', blurb: 'Grandparents. The family agents you pick; never money/usage ones.' },
  kid: { zh: '孩子', blurb: 'Children. Only the agents you pick; never money/usage ones.' },
  helper: { zh: '帮手', blurb: 'Nanny, cleaner. Household-task agents you pick.' },
  guest: { zh: '访客', blurb: 'Visitors. Nothing until you grant a specific agent.' },
};

/** An installed app's messaging audience: the tiers its manifest admits. */
export interface InstalledAppAudience {
  label: string;
  /** The `/alias`es the install wrote into contacts' reach — what a fresh invite
   *  is pre-filled with (the gate routes on these, never on a display label). */
  aliases: string[];
  tiers: ContactTier[];
}

type AppRowLike = {
  label: string;
  reach_aliases?: string[];
  bindings: { audience: Array<{ slot: string; tiers: ContactTier[] }> };
  bound_channels: Array<{ kind: string }>;
};

/** Installed apps that have a messaging endpoint, with the union of their admitted tiers. */
export function appAudiences(rows: AppRowLike[]): InstalledAppAudience[] {
  return rows
    .filter((r) => r.bound_channels.some((b) => b.kind === 'messaging'))
    .map((r) => ({
      label: r.label,
      aliases: r.reach_aliases?.length ? r.reach_aliases : [r.label],
      tiers: Array.from(new Set(r.bindings.audience.flatMap((a) => a.tiers))),
    }));
}

/** The reach a fresh invite starts with: the owner reaches every agent that
 *  exists today; a guest nothing; every other tier the installed apps whose
 *  audience admits it. Apps installed LATER add themselves to every contact of
 *  an admitted tier (the daemon's install write-through), so a list only ever
 *  needs today's agents. */
export function suggestedReach(tier: ContactTier, agents: string[], apps: InstalledAppAudience[]): string[] {
  if (tier === 'owner') return Array.from(new Set(agents));
  if (tier === 'guest') return [];
  return Array.from(new Set(apps.filter((a) => a.tiers.includes(tier)).flatMap((a) => a.aliases)));
}

/** iLink bots are per member and bound by SCAN (one clawbot per WeChat account);
 *  the other transports bind by the texted code. */
/** Does this transport bind by scan (one clawbot per WeChat account)? iLink does; 公众号 (`oa`)
 *  and Telegram bind by the 6-digit code. An UNKNOWN transport (no status — the gate is
 *  unreachable) reads as the household default, iLink — never as the code ceremony. */
export const scanTransport = (transport: string | null | undefined): boolean => !transport || transport === 'ilink';

export type InviteState = 'minted' | 'claimed';
export const inviteState = (p: GatewayPendingBindView): InviteState => (p.claimed ? 'claimed' : 'minted');

/** What the family member must text to the bot (the gate's `绑定 <code>` grammar). */
export const sendText = (code: string): string => `绑定 ${code}`;

export type SelfState = 'none' | 'minted' | 'claimed' | 'bound';

/** Where the owner's own bind stands. Bound = an owner-tier contact exists. */
export function selfState(pending: GatewayPendingBindView[], contacts: ContactSummary[]): SelfState {
  if (contacts.some((c) => c.tier === 'owner')) return 'bound';
  const mine = pending.find((p) => p.contact_id === SELF_CONTACT_ID) ?? pending.find((p) => p.tier === 'owner');
  if (!mine) return 'none';
  return mine.claimed ? 'claimed' : 'minted';
}

export type ContactsTab = 'connection' | 'invitations' | 'contacts';

/** The tab the page opens on: the gate and the owner's own bot come first,
 *  then open invites, then the bound household. A tab the user picked wins. */
export function defaultTab(online: boolean, self: SelfState, openInvites: number): ContactsTab {
  if (!online || self !== 'bound') return 'connection';
  if (openInvites > 0) return 'invitations';
  return 'contacts';
}

/** The ONE thing to do next, naming the tab it lives on — null once the household
 *  is settled (owner bound with their own bot, no open invites, a member bound). */
export function nextStepHint(
  online: boolean,
  self: SelfState,
  scan: boolean,
  openInvites: number,
  familyBound: number,
  ownerConnected: boolean,
): { text: string; tab: ContactsTab } | null {
  if (!online) return { text: scan ? 'connect your own WeChat — scan the QR from the connection card' : 'connect the household bot', tab: 'connection' };
  if (self !== 'bound') return { text: scan ? 'bind yourself as the owner — connect my WeChat' : 'bind yourself as the owner — mint your code and text it to the bot', tab: 'connection' };
  if (scan && !ownerConnected) return { text: 'your own WeChat has no clawbot yet — connect it from the connection card', tab: 'connection' };
  if (openInvites > 0) return { text: `${openInvites} open invite${openInvites === 1 ? '' : 's'} — ${scan ? 'show the connect QR when they are with you' : 'they text the code, you approve'}`, tab: 'invitations' };
  if (familyBound === 0) return { text: 'invite your first family member', tab: 'invitations' };
  return null;
}
