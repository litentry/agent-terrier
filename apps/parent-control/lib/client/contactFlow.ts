import type { ChannelDoc } from '../generated/ChannelDoc';
import type { ChannelGrant } from '../generated/ChannelGrant';
import type { ContactSummary } from '../generated/ContactSummary';
import type { ContactTier } from '../generated/ContactTier';
import type { GatewayPendingBindView } from '../generated/GatewayPendingBindView';

// The Contacts page's flow, as pure functions (unit-tested without React):
// one bot per household connected ONCE; every member — the owner first —
// binds by texting an invite code to that bot; the owner approves each bind.
// A member's access is their rows on the household's CHANNEL DOCUMENTS
// (speak / read per channel) — never a list of apps.

/** The owner's own invite uses a FIXED contact id so re-minting replaces it. */
export const SELF_CONTACT_ID = 'self-owner';
export const SELF_DISPLAY_NAME = '我自己';

export const TIER_ORDER: ContactTier[] = ['owner', 'partner', 'elder', 'kid', 'helper', 'guest'];

/** What each tier means, in the words a parent would use. */
export const TIER_INFO: Record<ContactTier, { zh: string; blurb: string }> = {
  owner: { zh: '拥有者', blurb: 'You. Every channel, each app’s operator channel included; an app you install later adds its channel here.' },
  partner: { zh: '配偶', blurb: 'Your spouse. The family channels; an operator channel only when you switch it on.' },
  elder: { zh: '长辈', blurb: 'Grandparents. The family channels whose apps admit them; never an operator channel by default.' },
  kid: { zh: '孩子', blurb: 'Children. Only the channels you pick; they can read the family chat without posting.' },
  helper: { zh: '帮手', blurb: 'Nanny, cleaner. The household channels whose apps admit them.' },
  guest: { zh: '访客', blurb: 'Visitors. Nothing until you add them to a channel.' },
};

/** The channels a member can be given rows on: household channels first,
 *  each app's operator channel after (the explicit ones). */
export function grantableChannels(docs: ChannelDoc[]): ChannelDoc[] {
  return [...docs].sort((a, b) => Number(!!a.operator_of) - Number(!!b.operator_of) || a.id.localeCompare(b.id));
}

/** The rows a fresh invite starts with — a proposal the owner edits before
 *  minting: the owner speaks everywhere (operator channels included); a guest
 *  nothing; every other tier speaks on the household channels whose apps
 *  admit it (each app row carries its template's audience) and reads the
 *  household default otherwise. Operator channels are never proposed. Apps
 *  installed LATER propose their own rows (the daemon's install write-through). */
export function suggestedGrants(tier: ContactTier, docs: ChannelDoc[]): ChannelGrant[] {
  const out: ChannelGrant[] = [];
  for (const d of grantableChannels(docs)) {
    if (tier === 'owner') {
      out.push({ channel_id: d.id, speak: true, read: true });
      continue;
    }
    if (tier === 'guest' || d.operator_of) continue;
    const admitted = d.apps.some((a) => a.audience.includes(tier));
    if (admitted) out.push({ channel_id: d.id, speak: true, read: true });
    else if (d.household_default) out.push({ channel_id: d.id, speak: false, read: true });
  }
  return out;
}

/** One line naming the channels a set of grants covers, as the page shows it. */
export function describeGrants(grants: { channel_id: string; speak: boolean; read: boolean }[], docs: ChannelDoc[]): string {
  const name = (id: string) => docs.find((d) => d.id === id)?.name || id;
  const parts = grants
    .filter((g) => g.speak || g.read)
    .map((g) => `${name(g.channel_id)}${g.speak ? '' : ' (read only)'}`);
  return parts.length ? parts.join(', ') : '—';
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
