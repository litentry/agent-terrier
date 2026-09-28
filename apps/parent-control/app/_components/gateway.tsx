'use client';

// #418/#419 — the household interaction layer, split into the Parent Control
// design system's two themed sections (globals.css: channels = hue 200,
// contacts = hue 330), matching the arch's D4-channel / D5-contact distinction:
//
//   • ChannelsPage (data-section="channels") — the CONDUITS. Connect the WeChat
//     bot: the operator scans the QR with the SPARE account → that account
//     becomes the bot; the gateway writes its own secrets file + hot-swaps the
//     inbound loop (no restart). Devices are channel endpoints paired elsewhere.
//   • ContactsPage (data-section="contacts") — the FAMILY. Invite (one-time
//     code) → the member echoes it to the bot → the master approves. D13-safe
//     throughout: the UI never sees an openid.
//
// Both drive the daemon proxy (`/v1/master/gateway/*`); the admin bearer stays
// server-side.
import { useCallback, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { QRCodeSVG } from 'qrcode.react';

import { PageHead, Panel, Modal, Dot, Tabs } from './shared';
import { RoutePage } from './route';
import {
  gatewayClient,
  gatewayDebugEnabled,
  gatewayNotConfigured,
  gwlog,
  isTerminalLoginStatus,
  setGatewayDebug,
} from '@/lib/gatewayClient';
import type { GatewayStatusView } from '@/lib/generated/GatewayStatusView';
import type { GatewayPendingBindView } from '@/lib/generated/GatewayPendingBindView';
import type { ContactSummary } from '@/lib/generated/ContactSummary';
import type { ContactTier } from '@/lib/generated/ContactTier';
import type { GatewayMonitorEvent } from '@/lib/generated/GatewayMonitorEvent';
import type { GatewayActivityEvent } from '@/lib/generated/GatewayActivityEvent';
import type { ChannelDoc } from '@/lib/generated/ChannelDoc';
import type { ChannelGrant } from '@/lib/generated/ChannelGrant';
import {
  SELF_CONTACT_ID,
  SELF_DISPLAY_NAME,
  TIER_INFO,
  describeGrants,
  grantableChannels,
  defaultTab,
  inviteState,
  nextStepHint,
  type ContactsTab,
  scanTransport,
  selfState,
  sendText,
  suggestedGrants,
  type SelfState,
} from '@/lib/client/contactFlow';

const TIERS: ContactTier[] = ['owner', 'partner', 'elder', 'kid', 'helper', 'guest'];

// The app styles form fields inline (no `.input` class) — mirror credentials.tsx.
const INPUT_STYLE: CSSProperties = {
  padding: '8px 10px',
  fontSize: 12.5,
  border: '1px solid var(--rule)',
  background: 'var(--bg)',
  color: 'var(--ink)',
  width: '100%',
};

function Field({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
      <span className="muted">{label}</span>
      {children}
    </label>
  );
}

// Human-readable, non-alarming reason text for the reason codes the gateway/
// daemon return. Anything unmapped shows the raw reason + detail (never a blank).
const REASON_TEXT: Record<string, string> = {
  gateway_not_configured: 'No contact gate URL — the daemon derives it from its broker; point the daemon at a deployed broker (or set AGENTKEYS_WORKER_WEIXIN_URL to override).',
  'gateway-not-configured': 'No contact gate URL — the daemon derives it from its broker; point the daemon at a deployed broker (or set AGENTKEYS_WORKER_WEIXIN_URL to override).',
  'gateway-admin-not-configured':
    'The contact gate admin token isn’t set on the daemon — put this stack’s AGENTKEYS_WEIXIN_ADMIN_TOKEN (from the broker’s weixin-secrets.env) in scripts/operator-workstation.<stack>.secrets.env of the MAIN checkout, then restart the local web app.',
  admin_disabled: 'The contact gate has no admin token configured — set AGENTKEYS_WEIXIN_ADMIN_TOKEN on the broker.',
  admin_unauthorized:
    'The daemon’s admin token doesn’t match the contact gate’s — probably another stack’s bearer or an ambient ~/.zshenv export. Put this stack’s bearer in scripts/operator-workstation.<stack>.secrets.env of the MAIN checkout (dev.sh reads the checkout it runs from, then the main checkout) and restart the local web app.',
  transport_not_ilink: 'This contact gate runs the 公众号 (oa) transport — the QR connect flow is for the personal-bot (ilink) transport.',
  daemon_unreachable: 'The local daemon isn’t reachable — is it running?',
  no_active_login: 'The login session expired — start again.',
  bind_not_claimed: 'No one has sent this code to the bot yet — it can’t be approved until they do.',
  operator_grade_reach_denied: 'Only the owner tier may speak where a money/usage app is bound.',
};

// #722 — how a turn was routed, as the monitor's suffix: «routed by jev (0.81)»
// / «asked (0.42)» / «ask reply» / «single channel»; nothing for a typed /alias.
function routedByLabel(e: { reason: string; routed_by?: string; confidence?: number }): string {
  const conf = e.confidence == null ? '' : ` (${e.confidence.toFixed(2)})`;
  if (e.reason === 'router_ask') return ` · asked${conf}`;
  if (!e.routed_by) return '';
  const names: Record<string, string> = {
    jev: 'routed by jev',
    jev_follow_up: 'follow-up',
    ask_reply: 'ask reply',
    single_channel: 'single channel',
    single_media_channel: 'the one channel taking it',
    advisory_router: 'whole-word',
    sticky_last_channel: 'last channel',
  };
  return ` · ${names[e.routed_by] ?? e.routed_by}${conf}`;
}

function reason(r: { reason: string; detail?: string }): string {
  return REASON_TEXT[r.reason] ?? r.detail ?? r.reason;
}

function tierLabel(t: ContactTier): string {
  return { owner: '拥有者', partner: '配偶', elder: '长辈', kid: '孩子', helper: '帮手', guest: '访客' }[t];
}

// Shared gateway-status hook (both pages read the connection card). `autoLoad`
// is false on the contacts page, which drives its own combined refresh.
function useGatewayStatus(autoLoad = true) {
  const [status, setStatus] = useState<GatewayStatusView | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  // Returns whether the status fetch succeeded, so a caller can skip the
  // dependent fetches (contacts / pending) when the gateway isn't up.
  const refreshStatus = useCallback(async (): Promise<boolean> => {
    const s = await gatewayClient.status();
    if (s.ok) {
      setStatus(s.value);
      setStatusErr(null);
      setNotConfigured(false);
    } else {
      setStatus(null);
      setStatusErr(reason(s));
      setNotConfigured(gatewayNotConfigured(s));
    }
    return s.ok;
  }, []);
  useEffect(() => {
    if (autoLoad) void refreshStatus();
  }, [autoLoad, refreshStatus]);
  return { status, statusErr, notConfigured, refreshStatus };
}

function useToast(): { toast: string | null; flash: (m: string) => void } {
  const [toast, setToast] = useState<string | null>(null);
  const flash = (m: string) => {
    setToast(m);
    window.setTimeout(() => setToast(null), 4000);
  };
  return { toast, flash };
}

function Toast({ toast }: { toast: string | null }) {
  if (!toast) return null;
  return (
    <div className="banner" style={{ marginBottom: 14 }}>
      <span className="lbl">✓</span>
      <span>{toast}</span>
    </div>
  );
}

// (#404 IA: the "channels" page is now the channel REGISTRY — `channels.tsx`
// (id-anchored definitions: create / rename / delete). Devices pair on the
// devices page (`devices.tsx`). This file owns the transport + contacts
// surface: TransportPage (the method's connection, the owner's own bind, the
// route / monitor / history / activity tabs) and ContactsPage (invites, the family).)

// ── live monitor (#1) ───────────────────────────────────────────────────────────
// Polls /v1/master/gateway/monitor every 3 s while the bot is online, appending
// new turns. Each row: time · sender (display_name, D13 — never the openid) ·
// tier · text preview · the L3 decision (✓ → target, or ✕ + reason).
function MonitorPanel({ online }: { online: boolean }) {
  const [events, setEvents] = useState<GatewayMonitorEvent[]>([]);
  const cursorRef = useRef(0);

  useEffect(() => {
    if (!online) return;
    let alive = true;
    const tick = async () => {
      const r = await gatewayClient.monitor(cursorRef.current);
      if (!alive || !r.ok) return;
      cursorRef.current = r.value.cursor;
      if (r.value.events.length) {
        setEvents((prev) => [...prev, ...r.value.events].slice(-100));
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 3000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [online]);

  const fmtTime = (ms: number) => new Date(ms).toLocaleTimeString();

  return (
    <Panel
      title="live monitor"
      right={<span className="muted" style={{ fontSize: 11 }}>{online ? '· polling every 3s' : '· offline'}</span>}
    >
      {!online ? (
        <div className="muted" style={{ fontSize: 13 }}>Connect the bot to watch messages live.</div>
      ) : events.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>
          No messages yet. Every inbound turn — allowed, denied, or an unknown-sender attempt — appears here as it happens.
        </div>
      ) : (
        <div style={{ maxHeight: 300, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 5 }}>
          {[...events].reverse().map((e) => (
            <div key={e.seq} style={{ fontSize: 12, display: 'flex', gap: 8, alignItems: 'baseline' }}>
              <span className="muted" style={{ fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>{fmtTime(e.ts_ms)}</span>
              <span style={{ flexShrink: 0 }}><strong>{e.contact}</strong> <span className="muted">{e.tier}</span></span>
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.text || '—'}</span>
              <span style={{ flexShrink: 0, color: e.allowed ? 'var(--ok, #1a7f5a)' : 'var(--danger)' }}>
                {e.allowed ? `✓ → ${e.target ?? '?'}` : `✕ ${e.reason}`}
                {routedByLabel(e)}
              </span>
            </div>
          ))}
        </div>
      )}
      <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
        Live tail (last 100 turns). The full durable record is below in <strong>history</strong>. Senders show as their contact name — WeChat identity is never exposed (D13).
      </div>
    </Panel>
  );
}

// ── durable history (#419) ──────────────────────────────────────────────────────
// Reads the append-only log (survives restarts, the full record + future stats
// home). Loads the newest page on demand, "load older" pages backward by ts_ms.
function HistoryPanel() {
  const [events, setEvents] = useState<GatewayMonitorEvent[]>([]);
  const [beforeTs, setBeforeTs] = useState<number | undefined>(undefined);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async (before?: number) => {
    setBusy(true);
    const r = await gatewayClient.history(before, 50);
    setBusy(false);
    setLoaded(true);
    if (!r.ok) return;
    setEvents((prev) => (before ? [...prev, ...r.value.events] : r.value.events));
    setBeforeTs(r.value.next_before_ts ?? undefined);
    if (r.value.events.length < 50) setDone(true);
  }, []);

  const fmt = (ms: number) => new Date(ms).toLocaleString();

  return (
    <Panel
      title="history"
      right={
        loaded ? (
          <span className="muted" style={{ fontSize: 11 }}>· durable · {events.length}</span>
        ) : (
          <button className="btn sm" onClick={() => void load()}>load</button>
        )
      }
    >
      {!loaded ? (
        <div className="muted" style={{ fontSize: 13 }}>
          Every inbound turn is kept durably (survives restarts) — the owner’s full message record and the future home of message stats. Click <strong>load</strong> to view it.
        </div>
      ) : events.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No messages recorded yet.</div>
      ) : (
        <>
          <div style={{ maxHeight: 360, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 5 }}>
            {events.map((e) => (
              <div key={`${e.ts_ms}-${e.seq}`} style={{ fontSize: 12, display: 'flex', gap: 8, alignItems: 'baseline' }}>
                <span className="muted" style={{ fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>{fmt(e.ts_ms)}</span>
                <span style={{ flexShrink: 0 }}><strong>{e.contact}</strong> <span className="muted">{e.tier}</span></span>
                <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.text || '—'}</span>
                <span style={{ flexShrink: 0, color: e.allowed ? 'var(--ok, #1a7f5a)' : 'var(--danger)' }}>
                  {e.allowed ? `✓ → ${e.target ?? '?'}` : `✕ ${e.reason}`}
                  {routedByLabel(e)}
                </span>
              </div>
            ))}
          </div>
          {!done && (
            <div style={{ marginTop: 8 }}>
              <button className="btn sm" disabled={busy} onClick={() => void load(beforeTs)}>
                {busy ? 'loading…' : 'load older'}
              </button>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

// ── contact audit / activity (#419) ─────────────────────────────────────────────
// The DURABLE control-action trail (invite/claim/bound/rejected/revoked), read
// from the gateway's append-only log — survives daemon AND worker restarts,
// unlike the master audit feed's in-memory buffer. `auditOff` warns when the
// tamper-proof on-chain anchor is disarmed (operator omni unset).
const ACTION_ICON: Record<string, string> = {
  invite: '✎',
  claim: '↩',
  bound: '✓',
  rejected: '✕',
  revoked: '⊘',
  connected: '⚡',
  disconnected: '⏻',
};

function ActivityPanel({ auditOff }: { auditOff: boolean }) {
  const [events, setEvents] = useState<GatewayActivityEvent[]>([]);
  const [beforeTs, setBeforeTs] = useState<number | undefined>(undefined);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async (before?: number) => {
    setBusy(true);
    const r = await gatewayClient.activity(before, 50);
    setBusy(false);
    setLoaded(true);
    if (!r.ok) return;
    setEvents((prev) => (before ? [...prev, ...r.value.events] : r.value.events));
    setBeforeTs(r.value.next_before_ts ?? undefined);
    if (r.value.events.length < 50) setDone(true);
  }, []);

  const fmt = (ms: number) => new Date(ms).toLocaleString();

  return (
    <Panel
      title="contact audit · 活动"
      right={
        loaded ? (
          <span className="muted" style={{ fontSize: 11 }}>· durable · {events.length}</span>
        ) : (
          <button className="btn sm" onClick={() => void load()}>load</button>
        )
      }
    >
      {auditOff && (
        <div className="banner warn" style={{ marginBottom: 10 }}>
          <span className="lbl">⚠</span>
          <span>
            On-chain audit is <strong>off</strong> — actions are recorded durably here but NOT anchored
            on-chain. Set <code>AGENTKEYS_WEIXIN_OPERATOR_OMNI</code> on the broker + restart the contact gate.
          </span>
        </div>
      )}
      {!loaded ? (
        <div className="muted" style={{ fontSize: 13 }}>
          Every bind / reject / revoke is kept durably (survives restarts). Click <strong>load</strong> to view the audit trail.
        </div>
      ) : events.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No contact actions recorded yet.</div>
      ) : (
        <>
          <div style={{ maxHeight: 320, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 5 }}>
            {events.map((e, i) => (
              <div key={`${e.ts_ms}-${i}`} style={{ fontSize: 12, display: 'flex', gap: 8, alignItems: 'baseline' }}>
                <span className="muted" style={{ fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>{fmt(e.ts_ms)}</span>
                <span style={{ flexShrink: 0, width: 72 }}>{ACTION_ICON[e.action] ?? '·'} {e.action}</span>
                <span style={{ flexShrink: 0 }}><strong>{e.contact}</strong></span>
                <span className="muted" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.detail}</span>
                <span style={{ flexShrink: 0 }} title={e.on_chain ? 'anchored on-chain' : 'local record only'}>{e.on_chain ? '⛓' : '·'}</span>
              </div>
            ))}
          </div>
          {!done && (
            <div style={{ marginTop: 8 }}>
              <button className="btn sm" disabled={busy} onClick={() => void load(beforeTs)}>
                {busy ? 'loading…' : 'load older'}
              </button>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

// A persisted toggle for the gateway request/response console trace. OFF by
// default — this page polls status/contacts/monitor on a timer, so the
// `[contact gate]` logs flood DevTools; flip it on only when diagnosing a
// connect/bind issue. The preference lives in localStorage (survives reloads)
// and gates gwlog() app-wide (see gatewayClient.ts).
function GatewayDebugToggle() {
  const [on, setOn] = useState(false);
  // localStorage is client-only — read it after mount so SSR renders the
  // default-off state and hydration doesn't mismatch.
  useEffect(() => setOn(gatewayDebugEnabled()), []);
  const toggle = () => {
    const next = !on;
    setGatewayDebug(next);
    setOn(next);
  };
  return (
    <button
      className="btn sm"
      onClick={toggle}
      aria-pressed={on}
      title={
        on
          ? 'Contact gate request/response logs are ON — click to silence the console'
          : 'Log every contact gate request/response to the console (connect/bind diagnostics)'
      }
    >
      {on ? '● debug logs' : '○ debug logs'}
    </button>
  );
}

// ── the household's shared state ─────────────────────────────────────────────
// The contact gate page (the bot, the owner's own bind, the router, the live
// turns) and the contacts page (invites, the bound family) read the same
// status / contacts / pending / channel documents: one hook, one refresh, one
// poll while anything is in flight.
function useHousehold() {
  const { status, statusErr, notConfigured, refreshStatus } = useGatewayStatus(false);
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const [pending, setPending] = useState<GatewayPendingBindView[]>([]);
  // The household's channel documents: what a member can be given rows on,
  // and what an invite gets pre-filled from (each app row's audience).
  const [docs, setDocs] = useState<ChannelDoc[]>([]);
  const refresh = useCallback(async () => {
    const ok = await refreshStatus();
    if (!ok) {
      setContacts([]);
      setPending([]);
      return;
    }
    const [c, p] = await Promise.all([gatewayClient.contacts(), gatewayClient.bindPending()]);
    if (c.ok) {
      setContacts(c.value.contacts);
      setDocs(c.value.channels ?? []);
    }
    if (p.ok) setPending(p.value.pending);
  }, [refreshStatus]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  // The flow advances LIVE (a claim lands, a bind completes) — poll while
  // anything is still in flight, never when the household is settled.
  const inFlight = !notConfigured && (contacts.length === 0 || pending.length > 0);
  useEffect(() => {
    if (!inFlight) return;
    const id = window.setInterval(() => void refresh(), 4000);
    return () => window.clearInterval(id);
  }, [inFlight, refresh]);
  const online = !!status?.online;
  // No status = the gate is unreachable (401/offline): the steps still read as the
  // household default (iLink, scan) and every mint is held until the gate is fixed.
  const reachable = status !== null;
  const scan = scanTransport(status?.transport);
  const self = selfState(pending, contacts);
  // The owner's connect QR is minted FOR their registry row: the bound owner's own
  // id when one exists (a code-bound owner re-binds by scan — their own phone
  // becomes their bot), else the console's `self-owner` invite.
  const selfContactId = contacts.find((c) => c.tier === 'owner')?.contact_id ?? SELF_CONTACT_ID;
  const familyPending = pending.filter((p) => p.contact_id !== SELF_CONTACT_ID);
  const me = contacts.find((c) => c.tier === 'owner');
  const familyBound = contacts.filter((c) => c.tier !== 'owner').length;
  // The single thing to do next, and where it lives (the gate page or a contacts tab).
  const hint = nextStepHint(online, self, scan, familyPending.length, familyBound, !!me?.connected);
  return { status, statusErr, notConfigured, refresh, contacts, pending, docs, online, reachable, scan, self, selfContactId, familyPending, me, familyBound, hint };
}

// ── Transport page (data-section="contacts") — how the family reaches the household ──
// The messaging METHOD this stack runs (WeChat via iLink, or Telegram; a
// dedicated app later) and the contact gate behind it — the relayer that owns
// no channel: the method's connection and the owner's own bind, the router
// (what the decision model is sent and how it answered), the live turns, the
// durable record and the contact audit. The people — invites, the bound family
// and their channel rows — are the contacts page. (Replaced the "contact gate"
// tab, owner direction 2026-09-26: a transport is a method, never a channel.)
export type TransportTab = 'connection' | 'route' | 'monitor' | 'history' | 'activity';

/** The methods a household can reach its channels through, and which this stack runs. */
function methodRows(transport: string | undefined, online: boolean, notConfigured: boolean): { name: string; kind: string; state: string; here: boolean }[] {
  const t = (transport ?? '').toLowerCase();
  const wechatHere = t === 'ilink' || t === 'oa' || t === 'weixin';
  const telegramHere = t === 'telegram';
  const state = notConfigured ? 'no contact gate on this stack' : online ? 'connected' : 'offline';
  return [
    { name: 'WeChat · iLink', kind: 'aggregating — one thread per member', state: wechatHere ? state : 'on a stack that runs it', here: wechatHere },
    { name: 'Telegram (a DM)', kind: 'aggregating — one thread per member', state: telegramHere ? state : 'on a stack that runs it', here: telegramHere },
    { name: 'Dedicated app', kind: 'channel-native — a thread per channel', state: 'later', here: false },
  ];
}

export function TransportPage({ onGoContacts }: { onGoContacts: () => void }) {
  const { status, statusErr, notConfigured, refresh, contacts, pending, docs, online, reachable, scan, self, selfContactId, me, hint } = useHousehold();
  const { toast, flash } = useToast();
  const [tab, setTab] = useState<TransportTab>('connection');
  const botsOnline = status?.bots_online ?? 0;
  const ownerState = self === 'bound'
    ? (scan ? (me?.connected ? 'bound · your clawbot is connected' : 'bound · no clawbot on your own WeChat yet') : 'bound')
    : self === 'claimed'
      ? 'code received — approve'
      : self === 'minted'
        ? (scan ? 'invite minted — scan your connect QR' : 'code minted — text it to the bot')
        : online
          ? 'not bound yet'
          : 'connect first';
  return (
    <>
      <PageHead
        crumb="household / transport"
        title="Transport"
        desc="How your family reaches the household's channels: the messaging method this stack runs, and the contact gate behind it — a relayer that owns no channel. Connect the method here and bind yourself as the owner; the route tab shows what the router sends the decision model for each message and how it answered; monitor, history and activity are the live turns, the durable record and the contact audit. Invites and the family's channel rows live on the contacts page."
        actions={
          <>
            <GatewayDebugToggle />
            <button className="btn sm" onClick={() => void refresh()}>↻ refresh</button>
          </>
        }
      />
      <Toast toast={toast} />
      <Tabs
        items={[
          {
            key: 'connection',
            label: 'connection',
            badge: notConfigured ? 'no gate' : online ? `${botsOnline} bot${botsOnline === 1 ? '' : 's'} online` : 'offline',
            attention: hint?.tab === 'transport',
          },
          { key: 'route', label: 'route' },
          { key: 'monitor', label: 'monitor', badge: online ? 'live' : undefined },
          { key: 'history', label: 'history' },
          { key: 'activity', label: 'activity' },
        ]}
        active={tab}
        onChange={setTab}
      />
      {hint && (
        <div className="tab-hint muted">
          Next: <button type="button" onClick={() => (hint.tab === 'transport' ? setTab('connection') : onGoContacts())}>{hint.text}</button>
        </div>
      )}

      {tab === 'connection' && (
        <>
          <Panel title="methods" flush>
            <table className="tab" style={{ margin: 0 }}>
              <tbody>
                {methodRows(status?.transport, online, notConfigured).map((m) => (
                  <tr key={m.name}>
                    <td style={{ fontWeight: m.here ? 500 : 400 }}>{m.name}</td>
                    <td className="muted">{m.kind}</td>
                    <td className="muted">{m.here ? <strong>this stack · {m.state}</strong> : m.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted" style={{ fontSize: 11.5, margin: '8px 16px 12px' }}>
              A method is not a channel: the contact gate relays the household&apos;s channels through it and holds one grant per channel it relays — nothing of its own.
            </p>
          </Panel>
          {scan ? (
            <p className="muted" style={{ fontSize: 12.5, margin: '0 0 12px' }}>
              A clawbot lives only in the WeChat account that scanned its QR — there is no sharing. Every member, you first, connects their <strong>own</strong> WeChat; each bot is linked to this household and routes to the same agents.
              WeChat's policy for personal accounts on this API is undocumented.
            </p>
          ) : (
            <p className="muted" style={{ fontSize: 12.5, margin: '0 0 12px' }}>
              This contact gate runs a <strong>shared</strong> bot (a 公众号 or a Telegram bot) that anyone can message. Connect it once here;
              family members never scan anything — each gets a 6-digit code from the invitations tab.
            </p>
          )}
          <ConnectPanel status={status} statusErr={statusErr} notConfigured={notConfigured} selfContactId={selfContactId} onChange={() => void refresh()} onFlash={flash} />
          <Panel
            title="you — the owner"
            right={<span className="muted" style={{ fontSize: 12, color: hint?.tab === 'transport' && online ? 'var(--accent)' : undefined }}>{ownerState}</span>}
          >
            <SelfBindCard self={self} pending={pending} contacts={contacts} docs={docs} online={online} reachable={reachable} scan={scan} onChange={() => void refresh()} onFlash={flash} />
          </Panel>
        </>
      )}
      {tab === 'route' && <RoutePage embedded />}
      {tab === 'monitor' && <MonitorPanel online={online} />}
      {tab === 'history' && <HistoryPanel />}
      {tab === 'activity' && <ActivityPanel auditOff={online && status?.audit_on_chain === false} />}
    </>
  );
}

// ── Contacts page (data-section="contacts", hue 330) — the family ─────────────
export function ContactsPage({ onGoTransport }: { onGoTransport: () => void }) {
  const { refresh, contacts, docs, online, reachable, scan, self, familyPending, hint } = useHousehold();
  const { toast, flash } = useToast();
  // Two tabs. The page opens on the one the flow points at; a tab the user
  // picked stays picked. The "Next:" line names the single thing to do and
  // jumps to it — the transport page when the bot or the owner's own bind
  // is what's missing.
  const suggestedTab = defaultTab(online, self, familyPending.length);
  const [pickedTab, setPickedTab] = useState<ContactsTab | null>(null);
  const activeTab: ContactsTab = pickedTab ?? suggestedTab;
  return (
    <>
      <PageHead
        crumb="household / contacts"
        title="Contacts"
        desc="Every family member — you first — gets their own clawbot: a connect QR minted here, scanned with their own WeChat. Nothing binds without an invite you minted, and no one's WeChat identity is ever shown (D13)."
        actions={<button className="btn sm" onClick={() => void refresh()}>↻ refresh</button>}
      />
      <Toast toast={toast} />
      <Tabs
        items={[
          { key: 'invitations', label: 'invitations', badge: familyPending.length, attention: hint?.tab === 'invitations' },
          { key: 'contacts', label: 'contacts', badge: contacts.length },
        ]}
        active={activeTab}
        onChange={setPickedTab}
      />
      {hint && (
        <div className="tab-hint muted">
          Next: <button type="button" onClick={() => (hint.tab === 'transport' ? onGoTransport() : setPickedTab(hint.tab))}>{hint.text}</button>
        </div>
      )}

      {activeTab === 'invitations' && (
        <>
          {scan ? (
            <p className="muted" style={{ fontSize: 12.5, margin: '0 0 12px' }}>
              Mint an invite (name, tier, the channels they join), then open their connect QR from the row when they are with you — they scan it with <strong>their own</strong> WeChat and their clawbot appears, bound with the tier and channels you chose. The mint is your approval; nothing else to confirm. They are told in their chat with their first message.
            </p>
          ) : (
            <p className="muted" style={{ fontSize: 12.5, margin: '0 0 12px' }}>
              Members don't scan or connect anything: they open the shared bot themselves (follow the 公众号, or open the Telegram bot), you mint an invite,
              they text the code to it in a <strong>private</strong> chat from <strong>their own</strong> account (groups are ignored, and the bot cannot message first), you approve. Each invite below shows where it stands.
            </p>
          )}
          <InvitePanel docs={docs} online={scan ? reachable : online} scan={scan} onInvited={() => void refresh()} onFlash={flash} />
          <InvitesTable pending={familyPending} docs={docs} scan={scan} onChange={() => void refresh()} onFlash={flash} />
        </>
      )}

      {activeTab === 'contacts' && <ContactsPanel contacts={contacts} docs={docs} onChange={() => void refresh()} onFlash={flash} />}
    </>
  );
}

// ── step 2: the owner's own bind ──────────────────────────────────────────────
// The owner binds like everyone else — on iLink a scan with their own WeChat (their
// own clawbot), on 公众号/Telegram a code texted to the shared bot. The card is the
// state machine in one place:
// mint → the code, right here, with the send text → the bot received it →
// approve → bound (with the rows that were granted).
function SelfBindCard({
  self,
  pending,
  contacts,
  docs,
  online,
  reachable,
  scan,
  onChange,
  onFlash,
}: {
  self: SelfState;
  pending: GatewayPendingBindView[];
  contacts: ContactSummary[];
  docs: ChannelDoc[];
  online: boolean;
  reachable: boolean;
  scan: boolean;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const mine = pending.find((p) => p.contact_id === SELF_CONTACT_ID) ?? pending.find((p) => p.tier === 'owner');
  const me = contacts.find((c) => c.tier === 'owner');
  // The owner speaks on every channel, each app's operator channel included.
  const grants = suggestedGrants('owner', docs);
  const mint = async () => {
    setBusy(true);
    const r = await gatewayClient.bindInvite({ contact_id: SELF_CONTACT_ID, display_name: SELF_DISPLAY_NAME, tier: 'owner', channels: grants });
    setBusy(false);
    if (!r.ok) {
      onFlash(`Minting your code failed — ${reason(r)}`);
      return;
    }
    onChange();
  };
  const approve = async () => {
    if (!mine) return;
    setBusy(true);
    const r = await gatewayClient.bindApprove({ bind_code: mine.bind_code, tier: null, channels: null });
    setBusy(false);
    if (!r.ok) {
      onFlash(`Approve failed — ${reason(r)}`);
      return;
    }
    onFlash('You are bound as the owner — every message from your WeChat now carries your name');
    onChange();
  };
  if (self === 'bound' && me) {
    return (
      <div style={{ fontSize: 13, lineHeight: 1.7 }}>
        ✓ Bound as <strong>{me.display_name}</strong> · owner · channels: {describeGrants(me.channels, docs)}
        {scan && (me.connected ? <span> · your clawbot is connected</span> : <span style={{ color: 'var(--danger)' }}> · no clawbot on your own WeChat yet — ⊕ connect in the card above and scan with your own phone</span>)}
        {!me.welcomed && <div className="muted" style={{ fontSize: 12 }}>The «✅ 绑定成功» acknowledgement reaches you with your first message to the bot.</div>}
        <div className="muted" style={{ fontSize: 12 }}>Apps you install later add their channels here automatically.</div>
      </div>
    );
  }
  if (scan && self !== 'bound') {
    return (
      <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
        <div>
          Scan a connect QR with <strong>your own</strong> WeChat — your clawbot appears as a contact there, linked to this household, and you are bound as the owner
          {grants.length ? ` on ${grants.length} channel${grants.length === 1 ? '' : 's'}` : ''}.
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            className="btn primary"
            disabled={busy || !reachable}
            onClick={() =>
              void (async () => {
                if (self === 'none') await mint();
                setScanOpen(true);
              })()
            }
          >
            {busy ? 'minting…' : self === 'none' ? '⊕ connect my WeChat' : '▣ show my connect QR'}
          </button>
          {self === 'minted' && <button className="btn sm" disabled={busy || !reachable} onClick={() => void mint()}>re-mint</button>}
          {!reachable && <span className="muted" style={{ fontSize: 12 }}>the contact gate is unreachable — fix step 1 first</span>}
        </div>
        {scanOpen && (
          <ConnectModal
            contactId={SELF_CONTACT_ID}
            onClose={() => setScanOpen(false)}
            onConnected={(botId) => {
              setScanOpen(false);
              onFlash(`Connected · ${botId} — you are bound as the owner`);
              onChange();
            }}
          />
        )}
      </div>
    );
  }
  if (self === 'none') {
    return (
      <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
        <div>Mint your own code, then text it to the shared bot in a private chat from your <strong>own</strong> account.</div>
        <div>
          <button className="btn primary" disabled={busy || !online} onClick={() => void mint()}>
            {busy ? 'minting…' : `⊕ mint my code · owner · ${grants.length ? `${grants.length} channel${grants.length === 1 ? '' : 's'}` : 'no channels yet'}`}
          </button>
          {!online && <span className="muted" style={{ fontSize: 12, marginLeft: 8 }}>connect the bot first</span>}
        </div>
      </div>
    );
  }
  if (!mine) return null;
  if (self === 'minted') {
    return (
      <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
        <div>Text this to the bot from your <strong>daily</strong> WeChat:</div>
        <CodeLine code={mine.bind_code} onCopied={() => onFlash('Copied — paste it into the chat with the bot')} />
        <div className="muted" style={{ fontSize: 12 }}>
          channels when bound: {describeGrants(mine.channels, docs)} · waiting for the bot to receive it (this page refreshes by itself) ·{' '}
          <button className="btn sm" disabled={busy} onClick={() => void mint()}>re-mint</button>
        </div>
      </div>
    );
  }
  return (
    <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
      <div>The bot received your code. Approving binds <strong>that</strong> WeChat as the owner · channels: {describeGrants(mine.channels, docs)}.</div>
      <div className="muted" style={{ fontSize: 12 }}>The sender's WeChat identity is never shown (D13). If you did not send this code yourself, reject it.</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn primary" disabled={busy} onClick={() => void approve()}>{busy ? 'approving…' : '✓ approve — bind me'}</button>
        <RejectButton bindCode={mine.bind_code} name={SELF_DISPLAY_NAME} onChange={onChange} onFlash={onFlash} />
      </div>
    </div>
  );
}

// The code, big, with the exact text to send and a copy button.
function CodeLine({ code, onCopied }: { code: string; onCopied: () => void }) {
  const text = sendText(code);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      <span style={{ fontFamily: 'var(--mono, monospace)', fontSize: 28, fontWeight: 700, letterSpacing: '0.14em' }}>{code}</span>
      <code style={{ fontSize: 12.5 }}>{text}</code>
      <button
        className="btn sm"
        onClick={() => {
          void navigator.clipboard?.writeText(text);
          onCopied();
        }}
      >
        ⧉ copy
      </button>
    </div>
  );
}

// ── step 3: the family invites, each with its state ───────────────────────────
function InvitesTable({
  pending,
  docs,
  scan,
  onChange,
  onFlash,
}: {
  pending: GatewayPendingBindView[];
  docs: ChannelDoc[];
  scan: boolean;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  if (pending.length === 0) return null;
  const claimed = pending.filter((p) => p.claimed);
  const minted = pending.filter((p) => !p.claimed);
  return (
    <div style={{ marginTop: 14 }}>
      <div className="perm-section-head">
        <span className="ttl">open invites</span>
        <span className="summary">{claimed.length > 0 ? `${claimed.length} to approve` : `${minted.length} waiting`}</span>
      </div>
      <div style={{ display: 'grid', gap: 6 }}>
        {claimed.map((p) => <InviteRow key={p.bind_code} p={p} docs={docs} scan={scan} onChange={onChange} onFlash={onFlash} />)}
        {minted.map((p) => <InviteRow key={p.bind_code} p={p} docs={docs} scan={scan} onChange={onChange} onFlash={onFlash} />)}
      </div>
    </div>
  );
}

function InviteRow({
  p,
  docs,
  scan,
  onChange,
  onFlash,
}: {
  p: GatewayPendingBindView;
  docs: ChannelDoc[];
  scan: boolean;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const state = inviteState(p);
  const approve = async () => {
    setBusy(true);
    setErr(null);
    const r = await gatewayClient.bindApprove({ bind_code: p.bind_code, tier: null, channels: null });
    setBusy(false);
    if (!r.ok) {
      setErr(reason(r));
      return;
    }
    onFlash(`${p.display_name} is bound (${p.tier} · ${tierLabel(p.tier)})`);
    onChange();
  };
  const pill: CSSProperties = {
    fontSize: 11,
    padding: '2px 8px',
    borderRadius: 999,
    border: '1px solid var(--rule)',
    color: state === 'claimed' ? 'var(--accent)' : 'var(--ink-dim)',
    whiteSpace: 'nowrap',
  };
  return (
    <div className="row" style={{ display: 'grid', gap: 6, padding: '10px 4px', borderTop: '1px solid var(--rule-soft)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span>
          <strong>{p.display_name}</strong> · <span className="muted">{p.tier} · {tierLabel(p.tier)}</span>
          <span className="muted" style={{ fontSize: 12 }}> · channels: {describeGrants(p.channels, docs)}</span>
        </span>
        <span style={pill}>{state === 'claimed' ? '② code received — approve' : scan ? '① invite minted — scan pending' : '① code minted — waiting'}</span>
      </div>
      {state === 'minted' && scan ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', fontSize: 12.5 }}>
          <span className="muted">{p.display_name} scans a connect QR with their own WeChat — their clawbot appears there, bound as {p.tier} · {tierLabel(p.tier)}:</span>
          <button className="btn primary sm" onClick={() => setScanOpen(true)}>▣ show {p.display_name}'s connect QR</button>
          <RejectButton bindCode={p.bind_code} name={p.display_name} onChange={onChange} onFlash={onFlash} />
          {scanOpen && (
            <ConnectModal
              contactId={p.contact_id}
              who={p.display_name}
              onClose={() => setScanOpen(false)}
              onConnected={(botId) => {
                setScanOpen(false);
                onFlash(`${p.display_name} connected · ${botId} — bound as ${p.tier}`);
                onChange();
              }}
            />
          )}
        </div>
      ) : state === 'minted' ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', fontSize: 12.5 }}>
          <span className="muted">{p.display_name} texts this to the bot from their own WeChat:</span>
          <CodeLine code={p.bind_code} onCopied={() => onFlash(`Copied — send it to ${p.display_name}`)} />
          <RejectButton bindCode={p.bind_code} name={p.display_name} onChange={onChange} onFlash={onFlash} />
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 6, fontSize: 12.5 }}>
          <div>
            Someone sent {p.display_name}'s code to the bot. Approving binds <strong>that</strong> WeChat to <strong>{p.display_name}</strong> as {p.tier} · {tierLabel(p.tier)}, on {describeGrants(p.channels, docs)}.
          </div>
          <div className="muted" style={{ fontSize: 12 }}>The sender's WeChat identity is never shown (D13) — if you did not hand this code to {p.display_name}, reject it.</div>
          {err && <div className="muted" style={{ color: 'var(--danger)', fontSize: 12 }}>⚠ {err}</div>}
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn primary sm" disabled={busy} onClick={() => void approve()}>{busy ? 'approving…' : `✓ approve — bind ${p.display_name}`}</button>
            <RejectButton bindCode={p.bind_code} name={p.display_name} onChange={onChange} onFlash={onFlash} />
          </div>
        </div>
      )}
    </div>
  );
}


// ── connect ───────────────────────────────────────────────────────────────────

function ConnectPanel({
  status,
  statusErr,
  notConfigured,
  selfContactId = SELF_CONTACT_ID,
  onChange,
  onFlash,
}: {
  status: GatewayStatusView | null;
  statusErr: string | null;
  notConfigured: boolean;
  selfContactId?: string;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const online = status?.online ?? false;
  const transport = status?.transport ?? '—';
  const scan = scanTransport(status?.transport);
  return (
    <Panel
      title={scan ? 'connection · your clawbot' : 'connection · the bot'}
      right={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
          <Dot status={online ? 'ok' : notConfigured ? 'muted' : 'warn'} pulse={online} />
          {online ? `online · ${status?.bot_id ?? 'bot'}` : notConfigured ? 'not set up' : 'offline'}
        </span>
      }
    >
      {statusErr ? (
        notConfigured ? (
          <div style={{ lineHeight: 1.7, fontSize: 12.5 }}>
            <div style={{ marginBottom: 6 }}>No WeChat contact gate reachable for this daemon yet — expected until it points at a deployed contact gate.</div>
            <div className="muted">The contact gate URL is derived from your broker automatically; you only need the admin bearer — set <code>AGENTKEYS_WEIXIN_ADMIN_TOKEN</code> (retrieve it from the broker&apos;s <code>weixin-secrets.env</code>, #418) in the daemon env, then reload.</div>
            <div className="muted" style={{ marginTop: 6, opacity: 0.7 }}>{statusErr}</div>
          </div>
        ) : (
          <div className="muted" style={{ lineHeight: 1.6 }}>⚠ {statusErr}</div>
        )
      ) : (
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center' }}>
          <dl className="kvs" style={{ margin: 0 }}>
            <dt>transport</dt><dd>{transport}</dd>
            <dt>bound contacts</dt><dd>{status?.bound_contacts ?? 0}</dd>
            <dt>open invites</dt><dd>{status?.open_invites ?? 0}</dd>
            <dt>awaiting approve</dt><dd>{status?.pending_binds ?? 0}</dd>
            <dt>bots online</dt><dd>{status?.bots_online ?? 0}</dd>
          </dl>
          {(status?.bots_unpersisted ?? 0) > 0 && (
            <div style={{ color: 'var(--danger)', fontSize: 12.5, maxWidth: 420 }}>
              ⚠ {status?.bots_unpersisted} bot token{status?.bots_unpersisted === 1 ? '' : 's'} not saved on the gate — they drop at the next gate restart. The gate cannot write its tokens file; set AGENTKEYS_WEIXIN_ILINK_TOKENS_FILE to a path in its writable state dir and converge.
            </div>
          )}
          <div>
            <ConnectButton transport={transport} online={online} scan={scan} selfContactId={selfContactId} onChange={onChange} onFlash={onFlash} />
          </div>
        </div>
      )}
    </Panel>
  );
}

function ConnectButton({
  transport,
  online,
  scan,
  selfContactId = SELF_CONTACT_ID,
  onChange,
  onFlash,
}: {
  transport: string;
  online: boolean;
  scan: boolean;
  selfContactId?: string;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  if (transport === 'oa') {
    return <span className="muted" style={{ fontSize: 12 }}>公众号 transport — configured via the WeChat console, no QR connect.</span>;
  }
  const disconnect = async () => {
    if (!window.confirm('Disconnect the WeChat bot? It goes offline and you’ll scan a fresh QR to reconnect.')) return;
    setDisconnecting(true);
    const r = await gatewayClient.disconnect();
    setDisconnecting(false);
    onChange();
    onFlash(r.ok ? 'Bot disconnected — connect again for a clean QR' : `Disconnect failed: ${reason(r)}`);
  };
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
      {(!scan || online) && (
        <button className="btn primary" onClick={() => setOpen(true)}>
          {online ? (scan ? '↻ reconnect my bot' : '↻ reconnect') : '⊕ connect bot'}
        </button>
      )}
      {online && (
        <button className="btn" disabled={disconnecting} onClick={() => void disconnect()}>
          {disconnecting ? '…' : '⏻ disconnect'}
        </button>
      )}
      {open && (
        <ConnectModal
          contactId={scan ? selfContactId : undefined}
          onClose={() => setOpen(false)}
          onConnected={(botId) => {
            setOpen(false);
            onChange();
            onFlash(`Bot connected · ${botId}`);
          }}
        />
      )}
    </div>
  );
}

type LoginPhase =
  | { kind: 'starting' }
  | { kind: 'scan'; loginId: string; qr: string }
  | { kind: 'verify'; loginId: string; qr: string; detail: string }
  | { kind: 'done'; message: string }
  | { kind: 'error'; message: string };

function ConnectModal({
  onClose,
  onConnected,
  contactId,
  who,
}: {
  onClose: () => void;
  onConnected: (botId: string) => void;
  /** One bot per member: the invite this QR is minted for (the scan binds it). */
  contactId?: string;
  /** The member's display name — a QR for someone else's phone. */
  who?: string;
}) {
  const [phase, setPhase] = useState<LoginPhase>({ kind: 'starting' });
  const [code, setCode] = useState('');
  // A per-run token, NOT a shared bool. React StrictMode (dev) double-mounts the
  // effect (mount → cleanup → mount), and rapid re-clicks re-run start(); a
  // shared `cancelled` ref gets reset by the second run, so the FIRST login's
  // poll keeps going against a login_id the server already replaced → 404
  // no_active_login rendered as a spurious "session expired". Each start() bumps
  // runIdRef; a poll acts only while its captured runId is still current.
  const runIdRef = useRef(0);

  // Drive the whole ceremony: start → loop login/status → (verify) → connected.
  const runPoll = useCallback(async (runId: number, loginId: string, qr: string) => {
    let transientStreak = 0;
    for (;;) {
      if (runId !== runIdRef.current) return; // superseded by a newer start()
      const s = await gatewayClient.loginStatus(loginId);
      if (runId !== runIdRef.current) return;
      if (!s.ok) {
        // 5xx/504 or a network blip (status 0) is TRANSIENT: the ~35 s
        // server-held long-poll can be cut short by a proxy read-timeout or a
        // brief daemon/worker restart. Keep polling — only a real 4xx (e.g. 404
        // no_active_login = login truly expired) is terminal. Bound the streak so
        // a persistent proxy problem surfaces a message instead of hanging.
        if (s.status >= 500 || s.status === 0) {
          if (++transientStreak >= 6) {
            setPhase({ kind: 'error', message: `网关反复超时（HTTP ${s.status}）— 请稍后重试或检查 weixin 网关代理超时` });
            return;
          }
          await new Promise((r) => setTimeout(r, 1500));
          continue;
        }
        setPhase({ kind: 'error', message: reason(s) });
        return;
      }
      transientStreak = 0;
      const st = s.value;
      gwlog('login/status', loginId, '→', st.status, st.detail ?? '');
      if (st.status === 'need_verifycode') {
        setPhase({ kind: 'verify', loginId, qr, detail: st.detail ?? '输入手机上显示的数字' });
        return; // wait for the operator to submit the code (submitVerify resumes)
      }
      if (st.status === 'connected') {
        onConnected(st.bot_id ?? 'bot');
        return;
      }
      // `already_bound` = a re-scan of an account already connected to THIS
      // gateway: the existing token is reused (nothing changed) and the phone's
      // authorize page is just leftover — you can close it. This is the common
      // "web says online but my phone still shows the connect page" case; show it
      // as a benign outcome, never the red error the other terminal statuses get.
      if (st.status === 'already_bound') {
        setPhase({ kind: 'done', message: st.detail ?? '该账号已连接，沿用现有 token。手机上的授权页可直接关闭。' });
        return;
      }
      if (isTerminalLoginStatus(st.status)) {
        setPhase({ kind: 'error', message: st.detail ?? `连接结束：${st.status}` });
        return;
      }
      // wait / scaned → keep polling (the status call itself is the ~35 s hold).
    }
  }, [onConnected]);

  const start = useCallback(async () => {
    const runId = ++runIdRef.current; // supersede any in-flight run
    setPhase({ kind: 'starting' });
    const r = await gatewayClient.loginStart(contactId);
    if (runId !== runIdRef.current) return;
    if (!r.ok) {
      setPhase({ kind: 'error', message: reason(r) });
      return;
    }
    setPhase({ kind: 'scan', loginId: r.value.login_id, qr: r.value.qrcode_url });
    void runPoll(runId, r.value.login_id, r.value.qrcode_url);
  }, [runPoll]);

  // Run the ceremony ONCE per modal open. `start` is kept in a ref so this
  // effect is MOUNT-ONLY: ancestor re-renders (a status refresh re-renders
  // ChannelsPage → ConnectPanel → ConnectButton, handing ConnectModal fresh
  // inline callbacks → a new `start` identity) would, under a `[start]` dep,
  // RE-RUN the whole ceremony each time — minting a fresh login/start + QR and
  // spawning COMPETING iLink login sessions on the server. That's what made the
  // phone flash "connected" then revert to the QR page: it authorized one
  // session while others dangled. The setTimeout makes it StrictMode-safe — the
  // dev double-mount's first timer is cleared by its cleanup before it fires, so
  // exactly one login/start goes out.
  const startRef = useRef(start);
  startRef.current = start;
  useEffect(() => {
    const t = setTimeout(() => void startRef.current(), 0);
    return () => {
      clearTimeout(t);
      runIdRef.current++; // invalidate any in-flight run on unmount
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitVerify = async (loginId: string, qr: string) => {
    const v = await gatewayClient.loginVerify(loginId, code.trim());
    setCode('');
    if (!v.ok) {
      setPhase({ kind: 'error', message: reason(v) });
      return;
    }
    setPhase({ kind: 'scan', loginId, qr });
    void runPoll(runIdRef.current, loginId, qr);
  };

  return (
    <Modal title={who ? `${who} — connect their WeChat` : 'Connect your WeChat'} onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center', textAlign: 'center' }}>
        {phase.kind === 'starting' && <div className="muted">Minting a login QR…</div>}

        {(phase.kind === 'scan' || phase.kind === 'verify') && (
          <>
            <div style={{ background: '#fff', padding: 14, borderRadius: 10 }}>
              <QRCodeSVG value={phase.qr} size={220} includeMargin />
            </div>
            <ol style={{ textAlign: 'left', fontSize: 13, lineHeight: 1.7, maxWidth: 340, margin: 0, paddingLeft: 18 }}>
              <li>
                {who ? (
                  <>Have <strong>{who}</strong> scan this with <strong>their own</strong> WeChat (扫一扫). Their clawbot appears as a contact in their WeChat, linked to this household.</>
                ) : (
                  <>Scan with <strong>your own</strong> WeChat (扫一扫). Your clawbot appears as a contact in your WeChat, linked to this household.</>
                )}
              </li>
              <li>On the phone, tap <strong>连接 / 授权 (Connect / Authorize)</strong> — that page IS the confirmation step.</li>
            </ol>
          </>
        )}

        {phase.kind === 'verify' && (
          <div style={{ width: '100%', maxWidth: 340 }}>
            <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>{phase.detail}</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                inputMode="numeric"
                placeholder="手机上显示的数字"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                style={{ ...INPUT_STYLE, flex: 1 }}
              />
              <button className="btn primary" disabled={!code.trim()} onClick={() => void submitVerify(phase.loginId, phase.qr)}>
                submit
              </button>
            </div>
          </div>
        )}

        {phase.kind === 'done' && (
          <>
            <div className="muted" style={{ color: 'var(--ok, #1a7f5a)', lineHeight: 1.6 }}>✓ {phase.message}</div>
            <button className="btn" onClick={onClose}>close</button>
          </>
        )}

        {phase.kind === 'error' && (
          <>
            <div className="muted" style={{ color: 'var(--danger)', lineHeight: 1.6 }}>⚠ {phase.message}</div>
            <button className="btn" onClick={() => void start()}>try again</button>
          </>
        )}
      </div>
    </Modal>
  );
}

// ── invite ──────────────────────────────────────────────────────────────────

// A three-state row chip: not a member · listens (reads) · speaks (posts + reads).
type Row = 'none' | 'listen' | 'speak';
const rowOf = (g: ChannelGrant | undefined): Row => (!g || (!g.speak && !g.read) ? 'none' : g.speak ? 'speak' : 'listen');
const grantOf = (channel_id: string, r: Row): ChannelGrant => ({ channel_id, speak: r === 'speak', read: r !== 'none' });
const nextRow = (r: Row): Row => (r === 'none' ? 'listen' : r === 'listen' ? 'speak' : 'none');
const CHIP = (r: Row): CSSProperties => ({
  padding: '4px 11px',
  borderRadius: 999,
  fontSize: 12,
  cursor: 'pointer',
  border: `1px solid ${r !== 'none' ? 'var(--accent, #1a7f5a)' : 'var(--border, #d8d8cf)'}`,
  background: r === 'speak' ? 'var(--accent, #1a7f5a)' : 'transparent',
  color: r === 'speak' ? '#fff' : r === 'listen' ? 'var(--accent, #1a7f5a)' : 'inherit',
});

/** The channel rows editor: one chip per channel — tap to cycle none → listens →
 *  speaks. Household channels first; each app's operator channel after, marked
 *  (the explicit ones: never pre-filled for anyone but the owner). */
function RowsEditor({ docs, grants, onChange }: { docs: ChannelDoc[]; grants: ChannelGrant[]; onChange: (g: ChannelGrant[]) => void }) {
  const get = (id: string) => rowOf(grants.find((g) => g.channel_id === id));
  const set = (id: string, r: Row) => onChange([...grants.filter((g) => g.channel_id !== id), ...(r === 'none' ? [] : [grantOf(id, r)])]);
  const ordered = grantableChannels(docs);
  if (ordered.length === 0) return <span className="muted" style={{ fontSize: 12 }}>No channel yet — install an app or create one on the channels page.</span>;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
      {ordered.map((d) => {
        const r = get(d.id);
        return (
          <button type="button" key={d.id} onClick={() => set(d.id, nextRow(r))} style={CHIP(r)} title={`${d.purpose || d.id} — tap to change: none → listens → speaks`}>
            {r === 'speak' ? '✓ ' : r === 'listen' ? '◔ ' : ''}{d.name || d.id}{d.operator_of ? ' · operator' : ''}{r === 'listen' ? ' (reads)' : ''}
          </button>
        );
      })}
    </div>
  );
}

function InvitePanel({
  docs,
  online,
  scan,
  onInvited,
  onFlash,
}: {
  docs: ChannelDoc[];
  online: boolean;
  scan: boolean;
  onInvited: () => void;
  onFlash: (m: string) => void;
}) {
  const [displayName, setDisplayName] = useState('');
  const [tier, setTier] = useState<ContactTier>('kid');
  const [grants, setGrants] = useState<ChannelGrant[]>([]);
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState<{ code: string; sendText: string; name: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // A tier change re-seeds the rows with what that tier usually gets.
  const docsKey = docs.map((d) => `${d.id}:${d.updated_at}`).join(',');
  useEffect(() => {
    setGrants(suggestedGrants(tier, docs));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tier, docsKey]);

  const submit = async () => {
    setErr(null);
    setBusy(true);
    const contactId = `${displayName.trim().toLowerCase().replace(/\s+/g, '-')}-${Math.random().toString(36).slice(2, 6)}`;
    const r = await gatewayClient.bindInvite({ contact_id: contactId, display_name: displayName.trim(), tier, channels: grants });
    setBusy(false);
    if (!r.ok) {
      setErr(reason(r));
      return;
    }
    if (scan) onFlash(`Invite for ${displayName.trim()} minted — open their connect QR from the row below when they're ready`);
    else setMinted({ code: r.value.bind_code, sendText: r.value.send_text, name: displayName.trim() });
    setDisplayName('');
    setGrants(suggestedGrants(tier, docs));
    onInvited();
  };

  return (
    <div>
      <div className="perm-section-head"><span className="ttl">mint an invite</span></div>
      <div style={{ display: 'grid', gap: 10, maxWidth: 560 }}>
        <Field label="name">
          <input style={INPUT_STYLE} placeholder="奶奶 / Emma" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </Field>
        <Field label="tier">
          <select style={INPUT_STYLE} value={tier} onChange={(e) => setTier(e.target.value as ContactTier)}>
            {TIERS.map((t) => <option key={t} value={t}>{t} · {tierLabel(t)}</option>)}
          </select>
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{TIER_INFO[tier].blurb}</div>
        </Field>
        <Field label={<>channels <span className="muted">(where they may speak, or only read)</span></>}>
          <RowsEditor docs={docs} grants={grants} onChange={setGrants} />
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
            Pre-filled with what this tier usually gets: the channels whose apps admit it, the family chat read-only otherwise. An app&apos;s operator channel is never pre-filled — switch it on here or on the contact&apos;s row when you mean it. Apps you install later propose their own rows.
          </div>
        </Field>
        {err && <div className="muted" style={{ color: 'var(--danger)' }}>⚠ {err}</div>}
        <div>
          <button className="btn primary" disabled={busy || !displayName.trim() || !online} onClick={() => void submit()}>
            {busy ? 'minting…' : '⊕ mint invite'}
          </button>
          {!online && <span className="muted" style={{ fontSize: 12, marginLeft: 8 }}>{scan ? 'the contact gate is unreachable — fix step 1 first' : 'connect the bot first'}</span>}
        </div>
      </div>

      {minted && (
        <InviteModal
          name={minted.name}
          code={minted.code}
          sendText={minted.sendText}
          onClose={() => setMinted(null)}
          onCopied={() => onFlash('Invite copied — share it with the family member')}
        />
      )}
    </div>
  );
}

function InviteModal({
  name,
  code,
  sendText,
  onClose,
  onCopied,
}: {
  name: string;
  code: string;
  sendText: string;
  onClose: () => void;
  onCopied: () => void;
}) {
  return (
    <Modal title={`Invite for ${name}`} onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center', textAlign: 'center' }}>
        <div style={{ fontSize: 13, lineHeight: 1.7, maxWidth: 360 }}>
          Ask <strong>{name}</strong> to send this 6-digit code to the bot from their own WeChat:
        </div>
        <div style={{ fontFamily: 'var(--mono, monospace)', fontSize: 40, fontWeight: 700, letterSpacing: '0.16em' }}>{code}</div>
        <button
          className="btn"
          onClick={() => {
            void navigator.clipboard?.writeText(sendText);
            onCopied();
          }}
        >
          ⧉ copy “{sendText}”
        </button>
        <div className="muted" style={{ fontSize: 12, lineHeight: 1.6, maxWidth: 360 }}>
          Once they text it, it appears below in <strong>待确认 · awaiting approval</strong> for you to confirm. One-time &amp; expiring.
        </div>
      </div>
    </Modal>
  );
}

// Withdraw an invite (open or claimed) — the code dies immediately; a claimed
// sender gets unknown-sender silence from then on. Low-stakes (re-invite is one
// click), so no confirm dialog.
function RejectButton({
  bindCode,
  name,
  onChange,
  onFlash,
}: {
  bindCode: string;
  name: string;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const remove = async () => {
    setBusy(true);
    const r = await gatewayClient.bindReject(bindCode);
    setBusy(false);
    if (!r.ok) {
      onFlash(`Remove failed — ${reason(r)}`);
      return;
    }
    onFlash(`Invite for ${name} withdrawn`);
    onChange();
  };
  return (
    <button className="btn sm" disabled={busy} title="withdraw this invite" onClick={() => void remove()}>
      {busy ? '…' : '✕ remove'}
    </button>
  );
}

// ── contacts ──────────────────────────────────────────────────────────────────

function ContactsPanel({
  contacts,
  docs,
  onChange,
  onFlash,
}: {
  contacts: ContactSummary[];
  docs: ChannelDoc[];
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  return (
    <Panel title="bound contacts" right={<span className="count">{contacts.length}</span>}>
      {contacts.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No family members yet. Invite one above.</div>
      ) : (
        <table className="tab" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left' }}>name</th>
              <th style={{ textAlign: 'left' }}>tier</th>
              <th style={{ textAlign: 'left' }}>channels</th>
              <th style={{ textAlign: 'left' }}>acknowledged</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {contacts.map((c) => (
              <ContactRow key={c.contact_id} contact={c} docs={docs} onChange={onChange} onFlash={onFlash} />
            ))}
          </tbody>
        </table>
      )}
      <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
        A member&apos;s access is their rows on the household&apos;s channels: <strong>speaks</strong> = may post there (the router picks among these), <strong>reads</strong> = receives what lands there. An app&apos;s operator channel is switched on per member, by you. Contacts have no chat history here (and their WeChat identity is never shown) — D13.
      </div>
    </Panel>
  );
}

// One contact row — read-only until you hit `edit`, then a tier picker + the
// channel rows editor that POSTs the new rows (replacing the member's rows);
// `revoke` unbinds. Both refresh the list on success.
function ContactRow({
  contact,
  docs,
  onChange,
  onFlash,
}: {
  contact: ContactSummary;
  docs: ChannelDoc[];
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [tier, setTier] = useState<ContactTier>(contact.tier);
  const current = (): ChannelGrant[] => contact.channels.map((c) => ({ channel_id: c.channel_id, speak: c.speak, read: c.read }));
  const [grants, setGrants] = useState<ChannelGrant[]>(current);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    const r = await gatewayClient.contactsUpdate({ contact_id: contact.contact_id, tier, channels: grants });
    setBusy(false);
    if (r.ok) {
      setEditing(false);
      onChange();
      onFlash(`Updated ${contact.display_name}`);
    } else {
      onFlash(`Update failed: ${reason(r)}`);
    }
  };

  const resendAck = async () => {
    setBusy(true);
    const r = await gatewayClient.contactsWelcome(contact.contact_id);
    setBusy(false);
    if (!r.ok) {
      onFlash(`Resend failed: ${reason(r)}`);
      return;
    }
    onChange();
    onFlash(
      r.value.sent
        ? `Acknowledgement sent to ${contact.display_name}'s chat`
        : `${contact.display_name} gets the acknowledgement with their next message (their bot cannot speak first)`,
    );
  };

  const revoke = async () => {
    if (!window.confirm(`Unbind ${contact.display_name}? They leave every channel and can no longer reach the household through the bot.`)) return;
    setBusy(true);
    const r = await gatewayClient.contactsRevoke(contact.contact_id);
    setBusy(false);
    if (r.ok) {
      onChange();
      onFlash(`Revoked ${contact.display_name}`);
    } else {
      onFlash(`Revoke failed: ${reason(r)}`);
    }
  };

  if (editing) {
    return (
      <tr>
        <td>{contact.display_name}</td>
        <td>
          <select value={tier} onChange={(e) => setTier(e.target.value as ContactTier)} style={INPUT_STYLE}>
            {TIERS.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </td>
        <td>
          <RowsEditor docs={docs} grants={grants} onChange={setGrants} />
        </td>
        <td />
        <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
          <button className="btn sm" disabled={busy} onClick={() => void save()}>save</button>{' '}
          <button
            className="btn sm"
            disabled={busy}
            onClick={() => {
              setEditing(false);
              setTier(contact.tier);
              setGrants(current());
            }}
          >
            cancel
          </button>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td>{contact.display_name}</td>
      <td>{contact.tier} · <span className="muted">{tierLabel(contact.tier)}</span></td>
      <td className="muted">{describeGrants(contact.channels, docs)}</td>
      <td className="muted" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
        {contact.welcomed ? '✓ told in their chat' : 'with their next message'}{' '}
        <button className="btn sm" disabled={busy} onClick={() => void resendAck()} title="Send the «✅ 绑定成功» acknowledgement again — now if their bot can, else with their next message">↻ resend</button>
      </td>
      <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
        <button className="btn sm" disabled={busy} onClick={() => { setGrants(current()); setEditing(true); }}>edit</button>{' '}
        <button className="btn sm" disabled={busy} onClick={() => void revoke()} style={{ color: 'var(--danger)' }}>revoke</button>
      </td>
    </tr>
  );
}
