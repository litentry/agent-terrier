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

import { PageHead, Panel, Modal, Dot } from './shared';
import { gatewayClient, gatewayNotConfigured, gwlog, isTerminalLoginStatus } from '@/lib/gatewayClient';
import type { GatewayStatusView } from '@/lib/generated/GatewayStatusView';
import type { GatewayPendingBindView } from '@/lib/generated/GatewayPendingBindView';
import type { ContactSummary } from '@/lib/generated/ContactSummary';
import type { ContactTier } from '@/lib/generated/ContactTier';
import type { GatewayMonitorEvent } from '@/lib/generated/GatewayMonitorEvent';
import type { GatewayActivityEvent } from '@/lib/generated/GatewayActivityEvent';

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
  gateway_not_configured: 'No gateway URL — the daemon derives it from its broker; point the daemon at a deployed broker (or set AGENTKEYS_WORKER_WEIXIN_URL to override).',
  'gateway-not-configured': 'No gateway URL — the daemon derives it from its broker; point the daemon at a deployed broker (or set AGENTKEYS_WORKER_WEIXIN_URL to override).',
  'gateway-admin-not-configured':
    'The gateway admin token isn’t set on the daemon — copy AGENTKEYS_WEIXIN_ADMIN_TOKEN from the broker’s weixin-secrets.env into the daemon env.',
  admin_disabled: 'The gateway has no admin token configured — set AGENTKEYS_WEIXIN_ADMIN_TOKEN on the broker.',
  admin_unauthorized: 'The daemon’s admin token doesn’t match the gateway’s — re-copy it from the broker.',
  transport_not_ilink: 'This gateway runs the 公众号 (oa) transport — the QR connect flow is for the personal-bot (ilink) transport.',
  daemon_unreachable: 'The local daemon isn’t reachable — is it running?',
  no_active_login: 'The login session expired — start again.',
  bind_not_claimed: 'No one has sent this code to the bot yet — it can’t be approved until they do.',
  operator_grade_reach_denied: 'Money/usage agents can only be granted to the owner tier.',
};

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
// devices page (`devices.tsx`). This file owns the WeChat gateway + contacts
// surface — its ConnectPanel / monitor / history / activity render inside
// ContactsPage below.)

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
            on-chain. Set <code>AGENTKEYS_WEIXIN_OPERATOR_OMNI</code> on the broker + restart the gateway.
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

// ── Contacts page (data-section="contacts", hue 330) — the family ──────────────
export function ContactsPage({ deeplinkReach }: { deeplinkReach?: string[] }) {
  const { status, statusErr, notConfigured, refreshStatus } = useGatewayStatus(false);
  const { toast, flash } = useToast();
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const [pending, setPending] = useState<GatewayPendingBindView[]>([]);

  const refresh = useCallback(async () => {
    const ok = await refreshStatus();
    // Gateway down / not configured → skip the dependent fetches (they'd only
    // 503 too, spamming the console). The connect card carries the reason.
    if (!ok) {
      setContacts([]);
      setPending([]);
      return;
    }
    const [c, p] = await Promise.all([gatewayClient.contacts(), gatewayClient.bindPending()]);
    if (c.ok) setContacts(c.value.contacts);
    if (p.ok) setPending(p.value.pending);
  }, [refreshStatus]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // While setup is incomplete (no bound contact yet), poll so the guided
  // stepper advances LIVE — the claim lands (step 2 → 3) without a manual
  // refresh. Stops the moment the first contact binds.
  const setupIncomplete = !notConfigured && contacts.length === 0;
  useEffect(() => {
    if (!setupIncomplete) return;
    const id = window.setInterval(() => void refresh(), 4000);
    return () => window.clearInterval(id);
  }, [setupIncomplete, refresh]);

  const online = !!status?.online;
  return (
    <>
      <PageHead
        crumb="household / contacts"
        title="Contacts"
        desc="Connect the household WeChat bot, then invite family members — each a contact with a tier + reach (which agents they may talk to). Nothing binds without your approval, and no one’s WeChat identity is ever shown (D13)."
        actions={<button className="btn sm" onClick={() => void refresh()}>↻ refresh</button>}
      />
      <Toast toast={toast} />
      <SetupStepper
        online={online}
        notConfigured={notConfigured}
        boundCount={contacts.length}
        claimedCount={pending.filter((p) => p.claimed).length}
        deeplinkReach={deeplinkReach}
        onChange={() => void refresh()}
        onFlash={flash}
      />
      <ConnectPanel status={status} statusErr={statusErr} notConfigured={notConfigured} onChange={() => void refresh()} onFlash={flash} />
      <InvitePanel deeplinkReach={deeplinkReach} online={online} onInvited={() => void refresh()} onFlash={flash} />
      <PendingPanel pending={pending} onChange={() => void refresh()} onFlash={flash} />
      <ContactsPanel contacts={contacts} onChange={() => void refresh()} onFlash={flash} />
      <ActivityPanel auditOff={online && status?.audit_on_chain === false} />
      <MonitorPanel online={online} />
      <HistoryPanel />
    </>
  );
}

// ── guided setup (#419) ─────────────────────────────────────────────────────────
// The two WeChat ceremonies chained into ONE operator flow. They can't literally
// be one step — the QR logs the BOT in (the spare account, iLink requires the
// scan) while the 6-digit code binds a MEMBER (their daily account), and the bot
// can't message first (passive-reply-only) — but the stepper walks you straight
// through: ① connect → ② invite yourself (one click, owner + all agents) →
// ③ approve the claim. Hides once the first contact is bound.
function SetupStepper({
  online,
  notConfigured,
  boundCount,
  claimedCount,
  deeplinkReach,
  onChange,
  onFlash,
}: {
  online: boolean;
  notConfigured: boolean;
  boundCount: number;
  claimedCount: number;
  deeplinkReach?: string[];
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [connectOpen, setConnectOpen] = useState(false);
  const [minted, setMinted] = useState<{ code: string; sendText: string; name: string } | null>(null);
  const [busy, setBusy] = useState(false);
  if (notConfigured || boundCount > 0) return null;

  const step = !online ? 1 : claimedCount > 0 ? 3 : 2;

  const inviteSelf = async () => {
    setBusy(true);
    // Fixed contact_id: re-clicking replaces the open self-invite instead of
    // littering the registry with stale codes.
    const r = await gatewayClient.bindInvite({
      contact_id: 'self-owner',
      display_name: '我自己',
      tier: 'owner',
      reach: deeplinkReach ?? [],
    });
    setBusy(false);
    if (!r.ok) {
      onFlash(`Self-invite failed — ${reason(r)}`);
      return;
    }
    setMinted({ code: r.value.bind_code, sendText: r.value.send_text, name: '我自己' });
    onChange();
  };

  const stepStyle = (n: number): CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    opacity: n === step ? 1 : 0.55,
    fontWeight: n === step ? 600 : 400,
  });
  const mark = (n: number) => (n < step ? '✓' : `${n}`);

  return (
    <Panel title="快速设置 · guided setup">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
        <div style={stepStyle(1)}>
          <span className={step > 1 ? '' : 'muted'}>{mark(1)}</span>
          <span>Connect the bot — scan the QR with the <strong>spare</strong> WeChat account (it becomes the bot).</span>
          {step === 1 && (
            <button className="btn primary sm" onClick={() => setConnectOpen(true)}>⊕ connect</button>
          )}
        </div>
        <div style={stepStyle(2)}>
          <span className={step > 2 ? '' : 'muted'}>{mark(2)}</span>
          <span>Bind yourself — text the 6-digit code to the bot from your <strong>daily</strong> WeChat.</span>
          {step === 2 && (
            <button className="btn primary sm" disabled={busy} onClick={() => void inviteSelf()}>
              {busy ? 'minting…' : '⊕ invite myself (owner · all agents)'}
            </button>
          )}
        </div>
        <div style={stepStyle(3)}>
          <span className="muted">{mark(3)}</span>
          <span>Approve the claim below (待确认) — then you’re bound and every message shows your name.</span>
          {step === 3 && <span style={{ color: 'var(--accent)' }}>↓ approve below</span>}
        </div>
      </div>
      {connectOpen && (
        <ConnectModal
          onClose={() => setConnectOpen(false)}
          onConnected={(botId) => {
            setConnectOpen(false);
            onChange();
            onFlash(`Bot connected · ${botId} — now bind yourself (step 2)`);
          }}
        />
      )}
      {minted && (
        <InviteModal
          name={minted.name}
          code={minted.code}
          sendText={minted.sendText}
          onClose={() => setMinted(null)}
          onCopied={() => onFlash('Code copied — text it to the bot from your daily WeChat')}
        />
      )}
    </Panel>
  );
}

// ── connect ───────────────────────────────────────────────────────────────────

function ConnectPanel({
  status,
  statusErr,
  notConfigured,
  onChange,
  onFlash,
}: {
  status: GatewayStatusView | null;
  statusErr: string | null;
  notConfigured: boolean;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const online = status?.online ?? false;
  const transport = status?.transport ?? '—';
  return (
    <Panel
      title="connection"
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
            <div style={{ marginBottom: 6 }}>No WeChat gateway reachable for this daemon yet — expected until it points at a deployed gateway.</div>
            <div className="muted">The gateway URL is derived from your broker automatically; you only need the admin bearer — set <code>AGENTKEYS_WEIXIN_ADMIN_TOKEN</code> (retrieve it from the broker&apos;s <code>weixin-secrets.env</code>, #418) in the daemon env, then reload.</div>
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
          </dl>
          <div>
            <ConnectButton transport={transport} online={online} onChange={onChange} onFlash={onFlash} />
          </div>
        </div>
      )}
    </Panel>
  );
}

function ConnectButton({
  transport,
  online,
  onChange,
  onFlash,
}: {
  transport: string;
  online: boolean;
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
      <button className="btn primary" onClick={() => setOpen(true)}>
        {online ? '↻ reconnect' : '⊕ connect bot'}
      </button>
      {online && (
        <button className="btn" disabled={disconnecting} onClick={() => void disconnect()}>
          {disconnecting ? '…' : '⏻ disconnect'}
        </button>
      )}
      {open && (
        <ConnectModal
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

function ConnectModal({ onClose, onConnected }: { onClose: () => void; onConnected: (botId: string) => void }) {
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
    const r = await gatewayClient.loginStart();
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
    <Modal title="Connect the WeChat bot" onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center', textAlign: 'center' }}>
        {phase.kind === 'starting' && <div className="muted">Minting a login QR…</div>}

        {(phase.kind === 'scan' || phase.kind === 'verify') && (
          <>
            <div style={{ background: '#fff', padding: 14, borderRadius: 10 }}>
              <QRCodeSVG value={phase.qr} size={220} includeMargin />
            </div>
            <ol style={{ textAlign: 'left', fontSize: 13, lineHeight: 1.7, maxWidth: 340, margin: 0, paddingLeft: 18 }}>
              <li>Scan with the <strong>spare</strong> WeChat account (never a family member’s daily account — that account becomes the bot).</li>
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

// A toggle chip (reach selector). Selected = filled accent; unselected = outline.
const CHIP = (on: boolean): CSSProperties => ({
  padding: '4px 11px',
  borderRadius: 999,
  fontSize: 12,
  cursor: 'pointer',
  border: `1px solid ${on ? 'var(--accent, #1a7f5a)' : 'var(--border, #d8d8cf)'}`,
  background: on ? 'var(--accent, #1a7f5a)' : 'transparent',
  color: on ? '#fff' : 'inherit',
});

function InvitePanel({
  deeplinkReach,
  online,
  onInvited,
  onFlash,
}: {
  deeplinkReach?: string[];
  online: boolean;
  onInvited: () => void;
  onFlash: (m: string) => void;
}) {
  const options = deeplinkReach ?? [];
  const [displayName, setDisplayName] = useState('');
  const [tier, setTier] = useState<ContactTier>('kid');
  const [reach, setReach] = useState<Set<string>>(new Set());
  const [reachText, setReachText] = useState('');
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState<{ code: string; sendText: string; name: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const allSelected = options.length > 0 && options.every((a) => reach.has(a));
  const toggle = (a: string) =>
    setReach((prev) => {
      const n = new Set(prev);
      if (n.has(a)) n.delete(a);
      else n.add(a);
      return n;
    });
  const toggleAll = () => setReach(allSelected ? new Set() : new Set(options));

  const submit = async () => {
    setErr(null);
    setBusy(true);
    const reachList =
      options.length > 0
        ? Array.from(reach)
        : reachText.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    const contactId = `${displayName.trim().toLowerCase().replace(/\s+/g, '-')}-${Math.random().toString(36).slice(2, 6)}`;
    const r = await gatewayClient.bindInvite({ contact_id: contactId, display_name: displayName.trim(), tier, reach: reachList });
    setBusy(false);
    if (!r.ok) {
      setErr(reason(r));
      return;
    }
    setMinted({ code: r.value.bind_code, sendText: r.value.send_text, name: displayName.trim() });
    setDisplayName('');
    setReach(new Set());
    setReachText('');
    onInvited();
  };

  return (
    <Panel title="invite a family member">
      <div style={{ display: 'grid', gap: 10, maxWidth: 460 }}>
        <Field label="name">
          <input style={INPUT_STYLE} placeholder="奶奶 / Emma" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </Field>
        <Field label="tier">
          <select style={INPUT_STYLE} value={tier} onChange={(e) => setTier(e.target.value as ContactTier)}>
            {TIERS.map((t) => <option key={t} value={t}>{t} · {tierLabel(t)}</option>)}
          </select>
        </Field>
        <Field label={<>reach <span className="muted">(which agents they may talk to)</span></>}>
          {options.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              <button type="button" onClick={toggleAll} style={CHIP(allSelected)}>{allSelected ? '✓ all' : 'all'}</button>
              {options.map((a) => (
                <button type="button" key={a} onClick={() => toggle(a)} style={CHIP(reach.has(a))}>
                  {reach.has(a) ? '✓ ' : ''}{a}
                </button>
              ))}
            </div>
          ) : (
            <input style={INPUT_STYLE} placeholder="chef, storyteller" value={reachText} onChange={(e) => setReachText(e.target.value)} />
          )}
        </Field>
        {err && <div className="muted" style={{ color: 'var(--danger)' }}>⚠ {err}</div>}
        <div>
          <button className="btn primary" disabled={busy || !displayName.trim() || !online} onClick={() => void submit()}>
            {busy ? 'minting…' : '⊕ mint invite'}
          </button>
          {!online && <span className="muted" style={{ fontSize: 12, marginLeft: 8 }}>connect the bot first</span>}
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
    </Panel>
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

// ── pending (approve) ─────────────────────────────────────────────────────────

function PendingPanel({
  pending,
  onChange,
  onFlash,
}: {
  pending: GatewayPendingBindView[];
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const claimed = pending.filter((p) => p.claimed);
  const open = pending.filter((p) => !p.claimed);
  return (
    <Panel
      title="待确认 · awaiting your approval"
      right={claimed.length > 0 ? <span className="count" style={{ color: 'var(--accent)' }}>{claimed.length}●</span> : undefined}
    >
      {pending.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No open invites. Mint one above; when the family member sends the code to the bot, it lands here for your confirm.</div>
      ) : (
        <div style={{ display: 'grid', gap: 8 }}>
          {claimed.map((p) => <PendingRow key={p.bind_code} p={p} onChange={onChange} onFlash={onFlash} />)}
          {open.map((p) => (
            <div key={p.bind_code} className="row" style={{ opacity: 0.6, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, padding: '8px 4px' }}>
              <span>{p.display_name} · <span className="muted">{p.tier}</span></span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="muted" style={{ fontSize: 12 }}>waiting for {p.display_name} to send <code>{`绑定 ${p.bind_code}`}</code></span>
                <RejectButton bindCode={p.bind_code} name={p.display_name} onChange={onChange} onFlash={onFlash} />
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function PendingRow({ p, onChange, onFlash }: { p: GatewayPendingBindView; onChange: () => void; onFlash: (m: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const approve = async () => {
    setBusy(true);
    setErr(null);
    const r = await gatewayClient.bindApprove({ bind_code: p.bind_code, tier: null, reach: null });
    setBusy(false);
    if (!r.ok) {
      setErr(reason(r));
      return;
    }
    onFlash(`${p.display_name} is now bound (${p.tier})`);
    onChange();
  };
  return (
    <div className="row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, padding: '8px 4px', borderTop: '1px solid var(--line, #2a2a2a)' }}>
      <div>
        <div><strong>{p.display_name}</strong> · <span className="muted">{p.tier} · {tierLabel(p.tier)}</span></div>
        <div className="muted" style={{ fontSize: 12 }}>reach: {p.reach.length ? p.reach.join(', ') : '—'}</div>
        {err && <div className="muted" style={{ color: 'var(--danger)', fontSize: 12 }}>⚠ {err}</div>}
      </div>
      <span style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
        <RejectButton bindCode={p.bind_code} name={p.display_name} onChange={onChange} onFlash={onFlash} />
        <button className="btn primary sm" disabled={busy} onClick={() => void approve()}>{busy ? 'approving…' : '✓ approve'}</button>
      </span>
    </div>
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
  onChange,
  onFlash,
}: {
  contacts: ContactSummary[];
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  return (
    <Panel title="family" right={<span className="count">{contacts.length}</span>}>
      {contacts.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No family members yet. Invite one above.</div>
      ) : (
        <table className="tab" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left' }}>name</th>
              <th style={{ textAlign: 'left' }}>tier</th>
              <th style={{ textAlign: 'left' }}>reach</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {contacts.map((c) => (
              <ContactRow key={c.contact_id} contact={c} onChange={onChange} onFlash={onFlash} />
            ))}
          </tbody>
        </table>
      )}
      <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
        Contacts have no chat history here (and their WeChat identity is never shown) — D13: you have full visibility in the audit feed, they have none in-chat.
      </div>
    </Panel>
  );
}

// One contact row — read-only until you hit `edit`, then a tier picker + reach
// editor (comma/space separated) that POSTs the new routing policy; `revoke`
// unbinds. Both refresh the list on success.
function ContactRow({
  contact,
  onChange,
  onFlash,
}: {
  contact: ContactSummary;
  onChange: () => void;
  onFlash: (m: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [tier, setTier] = useState<ContactTier>(contact.tier);
  const [reachText, setReachText] = useState(contact.reach.join(', '));
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    const reach = reachText.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    const r = await gatewayClient.contactsUpdate({ contact_id: contact.contact_id, tier, reach });
    setBusy(false);
    if (r.ok) {
      setEditing(false);
      onChange();
      onFlash(`Updated ${contact.display_name}`);
    } else {
      onFlash(`Update failed: ${reason(r)}`);
    }
  };

  const revoke = async () => {
    if (!window.confirm(`Unbind ${contact.display_name}? They can no longer reach any agent through the bot.`)) return;
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
          <input
            value={reachText}
            onChange={(e) => setReachText(e.target.value)}
            placeholder="chef, storyteller"
            style={{ ...INPUT_STYLE, width: '100%' }}
          />
        </td>
        <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
          <button className="btn sm" disabled={busy} onClick={() => void save()}>save</button>{' '}
          <button
            className="btn sm"
            disabled={busy}
            onClick={() => {
              setEditing(false);
              setTier(contact.tier);
              setReachText(contact.reach.join(', '));
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
      <td className="muted">{contact.reach.length ? contact.reach.join(', ') : '—'}</td>
      <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
        <button className="btn sm" disabled={busy} onClick={() => setEditing(true)}>edit</button>{' '}
        <button className="btn sm" disabled={busy} onClick={() => void revoke()} style={{ color: 'var(--danger)' }}>revoke</button>
      </td>
    </tr>
  );
}
