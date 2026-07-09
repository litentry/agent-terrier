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
import { gatewayClient, gatewayNotConfigured, isTerminalLoginStatus } from '@/lib/gatewayClient';
import type { GatewayStatusView } from '@/lib/generated/GatewayStatusView';
import type { GatewayPendingBindView } from '@/lib/generated/GatewayPendingBindView';
import type { ContactSummary } from '@/lib/generated/ContactSummary';
import type { ContactTier } from '@/lib/generated/ContactTier';

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

// ── Channels page (data-section="channels", hue 200) — the conduits ─────────────
export function ChannelsPage() {
  const { status, statusErr, notConfigured, refreshStatus } = useGatewayStatus();
  const { toast, flash } = useToast();
  return (
    <>
      <PageHead
        crumb="household / channels"
        title="Channels"
        desc="The conduits your agents talk through. The WeChat gateway is one household bot — connect it once with a spare account. (Devices — display, camera, mic — are channel endpoints you pair under actors.)"
        actions={<button className="btn sm" onClick={() => void refreshStatus()}>↻ refresh</button>}
      />
      <Toast toast={toast} />
      <ConnectPanel status={status} statusErr={statusErr} notConfigured={notConfigured} onChange={() => void refreshStatus()} onFlash={flash} />
    </>
  );
}

// ── Contacts page (data-section="contacts", hue 330) — the family ──────────────
export function ContactsPage({ deeplinkReach }: { deeplinkReach?: string[] }) {
  const { status, notConfigured, refreshStatus } = useGatewayStatus(false);
  const { toast, flash } = useToast();
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const [pending, setPending] = useState<GatewayPendingBindView[]>([]);

  const refresh = useCallback(async () => {
    const ok = await refreshStatus();
    // Gateway down / not configured → skip the dependent fetches (they'd only
    // 503 too, spamming the console). The status card carries the reason.
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

  return (
    <>
      <PageHead
        crumb="household / contacts"
        title="Contacts"
        desc="Every family member is a contact with a tier + reach (which agents they may talk to). Invite them to the WeChat bot; nothing binds without your approval, and no one’s WeChat identity is ever shown (D13)."
        actions={<button className="btn sm" onClick={() => void refresh()}>↻ refresh</button>}
      />
      <Toast toast={toast} />
      {notConfigured ? (
        <div className="banner" style={{ marginBottom: 14 }}>
          <span className="lbl">i</span>
          <span>No WeChat gateway is set up for this daemon yet — see <strong>Channels</strong> to connect one. Family binding needs a live gateway.</span>
        </div>
      ) : status && !status.online ? (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">⚠</span>
          <span>The WeChat bot isn’t connected yet — connect it under <strong>Channels</strong> before family members can reach agents.</span>
        </div>
      ) : null}
      <InvitePanel deeplinkReach={deeplinkReach} onInvited={() => void refresh()} onFlash={flash} />
      <PendingPanel pending={pending} onChange={() => void refresh()} onFlash={flash} />
      <ContactsPanel contacts={contacts} />
    </>
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
  if (transport === 'oa') {
    return <span className="muted" style={{ fontSize: 12 }}>公众号 transport — configured via the WeChat console, no QR connect.</span>;
  }
  return (
    <>
      <button className="btn primary" onClick={() => setOpen(true)}>
        {online ? '↻ reconnect' : '⊕ connect bot'}
      </button>
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
    </>
  );
}

type LoginPhase =
  | { kind: 'starting' }
  | { kind: 'scan'; loginId: string; qr: string }
  | { kind: 'verify'; loginId: string; qr: string; detail: string }
  | { kind: 'error'; message: string };

function ConnectModal({ onClose, onConnected }: { onClose: () => void; onConnected: (botId: string) => void }) {
  const [phase, setPhase] = useState<LoginPhase>({ kind: 'starting' });
  const [code, setCode] = useState('');
  const cancelled = useRef(false);

  // Drive the whole ceremony: start → loop login/status → (verify) → connected.
  const runPoll = useCallback(async (loginId: string, qr: string) => {
    for (;;) {
      if (cancelled.current) return;
      const s = await gatewayClient.loginStatus(loginId);
      if (cancelled.current) return;
      if (!s.ok) {
        setPhase({ kind: 'error', message: reason(s) });
        return;
      }
      const st = s.value;
      if (st.status === 'need_verifycode') {
        setPhase({ kind: 'verify', loginId, qr, detail: st.detail ?? '输入手机上显示的数字' });
        return; // wait for the operator to submit the code (submitVerify resumes)
      }
      if (st.status === 'connected') {
        onConnected(st.bot_id ?? 'bot');
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
    setPhase({ kind: 'starting' });
    const r = await gatewayClient.loginStart();
    if (cancelled.current) return;
    if (!r.ok) {
      setPhase({ kind: 'error', message: reason(r) });
      return;
    }
    setPhase({ kind: 'scan', loginId: r.value.login_id, qr: r.value.qrcode_url });
    void runPoll(r.value.login_id, r.value.qrcode_url);
  }, [runPoll]);

  useEffect(() => {
    cancelled.current = false;
    void start();
    return () => {
      cancelled.current = true;
    };
  }, [start]);

  const submitVerify = async (loginId: string, qr: string) => {
    const v = await gatewayClient.loginVerify(loginId, code.trim());
    setCode('');
    if (!v.ok) {
      setPhase({ kind: 'error', message: reason(v) });
      return;
    }
    setPhase({ kind: 'scan', loginId, qr });
    void runPoll(loginId, qr);
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

function InvitePanel({
  deeplinkReach,
  onInvited,
  onFlash,
}: {
  deeplinkReach?: string[];
  onInvited: () => void;
  onFlash: (m: string) => void;
}) {
  const [displayName, setDisplayName] = useState('');
  const [tier, setTier] = useState<ContactTier>('kid');
  const [reachText, setReachText] = useState('');
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState<{ code: string; sendText: string; name: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setErr(null);
    setBusy(true);
    const reach = reachText.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    const contactId = `${displayName.trim().toLowerCase().replace(/\s+/g, '-')}-${Math.random().toString(36).slice(2, 6)}`;
    const r = await gatewayClient.bindInvite({ contact_id: contactId, display_name: displayName.trim(), tier, reach });
    setBusy(false);
    if (!r.ok) {
      setErr(reason(r));
      return;
    }
    setMinted({ code: r.value.bind_code, sendText: r.value.send_text, name: displayName.trim() });
    setDisplayName('');
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
        <Field label={<>reach <span className="muted">(agent aliases, comma-separated)</span></>}>
          <input style={INPUT_STYLE} placeholder="chef, storyteller" value={reachText} onChange={(e) => setReachText(e.target.value)} list="gw-reach" />
          {deeplinkReach && deeplinkReach.length > 0 && (
            <datalist id="gw-reach">{deeplinkReach.map((a) => <option key={a} value={a} />)}</datalist>
          )}
        </Field>
        {err && <div className="muted" style={{ color: 'var(--danger)' }}>⚠ {err}</div>}
        <div>
          <button className="btn primary" disabled={busy || !displayName.trim()} onClick={() => void submit()}>
            {busy ? 'minting…' : '⊕ mint invite'}
          </button>
        </div>
      </div>

      {minted && (
        <InviteModal
          name={minted.name}
          code={minted.code}
          sendText={minted.sendText}
          onClose={() => setMinted(null)}
          onCopied={() => onFlash('Invite text copied — share it with the family member')}
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
        <div style={{ background: '#fff', padding: 14, borderRadius: 10 }}>
          <QRCodeSVG value={sendText} size={200} includeMargin />
        </div>
        <div style={{ fontSize: 13, lineHeight: 1.7, maxWidth: 340 }}>
          Ask <strong>{name}</strong> to send this to the bot from their own WeChat (scan the QR, or copy the text). One-time code:
          <div style={{ fontFamily: 'var(--mono, monospace)', fontSize: 18, letterSpacing: '0.06em', margin: '8px 0' }}>{sendText}</div>
          Once they send it, it appears below in <strong>待确认</strong> for your approval.
        </div>
        <button
          className="btn"
          onClick={() => {
            void navigator.clipboard?.writeText(sendText);
            onCopied();
          }}
        >
          ⧉ copy text
        </button>
        <div className="muted" style={{ fontSize: 11 }}>code: {code}</div>
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
            <div key={p.bind_code} className="row" style={{ opacity: 0.6, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 4px' }}>
              <span>{p.display_name} · <span className="muted">{p.tier}</span></span>
              <span className="muted" style={{ fontSize: 12 }}>waiting for {p.display_name} to send <code>{`绑定 ${p.bind_code}`}</code></span>
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
      <button className="btn primary sm" disabled={busy} onClick={() => void approve()}>{busy ? 'approving…' : '✓ approve'}</button>
    </div>
  );
}

// ── contacts ──────────────────────────────────────────────────────────────────

function ContactsPanel({ contacts }: { contacts: ContactSummary[] }) {
  return (
    <Panel title="family" right={<span className="count">{contacts.length}</span>}>
      {contacts.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No family members yet. Invite one above.</div>
      ) : (
        <table className="tab" style={{ width: '100%' }}>
          <thead>
            <tr><th style={{ textAlign: 'left' }}>name</th><th style={{ textAlign: 'left' }}>tier</th><th style={{ textAlign: 'left' }}>reach</th></tr>
          </thead>
          <tbody>
            {contacts.map((c) => (
              <tr key={c.contact_id}>
                <td>{c.display_name}</td>
                <td>{c.tier} · <span className="muted">{tierLabel(c.tier)}</span></td>
                <td className="muted">{c.reach.length ? c.reach.join(', ') : '—'}</td>
              </tr>
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
