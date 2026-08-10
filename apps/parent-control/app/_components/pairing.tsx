'use client';

import { useCallback, useEffect, useState } from 'react';
import { useClient } from '@/lib/ClientProvider';
import type { ApiImageStatus } from '@/lib/generated/ApiImageStatus';
import { Dot, PageHead } from './shared';
import { PermissionView } from './permissions';
import type { Actor, PairingRequest } from './types';

// #249 — the accept card's scope picker rows: every grantable service the
// operator can select before Touch ID. Defaults = the REQUESTED tokens; a bare
// ns-less `memory` request preselects every available namespace (the agent asked
// for the memory class — the operator reviews + adjusts). Available-but-not-
// requested namespaces render unchecked so the operator can widen deliberately.
function scopeOptions(
  req: PairingRequest,
  namespaces: string[],
): { svc: string; reason: string; preselected: boolean }[] {
  const opts: { svc: string; reason: string; preselected: boolean }[] = [];
  const seen = new Set<string>();
  const push = (svc: string, reason: string, preselected: boolean) => {
    if (seen.has(svc)) return;
    seen.add(svc);
    opts.push({ svc, reason, preselected });
  };
  for (const p of req.requested) {
    if (p.ns.length > 0) {
      p.ns.forEach((ns) => push(`${p.cap}:${ns}`, p.reason, true));
    } else if (p.cap === 'memory') {
      namespaces.forEach((ns) => push(`memory:${ns}`, `${p.reason} (memory class — pick namespaces)`, true));
    }
    // A bare NON-memory token can't compile to an on-chain service — surfaced
    // separately in the card, never silently dropped into a grant.
  }
  namespaces.forEach((ns) => push(`memory:${ns}`, 'available namespace — not requested', false));
  return opts;
}

// #224 — live countdown to a pairing request's expiry (`expiresAt`, the SAME unix
// second the agent's `--request-pairing` prints). Ticks once a second. A request
// whose window has elapsed reads "⚠ expired" in the warn color — the visible tell
// that a card is a STALE / duplicate request to refuse rather than approve (the
// two-duplicate-cards incident this issue fixes). `expiresAt` of 0 means the broker
// row predates the field → "expiry unknown" rather than a bogus countdown.
// #577 follow-up — render the sandbox's veFaaS lease deadline compactly:
// relative when parseable ("expires in 3h"), verbatim otherwise, empty when
// the backend has no expiry (ECS).
function sandboxExpiryLabel(expireAt: string | null | undefined): string {
  if (!expireAt) return '';
  const t = Date.parse(expireAt);
  if (Number.isNaN(t)) return ` · expires ${expireAt}`;
  const mins = Math.round((t - Date.now()) / 60000);
  if (mins <= 0) return ' · expired';
  if (mins < 60) return ` · expires in ${mins}m`;
  return ` · expires in ${Math.round(mins / 60)}h`;
}

export function ExpiryCountdown({ expiresAt }: { expiresAt: number }) {
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);
  if (!expiresAt) return <span className="muted">expiry unknown</span>;
  const remaining = expiresAt - nowSec;
  const expired = remaining <= 0;
  const mag = Math.abs(remaining);
  const human = mag >= 60 ? `${Math.floor(mag / 60)}m ${mag % 60}s` : `${mag}s`;
  return (
    <span
      style={{
        color: expired ? 'var(--warn, #b8860b)' : 'var(--ink-dim)',
        fontWeight: expired ? 600 : 400,
      }}
    >
      {expired ? `⚠ expired ${human} ago` : `expires in ${human}`}
    </span>
  );
}

// household / delegates — pairing + management of SANDBOX DELEGATES (#404 IA:
// the former top-level "pairing" page; devices pair on the devices page).
export function DelegatesPage({
  requests,
  actors,
  namespaces,
  onAccept,
  onDecline,
  onRefresh,
  onClaim,
  claiming,
  justPaired,
  onManage,
  onUnpair,
  onNewAgent,
  onArchive,
  deviceRequestCount = 0,
  onGoDevices,
  showToast,
}: {
  /** Pending SANDBOX-DELEGATE claims only — device claims (isDevice) are routed
   *  to the devices page by App (the #404 decoupling: this page pairs agents
   *  that run in sandboxes; devices are channel endpoints). */
  requests: PairingRequest[];
  actors: Actor[];
  /** Grantable memory namespaces (taxonomy categories, falling back to the canonical four). */
  namespaces: string[];
  onAccept: (req: PairingRequest, services: string[]) => void;
  onDecline: (id: string) => void;
  onRefresh: () => void;
  onClaim: (input: { code: string; label: string }) => void;
  claiming: boolean;
  justPaired: string | null;
  onManage?: (id: string) => void;
  onUnpair?: (a: Actor) => void;
  /** #429 — open the "New agent" spawn modal (one Touch ID, zero rendezvous). */
  onNewAgent?: () => void;
  /** #429 — open the archive dialog (keep-vs-delete, slot returns). */
  onArchive?: (a: Actor) => void;
  /** #408 — device claims currently pending (shown as a redirect banner here). */
  deviceRequestCount?: number;
  onGoDevices?: () => void;
  /** #577 — update-outcome toasts (falls back to console when absent). */
  showToast?: (msg: string, sticky?: boolean) => void;
}) {
  const client = useClient();
  const [view, setView] = useState<'devices' | 'permissions'>('devices');
  const [claimCode, setClaimCode] = useState('');
  const [claimLabel, setClaimLabel] = useState('');
  const pairedAgents = actors.filter((a) => a.role === 'agent');

  // #577 — image staleness + the one-click update. `stale === true` renders
  // the "update available" chip; the update button itself is always offered
  // (it doubles as "respawn now" for an expired/dead sandbox).
  const [imageStatus, setImageStatus] = useState<ApiImageStatus | null>(null);
  const [updating, setUpdating] = useState<Set<string>>(new Set());
  const [forceArmed, setForceArmed] = useState<Set<string>>(new Set());
  const toast = showToast ?? ((msg: string) => console.log('[delegates]', msg));
  const updatableHashes = pairedAgents
    .filter((a) => a.status !== 'bad' && a.deviceKeyHash)
    .map((a) => a.deviceKeyHash as string);
  const updatableKey = updatableHashes.join(',');

  const refreshImageStatus = useCallback(async () => {
    const hashes = updatableKey ? updatableKey.split(',') : [];
    if (hashes.length === 0) {
      setImageStatus(null);
      return;
    }
    const r = await client.agentImageStatus(hashes);
    // An older daemon/broker without #577 just hides the staleness surface —
    // the page stays fully usable.
    setImageStatus(r.ok ? r.data : null);
  }, [client, updatableKey]);

  useEffect(() => {
    refreshImageStatus();
  }, [refreshImageStatus]);

  const imageRowFor = (dkh: string | undefined) => {
    if (!dkh || !imageStatus) return null;
    return (
      imageStatus.delegates.find(
        (d) =>
          d.device_key_hash.toLowerCase().replace(/^0x/, '') ===
          dkh.toLowerCase().replace(/^0x/, ''),
      ) ?? null
    );
  };
  const staleFor = (dkh: string | undefined): boolean | null =>
    imageRowFor(dkh)?.stale ?? null;

  const updateOne = useCallback(
    async (a: Actor) => {
      const dkh = a.deviceKeyHash;
      if (!dkh || updating.has(dkh)) return;
      setUpdating((prev) => new Set(prev).add(dkh));
      try {
        const r = await client.agentUpdate({ deviceKeyHash: dkh, force: forceArmed.has(dkh) });
        if (r.ok) {
          setForceArmed((prev) => {
            const next = new Set(prev);
            next.delete(dkh);
            return next;
          });
          const d = r.data;
          toast(
            d.sandbox_error
              ? `${a.label}: update FAILED to re-create the runtime — ${d.sandbox_error}`
              : `${a.label} updated${d.sandbox_id ? ` (sandbox ${d.sandbox_id})` : ''} — ${d.session_detail}`,
            !!d.sandbox_error,
          );
        } else {
          const detail = r.status?.detail ?? 'update failed';
          if (detail.includes('jobs_running')) {
            // Arm force for THIS delegate: the next click updates anyway.
            setForceArmed((prev) => new Set(prev).add(dkh));
            toast(
              `${a.label} has background jobs running — updating now would kill them. ` +
                'Click again to update anyway.',
              true,
            );
          } else {
            toast(`${a.label} update failed — ${detail}`, true);
          }
        }
      } finally {
        setUpdating((prev) => {
          const next = new Set(prev);
          next.delete(dkh);
          return next;
        });
        refreshImageStatus();
      }
    },
    [client, forceArmed, refreshImageStatus, toast, updating],
  );

  const staleAgents = pairedAgents.filter((a) => staleFor(a.deviceKeyHash) === true);
  const [updatingAll, setUpdatingAll] = useState(false);
  const updateAllStale = useCallback(async () => {
    setUpdatingAll(true);
    try {
      // Sequential on purpose: creates are serialized broker-side anyway (the
      // ensure lock), and one toast per delegate keeps outcomes attributable.
      for (const a of staleAgents) {
        // eslint-disable-next-line no-await-in-loop
        await updateOne(a);
      }
    } finally {
      setUpdatingAll(false);
    }
  }, [staleAgents, updateOne]);

  const submitClaim = () => {
    if (claimCode.trim() && claimLabel.trim()) {
      onClaim({ code: claimCode.trim(), label: claimLabel.trim() });
      setClaimCode('');
    }
  };

  return (
    <>
      <PageHead
        crumb="household / delegates · agent-initiated (method A) · arch §10.2"
        title="Delegates"
        desc="Pair AGENTS (sandbox delegates) here: an agent shows a one-time pairing code; you claim it (J1_master-gated), review the identity + requested scope, then approve with one Touch ID — registerAgentDevice + the scope grant in one block. Physical AI devices (camera, display, console) are channel endpoints — pair those on the devices page instead."
        actions={
          <>
            {staleAgents.length > 0 && (
              <button
                className="btn primary"
                disabled={updatingAll}
                onClick={updateAllStale}
                title="Kill + re-create each stale delegate's sandbox on the current image — same identity, grants and chat channel; no archive, no Touch ID."
              >
                {updatingAll
                  ? 'updating…'
                  : `⟳ update ${staleAgents.length} stale agent${staleAgents.length > 1 ? 's' : ''}`}
              </button>
            )}
            {onNewAgent && (
              <button className="btn primary" onClick={onNewAgent}>
                ＋ New agent
              </button>
            )}
            <button className="btn" onClick={onRefresh}>↻ check for codes</button>
          </>
        }
      />

      {/* #408 — device claims never render here: a device is a channel endpoint
          (its accept enforces ≥1 channel + never spawns), so its card lives on
          the devices page. Surface a pointer so a scanned device isn't "lost". */}
      {deviceRequestCount > 0 && (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">⚠</span>
          <span>
            {deviceRequestCount} device claim{deviceRequestCount > 1 ? 's are' : ' is'} waiting on the <strong>devices</strong> page (devices attach channels, not memory scopes).
          </span>
          {onGoDevices && (
            <button className="btn sm" style={{ marginLeft: 'auto' }} onClick={onGoDevices}>open devices →</button>
          )}
        </div>
      )}

      {/* #214 §10.2 P.1 — the master claims the agent's one-time pairing code
          (typed here, or scanned from the device's runtime QR). This binds the
          agent under the label + declares its scope; it then drops into the
          rendezvous below awaiting on-chain register + scope approval. */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', padding: '10px 0 18px', borderBottom: '1px solid var(--rule)', marginBottom: 18 }}>
        <span className="pair-k" style={{ marginRight: 4 }}>claim a code</span>
        <input
          placeholder="pairing code (shown on the agent device)"
          value={claimCode}
          onChange={(e) => setClaimCode(e.target.value)}
          style={{ flex: '1 1 240px', padding: '8px 10px', fontSize: 12.5, fontFamily: 'var(--mono)', letterSpacing: '0.05em', border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)' }}
        />
        <input
          placeholder="agent label (e.g. demo-agent)"
          value={claimLabel}
          onChange={(e) => setClaimLabel(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') submitClaim(); }}
          style={{ flex: '1 1 160px', padding: '8px 10px', fontSize: 12.5, border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)' }}
        />
        <button className="btn primary" disabled={claiming || !claimCode.trim() || !claimLabel.trim()} onClick={submitClaim}>
          {claiming ? 'claiming…' : '⊕ claim'}
        </button>
      </div>

      {requests.length > 0 ? (
        requests.map((req) => (
          <PairRequestCard key={req.id} req={req} namespaces={namespaces} onAccept={onAccept} onDecline={onDecline} />
        ))
      ) : (
        <div className="banner" style={{ marginBottom: 22 }}>
          <span className="lbl">idle</span>
          <span>
            No pending pairing codes.{' '}
            {justPaired ? <><strong>{justPaired}</strong> was just paired and now appears below.</> : 'When an agent shows a pairing code, claim it here — hit "check for codes" to poll.'}
          </span>
        </div>
      )}

      <div className="view-toggle">
        <button className={view === 'devices' ? 'on' : ''} onClick={() => setView('devices')}>device view</button>
        <button className={view === 'permissions' ? 'on' : ''} onClick={() => setView('permissions')}>permission view</button>
      </div>

      {view === 'devices' && (
        <div className="device-grid">
          {pairedAgents.map((a) => (
            <div key={a.id} className={`device-card ${a.status === 'bad' ? 'revoked' : ''}`}>
              <div className="device-card-head">
                <Dot status={a.status} pulse={a.lastActive.endsWith('m ago')} />
                <span style={{ fontWeight: 600 }}>{a.label.replace(' (revoked)', '')}</span>
                {a.justPaired && <span className="chip ok" style={{ marginLeft: 'auto' }}>new</span>}
                {/* #577 — running older image bits than the current precache
                    registration; one click below brings it current. */}
                {staleFor(a.deviceKeyHash) === true && (
                  <span className="chip warn" style={{ marginLeft: a.justPaired ? 0 : 'auto' }}>
                    update available
                  </span>
                )}
              </div>
              <dl className="device-kvs">
                <dt>actor</dt><dd className="mono">{a.omni}</dd>
                <dt>vendor</dt><dd>{a.vendor}</dd>
                <dt>device</dt><dd>{a.device}</dd>
                <dt>scope</dt>
                <dd>
                  {Object.entries(a.scope ?? {})
                    .filter(([, v]) => v.read || v.write)
                    .map(([ns, v]) => `${ns}:${v.write ? 'rw' : 'r'}`)
                    .join(' · ') || 'none'}
                </dd>
                <dt>active</dt><dd className="muted">{a.lastActive}</dd>
                {/* #577 follow-up — the LIVE runtime identity (bridge-reported
                    Hermes engine + version, the bump ground truth) and the
                    sandbox instance behind this delegate. Absent rows render
                    nothing: a dead sandbox or an older daemon hides them. */}
                {(() => {
                  const rt = imageRowFor(a.deviceKeyHash);
                  if (!rt) return null;
                  return (
                    <>
                      {(rt.agent_engine || rt.agent_version) && (
                        <>
                          <dt>runtime</dt>
                          <dd title={rt.model ? `LLM endpoint: ${rt.model}` : undefined}>
                            {rt.agent_engine ?? 'agent'}
                            {rt.agent_version ? ` ${rt.agent_version}` : ''}
                            {rt.stale === false ? ' · current image' : ''}
                          </dd>
                        </>
                      )}
                      {rt.sandbox_id && (
                        <>
                          <dt>sandbox</dt>
                          <dd
                            className="mono"
                            title={`${rt.sandbox_id}${
                              rt.booted_registration_id
                                ? ` · image registration ${rt.booted_registration_id}`
                                : ''
                            }`}
                          >
                            {rt.sandbox_id.length > 14
                              ? `…${rt.sandbox_id.slice(-14)}`
                              : rt.sandbox_id}
                            {rt.sandbox_status ? ` · ${rt.sandbox_status}` : ''}
                            {sandboxExpiryLabel(rt.expire_at)}
                          </dd>
                        </>
                      )}
                    </>
                  );
                })()}
              </dl>
              {a.status !== 'bad' && onUnpair && (
                <button
                  className="btn"
                  style={{ marginTop: 10, width: '100%', fontSize: 11.5 }}
                  onClick={() => onUnpair(a)}
                >
                  unpair · revoke on-chain
                </button>
              )}
              {a.status !== 'bad' && onArchive && a.deviceKeyHash && (
                <button className="btn sm" onClick={() => onArchive(a)}>
                  archive · slot returns
                </button>
              )}
              {/* #577 — the in-place runtime update: kill + re-create on the
                  current image, SAME identity/grants/channel, best-effort
                  Hermes-home hand-off. No archive ceremony, no Touch ID. Also
                  the "respawn now" affordance for an expired sandbox. */}
              {a.status !== 'bad' && a.deviceKeyHash && (
                <button
                  className={`btn sm ${staleFor(a.deviceKeyHash) === true ? 'primary' : ''}`}
                  disabled={updating.has(a.deviceKeyHash)}
                  onClick={() => updateOne(a)}
                  title="Re-create this agent's sandbox on the current image. Identity, grants, channel and persona are preserved; the live conversation restarts."
                >
                  {updating.has(a.deviceKeyHash)
                    ? 'updating… (may take a minute)'
                    : forceArmed.has(a.deviceKeyHash)
                      ? '⟳ update anyway (kills running jobs)'
                      : '⟳ update runtime'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {view === 'permissions' && <PermissionView agents={pairedAgents} onManage={onManage} />}
    </>
  );
}

// One incoming pairing request: identity review + the #249 scope picker. The
// operator adjusts the namespace selection (default = the requested tokens)
// BEFORE the Touch ID — the accept then batches registerAgentDevice + the REAL
// setScope over exactly this selection, so §B ends with the agent scoped.
function PairRequestCard({
  req,
  namespaces,
  onAccept,
  onDecline,
}: {
  req: PairingRequest;
  namespaces: string[];
  onAccept: (req: PairingRequest, services: string[]) => void;
  onDecline: (id: string) => void;
}) {
  const options = scopeOptions(req, namespaces);
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(options.filter((o) => o.preselected).map((o) => o.svc)),
  );
  const toggle = (svc: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(svc)) next.delete(svc);
      else next.add(svc);
      return next;
    });
  };
  // Bare ns-less NON-memory tokens can't compile to an on-chain service —
  // show them so a request is never silently narrowed.
  const bareUnknown = req.requested.filter((p) => p.ns.length === 0 && p.cap !== 'memory');
  // Keep the request's token order: grant exactly what's checked.
  const services = options.filter((o) => selected.has(o.svc)).map((o) => o.svc);

  return (
    <div className="pair-req">
            <div className="pair-req-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <Dot status="warn" pulse />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>
                    Pairing request · <span className="serif" style={{ fontStyle: 'italic' }}>{req.agent}</span>
                  </div>
                  {/* #224 — start time + LIVE expiry countdown. A card reading
                      "⚠ expired" (or an old start) is the stale/duplicate one to
                      refuse; the freshness signal that the agent can cross-check. */}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {req.vendor} · requested {req.requestedAt ? new Date(req.requestedAt * 1000).toLocaleString() : '—'} · <ExpiryCountdown expiresAt={req.expiresAt} />
                  </div>
                </div>
              </div>
              <span className="chip warn">action required</span>
            </div>

            <div className="pair-req-grid">
              <div>
                {/* DECLARED — self-reported by the runtime, NOT cryptographically
                    attested. Cosmetic context only; never a basis for trust. The
                    only verifiable identity is the attested column on the right. */}
                <div className="pair-k" style={{ fontStyle: 'italic', opacity: 0.85, marginBottom: 6, color: 'var(--warn, #b8860b)' }}>
                  ⚠ declared by the runtime · self-reported, NOT attested
                </div>
                <div className="pair-k">device</div>
                <div className="pair-v">{req.device}</div>
                <div className="pair-k">machine</div>
                <div className="pair-v mono" style={{ fontSize: 11 }}>{req.machine}</div>
                <div className="pair-k">runtime</div>
                <div className="pair-v">{req.runtime}</div>
              </div>
              <div>
                {/* ATTESTED — the cryptographic device identity (proved by the
                    agent's pop_sig over its K10 key). #224: cross-check
                    device_key_hash + D_pub against the agent's `--request-pairing`
                    output before approving. pairing code + request id are broker-
                    minted handles (not attested, but tamper-evident on claim). */}
                <div className="pair-k" style={{ fontStyle: 'italic', opacity: 0.85, marginBottom: 6 }}>
                  ✓ attested cryptographic identity · cross-check on the agent
                </div>
                <div className="pair-k">device key hash · verify on agent</div>
                <div className="pair-v mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{req.deviceKeyHash || req.deviceKeyHashShort}</div>
                <div className="pair-k">device public address · verify on agent</div>
                <div className="pair-v mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{req.dpubFull || req.dpub}</div>
                <div className="pair-k">pairing code · matches the agent device</div>
                <div className="pair-v mono" style={{ fontSize: 13, letterSpacing: '0.04em', wordBreak: 'break-all' }}>{req.pairCode || '—'}</div>
                <div className="pair-k">request id · master handle</div>
                <div className="pair-v mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{req.id}</div>
                <div className="pair-k">derivation</div>
                <div className="pair-v mono">O_master{req.derivation}</div>
              </div>
            </div>

            <div className="pair-perms">
              {/* #249 — the operator SELECTS the grant before Touch ID. Checked =
                  granted in the accept's setScope half; default = the requested
                  tokens. Unchecking everything binds with zero grants (explicitly
                  confirmed upstream — never silent). */}
              <div className="pair-k" style={{ marginBottom: 8 }}>
                grant permissions · {services.length} of {options.length} selected
              </div>
              {options.map((o) => (
                <label key={o.svc} className="pair-perm-row" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    type="checkbox"
                    checked={selected.has(o.svc)}
                    onChange={() => toggle(o.svc)}
                    style={{ accentColor: 'var(--ink)' }}
                  />
                  <span className="chip mono">{o.svc}</span>
                  <span style={{ fontSize: 11.5, color: 'var(--ink-dim)' }}>{o.reason}</span>
                </label>
              ))}
              {bareUnknown.map((p) => (
                <div key={p.cap} className="pair-perm-row">
                  <span className="chip warn">{p.cap}</span>
                  <span style={{ fontSize: 11.5, color: 'var(--ink-dim)' }}>
                    requested without a namespace — cannot compile to an on-chain scope service; not grantable here
                  </span>
                </div>
              ))}
            </div>

            <div className="pair-req-foot">
              <div className="muted" style={{ fontSize: 10.5 }}>{req.attestation}</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn" onClick={() => onDecline(req.id)}>decline</button>
                <button className="btn primary" onClick={() => onAccept(req, services)}>
                  accept pairing · Touch ID · {services.length} {services.length === 1 ? 'grant' : 'grants'}
                </button>
              </div>
            </div>
    </div>
  );
}
