'use client';

import { useState } from 'react';
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

// Workflows 3–8: incoming pairing requests + device view + permission view.
export function PairingPage({
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
}: {
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
}) {
  const [view, setView] = useState<'devices' | 'permissions'>('devices');
  const [claimCode, setClaimCode] = useState('');
  const [claimLabel, setClaimLabel] = useState('');
  const pairedAgents = actors.filter((a) => a.role === 'agent');

  const submitClaim = () => {
    if (claimCode.trim() && claimLabel.trim()) {
      onClaim({ code: claimCode.trim(), label: claimLabel.trim() });
      setClaimCode('');
    }
  };

  return (
    <>
      <PageHead
        crumb="pairing · agent-initiated (method A) · arch §10.2"
        title={<><span className="muted serif">/</span> pairing</>}
        desc="An agent on another machine shows a one-time pairing code; you claim it here (J1_master-gated), review the device + requested scope, then approve with one Touch ID — which submits registerAgentDevice + the scope grant. Granted scope becomes on-chain cap-tokens."
        actions={<button className="btn" onClick={onRefresh}>↻ check for codes</button>}
      />

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
                  <div className="muted" style={{ fontSize: 11.5 }}>{req.vendor} · requested {req.requestedAt ? new Date(req.requestedAt * 1000).toLocaleString() : '—'}</div>
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
