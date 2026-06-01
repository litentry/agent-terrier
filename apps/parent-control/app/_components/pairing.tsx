'use client';

import { useState } from 'react';
import { Dot, PageHead } from './shared';
import { PermissionView } from './permissions';
import type { Actor, PairingRequest } from './types';

// Workflows 3–8: incoming pairing requests + device view + permission view.
export function PairingPage({
  requests,
  actors,
  onAccept,
  onDecline,
  onRefresh,
  justPaired,
  onManage,
}: {
  requests: PairingRequest[];
  actors: Actor[];
  onAccept: (req: PairingRequest) => void;
  onDecline: (id: string) => void;
  onRefresh: () => void;
  justPaired: string | null;
  onManage?: (id: string) => void;
}) {
  const [view, setView] = useState<'devices' | 'permissions'>('devices');
  const pairedAgents = actors.filter((a) => a.role === 'agent');

  return (
    <>
      <PageHead
        crumb="pairing · agent-initiated (method A) · arch §10.2"
        title={<><span className="muted serif">/</span> pairing</>}
        desc="An agent on another machine shows a one-time pairing code; you claim it here (J1_master-gated), review the device + requested scope, then approve with one Touch ID — which submits registerAgentDevice + the scope grant. Granted scope becomes on-chain cap-tokens."
        actions={<button className="btn" onClick={onRefresh}>↻ check for codes</button>}
      />

      {requests.length > 0 ? (
        requests.map((req) => (
          <div key={req.id} className="pair-req">
            <div className="pair-req-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <Dot status="warn" pulse />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>
                    Pairing request · <span className="serif" style={{ fontStyle: 'italic' }}>{req.agent}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 11.5 }}>{req.vendor} · {req.requestedAt}</div>
                </div>
              </div>
              <span className="chip warn">action required</span>
            </div>

            <div className="pair-req-grid">
              <div>
                <div className="pair-k">device</div>
                <div className="pair-v">{req.device}</div>
                <div className="pair-k">machine</div>
                <div className="pair-v mono" style={{ fontSize: 11 }}>{req.machine}</div>
                <div className="pair-k">runtime</div>
                <div className="pair-v">{req.runtime}</div>
              </div>
              <div>
                <div className="pair-k">pair-code</div>
                <div className="pair-v mono" style={{ fontSize: 16, letterSpacing: '0.1em' }}>{req.pairCode}</div>
                <div className="pair-k">derivation</div>
                <div className="pair-v mono">O_master{req.derivation}</div>
                <div className="pair-k">D_pub</div>
                <div className="pair-v mono" style={{ fontSize: 11 }}>{req.dpub}</div>
              </div>
            </div>

            <div className="pair-perms">
              <div className="pair-k" style={{ marginBottom: 8 }}>requested permissions</div>
              {req.requested.map((p) => (
                <div key={p.cap} className="pair-perm-row">
                  <span className="chip">{p.cap}</span>
                  <span className="muted" style={{ fontSize: 11 }}>{p.ns.join(', ')}</span>
                  <span style={{ fontSize: 11.5, color: 'var(--ink-dim)' }}>{p.reason}</span>
                </div>
              ))}
            </div>

            <div className="pair-req-foot">
              <div className="muted" style={{ fontSize: 10.5 }}>{req.attestation}</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn" onClick={() => onDecline(req.id)}>decline</button>
                <button className="btn primary" onClick={() => onAccept(req)}>accept pairing · Touch ID</button>
              </div>
            </div>
          </div>
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
            </div>
          ))}
        </div>
      )}

      {view === 'permissions' && <PermissionView agents={pairedAgents} onManage={onManage} />}
    </>
  );
}
