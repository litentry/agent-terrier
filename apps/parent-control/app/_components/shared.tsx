'use client';

import { useEffect, useState, type ReactNode } from 'react';
import { CHIP_STYLES } from '@/lib/constants';
import type { ConnectionStatus } from '@/lib/client/types';
import type { Actor, ChipKind, StatusKind } from './types';

export function Chip({ children, kind = 'default' }: { children: ReactNode; kind?: ChipKind }) {
  const cls = CHIP_STYLES[kind] || 'chip';
  return <span className={cls}>{children}</span>;
}

export function Dot({ status = 'ok', pulse = false }: { status?: StatusKind; pulse?: boolean }) {
  const cls = `dot ${status === 'ok' ? '' : status} ${pulse ? 'pulse' : ''}`.trim();
  return <span className={cls}></span>;
}

export function PageHead({
  crumb,
  title,
  desc,
  actions,
}: {
  crumb?: ReactNode;
  title: ReactNode;
  desc?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        {crumb && <div className="crumb">{crumb}</div>}
        <h1>{title}</h1>
        {desc && <div className="desc">{desc}</div>}
      </div>
      {actions && <div style={{ display: 'flex', gap: 8 }}>{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  right,
  flush,
  children,
}: {
  title?: ReactNode;
  right?: ReactNode;
  flush?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="panel">
      {title && (
        <div className="panel-head">
          <span>{title}</span>
          {right}
        </div>
      )}
      <div className={`panel-body ${flush ? 'flush' : ''}`}>{children}</div>
    </div>
  );
}

export function Modal({
  title,
  onClose,
  children,
  footer,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [onClose]);
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ttl">{title}</span>
          <button className="x" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

function hashCode(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (((h << 5) - h) + s.charCodeAt(i)) | 0;
  return h;
}

export function WebAuthnModal({
  intent,
  onConfirm,
  onCancel,
}: {
  intent: { text: string; fields: [string, string][] };
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [phase, setPhase] = useState<'idle' | 'scanning' | 'ok'>('idle');
  const startScan = () => {
    setPhase('scanning');
    setTimeout(() => {
      setPhase('ok');
      setTimeout(onConfirm, 350);
    }, 1100);
  };

  return (
    <div className="modal-bg" onClick={phase === 'idle' ? onCancel : undefined}>
      <div className="modal wa-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ttl">K11 · WebAuthn confirmation</span>
          {phase === 'idle' && (
            <button className="x" onClick={onCancel}>
              ×
            </button>
          )}
        </div>
        <div className="modal-body">
          <h2 className="ttl-big">{intent.text}</h2>
          <div className="muted" style={{ fontSize: 11 }}>
            agentkeys-cli @ localhost:9091 · this device only
          </div>

          <div className="wa-intent">
            {intent.fields.map(([k, v]) => (
              <div key={k} style={{ marginBottom: 4 }}>
                <span className="key">{k}</span>
                <span className="val">{v}</span>
              </div>
            ))}
          </div>

          <div className="wa-fingerprint">
            <div className={`fp-ring ${phase === 'scanning' ? 'scanning' : ''}`}>
              <span className="glyph">{phase === 'ok' ? '✓' : 'fp'}</span>
            </div>
            <div className="fp-msg">
              {phase === 'idle' && 'Touch the sensor to authorize this mutation.'}
              {phase === 'scanning' && 'Verifying biometric…'}
              {phase === 'ok' && 'Authorized · publishing to chain.'}
            </div>
          </div>

          <div className="muted" style={{ fontSize: 10.5, marginTop: 12, textAlign: 'center' }}>
            challenge = sha256(intent · binding_nonce · D_pub)
            <br />
            <span style={{ fontFamily: 'inherit' }}>
              0x{Math.abs(hashCode(intent.text)).toString(16).padStart(8, '0')}…
              {Math.abs(hashCode(JSON.stringify(intent.fields))).toString(16).padStart(8, '0')}
            </span>
          </div>
        </div>
        <div className="modal-foot">
          {phase === 'idle' && (
            <>
              <button className="btn" onClick={onCancel}>
                cancel
              </button>
              <button className="btn primary" onClick={startScan}>
                authorize · Touch ID
              </button>
            </>
          )}
          {phase === 'scanning' && (
            <button className="btn" disabled>
              verifying…
            </button>
          )}
          {phase === 'ok' && (
            <button className="btn primary" disabled>
              authorized ✓
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({
  status,
  title = 'backend not connected',
  hint,
}: {
  status: ConnectionStatus;
  title?: string;
  hint?: ReactNode;
}) {
  if (status.kind === 'connected') return null;
  const reasonText =
    status.reason === 'no-backend-configured'
      ? 'No daemon backend configured.'
      : status.reason === 'unauthorized'
        ? 'Daemon rejected the session JWT (expired or revoked).'
        : 'Daemon unreachable. Is it running?';
  return (
    <div
      style={{
        padding: '40px 20px',
        textAlign: 'center',
        border: '1px dashed var(--rule-soft)',
        background: 'var(--bg-elev)',
        fontSize: 12,
      }}
    >
      <div
        className="serif"
        style={{ fontSize: 18, fontStyle: 'italic', marginBottom: 8 }}
      >
        {title}
      </div>
      <div className="muted" style={{ marginBottom: 6 }}>
        {reasonText}
      </div>
      {status.detail && (
        <div className="muted" style={{ fontSize: 11, marginTop: 6, maxWidth: 520, marginInline: 'auto' }}>
          {status.detail}
        </div>
      )}
      {hint && (
        <div style={{ fontSize: 11, marginTop: 14, color: 'var(--ink-dim)' }}>{hint}</div>
      )}
    </div>
  );
}

export function ActorTree({
  actors,
  onPick,
  currentId,
}: {
  actors: Actor[];
  onPick: (id: string) => void;
  currentId?: string;
}) {
  const master = actors.find((a) => a.role === 'master')!;
  const agents = actors.filter((a) => a.role === 'agent');
  return (
    <div className="tree">
      <div
        className="node"
        style={{ cursor: 'pointer', fontWeight: currentId === master.id ? 600 : 400 }}
        onClick={() => onPick(master.id)}
      >
        <Dot status="ok" />
        <span className="serif" style={{ fontStyle: 'italic', fontSize: 14 }}>
          {master.label}
        </span>
        <span className="meta">master · {master.omniHex}</span>
      </div>
      {agents.map((a, i) => {
        const last = i === agents.length - 1;
        return (
          <div
            key={a.id}
            className="node"
            style={{ cursor: 'pointer', fontWeight: currentId === a.id ? 600 : 400 }}
            onClick={() => onPick(a.id)}
          >
            <span className="branch">{last ? '└── ' : '├── '}</span>
            <Dot status={a.status} pulse={a.lastActive === 'now' || a.lastActive.endsWith('m ago')} />
            {a.label}
            <span className="meta">
              {a.derivation} · {a.lastActive}
            </span>
          </div>
        );
      })}
    </div>
  );
}
