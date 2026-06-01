'use client';

import { useEffect, useState } from 'react';
import { txHash } from '@/lib/demoData';
import { useClient } from '@/lib/ClientProvider';
import type { AgentKeysClient } from '@/lib/client/types';
import { credentialToFinishPayload, jsonToCreationOptions, webauthnAvailable } from '@/lib/webauthn';
import type { CeremonyStep } from './types';

// Real K11 enroll via the daemon ui-bridge (PR-B) — used by onboarding when a
// daemon is configured. Returns 'real' on a completed browser ceremony,
// 'fallback' when no daemon / no authenticator / the user dismissed it (the
// onboarding then runs the narrated ceremony so the offline demo still flows).
async function tryRealEnroll(client: AgentKeysClient): Promise<'real' | 'fallback'> {
  if (!webauthnAvailable()) return 'fallback';
  const begin = await client.enrollK11Begin({ userName: 'sara@local', userDisplayName: 'Sara (master)' });
  if (!begin.ok) return 'fallback'; // EmptyBackend → disconnected → narrated fallback
  try {
    const opts = jsonToCreationOptions({
      rp: { id: begin.data.rpId, name: begin.data.rpName },
      user: { id: begin.data.userId, name: begin.data.userName, displayName: begin.data.userDisplayName },
      challenge: begin.data.challenge,
      pubKeyCredParams: begin.data.pubKeyCredParams,
      timeout: begin.data.timeout,
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    });
    const cred = (await navigator.credentials.create({ publicKey: opts })) as PublicKeyCredential | null;
    if (!cred) return 'fallback';
    const payload = credentialToFinishPayload(cred);
    const fin = await client.enrollK11Finish({
      credentialId: payload.credentialId,
      attestationObject: payload.attestationObject,
      clientDataJSON: payload.clientDataJSON,
      bindingNonce: begin.data.userId,
    });
    return fin.ok ? 'real' : 'fallback';
  } catch {
    return 'fallback';
  }
}

// Shared progress-bar ceremony with a live step log + per-step tx hashes.
export function CeremonyRunner({
  steps,
  onDone,
  accent = '#1a1815',
  stepMs = 750,
}: {
  steps: CeremonyStep[];
  onDone: () => void;
  accent?: string;
  stepMs?: number;
}) {
  const [done, setDone] = useState(0);
  const [txs, setTxs] = useState<Record<number, string>>({});

  useEffect(() => {
    if (done >= steps.length) {
      const t = setTimeout(onDone, 700);
      return () => clearTimeout(t);
    }
    let cancelled = false;
    const t = setTimeout(async () => {
      const step = steps[done];
      // Real async work for this step (e.g. the §9 Stage-2 WebAuthn Touch ID)
      // runs WHILE the row shows "running"; the bar advances when it resolves.
      if (step.action) {
        try { await step.action(); } catch { /* fall through — narrated */ }
      }
      if (cancelled) return;
      if (step.onchain) {
        setTxs((prev) => ({ ...prev, [done]: txHash(step.label + done) }));
      }
      setDone((d) => d + 1);
    }, stepMs);
    return () => { cancelled = true; clearTimeout(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done]);

  const pct = Math.round((done / steps.length) * 100);

  return (
    <div className="ceremony">
      <div className="ceremony-bar-wrap">
        <div className="ceremony-bar-track">
          <div className="ceremony-bar-fill" style={{ width: `${pct}%`, background: accent }} />
        </div>
        <div className="ceremony-bar-meta">
          <span>{done >= steps.length ? 'complete' : 'working…'}</span>
          <span className="mono">
            {Math.min(done, steps.length)}/{steps.length} · {pct}%
          </span>
        </div>
      </div>

      <div className="ceremony-log">
        {steps.map((s, i) => {
          const status = i < done ? 'done' : i === done ? 'running' : 'pending';
          return (
            <div key={i} className={`clog-row ${status}`}>
              <span className="clog-mark">{status === 'done' ? '✓' : status === 'running' ? '▸' : '·'}</span>
              <div className="clog-body">
                <div className="clog-label">
                  {s.label}
                  {s.onchain && <span className="clog-chain">on-chain</span>}
                </div>
                <div className="clog-sub">{s.sub}</div>
                {txs[i] && <div className="clog-tx mono">tx {txs[i].slice(0, 22)}… · heima · confirmed</div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Full-screen WebAuthn login → onboarding ceremony (workflow 1).
export function OnboardingScreen({ onComplete }: { onComplete: () => void }) {
  const client = useClient();
  const [phase, setPhase] = useState<'email' | 'ceremony'>('email');
  const [enrollMode, setEnrollMode] = useState<'real' | 'demo' | 'pending'>('pending');
  const [email, setEmail] = useState('');
  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());

  // First-run is the arch.md §9 master-bootstrap ceremony. Identity (the real
  // email) comes FIRST; the WebAuthn Touch ID is Stage 2 (master binding),
  // fired automatically MID-ceremony. There is no separate "register" step —
  // the passkey binding is one stage of the running ceremony.
  const submitEmail = () => {
    if (emailValid) setPhase('ceremony');
  };

  // §9 Stages 0–4. The Stage-2 binding step carries the real WebAuthn action;
  // the runner awaits it (real Touch ID via the daemon ui-bridge, narrated
  // fallback offline).
  const stages: CeremonyStep[] = [
    { label: 'Generate device key (K10)', sub: 'secp256k1 keypair · generated locally · no network · sealed in the OS keychain' },
    { label: 'Verify your email', sub: `magic link → ${email} · broker returns binding_nonce (single-use, TTL-bound)` },
    {
      label: 'Bind passkey (K11) · Touch ID',
      sub: 'WebAuthn create · challenge = SHA256(binding_nonce ‖ D_pub) · commits the device atomically',
      action: async () => {
        const outcome = await tryRealEnroll(client);
        setEnrollMode(outcome === 'real' ? 'real' : 'demo');
      },
    },
    { label: 'Derive wallet + SIWE → session', sub: 'signer derives initial_master_wallet · SIWE round-trip → J1 · actor_omni freezes here' },
    { label: 'Register master device on chain', sub: 'SidecarRegistry.register_master_device · roles = CAP_MINT | RECOVERY | SCOPE_MGMT', onchain: true, fn: 'register_master_device(bytes32,bytes32,bytes32,bytes32,bytes,uint8,bytes)' },
  ];

  return (
    <div className="onboard">
      <div className="onboard-card">
        <div className="onboard-brand">
          <div
            style={{
              width: 56, height: 56, border: '1px solid var(--rule)', display: 'grid',
              placeItems: 'center', fontSize: 28, color: 'var(--ink)',
            }}
            aria-hidden
          >
            ◐
          </div>
          <div>
            <div className="serif" style={{ fontSize: 30, fontStyle: 'italic', letterSpacing: '-0.02em', lineHeight: 1 }}>
              agentKeys
            </div>
            <div style={{ fontSize: 11, color: 'var(--ink-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 6 }}>
              sovereign keys · for agents
            </div>
          </div>
        </div>

        <div className="hr-ascii" style={{ margin: '20px 0' }}>{'─'.repeat(220)}</div>

        {phase === 'email' && (
          <div className="onboard-login">
            <h1 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 6px' }}>Set up your master identity.</h1>
            <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', marginBottom: 18, maxWidth: 400 }}>
              Enter the email you&apos;ll use as your account. We send a one-time magic link there to verify it&apos;s
              yours — your master identity is anchored to it. No password, no seed phrase.
            </p>
            <label
              htmlFor="ak-email"
              style={{ display: 'block', fontSize: 10.5, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--ink-faint)', marginBottom: 6 }}
            >
              email address
            </label>
            <input
              id="ak-email"
              type="email"
              inputMode="email"
              autoComplete="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') submitEmail(); }}
              placeholder="you@example.com"
              style={{
                width: '100%', padding: '11px 12px', fontFamily: 'inherit', fontSize: 14,
                border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)', marginBottom: 14,
              }}
            />
            <button
              className="btn primary"
              style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
              disabled={!emailValid}
              onClick={submitEmail}
            >
              Continue →
            </button>
            <div style={{ fontSize: 10.5, color: 'var(--ink-faint)', marginTop: 14, textAlign: 'center' }}>
              first login creates O_master · HDKD root at /
            </div>
          </div>
        )}

        {phase === 'ceremony' && (
          <div>
            <div style={{ fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-dim)', marginBottom: 14 }}>
              Bringing up your trust core · {email}
              {enrollMode === 'real' && <span className="chip ok" style={{ marginLeft: 8 }}>K11 bound · real WebAuthn</span>}
              {enrollMode === 'demo' && <span className="chip" style={{ marginLeft: 8 }}>demo · no daemon</span>}
            </div>
            <CeremonyRunner steps={stages} onDone={onComplete} stepMs={760} />
          </div>
        )}
      </div>
    </div>
  );
}
