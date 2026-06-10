'use client';

import { useEffect, useRef, useState } from 'react';
import { txHash } from '@/lib/demoData';
import { useClient } from '@/lib/ClientProvider';
import type { AgentKeysClient, ConfigPreset } from '@/lib/client/types';
import { credentialToFinishPayload, getAssertionOverHash, jsonToCreationOptions, webauthnAvailable } from '@/lib/webauthn';
import type { AcceptAssertion } from '@/lib/webauthn';
import { akLog } from '@/lib/debug';
import type { CeremonyStep } from './types';
import { getMaskEmail, maskEmail, setMaskEmail } from '@/lib/maskEmail';

// Real K11 enroll via the daemon ui-bridge (PR-B) — used by onboarding when a
// daemon is configured. Returns 'real' on a completed browser ceremony,
// 'fallback' when no daemon / no authenticator / the user dismissed it (the
// onboarding then runs the narrated ceremony so the offline demo still flows).
function readMasterCredId(): string {
  try { return localStorage.getItem('ak_master_cred_id') || ''; } catch { return ''; }
}

/** The on-chain register still owed after the Stage-2 K11 bind (#225 E7 /
 *  #232): the "Register master" ceremony step signs `userOpHash` with the SAME
 *  passkey (2nd Touch ID) and submits it — so the prompt fires at the step the
 *  progress bar actually shows, not during "Bind passkey". */
interface PendingMasterRegister {
  userOpHash: string;
  account?: string;
  credentialId: string;
}

type EnrollOutcome =
  | { mode: 'fallback' }
  | { mode: 'real'; register?: PendingMasterRegister };

async function tryRealEnroll(client: AgentKeysClient, email: string): Promise<EnrollOutcome> {
  if (!webauthnAvailable()) return { mode: 'fallback' };

  // #225 E7 idempotency: if the master is ALREADY bound on chain, do NOT mint a new
  // passkey. `navigator.credentials.create()` always makes a BRAND-NEW credential,
  // but `registerFirstMasterDevice` is first-master-only — so a re-onboard can't
  // re-bind, and the new passkey + an overwritten `ak_master_cred_id` pointer make
  // the accept sign with the WRONG key (the on-chain account stays on the original
  // passkey → SIG_VALIDATION_FAILED). Reuse the already-bound passkey instead.
  const existingCred = readMasterCredId();
  const st = await client.getOnboardingState();
  if (st.ok && st.data.chain === 'master-registered') {
    if (existingCred) {
      akLog('onboarding: master already bound — REUSING passkey (no new create)', {
        boundCredentialId: existingCred,
        omni: st.data.omni,
      });
      return { mode: 'real' }; // already onboarded; the bound-passkey pointer is intact
    }
    akLog('onboarding: master bound on chain but NO local passkey pointer — reset + re-onboard needed', {
      omni: st.data.omni,
    });
    // Bound on chain but NO local pointer (storage cleared / different browser): we
    // can't safely re-enroll (first-master-only can't re-bind) — surface so the UI
    // offers "reset master + re-onboard" rather than minting an unusable passkey.
    return { mode: 'fallback' };
  }

  const begin = await client.enrollK11Begin({ userName: email, userDisplayName: email });
  if (!begin.ok) return { mode: 'fallback' }; // EmptyBackend → disconnected → narrated fallback
  try {
    // The macOS/Safari passkey dialog quotes user.name ("A passkey for '…'") and
    // the saved Passwords.app entry uses these fields. When the privacy toggle is
    // on, replace them with a generic label — display-only: WebAuthn registration
    // never returns user.name to the daemon (it's absent from clientDataJSON + the
    // attestation), so the real email sent at enroll/begin stays the identity
    // anchor and the daemon's finish verification is unaffected. user.id (the
    // stable handle) is left untouched.
    const masked = getMaskEmail();
    const label = (raw: string) => (masked ? 'AgentKeys master device' : raw);
    const opts = jsonToCreationOptions({
      rp: { id: begin.data.rpId, name: begin.data.rpName },
      user: { id: begin.data.userId, name: label(begin.data.userName), displayName: label(begin.data.userDisplayName) },
      challenge: begin.data.challenge,
      pubKeyCredParams: begin.data.pubKeyCredParams,
      timeout: begin.data.timeout,
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    });
    const cred = (await navigator.credentials.create({ publicKey: opts })) as PublicKeyCredential | null;
    if (!cred) return { mode: 'fallback' };
    const payload = credentialToFinishPayload(cred);
    akLog('onboarding: K11 passkey CREATED (generated)', {
      generatedCredentialId: payload.credentialId,
      rpId: begin.data.rpId,
    });
    const fin = await client.enrollK11Finish({
      credentialId: payload.credentialId,
      attestationObject: payload.attestationObject,
      clientDataJSON: payload.clientDataJSON,
      bindingNonce: begin.data.userId,
    });
    if (fin.ok) {
      akLog('onboarding: master account assembled (to bind)', {
        account: fin.data.registerAccount,
        chain: fin.data.chain,
        registerUserOpHash: fin.data.registerUserOpHash,
        passkeyCredentialId: payload.credentialId,
      });
      // #225 E7: the master binds as a passkey **P256Account** (operatorMasterWallet
      // = the smart account), not an EOA. K11-finish built + funded the account and
      // returned the register userOpHash; a SECOND Touch ID signs it, then the
      // daemon lands handleOps. The signing itself is the SEPARATE "Register
      // master" ceremony step (#232) — handed off so the 2nd Touch ID fires when
      // the progress bar says "register", not while it still shows "bind".
      if (fin.data.chain === 'register-pending' && fin.data.registerUserOpHash) {
        return {
          mode: 'real',
          register: {
            userOpHash: fin.data.registerUserOpHash,
            account: fin.data.registerAccount,
            credentialId: payload.credentialId,
          },
        };
      }
      // If fin.data.chain === 'master-registered' here, the daemon found the master
      // ALREADY bound (register build skipped) — we just minted a passkey we CANNOT
      // bind, so we deliberately do NOT overwrite ak_master_cred_id with it.
      return { mode: 'real' };
    }
    return { mode: 'fallback' };
  } catch {
    return { mode: 'fallback' };
  }
}

// #232: how often the register step re-checks `GET /v1/onboarding/state`, and
// the hard ceiling before the step gives up (handleOps lands in 10–30 s; the
// cap only bounds a daemon that stops answering entirely).
const REGISTER_POLL_INTERVAL_MS = 3000;
const REGISTER_CONFIRM_TIMEOUT_MS = 120_000;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// #232: the "Register master P256Account" ceremony step — sign the register
// userOpHash (2nd Touch ID) and land it on chain. The slow Heima handleOps
// (10–30 s) can outrun the browser's `await` (the HTTP response gets lost while
// the tx still lands), so the in-flight submit RACES an onboarding-state poll:
// whichever first proves `chain == "master-registered"` advances the ceremony.
// The chain state — not the HTTP response — is the ground truth.
async function submitMasterRegister(client: AgentKeysClient, reg: PendingMasterRegister): Promise<void> {
  akLog('onboarding: signing REGISTER userOpHash (2nd Touch ID)', {
    account: reg.account,
    registerUserOpHash: reg.userOpHash,
    signingCredentialId: reg.credentialId,
  });

  let assertion: AcceptAssertion;
  try {
    assertion = await getAssertionOverHash(reg.userOpHash, [reg.credentialId]);
  } catch (e) {
    // Touch ID cancelled/failed: nothing was signed, so nothing can land. The
    // passkey is enrolled + the account deployed, but the master is NOT bound —
    // do NOT persist the pointer. The operator retries; surfaced via onboarding state.
    akLog('onboarding: register Touch ID threw — pointer NOT persisted', {
      error: (e as Error)?.message,
      account: reg.account,
    });
    return;
  }

  let settled = false;
  const submit = (async () => {
    try {
      const sub = await client.registerMasterSubmit(assertion);
      return sub.ok
        ? { via: 'submit' as const, ok: true as const, txHash: sub.data.txHash }
        : { via: 'submit' as const, ok: false as const, detail: sub.status.detail ?? 'submit failed' };
    } catch (e) {
      return { via: 'submit' as const, ok: false as const, detail: (e as Error)?.message ?? 'submit threw' };
    }
  })();
  const statePoll = (async () => {
    for (;;) {
      await sleep(REGISTER_POLL_INTERVAL_MS);
      if (settled) return { via: 'poll-stopped' as const };
      const st = await client.getOnboardingState();
      if (st.ok && st.data.chain === 'master-registered') return { via: 'state-poll' as const };
    }
  })();
  const timeout = sleep(REGISTER_CONFIRM_TIMEOUT_MS).then(() => ({ via: 'timeout' as const }));

  const first = await Promise.race([submit, statePoll, timeout]);
  settled = true;

  let registered = false;
  let txHash: string | undefined;
  let failDetail = '';
  if (first.via === 'submit') {
    if (first.ok) {
      registered = true;
      txHash = first.txHash;
    } else {
      // The HTTP submit failed — but handleOps may still have landed (the
      // response can be dropped after the tx went out). The chain state decides.
      const st = await client.getOnboardingState();
      registered = !!(st.ok && st.data.chain === 'master-registered');
      failDetail = first.detail;
    }
  } else if (first.via === 'state-poll') {
    registered = true; // the await lost the race but the register landed
  } else {
    // 'timeout' — or the defensive 'poll-stopped' arm that can't win the race.
    failDetail = `no register confirmation within ${REGISTER_CONFIRM_TIMEOUT_MS / 1000} s`;
  }

  // Persist the auto-select pointer ONLY when the register actually BOUND the
  // account (B2). A stored-but-unbound pointer is exactly the wrong-passkey
  // trap: the accept would auto-select this key while the chain master is a
  // different one → SIG_VALIDATION_FAILED.
  if (registered) {
    try { localStorage.setItem('ak_master_cred_id', reg.credentialId); } catch {}
    akLog('onboarding: master REGISTERED + signer persisted ✅', {
      account: reg.account,
      txHash,
      confirmedVia: first.via,
      boundCredentialId: reg.credentialId,
    });
  } else {
    akLog('onboarding: register submit FAILED — pointer NOT persisted', {
      detail: failDetail,
      account: reg.account,
    });
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
                  {s.touchId && <span className="clog-touch">Touch ID · {s.touchId}</span>}
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
export function OnboardingScreen({
  onComplete,
}: {
  // `summary` lets the host (App) show the right post-onboarding toast: how many
  // categories were authored, whether the taxonomy already existed (idempotent
  // re-onboard), and whether it was a dev-only (no config worker) write.
  onComplete: (summary?: { categories?: number; already?: boolean; dev?: boolean }) => void;
}) {
  const client = useClient();
  // email → verify → ceremony (passkey) → setup (#207 1A: author the taxonomy)
  // → onComplete. `setup` is the last onboarding step before connecting agents.
  const [phase, setPhase] = useState<'email' | 'verify' | 'ceremony' | 'setup'>('email');
  const [enrollMode, setEnrollMode] = useState<'real' | 'demo' | 'pending'>('pending');
  const [email, setEmail] = useState('');
  const [requestId, setRequestId] = useState('');
  const [omni, setOmni] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [maskEm, setMaskEm] = useState(true);
  // #232: the on-chain register handed from the K11-bind step to the "Register
  // master" step (a ref — the `stages` closures are rebuilt per render).
  const pendingRegister = useRef<PendingMasterRegister | null>(null);
  useEffect(() => { setMaskEm(getMaskEmail()); }, []);
  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());

  // #207 item 1A — the onboarding setup step: author the default taxonomy behind a
  // visible progress ceremony (init does cap-mint → STS → config worker → S3, so
  // it takes several seconds). `checking` runs the idempotency probe, `pick` shows
  // the preset picker, `authoring` runs the progress bar.
  const [setupStage, setSetupStage] = useState<'checking' | 'pick' | 'authoring'>('checking');
  const [presets, setPresets] = useState<ConfigPreset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState('');
  const [setupNote, setSetupNote] = useState('');
  const initResult = useRef<{ ok: boolean; count: number; dev: boolean; note: string }>({
    ok: false,
    count: 0,
    dev: false,
    note: '',
  });

  // On entering 'setup': (1) IDEMPOTENCY — if a taxonomy ALREADY exists (a
  // re-onboard), jump straight in without re-authoring (never clobber, never
  // re-prompt). (2) else load the presets for the picker.
  useEffect(() => {
    if (phase !== 'setup') return;
    let cancelled = false;
    (async () => {
      const existing = await client.listMemoryCategories();
      if (cancelled) return;
      if (existing.ok && existing.data.length > 0) {
        onComplete({ categories: existing.data.length, already: true });
        return;
      }
      const r = await client.listConfigPresets();
      if (cancelled) return;
      if (r.ok) {
        setPresets(r.data.presets);
        setSelectedPreset(r.data.defaultId);
      } else {
        setSetupNote('Categories are set up once a daemon is connected — you can do this later from the memory page.');
      }
      setSetupStage('pick');
    })();
    return () => {
      cancelled = true;
    };
  }, [phase, client]);

  const chosenPreset = presets.find((p) => p.id === selectedPreset) ?? presets[0];

  // The init progress ceremony. The real author call fires as the slow step's
  // `action` (the runner AWAITS it), so the bar reflects the true duration and
  // we read the captured result in `authoringDone`.
  const initStages: CeremonyStep[] = [
    {
      label: 'Read your profile',
      sub: chosenPreset ? `${chosenPreset.label} · ${chosenPreset.categories.length} categories` : '',
    },
    {
      label: 'Compile category taxonomy',
      sub: 'merge into config/memory-taxonomy (idempotent — never clobbers existing)',
    },
    {
      label: 'Encrypt + store to Config',
      sub: 'cap-mint → STS → config worker → S3 · AES-256-GCM · master-only',
      action: async () => {
        const r = await client.initConfigDefault(selectedPreset);
        if (r.ok) {
          initResult.current = {
            ok: true,
            count: r.data.categories.length,
            dev: r.data.taxonomyStatus === 'cached',
            note: '',
          };
        } else {
          const detail = r.status.detail ?? '';
          const m = detail.match(/\{"error":"([^"]+)"\}/);
          initResult.current = { ok: false, count: 0, dev: false, note: m ? m[1] : detail || 'init failed' };
          throw new Error('init failed'); // narrated by the runner; handled in authoringDone
        }
      },
    },
    {
      label: 'Index + audit',
      sub: 'CredentialAudit.append(op=config.taxonomy) · tier-1 + anchor',
      onchain: true,
      fn: 'append(bytes32,bytes32,bytes32)',
    },
  ];

  const startAuthoring = () => {
    if (!selectedPreset) return;
    setSetupNote('');
    initResult.current = { ok: false, count: 0, dev: false, note: '' };
    setSetupStage('authoring');
  };

  // The runner finished the animation — act on the REAL captured result: success
  // jumps straight into the app (no extra button); failure returns to the picker
  // with the actionable error.
  const authoringDone = () => {
    const res = initResult.current;
    if (res.ok) {
      onComplete({ categories: res.count, dev: res.dev });
    } else {
      setSetupStage('pick');
      setSetupNote(`Couldn't author your categories — ${res.note}. Fix the config worker, then try again.`);
    }
  };

  // First-run is the arch.md §9 master-bootstrap ceremony. Identity (the real
  // email) comes FIRST; the WebAuthn Touch ID is Stage 2 (master binding),
  // fired automatically MID-ceremony. There is no separate "register" step —
  // the passkey binding is one stage of the running ceremony.
  // Enter email → REAL broker magic link via the daemon. If the backend is
  // disconnected (no daemon), fall back to the narrated demo so the offline UI
  // still flows (enrollMode = 'demo').
  const submitEmail = async () => {
    if (!emailValid || busy) return;
    setBusy(true);
    setNote('');
    const r = await client.startEmailVerify(email.trim());
    setBusy(false);
    if (r.ok) {
      setRequestId(r.data.requestId);
      setPhase('verify');
    } else {
      setEnrollMode('demo');
      setPhase('ceremony');
    }
  };

  // While in 'verify', poll the broker until the operator clicks the magic link.
  useEffect(() => {
    if (phase !== 'verify' || !requestId) return;
    let cancelled = false;
    const tick = async () => {
      const r = await client.pollEmailVerify(requestId);
      if (cancelled || !r.ok) return;
      if (r.data.status === 'verified') {
        setOmni(r.data.omniAccount ?? '');
        setPhase('ceremony');
      } else if (r.data.status.startsWith('failed')) {
        setNote(`Email verification ${r.data.status} — start over with a fresh link.`);
      }
    };
    void tick();
    const id = setInterval(tick, 3000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [phase, requestId, client]);

  // §9 Stages 0–4. The Stage-2 binding step carries the real WebAuthn action;
  // the runner awaits it (real Touch ID via the daemon ui-bridge, narrated
  // fallback offline).
  const stages: CeremonyStep[] = [
    { label: 'Generate device key (K10)', sub: 'secp256k1 keypair · generated locally · no network · sealed in the OS keychain' },
    { label: 'Email verified ✓', sub: `${maskEmail(email, maskEm)} · broker issued the single-use binding_nonce` },
    {
      label: 'Bind passkey (K11)',
      sub: 'WebAuthn create — makes your passkey in the Secure Enclave (bound to your verified email, not a demo identity). This is the FIRST of two Touch ID prompts.',
      touchId: '1 of 2',
      action: async () => {
        const outcome = await tryRealEnroll(client, email.trim());
        pendingRegister.current = outcome.mode === 'real' ? outcome.register ?? null : null;
        setEnrollMode(outcome.mode === 'real' ? 'real' : 'demo');
      },
    },
    { label: 'Activate managed wallet → session', sub: 'the signer derives + attests your managed wallet (EIP-191) and mints your session (J1) — no wallet app, no MetaMask. No Touch ID here.' },
    {
      label: 'Register master P256Account on chain',
      sub: 'the SAME passkey signs the register UserOp → handleOps binds operatorMasterWallet = your passkey smart account. This is the SECOND Touch ID prompt — expected, not an error. The on-chain confirm can take ~30 s.',
      touchId: '2 of 2',
      onchain: true,
      fn: 'P256Account.registerFirstMasterDevice(...)',
      // #232: the 2nd Touch ID fires HERE — at the step the bar shows — and the
      // step tolerates slow handleOps (submit raced against the state poll).
      // No-op when there's nothing to register (demo fallback / already bound).
      action: async () => {
        const reg = pendingRegister.current;
        if (!reg) return;
        pendingRegister.current = null;
        await submitMasterRegister(client, reg);
      },
    },
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
              type={maskEm ? 'password' : 'email'}
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
              type="button"
              onClick={() => { const v = !maskEm; setMaskEm(v); setMaskEmail(v); }}
              style={{ background: 'none', border: 'none', color: 'var(--ink-faint)', fontSize: 11, cursor: 'pointer', padding: '0 0 10px', textDecoration: 'underline' }}
              title="Toggle email masking (for screen-sharing); persists"
            >
              {maskEm ? '🕶 email hidden — click to show' : '👁 email shown — click to hide'}
            </button>
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

        {phase === 'verify' && (
          <div className="onboard-login">
            <h1 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 6px' }}>Check your inbox.</h1>
            <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', marginBottom: 18, maxWidth: 400 }}>
              We sent a one-time magic link to <strong>{maskEmail(email, maskEm)}</strong>. Click it to verify this address — this page
              continues automatically once you do.
            </p>
            <div style={{ fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--ink-faint)' }}>
              ▸ waiting for the link to be clicked…
            </div>
            {note && <div style={{ fontSize: 11.5, color: '#b00', marginTop: 12 }}>{note}</div>}
            <button
              className="btn"
              style={{ marginTop: 18, padding: '8px 14px' }}
              onClick={() => { setPhase('email'); setRequestId(''); setNote(''); }}
            >
              ← use a different email
            </button>
          </div>
        )}

        {phase === 'ceremony' && (
          <div>
            <div style={{ fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-dim)', marginBottom: 14 }}>
              Bringing up your trust core · {maskEmail(email, maskEm)}
              {enrollMode === 'real' && <span className="chip ok" style={{ marginLeft: 8 }}>K11 bound · real WebAuthn</span>}
              {enrollMode === 'demo' && <span className="chip" style={{ marginLeft: 8 }}>demo · no daemon</span>}
            </div>
            {omni && (
              <div className="mono" style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 14, wordBreak: 'break-all' }}>
                logged in as <strong>{maskEmail(email, maskEm)}</strong> · omni {omni}
              </div>
            )}
            <div className="touchid-notice">
              <strong>🔐 Touch ID is requested twice.</strong> Once to <strong>create</strong> your passkey, then once more to <strong>authorize</strong> its on-chain registration — both with the same passkey. The second prompt is expected, not a retry or an error.
            </div>
            <CeremonyRunner steps={stages} onDone={() => setPhase('setup')} stepMs={760} />
          </div>
        )}

        {phase === 'setup' && (
          <div className="onboard-login">
            {setupStage === 'checking' && (
              <div style={{ fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-faint)' }}>
                ▸ checking your setup…
              </div>
            )}

            {setupStage === 'pick' && (
              <>
                <h1 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 6px' }}>Set up your categories.</h1>
                <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', marginBottom: 16, maxWidth: 420 }}>
                  Pick a starting profile. This authors your <strong>category taxonomy</strong> — the vocabulary agentKeys uses
                  to scope everything an agent can touch: the <strong>memory</strong> it reads, the <strong>credentials</strong> it
                  uses, and more data classes (payments, …) as you add them. It seeds your categories now; credentials are
                  auto-categorized into the same taxonomy when you connect an agent. Refine it any time — nothing is shared until
                  you connect one.
                </p>
                {presets.length > 0 ? (
                  <>
                    <label htmlFor="ak-preset" style={{ display: 'block', fontSize: 10.5, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--ink-faint)', marginBottom: 6 }}>
                      starting profile
                    </label>
                    <select
                      id="ak-preset"
                      value={selectedPreset}
                      onChange={(e) => setSelectedPreset(e.target.value)}
                      style={{ width: '100%', padding: '10px 11px', fontSize: 13, border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)', marginBottom: 10 }}
                    >
                      {presets.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                    </select>
                    {chosenPreset && (
                      <>
                        <p className="muted" style={{ fontSize: 11.5, margin: '0 0 10px' }}>{chosenPreset.description}</p>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 16 }}>
                          {chosenPreset.categories.map((c) => <span key={c.ns} className="chip">{c.label}</span>)}
                        </div>
                      </>
                    )}
                    <button className="btn primary" style={{ width: '100%', justifyContent: 'center', padding: '12px' }} onClick={startAuthoring}>
                      ⊕ initialize my categories
                    </button>
                    <button className="btn" style={{ width: '100%', justifyContent: 'center', padding: '9px', marginTop: 8 }} onClick={() => onComplete()}>
                      skip — set up later
                    </button>
                  </>
                ) : (
                  <button className="btn primary" style={{ width: '100%', justifyContent: 'center', padding: '12px' }} onClick={() => onComplete()}>
                    Continue →
                  </button>
                )}
                {setupNote && <div style={{ fontSize: 11.5, color: 'var(--accent, #b8860b)', marginTop: 12 }}>{setupNote}</div>}
              </>
            )}

            {setupStage === 'authoring' && (
              <>
                <div style={{ fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-dim)', marginBottom: 14 }}>
                  Authoring your taxonomy{chosenPreset ? ` · ${chosenPreset.label}` : ''}
                </div>
                <CeremonyRunner steps={initStages} onDone={authoringDone} stepMs={700} />
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
