'use client';

import React, { useEffect, useRef, useState } from 'react';
import type { HostedSignerRequest } from '@/lib/generated/HostedSignerRequest';
import type { HostedSignerApproval } from '@/lib/generated/HostedSignerApproval';
import type { HostedSignerChallenge } from '@/lib/generated/HostedSignerChallenge';
import type { HostedSignerStartRequest } from '@/lib/generated/HostedSignerStartRequest';
import type { HostedSignerStatusRequest } from '@/lib/generated/HostedSignerStatusRequest';
import type { HostedSignerStatus } from '@/lib/generated/HostedSignerStatus';
import { createHostedIdentity, signHostedEnrollment, type HostedBrowserIdentity } from '@/lib/hostedIdentity';
import { getAssertionOverHash } from '@/lib/webauthn';

export interface HostedBrowserEnrollmentProps {
  brokerUrl: string;
  omni: string;
  start: (request: HostedSignerStartRequest) => Promise<HostedSignerChallenge>;
  publish: (request: HostedSignerApproval) => Promise<HostedSignerRequest>;
  status: (request: HostedSignerStatusRequest) => Promise<HostedSignerStatus>;
  onReady: (identity: HostedBrowserIdentity) => void | Promise<void>;
}

export function HostedBrowserEnrollment({ brokerUrl, omni, start, publish, status, onReady }: HostedBrowserEnrollmentProps) {
  const [request, setRequest] = useState<HostedSignerRequest | null>(null);
  const callbacks = useRef({ status, onReady });
  callbacks.current = { status, onReady };
  const [identity, setIdentity] = useState<HostedBrowserIdentity | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  async function begin() {
    setBusy(true); setError(''); setMessage('');
    try {
      const currentIdentity = identity ?? await createHostedIdentity(brokerUrl, omni);
      setIdentity(currentIdentity);
      const current = await status({ credential_id: currentIdentity.credentialId, device_key_hash: currentIdentity.deviceKeyHash });
      if (current.active && current.device_active) { await onReady(currentIdentity); return; }
      const enrollment = await start({ credential_id: currentIdentity.credentialId, public_key_x: currentIdentity.publicKeyX, public_key_y: currentIdentity.publicKeyY,
        device_key_hash: currentIdentity.deviceKeyHash, origin: location.origin, rp_id: location.hostname });
      const proof = await getAssertionOverHash(enrollment.challenge, [currentIdentity.credentialId]);
      const device_proof = await signHostedEnrollment(currentIdentity, enrollment.challenge);
      const approval: HostedSignerApproval = { enrollment, proof, device_proof };
      setRequest(await publish(approval));
      setMessage('Waiting for approval in your original console. This browser will continue automatically when approval is confirmed.');
    } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
  }
  useEffect(() => {
    if (!request || !identity) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function check() {
      if (Date.now() / 1000 >= request!.approval.enrollment.intent.expires_at) {
        setMessage('This request expired. Start a fresh request to continue.'); return;
      }
      try {
        const current = await callbacks.current.status({ credential_id: identity!.credentialId, device_key_hash: identity!.deviceKeyHash });
        if (cancelled) return;
        if (current.active && current.device_active) { await callbacks.current.onReady(identity!); return; }
      } catch (failure) { if (!cancelled) { setError(String(failure)); setMessage('Approval check paused. Refresh the request after signing in again or restoring the connection.'); } return; }
      if (!cancelled) timer = setTimeout(() => void check(), 3000);
    }
    void check();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [request, identity]);
  return <section className="panel" aria-label="Enable this browser">
    <h2>Enable this browser</h2>
    <p>Your existing account and data stay the same. Approve this browser once from the console where your current passkey works.</p>
    <p>Touch ID unlocks this browser’s keys. Only public identity information is saved; device secrets stay in memory.</p>
    <button disabled={busy} onClick={() => void begin()}>{request ? 'Refresh approval request' : 'Set up browser access'}</button>
    {request && <p>Open your original console and review the browser request for <strong>{request.approval.enrollment.intent.origin}</strong>. Confirm only if its account and device match this request: <code>{request.approval.enrollment.intent.device_key_hash}</code>.</p>}
    {message && <p role="status">{message}</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
