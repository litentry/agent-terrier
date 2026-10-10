'use client';

import React, { useEffect, useRef, useState } from 'react';
import { getAssertionOverHash } from '@/lib/webauthn';
import type { HostedSignerPending } from '@/lib/generated/HostedSignerPending';
import type { HostedSignerRequest } from '@/lib/generated/HostedSignerRequest';
import type { HostedSignerApproval } from '@/lib/generated/HostedSignerApproval';
import type { HostedSignerChallenge } from '@/lib/generated/HostedSignerChallenge';
import type { HostedSignerBuildRequest } from '@/lib/generated/HostedSignerBuildRequest';
import type { BuildAcceptUserOpResponse } from '@/lib/generated/BuildAcceptUserOpResponse';
import type { SubmitAcceptUserOpRequest } from '@/lib/generated/SubmitAcceptUserOpRequest';
import type { SubmitAcceptUserOpResponse } from '@/lib/generated/SubmitAcceptUserOpResponse';

export interface HostedEnrollmentApprovalProps {
  active?: boolean;
  credentialId: string;
  pending: () => Promise<HostedSignerPending>;
  dismiss: (id: string) => Promise<void>;
  prepare: (request: HostedSignerApproval) => Promise<HostedSignerChallenge>;
  build: (request: HostedSignerBuildRequest) => Promise<BuildAcceptUserOpResponse>;
  submit: (request: SubmitAcceptUserOpRequest) => Promise<SubmitAcceptUserOpResponse>;
}

export function HostedEnrollmentApproval({ active = true, credentialId, pending, dismiss, prepare, build, submit }: HostedEnrollmentApprovalProps) {
  const [requests, setRequests] = useState<HostedSignerRequest[]>([]);
  const [requestId, setRequestId] = useState('');
  const pendingCallback = useRef(pending);
  pendingCallback.current = pending;
  const [approved, setApproved] = useState<HostedSignerApproval | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  useEffect(() => {
    if (!active || !credentialId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try { const result = await pendingCallback.current(); if (!cancelled) { setRequests(result.requests); setError(''); } }
      catch (failure) { if (!cancelled) setError(String(failure)); }
      if (!cancelled) timer = setTimeout(() => void refresh(), 5000);
    }
    void refresh();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [active, credentialId]);
  async function inspect(row: HostedSignerRequest) {
    setBusy(true); setError(''); setApproved(null); setMessage('');
    try {
      const request = row.approval;
      setRequestId(row.id);
      const enrollment = await prepare(request);
      setApproved({ ...request, enrollment });
    } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
  }
  async function approve() {
    if (!approved) return;
    setBusy(true); setError('');
    try {
      if (!credentialId) throw new Error('Sign in with your existing passkey on this original console first.');
      setMessage('First approval: authorize this browser device.');
      const recovery = await getAssertionOverHash(approved.enrollment.recovery_challenge, [credentialId]);
      const operation = await build({ intent: approved.enrollment.intent, proof: approved.proof, device_proof: approved.device_proof,
        recovery_assertion: { attesting_device_key_hash: approved.enrollment.attesting_device_key_hash, assertion: recovery } });
      if (operation.user_op.sender.toLowerCase() !== approved.enrollment.intent.account.toLowerCase()
        || operation.chain_id !== approved.enrollment.intent.chain_id) throw new Error('The approval account or chain changed. Request was not submitted.');
      setMessage('Second approval: confirm the account update.');
      const assertion = await getAssertionOverHash(operation.user_op_hash, [credentialId]);
      const result = await submit({ user_op: operation.user_op, assertion });
      if (!result.ok) throw new Error('Browser approval was not accepted.');
      setMessage(result.pending ? 'Submitted. Wait for confirmation, then continue in the new browser.' : 'Browser approved. Return to the new browser and continue.');
      setApproved(null);
      await dismiss(requestId);
      setRequests((rows) => rows.filter((row) => row.id !== requestId));
    } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
  }
  if (!active || !credentialId || (!requests.length && !approved && !message && !error)) return null;
  return <section className="panel" aria-label="Browser access">
    <h2>Browser access</h2>
    <p>A new browser is requesting access to your existing account. Review the website and account, then approve with your current passkey.</p>
    {!approved && requests.map((row) => <div key={row.id}>
      <strong>{row.approval.enrollment.intent.origin}</strong>
      <button disabled={busy} onClick={() => void inspect(row)}>Review browser request</button>
      <button disabled={busy} onClick={() => void dismiss(row.id).then(() => setRequests((rows) => rows.filter((request) => request.id !== row.id))).catch((failure) => setError(String(failure)))}>Decline</button>
    </div>)}
    {approved && <div>
      <p>Website: <strong>{approved.enrollment.intent.origin}</strong></p>
      <p>Account: <code>{approved.enrollment.intent.account}</code></p>
      <p>Browser device: <code>{approved.enrollment.intent.device_key_hash}</code></p>
      <p>This browser can read your account data and approve account actions with its new passkey. Two Touch ID confirmations authorize its device and the account update.</p>
      <button disabled={busy} onClick={() => void approve()}>Approve this browser</button>
    </div>}
    {message && <p role="status">{message}</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
