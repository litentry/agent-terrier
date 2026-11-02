'use client';

import { useEffect, useRef, useState } from 'react';
import type { HostedSignerApproval } from '@/lib/generated/HostedSignerApproval';
import type { HostedSignerChallenge } from '@/lib/generated/HostedSignerChallenge';
import type { HostedSignerStartRequest } from '@/lib/generated/HostedSignerStartRequest';
import { createHostedIdentity, type HostedBrowserIdentity } from '@/lib/hostedIdentity';
import { buildBrowserApproval } from '@/lib/browserEnrollment';

interface LocalBrowserEnrollmentProps {
  brokerUrl: string;
  initialOmni?: string;
  account: (omni: string) => Promise<string>;
  start: (omni: string, request: HostedSignerStartRequest) => Promise<HostedSignerChallenge>;
  signIn: (omni: string) => Promise<HostedBrowserIdentity>;
  onReady: (identity: HostedBrowserIdentity) => void | Promise<void>;
}

export function LocalBrowserEnrollment({ brokerUrl, initialOmni = '', account, start, signIn, onReady }: LocalBrowserEnrollmentProps) {
  const [omni, setOmni] = useState(initialOmni);
  const [approval, setApproval] = useState<HostedSignerApproval | null>(null);
  const [download, setDownload] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const identity = useRef<HostedBrowserIdentity | null>(null);
  const generation = useRef(0);
  const ownerEdited = useRef(false);
  useEffect(() => () => { generation.current += 1; identity.current = null; }, []);
  useEffect(() => {
    if (!ownerEdited.current && initialOmni) setOmni(initialOmni);
  }, [initialOmni]);
  useEffect(() => {
    if (!approval) { setDownload(''); return; }
    const address = URL.createObjectURL(new Blob([JSON.stringify(approval, null, 2)], { type: 'application/json' }));
    setDownload(address);
    return () => URL.revokeObjectURL(address);
  }, [approval]);

  const selectedOmni = omni.trim().replace(/^0x/, '').toLowerCase();
  const validOmni = /^[a-f0-9]{64}$/.test(selectedOmni);
  async function begin() {
    if (busy || !validOmni) return;
    const attempt = ++generation.current;
    setBusy(true); setError(''); setApproval(null);
    try {
      if (location.hostname !== 'localhost') throw new Error('Open the local website at its localhost address before creating a passkey.');
      const expectedAccount = await account(selectedOmni);
      if (attempt !== generation.current) return;
      const current = identity.current ?? await createHostedIdentity(brokerUrl, selectedOmni);
      if (attempt !== generation.current) return;
      identity.current = current;
      const request = await buildBrowserApproval(current, async (enrollment) => {
        const result = await start(selectedOmni, enrollment);
        if (result.intent.account.toLowerCase() !== expectedAccount.toLowerCase()) throw new Error('The account changed during setup. Start again.');
        if (attempt !== generation.current) throw new Error('Browser setup was cancelled.');
        return result;
      });
      if (attempt === generation.current) setApproval(request);
    } catch (failure) { if (attempt === generation.current) setError(String(failure)); }
    finally { if (attempt === generation.current) setBusy(false); }
  }

  async function finish() {
    if (busy || !validOmni) return;
    const attempt = ++generation.current;
    setBusy(true); setError('');
    try {
      const unlocked = await signIn(selectedOmni);
      if (attempt === generation.current) await onReady(unlocked);
    } catch (failure) { if (attempt === generation.current) setError(String(failure)); }
    finally { if (attempt === generation.current) setBusy(false); }
  }

  return <section className="onboard-login" aria-label="Local browser setup">
    <h1 className="serif">Connect your local owner</h1>
    <p>Use the owner you registered in the local CLI. No email account is needed.</p>
    <label htmlFor="local-owner-id">Owner ID</label>
    <input id="local-owner-id" value={omni} disabled={busy} autoComplete="off" spellCheck={false}
      placeholder="Paste operator_omni from owner registration"
      onChange={(event) => { ownerEdited.current = true; generation.current += 1; identity.current = null; setApproval(null); setError(''); setOmni(event.target.value); }} />
    <p>This browser creates its own passkey. The CLI owner must approve it before you can sign in.</p>
    <button className="btn primary" disabled={busy || !validOmni} onClick={() => void begin()}>
      {approval ? 'Refresh approval request' : 'Create approval request'}
    </button>
    {approval && <div role="status" style={{ overflowWrap: 'anywhere', marginTop: 16 }}>
      <p>Account: <code>{approval.enrollment.intent.account}</code><br />Website: <code>{approval.enrollment.intent.origin}</code></p>
      <p>Device fingerprint: <code>{approval.enrollment.intent.device_key_hash}</code></p>
      <p>This request expires at {new Date(approval.enrollment.intent.expires_at * 1000).toLocaleTimeString()}.</p>
      {download && <a className="btn" href={download} download="agent-terrier-browser.json">Download public request</a>}
      <p>Locally, from the repository checkout using the same state, run this command. Replace the owner name and request path with your values:</p>
      <pre style={{ overflowX: 'auto' }}><code>{`python3 terrier browser approve \\\n  --name "YOUR_LOCAL_OWNER" \\\n  --request-file "PATH_TO_DOWNLOADED_REQUEST" \\\n  --confirm-device-key-hash "${approval.enrollment.intent.device_key_hash}"`}</code></pre>
      <p>The request contains public proofs only. Keep the owner's key and session files on this computer.</p>
    </div>}
    <button className="btn" disabled={busy || !validOmni} onClick={() => void finish()}>
      {approval ? 'Approved in CLI — sign in' : 'Sign in with existing passkey'}
    </button>
    {busy && <p role="status">Preparing browser access. Complete any passkey prompt to continue.</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
