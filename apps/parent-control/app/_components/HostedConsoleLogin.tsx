'use client';

import { useEffect, useState } from 'react';
import type { CoreBackend } from '../../lib/client/core';
import type { MasterSessionInfo } from '../../lib/generated/MasterSessionInfo';

const POLL_INTERVAL_MS = 2500;

function loginError(failure: unknown): string {
  const message = String(failure);
  if (message.includes('/v1/auth/config')) return 'Sign-in is not ready on this server. Please contact the administrator.';
  if (message.includes('403')) return 'This email address is not approved for access. Please contact the administrator.';
  if (message.includes('401') || message.includes('expired')) return 'Your sign-in link or session expired. Please sign in again.';
  return 'Unable to complete sign-in. Please check your connection and try again.';
}

export function HostedConsoleLogin({ client }: { client: CoreBackend }) {
  const [email, setEmail] = useState('');
  const [pending, setPending] = useState<{ requestId: string; expiresAt: number } | null>(null);
  const [session, setSession] = useState<MasterSessionInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!pending) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        if (Date.now() >= pending.expiresAt) throw new Error('The sign-in link expired. Request a new link.');
        const verified = await client.pollEmailLogin(pending.requestId);
        if (cancelled) return;
        if (verified) {
          setSession(verified);
          setPending(null);
        } else {
          timer = setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch (failure) {
        if (cancelled) return;
        setError(loginError(failure));
        setPending(null);
        client.clearHostedSession();
      }
    };
    timer = setTimeout(poll, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [client, pending]);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    const validate = async () => {
      try {
        const current = await client.hostedSessionInfo();
        if (!cancelled && !current) { setSession(null); setError('Your session expired. Please sign in again.'); }
      } catch (failure) {
        if (!cancelled) { setSession(null); setError(loginError(failure)); }
      }
    };
    const timer = setInterval(validate, 60000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [client, session]);

  useEffect(() => () => client.clearHostedSession(), [client]);

  const signOut = () => {
    client.clearHostedSession();
    setPending(null);
    setSession(null);
    setError('');
  };

  return (
    <main className="hosted-console-preview">
      <section className="onboard-card" aria-labelledby="hosted-console-title">
        <p className="hosted-console-label">Agent Terrier · private access</p>
        <h1 id="hosted-console-title">{session ? 'You are signed in.' : 'Sign in with your email'}</h1>
        {session ? <>
          <p>{email}</p>
          <p>Account: <code className="hosted-account-id">{session.omni_account}</code></p>
          <p>Your identity is verified. Agent management and passkey sign-in are not available in this hosted console yet.</p>
          <button type="button" onClick={signOut}>Sign out</button>
        </> : <>
          <p>Access is limited to approved email addresses. Signing in uses your existing identity and does not create another account.</p>
          <form onSubmit={async event => {
            event.preventDefault();
            setBusy(true);
            setError('');
            try {
              const challenge = await client.requestEmailLogin(email);
              setPending({ requestId: challenge.request_id, expiresAt: Date.now() + challenge.expires_in_seconds * 1000 });
            } catch (failure) {
              setError(loginError(failure));
            } finally { setBusy(false); }
          }}>
            <label htmlFor="hosted-email">Email address</label>
            <input id="hosted-email" type="email" autoComplete="email" value={email} required
              disabled={busy || !!pending} onChange={event => setEmail(event.target.value)} />
            <button type="submit" disabled={busy || !!pending}>{busy ? 'Sending…' : 'Send sign-in link'}</button>
          </form>
          {pending && <div role="status">
            <p>Check your inbox and open the verification link. Keep this page open to finish signing in.</p>
            <button type="button" onClick={signOut}>Cancel sign-in</button>
          </div>}
          <p>Your session stays in this tab’s memory. Reloading or closing the page requires signing in again.</p>
        </>}
        {error && <p role="alert">{error}</p>}
      </section>
    </main>
  );
}
