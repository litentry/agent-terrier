'use client';

import { useState } from 'react';
import type { ConnectionStatus, CredService } from '@/lib/client/types';
import { EmptyState, PageHead, Panel } from './shared';

// Credentials — the SAME data-class abstraction as memory (#207). The memory page
// lists namespaces → categories (the taxonomy); this lists stored credential
// services → categories (the catalog). Both are list-then-categorize over the
// master's own real data; the secret is decrypt-on-read and never shown here.
export function CredentialsPage({
  credentials,
  status,
  storing,
  onStore,
}: {
  credentials: CredService[];
  status: ConnectionStatus;
  storing: boolean;
  onStore: (service: string, secret: string) => void;
}) {
  const [service, setService] = useState('');
  const [secret, setSecret] = useState('');
  const connected = status.kind === 'connected';

  const byCategory: Record<string, CredService[]> = {};
  for (const c of credentials) (byCategory[c.category] ??= []).push(c);
  const categories = Object.keys(byCategory).sort();

  const submit = () => {
    if (service.trim() && secret) {
      onStore(service.trim().toLowerCase(), secret);
      setService('');
      setSecret('');
    }
  };

  return (
    <>
      <PageHead
        crumb="credentials · per-service · catalog-categorized"
        title={<><span className="muted serif">/</span> credentials</>}
        desc="Your vaulted credentials — the same data-class abstraction as memory. Each is categorized by the shared catalog (stripe → payments, openrouter → ai-services); sensitive categories (payments, access-control, health, …) are flagged. An agent fetches a credential only with a granted cred:<service> scope; the secret is decrypt-on-read and never shown here."
      />

      {!connected ? (
        <EmptyState
          status={status}
          title="credentials unavailable"
          hint="Master credentials are listed + vaulted through the daemon (GET/POST /v1/master/credentials). Connect a daemon to populate this view."
        />
      ) : (
        <>
          <Panel title="── vault a credential">
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', padding: '4px 0' }}>
              <input
                placeholder="service (e.g. openrouter, stripe)"
                value={service}
                onChange={(e) => setService(e.target.value)}
                style={{ flex: '1 1 180px', padding: '8px 10px', fontSize: 12.5, border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)' }}
              />
              <input
                type="password"
                placeholder="secret / API key"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
                style={{ flex: '1 1 220px', padding: '8px 10px', fontSize: 12.5, border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)' }}
              />
              <button className="btn primary" disabled={storing || !service.trim() || !secret} onClick={submit}>
                {storing ? 'vaulting…' : '⊕ vault'}
              </button>
            </div>
            <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
              Stored encrypted (AES-256-GCM, K3 KEK) at <code>bots/&lt;you&gt;/credentials/&lt;service&gt;.enc</code> via the real
              chain (cap-mint → STS → cred worker → S3) — categorized on store by the catalog.
            </div>
          </Panel>

          {categories.length === 0 ? (
            <div className="empty-memory">
              <div className="serif" style={{ fontSize: 40, fontStyle: 'italic', color: 'var(--ink-faint)', marginBottom: 4 }}>∅</div>
              <h2 className="serif" style={{ fontSize: 22, fontStyle: 'italic', margin: '0 0 8px' }}>No credentials vaulted yet.</h2>
              <p style={{ fontSize: 12.5, color: 'var(--ink-dim)', maxWidth: 440, margin: '0 auto' }}>
                Vault one above — it&apos;s categorized into the same taxonomy your agents are scoped against, exactly like a
                memory namespace.
              </p>
            </div>
          ) : (
            <>
              <div className="stats">
                <div className="stat"><div className="v">{credentials.length}</div><div className="k">credentials</div></div>
                <div className="stat"><div className="v">{categories.length}</div><div className="k">categories</div></div>
                <div className="stat"><div className="v">{credentials.filter((c) => c.sensitivity === 'sensitive').length}</div><div className="k">sensitive</div></div>
              </div>

              {categories.map((cat) => (
                <Panel key={cat} title={`── ${cat}`} flush>
                  <table className="tab">
                    <thead>
                      <tr><th>service</th><th>category</th><th>sensitivity</th><th>scope</th></tr>
                    </thead>
                    <tbody>
                      {byCategory[cat].map((c) => (
                        <tr key={c.service}>
                          <td><span className="mono" style={{ fontWeight: 500 }}>{c.service}</span></td>
                          <td className="muted">{c.category}</td>
                          <td><span className={`chip ${c.sensitivity === 'sensitive' ? 'warn' : 'ok'}`}>{c.sensitivity}</span></td>
                          <td className="mono muted">cred:{c.service}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Panel>
              ))}
            </>
          )}
        </>
      )}
    </>
  );
}
