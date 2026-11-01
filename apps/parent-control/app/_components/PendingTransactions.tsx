'use client';
import { useEffect, useState } from 'react';
import type { CoreBackend } from '@/lib/client/core';

export function PendingTransactions({ client, onConfirmed }: { client: CoreBackend; onConfirmed: () => void }) {
  const [pending, setPending] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    const refresh = () => setPending(client.pendingTransactions());
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  }, [client]);
  if (!pending.length) return null;
  const check = async () => {
    setBusy(true); setError('');
    try {
      for (const id of pending) {
        const result = await client.confirmPendingTransaction(id);
        if (!result.ok) { setError(result.status.detail ?? result.status.reason); return; }
      }
      setPending(client.pendingTransactions());
      onConfirmed();
    } finally { setBusy(false); }
  };
  return <section className="banner" aria-label="Pending transactions">
    <span>{pending.length} account change(s) need confirmation or a follow-up save. Keep this tab open until they finish.</span>
    <button className="btn sm" disabled={busy} onClick={() => void check()}>{busy ? 'Checking…' : 'Check confirmation'}</button>
    {error && <span role="alert">{error}</span>}
  </section>;
}
