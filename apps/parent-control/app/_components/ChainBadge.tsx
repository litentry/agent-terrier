'use client';

import { useEffect, useState } from 'react';
import { useClient, useConnectionStatus } from '@/lib/ClientProvider';
import type { ChainInfo } from '@/lib/client/types';

/**
 * Persistent top-right badge: the chain + RPC node the daemon operates against.
 *
 * Sourced LIVE from `GET /v1/chain/info` (the daemon's resolved chain profile) —
 * never hardcoded. Mounted in the root layout so it shows on EVERY screen, the
 * onboarding flow included (App.tsx early-returns the onboarding screen before its
 * own chrome renders, so an in-app indicator alone is invisible there). When the
 * daemon is unreachable it shows "daemon offline" rather than any baked-in default.
 */
export function ChainBadge() {
  const client = useClient();
  const status = useConnectionStatus();
  const [info, setInfo] = useState<ChainInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const r = await client.getChainInfo();
        if (!cancelled && r.ok) setInfo(r.data);
      } catch {
        // daemon unreachable — keep the last known value; the dot shows offline.
      }
    };
    void load();
    const id = setInterval(() => void load(), 20_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [client]);

  const online = status.kind === 'connected';
  const rpcHost = info ? hostOf(info.rpc) : null;

  return (
    <div
      className="chain-badge"
      title={
        info
          ? `chain ${info.name} · id ${info.chainId} · RPC ${info.rpc}`
          : 'daemon chain info unavailable'
      }
    >
      <span
        className="chain-badge__dot"
        style={{ background: online ? 'var(--ok)' : 'var(--danger)' }}
        aria-hidden
      />
      {info ? (
        <>
          <strong>{info.display || info.name}</strong>
          <span className="chain-badge__sep">·</span>
          <span title="chain id">#{info.chainId}</span>
          {rpcHost ? (
            <>
              <span className="chain-badge__sep">·</span>
              <span title={info.rpc}>{rpcHost}</span>
            </>
          ) : null}
        </>
      ) : (
        <span className="chain-badge__muted">{online ? 'chain…' : 'daemon offline'}</span>
      )}
    </div>
  );
}

/** Show just the host of an RPC URL (e.g. `base-rpc.publicnode.com`); the full URL is in the title. */
function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
