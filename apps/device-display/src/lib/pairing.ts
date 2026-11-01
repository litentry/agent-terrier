// The device's lifecycle on one broker (arch.md §10.2): boot → resolve (already
// bound? mint a session) → else request a pairing code → poll until the owner
// claims + approves → bound. Pure helpers here; the wasm-backed calls are in
// client.ts, the screen in DisplayApp.tsx.

export interface DeviceSession {
  session_jwt: string;
  actor_omni: string;
  operator_omni: string;
  device_key_hash: string;
  label: string | null;
  /** Unix seconds the session was minted (re-resolve after ~4 h). */
  minted_at: number;
}

export interface PendingPairing {
  request_id: string;
  pairing_code: string;
  /** Unix seconds (the broker's 600 s TTL). */
  expires_at: number;
}

export type Phase =
  | { kind: 'unconfigured' }
  | { kind: 'booting' }
  | { kind: 'pairing'; pending: PendingPairing }
  | { kind: 'bound'; session: DeviceSession }
  | { kind: 'error'; message: string; retryable: boolean };

interface BrokerSessionLike {
  session_jwt?: string | null;
  actor_omni?: string | null;
  operator_omni?: string | null;
  device_key_hash?: string | null;
  label?: string | null;
}

/** A bound session from a poll/resolve answer, or null while it is `pending`. */
export function sessionFromBroker(r: BrokerSessionLike, nowSecs: number): DeviceSession | null {
  if (!r.session_jwt || !r.actor_omni || !r.operator_omni) return null;
  return {
    session_jwt: r.session_jwt,
    actor_omni: r.actor_omni,
    operator_omni: r.operator_omni,
    device_key_hash: r.device_key_hash ?? '',
    label: r.label ?? null,
    minted_at: nowSecs,
  };
}

export function isExpired(expiresAt: number, nowSecs: number): boolean {
  return expiresAt > 0 && nowSecs >= expiresAt;
}

/** Re-mint well inside the delegate/device TTL (the broker's shortest is 5 h). */
export const SESSION_REFRESH_SECS = 4 * 3600;

export function sessionStale(s: DeviceSession, nowSecs: number): boolean {
  return nowSecs - s.minted_at >= SESSION_REFRESH_SECS;
}

export const sessionKey = (brokerUrl: string) => `agentkeys.display.session:${brokerUrl}`;
export const pairingKey = (brokerUrl: string) => `agentkeys.display.pairing:${brokerUrl}`;

/** The wasm layer rejects with the broker's error string (`… status=401 body=…`). */
export function describeError(e: unknown): { message: string; status: number | null; retryable: boolean } {
  const message = e instanceof Error ? e.message : String(e);
  const m = /status=(\d{3})/.exec(message);
  const status = m ? Number(m[1]) : null;
  // 4xx = the broker refused us (not bound / bad PoP / expired): re-pair, not retry.
  const retryable = status === null || status >= 500;
  return { message, status, retryable };
}

/** The QR payload: the code the owner types, plus the label + feed the device
 *  wants — a scanner-equipped console can pre-fill its claim form from it. */
export function pairingUri(code: string, label: string, feedId: string): string {
  const q = new URLSearchParams({ code, label, feed: feedId });
  return `agentkeys-pair://claim?${q.toString()}`;
}
