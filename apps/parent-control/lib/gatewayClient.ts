// #418 — the WeChat gateway admin client. Talks to the DAEMON proxy
// (`/v1/master/gateway/*`), which injects the gateway admin bearer server-side
// (the browser never holds it). Every wire shape is GENERATED from the Rust
// `agentkeys-protocol` structs via ts-rs (lib/generated/*) — a Rust-side rename
// regenerates the .ts and breaks this compile (the #275 rung-3 drift gate).
import type { GatewayStatusView } from '@/lib/generated/GatewayStatusView';
import type { GatewayLoginStartResponse } from '@/lib/generated/GatewayLoginStartResponse';
import type { GatewayLoginStatusResponse } from '@/lib/generated/GatewayLoginStatusResponse';
import type { GatewayBindInviteRequest } from '@/lib/generated/GatewayBindInviteRequest';
import type { GatewayBindInviteResponse } from '@/lib/generated/GatewayBindInviteResponse';
import type { GatewayPendingBindView } from '@/lib/generated/GatewayPendingBindView';
import type { GatewayApproveRequest } from '@/lib/generated/GatewayApproveRequest';
import type { GatewayBindRejectRequest } from '@/lib/generated/GatewayBindRejectRequest';
import type { GatewayApproveResponse } from '@/lib/generated/GatewayApproveResponse';
import type { ContactSummary } from '@/lib/generated/ContactSummary';
import type { GatewayContactUpdateRequest } from '@/lib/generated/GatewayContactUpdateRequest';
import type { GatewayContactRevokeRequest } from '@/lib/generated/GatewayContactRevokeRequest';
import type { GatewayMonitorResponse } from '@/lib/generated/GatewayMonitorResponse';
import type { GatewayHistoryResponse } from '@/lib/generated/GatewayHistoryResponse';
import type { GatewayActivityResponse } from '@/lib/generated/GatewayActivityResponse';

const DEFAULT_BASE_URL = 'http://localhost:3114';

function baseUrl(): string {
  return (process.env.NEXT_PUBLIC_AGENTKEYS_DAEMON_URL ?? DEFAULT_BASE_URL).replace(/\/$/, '');
}

/** Front-end gateway tracing (#419 connect/login diagnostics). OFF by default —
 *  the contacts/channels pages poll `status`/`contacts`/`monitor` on a timer, so
 *  leaving it on floods DevTools (every request + response is logged). Turn it on
 *  from the Contacts page's "debug logs" toggle (or `localStorage.gatewayDebug =
 *  '1'` by hand); the preference persists across reloads and gates gwlog()
 *  app-wide. Once on, this is how you tell a fresh `wait → scaned → connected`
 *  from a re-scan that returns `already_bound` (the bot was already connected;
 *  the phone's authorize page is leftover and can be closed). */
const GATEWAY_DEBUG_KEY = 'gatewayDebug';

/** Whether gateway request/response tracing is currently enabled (opt-in — the
 *  key must be exactly `'1'`; unset / any other value / no localStorage = off). */
export function gatewayDebugEnabled(): boolean {
  try {
    return globalThis.localStorage?.getItem(GATEWAY_DEBUG_KEY) === '1';
  } catch {
    return false; // no localStorage (SSR/no-DOM) — stay quiet
  }
}

/** Persist the gateway-trace preference (survives reloads). `false` removes the
 *  key so the state reads back as the default-off. */
export function setGatewayDebug(on: boolean): void {
  try {
    if (on) globalThis.localStorage?.setItem(GATEWAY_DEBUG_KEY, '1');
    else globalThis.localStorage?.removeItem(GATEWAY_DEBUG_KEY);
  } catch {
    /* no localStorage — nothing to persist */
  }
}

export function gwlog(...args: unknown[]): void {
  if (!gatewayDebugEnabled()) return;
  // eslint-disable-next-line no-console
  console.info('%c[gateway]', 'color:#0a7;font-weight:600', ...args);
}

/** A gateway call outcome: `ok` with the typed body, or a reason + detail the
 *  UI shows verbatim (the daemon/gateway both answer `{ok:false, reason, detail}`). */
export type GatewayResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: string; detail?: string; status: number };

async function call<T>(
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
): Promise<GatewayResult<T>> {
  gwlog('→', method, path, body ?? '');
  let resp: Response;
  try {
    resp = await fetch(`${baseUrl()}${path}`, {
      method,
      cache: 'no-store',
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    gwlog('✗', method, path, 'network:', (e as Error).message);
    return { ok: false, reason: 'daemon_unreachable', detail: (e as Error).message, status: 0 };
  }
  const text = await resp.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    // non-JSON error body (e.g. a plain-text 502) — surface it as the detail.
    gwlog('✗', method, path, resp.status, 'non-JSON body:', text.slice(0, 200));
    return { ok: false, reason: 'bad_response', detail: text.slice(0, 200), status: resp.status };
  }
  gwlog('←', method, path, resp.status, json);
  const obj = (json ?? {}) as Record<string, unknown>;
  if (!resp.ok || obj.ok === false) {
    // The gateway WORKER answers {ok:false, reason, detail}; the DAEMON proxy's
    // OWN short-circuits (no master session / gateway-not-configured) answer
    // {error} (shared `pairing_err` shape). Read both so the UI shows the real
    // message, never a bare http_503.
    const errStr = typeof obj.error === 'string' ? obj.error : undefined;
    return {
      ok: false,
      reason: (typeof obj.reason === 'string' ? obj.reason : undefined) ?? errStr ?? `http_${resp.status}`,
      detail: (typeof obj.detail === 'string' ? obj.detail : undefined) ?? errStr,
      status: resp.status,
    };
  }
  return { ok: true, value: json as T };
}

/** True when a failure means the gateway simply isn't wired to this daemon yet —
 *  a calm "not set up" state, not an error. This is the normal local-dev daemon
 *  (no `AGENTKEYS_WORKER_WEIXIN_URL` / admin token) or a gateway worker that's
 *  down; distinct from `daemon_unreachable` (the local daemon itself is off). */
export function gatewayNotConfigured(r: { reason: string; detail?: string; status: number }): boolean {
  const s = `${r.reason} ${r.detail ?? ''}`.toLowerCase();
  return (
    r.status === 503 ||
    s.includes('not-configured') ||
    s.includes('not configured') ||
    s.includes('admin_disabled') ||
    s.includes('admin-not-configured')
  );
}

export const gatewayClient = {
  status: () => call<GatewayStatusView>('GET', '/v1/master/gateway/status'),

  // Login ceremony (the operator scans with the SPARE account). `loginStatus`
  // is ONE server-held poll step (~35 s) — the UI loops until a terminal status.
  loginStart: () => call<GatewayLoginStartResponse>('POST', '/v1/master/gateway/login/start'),
  loginStatus: (loginId: string) =>
    call<GatewayLoginStatusResponse>(
      'GET',
      `/v1/master/gateway/login/status?login_id=${encodeURIComponent(loginId)}`,
    ),
  loginVerify: (loginId: string, verifyCode: string) =>
    call<{ ok: boolean }>('POST', '/v1/master/gateway/login/verify', {
      login_id: loginId,
      verify_code: verifyCode,
    } satisfies { login_id: string; verify_code: string }),

  // Operator disconnect — clears the bot token (runtime + secrets) → bot goes
  // OFFLINE and the next connect is a clean QR from scratch (re-test the scan).
  disconnect: () =>
    call<{ ok: boolean; online?: boolean }>('POST', '/v1/master/gateway/login/disconnect'),

  // Bind ceremony (D5 — the master invites, the member echoes the code, the
  // master approves).
  bindInvite: (req: GatewayBindInviteRequest) =>
    call<GatewayBindInviteResponse>('POST', '/v1/master/gateway/bind/invite', req),
  bindPending: () =>
    call<{ ok: boolean; pending: GatewayPendingBindView[] }>(
      'GET',
      '/v1/master/gateway/bind/pending',
    ),
  bindApprove: (req: GatewayApproveRequest) =>
    call<GatewayApproveResponse>('POST', '/v1/master/gateway/bind/approve', req),

  // Operator WITHDRAWS an invite (open or claimed) before it binds — the code
  // dies; a claimed sender gets unknown-sender silence from then on.
  bindReject: (bindCode: string) =>
    call<{ ok: boolean; removed?: boolean }>('POST', '/v1/master/gateway/bind/reject', {
      bind_code: bindCode,
    } satisfies GatewayBindRejectRequest),

  contacts: () =>
    call<{ ok: boolean; contacts: ContactSummary[] }>('GET', '/v1/master/gateway/contacts'),

  // Live message monitor (#1) — poll with the last cursor; returns turns with
  // seq >= after + the next cursor. A fresh poll (after=0) returns the ring.
  monitor: (after: number) =>
    call<GatewayMonitorResponse>('GET', `/v1/master/gateway/monitor?after=${after}`),

  // Durable message history (#419) — newest-first, backward-paginated. Omit
  // `before` for the newest page; pass the response's `next_before_ts` to page
  // older. Survives restarts (read from the append-only log).
  history: (before?: number, limit = 50) =>
    call<GatewayHistoryResponse>(
      'GET',
      `/v1/master/gateway/history?limit=${limit}${before ? `&before=${before}` : ''}`,
    ),

  // Durable control-action audit trail (#419) — invite / claim / bound /
  // rejected / revoked, newest-first. Survives daemon + worker restarts.
  activity: (before?: number, limit = 50) =>
    call<GatewayActivityResponse>(
      'GET',
      `/v1/master/gateway/activity?limit=${limit}${before ? `&before=${before}` : ''}`,
    ),

  // Operator edits a bound contact's routing policy (tier/reach); omit a field
  // to leave it unchanged.
  contactsUpdate: (req: GatewayContactUpdateRequest) =>
    call<{ ok: boolean; contact?: ContactSummary }>(
      'POST',
      '/v1/master/gateway/contacts/update',
      req,
    ),

  // Operator unbinds a contact — they can no longer reach any agent.
  contactsRevoke: (contactId: string) =>
    call<{ ok: boolean; removed?: boolean }>('POST', '/v1/master/gateway/contacts/revoke', {
      contact_id: contactId,
    } satisfies GatewayContactRevokeRequest),
};

/** The terminal login statuses — the poll loop stops on any of these. */
export const TERMINAL_LOGIN_STATUSES = [
  'connected',
  'already_bound',
  'expired',
  'verify_code_blocked',
  'failed',
] as const;

export function isTerminalLoginStatus(s: string): boolean {
  return (TERMINAL_LOGIN_STATUSES as readonly string[]).includes(s);
}
