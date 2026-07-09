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
import type { GatewayApproveResponse } from '@/lib/generated/GatewayApproveResponse';
import type { ContactSummary } from '@/lib/generated/ContactSummary';

const DEFAULT_BASE_URL = 'http://localhost:3114';

function baseUrl(): string {
  return (process.env.NEXT_PUBLIC_AGENTKEYS_DAEMON_URL ?? DEFAULT_BASE_URL).replace(/\/$/, '');
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
  let resp: Response;
  try {
    resp = await fetch(`${baseUrl()}${path}`, {
      method,
      cache: 'no-store',
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    return { ok: false, reason: 'daemon_unreachable', detail: (e as Error).message, status: 0 };
  }
  const text = await resp.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    // non-JSON error body (e.g. a plain-text 502) — surface it as the detail.
    return { ok: false, reason: 'bad_response', detail: text.slice(0, 200), status: resp.status };
  }
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

  contacts: () =>
    call<{ ok: boolean; contacts: ContactSummary[] }>('GET', '/v1/master/gateway/contacts'),
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
