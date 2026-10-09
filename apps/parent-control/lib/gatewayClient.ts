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
import type { GatewayContactWelcomeRequest } from '@/lib/generated/GatewayContactWelcomeRequest';
import type { GatewayContactWelcomeResponse } from '@/lib/generated/GatewayContactWelcomeResponse';
import type { GatewayMonitorResponse } from '@/lib/generated/GatewayMonitorResponse';
import type { GatewayHistoryResponse } from '@/lib/generated/GatewayHistoryResponse';
import type { GatewayActivityResponse } from '@/lib/generated/GatewayActivityResponse';
import type { GatewayRouterSettingsRequest } from '@/lib/generated/GatewayRouterSettingsRequest';
import type { GatewayRouterSettingsResponse } from '@/lib/generated/GatewayRouterSettingsResponse';
import type { GatewayContactsResponse } from '@/lib/generated/GatewayContactsResponse';
import type { GatewayChannelsResponse } from '@/lib/generated/GatewayChannelsResponse';
import type { GatewayChannelUpdateRequest } from '@/lib/generated/GatewayChannelUpdateRequest';
import type { ChannelDoc } from '@/lib/generated/ChannelDoc';
import type { RouterViewWire } from '@/lib/routerView';
import type { HostedGatewayRequest } from '@/lib/generated/HostedGatewayRequest';
import type { GatewayLoginVerifyRequest } from '@/lib/generated/GatewayLoginVerifyRequest';

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
  if (process.env.NEXT_PUBLIC_AGENTKEYS_BACKEND === 'core') {
    const request = hostedRequest(method, path, body);
    return request
      ? callHosted<T>(request)
      : { ok: false, reason: 'gateway_operation_not_supported', status: 400 };
  }
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

export interface HostedGatewayAccess {
  sessionKey(): string | null;
  request(request: HostedGatewayRequest): Promise<GatewayResult<unknown>>;
  readRegistry(): Promise<{ value: unknown; revision: string } | null>;
  writeRegistry(value: unknown, expectedRevision: string): Promise<void>;
  afterMutation?(request: HostedGatewayRequest): Promise<void>;
}

let hostedGatewayAccess: HostedGatewayAccess | null = null;
let hostedRegistrySession: string | null = null;
let hostedGatewayQueue: Promise<void> = Promise.resolve();

export function setHostedGatewayAccess(access: HostedGatewayAccess | null): void {
  hostedGatewayAccess = access;
  hostedRegistrySession = null;
  hostedGatewayQueue = Promise.resolve();
}

function hostedRequest(method: 'GET' | 'POST', path: string, body: unknown): HostedGatewayRequest | null {
  const [route, query] = path.split('?');
  const params = new URLSearchParams(query);
  const payload = body ?? {};
  if (method === 'GET') {
    switch (route) {
      case '/v1/master/gateway/status': return { operation: 'status' };
      case '/v1/master/gateway/contacts': return { operation: 'contacts' };
      case '/v1/master/gateway/channels': return { operation: 'channels' };
      case '/v1/master/gateway/bind/pending': return { operation: 'bind_pending' };
      case '/v1/master/gateway/router': return { operation: 'router' };
      case '/v1/master/gateway/monitor': return { operation: 'monitor', payload: { after: Number(params.get('after') ?? 0) } };
      case '/v1/master/gateway/login/status': return { operation: 'login_status', payload: { login_id: params.get('login_id') ?? '' } };
      case '/v1/master/gateway/history':
      case '/v1/master/gateway/activity': return {
        operation: route.endsWith('/history') ? 'history' : 'activity',
        payload: { before: params.has('before') ? Number(params.get('before')) : null, limit: params.has('limit') ? Number(params.get('limit')) : null },
      };
      default: return null;
    }
  }
  switch (route) {
    case '/v1/master/gateway/login/start': return { operation: 'login_start', payload: { contact_id: (payload as { contact_id?: string }).contact_id ?? null } };
    case '/v1/master/gateway/login/verify': return { operation: 'login_verify', payload: payload as GatewayLoginVerifyRequest };
    case '/v1/master/gateway/login/disconnect': return { operation: 'login_disconnect' };
    case '/v1/master/gateway/bind/invite': return { operation: 'bind_invite', payload: payload as GatewayBindInviteRequest };
    case '/v1/master/gateway/bind/approve': return { operation: 'bind_approve', payload: payload as GatewayApproveRequest };
    case '/v1/master/gateway/bind/reject': return { operation: 'bind_reject', payload: payload as GatewayBindRejectRequest };
    case '/v1/master/gateway/contacts/update': return { operation: 'contacts_update', payload: payload as GatewayContactUpdateRequest };
    case '/v1/master/gateway/contacts/revoke': return { operation: 'contacts_revoke', payload: payload as GatewayContactRevokeRequest };
    case '/v1/master/gateway/contacts/welcome': return { operation: 'contacts_welcome', payload: payload as GatewayContactWelcomeRequest };
    case '/v1/master/gateway/channels/update': return { operation: 'channels_update', payload: payload as GatewayChannelUpdateRequest };
    case '/v1/master/gateway/router/settings': return { operation: 'router_settings', payload: payload as GatewayRouterSettingsRequest };
    default: return null;
  }
}

function registryIsEmpty(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Contact registry is not a valid document.');
  const registry = value as Record<string, unknown>;
  let empty = true;
  for (const field of ['bound', 'invites', 'pending', 'channels', 'apps']) {
    if (registry[field] !== undefined && !Array.isArray(registry[field])) throw new Error('Contact registry is not a valid document.');
    if (Array.isArray(registry[field]) && registry[field].length > 0) empty = false;
  }
  return empty && registry.router == null;
}

class HostedGatewayFailure extends Error {
  constructor(readonly result: Extract<GatewayResult<never>, { ok: false }>) {
    super(result.detail ?? result.reason);
  }
}

function checkHostedSession(access: HostedGatewayAccess, sessionKey: string): void {
  if (hostedGatewayAccess !== access || access.sessionKey() !== sessionKey) {
    throw new HostedGatewayFailure({ ok: false, reason: 'master_session_required', detail: 'Please sign in again.', status: 401 });
  }
}

async function requestHosted<T>(access: HostedGatewayAccess, sessionKey: string, request: HostedGatewayRequest): Promise<T> {
  checkHostedSession(access, sessionKey);
  const response = await access.request(request);
  checkHostedSession(access, sessionKey);
  if (!response.ok) throw new HostedGatewayFailure(response);
  return response.value as T;
}

async function reconcileHostedRegistry(access: HostedGatewayAccess, sessionKey: string): Promise<void> {
  if (hostedRegistrySession === sessionKey) return;
  const registry = await requestHosted<unknown>(access, sessionKey, { operation: 'registry_export' });
  checkHostedSession(access, sessionKey);
  const durable = await access.readRegistry();
  checkHostedSession(access, sessionKey);
  if (!registryIsEmpty(registry)) {
    await access.writeRegistry(registry, durable?.revision ?? '');
  } else if (durable && !registryIsEmpty(durable.value)) {
    await requestHosted(access, sessionKey, { operation: 'registry_restore', payload: { registry: durable.value } });
  }
  checkHostedSession(access, sessionKey);
  hostedRegistrySession = sessionKey;
}

const REGISTRY_MUTATIONS = new Set<HostedGatewayRequest['operation']>([
  'bind_invite', 'bind_approve', 'bind_reject', 'contacts_update', 'contacts_revoke',
  'contacts_welcome', 'channels_update', 'router_settings',
]);

async function executeHosted<T>(access: HostedGatewayAccess, sessionKey: string, request: HostedGatewayRequest): Promise<GatewayResult<T>> {
  let applied = false;
  let backedUp = false;
  try {
    checkHostedSession(access, sessionKey);
    const mutation = REGISTRY_MUTATIONS.has(request.operation);
    const couldBind = request.operation === 'login_status';
    if (mutation || couldBind || request.operation === 'contacts' || request.operation === 'channels') {
      await reconcileHostedRegistry(access, sessionKey);
    }
    const baseline = mutation || couldBind ? await access.readRegistry() : null;
    checkHostedSession(access, sessionKey);
    const value = await requestHosted<T>(access, sessionKey, request);
    applied = mutation || (couldBind && (value as { status?: string })?.status === 'connected');
    if (applied) {
      const registry = await requestHosted<unknown>(access, sessionKey, { operation: 'registry_export' });
      registryIsEmpty(registry);
      checkHostedSession(access, sessionKey);
      await access.writeRegistry(registry, baseline?.revision ?? '');
      checkHostedSession(access, sessionKey);
      backedUp = true;
      await access.afterMutation?.(request);
      checkHostedSession(access, sessionKey);
    }
    return { ok: true, value };
  } catch (error) {
    hostedRegistrySession = null;
    if (error instanceof HostedGatewayFailure && !applied) return error.result;
    return {
      ok: false,
      reason: backedUp ? 'gateway_followthrough_failed' : applied ? 'gateway_backup_failed' : 'gateway_registry_unavailable',
      detail: backedUp
        ? `The change and its backup were saved, but the running apps could not be refreshed. Retry the channel update to synchronize the apps. ${String(error)}`
        : applied
        ? `The change was applied to the contact gate, but its durable backup failed. Refresh Contacts to retry the backup before making another change. ${String(error)}`
        : `Contact registry could not be synchronized. ${String(error)}`,
      status: applied ? 502 : 503,
    };
  }
}

function callHosted<T>(request: HostedGatewayRequest): Promise<GatewayResult<T>> {
  const access = hostedGatewayAccess;
  const sessionKey = access?.sessionKey();
  if (!access || !sessionKey) return Promise.resolve({ ok: false, reason: 'master_session_required', detail: 'Please sign in again.', status: 401 });
  const serialized = REGISTRY_MUTATIONS.has(request.operation) || ['contacts', 'channels', 'login_status'].includes(request.operation);
  if (!serialized) return executeHosted<T>(access, sessionKey, request);
  const pending = hostedGatewayQueue.then(() => executeHosted<T>(access, sessionKey, request));
  hostedGatewayQueue = pending.then(() => undefined, () => undefined);
  return pending;
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
  // One bot per member (2026-09-11): `contactId` names the invite the QR is minted
  // for — the scan binds that contact. Absent = the legacy owner login.
  loginStart: (contactId?: string) =>
    call<GatewayLoginStartResponse>('POST', '/v1/master/gateway/login/start', contactId ? { contact_id: contactId } : undefined),
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

  contacts: () => call<GatewayContactsResponse>('GET', '/v1/master/gateway/contacts'),

  // Household channels — the channel documents the router reads (what each
  // channel is for, the apps bound to it, the members' rows). One write per
  // call; every field left out is untouched; every write is live.
  channels: () => call<GatewayChannelsResponse>('GET', '/v1/master/gateway/channels'),
  channelUpdate: (req: Partial<GatewayChannelUpdateRequest> & { channel_id: string }) =>
    call<{ ok: boolean; changed?: boolean; channel?: ChannelDoc }>('POST', '/v1/master/gateway/channels/update', {
      remove: false,
      ...req,
    }),

  // Live message monitor (#1) — poll with the last cursor; returns turns with
  // seq >= after + the next cursor. A fresh poll (after=0) returns the ring.
  monitor: (after: number) =>
    call<GatewayMonitorResponse>('GET', `/v1/master/gateway/monitor?after=${after}`),

  // #722 — the Route page: what the router sends the decision model (Kev /
  // Jev), the models the household may switch between, and the last turns
  // that consulted one. A gate older than the switch omits its fields — read
  // it through `normalizeRouterView` (lib/routerView.ts).
  router: () => call<RouterViewWire>('GET', '/v1/master/gateway/router'),
  // The household picks the model that routes (one the gate offers) and turns
  // compare mode on or off — a field left out is unchanged; live next turn.
  routerSettings: (req: GatewayRouterSettingsRequest) =>
    call<GatewayRouterSettingsResponse>('POST', '/v1/master/gateway/router/settings', req),

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

  // Operator edits a bound contact's tier and channel rows; omit a field to
  // leave it unchanged (`channels` replaces the member's rows).
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
  /** (Re)send a contact's bound acknowledgement — now, or armed for their next message. */
  contactsWelcome: (contactId: string) =>
    call<GatewayContactWelcomeResponse>('POST', '/v1/master/gateway/contacts/welcome', {
      contact_id: contactId,
    } satisfies GatewayContactWelcomeRequest),
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
