'use client';

import { EmptyBackend } from './empty';
import type { ConnectionStatus, DisconnectedStatus, EmailVerifyStart, EmailVerifyStatus, OnboardingState, Result } from './types';
import type { EmailChallenge } from '../generated/EmailChallenge';
import type { MasterSession } from '../generated/MasterSession';
import type { MasterSessionInfo } from '../generated/MasterSessionInfo';

// Lazy, client-only WebCore instances, memoized per broker URL on top of the
// shared module loader (lib/client/wasm-module.ts — also used by the
// DaemonBackend plant path, #275). Keying by URL means a second CoreBackend
// with a different broker gets its own instance; on failure the entry is
// evicted so the next call retries (a transient load/broker failure must not
// poison it).
import { loadWasmModule } from './wasm-module';

type LoadedCore = import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core').WebCore;
const coreByUrl = new Map<string, Promise<LoadedCore>>();
function loadCore(brokerUrl: string): Promise<LoadedCore> {
  let p = coreByUrl.get(brokerUrl);
  if (!p) {
    p = loadWasmModule().then((wasm) => new wasm.WebCore(brokerUrl));
    coreByUrl.set(brokerUrl, p);
    void p.catch(() => coreByUrl.delete(brokerUrl));
  }
  return p;
}

/**
 * CoreBackend — the phone-first host (browser → WASM core → broker DIRECTLY, no
 * daemon). X1 of docs/plan/web-flow/wire-real-paths.md: it loads the
 * `agentkeys-web-core` WASM module and exposes the broker calls (cap-mint,
 * pairing) the onboarding/pairing slices use.
 *
 * The `AgentKeysClient` READ endpoints (actors, audit, memory, …) are wired in
 * the later W-phases, so they inherit EmptyBackend's disconnected behaviour for
 * now (the UI identifies unavailable data); `status()` exercises the full path
 * (load WASM + probe the broker) and reports what happened.
 */
export class CoreBackend extends EmptyBackend {
  private brokerUrl: string;
  private masterSession: MasterSession | null = null;
  private loginGeneration = 0;
  private email = '';
  private pendingLogin: { requestId: string; expiresAt: number } | null = null;

  protected disconnected<T>(): Result<T> {
    return { ok: false, status: { kind: 'disconnected', reason: 'unsupported', detail: HOSTED_FEATURES_UNAVAILABLE } };
  }

  async startEmailVerify(email: string): Promise<Result<EmailVerifyStart>> {
    try {
      const challenge = await this.requestEmailLogin(email);
      return { ok: true, data: { requestId: challenge.request_id } };
    } catch (error) {
      return loginFailure(error);
    }
  }

  async pollEmailVerify(requestId: string): Promise<Result<EmailVerifyStatus>> {
    if (!this.pendingLogin || this.pendingLogin.requestId !== requestId) return loginFailure(new Error('Sign-in was cancelled.'));
    if (Date.now() >= this.pendingLogin.expiresAt) {
      this.clearHostedSession();
      return loginFailure(new Error('The sign-in link expired. Please try again.'));
    }
    const generation = this.loginGeneration;
    try {
      const session = await this.pollEmailLogin(requestId);
      return { ok: true, data: session ? { status: 'verified', omniAccount: session.omni_account } : { status: 'pending' } };
    } catch (error) {
      if (generation === this.loginGeneration) this.clearHostedSession();
      return loginFailure(error);
    }
  }

  async getOnboardingState(): Promise<Result<OnboardingState>> {
    try {
      const session = await this.hostedSessionInfo();
      return { ok: true, data: session
        ? { identity: 'verified', email: this.email, omni: session.omni_account, k11: 'none', session: 'active' }
        : { identity: 'none', k11: 'none', session: 'none' } };
    } catch (error) {
      return loginFailure(error);
    }
  }

  async logout(): Promise<Result<void>> {
    this.clearHostedSession();
    return { ok: true, data: undefined };
  }

  async requestEmailLogin(email: string): Promise<EmailChallenge> {
    this.clearHostedSession();
    const generation = this.loginGeneration;
    const challenge = await (await loadCore(this.brokerUrl)).emailRequest(email);
    if (generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
    this.email = email.trim();
    this.pendingLogin = { requestId: challenge.request_id, expiresAt: Date.now() + challenge.expires_in_seconds * 1000 };
    return challenge;
  }

  async pollEmailLogin(requestId: string): Promise<MasterSessionInfo | null> {
    const generation = this.loginGeneration;
    const core = await loadCore(this.brokerUrl);
    const session: MasterSession | null | undefined = await core.finishEmailLogin(requestId);
    if (!session) return null;
    const info: MasterSessionInfo = await core.sessionInfo(session.session_jwt);
    if (generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
    if (info.expires_at * 1000 <= Date.now()) throw new Error('The sign-in link expired. Please try again.');
    this.masterSession = session;
    return info;
  }

  clearHostedSession(): void {
    this.loginGeneration += 1;
    this.masterSession = null;
    this.pendingLogin = null;
    this.email = '';
  }

  async hostedSessionInfo(): Promise<MasterSessionInfo | null> {
    if (!this.masterSession) return null;
    if (this.masterSession.expires_at * 1000 <= Date.now()) {
      this.clearHostedSession();
      return null;
    }
    const generation = this.loginGeneration;
    const session = this.masterSession;
    try {
      const info = await (await loadCore(this.brokerUrl)).sessionInfo(session.session_jwt);
      if (generation !== this.loginGeneration || session !== this.masterSession) return null;
      if (info.expires_at * 1000 <= Date.now()) { this.clearHostedSession(); return null; }
      return info;
    } catch (error) {
      if (generation === this.loginGeneration && session === this.masterSession) this.clearHostedSession();
      throw error;
    }
  }


  constructor(brokerUrl: string) {
    super();
    this.brokerUrl = brokerUrl.replace(/\/+$/, '');
  }

  async status(): Promise<ConnectionStatus> {
    try {
      await loadCore(this.brokerUrl);
    } catch (e) {
      return {
        kind: 'disconnected',
        reason: 'no-backend-configured',
        detail: `WASM core failed to load: ${String(e)}`,
      };
    }
    try {
      const r = await fetch(`${this.brokerUrl}/healthz`, { cache: 'no-store' });
      return r.ok
        ? { kind: 'connected', via: 'broker', endpoint: this.brokerUrl }
        : { kind: 'disconnected', reason: 'unreachable', detail: `broker /healthz → ${r.status}.` };
    } catch (e) {
      return {
        kind: 'disconnected',
        reason: 'unreachable',
        detail: `broker ${this.brokerUrl} unreachable: ${String(e)}`,
      };
    }
  }

  // ── Broker calls in the browser (X1). Beyond the AgentKeysClient interface;
  //    the onboarding/pairing slices call these directly via the CoreBackend.
  //    `req.service` for memory MUST be namespace-qualified — `knowledge:<ns>`
  //    (use `knowledgeService(ns)` from lib/constants); a bare `memory` fails
  //    cap-mint with `service_not_in_scope` (arch.md §896). The agent's *read*
  //    is query-aware: the worker stores per-namespace (`knowledge:<ns>.enc`) and
  //    the configured engine (OpenViking / deterministic) ranks the
  //    gate-bounded lines per turn, never widening past scope (#177).
  async capMemoryPut(bearer: string, req: unknown): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).capMemoryPut(bearer, req);
  }
  async capMemoryGet(bearer: string, req: unknown): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).capMemoryGet(bearer, req);
  }
  async pairingClaim(bearer: string, req: unknown): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).pairingClaim(bearer, req);
  }
  async pendingBindings(bearer: string): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).pendingBindings(bearer);
  }
  async ackBinding(bearer: string, requestId: string): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).ackBinding(bearer, requestId);
  }
}

export const HOSTED_FEATURES_UNAVAILABLE = 'Agent management and stored data are not connected in this hosted version yet; empty views do not mean your account has no data.';

function loginFailure<T>(error: unknown): Result<T> {
  const message = String(error);
  let detail = 'Unable to complete sign-in. Please check your connection and try again.';
  let reason: DisconnectedStatus['reason'] = 'unreachable';
  if (message.includes('/v1/auth/config')) detail = 'Sign-in is not ready on this server. Please contact the administrator.';
  else if (message.includes('403')) { detail = 'This email address is not approved for access. Please contact the administrator.'; reason = 'unauthorized'; }
  else if (message.includes('401') || message.includes('expired')) { detail = 'Your sign-in link or session expired. Please sign in again.'; reason = 'unauthorized'; }
  else if (message.includes('cancelled')) detail = 'Sign-in was cancelled. Please try again.';
  return { ok: false, status: { kind: 'disconnected', reason, detail } };
}
