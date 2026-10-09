'use client';

import { MappedBackend } from './daemon';
import { setHostedGatewayAccess } from '../gatewayClient';
import { listHostedIdentities, loadHostedIdentity, unlockHostedIdentity, type HostedBrowserIdentity } from '../hostedIdentity';
import type { ConsoleConfig } from '../generated/ConsoleConfig';
import type { ChannelDefaultsRefreshRequest } from '../generated/ChannelDefaultsRefreshRequest';
import type { HostedSignerStartRequest } from '../generated/HostedSignerStartRequest';
import type { HostedSignerStatusRequest } from '../generated/HostedSignerStatusRequest';
import type { HostedSignerChallenge } from '../generated/HostedSignerChallenge';
import type { HostedSignerStatus } from '../generated/HostedSignerStatus';
import type { AuditEvent } from '@/app/_components/types';
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

const TRANSACTION_CONFIRMATION_TIMEOUT_MS = 180_000;
const TRANSACTION_POLL_INTERVAL_MS = 2_000;

export class CoreBackend extends MappedBackend {
  readonly brokerUrl: string;
  private browserIdentity: HostedBrowserIdentity | null = null;
  private configuration: Promise<ConsoleConfig> | null = null;
  private consoleClient: Promise<import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core').ConsoleClient> | null = null;
  private masterSession: MasterSession | null = null;
  private loginGeneration = 0;
  private email = '';
  private confirmationsInFlight = new Set<string>();
  private pendingConfirmations = new Map<string, { path: string; body: unknown }>();
  private pendingLogin: { requestId: string; expiresAt: number } | null = null;

  private config(): Promise<ConsoleConfig> {
    if (!this.configuration) {
      this.configuration = loadWasmModule().then((wasm) => wasm.consoleConfiguration(this.brokerUrl));
      void this.configuration.catch(() => { this.configuration = null; });
    }
    return this.configuration;
  }

  private console(): Promise<import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core').ConsoleClient> {
    if (!this.consoleClient) {
      this.consoleClient = Promise.all([loadWasmModule(), this.config()]).then(([wasm, config]) => new wasm.ConsoleClient(this.brokerUrl, config));
      void this.consoleClient.catch(() => { this.consoleClient = null; });
    }
    return this.consoleClient;
  }

  private session() {
    if (!this.masterSession || !this.browserIdentity || this.masterSession.expires_at * 1000 <= Date.now()) throw new Error('Your session expired. Sign in with Touch ID.');
    return { session: this.masterSession, identity: this.browserIdentity, generation: this.loginGeneration };
  }

  private async request<T>(method: string, path: string, body: unknown): Promise<Result<T>> {
    let activeConfirmation: string | null = null;
    let requestGeneration: number | null = null;
    try {
      const current = this.session();
      requestGeneration = current.generation;
      const console = await this.console();
      if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
      const invoke = (requestPath: string, requestBody: unknown) => console.request(current.session.session_jwt, current.session.omni_account, current.identity.secretHex,
        current.identity.consoleSecretHex, BigInt(Math.floor(Date.now() / 1000)), method, requestPath, requestBody);
      const operation = method === 'POST' && path.endsWith('/submit') && body && typeof body === 'object' && 'user_op' in body ? (body as { user_op: unknown }).user_op : undefined;
      const confirmationId = operation ? JSON.stringify(operation) : '';
      if (confirmationId) {
        if (this.confirmationsInFlight.has(confirmationId)) throw new Error('This account change is already being checked.');
        this.confirmationsInFlight.add(confirmationId);
        activeConfirmation = confirmationId;
      }
      const receiptOnly = path === '/v1/revoke/submit' || path === '/v1/master/hosted-signer/submit';
      const resumePath = receiptOnly ? '/v1/accept/receipt' : path;
      const resumeBody = receiptOnly ? { user_op: operation } : body;
      let data = await invoke(confirmationId && this.pendingConfirmations.has(confirmationId) ? resumePath : path,
        confirmationId && this.pendingConfirmations.has(confirmationId) ? resumeBody : body);
      const startedAt = Date.now();
      while (method === 'POST' && path.endsWith('/submit') && data?.pending === true) {
        this.pendingConfirmations.set(confirmationId, { path, body });
        if (Date.now() - startedAt >= TRANSACTION_CONFIRMATION_TIMEOUT_MS) throw new Error(`Transaction ${data.user_op_hash} is still awaiting confirmation. No completed action was reported. Use Check confirmation below to continue without submitting it again.`);
        await new Promise((resolve) => setTimeout(resolve, TRANSACTION_POLL_INTERVAL_MS));
        if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled. The submitted transaction may still confirm.');
        this.session();
        data = await invoke(resumePath, resumeBody);
      }
      if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
      if (confirmationId && (data?.ok === false || containsCeremonyFailure(data?.ceremony))) throw new Error(JSON.stringify({ chain_confirmed: !!data?.tx_hash, error: 'The account change requires follow-up recovery.', result: data }));
      if (confirmationId) this.pendingConfirmations.delete(confirmationId);
      return { ok: true, data: data as T };
    } catch (error) {
      if (activeConfirmation && requestGeneration === this.loginGeneration && !/(?:status[=: ]+|HTTP )(?:400|401|403|404|422)\b/.test(String(error))) {
        this.pendingConfirmations.set(activeConfirmation, { path, body });
      }
      return consoleFailure(error);
    } finally { if (activeConfirmation && requestGeneration === this.loginGeneration) this.confirmationsInFlight.delete(activeConfirmation); }
  }

  pendingTransactions(): string[] { return [...this.pendingConfirmations.keys()].filter((id) => !this.confirmationsInFlight.has(id)); }
  async confirmPendingTransaction(id: string): Promise<Result<unknown>> {
    const pending = this.pendingConfirmations.get(id);
    if (!pending) return consoleFailure(new Error('The transaction is no longer awaiting confirmation in this session.'));
    return this.request('POST', pending.path, pending.body);
  }

  protected async getJson<T>(path: string): Promise<Result<T>> { return this.request('GET', path, null); }
  protected async postJson<T>(path: string, body: unknown): Promise<Result<T>> { return this.request('POST', path, body); }
  protected async postJsonBody<T>(path: string, body: string): Promise<Result<T>> {
    try { return this.request('POST', path, JSON.parse(body)); } catch (error) { return consoleFailure(error); }
  }

  async getChainInfo(chain?: string): Promise<Result<import('./types').ChainInfo>> {
    try {
      const config = await this.config();
      if (chain && chain !== config.chain.name) throw new Error('Select the console for that stack to view its deployed contracts.');
      return { ok: true, data: config.chain };
    } catch (error) { return consoleFailure(error); }
  }

  async getChainList(): Promise<Result<import('./types').ChainList>> {
    const info = await this.getChainInfo();
    return info.ok ? { ok: true, data: { daemonChain: info.data.name, daemonBroker: this.brokerUrl,
      chains: [{ name: info.data.name, display: info.data.display, chainId: info.data.chainId, contracts: info.data.contracts.length }] } } : info;
  }

  async getStackList(): Promise<Result<import('./types').StackList>> {
    const info = await this.getChainInfo();
    return info.ok ? { ok: true, data: { daemonChain: info.data.name, daemonBroker: this.brokerUrl,
      stacks: [{ name: info.data.display, chain: info.data.name, brokerUrl: this.brokerUrl, active: true, healthy: (await this.status()).kind === 'connected' }] } } : info;
  }

  async hostedSignerStart(request: HostedSignerStartRequest): Promise<HostedSignerChallenge> {
    if (!this.masterSession) throw new Error('Sign in with your approved email first.');
    const wasm = await loadWasmModule();
    const signer = new wasm.HostedSignerClient(this.brokerUrl);
    try { return await signer.start(this.masterSession.session_jwt, request); } finally { signer.free(); }
  }

  async hostedSignerPublish(request: import('../generated/HostedSignerApproval').HostedSignerApproval): Promise<import('../generated/HostedSignerRequest').HostedSignerRequest> {
    if (!this.masterSession) throw new Error('Sign in with your approved email first.');
    const wasm = await loadWasmModule();
    const signer = new wasm.HostedSignerClient(this.brokerUrl);
    try { return await signer.publish(this.masterSession.session_jwt, request); } finally { signer.free(); }
  }

  async hostedSignerStatus(request: HostedSignerStatusRequest): Promise<HostedSignerStatus> {
    if (!this.masterSession) throw new Error('Sign in with your approved email first.');
    const wasm = await loadWasmModule();
    const signer = new wasm.HostedSignerClient(this.brokerUrl);
    try { return await signer.status(this.masterSession.session_jwt, request); } finally { signer.free(); }
  }

  async activateHostedIdentity(identity: HostedBrowserIdentity): Promise<void> {
    const session = this.masterSession;
    const generation = this.loginGeneration;
    if (!session || identity.omni !== session.omni_account.replace(/^0x/, '').toLowerCase() || identity.brokerUrl !== this.brokerUrl) throw new Error('Browser identity belongs to a different account or stack.');
    const status = await this.hostedSignerStatus({ credential_id: identity.credentialId, device_key_hash: identity.deviceKeyHash });
    if (!status.active || !status.device_active) throw new Error('This browser has not been approved on chain.');
    if (generation !== this.loginGeneration || session !== this.masterSession) throw new Error('Sign-in was cancelled.');
    this.browserIdentity = identity;
    this.registerGateway();
  }

  async signInWithPasskey(omni?: string): Promise<HostedBrowserIdentity> {
    const identities = listHostedIdentities(this.brokerUrl);
    const selectedOmni = omni ?? this.browserIdentity?.omni;
    if (!selectedOmni && identities.length > 1) throw new Error('Sign in by email to select your account.');
    const credential = selectedOmni ? loadHostedIdentity(this.brokerUrl, selectedOmni) : identities[0];
    if (!credential) throw new Error('Sign in by email to enable this browser first.');
    this.clearHostedSession();
    const generation = this.loginGeneration;
    const wasm = await loadWasmModule();
    const signer = new wasm.HostedSignerClient(this.brokerUrl);
    try {
      const challenge = await signer.passkeyStart(credential.omni);
      const unlocked = await unlockHostedIdentity(credential, challenge.challenge);
      const result = await signer.passkeyFinish(challenge.challenge, unlocked.assertion);
      const info: MasterSessionInfo = await (await loadCore(this.brokerUrl)).sessionInfo(result.session_jwt);
      if (generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
      this.masterSession = { ...info, session_jwt: result.session_jwt };
      await this.activateHostedIdentity(unlocked.identity);
      return unlocked.identity;
    } finally { signer.free(); }
  }

  private registerGateway(): void {
    setHostedGatewayAccess({
      sessionKey: () => this.masterSession && this.browserIdentity && this.masterSession.expires_at * 1000 > Date.now() ? `${this.brokerUrl}:${this.loginGeneration}` : null,
      request: async (body) => {
        const result = await this.request<unknown>('POST', '/v1/master/gateway', body);
        return result.ok ? { ok: true, value: result.data } : { ok: false, reason: result.status.reason, detail: result.status.detail, status: result.status.reason === 'unauthorized' ? 401 : 502 };
      },
      readRegistry: async () => {
        const current = this.session();
        const [console, wasm] = await Promise.all([this.console(), loadWasmModule()]);
        if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
        const result = await console.configRead(current.session.session_jwt, current.session.omni_account,
          current.identity.secretHex, BigInt(Math.floor(Date.now() / 1000)), wasm.gatewayContactsService());
        if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
        return result;
      },
      writeRegistry: async (value, revision) => {
        const current = this.session();
        const [console, wasm] = await Promise.all([this.console(), loadWasmModule()]);
        if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
        await console.configWrite(current.session.session_jwt, current.session.omni_account,
          current.identity.secretHex, BigInt(Math.floor(Date.now() / 1000)), wasm.gatewayContactsService(), value, revision);
        if (current.generation !== this.loginGeneration) throw new Error('Sign-in was cancelled.');
      },
      afterMutation: async (request) => {
        if (request.operation !== 'channels_update') return;
        const body: ChannelDefaultsRefreshRequest = { channel_id: request.payload.channel_id };
        const result = await this.request<unknown>('POST', '/v1/master/apps/channel-defaults/refresh', body);
        if (!result.ok) throw new Error(result.status.detail ?? result.status.reason);
      },
    });
  }

  streamAudit(onEvent: (event: AuditEvent) => void, onStatusChange: (status: ConnectionStatus) => void): () => void {
    let cancelled = false;
    let running = false;
    const seen = new Set<string>();
    const poll = async () => {
      if (running || cancelled) return;
      running = true;
      const result = await this.listRecentAuditEvents();
      running = false;
      if (cancelled) return;
      if (!result.ok) { onStatusChange(result.status); return; }
      onStatusChange({ kind: 'connected', via: 'broker', endpoint: this.brokerUrl });
      for (const event of result.data) if (!seen.has(event.id)) { seen.add(event.id); onEvent(event); }
      const currentIds = new Set(result.data.map((event) => event.id));
      for (const id of seen) if (!currentIds.has(id)) seen.delete(id);
    };
    void poll();
    const timer = setInterval(() => { void poll(); }, 5000);
    return () => { cancelled = true; clearInterval(timer); };
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
      const credentials = typeof window === 'undefined' ? [] : listHostedIdentities(this.brokerUrl);
      return { ok: true, data: session
        ? { identity: 'verified', email: this.email, omni: session.omni_account, k11: this.browserIdentity ? 'enrolled' : 'none',
            chain: this.browserIdentity ? 'master-registered' : 'none', session: 'active' }
        : { identity: 'none', k11: 'none', session: credentials.length ? 'expired' : 'none', relogin: credentials.length === 1 ? { omni: credentials[0].omni } : undefined } };
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
    this.browserIdentity = null;
    this.consoleClient = null;
    this.pendingConfirmations.clear();
    this.confirmationsInFlight.clear();
    setHostedGatewayAccess(null);
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
    super(brokerUrl);
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

function consoleFailure<T>(error: unknown): Result<T> {
  const detail = String(error);
  return { ok: false, status: { kind: 'disconnected', reason: /401|403|expired|Sign in/.test(detail) ? 'unauthorized' : 'unreachable', detail } };
}

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

function containsCeremonyFailure(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(containsCeremonyFailure);
  return Object.entries(value).some(([key, item]) => key === 'error' ? item != null && item !== '' : containsCeremonyFailure(item));
}
