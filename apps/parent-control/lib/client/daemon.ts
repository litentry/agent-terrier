import type {
  AgentKeysClient,
  AnchorStatus,
  CapToken,
  ChainInfo,
  Classification,
  ConfigPresetList,
  ConnectionStatus,
  CredCategorization,
  CredService,
  DecodedAuditEvent,
  DisconnectedStatus,
  EmailVerifyStart,
  EmailVerifyStatus,
  InitConfigResult,
  K11EnrollBegin,
  K11EnrollFinishInput,
  K11EnrollResult,
  RegisterMasterAssertion,
  RegisterMasterResult,
  MasterMemoryEntry,
  MasterResetResult,
  MemoryCategory,
  OnboardingState,
  PlantResult,
  ProposedScope,
  Result,
  RevokeIntent,
  SurfaceItem,
} from './types';
import type {
  Actor,
  AuditEvent,
  ChipKind,
  Namespace,
  PairingRequest,
  ScopeBits,
  StatusKind,
  Worker,
} from '@/app/_components/types';

/**
 * DaemonBackend — talks to a running agentkeys-daemon over HTTP.
 *
 * Every method here maps 1:1 to a daemon HTTP endpoint:
 *
 *   GET  /healthz                       → status()
 *   GET  /v1/actors                     → listActors
 *   GET  /v1/actors/:id                 → getActor
 *   GET  /v1/actors/:id/caps            → listCapTokens
 *   GET  /v1/audit/recent               → listRecentAuditEvents
 *   GET  /v1/audit/stream  (SSE)        → streamAudit
 *   GET  /v1/anchor/status              → getAnchorStatus
 *   GET  /v1/workers                    → listWorkers
 *   GET  /v1/workers/:id                → getWorker
 *   POST /v1/actors/:id/scope           → updateScope
 *   POST /v1/actors/:id/payment-cap     → updatePaymentCap
 *   POST /v1/actors/:id/revoke          → revokeDevice
 *   POST /v1/actors/:id/caps/revoke     → revokeCap
 *   POST /v1/k11/enroll/begin           → enrollK11Begin
 *   POST /v1/k11/enroll/finish          → enrollK11Finish
 */

const DEFAULT_BASE_URL = 'http://localhost:3114';

function unreachable(detail: string): DisconnectedStatus {
  return { kind: 'disconnected', reason: 'unreachable', detail };
}

export class DaemonBackend implements AgentKeysClient {
  private baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = (baseUrl ?? process.env.NEXT_PUBLIC_AGENTKEYS_DAEMON_URL ?? DEFAULT_BASE_URL).replace(/\/$/, '');
  }

  private async getJson<T>(path: string): Promise<Result<T>> {
    try {
      const resp = await fetch(`${this.baseUrl}${path}`, { method: 'GET', cache: 'no-store' });
      if (!resp.ok) {
        const text = await resp.text();
        return { ok: false, status: unreachable(`GET ${path} → ${resp.status}: ${text}`) };
      }
      return { ok: true, data: (await resp.json()) as T };
    } catch (e) {
      return { ok: false, status: unreachable(`GET ${path}: ${(e as Error).message}`) };
    }
  }

  private async postJson<T>(path: string, body: unknown): Promise<Result<T>> {
    try {
      const resp = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        const text = await resp.text();
        return { ok: false, status: unreachable(`POST ${path} → ${resp.status}: ${text}`) };
      }
      return { ok: true, data: (await resp.json()) as T };
    } catch (e) {
      return { ok: false, status: unreachable(`POST ${path}: ${(e as Error).message}`) };
    }
  }

  async status(): Promise<ConnectionStatus> {
    try {
      const resp = await fetch(`${this.baseUrl}/healthz`, { method: 'GET', cache: 'no-store' });
      if (!resp.ok) return unreachable(`/healthz returned ${resp.status}`);
      return { kind: 'connected', via: 'daemon', endpoint: this.baseUrl };
    } catch (e) {
      return unreachable(`fetch ${this.baseUrl}/healthz failed: ${(e as Error).message}`);
    }
  }

  async getChainInfo(): Promise<Result<ChainInfo>> {
    return this.getJson<ChainInfo>('/v1/chain/info');
  }

  async decodeAuditEvent(id: string): Promise<Result<DecodedAuditEvent>> {
    return this.getJson<DecodedAuditEvent>(`/v1/audit/${encodeURIComponent(id)}/decode`);
  }

  async listActors(): Promise<Result<Actor[]>> {
    const r = await this.getJson<{ actors: ApiActor[] }>('/v1/actors');
    if (!r.ok) return r;
    return { ok: true, data: r.data.actors.map(apiToActor) };
  }

  async getActor(id: string): Promise<Result<Actor | null>> {
    const r = await this.getJson<ApiActor>(`/v1/actors/${encodeURIComponent(id)}`);
    if (!r.ok) {
      if (r.status.detail?.includes('→ 404')) return { ok: true, data: null };
      return r;
    }
    return { ok: true, data: apiToActor(r.data) };
  }

  async listCapTokens(actorId: string): Promise<Result<CapToken[]>> {
    const r = await this.getJson<{ caps: CapToken[] }>(
      `/v1/actors/${encodeURIComponent(actorId)}/caps`,
    );
    if (!r.ok) return r;
    return { ok: true, data: r.data.caps };
  }

  async listRecentAuditEvents(opts?: { actorId?: string; limit?: number }): Promise<Result<AuditEvent[]>> {
    const params = new URLSearchParams();
    if (opts?.actorId) params.set('actor_id', opts.actorId);
    if (opts?.limit) params.set('limit', String(opts.limit));
    const qs = params.toString();
    const r = await this.getJson<{ events: ApiAuditEvent[] }>(
      `/v1/audit/recent${qs ? `?${qs}` : ''}`,
    );
    if (!r.ok) return r;
    return { ok: true, data: r.data.events.map(apiToAuditEvent) };
  }

  streamAudit(
    onEvent: (e: AuditEvent) => void,
    onStatusChange: (s: ConnectionStatus) => void,
  ): () => void {
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
      onStatusChange(unreachable('EventSource not available in this environment'));
      return () => {};
    }
    const es = new EventSource(`${this.baseUrl}/v1/audit/stream`);
    es.addEventListener('audit', (msg) => {
      try {
        const apiEvent: ApiAuditEvent = JSON.parse((msg as MessageEvent).data);
        onEvent(apiToAuditEvent(apiEvent));
      } catch {
        // ignore malformed event
      }
    });
    es.onopen = () => onStatusChange({ kind: 'connected', via: 'daemon', endpoint: this.baseUrl });
    es.onerror = () => onStatusChange(unreachable('/v1/audit/stream errored'));
    return () => es.close();
  }

  async listWorkers(): Promise<Result<Worker[]>> {
    const r = await this.getJson<{ workers: ApiWorker[] }>('/v1/workers');
    if (!r.ok) return r;
    return { ok: true, data: r.data.workers.map(apiToWorker) };
  }

  async getWorker(id: Worker['id']): Promise<Result<Worker | null>> {
    const r = await this.getJson<ApiWorker>(`/v1/workers/${encodeURIComponent(id)}`);
    if (!r.ok) {
      if (r.status.detail?.includes('→ 404')) return { ok: true, data: null };
      return r;
    }
    return { ok: true, data: apiToWorker(r.data) };
  }

  async getAnchorStatus(): Promise<Result<AnchorStatus>> {
    const r = await this.getJson<{
      last_anchor_at: number;
      next_anchor_in: number;
      recent: { ts: string; root: string; count: number; txn: string; conf: number }[];
    }>('/v1/anchor/status');
    if (!r.ok) return r;
    return {
      ok: true,
      data: {
        lastAnchorAt: r.data.last_anchor_at,
        nextAnchorIn: r.data.next_anchor_in,
        recent: r.data.recent,
      },
    };
  }

  async updateScope(actorId: string, ns: Namespace, value: ScopeBits): Promise<Result<void>> {
    const r = await this.postJson<unknown>(`/v1/actors/${encodeURIComponent(actorId)}/scope`, {
      namespace: ns,
      read: value.read,
      write: value.write,
    });
    return r.ok ? { ok: true, data: undefined as unknown as void } : r;
  }

  async updatePaymentCap(actorId: string, perTx: number, daily: number): Promise<Result<void>> {
    const r = await this.postJson<unknown>(`/v1/actors/${encodeURIComponent(actorId)}/payment-cap`, {
      per_tx: perTx,
      daily,
    });
    return r.ok ? { ok: true, data: undefined as unknown as void } : r;
  }

  async revokeDevice(actorId: string, intent: RevokeIntent): Promise<Result<void>> {
    const r = await this.postJson<unknown>(`/v1/actors/${encodeURIComponent(actorId)}/revoke`, {
      intent_text: intent.text,
      intent_fields: intent.fields,
    });
    return r.ok ? { ok: true, data: undefined as unknown as void } : r;
  }

  async revokeCap(actorId: string, capName: string, intent: RevokeIntent): Promise<Result<void>> {
    const r = await this.postJson<unknown>(
      `/v1/actors/${encodeURIComponent(actorId)}/caps/revoke`,
      { cap: capName, intent_text: intent.text },
    );
    return r.ok ? { ok: true, data: undefined as unknown as void } : r;
  }

  async startEmailVerify(email: string): Promise<Result<EmailVerifyStart>> {
    const r = await this.postJson<{ request_id: string }>('/v1/auth/email/start', { email });
    return r.ok ? { ok: true, data: { requestId: r.data.request_id } } : r;
  }

  async pollEmailVerify(requestId: string): Promise<Result<EmailVerifyStatus>> {
    const r = await this.getJson<{ status: string; omni_account?: string }>(
      `/v1/auth/email/status?request_id=${encodeURIComponent(requestId)}`,
    );
    return r.ok ? { ok: true, data: { status: r.data.status, omniAccount: r.data.omni_account } } : r;
  }

  async getOnboardingState(): Promise<Result<OnboardingState>> {
    return this.getJson<OnboardingState>('/v1/onboarding/state');
  }

  async logout(): Promise<Result<void>> {
    const r = await this.postJson<{ ok: boolean }>('/v1/auth/logout', {});
    return r.ok ? { ok: true, data: undefined } : r;
  }

  async resetMaster(): Promise<Result<MasterResetResult>> {
    return this.postJson<MasterResetResult>('/v1/master/reset', {});
  }

  async enrollK11Begin(input: { userName: string; userDisplayName: string }): Promise<Result<K11EnrollBegin>> {
    try {
      const resp = await fetch(`${this.baseUrl}/v1/k11/enroll/begin`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: input.userName, display_name: input.userDisplayName }),
      });
      if (!resp.ok) {
        const text = await resp.text();
        return { ok: false, status: unreachable(`enroll/begin returned ${resp.status}: ${text}`) };
      }
      const body = await resp.json();
      const opts = body.creation_options?.publicKey ?? body.creation_options ?? {};
      return {
        ok: true,
        data: {
          challenge: opts.challenge ?? '',
          rpId: opts.rp?.id ?? 'localhost',
          rpName: opts.rp?.name ?? 'AgentKeys',
          userId: body.user_id ?? '',
          userName: opts.user?.name ?? input.userName,
          userDisplayName: opts.user?.displayName ?? input.userDisplayName,
          bindingNonce: '',
          pubKeyCredParams: opts.pubKeyCredParams ?? [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 },
          ],
          timeout: opts.timeout ?? 60_000,
        },
      };
    } catch (e) {
      return { ok: false, status: unreachable(`enroll/begin fetch failed: ${(e as Error).message}`) };
    }
  }

  async enrollK11Finish(input: K11EnrollFinishInput): Promise<Result<K11EnrollResult>> {
    try {
      const resp = await fetch(`${this.baseUrl}/v1/k11/enroll/finish`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          user_id: input.bindingNonce,
          credential: {
            id: input.credentialId,
            rawId: input.credentialId,
            response: {
              attestationObject: input.attestationObject,
              clientDataJSON: input.clientDataJSON,
            },
            type: 'public-key',
          },
        }),
      });
      if (!resp.ok) {
        const text = await resp.text();
        return { ok: false, status: unreachable(`enroll/finish returned ${resp.status}: ${text}`) };
      }
      const body = await resp.json();
      return {
        ok: true,
        data: {
          credentialId: body.credential_id,
          registeredAt: body.registered_at_unix,
          chainTxHash: body.chain_tx_hash ?? undefined,
          chain: body.chain ?? undefined,
          registerUserOpHash: body.register_userop_hash ?? undefined,
          registerAccount: body.register_account ?? undefined,
        },
      };
    } catch (e) {
      return { ok: false, status: unreachable(`enroll/finish fetch failed: ${(e as Error).message}`) };
    }
  }

  // #225 E7: phase 2 of the master register. The browser passkey signed the
  // register userOpHash (from enrollK11Finish); relay the assertion so the daemon
  // lands handleOps and binds operatorMasterWallet = the master P256Account.
  async registerMasterSubmit(assertion: RegisterMasterAssertion): Promise<Result<RegisterMasterResult>> {
    try {
      const resp = await fetch(`${this.baseUrl}/v1/master/register/submit`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ assertion }),
      });
      if (!resp.ok) {
        const text = await resp.text();
        return { ok: false, status: unreachable(`register/submit returned ${resp.status}: ${text}`) };
      }
      const body = await resp.json();
      return {
        ok: true,
        data: { ok: body.ok ?? true, txHash: body.tx_hash ?? undefined, account: body.account ?? undefined },
      };
    } catch (e) {
      return { ok: false, status: unreachable(`register/submit fetch failed: ${(e as Error).message}`) };
    }
  }

  async listMemoryCategories(): Promise<Result<MemoryCategory[]>> {
    const r = await this.getJson<{ categories: ApiMemoryCategory[] }>('/v1/master/memory');
    if (!r.ok) return r;
    return { ok: true, data: r.data.categories.map((c) => ({ ns: c.ns, label: c.label })) };
  }

  async getMemoryEntries(ns: string, key?: string): Promise<Result<MasterMemoryEntry[]>> {
    const qs = key
      ? `?ns=${encodeURIComponent(ns)}&key=${encodeURIComponent(key)}`
      : `?ns=${encodeURIComponent(ns)}`;
    const r = await this.getJson<{ ns: string; entries: ApiMemoryEntry[] }>(
      `/v1/master/memory/entry${qs}`,
    );
    if (!r.ok) return r;
    return { ok: true, data: r.data.entries.map(apiToMemoryEntry) };
  }

  async plantMemory(entries: MasterMemoryEntry[]): Promise<Result<PlantResult>> {
    const r = await this.postJson<{ planted: number; skipped: number; total: number; taxonomy_status?: string }>(
      '/v1/master/memory/plant',
      {
        // @web-fixture: master_memory_plant — entry shape gated by scripts/check-web-api-drift.sh
        // (must match the daemon's ApiMemoryEntry + web-parity-demo.sh; issue #203 / the #206 parity ladder).
        entries: entries.map((m) => ({
          ns: m.ns, key: m.key, title: m.title, bytes: m.bytes,
          version: m.version, updated: m.updated, preview: m.preview, body: m.body,
          content_hash: m.contentHash ?? '',
        })),
      },
    );
    if (!r.ok) return r;
    return {
      ok: true,
      data: {
        planted: r.data.planted,
        skipped: r.data.skipped,
        total: r.data.total,
        taxonomyStatus: r.data.taxonomy_status ?? 'ok',
      },
    };
  }

  async listConfigPresets(): Promise<Result<ConfigPresetList>> {
    const r = await this.getJson<{
      default_id: string;
      presets: { id: string; label: string; description: string; categories: ApiMemoryCategory[] }[];
    }>('/v1/master/config/presets');
    if (!r.ok) return r;
    return {
      ok: true,
      data: {
        defaultId: r.data.default_id,
        presets: r.data.presets.map((p) => ({
          id: p.id,
          label: p.label,
          description: p.description,
          categories: p.categories.map((c) => ({ ns: c.ns, label: c.label })),
        })),
      },
    };
  }

  async initConfigDefault(presetId: string): Promise<Result<InitConfigResult>> {
    const r = await this.postJson<{
      preset_id: string;
      taxonomy_status: string;
      categories: ApiMemoryCategory[];
    }>('/v1/master/config/init', { preset_id: presetId });
    if (!r.ok) return r;
    return {
      ok: true,
      data: {
        presetId: r.data.preset_id,
        taxonomyStatus: r.data.taxonomy_status,
        categories: r.data.categories.map((c) => ({ ns: c.ns, label: c.label })),
      },
    };
  }

  async classifyEntity(dataClass: string, entity: string): Promise<Result<CredCategorization>> {
    const r = await this.postJson<{
      data_class: string;
      entity: string;
      service: string;
      classification: Classification;
      audited: boolean;
    }>('/v1/master/classify/tag', { data_class: dataClass, entity });
    if (!r.ok) return r;
    return {
      ok: true,
      data: {
        dataClass: r.data.data_class,
        entity: r.data.entity,
        service: r.data.service,
        classification: r.data.classification,
        audited: r.data.audited,
      },
    };
  }

  async proposeScopes(actorId: string, surface: SurfaceItem[]): Promise<Result<ProposedScope[]>> {
    const r = await this.postJson<{ actor_id: string; proposals: ApiProposedScope[] }>(
      '/v1/master/classify/propose',
      { actor_id: actorId, surface: surface.map((s) => ({ data_class: s.dataClass, entity: s.entity })) },
    );
    if (!r.ok) return r;
    return {
      ok: true,
      data: r.data.proposals.map((p) => ({
        dataClass: p.data_class,
        entity: p.entity,
        service: p.service,
        category: p.category,
        sensitivity: p.sensitivity,
        gating: p.gating,
        confidence: p.confidence,
      })),
    };
  }

  async grantScope(actorId: string, p: ProposedScope): Promise<Result<Actor>> {
    const r = await this.postJson<ApiActor>(
      `/v1/actors/${encodeURIComponent(actorId)}/scope/grant`,
      { data_class: p.dataClass, entity: p.entity, category: p.category, gating: p.gating },
    );
    if (!r.ok) return r;
    return { ok: true, data: apiToActor(r.data) };
  }

  // #214: poll the broker rendezvous for agents the master has claimed that
  // await on-chain approval. The daemon maps broker PendingBinding rows → the
  // PairingRequest shape, so this is a straight pass-through.
  async listPairingRequests(): Promise<Result<PairingRequest[]>> {
    const r = await this.getJson<{ requests: PairingRequest[] }>('/v1/agent/pairing/pending');
    if (!r.ok) return r;
    return { ok: true, data: r.data.requests };
  }

  // #214: claim an agent's one-time pairing code → broker /v1/agent/pairing/claim.
  async claimPairing(input: { code: string; label: string; scope?: string }): Promise<Result<void>> {
    const r = await this.postJson<unknown>('/v1/agent/pairing/claim', {
      pairing_code: input.code,
      label: input.label,
      requested_scope: input.scope ?? '',
    });
    if (!r.ok) return r;
    return { ok: true, data: undefined };
  }

  // #214: approve a claimed agent → daemon registers it on chain + acks the broker.
  async registerPairing(requestId: string): Promise<Result<void>> {
    const r = await this.postJson<unknown>('/v1/agent/pairing/register', { request_id: requestId });
    if (!r.ok) return r;
    return { ok: true, data: undefined };
  }

  // #225: decline a claimed pairing request — broker drops the pending row (J1, no Touch ID).
  async declinePairing(requestId: string): Promise<Result<void>> {
    const r = await this.postJson<unknown>('/v1/agent/pairing/decline', { request_id: requestId });
    if (!r.ok) return r;
    return { ok: true, data: undefined };
  }

  // #225 E7: after the on-chain accept lands, mark the binding BOUND so the broker drops
  // it from pending (the accept/submit body has no request_id, so the broker can't do it
  // itself). J1-gated, no Touch ID. Without this the accepted request keeps reappearing.
  async ackPairing(requestId: string): Promise<Result<void>> {
    const r = await this.postJson<unknown>('/v1/agent/pairing/ack', { request_id: requestId });
    if (!r.ok) return r;
    return { ok: true, data: undefined };
  }

  async acceptBuild(input: {
    requestId: string;
    services: string[];
    readOnly: boolean;
    maxPerCall: string;
    maxPerPeriod: string;
    maxTotal: string;
    periodSeconds: number;
  }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  > {
    return this.postJson('/v1/accept/build', {
      request_id: input.requestId,
      services: input.services,
      read_only: input.readOnly,
      max_per_call: input.maxPerCall,
      max_per_period: input.maxPerPeriod,
      max_total: input.maxTotal,
      period_seconds: input.periodSeconds,
    });
  }

  async acceptSubmit(body: unknown): Promise<Result<unknown>> {
    return this.postJson('/v1/accept/submit', body);
  }

  async listCredentials(): Promise<Result<CredService[]>> {
    const r = await this.getJson<{
      credentials: { service: string; category: string; sensitivity: 'safe' | 'sensitive' }[];
    }>('/v1/master/credentials');
    if (!r.ok) return r;
    return {
      ok: true,
      data: r.data.credentials.map((c) => ({
        service: c.service,
        category: c.category,
        sensitivity: c.sensitivity,
      })),
    };
  }

  async storeCredential(service: string, secret: string): Promise<Result<{ service: string; category: string }>> {
    const r = await this.postJson<{ ok: boolean; service: string; category: string }>(
      '/v1/master/credentials/store',
      { service, secret },
    );
    if (!r.ok) return r;
    return { ok: true, data: { service: r.data.service, category: r.data.category } };
  }
}

interface ApiProposedScope {
  data_class: string;
  entity: string;
  service: string;
  category: string;
  sensitivity: 'safe' | 'sensitive';
  gating: 'auto' | 'k11';
  confidence: number;
}

// ─── API wire types (snake_case, mirror ui_bridge.rs ApiActor etc.) ────

interface ApiActor {
  id: string;
  omni: string;
  omni_hex: string;
  label: string;
  role: string;
  parent: string | null;
  derivation: string;
  device: string;
  device_pubkey: string;
  last_active: string;
  status: string;
  vendor: string;
  k11: boolean;
  scope?: Record<string, { read: boolean; write: boolean }>;
  payment_cap?: { per_tx: number; daily: number; currency: string };
  time_window?: { start: string; end: string; tz: string };
  services?: string[];
  // #225 E7: on-chain account (master → P256Account address; agent → device omni).
  account_address?: string | null;
  account_type?: string; // "p256account" | "device" | "none"
}

interface ApiAuditEvent {
  id: string;
  ts: string;
  actor_id: string;
  actor: string;
  kind: string;
  detail: string;
  chip: string;
  sev: string;
}

interface ApiWorker {
  id: string;
  title: string;
  host: string;
  desc: string;
  calls_today: number;
  calls_hour: number;
  p50: number;
  p95: number;
  cap: string;
  by_actor: { actor: string; count: number; share: number }[];
}

function apiToActor(a: ApiActor): Actor {
  return {
    id: a.id,
    omni: a.omni,
    omniHex: a.omni_hex,
    label: a.label,
    role: a.role === 'master' ? 'master' : 'agent',
    parent: a.parent,
    derivation: a.derivation,
    device: a.device,
    devicePubkey: a.device_pubkey,
    lastActive: a.last_active,
    status: normalizeStatus(a.status),
    vendor: a.vendor,
    k11: a.k11,
    accountAddress: a.account_address ?? undefined,
    accountType: a.account_type ?? undefined,
    scope: a.scope as Actor['scope'],
    paymentCap: a.payment_cap
      ? { perTx: a.payment_cap.per_tx, daily: a.payment_cap.daily, currency: a.payment_cap.currency }
      : undefined,
    timeWindow: a.time_window,
    services: a.services,
  };
}

function apiToAuditEvent(e: ApiAuditEvent): AuditEvent {
  return {
    id: e.id,
    ts: e.ts,
    actorId: e.actor_id,
    actor: e.actor,
    kind: e.kind,
    detail: e.detail,
    chip: normalizeChip(e.chip),
    sev: normalizeStatus(e.sev),
  };
}

function apiToWorker(w: ApiWorker): Worker {
  return {
    id: w.id as Worker['id'],
    title: w.title,
    host: w.host,
    desc: w.desc,
    callsToday: w.calls_today,
    callsHour: w.calls_hour,
    p50: w.p50,
    p95: w.p95,
    cap: w.cap,
    byActor: w.by_actor,
  };
}

function normalizeStatus(s: string): StatusKind {
  if (s === 'ok' || s === 'warn' || s === 'bad' || s === 'muted') return s;
  return 'muted';
}

function normalizeChip(c: string): ChipKind {
  const allowed: ChipKind[] = [
    'default',
    'ok',
    'warn',
    'bad',
    'memory',
    'creds',
    'audit',
    'broker',
    'chain',
    'payment',
    'revoke',
  ];
  return (allowed as string[]).includes(c) ? (c as ChipKind) : 'default';
}

interface ApiMemoryEntry {
  ns: string;
  key: string;
  title: string;
  bytes: number;
  version: string;
  updated: string;
  preview: string;
  body: string;
  content_hash?: string;
}

interface ApiMemoryCategory {
  ns: string;
  label: string;
}

function apiToMemoryEntry(m: ApiMemoryEntry): MasterMemoryEntry {
  return {
    ns: m.ns, key: m.key, title: m.title, bytes: m.bytes,
    version: m.version, updated: m.updated, preview: m.preview, body: m.body,
    contentHash: m.content_hash,
  };
}
