import type {
  AgentKeysClient,
  AnchorStatus,
  CapToken,
  ChainInfo,
  ChannelDef,
  Classification,
  ConfigPresetList,
  AgentContextView,
  ConnectionStatus,
  CredCategorization,
  CredService,
  DecodedAuditEvent,
  DisconnectedStatus,
  InboxItemBody,
  EmailVerifyStart,
  EmailVerifyStatus,
  InitConfigResult,
  K11EnrollBegin,
  K11EnrollFinishInput,
  K11EnrollResult,
  RegisterMasterAssertion,
  RegisterMasterResult,
  ReloginResult,
  ReloginStart,
  InheritableNamespace,
  MasterMemoryEntry,
  MasterResetResult,
  MemoryCategory,
  OnboardingState,
  PlantResult,
  ProposedScope,
  Result,
  RevokeIntent,
  SurfaceItem,
  SubmitResult,
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
// Wire types GENERATED from the Rust structs via ts-rs (#203 B2 / #215 re-land):
// the daemon's ui_bridge Api* structs, the catalog Sensitivity union, and the
// broker UserOp build/submit response shapes (agentkeys-protocol). Do not
// hand-edit @/lib/generated or re-declare these here — a Rust-side field rename
// regenerates the .ts and the mappers below stop compiling (rung-3 drift gate;
// CI also git-diffs the generated dir after `cargo test` regenerates it).
import type { ApiActor } from '@/lib/generated/ApiActor';
import type { ApiChannel } from '@/lib/generated/ApiChannel';
import type { ApiAnchorStatus } from '@/lib/generated/ApiAnchorStatus';
import type { ApiAuditEvent } from '@/lib/generated/ApiAuditEvent';
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';
import type { ApiMemoryEntry } from '@/lib/generated/ApiMemoryEntry';
import type { ApiPersonaEditResponse } from '@/lib/generated/ApiPersonaEditResponse';
import type { ApiPersonaState } from '@/lib/generated/ApiPersonaState';
import type { ApiChatEvent } from '@/lib/generated/ApiChatEvent';
import type { ApiRegisterState } from '@/lib/generated/ApiRegisterState';
import type { BuildArchiveUserOpResponse } from '@/lib/generated/BuildArchiveUserOpResponse';
import type { BuildSpawnUserOpResponse } from '@/lib/generated/BuildSpawnUserOpResponse';
import type { PresetCatalogResponse } from '@/lib/generated/PresetCatalogResponse';
import type { SubmitAcceptUserOpResponse } from '@/lib/generated/SubmitAcceptUserOpResponse';
import type { ApiWorker } from '@/lib/generated/ApiWorker';
import type { BuildAcceptUserOpResponse } from '@/lib/generated/BuildAcceptUserOpResponse';
import type { MasterMemoryPlantResponse } from '@/lib/generated/MasterMemoryPlantResponse';
import type { MemoryCategory as ApiMemoryCategory } from '@/lib/generated/MemoryCategory';
import type { ProposedScope as ApiProposedScope } from '@/lib/generated/ProposedScope';
import type { SubmitAcceptUserOpResponse as ApiSubmitResult } from '@/lib/generated/SubmitAcceptUserOpResponse';
import { loadWasmModule } from './wasm-module';

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

  // Like postJson, but the body is ALREADY serialized JSON (the wasm plant
  // builder returns serde_json's exact bytes — re-stringifying would launder
  // them through JS). #275 tier-3.
  private async postJsonBody<T>(path: string, jsonBody: string): Promise<Result<T>> {
    try {
      const resp = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: jsonBody,
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

  async getChainInfo(chain?: string): Promise<Result<ChainInfo>> {
    const q = chain ? `?chain=${encodeURIComponent(chain)}` : '';
    return this.getJson<ChainInfo>(`/v1/chain/info${q}`);
  }

  async getChainList(): Promise<Result<import('./types').ChainList>> {
    return this.getJson<import('./types').ChainList>('/v1/chain/list');
  }

  async getStackList(): Promise<Result<import('./types').StackList>> {
    return this.getJson<import('./types').StackList>('/v1/stack/list');
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
    const r = await this.getJson<ApiAnchorStatus>('/v1/anchor/status');
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

  async revokeDevice(
    actorId: string,
    intent: RevokeIntent,
    onchain?: { txHash?: string; auditEnvelopeHashes?: string[] },
  ): Promise<Result<void>> {
    const r = await this.postJson<unknown>(`/v1/actors/${encodeURIComponent(actorId)}/revoke`, {
      intent_text: intent.text,
      intent_fields: intent.fields,
      // Touch-ID path: the revoke UserOp already landed; the daemon verifies the
      // registry reads `revoked` and flips local state without the script.
      onchain: !!onchain,
      onchain_tx_hash: onchain?.txHash ?? null,
      // #97: the DeviceRevoke envelope receipts from the submit — attached to
      // the daemon's feed event so the decode view fetches the real envelope.
      audit_envelope_hashes: onchain?.auditEnvelopeHashes ?? null,
    });
    return r.ok ? { ok: true, data: undefined as unknown as void } : r;
  }

  // The Touch-ID unpair + the #260 reset fleet revoke: build + submit the
  // master-account executeBatch([revokeAgentDevice × N]) UserOp (the only
  // signer the registry accepts for an account-master operator). One hash =
  // the per-agent unpair; every paired agent = the pre-reset fleet teardown
  // (ONE Touch ID). The broker skips already-revoked hashes; all-skipped
  // returns 409 "nothing to revoke".
  async revokeBuild(input: { deviceKeyHashes: string[] }): Promise<Result<BuildAcceptUserOpResponse>> {
    return this.postJson('/v1/revoke/build', { device_key_hashes: input.deviceKeyHashes });
  }

  async revokeSubmit(body: unknown): Promise<Result<SubmitResult>> {
    const r = await this.postJson<ApiSubmitResult>('/v1/revoke/submit', body);
    return r.ok ? { ok: true, data: apiToSubmitResult(r.data) } : r;
  }

  // #429 (epic #425) — the spawn/archive ceremonies + their bookkeeping reads.
  async presetCatalog(): Promise<Result<PresetCatalogResponse>> {
    return this.getJson<PresetCatalogResponse>('/v1/presets');
  }

  async spawnBuild(input: {
    label: string;
    presetId: string;
    memoryNs?: string;
    memoryInherited?: boolean;
  }): Promise<Result<BuildSpawnUserOpResponse>> {
    const body: Record<string, unknown> = {
      label: input.label,
      preset_id: input.presetId,
    };
    if (input.memoryNs) body.memory_ns = input.memoryNs;
    if (input.memoryInherited) body.memory_inherited = true;
    return this.postJson<BuildSpawnUserOpResponse>('/v1/agent/spawn/build', body);
  }

  async spawnSubmit(body: unknown): Promise<Result<SubmitAcceptUserOpResponse>> {
    return this.postJson<SubmitAcceptUserOpResponse>('/v1/agent/spawn/submit', body);
  }

  async archiveBuild(input: {
    deviceKeyHash: string;
    resourcesKept: boolean;
    memoryNs?: string;
  }): Promise<Result<BuildArchiveUserOpResponse>> {
    const body: Record<string, unknown> = { device_key_hash: input.deviceKeyHash };
    if (input.resourcesKept) body.resources_kept = true;
    if (input.memoryNs) body.memory_ns = input.memoryNs;
    return this.postJson<BuildArchiveUserOpResponse>('/v1/agent/archive/build', body);
  }

  async archiveSubmit(body: unknown): Promise<Result<SubmitAcceptUserOpResponse>> {
    return this.postJson<SubmitAcceptUserOpResponse>('/v1/agent/archive/submit', body);
  }

  async chatSend(channelId: string, text: string): Promise<Result<{ event_id: string }>> {
    return this.postJson('/v1/master/agent/chat/send', { channel_id: channelId, text });
  }

  async chatPoll(
    channelId: string,
    after: string,
    waitSeconds: number,
  ): Promise<Result<{ events: ApiChatEvent[]; cursor: string }>> {
    return this.postJson('/v1/master/agent/chat/poll', {
      channel_id: channelId,
      after,
      wait_seconds: waitSeconds,
    });
  }

  async inheritableNamespaces(): Promise<Result<InheritableNamespace[]>> {
    const r = await this.getJson<{
      namespaces: { ns: string; from_label: string; archived_at: number }[];
    }>('/v1/agent/inheritable-namespaces');
    return r.ok
      ? {
          ok: true,
          data: r.data.namespaces.map((n) => ({
            ns: n.ns,
            fromLabel: n.from_label,
            archivedAt: n.archived_at,
          })),
        }
      : r;
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

  async getRegisterState(): Promise<Result<ApiRegisterState>> {
    return this.getJson<ApiRegisterState>('/v1/master/register/state');
  }

  async logout(): Promise<Result<void>> {
    const r = await this.postJson<{ ok: boolean }>('/v1/auth/logout', {});
    return r.ok ? { ok: true, data: undefined } : r;
  }

  // #242 — one-Touch-ID master re-login (no email round-trip).
  async reloginStart(): Promise<Result<ReloginStart>> {
    return this.postJson<ReloginStart>('/v1/auth/relogin/start', {});
  }

  async reloginFinish(challenge: string, assertion: RegisterMasterAssertion): Promise<Result<ReloginResult>> {
    return this.postJson<ReloginResult>('/v1/auth/relogin/finish', { challenge, assertion });
  }

  async resetMaster(): Promise<Result<MasterResetResult>> {
    return this.postJson<MasterResetResult>('/v1/master/reset', {});
  }

  // Can the broker build a sponsored master register right now? Guards BOTH
  // the reset (before the Touch-ID fleet revoke) and onboarding (before
  // credentials.create) so neither strands nor orphans on a 503 broker.
  async registerPreflight(): Promise<Result<import('./types').RegisterPreflight>> {
    return this.getJson<import('./types').RegisterPreflight>('/v1/master/register/preflight');
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
          chainError: body.chain_error ?? undefined,
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
        data: {
          ok: body.ok ?? true,
          txHash: body.tx_hash ?? undefined,
          account: body.account ?? undefined,
          chain: body.chain ?? undefined,
          // #278 D6: an HTTP-200 with chain "register-pending" / pending:true is
          // a broadcast-but-unconfirmed op — the master is NOT bound yet.
          pending: body.pending === true || body.chain === 'register-pending',
        },
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
    // #275 tier-3: the plant route + body come from the daemon's OWN wire types
    // (agentkeys-protocol::web_api) compiled to wasm — one code path, so this
    // client cannot hand-build a drifted body (the old @web-fixture diff gate
    // for this file is retired; the ts-rs ApiMemoryEntry type checks the entry
    // shape at compile time and the wasm builder validates + serializes it).
    let route: string;
    let body: string;
    try {
      const wasm = await loadWasmModule();
      const wireEntries = entries.map((m): ApiMemoryEntry => ({
        ns: m.ns, key: m.key, title: m.title, bytes: m.bytes,
        version: m.version, updated: m.updated, preview: m.preview, body: m.body,
        content_hash: m.contentHash ?? '',
        // #390 — planted archives are recall content; persona is NEVER planted
        // (the daemon rejects the reserved ns; personas ride /v1/master/persona).
        kind: 'knowledge',
      }));
      route = wasm.masterMemoryPlantRoute();
      body = wasm.buildMasterMemoryPlantBody(wireEntries);
    } catch (e) {
      return { ok: false, status: unreachable(`wasm plant builder failed: ${String(e)}`) };
    }
    const r = await this.postJsonBody<MasterMemoryPlantResponse>(route, body);
    if (!r.ok) return r;
    return {
      ok: true,
      data: {
        planted: r.data.planted,
        skipped: r.data.skipped,
        total: r.data.total,
        taxonomyStatus: r.data.taxonomy_status,
      },
    };
  }

  // ── #339 P2 — absorption-inbox curate queue ──────────────────────────────
  // The wire item type (ApiInboxItem) is ts-rs-generated from the daemon's Rust
  // struct, so a Rust-side field rename is a frontend compile error (#215).

  async listInbox(): Promise<Result<ApiInboxItem[]>> {
    const r = await this.getJson<{ items: ApiInboxItem[] }>('/v1/master/inbox');
    if (!r.ok) return r;
    return { ok: true, data: r.data.items };
  }

  // #390 — `confirmContentHash` is the viewed-body watermark REQUIRED for a
  // `skill` proposal (the daemon 428s a skill accept without it); `persona`
  // proposals are never adoptable (403 — persona is master-authored).
  async acceptInbox(
    s3Key: string,
    confirmContentHash?: string,
  ): Promise<Result<{ planted: number; ns: string; key: string }>> {
    return this.postJson<{ planted: number; ns: string; key: string }>(
      '/v1/master/inbox/accept',
      confirmContentHash
        ? { s3_key: s3Key, confirm_content_hash: confirmContentHash }
        : { s3_key: s3Key },
    );
  }

  async rejectInbox(s3Key: string): Promise<Result<{ deleted: boolean }>> {
    return this.postJson<{ deleted: boolean }>('/v1/master/inbox/reject', { s3_key: s3Key });
  }

  // Read one proposal's full decrypted body so the master can review it before
  // accept/reject (the daemon relays the worker's inbox-get; master-self).
  async getInboxItem(s3Key: string): Promise<Result<InboxItemBody>> {
    return this.postJson<InboxItemBody>('/v1/master/inbox/entry', { s3_key: s3Key });
  }

  // ── #390 — persona editor + agent restart / live context ─────────────────
  // ApiPersonaState / ApiPersonaEditResponse are ts-rs-generated from the
  // daemon's Rust structs; the context-files shape is bridge-owned (python),
  // proxied verbatim.

  async getPersona(delegateOmni: string): Promise<Result<ApiPersonaState>> {
    return this.getJson<ApiPersonaState>(
      `/v1/master/persona?delegate=${encodeURIComponent(delegateOmni)}`,
    );
  }

  async editPersona(
    delegateOmni: string,
    body: string,
  ): Promise<Result<ApiPersonaEditResponse>> {
    return this.postJson<ApiPersonaEditResponse>('/v1/master/persona', {
      delegate_omni: delegateOmni,
      body,
    });
  }

  async rollbackPersona(
    delegateOmni: string,
    version: number,
  ): Promise<Result<ApiPersonaEditResponse>> {
    return this.postJson<ApiPersonaEditResponse>('/v1/master/persona/rollback', {
      delegate_omni: delegateOmni,
      version,
    });
  }

  async restartAgent(): Promise<Result<{ restarted: boolean }>> {
    return this.postJson<{ restarted: boolean }>('/v1/master/agent/restart', {});
  }

  async getAgentContext(): Promise<Result<AgentContextView>> {
    return this.getJson<AgentContextView>('/v1/master/agent/context');
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
    /** #408 — the accept is a channel-endpoint DEVICE bind (channels page). The
     *  daemon forwards it to the broker's BuildAcceptRequest.is_device (§14.10
     *  broker warn); the card itself hard-enforces ≥1 channel before calling. */
    isDevice?: boolean;
  }): Promise<Result<BuildAcceptUserOpResponse>> {
    return this.postJson('/v1/accept/build', {
      request_id: input.requestId,
      services: input.services,
      read_only: input.readOnly,
      max_per_call: input.maxPerCall,
      max_per_period: input.maxPerPeriod,
      max_total: input.maxTotal,
      period_seconds: input.periodSeconds,
      ...(input.isDevice ? { is_device: true } : {}),
    });
  }

  async acceptSubmit(body: unknown): Promise<Result<SubmitResult>> {
    const r = await this.postJson<ApiSubmitResult>('/v1/accept/submit', body);
    return r.ok ? { ok: true, data: apiToSubmitResult(r.data) } : r;
  }

  // #248: build + submit the scope-only setScope UserOp for a bound agent. The
  // daemon fills operator_omni from the master session and forwards to the
  // broker /v1/scope/{build,submit}.
  async scopeBuild(input: {
    actorOmni: string;
    services: string[];
    preserveServiceIds?: string[];
    readOnly: boolean;
  }): Promise<Result<BuildAcceptUserOpResponse>> {
    return this.postJson('/v1/scope/build', {
      actor_omni: input.actorOmni,
      services: input.services,
      preserve_service_ids: input.preserveServiceIds ?? [],
      read_only: input.readOnly,
    });
  }

  async scopeSubmit(body: unknown): Promise<Result<SubmitResult>> {
    const r = await this.postJson<ApiSubmitResult>('/v1/scope/submit', body);
    return r.ok ? { ok: true, data: apiToSubmitResult(r.data) } : r;
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

  // #404 — the channel registry (id-anchored channel definitions; durable
  // config-class doc). ids are immutable anchors; delete 409s while in use.
  async listChannels(): Promise<Result<{ channels: ChannelDef[]; storage: string }>> {
    const r = await this.getJson<{ channels: ApiChannel[]; storage: string }>('/v1/channels');
    if (!r.ok) return r;
    return {
      ok: true,
      data: { channels: r.data.channels.map(apiToChannelDef), storage: r.data.storage },
    };
  }

  async createChannel(input: { id: string; name: string; note?: string }): Promise<Result<ChannelDef>> {
    const r = await this.postJson<{ channel: ApiChannel }>('/v1/channels', input);
    if (!r.ok) return r;
    return { ok: true, data: apiToChannelDef(r.data.channel) };
  }

  async updateChannel(id: string, input: { name?: string; note?: string }): Promise<Result<ChannelDef>> {
    const r = await this.postJson<{ channel: ApiChannel }>(`/v1/channels/${encodeURIComponent(id)}`, input);
    if (!r.ok) return r;
    return { ok: true, data: apiToChannelDef(r.data.channel) };
  }

  async deleteChannel(id: string): Promise<Result<void>> {
    const r = await this.postJson<{ ok: boolean }>(`/v1/channels/${encodeURIComponent(id)}/delete`, {});
    if (!r.ok) return r;
    return { ok: true, data: undefined };
  }
}

function apiToChannelDef(c: ApiChannel): ChannelDef {
  return { id: c.id, name: c.name, note: c.note ?? undefined, createdAt: c.created_at };
}

// ─── Wire types are imported from @/lib/generated (ts-rs, generated from the
//     Rust structs — #203 B2). The mappers below convert the snake_case wire
//     types to the camelCase UI domain types; a Rust-side field rename
//     regenerates the .ts and breaks these mappers (the drift gate). ─────────

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
    scopeUnknownServiceIds: a.scope_unknown_service_ids,
    scopeChannelServiceIds: a.scope_channel_service_ids,
    deviceKeyHash: a.device_key_hash ?? undefined,
    kind: a.kind ?? undefined,
    paymentCap: a.payment_cap
      ? { perTx: a.payment_cap.per_tx, daily: a.payment_cap.daily, currency: a.payment_cap.currency }
      : undefined,
    timeWindow: a.time_window,
    services: a.services,
    presetId: a.preset_id ?? undefined,
    memoryNs: a.memory_ns ?? undefined,
  };
}

function apiToSubmitResult(r: ApiSubmitResult): SubmitResult {
  return {
    ok: r.ok,
    txHash: r.tx_hash || undefined,
    blockNumber: r.block_number || undefined,
    userOpHash: r.user_op_hash || undefined,
    pending: r.pending,
    auditEnvelopeHashes:
      r.audit_envelope_hashes && r.audit_envelope_hashes.length > 0
        ? r.audit_envelope_hashes
        : undefined,
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
    txHash: e.tx_hash,
    auditEnvelopeHashes: e.audit_envelope_hashes,
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

function apiToMemoryEntry(m: ApiMemoryEntry): MasterMemoryEntry {
  return {
    ns: m.ns, key: m.key, title: m.title, bytes: m.bytes,
    version: m.version, updated: m.updated, preview: m.preview, body: m.body,
    contentHash: m.content_hash,
  };
}
