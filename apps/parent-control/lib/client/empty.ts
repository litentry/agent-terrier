import type {
  AgentKeysClient,
  AnchorStatus,
  CapToken,
  AgentContextView,
  ConfigPresetList,
  ConnectionStatus,
  CredCategorization,
  CredService,
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
import type { Actor, AuditEvent, Namespace, PairingRequest, ScopeBits, Worker } from '@/app/_components/types';
import type { ApiAgentUpdateResult } from '@/lib/generated/ApiAgentUpdateResult';
import type { ApiImageStatus } from '@/lib/generated/ApiImageStatus';
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';
import type { ApiPersonaEditResponse } from '@/lib/generated/ApiPersonaEditResponse';
import type { ApiPersonaState } from '@/lib/generated/ApiPersonaState';
import type { ApiChatEvent } from '@/lib/generated/ApiChatEvent';
import type { ApiRegisterState } from '@/lib/generated/ApiRegisterState';
import type { BuildArchiveUserOpResponse } from '@/lib/generated/BuildArchiveUserOpResponse';
import type { BuildSpawnUserOpResponse } from '@/lib/generated/BuildSpawnUserOpResponse';
import type { PresetCatalogResponse } from '@/lib/generated/PresetCatalogResponse';
import type { SubmitAcceptUserOpResponse } from '@/lib/generated/SubmitAcceptUserOpResponse';

const DISCONNECTED: DisconnectedStatus = {
  kind: 'disconnected',
  reason: 'no-backend-configured',
  detail:
    'Set NEXT_PUBLIC_AGENTKEYS_BACKEND=daemon and AGENTKEYS_DAEMON_URL to a running agentkeys-daemon to populate this view.',
};

export class EmptyBackend implements AgentKeysClient {
  protected disconnected<T>(): Result<T> {
    return { ok: false, status: DISCONNECTED };
  }
  async status(): Promise<ConnectionStatus> {
    return DISCONNECTED;
  }

  async startEmailVerify(_email: string): Promise<Result<EmailVerifyStart>> {
    return this.disconnected();
  }

  async pollEmailVerify(_requestId: string): Promise<Result<EmailVerifyStatus>> {
    return this.disconnected();
  }

  async getOnboardingState(): Promise<Result<OnboardingState>> {
    return this.disconnected();
  }

  async getRegisterState(): Promise<Result<ApiRegisterState>> {
    return this.disconnected();
  }

  async logout(): Promise<Result<void>> {
    return this.disconnected();
  }

  async reloginStart(): Promise<Result<ReloginStart>> {
    return this.disconnected();
  }

  async reloginFinish(_challenge: string, _assertion: RegisterMasterAssertion): Promise<Result<ReloginResult>> {
    return this.disconnected();
  }

  async resetMaster(): Promise<Result<MasterResetResult>> {
    return this.disconnected();
  }

  async registerPreflight(): Promise<Result<import('./types').RegisterPreflight>> {
    return this.disconnected();
  }

  async listActors(): Promise<Result<Actor[]>> {
    return this.disconnected();
  }

  async getActor(): Promise<Result<Actor | null>> {
    return this.disconnected();
  }

  async getChainInfo(_chain?: string): Promise<Result<import('./types').ChainInfo>> {
    return this.disconnected();
  }

  async getChainList(): Promise<Result<import('./types').ChainList>> {
    return this.disconnected();
  }

  async getStackList(): Promise<Result<import('./types').StackList>> {
    return this.disconnected();
  }

  async decodeAuditEvent(_id: string): Promise<Result<import('./types').DecodedAuditEvent>> {
    return this.disconnected();
  }

  async listCapTokens(_actorId: string): Promise<Result<CapToken[]>> {
    return this.disconnected();
  }

  async listAuditPage(): Promise<Result<import('./types').AuditPage>> {
    return this.disconnected();
  }

  async listRecentAuditEvents(): Promise<Result<AuditEvent[]>> {
    return this.disconnected();
  }

  streamAudit(
    _onEvent: (e: AuditEvent) => void,
    onStatusChange: (s: ConnectionStatus) => void,
  ): () => void {
    onStatusChange(DISCONNECTED);
    return () => {};
  }

  async listWorkers(): Promise<Result<Worker[]>> {
    return this.disconnected();
  }

  async getWorker(): Promise<Result<Worker | null>> {
    return this.disconnected();
  }

  async getAnchorStatus(): Promise<Result<AnchorStatus>> {
    return this.disconnected();
  }

  async updateScope(_actorId: string, _ns: Namespace, _value: ScopeBits): Promise<Result<void>> {
    return this.disconnected();
  }

  async updatePaymentCap(_actorId: string, _perTx: number, _daily: number): Promise<Result<void>> {
    return this.disconnected();
  }

  async revokeDevice(
    _actorId: string,
    _intent: RevokeIntent,
    _onchain?: { txHash?: string; auditEnvelopeHashes?: string[] },
  ): Promise<Result<void>> {
    return this.disconnected();
  }

  async revokeCap(_actorId: string, _capName: string, _intent: RevokeIntent): Promise<Result<void>> {
    return this.disconnected();
  }

  async enrollK11Begin(): Promise<Result<K11EnrollBegin>> {
    return this.disconnected();
  }

  async enrollK11Finish(_input: K11EnrollFinishInput): Promise<Result<K11EnrollResult>> {
    return this.disconnected();
  }

  async registerMasterSubmit(_assertion: RegisterMasterAssertion): Promise<Result<RegisterMasterResult>> {
    return this.disconnected();
  }

  async listMemoryCategories(): Promise<Result<MemoryCategory[]>> {
    return this.disconnected();
  }

  async getMemoryEntries(_ns: string, _key?: string): Promise<Result<MasterMemoryEntry[]>> {
    return this.disconnected();
  }

  async plantMemory(_entries: MasterMemoryEntry[]): Promise<Result<PlantResult>> {
    return this.disconnected();
  }

  async listInbox(): Promise<Result<ApiInboxItem[]>> {
    return this.disconnected();
  }

  async acceptInbox(
    _s3Key: string,
    _confirmContentHash?: string,
  ): Promise<Result<{ planted: number; ns: string; key: string }>> {
    return this.disconnected();
  }

  async rejectInbox(_s3Key: string): Promise<Result<{ deleted: boolean }>> {
    return this.disconnected();
  }

  async getInboxItem(_s3Key: string): Promise<Result<InboxItemBody>> {
    return this.disconnected();
  }

  // ── #390 — persona editor + agent restart / live context ─────────────────

  async getPersona(_delegateOmni: string): Promise<Result<ApiPersonaState>> {
    return this.disconnected();
  }

  async editPersona(
    _delegateOmni: string,
    _body: string,
  ): Promise<Result<ApiPersonaEditResponse>> {
    return this.disconnected();
  }

  async rollbackPersona(
    _delegateOmni: string,
    _version: number,
  ): Promise<Result<ApiPersonaEditResponse>> {
    return this.disconnected();
  }

  async restartAgent(): Promise<Result<{ restarted: boolean }>> {
    return this.disconnected();
  }

  async presetReapply(
    _actorOmni: string,
  ): Promise<Result<{ ok: boolean; preset_id: string; sandbox_id: string | null; detail: string }>> {
    return this.disconnected();
  }

  async getAgentContext(): Promise<Result<AgentContextView>> {
    return this.disconnected();
  }

  async listConfigPresets(): Promise<Result<ConfigPresetList>> {
    return this.disconnected();
  }

  async initConfigDefault(_presetId: string): Promise<Result<InitConfigResult>> {
    return this.disconnected();
  }

  async classifyEntity(_dataClass: string, _entity: string): Promise<Result<CredCategorization>> {
    return this.disconnected();
  }

  async proposeScopes(_actorId: string, _surface: SurfaceItem[]): Promise<Result<ProposedScope[]>> {
    return this.disconnected();
  }

  async grantScope(_actorId: string, _p: ProposedScope): Promise<Result<Actor>> {
    return this.disconnected();
  }

  async listPairingRequests(): Promise<Result<PairingRequest[]>> {
    return this.disconnected();
  }

  async claimPairing(_input: { code: string; label: string; scope?: string }): Promise<Result<void>> {
    return this.disconnected();
  }

  async registerPairing(_requestId: string): Promise<Result<void>> {
    return this.disconnected();
  }

  async declinePairing(_requestId: string): Promise<Result<void>> {
    return this.disconnected();
  }

  async ackPairing(_requestId: string): Promise<Result<void>> {
    return this.disconnected();
  }

  async acceptBuild(_input: {
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
    return this.disconnected();
  }

  async acceptSubmit(_body: unknown): Promise<Result<SubmitResult>> {
    return this.disconnected();
  }

  async scopeBuild(_input: {
    actorOmni: string;
    services: string[];
    preserveServiceIds?: string[];
    readOnly: boolean;
  }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  > {
    return this.disconnected();
  }

  async scopeSubmit(_body: unknown): Promise<Result<SubmitResult>> {
    return this.disconnected();
  }

  async revokeBuild(_input: { deviceKeyHashes: string[] }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  > {
    return this.disconnected();
  }

  async revokeSubmit(_body: unknown): Promise<Result<SubmitResult>> {
    return this.disconnected();
  }

  async presetCatalog(): Promise<Result<PresetCatalogResponse>> {
    return this.disconnected();
  }

  async spawnBuild(_input: {
    label: string;
    presetId: string;
    memoryNs?: string;
    memoryInherited?: boolean;
  }): Promise<Result<BuildSpawnUserOpResponse>> {
    return this.disconnected();
  }

  async spawnSubmit(_body: unknown): Promise<Result<SubmitAcceptUserOpResponse>> {
    return this.disconnected();
  }

  async archiveBuild(_input: {
    deviceKeyHash: string;
    resourcesKept: boolean;
    memoryNs?: string;
  }): Promise<Result<BuildArchiveUserOpResponse>> {
    return this.disconnected();
  }

  async archiveSubmit(_body: unknown): Promise<Result<SubmitAcceptUserOpResponse>> {
    return this.disconnected();
  }

  async agentUpdate(_input: {
    deviceKeyHash: string;
    force?: boolean;
  }): Promise<Result<ApiAgentUpdateResult>> {
    return this.disconnected();
  }

  async agentImageStatus(_deviceKeyHashes: string[]): Promise<Result<ApiImageStatus>> {
    return this.disconnected();
  }

  async inheritableNamespaces(): Promise<Result<InheritableNamespace[]>> {
    return this.disconnected();
  }

  async chatSend(_channelId: string, _text: string): Promise<Result<{ event_id: string }>> {
    return this.disconnected();
  }

  async chatPoll(
    _channelId: string,
    _after: string,
    _waitSeconds: number,
  ): Promise<Result<{ events: ApiChatEvent[]; cursor: string }>> {
    return this.disconnected();
  }

  async listCredentials(): Promise<Result<CredService[]>> {
    return this.disconnected();
  }

  async storeCredential(_service: string, _secret: string): Promise<Result<{ service: string; category: string }>> {
    return this.disconnected();
  }
}
