import type {
  AgentKeysClient,
  AnchorStatus,
  CapToken,
  ConfigPresetList,
  ConnectionStatus,
  CredCategorization,
  CredService,
  DisconnectedStatus,
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
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';

const DISCONNECTED: DisconnectedStatus = {
  kind: 'disconnected',
  reason: 'no-backend-configured',
  detail:
    'Set NEXT_PUBLIC_AGENTKEYS_BACKEND=daemon and AGENTKEYS_DAEMON_URL to a running agentkeys-daemon to populate this view.',
};

function disconnected<T>(): Result<T> {
  return { ok: false, status: DISCONNECTED };
}

export class EmptyBackend implements AgentKeysClient {
  async status(): Promise<ConnectionStatus> {
    return DISCONNECTED;
  }

  async startEmailVerify(): Promise<Result<EmailVerifyStart>> {
    return disconnected();
  }

  async pollEmailVerify(): Promise<Result<EmailVerifyStatus>> {
    return disconnected();
  }

  async getOnboardingState(): Promise<Result<OnboardingState>> {
    return disconnected();
  }

  async logout(): Promise<Result<void>> {
    return disconnected();
  }

  async reloginStart(): Promise<Result<ReloginStart>> {
    return disconnected();
  }

  async reloginFinish(_challenge: string, _assertion: RegisterMasterAssertion): Promise<Result<ReloginResult>> {
    return disconnected();
  }

  async resetMaster(): Promise<Result<MasterResetResult>> {
    return disconnected();
  }

  async listActors(): Promise<Result<Actor[]>> {
    return disconnected();
  }

  async getActor(): Promise<Result<Actor | null>> {
    return disconnected();
  }

  async getChainInfo(_chain?: string): Promise<Result<import('./types').ChainInfo>> {
    return disconnected();
  }

  async getChainList(): Promise<Result<import('./types').ChainList>> {
    return disconnected();
  }

  async decodeAuditEvent(_id: string): Promise<Result<import('./types').DecodedAuditEvent>> {
    return disconnected();
  }

  async listCapTokens(_actorId: string): Promise<Result<CapToken[]>> {
    return disconnected();
  }

  async listRecentAuditEvents(): Promise<Result<AuditEvent[]>> {
    return disconnected();
  }

  streamAudit(
    _onEvent: (e: AuditEvent) => void,
    onStatusChange: (s: ConnectionStatus) => void,
  ): () => void {
    onStatusChange(DISCONNECTED);
    return () => {};
  }

  async listWorkers(): Promise<Result<Worker[]>> {
    return disconnected();
  }

  async getWorker(): Promise<Result<Worker | null>> {
    return disconnected();
  }

  async getAnchorStatus(): Promise<Result<AnchorStatus>> {
    return disconnected();
  }

  async updateScope(_actorId: string, _ns: Namespace, _value: ScopeBits): Promise<Result<void>> {
    return disconnected();
  }

  async updatePaymentCap(_actorId: string, _perTx: number, _daily: number): Promise<Result<void>> {
    return disconnected();
  }

  async revokeDevice(
    _actorId: string,
    _intent: RevokeIntent,
    _onchain?: { txHash?: string; auditEnvelopeHashes?: string[] },
  ): Promise<Result<void>> {
    return disconnected();
  }

  async revokeCap(_actorId: string, _capName: string, _intent: RevokeIntent): Promise<Result<void>> {
    return disconnected();
  }

  async enrollK11Begin(): Promise<Result<K11EnrollBegin>> {
    return disconnected();
  }

  async enrollK11Finish(_input: K11EnrollFinishInput): Promise<Result<K11EnrollResult>> {
    return disconnected();
  }

  async registerMasterSubmit(_assertion: RegisterMasterAssertion): Promise<Result<RegisterMasterResult>> {
    return disconnected();
  }

  async listMemoryCategories(): Promise<Result<MemoryCategory[]>> {
    return disconnected();
  }

  async getMemoryEntries(_ns: string, _key?: string): Promise<Result<MasterMemoryEntry[]>> {
    return disconnected();
  }

  async plantMemory(_entries: MasterMemoryEntry[]): Promise<Result<PlantResult>> {
    return disconnected();
  }

  async listInbox(): Promise<Result<ApiInboxItem[]>> {
    return disconnected();
  }

  async acceptInbox(_s3Key: string): Promise<Result<{ planted: number; ns: string; key: string }>> {
    return disconnected();
  }

  async rejectInbox(_s3Key: string): Promise<Result<{ deleted: boolean }>> {
    return disconnected();
  }

  async getInboxItem(
    _s3Key: string,
  ): Promise<Result<{ body: string; ns: string; key: string; source_delegate_omni: string; ts: number }>> {
    return disconnected();
  }

  async listConfigPresets(): Promise<Result<ConfigPresetList>> {
    return disconnected();
  }

  async initConfigDefault(_presetId: string): Promise<Result<InitConfigResult>> {
    return disconnected();
  }

  async classifyEntity(_dataClass: string, _entity: string): Promise<Result<CredCategorization>> {
    return disconnected();
  }

  async proposeScopes(_actorId: string, _surface: SurfaceItem[]): Promise<Result<ProposedScope[]>> {
    return disconnected();
  }

  async grantScope(_actorId: string, _p: ProposedScope): Promise<Result<Actor>> {
    return disconnected();
  }

  async listPairingRequests(): Promise<Result<PairingRequest[]>> {
    return disconnected();
  }

  async claimPairing(_input: { code: string; label: string; scope?: string }): Promise<Result<void>> {
    return disconnected();
  }

  async registerPairing(_requestId: string): Promise<Result<void>> {
    return disconnected();
  }

  async declinePairing(_requestId: string): Promise<Result<void>> {
    return disconnected();
  }

  async ackPairing(_requestId: string): Promise<Result<void>> {
    return disconnected();
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
    return disconnected();
  }

  async acceptSubmit(_body: unknown): Promise<Result<SubmitResult>> {
    return disconnected();
  }

  async scopeBuild(_input: {
    actorOmni: string;
    services: string[];
    preserveServiceIds?: string[];
    readOnly: boolean;
  }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  > {
    return disconnected();
  }

  async scopeSubmit(_body: unknown): Promise<Result<SubmitResult>> {
    return disconnected();
  }

  async revokeBuild(_input: { deviceKeyHashes: string[] }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  > {
    return disconnected();
  }

  async revokeSubmit(_body: unknown): Promise<Result<SubmitResult>> {
    return disconnected();
  }

  async listCredentials(): Promise<Result<CredService[]>> {
    return disconnected();
  }

  async storeCredential(_service: string, _secret: string): Promise<Result<{ service: string; category: string }>> {
    return disconnected();
  }
}
