import type {
  AgentKeysClient,
  AnchorStatus,
  CapToken,
  ConnectionStatus,
  DisconnectedStatus,
  K11EnrollBegin,
  K11EnrollFinishInput,
  K11EnrollResult,
  MasterMemoryEntry,
  PlantResult,
  Result,
  RevokeIntent,
} from './types';
import type { Actor, AuditEvent, Namespace, ScopeBits, Worker } from '@/app/_components/types';

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

  async listActors(): Promise<Result<Actor[]>> {
    return disconnected();
  }

  async getActor(): Promise<Result<Actor | null>> {
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

  async revokeDevice(_actorId: string, _intent: RevokeIntent): Promise<Result<void>> {
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

  async listMasterMemory(): Promise<Result<MasterMemoryEntry[]>> {
    return disconnected();
  }

  async plantMemory(_entries: MasterMemoryEntry[]): Promise<Result<PlantResult>> {
    return disconnected();
  }
}
