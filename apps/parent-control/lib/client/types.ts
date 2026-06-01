import type { Actor, AuditEvent, Namespace, ScopeBits, Worker } from '@/app/_components/types';

export type ConnectionStatus =
  | { kind: 'disconnected'; reason: 'no-backend-configured' | 'unreachable' | 'unauthorized'; detail?: string }
  | { kind: 'connected'; via: 'daemon' | 'broker' | 'mock'; endpoint: string };

export type DisconnectedStatus = Extract<ConnectionStatus, { kind: 'disconnected' }>;

export type Result<T> =
  | { ok: true; data: T }
  | { ok: false; status: DisconnectedStatus };

export interface AnchorBatch {
  ts: string;
  root: string;
  count: number;
  txn: string;
  conf: number;
}

export interface AnchorStatus {
  lastAnchorAt: number;
  nextAnchorIn: number;
  recent: AnchorBatch[];
}

export interface CapToken {
  id: string;
  cap: string;
  scope: string;
  ttl: string;
  minted: string;
  danger?: boolean;
}

export interface K11EnrollBegin {
  challenge: string;
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  bindingNonce: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout: number;
}

export interface K11EnrollFinishInput {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
  bindingNonce: string;
}

export interface K11EnrollResult {
  credentialId: string;
  registeredAt: number;
  chainTxHash?: string;
}

export interface RevokeIntent {
  text: string;
  fields: [string, string][];
}

export interface MasterMemoryEntry {
  ns: string;
  key: string;
  title: string;
  bytes: number;
  version: string;
  updated: string;
  preview: string;
  body: string;
  contentHash?: string;
}

export interface PlantResult {
  planted: number;
  skipped: number;
  total: number;
}

export interface AgentKeysClient {
  status(): Promise<ConnectionStatus>;

  listActors(): Promise<Result<Actor[]>>;
  getActor(id: string): Promise<Result<Actor | null>>;
  listCapTokens(actorId: string): Promise<Result<CapToken[]>>;
  listRecentAuditEvents(opts?: { actorId?: string; limit?: number }): Promise<Result<AuditEvent[]>>;
  streamAudit(onEvent: (e: AuditEvent) => void, onStatusChange: (s: ConnectionStatus) => void): () => void;

  listWorkers(): Promise<Result<Worker[]>>;
  getWorker(id: Worker['id']): Promise<Result<Worker | null>>;
  getAnchorStatus(): Promise<Result<AnchorStatus>>;

  updateScope(actorId: string, ns: Namespace, value: ScopeBits): Promise<Result<void>>;
  updatePaymentCap(actorId: string, perTx: number, daily: number): Promise<Result<void>>;
  revokeDevice(actorId: string, intent: RevokeIntent): Promise<Result<void>>;
  revokeCap(actorId: string, capName: string, intent: RevokeIntent): Promise<Result<void>>;

  enrollK11Begin(input: { userName: string; userDisplayName: string }): Promise<Result<K11EnrollBegin>>;
  enrollK11Finish(input: K11EnrollFinishInput): Promise<Result<K11EnrollResult>>;

  // §2 — master memory (real list + idempotent plant; server dedups by content-hash)
  listMasterMemory(): Promise<Result<MasterMemoryEntry[]>>;
  plantMemory(entries: MasterMemoryEntry[]): Promise<Result<PlantResult>>;
}
