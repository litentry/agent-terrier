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
  /** Namespace (e.g. `travel`). An agent's cap/scope to read this namespace is
   *  the namespace-qualified signed service `memory:<ns>` — build it with
   *  `memoryService(ns)` (lib/constants.ts); a bare `memory` fails cap-mint
   *  (arch.md §896, #177). The configured engine ranks injected lines per query. */
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
  /** Durable category-index outcome (#201 codex finding 2): `"ok"`,
   *  `"unconfigured"`, `"failed: <reason>"` (memory saved but the category index
   *  is stale → retry), or `"skipped: <reason>"`. */
  taxonomyStatus: string;
}

/** A memory CATEGORY from the durable, master-only Config taxonomy (#178 §7 /
 *  #201). The list resolves these WITHOUT decrypting any memory blob; the
 *  per-entry detail is fetched lazily via `getMemoryEntries(ns)`. */
export interface MemoryCategory {
  ns: string;
  label: string;
}

export interface EmailVerifyStart {
  requestId: string;
}

export interface EmailVerifyStatus {
  /** "pending" | "verified" | "failed:<reason>" */
  status: string;
  /** Set when verified: the operator's identity omni (shown after login). */
  omniAccount?: string;
}

export interface OnboardingState {
  /** "verified" once the magic link is clicked + held by the daemon; else "none". */
  identity: string;
  email?: string;
  omni?: string;
  /** "enrolled" if a K11 passkey was registered this session, else "none". */
  k11: string;
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

  // §1 onboarding — real email magic-link verify (broker-backed, W1). The
  // browser starts it, then polls until the operator clicks the link.
  startEmailVerify(email: string): Promise<Result<EmailVerifyStart>>;
  pollEmailVerify(requestId: string): Promise<Result<EmailVerifyStatus>>;
  // Real "logged in" state, held by the daemon (replaces the ak_onboarded flag).
  getOnboardingState(): Promise<Result<OnboardingState>>;
  logout(): Promise<Result<void>>;

  // §2 — master memory (#201 Phase 4). The LIST resolves CATEGORIES from the
  // durable, master-only Config taxonomy (zero memory decryption, survives daemon
  // restarts); per-namespace ENTRIES decrypt lazily ON DEMAND when a category is
  // opened. PLANT is idempotent (server dedups by content-hash). An agent reads a
  // namespace only with a `memory:<ns>` scope (memoryService(ns)), and the
  // configured engine ranks what's injected (#177).
  listMemoryCategories(): Promise<Result<MemoryCategory[]>>;
  getMemoryEntries(ns: string, key?: string): Promise<Result<MasterMemoryEntry[]>>;
  plantMemory(entries: MasterMemoryEntry[]): Promise<Result<PlantResult>>;
}
