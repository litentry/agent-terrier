export type Namespace = 'personal' | 'family' | 'work' | 'travel';

export type ScopeBits = { read: boolean; write: boolean };

export type ActorRole = 'master' | 'agent';
export type StatusKind = 'ok' | 'warn' | 'bad' | 'muted';

export interface Actor {
  id: string;
  omni: string;
  omniHex: string;
  label: string;
  role: ActorRole;
  parent: string | null;
  derivation: string;
  device: string;
  devicePubkey: string;
  lastActive: string;
  status: StatusKind;
  vendor: string;
  k11: boolean;
  children?: string[];
  scope?: Record<Namespace, ScopeBits>;
  paymentCap?: { perTx: number; daily: number; currency: string };
  timeWindow?: { start: string; end: string; tz: string };
  services?: string[];
  justPaired?: boolean;
}

export type ChipKind =
  | 'default'
  | 'ok'
  | 'warn'
  | 'bad'
  | 'memory'
  | 'creds'
  | 'audit'
  | 'broker'
  | 'chain'
  | 'payment'
  | 'revoke'
  | 'scope'
  | 'device'
  | 'k11';

// ─── 9-step flow types ───────────────────────────────────────────
export interface CeremonyStep {
  label: string;
  sub: string;
  onchain?: boolean;
  fn?: string;
  /** Optional real async work the runner awaits while this step is "running"
   *  (e.g. the WebAuthn Touch ID at the §9 Stage-2 binding step). */
  action?: () => Promise<void>;
}

export interface PreservedMemory {
  ns: Namespace;
  key: string;
  title: string;
  bytes: number;
  version: string;
  updated: string;
  preview: string;
  body: string;
}

// A vaulted credential envelope for an actor (Class-B bearer token). Populated
// from the client seam (real daemon) — no seed fixture; defaults to empty.
export interface VaultItem {
  service: string;
  actor: string;
  version: string;
  bytes: number;
  readCount: number;
  status: 'ok' | 'stale';
}

export interface RequestedPerm {
  cap: string;
  ns: string[];
  reason: string;
}

export interface PairingRequest {
  id: string;
  agent: string;
  vendor: string;
  device: string;
  machine: string;
  runtime: string;
  dpub: string;
  dpubFull: string;
  pairCode: string;
  derivation: string;
  requested: RequestedPerm[];
  requestedAt: string;
  attestation: string;
}

export interface ContractInfo {
  name: string;
  addr: string;
  deployedAt: string;
  purpose: string;
}

export interface ChainProfile {
  name: string;
  display: string;
  chainId: number;
  kind: string;
  rpc: string;
  wss: string;
  substrateWss: string;
  explorer: string;
  tokenSymbol: string;
  tokenDecimals: number;
  finality: string;
  block: string;
  contracts: ContractInfo[];
}

export interface AuditEvent {
  id: string;
  ts: string;
  actorId: string;
  actor: string;
  kind: string;
  detail: string;
  chip: ChipKind;
  sev: StatusKind;
  _isNew?: boolean;
}

export interface Worker {
  id: 'memory' | 'credentials' | 'audit' | 'email' | 'payment';
  title: string;
  host: string;
  desc: string;
  callsToday: number;
  callsHour: number;
  p50: number;
  p95: number;
  cap: string;
  byActor: { actor: string; count: number; share: number }[];
}

export type PendingAction =
  | {
      kind: 'revoke-device';
      actor: Actor;
      intent: { text: string; fields: [string, string][] };
    }
  | {
      kind: 'revoke-scope';
      actor: Actor;
      capName: string;
      intent: { text: string; fields: [string, string][] };
    };
