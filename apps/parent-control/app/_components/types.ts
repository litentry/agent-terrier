export type Namespace = 'personal' | 'family' | 'work' | 'travel';

// Two INDEPENDENT per-namespace grants (#339): `read` = `memory:<ns>` (read the
// master's shared canonical memory); `write` = `inbox:<ns>` (write/suggest into the
// master's inbox, which the master curates). The delegate NEVER writes the master's
// shared memory directly, and its own local memory is its own — neither is `write`.
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
  /** #225 E7: on-chain account address — the master's passkey P256Account
   *  (operatorMasterWallet), or an agent's K10 device omni. */
  accountAddress?: string;
  /** "p256account" (bound smart-account master) | "device" (agent) | "none"
   *  (master not yet registered on chain — show the register CTA). */
  accountType?: string;
  children?: string[];
  scope?: Record<Namespace, ScopeBits>;
  /** #248: on-chain scope service ids (keccak hex) that aren't a known
   *  `memory:<ns>` (e.g. `cred:<service>` from the accept). The panel's
   *  set-replace commit echoes these back so a memory toggle can't wipe them. */
  scopeUnknownServiceIds?: string[];
  /** On-chain SidecarRegistry device key hash — the Touch-ID unpair's target
   *  (revokeAgentDevice must run as the master-account UserOp). */
  deviceKeyHash?: string;
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
  /** When set (e.g. "1 of 2"), renders a "Touch ID · <n of m>" badge so the user
   *  expects the biometric prompt — the master onboarding fires TWO (create the
   *  passkey, then sign its on-chain registration), which surprises people. */
  touchId?: string;
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
  // #224 — the cross-verifiable device identity: the agent's `--request-pairing`
  // prints `device_key_hash`, so the operator confirms it matches before approving.
  deviceKeyHash: string;
  deviceKeyHashShort: string;
  pairCode: string;
  derivation: string;
  requested: RequestedPerm[];
  /** Unix seconds the agent requested pairing (`created_at`). Formatted in the UI. */
  requestedAt: number;
  /**
   * #224 — Unix seconds the pairing request expires (`expires_at`), the SAME value
   * the agent's `--request-pairing` prints. The card renders a live countdown off
   * it so a STALE card (already past expiry / an old start) is visibly the one to
   * refuse. 0 when the broker row predates the field.
   */
  expiresAt: number;
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
  /** #97: confirmed on-chain tx for control-plane ops (accept/scope/revoke). */
  txHash?: string;
  /** #97: AuditEnvelope receipt hashes — the decode view fetches the REAL
   *  envelopes by these instead of synthesizing a preview. */
  auditEnvelopeHashes?: string[];
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
