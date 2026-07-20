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
  /** What this actor IS, from its binding: 'device' | 'delegate'. Absent =
   *  unknown (no binding-manifest entry, e.g. rebuilt from chain) — which is
   *  NOT the same as 'delegate'. Never infer this from the scope. */
  kind?: string;
  paymentCap?: { perTx: number; daily: number; currency: string };
  timeWindow?: { start: string; end: string; tz: string };
  services?: string[];
  /** #429 — the preset the delegate was spawned from (#424 manifest layer). */
  presetId?: string;
  /** #429 — the delegate's memory:<ns> namespace name (manifest layer). */
  memoryNs?: string;
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
  /**
   * #408 D6 — the claim's scope is ONLY channel-pub/sub grants ⇒ this is a
   * channel-endpoint DEVICE claim (camera, display, console). Device claims are
   * handled on the channels page (its accept card hard-enforces ≥1 channel,
   * §14.10); the pairing page keeps sandbox DELEGATE claims only. Derived by the
   * daemon with the same predicate the broker's D9 no-spawn gate uses.
   */
  isDevice?: boolean;
}

/** `channel-pub:<id>` / `channel-sub:<id>` — the only grants a device may hold (D6). */
export const isChannelService = (svc: string): boolean => /^channel-(pub|sub):/i.test(svc.trim());

/** A bound actor whose known grants are all channel services = a channel-endpoint
 *  device (D6). Only decidable when the daemon knows the service NAMES (accepts
 *  done through this daemon session); after a daemon restart a chain-reconstructed
 *  device falls back to the pairing page's delegate grid with hash-only grants. */
export const actorIsChannelEndpoint = (a: Actor): boolean => {
  // The BINDING decides what an actor is — not what it is currently allowed to
  // do. This used to be scope-shape only ("every grant is a channel grant"),
  // which meant revoking a device's grants left it with an empty scope and
  // silently demoted it to a delegate: a real paired device then showed up
  // under Delegates, unrecognizable, while an unrelated agent that happened to
  // hold only channel grants was presented as the device.
  if (a.kind === 'device') return true;
  if (a.kind === 'delegate') return false;
  // Unknown binding (rebuilt from chain, no manifest entry): fall back to the
  // scope shape, which is only evidence when the scope is NON-EMPTY. An empty
  // scope proves nothing, so it must not read as either type.
  return (a.services?.length ?? 0) > 0 && (a.services ?? []).every(isChannelService);
};

/** True when we genuinely cannot tell a device from a delegate — no binding
 *  record AND no scope to infer from. The UI should say so rather than pick. */
export const actorTypeIsUnknown = (a: Actor): boolean =>
  !a.kind && (a.services?.length ?? 0) === 0;

/** Mirrors the daemon's `valid_channel_id`: 1..=48 of [a-z0-9-], no edge dash. */
export const isValidChannelId = (id: string): boolean =>
  /^[a-z0-9-]{1,48}$/.test(id) && !id.startsWith('-') && !id.endsWith('-');

/** The channel an agent's chat tab talks on: the one it actually HOLDS A GRANT
 *  for. `null` = it has none and its label cannot form a valid id.
 *
 *  This used to be `opchat-${label}`, which broke as soon as a label was a
 *  placeholder like "agent 0x346391ed…" — spaces and "…" are not legal channel-id
 *  characters, so every poll/send returned 400 `invalid channel_id`. A label is
 *  display text and may be anything; the grant is the binding. The label is kept
 *  only as a last-resort fallback, and only when it is actually valid. */
export const agentChatChannelId = (a: Actor): string | null => {
  const services = a.services ?? [];
  const idsWithPrefix = (prefix: string) =>
    services.filter((s) => s.startsWith(prefix)).map((s) => s.slice(prefix.length));
  const fromLabel = `opchat-${a.label}`;
  return (
    idsWithPrefix('channel-pub:')[0] ??
    idsWithPrefix('channel-sub:')[0] ??
    (isValidChannelId(fromLabel) ? fromLabel : null)
  );
};

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
