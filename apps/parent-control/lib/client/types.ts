import type { Actor, AuditEvent, Namespace, PairingRequest, ScopeBits, Worker } from '@/app/_components/types';
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';
import type { ApiPersonaEditResponse } from '@/lib/generated/ApiPersonaEditResponse';
import type { ApiPersonaState } from '@/lib/generated/ApiPersonaState';
import type { ApiChatEvent } from '@/lib/generated/ApiChatEvent';
import type { ApiRegisterState } from '@/lib/generated/ApiRegisterState';
import type { BuildArchiveUserOpResponse } from '@/lib/generated/BuildArchiveUserOpResponse';
import type { BuildSpawnUserOpResponse } from '@/lib/generated/BuildSpawnUserOpResponse';
import type { ContextKind } from '@/lib/generated/ContextKind';
import type { PresetCatalogResponse } from '@/lib/generated/PresetCatalogResponse';
import type { SubmitAcceptUserOpResponse } from '@/lib/generated/SubmitAcceptUserOpResponse';

/** #429 — one inheritable (kept, archived, currently-unheld) memory namespace. */
export interface InheritableNamespace {
  ns: string;
  /** The archived delegate the namespace came from. */
  fromLabel: string;
  archivedAt: number;
}

/** #339/#390 — one decrypted inbox proposal (daemon `POST /v1/master/inbox/entry`).
 *  `kind` drives the per-kind curate gate; `content_hash` is the skill accept's
 *  viewed-body watermark. */
export interface InboxItemBody {
  body: string;
  ns: string;
  key: string;
  source_delegate_omni: string;
  content_hash: string;
  ts: number;
  kind: ContextKind;
}

/** #390 — one live context file shaping the bound agent. Shape owned by the
 *  sandbox bridge (`hermes_bridge.py context_files()`), proxied verbatim by
 *  the daemon (`GET /v1/master/agent/context`) — NOT a ts-rs type because the
 *  producer is Python, not Rust. */
export interface AgentContextFile {
  id: 'soul' | 'agents' | 'agent_terrier' | 'config';
  path: string;
  editable: boolean;
  present: boolean;
  content?: string;
  /** The owner-editable part of AGENTS.md (above the locked-terrier marker). */
  owner_content?: string;
  sha256?: string;
  bytes?: number;
}

export interface AgentContextView {
  /** false = no sandbox bridge configured on the daemon — a legit absent state. */
  configured: boolean;
  files: AgentContextFile[];
}

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
  /** #225 E7: "register-pending" (browser must sign + submit), "master-registered"
   *  (idempotent skip — already on chain), or "none". */
  chain?: string;
  /** #278 D6: set when chain === "none" because the register actually FAILED (broker
   *  /v1/register/build error / paymaster misconfig), as opposed to a clean dev skip
   *  (no chainError). The ceremony surfaces this instead of proceeding silently. */
  chainError?: string;
  /** #225 E7: when chain === "register-pending", the userOpHash the browser passkey
   *  must sign (second Touch ID) and POST to register/submit. */
  registerUserOpHash?: string;
  /** #225 E7: the deployed master P256Account address (operatorMasterWallet-to-be). */
  registerAccount?: string;
}

/** #225 E7: the browser `get()` assertion over the register userOpHash. */
export interface RegisterMasterAssertion {
  authenticator_data: string;
  client_data_json: string;
  signature: string;
  credential_id: string;
}

export interface RegisterMasterResult {
  ok: boolean;
  txHash?: string;
  account?: string;
  /** #278 D6: the daemon's onboarding chain state for this submit —
   *  "master-registered" (bound + confirmed) or "register-pending" (broadcast
   *  but the receipt is unconfirmed; the master is NOT yet bound). */
  chain?: string;
  /** True when the register op was broadcast but its receipt hasn't confirmed:
   *  the master is NOT bound yet, so the ceremony must keep polling onboarding
   *  state and must NOT persist the passkey pointer or complete onboarding. */
  pending?: boolean;
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

/** A bundled default taxonomy preset (#207 item 1A, config-init entry point A).
 *  `categories` is the authored category tree the preset writes — the namespaces
 *  become the memory data class's category axis (`memory:<ns>`). These are
 *  shared bundled defaults (catalog ≠ policy: categories, never grants). */
export interface ConfigPreset {
  id: string;
  label: string;
  description: string;
  categories: MemoryCategory[];
}

export interface ConfigPresetList {
  /** The shipped default preset id (the rich adult-household profile). */
  defaultId: string;
  presets: ConfigPreset[];
}

export interface InitConfigResult {
  /** The preset actually authored (the resolved default for an empty id). */
  presetId: string;
  /** `"ok"` (durable Config written) or `"cached"` (Config unconfigured —
   *  authored into the daemon's in-memory mirror only, dev/no-infra). */
  taxonomyStatus: string;
  /** The merged category set now in effect (authored ∪ any pre-existing). */
  categories: MemoryCategory[];
}

export type Sensitivity = 'safe' | 'sensitive';

/** The classifier's TAG output (#207 items 5/7). The `sensitivity` is the
 *  CATALOG's floor — never a vendor/telemetry prior (§3 invariant 2). An unknown
 *  entity is `category: "unknown"`, `sensitive`, confidence 0 (deny-by-default). */
export interface Classification {
  category: string;
  sensitivity: Sensitivity;
  confidence: number;
  source: string;
}

/** A credential categorization (#207 item 7). `service` is the `cred:<id>` /
 *  service string a scope grant would be over; `audited` is true when the cap-gated
 *  worker path ran (vs the local catalog tier-0). */
export interface CredCategorization {
  dataClass: string;
  entity: string;
  service: string;
  classification: Classification;
  audited: boolean;
}

/** A proposed scope from connect-time auto-distribution (#207 item 5). `gating`
 *  is the sensitivity tier: `auto` (Safe → auto-confirm + daily review) or `k11`
 *  (Sensitive → explicit per-grant K11 confirm). PROPOSED only — never granted
 *  until the master confirms via the K11-gated scope path. */
export interface ProposedScope {
  dataClass: string;
  entity: string;
  service: string;
  category: string;
  sensitivity: Sensitivity;
  gating: 'auto' | 'k11';
  confidence: number;
}

/** One item of an agent's surface to classify: a cred service or a memory ns. */
export interface SurfaceItem {
  dataClass: string;
  entity: string;
}

/** A stored master credential, categorized via the catalog — the cred parallel to
 *  a memory category (#207). Credentials are a first-class data class in the app,
 *  same list-then-categorize abstraction as memory. */
export interface CredService {
  service: string;
  category: string;
  sensitivity: Sensitivity;
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

/** #242: the logout-surviving identity hint — who the "Sign back in with
 *  Touch ID" button would sign back in. Display only; the broker re-verifies
 *  the passkey against the CHAIN before minting anything. */
export interface ReloginInfo {
  email?: string;
  omni: string;
}

export interface OnboardingState {
  /** "verified" once the magic link is clicked + held by the daemon; else "none". */
  identity: string;
  email?: string;
  omni?: string;
  /** "enrolled" if a K11 passkey was registered this session, else "none". */
  k11: string;
  /** "master-registered" once the master device is on chain with CAP_MINT (#196)
   *  FOR THE LIVE SESSION's omni (#242 cross-email guard); else "none". */
  chain?: string;
  /**
   * Durable-session signal for restart-resume (issue #220):
   *   - "active"  → a still-valid J1 is held (rehydrated or fresh): memory/config work with ZERO prompts;
   *   - "expired" → master coords are persisted but the J1 lapsed: prompt exactly ONE passkey re-auth (NOT a re-onboarding);
   *   - "none"    → no persisted master session: full onboarding required.
   */
  session?: string;
  /** #242: present when the daemon still knows who the master is (survives
   *  logout; cleared by master reset) — drives the Touch ID re-login button. */
  relogin?: ReloginInfo;
}

/** `POST /v1/auth/relogin/start` (#242): the challenge the bound passkey signs. */
export interface ReloginStart {
  /** `0x` + 64 hex — sign via `getAssertionOverHash(challenge, [credId])`. */
  challenge: string;
  /** The on-chain master P256Account the assertion must satisfy. */
  account: string;
  email: string;
  omni: string;
}

/** `POST /v1/auth/relogin/finish` (#242): the restored identity. */
export interface ReloginResult {
  omni: string;
  email?: string;
}

/** On-chain half of `POST /v1/master/reset` (#225 E7) — the owner-gated resetMaster. */
export interface MasterResetOnchain {
  /** "reset" = operatorMasterWallet cleared this call; "skipped" = nothing to do / not wired;
   *  "failed" = on-chain unbind errored; "aborted" = #260 hard stop — account-master agents
   *  still bound, nothing mutated (run the Touch-ID fleet revoke, then reset again). */
  status: 'reset' | 'skipped' | 'failed' | 'aborted';
  /** Present on "skipped" — "already-unbound" | "no-register-script-configured" | "no-operator-omni-known". */
  reason?: string;
  /** Present on "failed" — the script/cast error (e.g. registry pre-VERSION-0.3 has no resetMaster). */
  error?: string;
  tx_hash?: string;
  operator_omni?: string;
}

/** Fleet-teardown half of `POST /v1/master/reset` (#243): what the reset
 *  disconnected beyond the master binding. Best-effort — anything that could
 *  not be torn down remotely lands in `failures`, never silently dropped. */
export interface MasterResetFleet {
  /** Pending pairing requests declined at the broker. */
  pending_declined: number;
  /** Paired agents revoked on chain (SidecarRegistry.revokeAgentDevice).
   *  `already_revoked` rows were found revoked on chain (the pre-reset
   *  Touch-ID fleet revoke landed them) — no script tx this call. */
  agents_revoked: { id: string; label: string; tx_hash?: string; already_revoked?: boolean }[];
  /** Local actor records cleared (agents + master view rows). */
  actors_cleared: number;
  /** The daemon's K11 enroll record was cleared (state reports k11: "none"). */
  k11_enroll_cleared: boolean;
  /** What could NOT be torn down (no chain script, broker error, …). */
  failures: string[];
  /** #260 abort only: agents still bound on chain that only the master
   *  P256Account can revoke — feed their hashes to the Touch-ID fleet revoke. */
  agents_still_bound?: { id: string; label: string; device_key_hash?: string | null }[];
}

/** Result of `GET /v1/master/register/preflight` — can the broker BUILD a
 *  sponsored master register right now? `register_ready: false` = its
 *  sponsored-register runtime is down (503). Two guards read it: RESET (an
 *  unbind that could never re-onboard would STRAND the identity — the
 *  2026-07-16 VE incident) and ONBOARDING (minting a passkey the broker can't
 *  register orphans it in the Secure Enclave and the 2nd Touch ID never fires
 *  — the 2026-07-17 observation). */
export interface RegisterPreflight {
  register_ready: boolean;
  /** Which path vouched: 'broker' (probed live), 'script' (no broker — the
   *  legacy local register script), 'indeterminate' (no session to probe with). */
  path?: string;
  /** The broker's own error detail when register_ready is false. */
  detail?: string;
}

/** Result of `POST /v1/master/reset` (#225 E7, fleet teardown #243, #260 guard). */
export interface MasterResetResult {
  ok: boolean;
  /** #260: true when the reset aborted because account-master agents are still
   *  bound — run the one-Touch-ID fleet revoke, then reset again. */
  needs_fleet_revoke?: boolean;
  /** 2026-07-16 guard: true when the reset was refused because the broker
   *  cannot re-register a master (a reset would strand the identity). */
  needs_register_path?: boolean;
  /** Operator guidance — adapts to whether the on-chain unbind landed. */
  note?: string;
  onchain?: MasterResetOnchain;
  fleet?: MasterResetFleet;
}

/** One deployed contract from `GET /v1/chain/info` (real address + explorer link). */
export interface ChainContract {
  name: string;
  address: string;
  purpose: string;
  deployedAt: string;
  explorerUrl: string;
}

/** Chain the daemon targets + its deployed contract registry (#153). */
export interface ChainInfo {
  name: string;
  display: string;
  chainId: number;
  rpc: string;
  wss: string;
  explorer: string;
  tokenSymbol: string;
  tokenDecimals: number;
  finality: string;
  contracts: ChainContract[];
  /** The chain the daemon OPERATES on (#282 switcher) — may differ from
   *  `name` when the UI is viewing another chain via `?chain=`. Optional
   *  for older daemons. */
  daemonChain?: string;
  /** Broker URL the daemon is bound to (#373 stack identity; null/absent for
   *  a brokerless or older daemon). */
  daemonBroker?: string | null;
}

/** One built-in chain profile from `GET /v1/chain/list` (#282 switcher). */
export interface ChainListEntry {
  name: string;
  display: string;
  chainId: number;
  contracts: number;
}

/** All built-in chains + which one the daemon operates on (#282 switcher). */
export interface ChainList {
  chains: ChainListEntry[];
  daemonChain: string;
  /** Broker URL the daemon is bound to (#373 — the (chain, broker) stack
   *  identity; null/absent for a brokerless or older daemon). */
  daemonBroker?: string | null;
}

/** One operator stack — a (chain, broker) pair — from `GET /v1/stack/list`
 *  (#373: the stack axis gained a cloud dimension; Heima-AWS and Heima-VE are
 *  the SAME chain behind DIFFERENT brokers/data planes). */
export interface StackEntry {
  name: string;
  chain: string;
  brokerUrl: string;
  /** This is the stack the daemon runs (chain AND broker match). */
  active: boolean;
  /** Live daemon-side `/healthz` probe of the stack's broker — false renders
   *  the stack degraded (e.g. the VE broker until its runtime port boots). */
  healthy: boolean;
}

/** The operator's stack inventory + the daemon's own binding (#373). */
export interface StackList {
  stacks: StackEntry[];
  daemonChain: string;
  daemonBroker?: string | null;
}

/** One ABI-decoded argument of a transaction's calldata. */
export interface DecodedArg {
  name: string;
  ty: string;
  value: unknown;
}

/** Calldata decoded against a verified contract ABI (real selector + typed args). */
export interface DecodedCalldata {
  contract: string;
  function: string;
  signature: string;
  selector: string;
  args: DecodedArg[];
  /** Set when some args (e.g. a WebAuthn assertion tuple) were not ABI-expanded. */
  note?: string;
  calldata: string;
  intent_tx_hash: string;
}

/** The on-chain transaction half of a decoded audit event. */
export interface DecodedTx {
  to_contract: string;
  to_address: string;
  explorer_url: string | null;
  decoded: DecodedCalldata;
}

/** The CBOR `AuditEnvelope v1` half of a decoded audit event. */
export interface DecodedEnvelope {
  envelope_hash: string;
  version: number;
  ts_unix: number;
  actor_omni: string;
  operator_omni: string;
  op_kind: number;
  op_kind_label: string | null;
  op_body: Record<string, unknown>;
  result: number;
  intent_text: string | null;
  intent_commitment: string | null;
  canonical_cbor?: string;
}

/** `GET /v1/audit/:id/decode` — both decode halves + the anchoring tier (#153). */
/** #97: the typed broker submit response relayed by the daemon proxies —
 *  `auditEnvelopeHashes` are the AuditEnvelope receipts the broker emitted for
 *  the landed executeBatch (DeviceAdd/ScopeGrant/ScopeRevoke/DeviceRevoke). */
export interface SubmitResult {
  ok: boolean;
  txHash?: string;
  blockNumber?: string;
  userOpHash?: string;
  /** true ⇒ broadcast but unconfirmed (receipt poll timed out); no receipts. */
  pending?: boolean;
  auditEnvelopeHashes?: string[];
}

export interface DecodedAuditEvent {
  id: string;
  kind: string;
  tier: string;
  tier_label: string;
  /** True when the decode is reconstructed from the audit row (preview), not
   *  fetched from a stored on-chain envelope/tx. Hashes are derived, not chain. */
  synthesized?: boolean;
  /** Human-readable provenance note for the synthesized/preview state. */
  provenance?: string;
  envelope: DecodedEnvelope | null;
  /** #97: ALL real envelopes fetched by receipt hash (an accept carries two:
   *  DeviceAdd + ScopeGrant). `envelope` stays the first for back-compat. */
  envelopes?: DecodedEnvelope[];
  /** #97: the confirmed on-chain tx hash from the submit receipt. */
  tx_hash?: string;
  tx: DecodedTx | null;
}

export interface AgentKeysClient {
  status(): Promise<ConnectionStatus>;

  /** Chain + deployed-contract registry for the chain page (#153). Pass a
   *  built-in chain name to VIEW another chain's registry (#282 switcher —
   *  display-only; the daemon's operational chain is unaffected). */
  getChainInfo(chain?: string): Promise<Result<ChainInfo>>;
  /** Built-in chain profiles + the daemon's operational chain (#282). */
  getChainList(): Promise<Result<ChainList>>;
  /** Operator stack inventory — (chain, broker) pairs + which one the daemon
   *  runs and per-broker health (#373 stack selector). */
  getStackList(): Promise<Result<StackList>>;
  /** Decode one audit event's CBOR envelope + on-chain calldata (#153). */
  decodeAuditEvent(id: string): Promise<Result<DecodedAuditEvent>>;

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
  revokeDevice(
    actorId: string,
    intent: RevokeIntent,
    onchain?: { txHash?: string; auditEnvelopeHashes?: string[] },
  ): Promise<Result<void>>;
  revokeCap(actorId: string, capName: string, intent: RevokeIntent): Promise<Result<void>>;

  enrollK11Begin(input: { userName: string; userDisplayName: string }): Promise<Result<K11EnrollBegin>>;
  enrollK11Finish(input: K11EnrollFinishInput): Promise<Result<K11EnrollResult>>;
  // #225 E7: phase 2 of the master register — submit the browser assertion over
  // the register userOpHash → handleOps binds operatorMasterWallet = the P256Account.
  registerMasterSubmit(assertion: RegisterMasterAssertion): Promise<Result<RegisterMasterResult>>;

  // §1 onboarding — real email magic-link verify (broker-backed, W1). The
  // browser starts it, then polls until the operator clicks the link.
  startEmailVerify(email: string): Promise<Result<EmailVerifyStart>>;
  pollEmailVerify(requestId: string): Promise<Result<EmailVerifyStatus>>;
  // Real "logged in" state, held by the daemon (replaces the ak_onboarded flag).
  getOnboardingState(): Promise<Result<OnboardingState>>;
  // #435 — the FRESH on-chain bound-probe (operatorMasterWallet), consulted
  // BEFORE any navigator.credentials.create: bound ⇒ skip enroll+register.
  getRegisterState(): Promise<Result<ApiRegisterState>>;
  logout(): Promise<Result<void>>;
  // #242 — one-Touch-ID master re-login after a logout (no email round-trip).
  // start → broker challenge for the held identity; the browser signs it with
  // the BOUND passkey; finish → the broker chain-verifies the assertion and the
  // daemon restores the full master session.
  reloginStart(): Promise<Result<ReloginStart>>;
  reloginFinish(challenge: string, assertion: RegisterMasterAssertion): Promise<Result<ReloginResult>>;
  // #225 E7: fully unbind the master so the operator can re-onboard a fresh passkey —
  // used when the bound master passkey was deleted in the OS password manager. Clears
  // BOTH the LOCAL binding (registered_master + persisted coords) AND the ON-CHAIN
  // operatorMasterWallet (owner-gated resetMaster via the deployer). `onchain` reports
  // whether the on-chain unbind landed; `note` carries the operator guidance. Cannot
  // delete the OS passkey (WebAuthn) — the operator does that manually.
  resetMaster(): Promise<Result<MasterResetResult>>;
  registerPreflight(): Promise<Result<RegisterPreflight>>;

  // §2 — master memory (#201 Phase 4). The LIST resolves CATEGORIES from the
  // durable, master-only Config taxonomy (zero memory decryption, survives daemon
  // restarts); per-namespace ENTRIES decrypt lazily ON DEMAND when a category is
  // opened. PLANT is idempotent (server dedups by content-hash). An agent reads a
  // namespace only with a `memory:<ns>` scope (memoryService(ns)), and the
  // configured engine ranks what's injected (#177).
  listMemoryCategories(): Promise<Result<MemoryCategory[]>>;
  getMemoryEntries(ns: string, key?: string): Promise<Result<MasterMemoryEntry[]>>;
  plantMemory(entries: MasterMemoryEntry[]): Promise<Result<PlantResult>>;
  // #339 P2 — absorption-inbox curate: list the queue, accept one INTO canonical
  // (merge + GC), or reject (GC only). `ApiInboxItem` is the ts-rs-generated wire type.
  // #390 — accept takes the viewed-body watermark (the item's content_hash) REQUIRED
  // for `skill` proposals; `persona` proposals are never adoptable (403).
  listInbox(): Promise<Result<ApiInboxItem[]>>;
  acceptInbox(
    s3Key: string,
    confirmContentHash?: string,
  ): Promise<Result<{ planted: number; ns: string; key: string }>>;
  rejectInbox(s3Key: string): Promise<Result<{ deleted: boolean }>>;
  getInboxItem(s3Key: string): Promise<Result<InboxItemBody>>;

  // #390 — the per-delegate persona (`SOUL.md`) editor + the agent restart /
  // live-context legs (master-hub-topology.md §16). `ApiPersonaState` /
  // `ApiPersonaEditResponse` are ts-rs-generated wire types; the context-files
  // shape is owned by the sandbox bridge (hermes_bridge.py `context_files()`),
  // proxied verbatim by the daemon.
  getPersona(delegateOmni: string): Promise<Result<ApiPersonaState>>;
  editPersona(delegateOmni: string, body: string): Promise<Result<ApiPersonaEditResponse>>;
  rollbackPersona(
    delegateOmni: string,
    version: number,
  ): Promise<Result<ApiPersonaEditResponse>>;
  restartAgent(): Promise<Result<{ restarted: boolean }>>;
  getAgentContext(): Promise<Result<AgentContextView>>;

  // §1A onboarding — config-init entry point A (default-preset bootstrap, #207
  // item 1A). `listConfigPresets` returns the bundled default taxonomies + the
  // shipped default id; `initConfigDefault` AUTHORS the master-only memory-types
  // taxonomy from the chosen preset (master-self, no K11 — it writes the category
  // INDEX, not scope grants). Entry point B (NL → COMPILE) is #207 item 1B,
  // deferred.
  listConfigPresets(): Promise<Result<ConfigPresetList>>;
  initConfigDefault(presetId: string): Promise<Result<InitConfigResult>>;

  // §classifier (#207 items 5/7). `classifyEntity` categorizes one entity (cred
  // auto-categorize, item 7); `proposeScopes` classifies an agent's surface and
  // returns sensitivity-tiered PROPOSED scopes (connect-time auto-distribute,
  // item 5). Neither writes scope — granting stays on the K11-gated path.
  classifyEntity(dataClass: string, entity: string): Promise<Result<CredCategorization>>;
  proposeScopes(actorId: string, surface: SurfaceItem[]): Promise<Result<ProposedScope[]>>;
  // Record a CONFIRMED auto-distribute grant (#207 items 5/7/8). Persists the
  // memory-namespace / cred-service grant in actor state + audits; returns the
  // updated actor. Reached ONLY after the master confirms (sensitive ⇒ K11).
  grantScope(actorId: string, p: ProposedScope): Promise<Result<Actor>>;

  // §pairing (#214) — the web-app half of the §10.2 agent-initiated ceremony.
  // `listPairingRequests` polls the broker rendezvous (daemon GET
  // /v1/agent/pairing/pending) for agents the master has claimed that await
  // on-chain register + scope. REAL data; the device key never touches the
  // master. (claim-by-code + register + scope land in follow-up slices.)
  listPairingRequests(): Promise<Result<PairingRequest[]>>;
  // Claim an agent's one-time pairing code (#214 §10.2 P.1) — binds it under a
  // label + declares its requested scope via the broker. The agent then appears
  // in listPairingRequests() awaiting on-chain register.
  claimPairing(input: { code: string; label: string; scope?: string }): Promise<Result<void>>;
  // Approve a claimed agent (#214 §10.2 P.2) — the daemon submits registerAgentDevice
  // on chain for the binding's request_id, then acks the broker. (The Touch-ID scope
  // grant is the separate grantScope step, P.3.)
  registerPairing(requestId: string): Promise<Result<void>>;
  // Decline a claimed pairing request (J1-gated, NO Touch ID) — the daemon tells the
  // broker to drop the pending rendezvous row so it stops reappearing on refresh.
  declinePairing(requestId: string): Promise<Result<void>>;
  // #225 E7: after the on-chain accept lands, mark the binding bound so the broker drops
  // it from pending (the accept/submit body carries no request_id). J1-gated, no Touch ID.
  ackPairing(requestId: string): Promise<Result<void>>;

  // #225 E7 — the Touch-ID-gated accept. `acceptBuild` → broker assembles the
  // sponsored executeBatch([registerAgentDevice, setScope]) UserOp + returns the
  // userOpHash the browser K11-signs; `acceptSubmit` relays the signed op (+ the
  // assertion) → EntryPoint.handleOps.
  acceptBuild(input: {
    requestId: string;
    services: string[];
    readOnly: boolean;
    maxPerCall: string;
    maxPerPeriod: string;
    maxTotal: string;
    periodSeconds: number;
    /** #408 — a channel-endpoint DEVICE accept (channels page): forwarded to the
     *  broker's `is_device` (§14.10 warn); the card hard-enforces ≥1 channel. */
    isDevice?: boolean;
  }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  >;
  acceptSubmit(body: unknown): Promise<Result<SubmitResult>>;

  // #248 — the Touch-ID-gated scope re-grant for an ALREADY-bound agent (the
  // permissions panel's commit). `scopeBuild` → broker assembles the
  // executeBatch([setScope]) UserOp + returns the userOpHash the browser
  // K11-signs; `scopeSubmit` relays the signed op → EntryPoint.handleOps.
  // `services` is the FULL replacement list (setScope is set-replace; empty
  // revokes every grant).
  scopeBuild(input: {
    actorOmni: string;
    services: string[];
    /** `Actor.scopeUnknownServiceIds` echoed back — grants the panel can't name
     *  (e.g. `cred:<service>`) that must survive the set-replace. */
    preserveServiceIds?: string[];
    readOnly: boolean;
  }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  >;
  scopeSubmit(body: unknown): Promise<Result<SubmitResult>>;

  // The Touch-ID unpair: `revokeAgentDevice` requires msg.sender ==
  // operatorMasterWallet, so for an account-master operator the revoke is a
  // master-account UserOp the browser K11-signs (one hash = the per-agent
  // unpair; every paired agent = the #260 pre-reset fleet teardown, ONE Touch
  // ID). After submit, call `revokeDevice(actorId, intent, { txHash })` — the
  // daemon then VERIFIES the registry reads `revoked` and flips local state
  // without the legacy script.
  revokeBuild(input: { deviceKeyHashes: string[] }): Promise<
    Result<{ user_op: Record<string, string>; user_op_hash: string; entry_point: string; chain_id: number }>
  >;
  revokeSubmit(body: unknown): Promise<Result<SubmitResult>>;

  // #429 (epic #425) — the delegate SPAWN + ARCHIVE ceremonies: ONE Touch ID
  // each, zero rendezvous. `spawnBuild` → the broker pre-checks the agent-slot
  // allowance (409 agent_slot_allowance_exhausted rides through verbatim),
  // derives the child omni + K10, and returns the userOpHash to K11-sign;
  // `spawnSubmit` relays it and the response's `ceremony` carries the
  // finalization (gate/sandbox/preset apply). `archiveBuild` records the
  // keep-vs-delete choice (#425 O4); the slot returns in-contract.
  presetCatalog(): Promise<Result<PresetCatalogResponse>>;
  spawnBuild(input: {
    label: string;
    presetId: string;
    /** Unset = fresh namespace named after the label; set + inherited = an
     *  archived delegate's KEPT namespace (#425 O2). */
    memoryNs?: string;
    memoryInherited?: boolean;
  }): Promise<Result<BuildSpawnUserOpResponse>>;
  spawnSubmit(body: unknown): Promise<Result<SubmitAcceptUserOpResponse>>;
  archiveBuild(input: {
    deviceKeyHash: string;
    resourcesKept: boolean;
    memoryNs?: string;
  }): Promise<Result<BuildArchiveUserOpResponse>>;
  archiveSubmit(body: unknown): Promise<Result<SubmitAcceptUserOpResponse>>;
  /** Kept namespaces of archived delegates, inheritable by AT MOST one live
   *  delegate (#429 bookkeeping — served from the #424 manifest). */
  inheritableNamespaces(): Promise<Result<InheritableNamespace[]>>;

  // #430 — the operator chat over the delegate's opchat feed (D8 operator-
  // owned; D13 operator-session-only). `chatPoll` doubles as the generic
  // feed-history read for ANY granted channel id (#431 Feeds tab).
  chatSend(channelId: string, text: string): Promise<Result<{ event_id: string }>>;
  chatPoll(
    channelId: string,
    after: string,
    waitSeconds: number,
  ): Promise<Result<{ events: ApiChatEvent[]; cursor: string }>>;

  // §credentials data class (#207). The SAME abstraction as memory: list the
  // master's stored credential services (categorized via the catalog) and vault
  // a new one. Real durable data — no in-memory stand-in.
  listCredentials(): Promise<Result<CredService[]>>;
  storeCredential(service: string, secret: string): Promise<Result<{ service: string; category: string }>>;

  // #404 — the master's channel REGISTRY (id-anchored channel definitions,
  // durable config-class doc). The devices pages SELECT from it — channels are
  // never created silently at pairing; `id` is the immutable on-chain anchor
  // (only `name`/`note` are editable; delete is refused while grants hold it).
  // Optional: only the daemon backend serves the registry.
  listChannels?(): Promise<Result<{ channels: ChannelDef[]; storage: string }>>;
  createChannel?(input: { id: string; name: string; note?: string }): Promise<Result<ChannelDef>>;
  updateChannel?(id: string, input: { name?: string; note?: string }): Promise<Result<ChannelDef>>;
  deleteChannel?(id: string): Promise<Result<void>>;
}

/** #404 — one channel definition (mirror of the generated ApiChannel). */
export interface ChannelDef {
  id: string;
  name: string;
  note?: string;
  createdAt: number;
}
