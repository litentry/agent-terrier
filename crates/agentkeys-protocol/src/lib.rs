//! The broker/worker wire protocol — the **single owner** of every request
//! and response shape the cap-mint + worker chain serializes (issue #203).
//!
//! Pure serde, **no transport** (no reqwest/tokio/aws), so it compiles to
//! `wasm32`: the native client `agentkeys-backend-client` re-exports it as
//! `::protocol`, and the browser host `agentkeys-web-core` (wasm) depends on
//! it directly. That split is the parity-ladder rung-3 move for the wire
//! shapes — the browser and the native client share ONE definition and cannot
//! drift (they used to: `ttl_seconds` was a required `u64` in backend-client
//! but `Option<u64>` in web-core's own copy, and web-core's copy was missing
//! the #76 K10 cap-PoP fields entirely). web-core must NOT depend on
//! `agentkeys-backend-client` instead: that crate pulls `aws-sdk-sts` +
//! `tokio` + native `reqwest` via the provisioner and breaks the wasm build
//! (the `wasm32` CI gate in `harness-ci.yml` enforces this).
//!
//! Before the one-owner discipline the same JSON was hand-typed in three
//! places (the MCP backend, the daemon `ui_bridge`, and bash `jq -n` bodies in
//! the harness), which is the structural cause of the drift bugs #200 fixed
//! (`evm_address` vs `{address,chain_id}`, bare-vs-`0x` omni, per-namespace
//! field shapes). Re-typing one of these in a second place is now either a
//! compile error (Rust callers share these types) or a fixture mismatch (the
//! harness gate diffs bash bodies against `agentkeys-backend-client`'s
//! `fixtures` module).
//!
//! Naming follows arch.md's canonical-names rule: the field names here MUST
//! match what `agentkeys_broker_server::handlers::cap` and the
//! `agentkeys_worker_*` handlers deserialize. We mirror by hand (not a shared
//! struct dep) because the broker/worker are heavy binaries — but the mirror
//! is now in ONE place, exercised end-to-end in the MCP server's
//! `tests/three_acts.rs` and pinned by the backend-client fixtures.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Op discriminator that maps onto the four broker cap-mint endpoints. The
/// route is the source of truth for the cap's `data_class` — the broker
/// statically derives the `DataClass` variant from which endpoint was hit, so
/// a `Memory` cap can never be minted from a `/v1/cap/cred-*` request (issue
/// #90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapMintOp {
    CredStore,
    CredFetch,
    MemoryPut,
    MemoryGet,
    /// #295 P1 — delegated READ of the master's CANONICAL memory (master-hub
    /// distribution). Mints `CapOp::CanonicalFetch`/`DataClass::Memory` at
    /// `/v1/cap/memory-canonical-get`; `op_str` is `"canonical_fetch"` so the
    /// K10 cap-PoP preimage matches the worker's `check_op`. Distinct from
    /// `MemoryGet` (own working memory) — see docs/plan/master-hub-topology.md §6a.
    MemoryCanonicalGet,
    /// #201 config data class — master-only taxonomy/config object. A third
    /// `DataClass::Config` with its own bucket + IAM role (arch.md §17.2); the
    /// cred + memory workers reject a Config cap via `verify::check_data_class`.
    ConfigStore,
    ConfigFetch,
}

impl CapMintOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cred_store" => Some(Self::CredStore),
            "cred_fetch" => Some(Self::CredFetch),
            "memory_put" => Some(Self::MemoryPut),
            "memory_get" => Some(Self::MemoryGet),
            "memory_canonical_get" => Some(Self::MemoryCanonicalGet),
            "config_store" => Some(Self::ConfigStore),
            "config_fetch" => Some(Self::ConfigFetch),
            _ => None,
        }
    }

    pub fn broker_path(self) -> &'static str {
        match self {
            Self::CredStore => "/v1/cap/cred-store",
            Self::CredFetch => "/v1/cap/cred-fetch",
            Self::MemoryPut => "/v1/cap/memory-put",
            Self::MemoryGet => "/v1/cap/memory-get",
            Self::MemoryCanonicalGet => "/v1/cap/memory-canonical-get",
            Self::ConfigStore => "/v1/cap/config-store",
            Self::ConfigFetch => "/v1/cap/config-fetch",
        }
    }

    pub fn data_class(self) -> &'static str {
        match self {
            Self::CredStore | Self::CredFetch => "credentials",
            Self::MemoryPut | Self::MemoryGet | Self::MemoryCanonicalGet => "memory",
            Self::ConfigStore | Self::ConfigFetch => "config",
        }
    }

    /// The signed-cap `CapOp` snake_case string this endpoint mints — the value
    /// that lands in `CapPayload.op` and must match the K10 cap-PoP preimage
    /// (issue #76). Store-class endpoints → `"store"`, fetch-class → `"fetch"`.
    /// Callers building the cap-PoP signature MUST use this so the worker's
    /// recomputed preimage agrees byte-for-byte.
    pub fn op_str(self) -> &'static str {
        match self {
            Self::CredStore | Self::MemoryPut | Self::ConfigStore => "store",
            Self::CredFetch | Self::MemoryGet | Self::ConfigFetch => "fetch",
            // #295 P1 — must match agentkeys_worker_creds::verify::CapOp::CanonicalFetch
            // (and the broker's) so the K10 cap-PoP preimage agrees byte-for-byte.
            Self::MemoryCanonicalGet => "canonical_fetch",
        }
    }
}

/// The cap-mint request as the *caller* constructs it (omni's, service,
/// device hash, TTL). [`BrokerCapRequest`] is the on-the-wire serialization;
/// they have the same fields today but stay distinct so a caller-side concept
/// (e.g. a future client-only field) can't silently leak onto the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapMintRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    pub ttl_seconds: u64,
}

/// Broker cap-mint request body — the exact JSON
/// `agentkeys_broker_server::handlers::cap` deserializes for all `/v1/cap/*`
/// endpoints, AND the on-the-wire shape the browser host
/// (`agentkeys-web-core`) serializes directly (it has no separate caller-side
/// type — it aliases this as `CapRequest`).
///
/// Carries the K10 cap-mint **proof-of-possession** (issue #76):
/// `client_sig` is an EIP-191 signature by the caller's K10 device key over
/// `device_crypto::cap_pop_payload(operator, actor, service, op, data_class,
/// client_nonce, client_ts)`. The broker validates it and the WORKER re-verifies
/// it independently — so a compromised broker (which lacks the K10 private key)
/// cannot mint a usable cap. Built by `BackendClient::cap_mint` (in
/// `agentkeys-backend-client`) from an injected `DeviceKey`, NOT hand-set by
/// callers.
///
/// `ttl_seconds` is `Option` + `skip_serializing_if` to mirror the broker's
/// `#[serde(default = "default_ttl_seconds")]`: `None` omits the field so the
/// broker applies its default (300s, clamped 60..1800); native callers coming
/// from [`CapMintRequest`] always send `Some(..)` (wire-identical to before).
/// This is the SINGLE on-wire definition, so the browser and the native client
/// can no longer drift on it — previously each crate had its own copy and they
/// diverged on this very field (the bug class #203 closed for the chain, now
/// extended to the browser).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerCapRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    // The K10 cap-PoP is OPTIONAL on the wire (issue #76 staged rollout): a caller
    // that holds the actor's K10 signs (the broker validates + the worker
    // re-verifies); a caller without one (e.g. a master before its K10 is
    // registered) omits these. Enforcement (reject-if-absent) is opt-in via the
    // worker's AGENTKEYS_WORKER_REQUIRE_CAP_POP — until then the PoP is
    // verified-when-present. `skip_serializing_if` keeps the no-PoP body
    // byte-identical to the pre-#76 shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<u64>,
}

/// Opaque cap-token blob — the broker signs it and the worker verifies the
/// signature; this side never inspects the inside, so a JSON `Value` is the
/// right type.
pub type CapToken = Value;

// ── memory worker (`/v1/memory/{put,get}`) ──────────────────────────────────

/// Memory-worker `/v1/memory/put` request body. Mirrors
/// `agentkeys_worker_memory::handlers::PutRequest`. `namespace` rides at the
/// body level for Phase 1 (lifting it into a SIGNED CapPayload field is an M4
/// follow-up per the wire-real-paths plan §8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
    pub namespace: String,
}

/// Memory-worker `/v1/memory/get` request body. Mirrors
/// `agentkeys_worker_memory::handlers::GetRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetBody {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryPutResp {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryGetResp {
    pub ok: bool,
    pub plaintext_b64: String,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── config worker (`/v1/config/{put,get}`) — #201 config data class ──────────

/// Config-worker `/v1/config/put` request body. Mirrors
/// `agentkeys_worker_config::handlers::PutRequest`. Config is a single
/// master-only object (the memory-types taxonomy), so — unlike `MemoryPutBody`
/// — there is NO `namespace` field; the object's identity is the signed cap
/// `service` (`memory-taxonomy`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPutBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

/// Config-worker `/v1/config/get` request body. Mirrors
/// `agentkeys_worker_config::handlers::GetRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGetBody {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigGetResp {
    pub ok: bool,
    pub plaintext_b64: String,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── cred worker (`/v1/cred/fetch`) — #216 agent-side vaulted-key fetch ────────

/// Cred-worker `/v1/cred/fetch` request body. Mirrors
/// `agentkeys_worker_creds::handlers::FetchRequest` — just the signed cap; the
/// credential `service` rides INSIDE the cap payload (it can't be spoofed at the
/// body level). The worker S3-GETs `bots/<actor>/credentials/<service>.enc`,
/// decrypts (K3 KEK), and returns the plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFetchBody {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredFetchResp {
    pub ok: bool,
    pub plaintext_b64: String,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

/// Cred-worker `/v1/cred/store` request body. Mirrors
/// `agentkeys_worker_creds::handlers::StoreRequest` — the signed cap (the
/// credential `service` rides INSIDE the cap payload) plus the base64 plaintext.
/// The worker encrypts (K3 KEK) + S3-PUTs `bots/<actor>/credentials/<service>.enc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStoreBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredStoreResp {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── audit worker (`/v1/audit/append/v2`) ────────────────────────────────────

/// Audit envelope version, pinned to `agentkeys_core::audit::ENVELOPE_VERSION`.
/// If that constant changes this must change too — covered by the MCP server's
/// integration smoke test.
pub const ENVELOPE_VERSION: u8 = 1;

/// Audit-worker `/v1/audit/append/v2` request body. Mirrors
/// `agentkeys_worker_audit::handlers::AppendV2Request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendV2 {
    pub version: u8,
    pub ts_unix: u64,
    pub actor_omni: String,
    pub operator_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
    pub intent_commitment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditAppendV2Resp {
    pub ok: bool,
    pub envelope_hash: String,
}

// ── high-level inputs / results (what the trait/callers pass + get back) ─────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutInput {
    pub cap: CapToken,
    pub namespace: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetInput {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutResult {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetResult {
    pub ok: bool,
    pub plaintext_b64: String,
    pub namespace: String,
}

/// #295 P1 §7a — request body for the broker `POST /v1/cap/canonical-sts`.
/// The delegate presents its broker-minted `CanonicalFetch` cap (and its OWN
/// session JWT as the Bearer) and receives read-only, exact-object STS creds.
/// The operator session bearer never enters the delegate runtime (the Codex
/// critical fix: the broker, not the client, holds operator authority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalStsBody {
    pub cap: CapToken,
}

/// Response from `/v1/cap/canonical-sts`: scoped (read-only, single-object) STS
/// creds the delegate relays as `X-Aws-*` to `/v1/memory/canonical-get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalStsResult {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFetchInput {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFetchResult {
    pub ok: bool,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStoreInput {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStoreResult {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendInput {
    pub operator_omni: String,
    pub actor_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendResult {
    pub ok: bool,
    pub envelope_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResult {
    pub ok: bool,
    pub revocation: String,
    /// Present when `revocation != "online_immediate"` — tells the caller what
    /// kind of revocation actually happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ── #225 / #164 E7 — on-chain K11-gated agent accept (sponsored executeBatch) ─
//
// The accept becomes ONE P256Account.executeBatch UserOp that lands the device
// binding (P.2) + the scope grant (P.3) atomically, gated by one master K11
// signature. Two broker endpoints, J1_master-gated: `build` assembles + co-signs
// the sponsored op and returns the userOpHash; the daemon K11-signs it; `submit`
// relays the signed op to `EntryPoint.handleOps`. The broker mirrors these shapes
// server-side (it doesn't depend on this crate); the frozen key-set tests in
// `crate::fixtures` pin them so the two sides can't drift.

/// Daemon → broker `POST /v1/accept/build`. The granted scope (`services` +
/// caps) is what the master approved in the pairing UI; the register fields bind
/// the agent device. `operator_omni`/`actor_omni` are `0x`-omni
/// ([`normalize_omni_0x`]); the `u128` caps ride as decimal strings (wire-safe
/// past 2^53; `"0"` = unset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAcceptUserOpRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub device_key_hash: String,
    pub agent_pop_sig: String,
    pub link_code_redemption: String,
    pub services: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
}

/// ERC-4337 v0.7 `PackedUserOperation`, hex-encoded for the wire. Mirrors
/// `agentkeys_broker_server::sponsor::PackedUserOp`; the daemon fills `signature`
/// with the master's K11 assertion over `user_op_hash`, then returns the whole op
/// to `/v1/accept/submit`.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct WireUserOp {
    pub sender: String,
    pub nonce: String,
    pub init_code: String,
    pub call_data: String,
    pub account_gas_limits: String,
    pub pre_verification_gas: String,
    pub gas_fees: String,
    pub paymaster_and_data: String,
    pub signature: String,
}

/// Broker → daemon response to `/v1/accept/build`. The master signs
/// `user_op_hash` (the `EntryPoint.getUserOpHash` of `user_op`) with K11.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct BuildAcceptUserOpResponse {
    pub user_op: WireUserOp,
    pub user_op_hash: String,
    pub entry_point: String,
    #[ts(type = "number")]
    pub chain_id: u64,
}

/// The raw browser WebAuthn assertion (base64url) over the accept `user_op_hash`,
/// as `apps/parent-control/lib/webauthn.ts::getAssertionOverHash` emits it. The
/// broker encodes it into the P256Account UserOp signature; it derives the
/// master's `credIdHash` from `operator_omni`, so the raw `credential_id` here is
/// for cross-checks/audit, not the signer key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptAssertion {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub credential_id: String,
}

/// Daemon → broker `POST /v1/accept/submit` — the op from `build` + the master's
/// browser WebAuthn `assertion` over `user_op_hash`. The broker encodes the
/// assertion into `user_op.signature` (binding the `credIdHash` it derives from
/// the verified J1 session omni, not a body field), then relays to
/// `EntryPoint.handleOps` (Stage B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAcceptUserOpRequest {
    pub user_op: WireUserOp,
    pub assertion: AcceptAssertion,
}

/// Broker → daemon response to `/v1/accept/submit` (and its `/v1/scope/submit`
/// and `/v1/revoke/submit` siblings — the daemon proxies relay it verbatim to
/// the web frontend, which consumes the generated TS type). Two variants share the
/// shape: confirmed (`tx_hash`/`block_number` set, #97 `audit_envelope_hashes`
/// carrying the control-plane AuditEnvelope receipts) and receipt-timeout
/// (`pending: true`, empty `tx_hash`/`block_number`, no envelopes — the op may
/// still mine; the UI confirms on chain by `user_op_hash`).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct SubmitAcceptUserOpResponse {
    pub ok: bool,
    pub tx_hash: String,
    pub block_number: String,
    /// The ERC-4337 userOpHash the bundler accepted (#97).
    pub user_op_hash: String,
    /// #97: control-plane audit receipts decoded from the confirmed
    /// executeBatch. Absent on the pending variant / pre-#97 brokers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub audit_envelope_hashes: Option<Vec<String>>,
    /// #230: broadcast but receipt-poll timed out — NOT an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub pending: Option<bool>,
}

// ── #248 — on-chain K11-gated scope re-grant for an ALREADY-bound agent ──────
//
// The permissions panel's setScope becomes ONE `P256Account.executeBatch([setScope])`
// UserOp, gated by the master's K11 Touch ID — the scope-only sibling of the accept
// batch (no register; the device binding already exists). Broker endpoints
// `/v1/scope/build` + `/v1/scope/submit`, J1_master-gated; `build` returns the
// `userOpHash` the master K11-signs, `submit` reuses the accept relay shape
// ([`SubmitAcceptUserOpRequest`] → bundler → `EntryPoint.handleOps`). The response
// to `build` is the same [`BuildAcceptUserOpResponse`].

/// Daemon → broker `POST /v1/scope/build`. `services` is the FULL replacement
/// list (`AgentKeysScope.setScope` is set-replace, not incremental); an empty
/// list revokes every grant. `preserve_service_ids` are raw on-chain service
/// ids (`0x`-hex keccak-32) echoed from the scope mirror — grants the panel
/// can't name (e.g. `cred:<service>`) that must SURVIVE a memory-toggle commit;
/// the broker unions them into the new grant. Field conventions match
/// [`BuildAcceptUserOpRequest`] (`0x`-omnis, decimal-string `u128` caps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildScopeUserOpRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub services: Vec<String>,
    #[serde(default)]
    pub preserve_service_ids: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
}

/// Daemon → broker `POST /v1/revoke/build` — the Touch-ID **unpair** and the
/// #260 master-reset **fleet teardown** (same endpoint, N hashes).
/// `SidecarRegistry.revokeAgentDevice` requires `msg.sender ==
/// operatorMasterWallet`, so for an account-master operator the revoke is a
/// master-account UserOp (`executeBatch([revokeAgentDevice × N])`); no EOA —
/// incl. the deployer script — can sign it. One hash = the single unpair; many
/// = every paired agent revoked in ONE UserOp (one Touch ID) BEFORE the master
/// unbind strands the bindings. The broker skips already-revoked/unregistered
/// hashes (the contract would revert the whole batch on them) and rejects
/// cross-operator ones. Response reuses [`BuildAcceptUserOpResponse`]; submit
/// reuses [`SubmitAcceptUserOpRequest`] at `/v1/revoke/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRevokeUserOpRequest {
    pub operator_omni: String,
    /// The agents' on-chain `SidecarRegistry` device key hashes (`0x` + 64 hex
    /// each).
    pub device_key_hashes: Vec<String>,
}

/// Daemon → broker `POST /v1/register/build` — the #278 D6 ONE-op master
/// register. Collapses the legacy 3-tx ceremony (deployer `createAccount` +
/// `depositTo` + self-funded register UserOp) into a single paymaster-sponsored
/// UserOp = `initCode` (counterfactual `P256AccountFactory.createAccount`) +
/// `executeBatch([registerFirstMasterDevice])`, gated by ONE master K11 Touch ID.
///
/// The request carries ONLY what the broker cannot derive: the master P-256
/// passkey coordinates (`owner_pubkey_x`/`owner_pubkey_y`, `0x`+64hex), the
/// WebAuthn `rpid_hash` (deployment/domain-specific, `0x`+64hex), and the device
/// `roles` bitmap. The broker derives everything omni-keyed from the verified J1
/// session omni — `cred_id_hash` ([`agentkeys_core::erc4337::master_cred_id_hash`]),
/// CREATE2 `salt` ([`master_account_salt`]), `device_key_hash`
/// ([`master_device_key_hash`]), `actor_omni == operator_omni` (a first master IS
/// the operator) — so a client cannot drift them. The predicted `sender` comes
/// from `factory.getAddress(...)` and rides back in
/// [`BuildAcceptUserOpResponse::user_op`]`.sender`; submit reuses
/// [`SubmitAcceptUserOpRequest`] at `/v1/register/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRegisterUserOpRequest {
    pub operator_omni: String,
    pub owner_pubkey_x: String,
    pub owner_pubkey_y: String,
    pub rpid_hash: String,
    pub roles: u8,
}

// ── the daemon's web-API plant contract (#275 tier-3) ───────────────────────

/// The daemon's **web-API plant contract** — the frontend↔daemon surface, as
/// opposed to the broker/worker chain above. It lives in this wasm-safe crate
/// so the browser host (`agentkeys-web-core`) compiles the SAME types the
/// daemon's `ui_bridge` serves: `daemon.ts` gets the route + body from a
/// wasm-exported builder instead of hand-building them, which dissolves the
/// old runtime parity check into the type system (#275, parity-ladder rung 3 —
/// "one code path; violating parity is a compile error"). The contract is
/// still pinned to `harness/fixtures/web-api/master_memory_plant.json` by a
/// `ui_bridge` unit test, and the REMAINING non-Rust consumer
/// (`harness/web-parity-demo.sh`) is gated against that fixture by
/// `scripts/check-web-api-drift.sh`.
pub mod web_api {
    use serde::{Deserialize, Serialize};

    /// Canonical master-memory plant route — the single source of truth for
    /// the path the React frontend (via the `agentkeys-web-core` wasm export)
    /// and the harness web-parity demo both POST to.
    pub const MASTER_MEMORY_PLANT_ROUTE: &str = "/v1/master/memory/plant";

    /// A master-actor memory entry. `content_hash` is the dedup key —
    /// keccak-free sha256 over (ns || key || body) so a re-plant of the same
    /// content is detected and skipped (the "prevent duplicate plant" gate).
    #[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
    #[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
    pub struct ApiMemoryEntry {
        pub ns: String,
        pub key: String,
        pub title: String,
        #[ts(type = "number")]
        pub bytes: u64,
        pub version: String,
        pub updated: String,
        pub preview: String,
        pub body: String,
        #[serde(default)]
        pub content_hash: String,
    }

    /// `POST` body for [`MASTER_MEMORY_PLANT_ROUTE`].
    #[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
    #[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
    pub struct MasterMemoryPlantRequest {
        pub entries: Vec<ApiMemoryEntry>,
    }

    /// Plant outcome. `taxonomy_status` surfaces the durable category-index
    /// write so a configured-Config store failure is NOT hidden behind an
    /// otherwise-successful memory plant: `"ok"` (written), `"unconfigured"`
    /// (Config not set up, cache-only), `"failed: <reason>"` (memory IS
    /// durable but the category index is stale → retry), or
    /// `"skipped: <reason>"` (config-context unavailable).
    #[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
    #[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
    pub struct MasterMemoryPlantResponse {
        #[ts(type = "number")]
        pub planted: usize,
        #[ts(type = "number")]
        pub skipped: usize,
        #[ts(type = "number")]
        pub total: usize,
        pub taxonomy_status: String,
    }
}

// ── shared protocol helpers (the omni-normalization bug site, centralized) ───

/// Build the signed cap **service** string for a memory namespace —
/// `memory:<ns>`. The broker binds this into the cap's signed `service` field
/// (issue #150), so every caller MUST spell it identically; hand-formatting
/// `format!("memory:{ns}")` in a second place is exactly the per-namespace
/// drift this crate exists to kill.
pub fn service_memory(namespace: &str) -> String {
    format!("memory:{namespace}")
}

/// Normalize an omni to the broker's expected `0x`-prefixed lower-hex shape.
///
/// The broker cap-mint input-validates that `operator_omni`/`actor_omni` start
/// with `0x`, but several upstream sources (the daemon onboarding session, JWT
/// claims) store the omni **bare**. This was the `0x`/bare drift bug #200
/// fixed by normalizing inline in the daemon — now there is ONE normalizer so
/// the next caller can't reintroduce it. Already-`0x` input is returned
/// unchanged (case preserved; the broker lower-cases on its side).
pub fn normalize_omni_0x(omni: &str) -> String {
    if omni.starts_with("0x") || omni.starts_with("0X") {
        omni.to_string()
    } else {
        format!("0x{omni}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_mint_op_roundtrips_paths_and_classes() {
        for (s, path, class) in [
            ("cred_store", "/v1/cap/cred-store", "credentials"),
            ("cred_fetch", "/v1/cap/cred-fetch", "credentials"),
            ("memory_put", "/v1/cap/memory-put", "memory"),
            ("memory_get", "/v1/cap/memory-get", "memory"),
            ("config_store", "/v1/cap/config-store", "config"),
            ("config_fetch", "/v1/cap/config-fetch", "config"),
        ] {
            let op = CapMintOp::parse(s).unwrap();
            assert_eq!(op.broker_path(), path);
            assert_eq!(op.data_class(), class);
        }
        assert!(CapMintOp::parse("bogus").is_none());
    }

    #[test]
    fn service_memory_is_namespace_prefixed() {
        assert_eq!(service_memory("travel"), "memory:travel");
        assert_eq!(service_memory("webparity"), "memory:webparity");
    }

    #[test]
    fn normalize_omni_adds_prefix_once() {
        assert_eq!(normalize_omni_0x("abcd"), "0xabcd");
        assert_eq!(normalize_omni_0x("0xabcd"), "0xabcd");
        assert_eq!(normalize_omni_0x("0Xabcd"), "0Xabcd");
    }

    #[test]
    fn broker_cap_request_ttl_is_optional_on_the_wire() {
        // Mirrors the broker's `#[serde(default)]`: `None` omits ttl_seconds (the
        // broker then applies its default), `Some` emits a bare number. This is
        // why the single on-wire type uses `Option` + skip rather than a required
        // `u64` — the divergence web-core and backend-client used to carry.
        let base = BrokerCapRequest {
            operator_omni: "0xop".into(),
            actor_omni: "0xactor".into(),
            service: "memory:travel".into(),
            device_key_hash: "0xdkh".into(),
            ttl_seconds: None,
            client_sig: None,
            client_nonce: None,
            client_ts: None,
        };
        let omitted = serde_json::to_value(&base).unwrap();
        assert!(
            omitted.get("ttl_seconds").is_none(),
            "None must omit ttl_seconds so the broker applies its default"
        );
        let present = serde_json::to_value(BrokerCapRequest {
            ttl_seconds: Some(900),
            ..base
        })
        .unwrap();
        assert_eq!(present["ttl_seconds"], 900);
    }
}
