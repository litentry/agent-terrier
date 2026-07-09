//! Cap-mint endpoints — `/v1/cap/cred-store` + `/v1/cap/cred-fetch`.
//!
//! Per arch.md §12.4 + §15.1: the broker is the cap-mint authority for
//! agent credential operations. A cap-token is a short-lived blob the
//! credentials-service worker (arch.md §15.1) re-verifies before any
//! AES-256-GCM encrypt/decrypt + S3 PUT/GET.
//!
//! ## Auth chain
//! 1. Session JWT (Bearer in `Authorization`) — broker's existing OIDC.
//!    Verifies the caller holds the operator's session, and the JWT's
//!    `agentkeys.omni_account` MUST match the requested `operator_omni`
//!    in the body.
//! 2. On-chain `SidecarRegistry.getDevice(deviceKeyHash)` — decoded fully.
//!    The device entry's `operatorOmni`, `actorOmni`, and `roles` MUST
//!    match the request. `revoked` MUST be false. `registeredAt` > 0.
//!    `roles & ROLE_CAP_MINT (=1)` MUST be non-zero.
//! 3. On-chain `AgentKeysScope.isServiceInScope(operator, actor,
//!    keccak(service))` MUST be true.
//! 4. On-chain `K3EpochCounter.currentEpoch` is embedded in the cap so
//!    the worker can re-verify against the latest epoch and reject
//!    stale-epoch caps after rotation.
//! 5. Cap payload includes an explicit `op` discriminator so the worker
//!    can refuse a fetch-cap submitted to /store etc.
//! 6. **K10 proof-of-possession (issue #76 — the broker-SPOF fix).** When a
//!    cap-mint request carries a `client_sig` (an EIP-191 signature by the
//!    caller's K10 device key over `device_crypto::cap_pop_payload(operator,
//!    actor, service, op, data_class, client_nonce, client_ts)`), the broker
//!    validates that it recovers to an address whose `keccak == device_key_hash`
//!    (which step 2 already bound on-chain to this operator/actor), then carries
//!    the PoP in the returned `CapToken` so the WORKER re-verifies it
//!    independently (`verify::check_client_pop`). The K10 private key never
//!    reaches the broker, so a compromised broker cannot forge it. **OPTIONAL +
//!    staged rollout:** the PoP is verified WHEN PRESENT here; a MISSING PoP is
//!    rejected only at the worker under `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1`
//!    (default off until every actor's K10 — incl. the master's, via
//!    `heima-register-master-k10.sh` — is registered). Flipping that flag is the
//!    point at which the broker SPOF is fully closed; until then the agent path
//!    (which always signs) is already verified. Supersedes the former stage-1
//!    simplification (§22b.4, "session JWT only, no K10 signature").

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use agentkeys_protocol::DelegationPath;

use crate::jwt::verify::verify_session_jwt;
use crate::state::SharedState;

/// Cap operation discriminator (matches CredentialAudit.OP_* on chain
/// and `agentkeys-worker-creds`'s mirror enum byte-for-byte).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapOp {
    Store,
    Fetch,
    /// Delegated READ of the master's CANONICAL memory (master-hub #295 P1
    /// distribution). Mirror of `agentkeys_worker_creds::verify::CapOp`. A
    /// distinct SIGNED op (not just a route) because an own-read and a
    /// canonical-read carry identical omnis (operator = master, actor =
    /// delegate) — only the resolved prefix differs. `operator != actor` makes
    /// `mint_cap`'s scope check consult the on-chain `memory:<ns>` grant (the
    /// master-self skip is bypassed). `as_u8` = 4 audits via the tier-1 worker
    /// (reuses `AuditOpKind::MemoryGet`), NOT the on-chain `CredentialAudit.OP_*`
    /// path, so no chain-enum change is needed.
    CanonicalFetch,
    /// Delegated APPEND to the master's absorption INBOX (master-hub #339 P2
    /// "push"). Mirror of `agentkeys_worker_creds::verify::CapOp::Append`. A
    /// distinct SIGNED op so an own-memory `Store` cap can never be redeemed as
    /// an inbox append. Like `CanonicalFetch` the DELEGATE mints it
    /// (`session == actor`); `operator != actor` makes `mint_cap`'s scope check
    /// consult the on-chain `inbox:<ns>` grant (distinct from the `memory:<ns>`
    /// read grant). `as_u8` = 5 audits via the tier-1 worker
    /// (`AuditOpKind::MemoryInboxAppend`), NOT the on-chain `CredentialAudit.OP_*`
    /// path, so no chain-enum change is needed.
    Append,
    Teardown,
    /// Compute-gate op for the classifier-service worker (#178 §15.6, #207
    /// items 2-3): a COMPILE or TAG call, NOT an S3 touch. `/v1/cap/classify`
    /// mints this; storage workers reject it via `check_op`. `as_u8` = 3 is a
    /// fresh code — the classifier audits via the tier-1 audit worker, NOT the
    /// on-chain `CredentialAudit.OP_*` path, so no chain-enum change is needed.
    Classify,
    /// #406 channels — PUBLISH into a channel feed. Distinct SIGNED op from
    /// `ChannelSubscribe` (direction isolation, D2). `as_u8` = 6 audits via the
    /// tier-1 audit worker (`AuditOpKind::ChannelPublish`), NOT the on-chain path.
    ChannelPublish,
    /// #406 channels — SUBSCRIBE (consume) from a channel feed. `as_u8` = 7.
    ChannelSubscribe,
}

impl CapOp {
    pub fn as_u8(self) -> u8 {
        match self {
            CapOp::Store => 0,
            CapOp::Fetch => 1,
            CapOp::Teardown => 2,
            CapOp::Classify => 3,
            CapOp::CanonicalFetch => 4,
            CapOp::Append => 5,
            CapOp::ChannelPublish => 6,
            CapOp::ChannelSubscribe => 7,
        }
    }

    /// snake_case string used in the K10 cap-PoP preimage (issue #76). MUST
    /// match `agentkeys_backend_client::CapMintOp::op_str` (client) and the
    /// worker's `CapOp::as_str`, or the recomputed preimage won't agree.
    pub fn as_str(self) -> &'static str {
        match self {
            CapOp::Store => "store",
            CapOp::Fetch => "fetch",
            CapOp::CanonicalFetch => "canonical_fetch",
            CapOp::Append => "append",
            CapOp::Teardown => "teardown",
            CapOp::Classify => "classify",
            CapOp::ChannelPublish => "channel_publish",
            CapOp::ChannelSubscribe => "channel_subscribe",
        }
    }
}

/// Data class the cap-token is bound to. Mirror of
/// `agentkeys_worker_creds::verify::DataClass`. The broker mints with
/// the right variant for each endpoint (`/v1/cap/cred-*` → Credentials,
/// `/v1/cap/memory-*` → Memory) and signs it into the payload; workers
/// reject caps whose data_class doesn't match their bucket. Issue #90
/// followup — codified in AGENTS.md.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Credentials,
    Memory,
    /// Policy / memory-types taxonomy (#178 §7). Master-only; its own bucket +
    /// role per §17.2. `/v1/cap/config-*` mints this; cred + memory workers
    /// reject a Config cap via `verify::check_data_class`.
    Config,
    /// #406 channels data class (`docs/spec/agent-channel-decoupling.md` D7).
    /// Its own `$CHANNEL_BUCKET` + IAM role (arch.md §17.2); the cred/memory/
    /// config workers reject a Channel cap via `verify::check_data_class`, and
    /// the channel worker rejects every non-Channel cap.
    Channel,
}

impl DataClass {
    /// snake_case string used in the K10 cap-PoP preimage (issue #76). MUST
    /// match `agentkeys_backend_client::CapMintOp::data_class` (client) and the
    /// worker's `DataClass::as_str`.
    pub fn as_str(self) -> &'static str {
        match self {
            DataClass::Credentials => "credentials",
            DataClass::Memory => "memory",
            DataClass::Config => "config",
            DataClass::Channel => "channel",
        }
    }
}

/// Cap payload — the signed-over portion of a cap-token. The worker
/// verifies `Sha256(json(payload))` against `broker_sig` using the
/// broker's session-keypair public key before honoring the cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapPayload {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub op: CapOp,
    /// Data class binding (issue #90 followup). REQUIRED; workers reject
    /// caps whose data_class doesn't match their bucket.
    pub data_class: DataClass,
    pub device_key_hash: String,
    pub k3_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapToken {
    pub payload: CapPayload,
    pub broker_sig: String,
    /// K10 cap-mint proof-of-possession (issue #76), carried alongside
    /// `broker_sig` (NOT inside `payload`, so `broker_sig` is unchanged). The
    /// worker recomputes `cap_pop_payload` from `payload` + `client_nonce`/
    /// `client_ts` and asserts `keccak(ecrecover(client_sig)) ==
    /// payload.device_key_hash`. `client_sig` integrity-protects the nonce/ts
    /// (altering them breaks the recovered address), so they need not be in the
    /// broker-signed payload. OPTIONAL (issue #76 staged rollout): omitted on the
    /// wire when the cap carries no PoP, so a no-PoP cap is byte-identical to the
    /// pre-#76 shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<u64>,
    /// Device→sandbox delegation (issue #369) — echoed VERBATIM from the request
    /// when the cap-PoP was signed by a sandbox's ephemeral key. The broker does
    /// NOT verify it (it stays untrusted — the whole #76/#369 posture); the worker
    /// re-verifies it independently. Omitted on the wire when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_path: Option<DelegationPath>,
}

#[derive(Debug, Deserialize)]
pub struct CapRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// K10 cap-mint proof-of-possession (issue #76) — OPTIONAL. When present, an
    /// EIP-191 sig by the caller's K10 over `device_crypto::cap_pop_payload(...)`,
    /// validated here + re-verified by the worker (a compromised broker can't
    /// forge it). When absent, the cap carries no PoP; the worker accepts it
    /// unless `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1`.
    #[serde(default)]
    pub client_sig: Option<String>,
    #[serde(default)]
    pub client_nonce: Option<String>,
    #[serde(default)]
    pub client_ts: Option<u64>,
    /// Device→sandbox delegation (issue #369) — present when `client_sig` is a
    /// delegated sandbox-key signature; echoed into the cap-token for the worker.
    #[serde(default)]
    pub delegation_path: Option<DelegationPath>,
}

fn default_ttl_seconds() -> u64 {
    300 // 5 min default; workers reject anything past expires_at.
}

#[derive(Debug, Serialize)]
pub struct CapErrorBody {
    pub error: String,
    pub reason: &'static str,
}

#[derive(Debug)]
pub enum CapError {
    InvalidInput(String),
    Unauthorized(String),
    Forbidden(String, &'static str),
    DeviceNotActive,
    DeviceBindingMismatch(&'static str),
    DeviceRoleMissing,
    DeviceRevoked,
    ServiceNotInScope,
    OperatorMismatch,
    /// K10 cap-mint proof-of-possession failed (issue #76): `client_sig` did not
    /// recover to an address whose `keccak == device_key_hash`, or was stale.
    CapPopInvalid(String),
    ChainRpc(String),
    Sign(String),
}

impl IntoResponse for CapError {
    fn into_response(self) -> axum::response::Response {
        let (status, reason): (StatusCode, &'static str) = match &self {
            CapError::InvalidInput(_) => (StatusCode::BAD_REQUEST, "invalid_input"),
            CapError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            CapError::Forbidden(_, r) => (StatusCode::FORBIDDEN, r),
            CapError::DeviceNotActive => (StatusCode::FORBIDDEN, "device_not_active"),
            CapError::DeviceBindingMismatch(_) => {
                (StatusCode::FORBIDDEN, "device_binding_mismatch")
            }
            CapError::DeviceRoleMissing => (StatusCode::FORBIDDEN, "device_role_missing"),
            CapError::DeviceRevoked => (StatusCode::FORBIDDEN, "device_revoked"),
            CapError::ServiceNotInScope => (StatusCode::FORBIDDEN, "service_not_in_scope"),
            CapError::OperatorMismatch => (StatusCode::FORBIDDEN, "operator_mismatch"),
            CapError::CapPopInvalid(_) => (StatusCode::FORBIDDEN, "cap_pop_invalid"),
            CapError::ChainRpc(_) => (StatusCode::BAD_GATEWAY, "chain_rpc_error"),
            CapError::Sign(_) => (StatusCode::INTERNAL_SERVER_ERROR, "sign_error"),
        };
        let msg = match self {
            CapError::InvalidInput(m) => m,
            CapError::Unauthorized(m) => m,
            CapError::Forbidden(m, _) => m,
            CapError::DeviceNotActive => "device is not active on chain".to_string(),
            CapError::DeviceBindingMismatch(field) => {
                format!("on-chain device binding mismatch on {field}")
            }
            CapError::DeviceRoleMissing => "device lacks CAP_MINT role".to_string(),
            CapError::DeviceRevoked => "device is revoked on chain".to_string(),
            CapError::ServiceNotInScope => "requested service is not in agent's scope".to_string(),
            CapError::OperatorMismatch => "session JWT operator differs from request".to_string(),
            CapError::CapPopInvalid(m) => m,
            CapError::ChainRpc(m) => m,
            CapError::Sign(m) => m,
        };
        (status, Json(CapErrorBody { error: msg, reason })).into_response()
    }
}

// ─── handlers ──────────────────────────────────────────────────────────

pub async fn cap_cred_store(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Store, DataClass::Credentials)
        .await
        .map(Json)
}

pub async fn cap_cred_fetch(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Fetch, DataClass::Credentials)
        .await
        .map(Json)
}

// Memory cap-mint endpoints (issue #90 followup): per-data-class
// explicit binding. The minted cap carries data_class=Memory; the cred
// worker would reject it via verify::check_data_class.
pub async fn cap_memory_put(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Store, DataClass::Memory)
        .await
        .map(Json)
}

pub async fn cap_memory_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Fetch, DataClass::Memory)
        .await
        .map(Json)
}

/// Delegated READ of the master's CANONICAL memory (master-hub #295 P1).
/// Mints a `CanonicalFetch`/`Memory` cap. When the requester is a delegate
/// (`operator != actor`), `mint_cap`'s scope check consults the on-chain
/// `memory:<ns>` grant the master set for that delegate (the master-self skip
/// is bypassed). The memory worker keys the read on the OPERATOR prefix for
/// this op; the caller relays operator-authority STS (the cred-fetch pattern).
pub async fn cap_memory_canonical_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(
        state,
        headers,
        req,
        CapOp::CanonicalFetch,
        DataClass::Memory,
    )
    .await
    .map(Json)
}

/// Delegated APPEND to the master's absorption INBOX (master-hub #339 P2 push).
/// Mints an `Append`/`Memory` cap. The DELEGATE mints it (`session == actor`);
/// because `operator != actor`, `mint_cap`'s scope check consults the on-chain
/// `inbox:<ns>` grant (a DISTINCT service-id from the `memory:<ns>` read grant —
/// granting read never grants push). The delegate then redeems the cap at the
/// memory worker's `/v1/memory/inbox-append`, which performs the write
/// server-side under a broker-minted, prefix-scoped operator STS (`/v1/cap/inbox-sts`);
/// the delegate holds no AWS creds.
pub async fn cap_memory_append(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Append, DataClass::Memory)
        .await
        .map(Json)
}

// Config cap-mint endpoints (#178 P1 / config-data-class-memory-list plan): the
// policy / memory-types taxonomy data class. The minted cap carries
// data_class=Config; the cred + memory workers reject it via
// verify::check_data_class. Master-only (the governed agent has no config cap).
pub async fn cap_config_store(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Store, DataClass::Config)
        .await
        .map(Json)
}

pub async fn cap_config_fetch(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Fetch, DataClass::Config)
        .await
        .map(Json)
}

// Channel cap-mint endpoints (#406 channels phase 1). data_class=Channel; the
// route fixes the DIRECTION via the signed op — `channel-pub` mints
// ChannelPublish, `channel-sub` mints ChannelSubscribe. The channel worker
// rejects a cross-direction cap (a publish cap at /poll) via check_op, and any
// non-Channel worker rejects a Channel cap via check_data_class. The scope
// check consults the on-chain `channel-pub:<id>` / `channel-sub:<id>` grant
// (distinct service-ids) when operator != actor (a device/delegate publishing
// or subscribing); master-self channels skip the scope check like every class.
pub async fn cap_channel_pub(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(
        state,
        headers,
        req,
        CapOp::ChannelPublish,
        DataClass::Channel,
    )
    .await
    .map(Json)
}

pub async fn cap_channel_sub(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(
        state,
        headers,
        req,
        CapOp::ChannelSubscribe,
        DataClass::Channel,
    )
    .await
    .map(Json)
}

/// Classifier-service cap-mint (#178 §15.6, #207 items 2-3). Unlike the storage
/// endpoints — where the route fixes the data class — a classify cap spans data
/// classes (you classify memory content, a credential service, a config entity),
/// so `data_class` is an explicit SIGNED field of the request. The minted cap
/// carries `{ op: Classify, data_class }`; the classifier worker rejects a cap
/// whose `data_class` doesn't match the surface being classified (a Memory-classify
/// cap can't TAG a credential), and the storage workers reject `op: Classify`.
#[derive(Debug, Deserialize)]
pub struct CapClassifyRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// The data class this classify cap authorizes (`memory` / `credentials` /
    /// `config`). Signed into the payload; the worker binds on it.
    pub data_class: DataClass,
    /// K10 cap-mint proof-of-possession (issue #76) — same as [`CapRequest`]; OPTIONAL.
    #[serde(default)]
    pub client_sig: Option<String>,
    #[serde(default)]
    pub client_nonce: Option<String>,
    #[serde(default)]
    pub client_ts: Option<u64>,
    /// Device→sandbox delegation (issue #369) — present when `client_sig` is a
    /// delegated sandbox-key signature. Passed through to the minted cap-token for
    /// the worker to re-verify; the broker never inspects it.
    #[serde(default)]
    pub delegation_path: Option<DelegationPath>,
}

pub async fn cap_classify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapClassifyRequest>,
) -> Result<Json<CapToken>, CapError> {
    let data_class = req.data_class;
    let cap_req = CapRequest {
        operator_omni: req.operator_omni,
        actor_omni: req.actor_omni,
        service: req.service,
        device_key_hash: req.device_key_hash,
        ttl_seconds: req.ttl_seconds,
        client_sig: req.client_sig,
        client_nonce: req.client_nonce,
        client_ts: req.client_ts,
        delegation_path: req.delegation_path,
    };
    mint_cap(state, headers, cap_req, CapOp::Classify, data_class)
        .await
        .map(Json)
}

// ─── cap construction ──────────────────────────────────────────────────

async fn mint_cap(
    state: SharedState,
    headers: HeaderMap,
    req: CapRequest,
    op: CapOp,
    data_class: DataClass,
) -> Result<CapToken, CapError> {
    validate_hex32(&req.operator_omni, "operator_omni")?;
    validate_hex32(&req.actor_omni, "actor_omni")?;
    validate_hex32(&req.device_key_hash, "device_key_hash")?;
    if req.service.is_empty() || req.service.len() > 64 {
        return Err(CapError::InvalidInput(
            "service must be 1..=64 chars".into(),
        ));
    }
    // #295 §7a finding 3: a service is interpolated into an S3 key AND (for the
    // canonical-read STS) an IAM Resource ARN. Reject characters that would
    // become an IAM wildcard or an S3 path traversal — `memory:*` must never be
    // a wildcard, `../` must never escape the prefix. (No legit service uses
    // these: memory = `memory:<ns>`, creds = `openrouter`, IoT = `home:r:dev`.)
    if req.service.contains(['*', '?', '/', '\\']) || req.service.contains("..") {
        return Err(CapError::InvalidInput(
            "service must not contain wildcard or path characters (* ? / \\ ..)".into(),
        ));
    }
    let ttl = req.ttl_seconds.clamp(60, 1800);

    // 0. Session JWT auth — caller must hold the operator session.
    let bearer = extract_bearer(&headers)?;
    let claims = verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, &bearer)
        .map_err(|e| CapError::Unauthorized(format!("session jwt verify: {e}")))?;

    let session_omni = normalize_hex32(&claims.agentkeys.omni_account)
        .map_err(|e| CapError::InvalidInput(format!("session omni invalid: {e}")))?;
    let req_omni = normalize_hex32(&req.operator_omni)
        .map_err(|e| CapError::InvalidInput(format!("operator_omni invalid: {e}")))?;
    let req_actor = normalize_hex32(&req.actor_omni)
        .map_err(|e| CapError::InvalidInput(format!("actor_omni invalid: {e}")))?;
    // Who must hold the session? The two DELEGATED cross-actor ops — `CanonicalFetch`
    // (#295 P1 §7a, the canonical READ) and `Append` (#339 P2, the inbox PUSH) — are
    // minted by the DELEGATE with its OWN session (`session == actor`); the master's
    // on-chain grant (`memory:<ns>` / `inbox:<ns>` respectively, checked below because
    // operator != actor bypasses the master-self skip) is the authorization. A
    // sandboxed delegate must never hold the operator session bearer. Every other op
    // is operator-session-minted.
    let required_session_omni = if matches!(op, CapOp::CanonicalFetch | CapOp::Append) {
        &req_actor
    } else {
        &req_omni
    };
    if session_omni != *required_session_omni {
        return Err(CapError::OperatorMismatch);
    }

    // Single-vault master-sovereign credentials (docs/plan/single-vault-credentials.md):
    // cred-STORE mints are MASTER-SELF ONLY. Scope is service-granular, so a
    // cred:<svc> FETCH grant would otherwise also authorize delegated STORE
    // mints — the #228 shadowing hole. Hard route-level gate (config's soft
    // "master-only because nobody grants it" posture is NOT enough here).
    enforce_cred_store_master_self(op, data_class, &session_omni, &req.actor_omni)?;

    let chain = ChainContracts::from_state(&state)?;

    // 1. SidecarRegistry.getDevice(deviceKeyHash) — full decode.
    let device = call_get_device(
        &state.http,
        &chain.rpc_url,
        &chain.registry,
        &req.device_key_hash,
    )
    .await?;
    if device.registered_at == 0 {
        return Err(CapError::DeviceNotActive);
    }
    if device.revoked {
        return Err(CapError::DeviceRevoked);
    }
    // Device binding: the device must be bound to (operator = master, actor =
    // delegate) as named in the request — independent of which side holds the
    // session (operator for normal ops, the delegate for `CanonicalFetch`). For
    // normal ops `session_omni == req_omni` (enforced above) so this is the same
    // gate; for canonical it pins the master as operator + the delegate's device.
    if device.operator_omni != req_omni {
        return Err(CapError::DeviceBindingMismatch("operator_omni"));
    }
    if device.actor_omni != req_actor {
        return Err(CapError::DeviceBindingMismatch("actor_omni"));
    }
    if (device.roles & ROLE_CAP_MINT) == 0 {
        return Err(CapError::DeviceRoleMissing);
    }

    // 1b. K10 proof-of-possession (issue #76 — the broker-SPOF fix). Step 1
    //     bound `device_key_hash → (operator, actor)` on chain. When the caller
    //     supplies a `client_sig`, validate it proves possession of that K10 (a
    //     compromised broker cannot forge it). OPTIONAL during rollout — a cap
    //     with no PoP is minted as-is; the WORKER is the authoritative gate that
    //     rejects a missing PoP when AGENTKEYS_WORKER_REQUIRE_CAP_POP=1. The
    //     worker re-verifies any supplied proof independently regardless.
    verify_cap_pop(&req, op, data_class)?;

    // 2. AgentKeysScope.isServiceInScope(operator, actor, keccak(service)).
    //    SKIP when operator == actor — the master accessing its OWN data classes
    //    (memory / credentials / email). Scope gates AGENTS, not the operator over
    //    its own actor. Bounded-safe: the device check above already pinned
    //    device.actor_omni == req.actor_omni, so this only ever opens
    //    bots/<O_master>/. Deliberate SKIP, NOT a removal of the scope-grant path
    //    (retained for a possible future design) — see docs/arch.md §12.4.
    let service_hash = keccak256_of_lc_service(&req.service);
    let in_scope = if req_omni == req_actor {
        true
    } else {
        call_is_service_in_scope(
            &state.http,
            &chain.rpc_url,
            &chain.scope,
            &req.operator_omni,
            &req.actor_omni,
            &service_hash,
        )
        .await?
    };
    if !in_scope {
        return Err(CapError::ServiceNotInScope);
    }

    // 3. K3EpochCounter.currentEpoch → embed.
    let k3_epoch = call_current_epoch(&state.http, &chain.rpc_url, &chain.epoch).await?;

    // 4. Build payload + sign.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CapError::Sign("clock before epoch".into()))?
        .as_secs();
    let mut nonce_bytes = [0u8; 16];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let payload = CapPayload {
        operator_omni: format!("0x{}", req_omni.clone()),
        actor_omni: format!("0x{}", req_actor.clone()),
        service: req.service.to_lowercase(),
        op,
        data_class,
        device_key_hash: format!("0x{}", strip_0x_lc(&req.device_key_hash)),
        k3_epoch,
        issued_at: now,
        expires_at: now + ttl,
        nonce,
    };
    let broker_sig = sign_cap_payload(&state.session_keypair.private_key_pem, &payload)?;
    Ok(CapToken {
        payload,
        broker_sig,
        client_sig: req.client_sig,
        client_nonce: req.client_nonce,
        client_ts: req.client_ts,
        // Echo the delegation VERBATIM (#369) — the worker re-verifies it; the
        // broker is untrusted and never inspects it.
        delegation_path: req.delegation_path,
    })
}

/// Single-vault gate (layer 1 — docs/plan/single-vault-credentials.md): a
/// credentials STORE cap may only be minted master-self (`actor == session
/// operator`). Every credential lives in the operator's vault; agents fetch
/// delegated but never self-store (the #228 agent-own vault is removed, which
/// closes the shadowing hole by construction). All other (op, data_class)
/// combinations pass through untouched.
fn enforce_cred_store_master_self(
    op: CapOp,
    data_class: DataClass,
    session_omni_norm: &str,
    actor_omni_raw: &str,
) -> Result<(), CapError> {
    if op != CapOp::Store || data_class != DataClass::Credentials {
        return Ok(());
    }
    let actor = normalize_hex32(actor_omni_raw)
        .map_err(|e| CapError::InvalidInput(format!("actor_omni invalid: {e}")))?;
    if actor != session_omni_norm {
        return Err(CapError::Forbidden(
            "cred store is master-self only — agents cannot self-store credentials \
             (single-vault: every credential lives in the operator's vault)"
                .to_string(),
            "cred_store_not_master_self",
        ));
    }
    Ok(())
}

/// Worker-side max age for a cap-PoP signature. Shared with the worker's
/// `verify::check_client_pop` so the broker and worker agree on the freshness
/// window. The broker also rejects far-future `client_ts` (clock-skew guard).
const CAP_POP_MAX_AGE_SECS: u64 = 300;

/// Validate the K10 cap-mint proof-of-possession (issue #76) when present.
///
/// OPTIONAL + verify-when-present (staged rollout): a cap-mint that carries no
/// `client_sig` is a no-op here — the cap is minted without a PoP, and the WORKER
/// is the authoritative gate that rejects a missing PoP when
/// `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1`. When a PoP IS supplied, it must recover
/// to an address whose `keccak == device_key_hash` (already bound on-chain to
/// this operator/actor) and be fresh — what a compromised broker cannot forge.
fn verify_cap_pop(req: &CapRequest, op: CapOp, data_class: DataClass) -> Result<(), CapError> {
    let (Some(client_sig), Some(client_nonce), Some(client_ts)) = (
        req.client_sig.as_deref(),
        req.client_nonce.as_deref(),
        req.client_ts,
    ) else {
        return Ok(()); // no PoP supplied — nothing to validate at the broker
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if client_ts > now + 60 {
        return Err(CapError::CapPopInvalid(format!(
            "client_ts {client_ts} is in the future (now {now})"
        )));
    }
    if now.saturating_sub(client_ts) > CAP_POP_MAX_AGE_SECS {
        return Err(CapError::CapPopInvalid(format!(
            "client_ts {client_ts} is stale (now {now}, max age {CAP_POP_MAX_AGE_SECS}s)"
        )));
    }
    let preimage = agentkeys_core::device_crypto::cap_pop_payload(
        &req.operator_omni,
        &req.actor_omni,
        &req.service,
        op.as_str(),
        data_class.as_str(),
        client_nonce,
        client_ts,
    );
    let recovered = agentkeys_core::device_crypto::ecrecover_eip191(&preimage, client_sig)
        .map_err(|e| CapError::CapPopInvalid(format!("client_sig recover: {e}")))?;
    let recovered_hash = agentkeys_core::device_crypto::device_key_hash(&recovered)
        .map_err(|e| CapError::CapPopInvalid(format!("recovered address hash: {e}")))?;

    // Direct K10 path (#76): the cap-PoP was signed by the on-chain-bound device key.
    if strip_0x_lc(&recovered_hash) == strip_0x_lc(&req.device_key_hash) {
        return Ok(());
    }
    // Delegated path (#369): the cap-PoP was signed by a sandbox's EPHEMERAL key,
    // not the device K10. Accept iff a device-issued, unexpired, in-scope delegation
    // authorizes EXACTLY this signer. The WORKER re-verifies this same delegation
    // independently (it is the authoritative gate); the broker checks it here only
    // to fail fast and stay untrusted. Uses the SAME shared scope matcher + crypto.
    if let Some(deleg) = &req.delegation_path {
        if deleg.expires_at <= now {
            return Err(CapError::CapPopInvalid(format!(
                "delegation expired at {} (now {now})",
                deleg.expires_at
            )));
        }
        if !agentkeys_core::device_crypto::cap_in_scope(
            &deleg.scope,
            data_class.as_str(),
            op.as_str(),
            &req.service,
        ) {
            return Err(CapError::CapPopInvalid(format!(
                "cap (service {}) outside delegation scope {:?}",
                req.service, deleg.scope
            )));
        }
        agentkeys_core::device_crypto::verify_delegation(
            &req.device_key_hash,
            &recovered,
            &deleg.scope,
            deleg.expires_at,
            &deleg.delegation_sig,
        )
        .map_err(|e| CapError::CapPopInvalid(format!("delegation verify: {e}")))?;
        return Ok(());
    }
    Err(CapError::CapPopInvalid(
        "client_sig does not match device_key_hash (K10 proof-of-possession failed)".into(),
    ))
}

// ─── on-chain reads (raw eth_call over reqwest) ────────────────────────

pub(crate) const ROLE_CAP_MINT: u8 = 1;

#[derive(Debug)]
pub(crate) struct ChainContracts {
    pub(crate) rpc_url: String,
    pub(crate) registry: String,
    scope: String,
    epoch: String,
}

impl ChainContracts {
    /// Resolve from env using the AGENTKEYS_CHAIN profile (default `heima`).
    /// Pattern: env keys are `{NAME}_{PROFILE_UC}` where PROFILE_UC =
    /// uppercased chain name with `-` → `_`. Matches the shape used in
    /// scripts/operator-workstation.env so broker/worker/CLI/bash all
    /// read the same value.
    pub(crate) fn from_state(_state: &SharedState) -> Result<Self, CapError> {
        let profile = std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".into());
        let profile_uc = profile.to_uppercase().replace('-', "_");
        let rpc_url = std::env::var("AGENTKEYS_CHAIN_RPC_HTTP")
            .or_else(|_| std::env::var(format!("CHAIN_RPC_HTTP_{profile_uc}")))
            .or_else(|_| std::env::var("HEIMA_RPC_HTTP"))
            .map_err(|_| CapError::ChainRpc(format!(
                "RPC URL not set (AGENTKEYS_CHAIN_RPC_HTTP or CHAIN_RPC_HTTP_{profile_uc} or HEIMA_RPC_HTTP)"
            )))?;
        let registry = profile_env(&profile_uc, "SIDECAR_REGISTRY_ADDRESS")?;
        let scope = profile_env(&profile_uc, "SCOPE_CONTRACT_ADDRESS")?;
        let epoch = profile_env(&profile_uc, "K3_EPOCH_COUNTER_ADDRESS")?;
        Ok(ChainContracts {
            rpc_url,
            registry,
            scope,
            epoch,
        })
    }
}

fn profile_env(profile_uc: &str, base: &str) -> Result<String, CapError> {
    let key = format!("{base}_{profile_uc}");
    std::env::var(&key).map_err(|_| CapError::ChainRpc(format!("{key} unset")))
}

#[derive(Debug)]
pub(crate) struct DeviceEntry {
    pub(crate) operator_omni: String, // hex without 0x
    pub(crate) actor_omni: String,
    pub(crate) roles: u8,
    pub(crate) registered_at: u64,
    pub(crate) revoked: bool,
}

async fn eth_call(
    http: &reqwest::Client,
    rpc_url: &str,
    to: &str,
    data: &str,
) -> Result<String, CapError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
        "id": 1,
    });
    // The Heima public RPC intermittently 500s on eth_call (~12% per call,
    // HTML error page → non-JSON). Retry transient failures (transport / HTTP
    // 5xx / non-JSON) with backoff so a flaky RPC doesn't randomly fail
    // cap-mint; do NOT retry a valid JSON-RPC `error` (a real revert result).
    const ATTEMPTS: u32 = 4;
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            let ms = 150u64 * (1u64 << (attempt - 1)); // 150, 300, 600 ms
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        let resp = match http.post(rpc_url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                last = format!("eth_call POST failed: {e}");
                continue;
            }
        };
        if resp.status().is_server_error() {
            last = format!("eth_call HTTP {}", resp.status());
            continue;
        }
        let v: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                last = format!("eth_call JSON parse: {e}");
                continue;
            }
        };
        if let Some(err) = v.get("error") {
            return Err(CapError::ChainRpc(format!("RPC error: {err}")));
        }
        return v
            .get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CapError::ChainRpc("eth_call missing 'result'".into()));
    }
    Err(CapError::ChainRpc(format!(
        "eth_call failed after {ATTEMPTS} attempts: {last}"
    )))
}

pub(crate) async fn call_get_device(
    http: &reqwest::Client,
    rpc: &str,
    registry: &str,
    device_key_hash: &str,
) -> Result<DeviceEntry, CapError> {
    let selector = function_selector("getDevice(bytes32)");
    let arg = strip_0x_pad32(device_key_hash, "device_key_hash")?;
    let data = format!("0x{selector}{arg}");
    let result = eth_call(http, rpc, registry, &data).await?;
    parse_device_entry(&result)
}

/// Decode the ABI-encoded DeviceEntry struct return from getDevice. The
/// struct layout (per SidecarRegistry.sol):
///   bytes32 operatorOmni    (word 0)
///   bytes32 actorOmni       (word 1)
///   bytes32 k11CredId       (word 2)
///   uint8   tier            (word 3, right-aligned)
///   uint8   roles           (word 4, right-aligned)
///   uint64  registeredAt    (word 5, right-aligned)
///   bool    revoked         (word 6, right-aligned)
fn parse_device_entry(raw: &str) -> Result<DeviceEntry, CapError> {
    let hex = raw.trim_start_matches("0x");
    // DeviceEntry post codex H1 (SidecarRegistry.sol) has 11 ABI words:
    //   word 0  operatorOmni     bytes32
    //   word 1  actorOmni        bytes32
    //   word 2  k11CredId        bytes32
    //   word 3  k11RpIdHash      bytes32  (NEW, codex H1)
    //   word 4  k11PubX          uint256  (NEW, codex H1)
    //   word 5  k11PubY          uint256  (NEW, codex H1)
    //   word 6  tier             uint8 (padded)
    //   word 7  roles            uint8 (padded)
    //   word 8  registeredAt     uint64 (padded)
    //   word 9  lastSignCount    uint32 (padded)
    //   word 10 revoked          bool (padded)
    if hex.len() < 11 * 64 {
        return Err(CapError::ChainRpc(format!(
            "getDevice returned {} bytes; expected ≥ 11×32 (post codex H1 struct)",
            hex.len() / 2
        )));
    }
    let operator_omni = hex[0..64].to_lowercase();
    let actor_omni = hex[64..128].to_lowercase();
    let roles_hex = &hex[7 * 64..8 * 64];
    let registered_hex = &hex[8 * 64..9 * 64];
    let revoked_hex = &hex[10 * 64..11 * 64];
    // Take last 2 hex chars (uint8) of the roles word.
    let roles = u8::from_str_radix(&roles_hex[62..64], 16).unwrap_or(0);
    let registered_at = u64::from_str_radix(&registered_hex[48..64], 16).unwrap_or(0);
    let revoked = revoked_hex.trim_start_matches('0').ends_with('1');
    Ok(DeviceEntry {
        operator_omni,
        actor_omni,
        roles,
        registered_at,
        revoked,
    })
}

async fn call_is_service_in_scope(
    http: &reqwest::Client,
    rpc: &str,
    scope: &str,
    operator: &str,
    actor: &str,
    service_hash: &str,
) -> Result<bool, CapError> {
    let selector = function_selector("isServiceInScope(bytes32,bytes32,bytes32)");
    let a = strip_0x_pad32(operator, "operator_omni")?;
    let b = strip_0x_pad32(actor, "actor_omni")?;
    let c = strip_0x_pad32(service_hash, "service_hash")?;
    let data = format!("0x{selector}{a}{b}{c}");
    let result = eth_call(http, rpc, scope, &data).await?;
    Ok(parse_bool_result(&result))
}

async fn call_current_epoch(
    http: &reqwest::Client,
    rpc: &str,
    epoch: &str,
) -> Result<u64, CapError> {
    let selector = function_selector("currentEpoch()");
    let data = format!("0x{selector}");
    let result = eth_call(http, rpc, epoch, &data).await?;
    parse_u64_result(&result)
}

// ─── helpers ───────────────────────────────────────────────────────────

fn extract_bearer(headers: &HeaderMap) -> Result<String, CapError> {
    let h = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| CapError::Unauthorized("missing Authorization header".into()))?
        .to_str()
        .map_err(|_| CapError::Unauthorized("Authorization not UTF-8".into()))?;
    h.strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or_else(|| CapError::Unauthorized("Authorization must be 'Bearer <jwt>'".into()))
}

fn validate_hex32(s: &str, field: &str) -> Result<(), CapError> {
    if !s.starts_with("0x") {
        return Err(CapError::InvalidInput(format!(
            "{field} must start with 0x"
        )));
    }
    if s.len() != 66 {
        return Err(CapError::InvalidInput(format!(
            "{field} must be 66 chars (0x + 64 hex), got {}",
            s.len()
        )));
    }
    hex::decode(&s[2..])
        .map_err(|_| CapError::InvalidInput(format!("{field} contains non-hex chars")))?;
    Ok(())
}

fn normalize_hex32(s: &str) -> Result<String, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(format!("expected 64-hex, got {}", stripped.len()));
    }
    hex::decode(stripped).map_err(|e| e.to_string())?;
    Ok(stripped.to_lowercase())
}

fn strip_0x_pad32(s: &str, field: &str) -> Result<String, CapError> {
    validate_hex32(s, field)?;
    Ok(s[2..].to_lowercase())
}

fn strip_0x_lc(s: &str) -> String {
    s.strip_prefix("0x").unwrap_or(s).to_lowercase()
}

fn parse_bool_result(s: &str) -> bool {
    s.trim_start_matches("0x")
        .trim_start_matches('0')
        .ends_with('1')
}

fn parse_u64_result(s: &str) -> Result<u64, CapError> {
    let stripped = s.trim_start_matches("0x");
    u64::from_str_radix(stripped, 16)
        .map_err(|e| CapError::ChainRpc(format!("epoch parse: {e} (raw: {s})")))
}

fn function_selector(sig: &str) -> String {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(sig.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..4])
}

fn keccak256_of_lc_service(name: &str) -> String {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(name.to_lowercase().as_bytes());
    let digest = hasher.finalize();
    format!("0x{}", hex::encode(digest))
}

/// Verify a `broker_sig` THIS broker produced over `payload` (#295 P1 §7a — the
/// `/v1/cap/canonical-sts` endpoint re-verifies a CanonicalFetch cap before
/// issuing scoped STS, so a forged/foreign cap can't obtain operator-prefix
/// credentials). Recomputes `Sha256(json(payload))` and checks the ECDSA sig
/// against the verifying key derived from the session signing PEM. Exact inverse
/// of [`sign_cap_payload`] (same digest input, same encoding).
pub(crate) fn verify_cap_payload_sig(
    signing_pem: &str,
    payload: &CapPayload,
    sig_b64: &str,
) -> bool {
    use p256::ecdsa::signature::Verifier;
    let Ok(canonical) = serde_json::to_vec(payload) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let digest = hasher.finalize();
    let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let Ok(signing_key) = SigningKey::from_pkcs8_pem(signing_pem) else {
        return false;
    };
    signing_key.verifying_key().verify(&digest, &sig).is_ok()
}

fn sign_cap_payload(signing_pem: &str, payload: &CapPayload) -> Result<String, CapError> {
    let canonical = serde_json::to_vec(payload)
        .map_err(|e| CapError::Sign(format!("payload JSON encode: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let digest = hasher.finalize();
    let signing_key = SigningKey::from_pkcs8_pem(signing_pem)
        .map_err(|e| CapError::Sign(format!("load signing key: {e}")))?;
    let sig: Signature = signing_key.sign(&digest);
    Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

trait FromPkcs8Pem: Sized {
    fn from_pkcs8_pem(pem: &str) -> Result<Self, p256::pkcs8::Error>;
}
impl FromPkcs8Pem for SigningKey {
    fn from_pkcs8_pem(pem: &str) -> Result<Self, p256::pkcs8::Error> {
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::SecretKey::from_pkcs8_pem(pem)?;
        Ok(SigningKey::from(sk))
    }
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_op_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&CapOp::Store).unwrap(), "\"store\"");
        assert_eq!(serde_json::to_string(&CapOp::Fetch).unwrap(), "\"fetch\"");
        assert_eq!(
            serde_json::to_string(&CapOp::Teardown).unwrap(),
            "\"teardown\""
        );
        assert_eq!(
            serde_json::to_string(&CapOp::Classify).unwrap(),
            "\"classify\""
        );
    }

    #[test]
    fn cap_op_as_u8_matches_audit_codes() {
        assert_eq!(CapOp::Store.as_u8(), 0);
        assert_eq!(CapOp::Fetch.as_u8(), 1);
        assert_eq!(CapOp::Teardown.as_u8(), 2);
        assert_eq!(CapOp::Classify.as_u8(), 3);
    }

    #[test]
    fn cred_store_mint_is_master_self_only() {
        // Single-vault (docs/plan/single-vault-credentials.md): a delegated
        // cred-STORE mint is a hard 403 — the route-level gate that closes
        // the #228 shadowing hole. Same actor delegated FETCH and delegated
        // memory PUT stay mintable (scope-gated as before).
        let master = "a".repeat(64);
        let agent_0x = format!("0x{}", "b".repeat(64));
        let master_0x = format!("0x{}", "a".repeat(64));

        let err = enforce_cred_store_master_self(
            CapOp::Store,
            DataClass::Credentials,
            &master,
            &agent_0x,
        )
        .unwrap_err();
        match err {
            CapError::Forbidden(_, reason) => assert_eq!(reason, "cred_store_not_master_self"),
            other => panic!("expected Forbidden(cred_store_not_master_self), got {other:?}"),
        }

        // master-self store (0x-prefixed raw form normalizes to the session omni)
        assert!(enforce_cred_store_master_self(
            CapOp::Store,
            DataClass::Credentials,
            &master,
            &master_0x,
        )
        .is_ok());
        // delegated fetch — untouched
        assert!(enforce_cred_store_master_self(
            CapOp::Fetch,
            DataClass::Credentials,
            &master,
            &agent_0x,
        )
        .is_ok());
        // delegated memory put — untouched (agents keep their own memory)
        assert!(enforce_cred_store_master_self(
            CapOp::Store,
            DataClass::Memory,
            &master,
            &agent_0x
        )
        .is_ok());
    }

    #[test]
    fn cap_classify_request_carries_data_class() {
        // The classify endpoint takes data_class in the body (it spans data
        // classes), unlike the storage endpoints where the route fixes it.
        let req: CapClassifyRequest = serde_json::from_value(serde_json::json!({
            "operator_omni": format!("0x{}", "a".repeat(64)),
            "actor_omni": format!("0x{}", "a".repeat(64)),
            "service": "classify:memory",
            "device_key_hash": format!("0x{}", "c".repeat(64)),
            "data_class": "memory",
            "client_sig": "0x00",
            "client_nonce": "00",
            "client_ts": 0,
        }))
        .unwrap();
        assert_eq!(req.data_class, DataClass::Memory);
        assert_eq!(req.ttl_seconds, 300); // default
    }

    fn cap_req_with(
        dkh: &str,
        client_sig: String,
        client_nonce: String,
        client_ts: u64,
    ) -> CapRequest {
        CapRequest {
            operator_omni: format!("0x{}", "a".repeat(64)),
            actor_omni: format!("0x{}", "b".repeat(64)),
            service: "memory:travel".into(),
            device_key_hash: dkh.to_string(),
            ttl_seconds: 300,
            client_sig: Some(client_sig),
            client_nonce: Some(client_nonce),
            client_ts: Some(client_ts),
            delegation_path: None,
        }
    }

    #[test]
    fn verify_cap_pop_accepts_valid_rejects_forged_and_wrong_op() {
        use agentkeys_core::device_crypto::DeviceKey;
        let dir = std::env::temp_dir();
        let dk = DeviceKey::load_or_generate(dir.join("ak-cap-pop-a.key").to_str().unwrap(), true)
            .unwrap();
        let dkh = dk.device_key_hash().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = "00112233aabbccdd".to_string();
        let (operator, actor, service) = (
            format!("0x{}", "a".repeat(64)),
            format!("0x{}", "b".repeat(64)),
            "memory:travel",
        );
        let sig = dk
            .cap_pop_sig(&operator, &actor, service, "store", "memory", &nonce, now)
            .unwrap();

        // Happy path: a real K10 sig over the right preimage → Ok.
        let ok = cap_req_with(&dkh, sig.clone(), nonce.clone(), now);
        assert!(verify_cap_pop(&ok, CapOp::Store, DataClass::Memory).is_ok());

        // Wrong op → preimage differs → recovered address mismatches the hash.
        assert!(matches!(
            verify_cap_pop(&ok, CapOp::Fetch, DataClass::Memory),
            Err(CapError::CapPopInvalid(_))
        ));

        // Forged: a valid signature from a DIFFERENT key (what a compromised
        // broker that lacks the user's K10 could at best produce) → rejected
        // because keccak(recovered) != device_key_hash. THIS is the SPOF fix.
        let other =
            DeviceKey::load_or_generate(dir.join("ak-cap-pop-b.key").to_str().unwrap(), true)
                .unwrap();
        let forged = other
            .cap_pop_sig(&operator, &actor, service, "store", "memory", &nonce, now)
            .unwrap();
        let bad = cap_req_with(&dkh, forged, nonce.clone(), now);
        assert!(matches!(
            verify_cap_pop(&bad, CapOp::Store, DataClass::Memory),
            Err(CapError::CapPopInvalid(_))
        ));

        // Stale timestamp → rejected.
        let stale_ts = now.saturating_sub(CAP_POP_MAX_AGE_SECS + 60);
        let stale_sig = dk
            .cap_pop_sig(
                &operator, &actor, service, "store", "memory", &nonce, stale_ts,
            )
            .unwrap();
        let stale = cap_req_with(&dkh, stale_sig, nonce, stale_ts);
        assert!(matches!(
            verify_cap_pop(&stale, CapOp::Store, DataClass::Memory),
            Err(CapError::CapPopInvalid(_))
        ));
    }

    #[test]
    fn verify_cap_pop_accepts_delegated_in_scope_rejects_out_of_scope() {
        // #369 broker delegated branch: the cap-PoP is signed by the SANDBOX's
        // ephemeral key (not the device K10), and a device-signed delegation
        // authorizes it. The broker accepts iff the delegation is in-scope + the
        // device co-signed it; a regression here (broker stops checking the
        // delegation scope or binding) turns this RED.
        use agentkeys_core::device_crypto::DeviceKey;
        let dir = std::env::temp_dir();
        let device =
            DeviceKey::load_or_generate(dir.join("ak-cap-deleg-dev.key").to_str().unwrap(), true)
                .unwrap();
        let sandbox =
            DeviceKey::load_or_generate(dir.join("ak-cap-deleg-sbx.key").to_str().unwrap(), true)
                .unwrap();
        let dkh = device.device_key_hash().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = "00112233aabbccdd".to_string();
        let (operator, actor, service) = (
            format!("0x{}", "a".repeat(64)),
            format!("0x{}", "b".repeat(64)),
            "memory:travel",
        );
        // The SANDBOX signs the cap-PoP; the cap carries the DEVICE's bound hash.
        let sig = sandbox
            .cap_pop_sig(&operator, &actor, service, "store", "memory", &nonce, now)
            .unwrap();
        let expires = now + 3600;
        let mk = |scope: &str, signer: &DeviceKey| {
            let mut r = cap_req_with(&dkh, sig.clone(), nonce.clone(), now);
            r.delegation_path = Some(DelegationPath {
                scope: scope.to_string(),
                expires_at: expires,
                delegation_sig: signer
                    .delegation_sig(sandbox.address(), scope, expires)
                    .unwrap(),
            });
            r
        };
        // In-scope, device-signed → accepted.
        assert!(verify_cap_pop(
            &mk("memory:travel memory:personal", &device),
            CapOp::Store,
            DataClass::Memory
        )
        .is_ok());
        // Out-of-scope (excludes memory:travel) → rejected.
        assert!(matches!(
            verify_cap_pop(
                &mk("memory:personal", &device),
                CapOp::Store,
                DataClass::Memory
            ),
            Err(CapError::CapPopInvalid(_))
        ));
        // Wrong-device: the SANDBOX self-signs the delegation → rejected (the
        // delegation must recover to the bound device).
        assert!(matches!(
            verify_cap_pop(
                &mk("memory:travel", &sandbox),
                CapOp::Store,
                DataClass::Memory
            ),
            Err(CapError::CapPopInvalid(_))
        ));
        // No delegation + a non-device signer → the direct #76 path rejects.
        let mut bare = cap_req_with(&dkh, sig.clone(), nonce.clone(), now);
        bare.delegation_path = None;
        assert!(matches!(
            verify_cap_pop(&bare, CapOp::Store, DataClass::Memory),
            Err(CapError::CapPopInvalid(_))
        ));
    }

    #[test]
    fn verify_cap_pop_is_noop_when_no_pop_supplied() {
        // Staged rollout (issue #76): a cap-mint with NO PoP is accepted at the
        // broker — the worker is the gate that rejects a missing PoP under
        // AGENTKEYS_WORKER_REQUIRE_CAP_POP=1.
        let req = CapRequest {
            operator_omni: format!("0x{}", "a".repeat(64)),
            actor_omni: format!("0x{}", "b".repeat(64)),
            service: "memory:travel".into(),
            device_key_hash: format!("0x{}", "c".repeat(64)),
            ttl_seconds: 300,
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        };
        assert!(verify_cap_pop(&req, CapOp::Store, DataClass::Memory).is_ok());
    }

    #[test]
    fn function_selector_matches_known_signatures() {
        assert_eq!(
            function_selector("isServiceInScope(bytes32,bytes32,bytes32)"),
            "13337240"
        );
        assert_eq!(function_selector("currentEpoch()"), "76671808");
        // getDevice selector is the one we actually call now.
        assert!(!function_selector("getDevice(bytes32)").is_empty());
    }

    #[test]
    fn keccak_service_lowercases() {
        let h1 = keccak256_of_lc_service("OpenRouter");
        let h2 = keccak256_of_lc_service("openrouter");
        assert_eq!(h1, h2);
    }

    #[test]
    fn validate_hex32_accepts_well_formed() {
        let valid = "0x".to_string() + &"a".repeat(64);
        assert!(validate_hex32(&valid, "x").is_ok());
    }

    #[test]
    fn validate_hex32_rejects_short() {
        let invalid = "0x".to_string() + &"a".repeat(63);
        assert!(matches!(
            validate_hex32(&invalid, "x"),
            Err(CapError::InvalidInput(_))
        ));
    }

    #[test]
    fn parse_bool_result_handles_padded() {
        assert!(parse_bool_result(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));
        assert!(!parse_bool_result(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn parse_u64_result_decodes_hex() {
        assert_eq!(
            parse_u64_result("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            1
        );
    }

    #[test]
    fn parse_device_entry_decodes_well_formed() {
        // 11 ABI words (post codex H1): operator + actor + k11{CredId,
        // RpIdHash, PubX, PubY} + tier + roles + registeredAt +
        // lastSignCount + revoked. roles=7 (CAP_MINT|RECOVERY|SCOPE_MGMT),
        // registeredAt=42, revoked=false.
        let mut raw = String::from("0x");
        raw.push_str(&"a".repeat(64)); // operatorOmni
        raw.push_str(&"b".repeat(64)); // actorOmni
        raw.push_str(&"0".repeat(64)); // k11CredId
        raw.push_str(&"0".repeat(64)); // k11RpIdHash
        raw.push_str(&"0".repeat(64)); // k11PubX
        raw.push_str(&"0".repeat(64)); // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64)); // tier=1
        raw.push_str(&format!("{:0>64x}", 7u64)); // roles=7
        raw.push_str(&format!("{:0>64x}", 42u64)); // registeredAt=42
        raw.push_str(&"0".repeat(64)); // lastSignCount=0
        raw.push_str(&"0".repeat(64)); // revoked=false
        let entry = parse_device_entry(&raw).unwrap();
        assert_eq!(entry.operator_omni, "a".repeat(64));
        assert_eq!(entry.actor_omni, "b".repeat(64));
        assert_eq!(entry.roles, 7);
        assert_eq!(entry.registered_at, 42);
        assert!(!entry.revoked);
    }

    #[test]
    fn parse_device_entry_detects_revoked() {
        let mut raw = String::from("0x");
        raw.push_str(&"a".repeat(64)); // operatorOmni
        raw.push_str(&"b".repeat(64)); // actorOmni
        raw.push_str(&"0".repeat(64)); // k11CredId
        raw.push_str(&"0".repeat(64)); // k11RpIdHash
        raw.push_str(&"0".repeat(64)); // k11PubX
        raw.push_str(&"0".repeat(64)); // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64)); // tier
        raw.push_str(&format!("{:0>64x}", 1u64)); // roles
        raw.push_str(&format!("{:0>64x}", 100u64)); // registeredAt
        raw.push_str(&"0".repeat(64)); // lastSignCount
        raw.push_str(&format!("{:0>64x}", 1u64)); // revoked=true
        let entry = parse_device_entry(&raw).unwrap();
        assert!(entry.revoked);
    }

    #[test]
    fn parse_device_entry_rejects_short() {
        let result = parse_device_entry("0x1234");
        assert!(matches!(result, Err(CapError::ChainRpc(_))));
    }

    #[test]
    fn cap_payload_includes_device_key_hash_and_op() {
        let p = CapPayload {
            operator_omni: format!("0x{}", "a".repeat(64)),
            actor_omni: format!("0x{}", "b".repeat(64)),
            service: "openrouter".into(),
            op: CapOp::Store,
            data_class: DataClass::Credentials,
            device_key_hash: format!("0x{}", "c".repeat(64)),
            k3_epoch: 1,
            issued_at: 1,
            expires_at: 100,
            nonce: "00".repeat(16),
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"device_key_hash\""));
        assert!(j.contains("\"op\":\"store\""));
        assert!(j.contains("\"data_class\":\"credentials\""));
        assert!(j.contains("\"issued_at\":1"));
    }

    #[test]
    fn cap_payload_serializes_data_class_per_endpoint() {
        // The data_class is what makes the cap-token data-class-explicit;
        // cred-store endpoints mint with Credentials, memory-* with Memory.
        for (dc, expect) in [
            (DataClass::Credentials, "credentials"),
            (DataClass::Memory, "memory"),
        ] {
            let p = CapPayload {
                operator_omni: format!("0x{}", "a".repeat(64)),
                actor_omni: format!("0x{}", "b".repeat(64)),
                service: "openrouter".into(),
                op: CapOp::Store,
                data_class: dc,
                device_key_hash: format!("0x{}", "c".repeat(64)),
                k3_epoch: 1,
                issued_at: 1,
                expires_at: 100,
                nonce: "00".repeat(16),
            };
            let j = serde_json::to_string(&p).unwrap();
            assert!(j.contains(&format!("\"data_class\":\"{expect}\"")));
        }
    }

    #[test]
    fn extract_bearer_strips_prefix() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc.def.ghi".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h).unwrap(), "abc.def.ghi");
    }

    #[test]
    fn extract_bearer_rejects_missing() {
        let h = HeaderMap::new();
        assert!(matches!(extract_bearer(&h), Err(CapError::Unauthorized(_))));
    }

    #[test]
    fn extract_bearer_rejects_non_bearer() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc".parse().unwrap(),
        );
        assert!(matches!(extract_bearer(&h), Err(CapError::Unauthorized(_))));
    }

    #[test]
    fn normalize_hex32_strips_prefix_lowers() {
        let s = format!("0x{}", "A".repeat(64));
        assert_eq!(normalize_hex32(&s).unwrap(), "a".repeat(64));
    }

    #[test]
    fn cap_error_unauthorized_returns_401() {
        let resp = CapError::Unauthorized("missing".into()).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn cap_error_operator_mismatch_returns_403() {
        let resp = CapError::OperatorMismatch.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn cap_error_device_role_missing_returns_403() {
        let resp = CapError::DeviceRoleMissing.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn cap_error_device_revoked_returns_403() {
        let resp = CapError::DeviceRevoked.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn cap_error_service_not_in_scope_returns_403() {
        let resp = CapError::ServiceNotInScope.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn cap_error_chain_rpc_returns_502() {
        let resp = CapError::ChainRpc("RPC unreachable".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn cap_error_invalid_input_returns_400() {
        let resp = CapError::InvalidInput("bad omni".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
