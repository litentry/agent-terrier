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
//!
//! Stage-1 simplification per arch.md §22b.4 (stage-1 simplifications inventory — no K10 signature requirement; issue #90 for the hardening): K10 signature over the
//! cap-mint request is not yet required (stage 2 adds the daemon's
//! per-call K10 signature). Until then, the session JWT + on-chain
//! device binding are the auth surface.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::jwt::verify::verify_session_jwt;
use crate::state::SharedState;

/// Cap operation discriminator (matches CredentialAudit.OP_* on chain
/// and `agentkeys-worker-creds`'s mirror enum byte-for-byte).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapOp {
    Store,
    Fetch,
    Teardown,
}

impl CapOp {
    pub fn as_u8(self) -> u8 {
        match self {
            CapOp::Store => 0,
            CapOp::Fetch => 1,
            CapOp::Teardown => 2,
        }
    }
}

/// Data class the cap-token is bound to. Mirror of
/// `agentkeys_worker_creds::verify::DataClass`. The broker mints with
/// the right variant for each endpoint (`/v1/cap/cred-*` → Credentials,
/// `/v1/cap/memory-*` → Memory) and signs it into the payload; workers
/// reject caps whose data_class doesn't match their bucket. Issue #90
/// followup — codified in CLAUDE.md.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Credentials,
    Memory,
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
}

#[derive(Debug, Deserialize)]
pub struct CapRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
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
    mint_cap(state, headers, req, CapOp::Store, DataClass::Credentials).await.map(Json)
}

pub async fn cap_cred_fetch(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Fetch, DataClass::Credentials).await.map(Json)
}

// Memory cap-mint endpoints (issue #90 followup): per-data-class
// explicit binding. The minted cap carries data_class=Memory; the cred
// worker would reject it via verify::check_data_class.
pub async fn cap_memory_put(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Store, DataClass::Memory).await.map(Json)
}

pub async fn cap_memory_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CapRequest>,
) -> Result<Json<CapToken>, CapError> {
    mint_cap(state, headers, req, CapOp::Fetch, DataClass::Memory).await.map(Json)
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
        return Err(CapError::InvalidInput("service must be 1..=64 chars".into()));
    }
    let ttl = req.ttl_seconds.clamp(60, 1800);

    // 0. Session JWT auth — caller must hold the operator session.
    let bearer = extract_bearer(&headers)?;
    let claims = verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &bearer,
    )
    .map_err(|e| CapError::Unauthorized(format!("session jwt verify: {e}")))?;

    let session_omni = normalize_hex32(&claims.agentkeys.omni_account)
        .map_err(|e| CapError::InvalidInput(format!("session omni invalid: {e}")))?;
    let req_omni = normalize_hex32(&req.operator_omni)
        .map_err(|e| CapError::InvalidInput(format!("operator_omni invalid: {e}")))?;
    if session_omni != req_omni {
        return Err(CapError::OperatorMismatch);
    }

    let chain = ChainContracts::from_state(&state)?;

    // 1. SidecarRegistry.getDevice(deviceKeyHash) — full decode.
    let device = call_get_device(&state.http, &chain.rpc_url, &chain.registry, &req.device_key_hash).await?;
    if device.registered_at == 0 {
        return Err(CapError::DeviceNotActive);
    }
    if device.revoked {
        return Err(CapError::DeviceRevoked);
    }
    let req_actor = normalize_hex32(&req.actor_omni)
        .map_err(|e| CapError::InvalidInput(format!("actor_omni invalid: {e}")))?;
    if device.operator_omni != session_omni {
        return Err(CapError::DeviceBindingMismatch("operator_omni"));
    }
    if device.actor_omni != req_actor {
        return Err(CapError::DeviceBindingMismatch("actor_omni"));
    }
    if (device.roles & ROLE_CAP_MINT) == 0 {
        return Err(CapError::DeviceRoleMissing);
    }

    // 2. AgentKeysScope.isServiceInScope(operator, actor, keccak(service)).
    let service_hash = keccak256_of_lc_service(&req.service);
    let in_scope = call_is_service_in_scope(
        &state.http,
        &chain.rpc_url,
        &chain.scope,
        &req.operator_omni,
        &req.actor_omni,
        &service_hash,
    )
    .await?;
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
    Ok(CapToken { payload, broker_sig })
}

// ─── on-chain reads (raw eth_call over reqwest) ────────────────────────

const ROLE_CAP_MINT: u8 = 1;

#[derive(Debug)]
struct ChainContracts {
    rpc_url: String,
    registry: String,
    scope: String,
    epoch: String,
}

impl ChainContracts {
    /// Resolve from env using the AGENTKEYS_CHAIN profile (default `heima`).
    /// Pattern: env keys are `{NAME}_{PROFILE_UC}` where PROFILE_UC =
    /// uppercased chain name with `-` → `_`. Matches the shape used in
    /// scripts/operator-workstation.env so broker/worker/CLI/bash all
    /// read the same value.
    fn from_state(_state: &SharedState) -> Result<Self, CapError> {
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
        Ok(ChainContracts { rpc_url, registry, scope, epoch })
    }
}

fn profile_env(profile_uc: &str, base: &str) -> Result<String, CapError> {
    let key = format!("{base}_{profile_uc}");
    std::env::var(&key).map_err(|_| CapError::ChainRpc(format!("{key} unset")))
}

#[derive(Debug)]
struct DeviceEntry {
    operator_omni: String, // hex without 0x
    actor_omni: String,
    roles: u8,
    registered_at: u64,
    revoked: bool,
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
    let resp = http
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| CapError::ChainRpc(format!("eth_call POST failed: {e}")))?;
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CapError::ChainRpc(format!("eth_call JSON parse: {e}")))?;
    if let Some(err) = v.get("error") {
        return Err(CapError::ChainRpc(format!("RPC error: {err}")));
    }
    v.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CapError::ChainRpc("eth_call missing 'result'".into()))
}

async fn call_get_device(
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
        return Err(CapError::InvalidInput(format!("{field} must start with 0x")));
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
    s.trim_start_matches("0x").trim_start_matches('0').ends_with('1')
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
        assert_eq!(serde_json::to_string(&CapOp::Teardown).unwrap(), "\"teardown\"");
    }

    #[test]
    fn cap_op_as_u8_matches_audit_codes() {
        assert_eq!(CapOp::Store.as_u8(), 0);
        assert_eq!(CapOp::Fetch.as_u8(), 1);
        assert_eq!(CapOp::Teardown.as_u8(), 2);
    }

    #[test]
    fn function_selector_matches_known_signatures() {
        assert_eq!(function_selector("isServiceInScope(bytes32,bytes32,bytes32)"), "13337240");
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
        assert!(matches!(validate_hex32(&invalid, "x"), Err(CapError::InvalidInput(_))));
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
            parse_u64_result("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
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
        raw.push_str(&"a".repeat(64));               // operatorOmni
        raw.push_str(&"b".repeat(64));               // actorOmni
        raw.push_str(&"0".repeat(64));               // k11CredId
        raw.push_str(&"0".repeat(64));               // k11RpIdHash
        raw.push_str(&"0".repeat(64));               // k11PubX
        raw.push_str(&"0".repeat(64));               // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64));    // tier=1
        raw.push_str(&format!("{:0>64x}", 7u64));    // roles=7
        raw.push_str(&format!("{:0>64x}", 42u64));   // registeredAt=42
        raw.push_str(&"0".repeat(64));               // lastSignCount=0
        raw.push_str(&"0".repeat(64));               // revoked=false
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
        raw.push_str(&"a".repeat(64));               // operatorOmni
        raw.push_str(&"b".repeat(64));               // actorOmni
        raw.push_str(&"0".repeat(64));               // k11CredId
        raw.push_str(&"0".repeat(64));               // k11RpIdHash
        raw.push_str(&"0".repeat(64));               // k11PubX
        raw.push_str(&"0".repeat(64));               // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64));    // tier
        raw.push_str(&format!("{:0>64x}", 1u64));    // roles
        raw.push_str(&format!("{:0>64x}", 100u64));  // registeredAt
        raw.push_str(&"0".repeat(64));               // lastSignCount
        raw.push_str(&format!("{:0>64x}", 1u64));    // revoked=true
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
        h.insert(axum::http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
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
