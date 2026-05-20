//! Cap-token verification — same shape as
//! agentkeys-broker-server/src/handlers/cap.rs but flipped (verify
//! instead of sign).
//!
//! The worker MUST independently re-verify against the chain before any
//! S3 touch (arch.md §15.1). Five checks (codex review findings #3 + #4):
//!   1. `broker_sig` is a valid P-256 signature over Sha256(json(payload))
//!      under the env-injected broker pubkey.
//!   2. `payload.expires_at > now()` AND `payload.issued_at <= now()`
//!      (cap not expired AND not from the future — clock-skew check).
//!   3. `payload.op` matches the endpoint that received the request
//!      (a fetch-cap MUST NOT be honored at /store).
//!   4. On-chain `SidecarRegistry.getDevice(payload.device_key_hash)`:
//!      registeredAt > 0, revoked == false,
//!      operatorOmni == payload.operator_omni,
//!      actorOmni == payload.actor_omni,
//!      roles & ROLE_CAP_MINT != 0.
//!   5. On-chain `AgentKeysScope.isServiceInScope(operator, actor,
//!      keccak(service))` == true.
//!   6. On-chain `K3EpochCounter.currentEpoch` == `payload.k3_epoch`
//!      (rotation invalidates stale caps).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapOp {
    Store,
    Fetch,
    Teardown,
}

/// Data class the cap-token is bound to. Each worker MUST verify
/// `cap.payload.data_class` matches its own class before touching S3.
/// Without this, a cred-store cap could be submitted to /v1/memory/put
/// (or vice versa) and pollute the wrong bucket at the cap-authz layer.
/// The IAM PrincipalTag enforces per-actor scoping at the AWS layer
/// (defense in depth); this binding is the cryptographic per-class gate
/// at the cap layer (issue #90 followup, codified in CLAUDE.md).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Credentials,
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapPayload {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub op: CapOp,
    /// Data class the cap is bound to. REQUIRED — workers reject caps
    /// whose data_class doesn't match the URL's bucket.
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

pub const ROLE_CAP_MINT: u8 = 1;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("broker public key parse: {0}")]
    BrokerKey(String),
    #[error("signature decode (base64): {0}")]
    SigDecode(String),
    #[error("signature parse: {0}")]
    SigParse(String),
    #[error("signature verify failed")]
    SigInvalid,
    #[error("payload canonical-json encode: {0}")]
    Encode(String),
    #[error("cap expired at {expires_at} (now={now})")]
    Expired { expires_at: u64, now: u64 },
    #[error("cap issued in the future at {issued_at} (now={now})")]
    Future { issued_at: u64, now: u64 },
    #[error("cap op {got:?} does not match endpoint {expected:?}")]
    OpMismatch { expected: CapOp, got: CapOp },
    #[error("cap data_class {got:?} does not match endpoint {expected:?}")]
    DataClassMismatch { expected: DataClass, got: DataClass },
    #[error("chain RPC error: {0}")]
    ChainRpc(String),
    #[error("requested service not in agent's on-chain scope")]
    NotInScope,
    #[error("device not registered or revoked")]
    DeviceInactive,
    #[error("device binding mismatch on {field}")]
    DeviceMismatch { field: &'static str },
    #[error("device lacks CAP_MINT role (got 0x{got:02x})")]
    DeviceRoleMissing { got: u8 },
    #[error("K3 epoch mismatch (expected {expected}, got {got})")]
    K3Mismatch { expected: u64, got: u64 },
}

pub fn verify_signature(
    pubkey_pem: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let canonical = serde_json::to_vec(&token.payload)
        .map_err(|e| VerifyError::Encode(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&canonical);
    let digest = h.finalize();
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&token.broker_sig)
        .map_err(|e| VerifyError::SigDecode(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| VerifyError::SigParse(e.to_string()))?;
    let vk = parse_p256_pubkey_pem(pubkey_pem)?;
    vk.verify(&digest, &sig).map_err(|_| VerifyError::SigInvalid)
}

pub fn check_op(token: &CapToken, expected: CapOp) -> Result<(), VerifyError> {
    if token.payload.op != expected {
        return Err(VerifyError::OpMismatch { expected, got: token.payload.op });
    }
    Ok(())
}

/// Per-data-class isolation check (issue #90 followup). Workers reject
/// caps whose data_class doesn't match the URL's bucket — a cred-store
/// cap MUST NOT be honored at /v1/memory/put, even though both endpoints
/// expect the same CapOp::Store. The data_class binding is signed into
/// the cap payload by the broker, so it cannot be forged downstream.
pub fn check_data_class(
    token: &CapToken,
    expected: DataClass,
) -> Result<(), VerifyError> {
    if token.payload.data_class != expected {
        return Err(VerifyError::DataClassMismatch {
            expected,
            got: token.payload.data_class,
        });
    }
    Ok(())
}

pub fn check_freshness(token: &CapToken) -> Result<(), VerifyError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if token.payload.expires_at <= now {
        return Err(VerifyError::Expired {
            expires_at: token.payload.expires_at,
            now,
        });
    }
    // 60s slop to absorb clock skew between broker and worker.
    if token.payload.issued_at > now + 60 {
        return Err(VerifyError::Future {
            issued_at: token.payload.issued_at,
            now,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct OnChainDevice {
    pub operator_omni: String,
    pub actor_omni: String,
    pub roles: u8,
    pub registered_at: u64,
    pub revoked: bool,
}

pub async fn check_chain_device(
    http: &reqwest::Client,
    rpc_url: &str,
    registry: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let selector = function_selector("getDevice(bytes32)");
    let arg = pad32(&token.payload.device_key_hash)?;
    let data = format!("0x{selector}{arg}");
    let raw = eth_call(http, rpc_url, registry, &data).await?;
    let device = parse_device_entry(&raw)?;
    if device.registered_at == 0 || device.revoked {
        return Err(VerifyError::DeviceInactive);
    }
    let req_operator = strip_0x_lc(&token.payload.operator_omni);
    let req_actor = strip_0x_lc(&token.payload.actor_omni);
    if device.operator_omni != req_operator {
        return Err(VerifyError::DeviceMismatch { field: "operator_omni" });
    }
    if device.actor_omni != req_actor {
        return Err(VerifyError::DeviceMismatch { field: "actor_omni" });
    }
    if (device.roles & ROLE_CAP_MINT) == 0 {
        return Err(VerifyError::DeviceRoleMissing { got: device.roles });
    }
    Ok(())
}

pub async fn check_chain_scope(
    http: &reqwest::Client,
    rpc_url: &str,
    scope_contract: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let selector = function_selector("isServiceInScope(bytes32,bytes32,bytes32)");
    let a = pad32(&token.payload.operator_omni)?;
    let b = pad32(&token.payload.actor_omni)?;
    let service_hash = keccak_lc_service(&token.payload.service);
    let c = pad32(&service_hash)?;
    let data = format!("0x{selector}{a}{b}{c}");
    let raw = eth_call(http, rpc_url, scope_contract, &data).await?;
    if !parse_bool(&raw) {
        return Err(VerifyError::NotInScope);
    }
    Ok(())
}

pub async fn check_chain_k3_epoch(
    http: &reqwest::Client,
    rpc_url: &str,
    epoch_contract: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let selector = function_selector("currentEpoch()");
    let data = format!("0x{selector}");
    let raw = eth_call(http, rpc_url, epoch_contract, &data).await?;
    let on_chain = parse_u64(&raw)?;
    if on_chain != token.payload.k3_epoch {
        return Err(VerifyError::K3Mismatch {
            expected: on_chain,
            got: token.payload.k3_epoch,
        });
    }
    Ok(())
}

async fn eth_call(
    http: &reqwest::Client,
    rpc_url: &str,
    to: &str,
    data: &str,
) -> Result<String, VerifyError> {
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
        .map_err(|e| VerifyError::ChainRpc(format!("eth_call POST: {e}")))?;
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VerifyError::ChainRpc(format!("eth_call json: {e}")))?;
    if let Some(err) = v.get("error") {
        return Err(VerifyError::ChainRpc(format!("rpc error: {err}")));
    }
    v.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| VerifyError::ChainRpc("missing 'result'".into()))
}

fn parse_device_entry(raw: &str) -> Result<OnChainDevice, VerifyError> {
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
        return Err(VerifyError::ChainRpc(format!(
            "getDevice returned {} bytes; expected ≥ 11×32 (post codex H1 struct)",
            hex.len() / 2
        )));
    }
    let operator_omni = hex[0..64].to_lowercase();
    let actor_omni = hex[64..128].to_lowercase();
    let roles = u8::from_str_radix(&hex[(7 * 64 + 62)..(7 * 64 + 64)], 16).unwrap_or(0);
    let registered_at = u64::from_str_radix(&hex[(8 * 64 + 48)..(8 * 64 + 64)], 16).unwrap_or(0);
    let revoked = hex[10 * 64..11 * 64].trim_start_matches('0').ends_with('1');
    Ok(OnChainDevice {
        operator_omni,
        actor_omni,
        roles,
        registered_at,
        revoked,
    })
}

fn parse_bool(raw: &str) -> bool {
    raw.trim_start_matches("0x")
        .trim_start_matches('0')
        .ends_with('1')
}

fn parse_u64(raw: &str) -> Result<u64, VerifyError> {
    let stripped = raw.trim_start_matches("0x");
    u64::from_str_radix(stripped, 16)
        .map_err(|e| VerifyError::ChainRpc(format!("u64 parse: {e}")))
}

fn parse_p256_pubkey_pem(pem: &str) -> Result<VerifyingKey, VerifyError> {
    use p256::pkcs8::DecodePublicKey;
    let pk = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| VerifyError::BrokerKey(e.to_string()))?;
    Ok(VerifyingKey::from(pk))
}

fn function_selector(sig: &str) -> String {
    let mut h = sha3::Keccak256::new();
    h.update(sig.as_bytes());
    let d = h.finalize();
    hex::encode(&d[..4])
}

fn keccak_lc_service(name: &str) -> String {
    let mut h = sha3::Keccak256::new();
    h.update(name.to_lowercase().as_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}

fn pad32(s: &str) -> Result<String, VerifyError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(VerifyError::ChainRpc(format!(
            "expected 64-hex (32 bytes), got {} chars",
            stripped.len()
        )));
    }
    Ok(stripped.to_lowercase())
}

fn strip_0x_lc(s: &str) -> String {
    s.strip_prefix("0x").unwrap_or(s).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token(op: CapOp) -> CapToken {
        sample_token_with_class(op, DataClass::Credentials)
    }

    fn sample_token_with_class(op: CapOp, data_class: DataClass) -> CapToken {
        CapToken {
            payload: CapPayload {
                operator_omni: format!("0x{}", "a".repeat(64)),
                actor_omni: format!("0x{}", "b".repeat(64)),
                service: "openrouter".into(),
                op,
                data_class,
                device_key_hash: format!("0x{}", "c".repeat(64)),
                k3_epoch: 1,
                issued_at: 1,
                expires_at: u64::MAX,
                nonce: "00".repeat(16),
            },
            broker_sig: "x".into(),
        }
    }

    #[test]
    fn data_class_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&DataClass::Credentials).unwrap(),
            "\"credentials\""
        );
        assert_eq!(
            serde_json::to_string(&DataClass::Memory).unwrap(),
            "\"memory\""
        );
    }

    #[test]
    fn check_data_class_accepts_match() {
        let t = sample_token_with_class(CapOp::Store, DataClass::Credentials);
        assert!(check_data_class(&t, DataClass::Credentials).is_ok());
    }

    #[test]
    fn check_data_class_rejects_cross_class() {
        // Cred-class cap submitted to memory worker (expected = Memory).
        let cred_cap = sample_token_with_class(CapOp::Store, DataClass::Credentials);
        match check_data_class(&cred_cap, DataClass::Memory) {
            Err(VerifyError::DataClassMismatch { expected, got }) => {
                assert_eq!(expected, DataClass::Memory);
                assert_eq!(got, DataClass::Credentials);
            }
            other => panic!("expected DataClassMismatch, got {:?}", other),
        }
        // Memory-class cap submitted to cred worker (expected = Credentials).
        let mem_cap = sample_token_with_class(CapOp::Store, DataClass::Memory);
        match check_data_class(&mem_cap, DataClass::Credentials) {
            Err(VerifyError::DataClassMismatch { expected, got }) => {
                assert_eq!(expected, DataClass::Credentials);
                assert_eq!(got, DataClass::Memory);
            }
            other => panic!("expected DataClassMismatch, got {:?}", other),
        }
    }

    #[test]
    fn cap_op_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&CapOp::Store).unwrap(), "\"store\"");
        assert_eq!(serde_json::to_string(&CapOp::Fetch).unwrap(), "\"fetch\"");
        assert_eq!(serde_json::to_string(&CapOp::Teardown).unwrap(), "\"teardown\"");
    }

    #[test]
    fn function_selector_matches_known_signatures() {
        assert_eq!(function_selector("isServiceInScope(bytes32,bytes32,bytes32)"), "13337240");
        assert_eq!(function_selector("currentEpoch()"), "76671808");
    }

    #[test]
    fn keccak_service_lowercases() {
        assert_eq!(keccak_lc_service("OpenRouter"), keccak_lc_service("openrouter"));
    }

    #[test]
    fn pad32_accepts_with_or_without_0x() {
        assert_eq!(pad32(&format!("0x{}", "a".repeat(64))).unwrap(), "a".repeat(64));
        assert_eq!(pad32(&"b".repeat(64)).unwrap(), "b".repeat(64));
    }

    #[test]
    fn pad32_rejects_short() {
        assert!(pad32("0x123").is_err());
    }

    #[test]
    fn check_freshness_rejects_past() {
        let mut t = sample_token(CapOp::Fetch);
        t.payload.expires_at = 1;
        assert!(matches!(check_freshness(&t), Err(VerifyError::Expired { .. })));
    }

    #[test]
    fn check_freshness_rejects_future() {
        let mut t = sample_token(CapOp::Fetch);
        t.payload.issued_at = u64::MAX / 2; // well past now+60s
        t.payload.expires_at = u64::MAX;
        assert!(matches!(check_freshness(&t), Err(VerifyError::Future { .. })));
    }

    #[test]
    fn check_op_rejects_mismatch() {
        let t = sample_token(CapOp::Store);
        assert!(matches!(
            check_op(&t, CapOp::Fetch),
            Err(VerifyError::OpMismatch { expected: CapOp::Fetch, got: CapOp::Store })
        ));
    }

    #[test]
    fn check_op_accepts_match() {
        let t = sample_token(CapOp::Store);
        assert!(check_op(&t, CapOp::Store).is_ok());
    }

    #[test]
    fn parse_device_entry_decodes_well_formed() {
        // 11-word post-codex-H1 DeviceEntry layout:
        //  word 0 operatorOmni  → "aaaa…" (64 hex)
        //  word 1 actorOmni     → "bbbb…"
        //  word 2 k11CredId     → 0
        //  word 3 k11RpIdHash   → 0 (codex H1)
        //  word 4 k11PubX       → 0 (codex H1)
        //  word 5 k11PubY       → 0 (codex H1)
        //  word 6 tier          → 1
        //  word 7 roles         → 7
        //  word 8 registeredAt  → 42
        //  word 9 lastSignCount → 0
        //  word 10 revoked      → 0
        let mut raw = String::from("0x");
        raw.push_str(&"a".repeat(64));                       // operator
        raw.push_str(&"b".repeat(64));                       // actor
        raw.push_str(&"0".repeat(64));                       // k11CredId
        raw.push_str(&"0".repeat(64));                       // k11RpIdHash
        raw.push_str(&"0".repeat(64));                       // k11PubX
        raw.push_str(&"0".repeat(64));                       // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64));            // tier
        raw.push_str(&format!("{:0>64x}", 7u64));            // roles
        raw.push_str(&format!("{:0>64x}", 42u64));           // registeredAt
        raw.push_str(&"0".repeat(64));                       // lastSignCount
        raw.push_str(&"0".repeat(64));                       // revoked
        let d = parse_device_entry(&raw).unwrap();
        assert_eq!(d.operator_omni, "a".repeat(64));
        assert_eq!(d.actor_omni, "b".repeat(64));
        assert_eq!(d.roles, 7);
        assert_eq!(d.registered_at, 42);
        assert!(!d.revoked);
    }

    #[test]
    fn sign_then_verify_roundtrip_with_test_keypair() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        use p256::pkcs8::EncodePublicKey;

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verify_key = signing_key.verifying_key();
        let pubkey_pem = p256::PublicKey::from(*verify_key)
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();

        let payload = sample_token(CapOp::Store).payload;
        let canonical = serde_json::to_vec(&payload).unwrap();
        let mut h = Sha256::new();
        h.update(&canonical);
        let sig: p256::ecdsa::Signature = signing_key.sign(&h.finalize());
        let token = CapToken {
            payload,
            broker_sig: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };

        verify_signature(&pubkey_pem, &token).unwrap();
        let mut bad = token.clone();
        bad.payload.service = "different".into();
        assert!(matches!(
            verify_signature(&pubkey_pem, &bad),
            Err(VerifyError::SigInvalid)
        ));
    }
}
