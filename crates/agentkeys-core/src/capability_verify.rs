//! Independent signature, actor-proof and chain authorization checks.

use agentkeys_protocol::DelegationPath;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use agentkeys_protocol::capability::{CapOp, CapPayload, CapToken, DataClass};

pub const ROLE_CAP_MINT: u8 = 1;

#[derive(Clone)]
pub struct AuthorityConfig {
    pub broker_public_key: String,
    pub rpc_url: String,
    pub registry: String,
    pub scope: String,
    pub epoch: String,
}

impl AuthorityConfig {
    pub fn from_profile(
        profile: &crate::chain_profile::ChainProfile,
        broker_public_key: String,
    ) -> anyhow::Result<Self> {
        use anyhow::Context;
        validate_broker_public_key(&broker_public_key)?;
        let contract = |name| {
            profile
                .contract(name)
                .map(|item| item.address.clone())
                .with_context(|| format!("profile is missing {name}"))
        };
        Ok(Self {
            broker_public_key,
            rpc_url: profile.rpc.http.clone(),
            registry: contract("SidecarRegistry")?,
            scope: contract("AgentKeysScope")?,
            epoch: contract("K3EpochCounter")?,
        })
    }
}

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
    #[error(
        "capability service is never cap-mintable (tool:/plugin: grants are runtime-guard grants, no worker owns them — #614)"
    )]
    CapabilityService,
    #[error("device not registered or revoked")]
    DeviceInactive,
    #[error("device binding mismatch on {field}")]
    DeviceMismatch { field: &'static str },
    #[error("device lacks CAP_MINT role (got 0x{got:02x})")]
    DeviceRoleMissing { got: u8 },
    #[error("K3 epoch mismatch (expected {expected}, got {got})")]
    K3Mismatch { expected: u64, got: u64 },
    #[error("cap K10 proof-of-possession missing (no client_sig) — broker-only caps are rejected")]
    CapPopMissing,
    #[error("cap K10 proof-of-possession invalid: {0}")]
    CapPopInvalid(String),
    #[error("cap K10 proof-of-possession stale (client_ts {client_ts}, now {now})")]
    CapPopStale { client_ts: u64, now: u64 },
    #[error("cap K10 proof-of-possession does not match device_key_hash")]
    CapPopMismatch,
    #[error("delegation expired at {expires_at} (now={now})")]
    DelegationExpired { expires_at: u64, now: u64 },
    #[error("cap (service {service}, data_class {data_class}, op {op}) outside delegation scope {scope:?}")]
    DelegationOutOfScope {
        scope: String,
        data_class: String,
        op: String,
        service: String,
    },
    #[error("delegation signature invalid: {0}")]
    DelegationInvalid(String),
}

pub fn validate_broker_public_key(pem: &str) -> Result<(), VerifyError> {
    parse_p256_pubkey_pem(pem).map(|_| ())
}

pub fn verify_signature(pubkey_pem: &str, token: &CapToken) -> Result<(), VerifyError> {
    let canonical =
        serde_json::to_vec(&token.payload).map_err(|e| VerifyError::Encode(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&canonical);
    let digest = h.finalize();
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&token.broker_sig)
        .map_err(|e| VerifyError::SigDecode(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| VerifyError::SigParse(e.to_string()))?;
    let vk = parse_p256_pubkey_pem(pubkey_pem)?;
    vk.verify(&digest, &sig)
        .map_err(|_| VerifyError::SigInvalid)
}

pub fn check_op(token: &CapToken, expected: CapOp) -> Result<(), VerifyError> {
    if token.payload.op != expected {
        return Err(VerifyError::OpMismatch {
            expected,
            got: token.payload.op,
        });
    }
    Ok(())
}

pub fn check_data_class(token: &CapToken, expected: DataClass) -> Result<(), VerifyError> {
    if agentkeys_protocol::is_capability_service(&token.payload.service) {
        return Err(VerifyError::CapabilityService);
    }
    if token.payload.data_class != expected {
        return Err(VerifyError::DataClassMismatch {
            expected,
            got: token.payload.data_class,
        });
    }
    Ok(())
}

pub const CAP_POP_MAX_AGE_SECS: u64 = 300;

pub fn enforce_client_pop(token: &CapToken) -> Result<(), VerifyError> {
    check_client_pop(token, CAP_POP_MAX_AGE_SECS)
}

pub fn check_client_pop(token: &CapToken, max_age_secs: u64) -> Result<(), VerifyError> {
    let client_sig = token
        .client_sig
        .as_deref()
        .ok_or(VerifyError::CapPopMissing)?;
    let client_nonce = token
        .client_nonce
        .as_deref()
        .ok_or(VerifyError::CapPopMissing)?;
    let client_ts = token.client_ts.ok_or(VerifyError::CapPopMissing)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if client_ts > now + 60 || now.saturating_sub(client_ts) > max_age_secs {
        return Err(VerifyError::CapPopStale { client_ts, now });
    }

    let preimage = crate::device_crypto::cap_pop_payload(
        &token.payload.operator_omni,
        &token.payload.actor_omni,
        &token.payload.service,
        token.payload.op.as_str(),
        token.payload.data_class.as_str(),
        client_nonce,
        client_ts,
    );
    let recovered = crate::device_crypto::ecrecover_eip191(&preimage, client_sig)
        .map_err(|e| VerifyError::CapPopInvalid(e.to_string()))?;
    let recovered_hash = crate::device_crypto::device_key_hash(&recovered)
        .map_err(|e| VerifyError::CapPopInvalid(e.to_string()))?;
    if strip_0x_lc(&recovered_hash) == strip_0x_lc(&token.payload.device_key_hash) {
        return Ok(());
    }
    if let Some(deleg) = &token.delegation_path {
        return check_delegation(token, &recovered, deleg, now);
    }
    Err(VerifyError::CapPopMismatch)
}

fn check_delegation(
    token: &CapToken,
    sandbox_key: &str,
    deleg: &DelegationPath,
    now: u64,
) -> Result<(), VerifyError> {
    if deleg.expires_at <= now {
        return Err(VerifyError::DelegationExpired {
            expires_at: deleg.expires_at,
            now,
        });
    }
    let data_class = token.payload.data_class.as_str();
    let op = token.payload.op.as_str();
    let service = token.payload.service.as_str();
    if !crate::device_crypto::cap_in_scope(&deleg.scope, data_class, op, service) {
        return Err(VerifyError::DelegationOutOfScope {
            scope: deleg.scope.clone(),
            data_class: data_class.to_string(),
            op: op.to_string(),
            service: service.to_string(),
        });
    }
    crate::device_crypto::verify_delegation(
        &token.payload.device_key_hash,
        sandbox_key,
        &deleg.scope,
        deleg.expires_at,
        &deleg.delegation_sig,
    )
    .map_err(|e| VerifyError::DelegationInvalid(e.to_string()))?;
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

pub async fn get_chain_device(
    http: &reqwest::Client,
    rpc_url: &str,
    registry: &str,
    device_key_hash: &str,
) -> Result<OnChainDevice, VerifyError> {
    let selector = function_selector("getDevice(bytes32)");
    let arg = pad32(device_key_hash)?;
    let data = format!("0x{selector}{arg}");
    let raw = eth_call(http, rpc_url, registry, &data).await?;
    parse_device_entry(&raw)
}

pub async fn check_chain_device(
    http: &reqwest::Client,
    rpc_url: &str,
    registry: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let device = get_chain_device(http, rpc_url, registry, &token.payload.device_key_hash).await?;
    if device.registered_at == 0 || device.revoked {
        return Err(VerifyError::DeviceInactive);
    }
    let req_operator = strip_0x_lc(&token.payload.operator_omni);
    let req_actor = strip_0x_lc(&token.payload.actor_omni);
    if device.operator_omni != req_operator {
        return Err(VerifyError::DeviceMismatch {
            field: "operator_omni",
        });
    }
    if device.actor_omni != req_actor {
        return Err(VerifyError::DeviceMismatch {
            field: "actor_omni",
        });
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
    if a == b {
        return Ok(());
    }
    let service_hash = keccak_lc_service(&token.payload.service);
    let c = pad32(&service_hash)?;
    let data = format!("0x{selector}{a}{b}{c}");
    let raw = eth_call(http, rpc_url, scope_contract, &data).await?;
    if !parse_bool(&raw)? {
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

pub const ETH_CALL_ATTEMPT_TIMEOUT_SECS: u64 = 10;

pub async fn eth_call(
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
    const ATTEMPTS: u32 = 5;
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            let ms = 150u64 * (1u64 << (attempt - 1)); // 150, 300, 600 ms
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        let resp = match http
            .post(rpc_url)
            .timeout(std::time::Duration::from_secs(
                ETH_CALL_ATTEMPT_TIMEOUT_SECS,
            ))
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last = format!("eth_call POST: {e}");
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
                last = format!("eth_call json: {e}");
                continue;
            }
        };
        if let Some(err) = v.get("error") {
            if is_rate_limit_error(err) {
                last = format!("eth_call rate-limited: {err}");
                continue;
            }
            return Err(VerifyError::ChainRpc(format!("rpc error: {err}")));
        }
        return v
            .get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VerifyError::ChainRpc("missing 'result'".into()));
    }
    Err(VerifyError::ChainRpc(format!(
        "eth_call failed after {ATTEMPTS} attempts: {last}"
    )))
}

fn is_rate_limit_error(err: &serde_json::Value) -> bool {
    if matches!(
        err.get("code").and_then(|c| c.as_i64()),
        Some(-32016) | Some(-32005) | Some(-32029)
    ) {
        return true;
    }
    err.get("message")
        .and_then(|m| m.as_str())
        .map(|m| m.to_lowercase())
        .map(|m| {
            m.contains("rate limit")
                || m.contains("too many requests")
                || m.contains("limit exceeded")
        })
        .unwrap_or(false)
}

fn parse_device_entry(raw: &str) -> Result<OnChainDevice, VerifyError> {
    let record = crate::registry::parse_device_probe(raw)
        .map_err(|error| VerifyError::ChainRpc(error.to_string()))?;
    Ok(OnChainDevice {
        operator_omni: hex::encode(record.operator_omni),
        actor_omni: hex::encode(record.actor_omni),
        roles: record.roles,
        registered_at: record.registered_at,
        revoked: record.revoked,
    })
}

fn parse_bool(raw: &str) -> Result<bool, VerifyError> {
    crate::registry::parse_bool(raw).map_err(|error| VerifyError::ChainRpc(error.to_string()))
}

fn parse_u64(raw: &str) -> Result<u64, VerifyError> {
    crate::registry::parse_u64(raw).map_err(|error| VerifyError::ChainRpc(error.to_string()))
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
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    #[test]
    fn missing_actor_proof_is_rejected_without_a_rollout_flag() {
        assert!(matches!(
            enforce_client_pop(&sample_token(CapOp::Fetch)),
            Err(VerifyError::CapPopMissing)
        ));
    }

    #[tokio::test]
    async fn check_chain_scope_skips_when_operator_is_actor() {
        let mut token = sample_token(CapOp::Fetch);
        token.payload.actor_omni = token.payload.operator_omni.clone();
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, "http://127.0.0.1:1", "0xscope", &token).await;
        assert!(r.is_ok(), "operator==actor must skip scope (got {r:?})");
    }

    #[tokio::test]
    async fn check_chain_scope_consults_chain_when_operator_differs() {
        let token = sample_token(CapOp::Fetch); // operator 0xaa…, actor 0xbb…
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, "http://127.0.0.1:1", "0xscope", &token).await;
        assert!(r.is_err(), "operator!=actor must still consult the chain");
    }

    fn spawn_mock_rpc(result_hex: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let Ok(mut s) = stream else { return };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf); // drain the request; we don't parse it
                let json = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{result_hex}\"}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn check_chain_scope_ok_when_chain_grants() {
        let url =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000001");
        let token = sample_token(CapOp::Fetch); // operator 0xaa…, actor 0xbb… (distinct)
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, &url, "0xscope", &token).await;
        assert!(r.is_ok(), "granted cross-actor scope must pass (got {r:?})");
    }

    #[tokio::test]
    async fn check_chain_scope_rejects_when_chain_denies() {
        let url =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000000");
        let token = sample_token(CapOp::Fetch);
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, &url, "0xscope", &token).await;
        assert!(
            matches!(r, Err(VerifyError::NotInScope)),
            "ungranted cross-actor scope must be NotInScope (got {r:?})"
        );
    }

    #[tokio::test]
    async fn malformed_scope_response_is_a_chain_error() {
        let url =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000011");
        let result = check_chain_scope(
            &reqwest::Client::new(),
            &url,
            "0xscope",
            &sample_token(CapOp::Fetch),
        )
        .await;
        assert!(matches!(result, Err(VerifyError::ChainRpc(_))));
    }

    #[tokio::test]
    async fn epoch_requires_a_canonical_value_and_current_authority() {
        let client = reqwest::Client::new();
        let token = sample_token(CapOp::Fetch);
        let valid =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000001");
        assert!(check_chain_k3_epoch(&client, &valid, "0xepoch", &token)
            .await
            .is_ok());
        let rotated =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000002");
        assert!(matches!(
            check_chain_k3_epoch(&client, &rotated, "0xepoch", &token).await,
            Err(VerifyError::K3Mismatch {
                expected: 2,
                got: 1
            })
        ));
        let malformed = spawn_mock_rpc("0x1");
        assert!(matches!(
            check_chain_k3_epoch(&client, &malformed, "0xepoch", &token).await,
            Err(VerifyError::ChainRpc(_))
        ));
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
        assert_eq!(
            serde_json::to_string(&DataClass::Config).unwrap(),
            "\"config\""
        );
        assert_eq!(
            serde_json::to_string(&DataClass::Channel).unwrap(),
            "\"channel\""
        );
    }

    #[test]
    fn check_data_class_rejects_config_at_cred_and_memory() {
        let config_cap = sample_token_with_class(CapOp::Store, DataClass::Config);
        for expected in [DataClass::Credentials, DataClass::Memory] {
            match check_data_class(&config_cap, expected) {
                Err(VerifyError::DataClassMismatch { got, .. }) => {
                    assert_eq!(got, DataClass::Config);
                }
                other => panic!("expected DataClassMismatch for {expected:?}, got {other:?}"),
            }
        }
        let mem_cap = sample_token_with_class(CapOp::Store, DataClass::Memory);
        assert!(matches!(
            check_data_class(&mem_cap, DataClass::Config),
            Err(VerifyError::DataClassMismatch { .. })
        ));
    }

    #[test]
    fn check_data_class_accepts_match() {
        let t = sample_token_with_class(CapOp::Store, DataClass::Credentials);
        assert!(check_data_class(&t, DataClass::Credentials).is_ok());
    }

    #[test]
    fn check_data_class_rejects_cross_class() {
        let cred_cap = sample_token_with_class(CapOp::Store, DataClass::Credentials);
        match check_data_class(&cred_cap, DataClass::Memory) {
            Err(VerifyError::DataClassMismatch { expected, got }) => {
                assert_eq!(expected, DataClass::Memory);
                assert_eq!(got, DataClass::Credentials);
            }
            other => panic!("expected DataClassMismatch, got {:?}", other),
        }
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
        assert_eq!(
            serde_json::to_string(&CapOp::CanonicalFetch).unwrap(),
            "\"canonical_fetch\""
        );
        assert_eq!(CapOp::CanonicalFetch.as_str(), "canonical_fetch");
        assert_eq!(serde_json::to_string(&CapOp::Append).unwrap(), "\"append\"");
        assert_eq!(CapOp::Append.as_str(), "append");
        assert_eq!(
            serde_json::to_string(&CapOp::Teardown).unwrap(),
            "\"teardown\""
        );
    }

    #[test]
    fn function_selector_matches_known_signatures() {
        assert_eq!(
            function_selector("isServiceInScope(bytes32,bytes32,bytes32)"),
            "13337240"
        );
        assert_eq!(function_selector("currentEpoch()"), "76671808");
    }

    #[test]
    fn keccak_service_lowercases() {
        assert_eq!(
            keccak_lc_service("OpenRouter"),
            keccak_lc_service("openrouter")
        );
    }

    #[test]
    fn capability_service_caps_are_rejected_at_every_worker() {
        let mut token = sample_token_with_class(CapOp::Fetch, DataClass::Memory);
        token.payload.service = "tool:web".into();
        match check_data_class(&token, DataClass::Memory) {
            Err(VerifyError::CapabilityService) => {}
            other => panic!("expected CapabilityService, got {other:?}"),
        }
        token.payload.service = "PLUGIN:openviking".into();
        assert!(matches!(
            check_data_class(&token, DataClass::Memory),
            Err(VerifyError::CapabilityService)
        ));
        token.payload.service = "knowledge:travel".into();
        assert!(check_data_class(&token, DataClass::Memory).is_ok());
    }

    #[test]
    fn pad32_accepts_with_or_without_0x() {
        assert_eq!(
            pad32(&format!("0x{}", "a".repeat(64))).unwrap(),
            "a".repeat(64)
        );
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
        assert!(matches!(
            check_freshness(&t),
            Err(VerifyError::Expired { .. })
        ));
    }

    #[test]
    fn check_freshness_rejects_future() {
        let mut t = sample_token(CapOp::Fetch);
        t.payload.issued_at = u64::MAX / 2; // well past now+60s
        t.payload.expires_at = u64::MAX;
        assert!(matches!(
            check_freshness(&t),
            Err(VerifyError::Future { .. })
        ));
    }

    #[test]
    fn check_op_rejects_mismatch() {
        let t = sample_token(CapOp::Store);
        assert!(matches!(
            check_op(&t, CapOp::Fetch),
            Err(VerifyError::OpMismatch {
                expected: CapOp::Fetch,
                got: CapOp::Store
            })
        ));
    }

    #[test]
    fn check_op_accepts_match() {
        let t = sample_token(CapOp::Store);
        assert!(check_op(&t, CapOp::Store).is_ok());
    }

    #[test]
    fn malformed_registry_revocation_is_not_an_active_device() {
        let mut words = vec![0; 11 * 32];
        words[8 * 32 + 31] = 1;
        assert!(!parse_device_entry(&hex::encode(&words)).unwrap().revoked);
        words[10 * 32 + 31] = 2;
        assert!(parse_device_entry(&hex::encode(&words)).is_err());
    }

    #[test]
    fn parse_device_entry_decodes_well_formed() {
        let mut raw = String::from("0x");
        raw.push_str(&"a".repeat(64)); // operator
        raw.push_str(&"b".repeat(64)); // actor
        raw.push_str(&"0".repeat(64)); // k11CredId
        raw.push_str(&"0".repeat(64)); // k11RpIdHash
        raw.push_str(&"0".repeat(64)); // k11PubX
        raw.push_str(&"0".repeat(64)); // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64)); // tier
        raw.push_str(&format!("{:0>64x}", 7u64)); // roles
        raw.push_str(&format!("{:0>64x}", 42u64)); // registeredAt
        raw.push_str(&"0".repeat(64)); // lastSignCount
        raw.push_str(&"0".repeat(64)); // revoked
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
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        };

        verify_signature(&pubkey_pem, &token).unwrap();
        let mut bad = token.clone();
        bad.payload.service = "different".into();
        assert!(matches!(
            verify_signature(&pubkey_pem, &bad),
            Err(VerifyError::SigInvalid)
        ));
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_pop_into(token: &mut CapToken, dk: &crate::device_crypto::DeviceKey, ts: u64) {
        let nonce = "0011223344556677".to_string();
        let sig = dk
            .cap_pop_sig(
                &token.payload.operator_omni,
                &token.payload.actor_omni,
                &token.payload.service,
                token.payload.op.as_str(),
                token.payload.data_class.as_str(),
                &nonce,
                ts,
            )
            .unwrap();
        token.payload.device_key_hash = dk.device_key_hash().unwrap();
        token.client_sig = Some(sig);
        token.client_nonce = Some(nonce);
        token.client_ts = Some(ts);
    }

    fn fresh_device(name: &str) -> crate::device_crypto::DeviceKey {
        let directory = tempfile::tempdir().unwrap();
        crate::device_crypto::DeviceKey::load_or_generate(
            directory.path().join(name).to_str().unwrap(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn check_client_pop_accepts_valid() {
        let dk = fresh_device("ak-verify-pop-ok.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        sign_pop_into(&mut token, &dk, now_secs());
        assert!(enforce_client_pop(&token).is_ok());
    }

    #[test]
    fn check_client_pop_rejects_missing() {
        let token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::CapPopMissing)
        ));
    }

    #[test]
    fn check_client_pop_rejects_forged_from_other_key() {
        let dk = fresh_device("ak-verify-pop-real.key");
        let other = fresh_device("ak-verify-pop-other.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        sign_pop_into(&mut token, &dk, now_secs()); // sets the real device_key_hash
        let nonce = token.client_nonce.clone().unwrap();
        token.client_sig = Some(
            other
                .cap_pop_sig(
                    &token.payload.operator_omni,
                    &token.payload.actor_omni,
                    &token.payload.service,
                    token.payload.op.as_str(),
                    token.payload.data_class.as_str(),
                    &nonce,
                    token.client_ts.unwrap(),
                )
                .unwrap(),
        );
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::CapPopMismatch)
        ));
    }

    #[test]
    fn check_client_pop_rejects_tampered_op() {
        let dk = fresh_device("ak-verify-pop-tamper.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        sign_pop_into(&mut token, &dk, now_secs());
        token.payload.op = CapOp::Fetch;
        assert!(enforce_client_pop(&token).is_err());
    }

    #[test]
    fn check_client_pop_rejects_stale() {
        let dk = fresh_device("ak-verify-pop-stale.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let stale = now_secs().saturating_sub(CAP_POP_MAX_AGE_SECS + 120);
        sign_pop_into(&mut token, &dk, stale);
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::CapPopStale { .. })
        ));
    }

    #[test]
    fn is_rate_limit_error_retries_throttles_not_reverts() {
        use serde_json::json;
        assert!(is_rate_limit_error(
            &json!({"code": -32016, "message": "over rate limit"})
        ));
        assert!(is_rate_limit_error(
            &json!({"code": -32005, "message": "limit exceeded"})
        ));
        assert!(is_rate_limit_error(&json!({"code": -32029})));
        assert!(is_rate_limit_error(
            &json!({"message": "Too Many Requests"})
        ));
        assert!(!is_rate_limit_error(
            &json!({"code": 3, "message": "execution reverted"})
        ));
        assert!(!is_rate_limit_error(
            &json!({"code": -32000, "message": "invalid opcode"})
        ));
    }

    fn sign_pop_as_sandbox(
        token: &mut CapToken,
        sandbox: &crate::device_crypto::DeviceKey,
        device_key_hash: &str,
        ts: u64,
    ) {
        let nonce = "0011223344556677".to_string();
        let sig = sandbox
            .cap_pop_sig(
                &token.payload.operator_omni,
                &token.payload.actor_omni,
                &token.payload.service,
                token.payload.op.as_str(),
                token.payload.data_class.as_str(),
                &nonce,
                ts,
            )
            .unwrap();
        token.payload.device_key_hash = device_key_hash.to_string();
        token.client_sig = Some(sig);
        token.client_nonce = Some(nonce);
        token.client_ts = Some(ts);
    }

    fn attach_delegation(
        token: &mut CapToken,
        signer: &crate::device_crypto::DeviceKey,
        sandbox_addr: &str,
        scope: &str,
        expires_at: u64,
    ) {
        let delegation_sig = signer
            .delegation_sig(sandbox_addr, scope, expires_at)
            .unwrap();
        token.delegation_path = Some(DelegationPath {
            scope: scope.to_string(),
            expires_at,
            delegation_sig,
        });
    }

    #[test]
    fn delegation_accepts_sandbox_cap_backed_by_device() {
        let device = fresh_device("ak-deleg-device.key");
        let sandbox = fresh_device("ak-deleg-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &device,
            sandbox.address(),
            "memory credentials",
            now_secs() + 3600,
        );
        assert!(enforce_client_pop(&token).is_ok());
    }

    #[test]
    fn delegation_rejects_expired() {
        let device = fresh_device("ak-deleg-exp-device.key");
        let sandbox = fresh_device("ak-deleg-exp-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &device,
            sandbox.address(),
            "memory",
            now_secs() - 10,
        );
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::DelegationExpired { .. })
        ));
    }

    #[test]
    fn delegation_rejects_out_of_scope() {
        let device = fresh_device("ak-deleg-scope-device.key");
        let sandbox = fresh_device("ak-deleg-scope-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &device,
            sandbox.address(),
            "credentials",
            now_secs() + 3600,
        );
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::DelegationOutOfScope { .. })
        ));
    }

    #[test]
    fn delegation_rejects_wrong_device() {
        let device = fresh_device("ak-deleg-wrong-device.key");
        let other = fresh_device("ak-deleg-wrong-other.key");
        let sandbox = fresh_device("ak-deleg-wrong-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &other,
            sandbox.address(),
            "memory",
            now_secs() + 3600,
        );
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::DelegationInvalid(_))
        ));
    }

    #[test]
    fn delegation_rejects_sandbox_self_delegation() {
        let device = fresh_device("ak-deleg-self-device.key");
        let sandbox = fresh_device("ak-deleg-self-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &sandbox,
            sandbox.address(),
            "memory",
            now_secs() + 3600,
        );
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::DelegationInvalid(_))
        ));
    }

    #[test]
    fn sandbox_cap_without_delegation_is_rejected() {
        let device = fresh_device("ak-deleg-none-device.key");
        let sandbox = fresh_device("ak-deleg-none-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        assert!(matches!(
            enforce_client_pop(&token),
            Err(VerifyError::CapPopMismatch)
        ));
    }

    #[test]
    fn delegation_scope_is_namespace_aware() {
        let device = fresh_device("ak-deleg-ns-device.key");
        let sandbox = fresh_device("ak-deleg-ns-sandbox.key");
        let dkh = device.device_key_hash().unwrap();

        let mut travel = sample_token_with_class(CapOp::CanonicalFetch, DataClass::Memory);
        travel.payload.service = "knowledge:travel".into();
        sign_pop_as_sandbox(&mut travel, &sandbox, &dkh, now_secs());

        let mut ok = travel.clone();
        attach_delegation(
            &mut ok,
            &device,
            sandbox.address(),
            "knowledge:travel knowledge:personal",
            now_secs() + 3600,
        );
        assert!(check_client_pop(&ok, CAP_POP_MAX_AGE_SECS).is_ok());

        let mut deny = travel.clone();
        attach_delegation(
            &mut deny,
            &device,
            sandbox.address(),
            "knowledge:personal knowledge:family",
            now_secs() + 3600,
        );
        assert!(matches!(
            check_client_pop(&deny, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::DelegationOutOfScope { .. })
        ));

        let mut wide = travel.clone();
        attach_delegation(
            &mut wide,
            &device,
            sandbox.address(),
            "memory",
            now_secs() + 3600,
        );
        assert!(check_client_pop(&wide, CAP_POP_MAX_AGE_SECS).is_ok());
    }
}
