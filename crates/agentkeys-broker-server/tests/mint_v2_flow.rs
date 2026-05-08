//! `/v1/mint-aws-creds` v2 path — Stage 7 issue#64 US-011 integration tests.
//!
//! Exercises the new wire shape: session JWT (Authorization) + JSON body
//! with per-call daemon signature. Audit row written through the
//! AuditAnchor trait, NOT only the legacy log. Wallet-binding match
//! (auth.address must equal JWT-bound wallet) is enforced.

use std::collections::HashMap;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    config::BrokerConfig,
    create_router,
    jwt::{issue::mint_session_jwt, SessionKeypair},
    oidc::OidcKeypair,
    plugins::{
        audit::{sqlite::SqliteAnchor, AuditAnchor, AuditPolicy},
        wallet::keystore::ClientSideKeystoreProvisioner,
        PluginRegistry,
    },
    state::{AppState, Tier2State},
    storage::{AuthNonceStore, GrantStore, IdempotencyStore, IdentityLinkStore, WalletStore},
    sts::{AssumedCredentials, StsClient, StubStsClient},
};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tempfile::TempDir;

const TEST_ISSUER: &str = "https://broker.test.invalid";
const STUB_ROLE_ARN: &str = "arn:aws:iam::000000000000:role/agentkeys-data-role";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-V2".into(),
        secret_access_key: "v2-secret".into(),
        session_token: "v2-session".into(),
        expiration_unix: 9_999_999_999,
    }
}

/// Spawn an in-process broker with a real session keypair, real SQLite
/// audit anchor, and a stub STS. Mark Tier-2 backend reachable directly
/// so /readyz is green during the test (the legacy mint tests do the
/// same).
async fn spawn_broker() -> (
    String,
    Arc<AppState>,
    SessionKeypair,
    String, // session_jwt for fixture wallet
    SigningKey, // matching signing key
) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let oidc_path = tmp.path().join("oidc-keypair.json");
    let session_path = tmp.path().join("session-keypair.json");
    let oidc = OidcKeypair::generate_and_persist(&oidc_path).unwrap();
    let session_kp = SessionKeypair::generate_and_persist(&session_path).unwrap();

    let signing_key = SigningKey::random(&mut agentkeys_broker_server::oidc::rand_compat::OsRngWrapper);
    let wallet_addr = address_from_signing_key(&signing_key);

    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));
    let config = BrokerConfig {
        data_role_arn: STUB_ROLE_ARN.into(),
        backend_url: "http://127.0.0.1:1".into(), // unused on v2 path
        audit_db_path: tmp.path().join("audit.sqlite"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        backend_request_timeout_seconds: 5,
        shutdown_grace_seconds: 5,
        oidc_issuer: TEST_ISSUER.into(),
        oidc_keypair_path: oidc_path,
        oidc_jwt_ttl_seconds: 300,
    };

    let nonce_store = Arc::new(AuthNonceStore::open_in_memory().unwrap());
    let wallet_store = Arc::new(WalletStore::open_in_memory().unwrap());
    let sqlite_anchor: Arc<dyn AuditAnchor> = Arc::new(SqliteAnchor::open_in_memory().unwrap());
    let registry = Arc::new(PluginRegistry {
        auth: HashMap::new(),
        wallet: Arc::new(ClientSideKeystoreProvisioner::new(Arc::clone(&wallet_store))),
        audit: vec![Arc::clone(&sqlite_anchor)],
    });

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();

    let state = Arc::new(AppState {
        config,
        http,
        audit: AuditLog::open_in_memory().unwrap(),
        sts,
        oidc: Arc::new(oidc),
        session_keypair: Arc::new(SessionKeypair::generate_and_persist(&tmp.path().join("session2.json")).unwrap()),
        registry,
        audit_policy: AuditPolicy::DualStrict,
        wallet_store,
        nonce_store,
        grant_store: Arc::new(GrantStore::open_in_memory().unwrap()),
        identity_link_store: Arc::new(IdentityLinkStore::open_in_memory().unwrap()),
        idempotency_store: Arc::new(IdempotencyStore::open_in_memory().unwrap()),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: Arc::new(Tier2State::default()),
        #[cfg(feature = "auth-email-link")]
        email_link: None,
        #[cfg(feature = "auth-oauth2")]
        oauth2: None,
    });
    state
        .tier2
        .backend_reachable
        .store(true, std::sync::atomic::Ordering::Relaxed);

    // The session keypair stored on AppState must match the one used to
    // mint the JWT — re-mint with the AppState keypair so verify works.
    let omni2 = agentkeys_broker_server::identity::derive_omni_account("evm", &wallet_addr);
    let jwt = mint_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        omni2.as_str(),
        &wallet_addr,
        "evm",
        &wallet_addr,
        300,
    )
    .unwrap();
    let _ = (session_kp,); // silence unused

    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let session_kp_copy = SessionKeypair::load(&tmp.path().join("session2.json")).unwrap();
    (
        format!("http://{}", addr),
        state,
        session_kp_copy,
        jwt,
        signing_key,
    )
}

fn address_from_signing_key(key: &SigningKey) -> String {
    let vkey = key.verifying_key();
    let pt = vkey.to_encoded_point(false);
    let mut h = Keccak256::new();
    h.update(&pt.as_bytes()[1..]);
    let pubkey_hash = h.finalize();
    format!("0x{}", hex::encode(&pubkey_hash[12..]))
}

/// Sign canonical-JSON-bytes with EIP-191 envelope; return 65-byte hex sig.
fn eip191_sign(key: &SigningKey, message: &[u8]) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message);
    let digest = h.finalize();
    let (sig, rid) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(rid.to_byte());
    format!("0x{}", hex::encode(&sig_bytes))
}

/// Build the canonical signing-input bytes (sorted-key JSON without
/// auth.signature) given a body-Value.
fn canonical_input(body: &Value) -> Vec<u8> {
    let mut stripped = body.clone();
    if let Some(auth) = stripped.get_mut("auth").and_then(Value::as_object_mut) {
        auth.remove("signature");
    }
    canonicalize(&stripped).into_bytes()
}

fn canonicalize(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonicalize(&map[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}

#[tokio::test]
async fn mint_v2_happy_path_returns_creds_and_audit_record_id() {
    let (broker_url, _state, _kp, jwt, signing_key) = spawn_broker().await;
    let wallet = address_from_signing_key(&signing_key);

    let body = serde_json::json!({
        "request_id": "mnt_test_1",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": wallet, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": wallet, "signature": "" }
    });
    let canon = canonical_input(&body);
    let sig = eip191_sign(&signing_key, &canon);
    let body = serde_json::json!({
        "request_id": "mnt_test_1",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": wallet, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": wallet, "signature": sig }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("authorization", format!("Bearer {}", jwt))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body_resp: Value = resp.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "body: {}", body_resp);
    assert_eq!(body_resp["access_key_id"], "ASIA-V2");
    assert_eq!(body_resp["wallet"].as_str().unwrap().to_lowercase(), wallet);
    assert!(body_resp["audit_record_id"].is_string());
    assert_eq!(body_resp["anchored"][0], "sqlite");
}

#[tokio::test]
async fn mint_v2_rejects_per_call_sig_for_wrong_address() {
    let (broker_url, _state, _kp, jwt, signing_key) = spawn_broker().await;
    let wallet = address_from_signing_key(&signing_key);
    // Sign with the right key but claim a different address in body.
    let mismatch_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let body = serde_json::json!({
        "request_id": "mnt_test_2",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": wallet, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": mismatch_addr, "signature": "" }
    });
    let canon = canonical_input(&body);
    let sig = eip191_sign(&signing_key, &canon);
    let body = serde_json::json!({
        "request_id": "mnt_test_2",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": wallet, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": mismatch_addr, "signature": sig }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("authorization", format!("Bearer {}", jwt))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mint_v2_rejects_missing_body() {
    let (broker_url, _state, _kp, jwt, _signing_key) = spawn_broker().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("authorization", format!("Bearer {}", jwt))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mint_v2_rejects_jwt_address_mismatch() {
    let (broker_url, _state, _kp, jwt, _signing_key) = spawn_broker().await;
    // Sign + claim with a DIFFERENT key/address than what's in the JWT.
    let other_key = SigningKey::random(&mut agentkeys_broker_server::oidc::rand_compat::OsRngWrapper);
    let other_addr = address_from_signing_key(&other_key);

    let body = serde_json::json!({
        "request_id": "mnt_test_3",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": other_addr, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": other_addr, "signature": "" }
    });
    let canon = canonical_input(&body);
    let sig = eip191_sign(&other_key, &canon);
    let body = serde_json::json!({
        "request_id": "mnt_test_3",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": other_addr, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": other_addr, "signature": sig }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("authorization", format!("Bearer {}", jwt))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap();
    // Per-call sig is valid for `other_addr` but the JWT claims a
    // different wallet → 401.
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mint_v2_rejects_garbage_signature() {
    let (broker_url, _state, _kp, jwt, signing_key) = spawn_broker().await;
    let wallet = address_from_signing_key(&signing_key);
    let body = serde_json::json!({
        "request_id": "mnt_test_4",
        "issued_at": "2026-05-05T14:00:00Z",
        "intent": { "agent_id": wallet, "service": "s3", "scope_path": "bots/" },
        "auth": { "address": wallet, "signature": format!("0x{}", "00".repeat(65)) }
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("authorization", format!("Bearer {}", jwt))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap();
    assert!(
        matches!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::BAD_REQUEST
        ),
        "expected 400/401, got {}",
        resp.status()
    );
}
