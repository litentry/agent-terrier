//! Integration test for the Stage 7 auth/wallet endpoints (US-009).
//!
//! Spawns an in-process broker with the SiweWalletAuth plug-in registered,
//! runs a full SIWE → mint-session-JWT round trip with a real k256
//! signing key, and verifies:
//! - challenge response carries a SIWE message
//! - verify with valid signature returns a session JWT
//! - verify-then-replay fails (nonce single-use)
//! - bad signature returns 401

use std::collections::HashMap;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    config::BrokerConfig,
    create_router,
    jwt::SessionKeypair,
    oidc::OidcKeypair,
    plugins::audit::sqlite::SqliteAnchor,
    plugins::audit::AuditAnchor as AuditAnchorTrait,
    plugins::audit::AuditPolicy,
    plugins::auth::wallet_sig::SiweWalletAuth,
    plugins::auth::UserAuthMethod,
    plugins::wallet::keystore::ClientSideKeystoreProvisioner,
    plugins::PluginRegistry,
    state::{AppState, Tier2State},
    storage::{AuthNonceStore, GrantStore, IdentityLinkStore, WalletStore},
    sts::{AssumedCredentials, StsClient, StubStsClient},
};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::path::PathBuf;
use tempfile::TempDir;

const TEST_ISSUER: &str = "https://broker.test.invalid";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-TEST".into(),
        secret_access_key: "test-secret".into(),
        session_token: "test-session".into(),
        expiration_unix: 9_999_999_999,
    }
}

async fn spawn_broker_with_wallet_sig() -> (String, Arc<AppState>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let oidc_kp_path = tmp.path().join("oidc.json");
    let oidc = Arc::new(OidcKeypair::generate_and_persist(&oidc_kp_path).unwrap());

    let session_kp_path = tmp.path().join("session.json");
    let session_keypair = Arc::new(SessionKeypair::generate_and_persist(&session_kp_path).unwrap());

    let nonce_store = Arc::new(AuthNonceStore::open_in_memory().unwrap());
    let wallet_store = Arc::new(WalletStore::open_in_memory().unwrap());

    // SiweWalletAuth — real plug-in.
    let mut auth: HashMap<String, Arc<dyn UserAuthMethod>> = HashMap::new();
    auth.insert(
        "wallet_sig".to_string(),
        Arc::new(SiweWalletAuth::new(
            Arc::clone(&nonce_store),
            "broker.test.invalid",
            TEST_ISSUER,
        )),
    );

    let sqlite_anchor: Arc<dyn AuditAnchorTrait> =
        Arc::new(SqliteAnchor::open_in_memory().unwrap());
    let registry = Arc::new(PluginRegistry {
        auth,
        wallet: Arc::new(ClientSideKeystoreProvisioner::new(Arc::clone(
            &wallet_store,
        ))),
        audit: vec![sqlite_anchor],
    });

    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));
    let config = BrokerConfig {
        data_role_arn: "arn:aws:iam::000:role/test".into(),
        audit_db_path: PathBuf::from(":memory:"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        shutdown_grace_seconds: 5,
        oidc_issuer: TEST_ISSUER.into(),
        oidc_keypair_path: oidc_kp_path,
        oidc_jwt_ttl_seconds: 300,
    };

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
        oidc,
        session_keypair,
        registry,
        audit_policy: AuditPolicy::SqlitePrimary,
        wallet_store,
        nonce_store,
        grant_store: Arc::new(GrantStore::open_in_memory().unwrap()),
        identity_link_store: Arc::new(IdentityLinkStore::open_in_memory().unwrap()),
        pairing_request_store: Arc::new(
            agentkeys_broker_server::storage::PairingRequestStore::open_in_memory().unwrap(),
        ),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: Arc::new(Tier2State::default()),
        #[cfg(feature = "auth-email-link")]
        email_link: None,
        #[cfg(feature = "auth-oauth2")]
        oauth2: None,
    });
    let app = create_router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{}", addr), state)
}

/// Sign an EIP-191 envelope of `message` with `signing_key` and return
/// the 65-byte 0x-prefixed hex signature (r || s || v).
fn sign_eip191(signing_key: &SigningKey, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();
    let (sig, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        signing_key.sign_prehash_recoverable(&digest).unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    format!("0x{}", hex::encode(bytes))
}

/// Compute the EVM-style 0x-prefixed lowercase hex address from a
/// k256 verifying key.
fn address_from_signing_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let pubkey_bytes = encoded_point.as_bytes();
    let mut h = Keccak256::new();
    h.update(&pubkey_bytes[1..]);
    let pubkey_hash = h.finalize();
    format!("0x{}", hex::encode(&pubkey_hash[12..]))
}

#[tokio::test]
async fn wallet_start_then_verify_returns_session_jwt() {
    let (broker, _) = spawn_broker_with_wallet_sig().await;
    let client = reqwest::Client::new();

    // Generate a real signing key; use its address as the SIWE address.
    let signing_key =
        SigningKey::random(&mut agentkeys_broker_server::oidc::rand_compat::OsRngWrapper);
    let address = address_from_signing_key(&signing_key);

    // 1. Start.
    let start: Value = client
        .post(format!("{}/v1/auth/wallet/start", broker))
        .json(&serde_json::json!({
            "address": address,
            "chain_id": 84532_u64,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = start["request_id"].as_str().unwrap().to_string();
    let siwe_message = start["siwe_message"].as_str().unwrap().to_string();
    assert!(siwe_message.contains("broker.test.invalid"));
    assert!(siwe_message.contains(&address));
    assert!(siwe_message.contains("Chain ID: 84532"));

    // 2. Sign the SIWE message + verify.
    let sig_hex = sign_eip191(&signing_key, &siwe_message);
    let resp = client
        .post(format!("{}/v1/auth/wallet/verify", broker))
        .json(&serde_json::json!({
            "request_id": request_id,
            "signature": sig_hex,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["session_jwt"].as_str().unwrap().matches('.').count() == 2);
    assert_eq!(body["wallet_address"], address);
    assert_eq!(body["identity_type"], "evm");
}

#[tokio::test]
async fn wallet_verify_replay_after_first_use_returns_401() {
    let (broker, _) = spawn_broker_with_wallet_sig().await;
    let client = reqwest::Client::new();

    let signing_key =
        SigningKey::random(&mut agentkeys_broker_server::oidc::rand_compat::OsRngWrapper);
    let address = address_from_signing_key(&signing_key);

    let start: Value = client
        .post(format!("{}/v1/auth/wallet/start", broker))
        .json(&serde_json::json!({"address": address, "chain_id": 1_u64}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = start["request_id"].as_str().unwrap();
    let siwe_message = start["siwe_message"].as_str().unwrap();
    let sig = sign_eip191(&signing_key, siwe_message);

    // First verify succeeds.
    let r1 = client
        .post(format!("{}/v1/auth/wallet/verify", broker))
        .json(&serde_json::json!({"request_id": request_id, "signature": sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), reqwest::StatusCode::OK);

    // Replay must fail.
    let r2 = client
        .post(format!("{}/v1/auth/wallet/verify", broker))
        .json(&serde_json::json!({"request_id": request_id, "signature": sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wallet_verify_garbage_signature_returns_4xx() {
    let (broker, _) = spawn_broker_with_wallet_sig().await;
    let client = reqwest::Client::new();

    let signing_key =
        SigningKey::random(&mut agentkeys_broker_server::oidc::rand_compat::OsRngWrapper);
    let address = address_from_signing_key(&signing_key);

    let start: Value = client
        .post(format!("{}/v1/auth/wallet/start", broker))
        .json(&serde_json::json!({"address": address, "chain_id": 1_u64}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = start["request_id"].as_str().unwrap();

    let resp = client
        .post(format!("{}/v1/auth/wallet/verify", broker))
        .json(&serde_json::json!({
            "request_id": request_id,
            "signature": format!("0x{}", "00".repeat(65)),
        }))
        .send()
        .await
        .unwrap();
    // k256 rejects all-zero r/s as InvalidRequest (400) before recover.
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 401,
        "expected 400 or 401, got {}",
        status
    );
}

#[tokio::test]
async fn wallet_start_rejects_malformed_address() {
    let (broker, _) = spawn_broker_with_wallet_sig().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/auth/wallet/start", broker))
        .json(&serde_json::json!({"address": "0xshort", "chain_id": 1_u64}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}
