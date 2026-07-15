//! End-to-end tests for the §369 device→sandbox delegation rendezvous:
//!   request (sandbox, J1-gated) → pending + sign (device, pop_sig) →
//!   poll (sandbox, J1-gated).
//!
//! Exercises the full HTTP path through `create_router` with a real secp256k1
//! device key (the ESP32's K10, here a software `DeviceKey`) co-signing a
//! delegation to a SEPARATE ephemeral sandbox key — and asserts the delegation the
//! sandbox retrieves is exactly what the WORKER will accept
//! (`device_crypto::verify_delegation`). The broker only relays; it holds no K10.

use std::path::PathBuf;
use std::sync::Arc;

use agentkeys_broker_server::audit::AuditLog;
use agentkeys_broker_server::config::BrokerConfig;
use agentkeys_broker_server::create_router;
use agentkeys_broker_server::identity::{derive_with_client_id, DEFAULT_CLIENT_ID};
use agentkeys_broker_server::jwt::issue::mint_agent_session_jwt;
use agentkeys_broker_server::oidc::OidcKeypair;
use agentkeys_broker_server::state::AppState;
use agentkeys_broker_server::sts::{AssumedCredentials, StsClient, StubStsClient};
use agentkeys_core::device_crypto::DeviceKey;
use serde_json::{json, Value};
use tempfile::TempDir;

const TEST_ISSUER: &str = "https://oidc.test.invalid";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-stub".into(),
        secret_access_key: "stub".into(),
        session_token: "stub".into(),
        expiration_unix: 9_999_999_999,
    }
}

async fn spawn_broker() -> (String, Arc<AppState>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let keypair_path = tmp.path().join("oidc-keypair.json");
    let oidc = OidcKeypair::generate_and_persist(&keypair_path).unwrap();
    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));
    let config = BrokerConfig {
        data_role_arn: "arn:aws:iam::000:role/test".into(),
        memory_role_arn: String::new(),
        audit_db_path: PathBuf::from(":memory:"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        shutdown_grace_seconds: 5,
        oidc_issuer: TEST_ISSUER.into(),
        oidc_keypair_path: keypair_path,
        oidc_jwt_ttl_seconds: 300,
        dev_mode: false,
        auth_methods: "wallet_sig".into(),
        audit_anchors: "sqlite".into(),
        refuse_to_boot_strict: false,
        client_id: agentkeys_broker_server::identity::DEFAULT_CLIENT_ID.to_string(),
    };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let session_keypair = agentkeys_broker_server::jwt::SessionKeypair::generate_and_persist(
        &tmp.path().join("session-keypair.json"),
    )
    .unwrap();
    let wallet_store =
        Arc::new(agentkeys_broker_server::storage::WalletStore::open_in_memory().unwrap());
    let nonce_store =
        Arc::new(agentkeys_broker_server::storage::AuthNonceStore::open_in_memory().unwrap());
    let sqlite_anchor: Arc<dyn agentkeys_broker_server::plugins::audit::AuditAnchor> = Arc::new(
        agentkeys_broker_server::plugins::audit::sqlite::SqliteAnchor::open_in_memory().unwrap(),
    );
    let registry = Arc::new(agentkeys_broker_server::plugins::PluginRegistry {
        auth: std::collections::HashMap::new(),
        wallet: Arc::new(
            agentkeys_broker_server::plugins::wallet::keystore::ClientSideKeystoreProvisioner::new(
                Arc::clone(&wallet_store),
            ),
        ),
        audit: vec![sqlite_anchor],
    });
    let state = Arc::new(AppState {
        config,
        http,
        audit: AuditLog::open_in_memory().unwrap(),
        sts,
        oidc: Arc::new(oidc),
        session_keypair: Arc::new(session_keypair),
        registry,
        audit_policy: agentkeys_broker_server::plugins::audit::AuditPolicy::SqlitePrimary,
        wallet_store,
        nonce_store,
        grant_store: Arc::new(
            agentkeys_broker_server::storage::GrantStore::open_in_memory().unwrap(),
        ),
        identity_link_store: Arc::new(
            agentkeys_broker_server::storage::IdentityLinkStore::open_in_memory().unwrap(),
        ),
        pairing_request_store: Arc::new(
            agentkeys_broker_server::storage::PairingRequestStore::open_in_memory().unwrap(),
        ),
        agent_delegation_store: Arc::new(
            agentkeys_broker_server::storage::AgentDelegationStore::open_in_memory().unwrap(),
        ),
        sandbox: None,
        pending_ceremonies: Arc::new(
            agentkeys_broker_server::handlers::spawn::PendingCeremonyStore::new(),
        ),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: Arc::new(agentkeys_broker_server::state::Tier2State::default()),
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

/// A fresh secp256k1 key (used both for the device's K10 and for the sandbox's
/// ephemeral key — the two are independent keys to the protocol).
fn fresh_key(name: &str) -> (TempDir, DeviceKey) {
    let kd = TempDir::new().unwrap();
    let dk = DeviceKey::load_or_generate(kd.path().join(name).to_str().unwrap(), true).unwrap();
    (kd, dk)
}

/// Mint a `J1_agent` bound to `device` (its `device_pubkey` claim = the device's
/// K10 address), as the sandbox would hold after resolving its session. Returns
/// the bearer.
fn agent_session(state: &AppState, device: &DeviceKey) -> String {
    let operator_omni = derive_with_client_id(
        DEFAULT_CLIENT_ID,
        "evm",
        "0xabcdef0123456789abcdef0123456789abcdef01",
    )
    .to_string();
    let actor_omni = derive_with_client_id(
        DEFAULT_CLIENT_ID,
        "evm",
        "0x1111111111111111111111111111111111111111",
    )
    .to_string();
    mint_agent_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        &actor_omni,
        &operator_omni,
        "//sandbox",
        device.address(),
        3600,
    )
    .unwrap()
}

#[tokio::test]
async fn request_requires_an_agent_session() {
    // /request is J1-gated — no bearer ⇒ 401, so a sandbox can't open a delegation
    // request without a session bound to a device.
    let (broker_url, _state) = spawn_broker().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agent/delegation/request", broker_url))
        .json(&json!({ "sandbox_pubkey": "0x2222222222222222222222222222222222222222", "requested_scope": "memory" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn full_delegation_origination_flow() {
    let (broker_url, state) = spawn_broker().await;
    let client = reqwest::Client::new();

    let (_dkd, device) = fresh_key("device.key"); // the ESP32 K10
    let (_skd, sandbox) = fresh_key("sandbox.key"); // the sandbox's ephemeral key
    let bearer = agent_session(&state, &device);

    // 1. SANDBOX opens a delegation request (J1-gated; device derived from the J1).
    let req: Value = client
        .post(format!("{}/v1/agent/delegation/request", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "sandbox_pubkey": sandbox.address(),
            "requested_scope": "memory credentials:fetch",
            "requested_ttl_seconds": 3600,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = req["request_id"].as_str().unwrap().to_string();
    let device_key_hash = req["device_key_hash"].as_str().unwrap().to_string();
    assert_eq!(device_key_hash, device.device_key_hash().unwrap());

    // 2. DEVICE discovers the open request via /pending (pop_sig-gated).
    let pending: Value = client
        .post(format!("{}/v1/agent/delegation/pending", broker_url))
        .json(&json!({ "device_pubkey": device.address(), "pop_sig": device.pop_sig().unwrap() }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = &pending["pending"][0];
    assert_eq!(row["request_id"].as_str().unwrap(), request_id);
    let sandbox_pubkey = row["sandbox_pubkey"].as_str().unwrap().to_string();
    assert_eq!(sandbox_pubkey, sandbox.address());
    let scope = row["requested_scope"].as_str().unwrap().to_string();

    // 3. DEVICE co-signs the delegation with K10 (the firmware's job) + submits it.
    let expires_at = 9_999_999_999u64;
    let delegation_sig = device
        .delegation_sig(&sandbox_pubkey, &scope, expires_at)
        .unwrap();
    let signed: Value = client
        .post(format!("{}/v1/agent/delegation/sign", broker_url))
        .json(&json!({
            "device_pubkey": device.address(),
            "pop_sig": device.pop_sig().unwrap(),
            "request_id": request_id,
            "scope": scope,
            "expires_at": expires_at,
            "delegation_sig": delegation_sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(signed["signed"], json!(true));

    // 4. SANDBOX polls + retrieves the device-signed delegation_path.
    let poll: Value = client
        .post(format!("{}/v1/agent/delegation/poll", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(poll["status"], json!("signed"));
    let got_sig = poll["delegation_sig"].as_str().unwrap();
    let got_scope = poll["scope"].as_str().unwrap();
    let got_expires = poll["expires_at"].as_u64().unwrap();

    // THE proof: what the sandbox retrieved is exactly what the WORKER accepts —
    // verify_delegation recovers the DEVICE (not the sandbox) and binds it to the
    // sandbox key, so the sandbox can now mint caps the worker will honor.
    let recovered = agentkeys_core::device_crypto::verify_delegation(
        &device_key_hash,
        sandbox.address(),
        got_scope,
        got_expires,
        got_sig,
    )
    .unwrap();
    assert_eq!(recovered, device.address());
}

#[tokio::test]
async fn sign_rejects_a_different_device() {
    // A device whose pop_sig is valid but whose hash doesn't match the request's
    // bound device cannot sign it — the request is invisible to the wrong device.
    let (broker_url, state) = spawn_broker().await;
    let client = reqwest::Client::new();
    let (_dkd, device) = fresh_key("device.key");
    let (_okd, other) = fresh_key("other.key");
    let (_skd, sandbox) = fresh_key("sandbox.key");
    let bearer = agent_session(&state, &device);

    let req: Value = client
        .post(format!("{}/v1/agent/delegation/request", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "sandbox_pubkey": sandbox.address(), "requested_scope": "memory" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = req["request_id"].as_str().unwrap().to_string();

    // `other` (a different device) tries to sign — its own valid pop_sig, but its
    // hash isn't the request's bound device ⇒ 401.
    let expires_at = 9_999_999_999u64;
    let forged = other
        .delegation_sig(sandbox.address(), "memory", expires_at)
        .unwrap();
    let resp = client
        .post(format!("{}/v1/agent/delegation/sign", broker_url))
        .json(&json!({
            "device_pubkey": other.address(),
            "pop_sig": other.pop_sig().unwrap(),
            "request_id": request_id,
            "scope": "memory",
            "expires_at": expires_at,
            "delegation_sig": forged,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn poll_is_bound_to_the_requesting_agents_device() {
    // A delegation request opened under device A's session can't be polled by a
    // session bound to device B (different device_pubkey claim).
    let (broker_url, state) = spawn_broker().await;
    let client = reqwest::Client::new();
    let (_akd, device_a) = fresh_key("device-a.key");
    let (_bkd, device_b) = fresh_key("device-b.key");
    let (_skd, sandbox) = fresh_key("sandbox.key");

    let bearer_a = agent_session(&state, &device_a);
    let req: Value = client
        .post(format!("{}/v1/agent/delegation/request", broker_url))
        .header("Authorization", format!("Bearer {bearer_a}"))
        .json(&json!({ "sandbox_pubkey": sandbox.address(), "requested_scope": "memory" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = req["request_id"].as_str().unwrap().to_string();

    let bearer_b = agent_session(&state, &device_b);
    let resp = client
        .post(format!("{}/v1/agent/delegation/poll", broker_url))
        .header("Authorization", format!("Bearer {bearer_b}"))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
