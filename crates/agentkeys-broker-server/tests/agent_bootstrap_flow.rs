//! End-to-end tests for the §10.2 agent-**initiated** pairing ceremony (issue
//! #144, method A):
//!   request (agent, pop_sig) → claim (master, J1-gated) → poll (agent, pop_sig)
//!   → pending-bindings (master).
//!
//! Exercises the full HTTP path through `create_router`, including the real
//! secp256k1 pop_sig produced by `agentkeys_core::device_crypto::DeviceKey` and
//! verified by the broker's request + poll handlers — the pop-critical match.

use std::path::PathBuf;
use std::sync::Arc;

use agentkeys_broker_server::audit::AuditLog;
use agentkeys_broker_server::config::BrokerConfig;
use agentkeys_broker_server::create_router;
use agentkeys_broker_server::identity::derive_omni_account;
use agentkeys_broker_server::jwt::issue::mint_session_jwt;
use agentkeys_broker_server::jwt::verify::verify_session_jwt;
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

/// Mint a master J1 session bound to a fresh master omni; returns (bearer, master_omni).
fn master_session(state: &AppState) -> (String, String) {
    let master_wallet = "0xabcdef0123456789abcdef0123456789abcdef01";
    let master_omni = derive_omni_account("evm", master_wallet).to_string();
    let token = mint_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        &master_omni,
        master_wallet,
        "evm",
        master_wallet,
        3600,
    )
    .unwrap();
    (token, master_omni)
}

/// Generate a fresh in-sandbox K10 device key.
fn device_key() -> (TempDir, DeviceKey) {
    let kd = TempDir::new().unwrap();
    let dk =
        DeviceKey::load_or_generate(kd.path().join("dev.key").to_str().unwrap(), true).unwrap();
    (kd, dk)
}

#[tokio::test]
async fn request_rejects_bad_pop_sig() {
    // The agent /request endpoint takes no bearer but MUST hold a valid pop_sig
    // — a sig from a different key (recovers to the wrong address) is rejected
    // and creates no row (no DoS amplification on the unauthenticated endpoint).
    let (broker_url, _state) = spawn_broker().await;
    let (_kd, dk) = device_key();
    let (_kd2, other) = device_key();
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agent/pairing/request", broker_url))
        .json(&json!({
            "device_pubkey": dk.address(),
            "pop_sig": other.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_requires_master_bearer() {
    let (broker_url, _state) = spawn_broker().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agent/pairing/claim", broker_url))
        .json(&json!({ "pairing_code": "whatever", "label": "agent-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_rejects_bad_label() {
    // Label is validated before the store is touched, so a bogus code + bad
    // label still 400s (no need to open a real request first).
    let (broker_url, state) = spawn_broker().await;
    let (bearer, _) = master_session(&state);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agent/pairing/claim", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "pairing_code": "whatever", "label": "Agent/A" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_request_claim_poll_pending_flow() {
    let (broker_url, state) = spawn_broker().await;
    let (bearer, master_omni) = master_session(&state);
    let client = reqwest::Client::new();

    // 1. AGENT generates K10 in the sandbox + opens an unbound pairing request.
    let (_kd, dk) = device_key();
    let request: Value = client
        .post(format!("{}/v1/agent/pairing/request", broker_url))
        .json(&json!({
            "device_pubkey": dk.address(),
            "pop_sig": dk.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = request["request_id"].as_str().unwrap().to_string();
    let pairing_code = request["pairing_code"].as_str().unwrap().to_string();
    assert!(request["device_key_hash"]
        .as_str()
        .unwrap()
        .starts_with("0x"));

    // 2. AGENT polls BEFORE any master claims → pending.
    let pending_poll: Value = client
        .post(format!("{}/v1/agent/pairing/poll", broker_url))
        .json(&json!({
            "request_id": request_id,
            "device_pubkey": dk.address(),
            "pop_sig": dk.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending_poll["status"], "pending");

    // 3. MASTER claims the code (the binding act). Derives the HDKD child omni.
    let claim: Value = client
        .post(format!("{}/v1/agent/pairing/claim", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "pairing_code": pairing_code,
            "label": "agent-a",
            "requested_scope": "memory",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let child_omni = claim["child_omni"].as_str().unwrap().to_string();
    // Public recomputability (acceptance criterion).
    assert_eq!(
        child_omni,
        agentkeys_core::actor_omni::child_omni_hex(&master_omni, "agent-a").unwrap()
    );
    assert_eq!(claim["operator_omni"], master_omni);
    assert_eq!(claim["request_id"], request_id);
    assert_eq!(claim["device_pubkey"], dk.address());

    // 4. AGENT polls again → claimed; J1_agent minted at retrieval.
    let claimed_poll: Value = client
        .post(format!("{}/v1/agent/pairing/poll", broker_url))
        .json(&json!({
            "request_id": request_id,
            "device_pubkey": dk.address(),
            "pop_sig": dk.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(claimed_poll["status"], "claimed");
    let j1_agent = claimed_poll["session_jwt"].as_str().unwrap();
    assert_eq!(claimed_poll["child_omni"], child_omni);

    // J1_agent carries the HDKD omni + lineage.
    let claims = verify_session_jwt(&state.session_keypair, TEST_ISSUER, j1_agent).unwrap();
    assert_eq!(claims.agentkeys.omni_account, child_omni);
    assert_eq!(
        claims.agentkeys.parent_omni.as_deref(),
        Some(master_omni.as_str())
    );
    assert_eq!(
        claims.agentkeys.derivation_path.as_deref(),
        Some("//agent-a")
    );
    assert_eq!(
        claims.agentkeys.device_pubkey.as_deref(),
        Some(dk.address())
    );
    assert_eq!(claims.agentkeys.identity_type, "agent_hdkd");

    // 5. MASTER pulls the pending binding (the push-notification substrate).
    let pending: Value = client
        .get(format!("{}/v1/agent/pending-bindings", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = pending["pending"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["request_id"], request_id);
    assert_eq!(arr[0]["child_omni"], child_omni);
    assert_eq!(arr[0]["device_pubkey"], dk.address());
    assert_eq!(arr[0]["requested_scope"], "memory");
    assert!(arr[0]["pop_sig"].as_str().unwrap().starts_with("0x"));
    assert!(arr[0]["device_key_hash"]
        .as_str()
        .unwrap()
        .starts_with("0x"));

    // 6. ack the binding (master submitted registerAgentDevice) → the rendezvous
    //    self-cleans, so a re-run sees an empty pending list (idempotent).
    let ack: Value = client
        .post(format!("{}/v1/agent/pending-bindings/ack", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ack["acked"], true);
    let pending2: Value = client
        .get(format!("{}/v1/agent/pending-bindings", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending2["pending"].as_array().unwrap().len(), 0);
    // Second ack is idempotent (already bound → acked:false).
    let ack2: Value = client
        .post(format!("{}/v1/agent/pending-bindings/ack", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ack2["acked"], false);

    // 7. single-use: a second claim of the same pairing_code is rejected.
    let replay = client
        .post(format!("{}/v1/agent/pairing/claim", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "pairing_code": pairing_code, "label": "agent-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn poll_rejects_wrong_device_and_bad_pop_sig() {
    let (broker_url, state) = spawn_broker().await;
    let (bearer, _master_omni) = master_session(&state);
    let client = reqwest::Client::new();

    // Open + claim a request so it's in the claimed state.
    let (_kd, dk) = device_key();
    let request: Value = client
        .post(format!("{}/v1/agent/pairing/request", broker_url))
        .json(&json!({ "device_pubkey": dk.address(), "pop_sig": dk.pop_sig().unwrap() }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_id = request["request_id"].as_str().unwrap().to_string();
    let pairing_code = request["pairing_code"].as_str().unwrap().to_string();
    client
        .post(format!("{}/v1/agent/pairing/claim", broker_url))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "pairing_code": pairing_code, "label": "agent-c" }))
        .send()
        .await
        .unwrap();

    // A pop_sig from a DIFFERENT key cannot poll (recovers to wrong address).
    let (_kd2, other) = device_key();
    let bad_sig = client
        .post(format!("{}/v1/agent/pairing/poll", broker_url))
        .json(&json!({
            "request_id": request_id,
            "device_pubkey": dk.address(),
            "pop_sig": other.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_sig.status(), reqwest::StatusCode::UNAUTHORIZED);

    // A valid pop_sig but for a DIFFERENT device_pubkey (the other key's own,
    // self-consistent) doesn't match the request's bound device → unauthorized
    // (NotFound collapsed to 401 so a guessed request_id leaks nothing).
    let wrong_device = client
        .post(format!("{}/v1/agent/pairing/poll", broker_url))
        .json(&json!({
            "request_id": request_id,
            "device_pubkey": other.address(),
            "pop_sig": other.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_device.status(), reqwest::StatusCode::UNAUTHORIZED);

    // The correct device + pop_sig still retrieves J1_agent.
    let good = client
        .post(format!("{}/v1/agent/pairing/poll", broker_url))
        .json(&json!({
            "request_id": request_id,
            "device_pubkey": dk.address(),
            "pop_sig": dk.pop_sig().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(good.status(), reqwest::StatusCode::OK);
}
