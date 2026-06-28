//! `/v1/wallet/*` integration tests — Phase B, US-028.
//!
//! Exercises the identity-link + recovery-lookup endpoints:
//! - `POST /v1/wallet/link` (master JWT) → 200, identity-link row created.
//! - `GET /v1/wallet/links` → 200, returns linked identities.
//! - `POST /v1/wallet/recover/lookup` (unauth) → 200, returns master
//!   OmniAccount when identity is linked, `linked: false` when not.
//! - Cross-master link rejection: master A cannot claim identity already
//!   owned by master B.
//! - Missing auth on link → 401; on lookup → 200 (lookup is unauth).

use std::collections::HashMap;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    config::BrokerConfig,
    create_router,
    jwt::issue::mint_session_jwt,
    jwt::SessionKeypair,
    oidc::OidcKeypair,
    plugins::{
        audit::{sqlite::SqliteAnchor, AuditAnchor, AuditPolicy},
        wallet::keystore::ClientSideKeystoreProvisioner,
        PluginRegistry,
    },
    state::{AppState, Tier2State},
    storage::{AuthNonceStore, GrantStore, IdentityLinkStore, WalletStore},
    sts::{AssumedCredentials, StsClient, StubStsClient},
};
use serde_json::Value;
use tempfile::TempDir;

const TEST_ISSUER: &str = "https://broker.wallet.test";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-WALLET".into(),
        secret_access_key: "wallet-secret".into(),
        session_token: "wallet-session".into(),
        expiration_unix: 9_999_999_999,
    }
}

struct Harness {
    pub broker_url: String,
    pub state: Arc<AppState>,
}

async fn spawn_broker() -> Harness {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let oidc = OidcKeypair::generate_and_persist(&tmp.path().join("oidc.json")).unwrap();
    let session_kp =
        SessionKeypair::generate_and_persist(&tmp.path().join("session.json")).unwrap();

    let auth_map: HashMap<String, Arc<dyn agentkeys_broker_server::plugins::auth::UserAuthMethod>> =
        HashMap::new();

    let wallet_store = Arc::new(WalletStore::open_in_memory().unwrap());
    let nonce_store = Arc::new(AuthNonceStore::open_in_memory().unwrap());
    let sqlite_anchor: Arc<dyn AuditAnchor> = Arc::new(SqliteAnchor::open_in_memory().unwrap());

    let registry = Arc::new(PluginRegistry {
        auth: auth_map,
        wallet: Arc::new(ClientSideKeystoreProvisioner::new(Arc::clone(
            &wallet_store,
        ))),
        audit: vec![sqlite_anchor],
    });

    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));

    let config = BrokerConfig {
        data_role_arn: "arn:aws:iam::000:role/test".into(),
        memory_role_arn: String::new(),
        audit_db_path: tmp.path().join("audit.sqlite"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        shutdown_grace_seconds: 5,
        oidc_issuer: TEST_ISSUER.into(),
        oidc_keypair_path: tmp.path().join("oidc.json"),
        oidc_jwt_ttl_seconds: 300,
        dev_mode: false,
        auth_methods: "wallet_sig".into(),
        audit_anchors: "sqlite".into(),
        refuse_to_boot_strict: false,
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
        oidc: Arc::new(oidc),
        session_keypair: Arc::new(session_kp),
        registry,
        audit_policy: AuditPolicy::SqlitePrimary,
        wallet_store,
        nonce_store,
        grant_store: Arc::new(GrantStore::open_in_memory().unwrap()),
        identity_link_store: Arc::new(IdentityLinkStore::open_in_memory().unwrap()),
        pairing_request_store: Arc::new(
            agentkeys_broker_server::storage::PairingRequestStore::open_in_memory().unwrap(),
        ),
        agent_delegation_store: Arc::new(
            agentkeys_broker_server::storage::AgentDelegationStore::open_in_memory().unwrap(),
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

    Harness {
        broker_url: format!("http://{}", addr),
        state,
    }
}

fn master_jwt(state: &AppState, omni: &str) -> String {
    mint_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        omni,
        "0xwallet",
        "evm",
        "0xwallet",
        3600,
    )
    .unwrap()
}

#[tokio::test]
async fn link_then_list_round_trip() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni-master");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/wallet/link", h.broker_url))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "alice@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{}/v1/wallet/links", h.broker_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let links = body["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["identity_type"].as_str().unwrap(), "email");
    assert_eq!(
        links[0]["identity_value"].as_str().unwrap(),
        "alice@example.com"
    );
}

#[tokio::test]
async fn cross_master_link_rejected() {
    let h = spawn_broker().await;
    let alice = master_jwt(&h.state, "0xomni-alice");
    let bob = master_jwt(&h.state, "0xomni-bob");
    let client = reqwest::Client::new();

    // Alice claims an email
    let resp = client
        .post(format!("{}/v1/wallet/link", h.broker_url))
        .bearer_auth(&alice)
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "shared@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Bob tries the same — must be rejected.
    let resp = client
        .post(format!("{}/v1/wallet/link", h.broker_url))
        .bearer_auth(&bob)
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "shared@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn link_is_idempotent_for_same_master() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni-master");
    let client = reqwest::Client::new();

    for _ in 0..3 {
        let resp = client
            .post(format!("{}/v1/wallet/link", h.broker_url))
            .bearer_auth(&jwt)
            .json(&serde_json::json!({
                "identity_type":  "email",
                "identity_value": "alice@example.com"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    // Verify only ONE row exists.
    let resp = client
        .get(format!("{}/v1/wallet/links", h.broker_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["links"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn recover_lookup_finds_master() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni-recovery-master");
    let client = reqwest::Client::new();

    // Master pre-attaches an email.
    client
        .post(format!("{}/v1/wallet/link", h.broker_url))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "lost-user@example.com"
        }))
        .send()
        .await
        .unwrap();

    // Anyone can call recover/lookup — no bearer needed.
    let resp = client
        .post(format!("{}/v1/wallet/recover/lookup", h.broker_url))
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "lost-user@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["linked"], true);
    assert_eq!(
        body["omni_account"].as_str().unwrap(),
        "0xomni-recovery-master"
    );
}

#[tokio::test]
async fn recover_lookup_returns_unlinked_when_unknown() {
    let h = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/wallet/recover/lookup", h.broker_url))
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "ghost@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["linked"], false);
}

#[tokio::test]
async fn link_requires_auth() {
    let h = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/wallet/link", h.broker_url))
        .json(&serde_json::json!({
            "identity_type":  "email",
            "identity_value": "alice@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn link_rejects_empty_fields() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/wallet/link", h.broker_url))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({
            "identity_type":  "",
            "identity_value": "alice@example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
