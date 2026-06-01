//! `/v1/grant/*` integration tests — Phase B, US-026/027.
//!
//! Exercises the capability-grant lifecycle end-to-end:
//! - `POST /v1/grant/create` (master JWT) → 200, returns grant_id +
//!   audit_proof (compact JWS).
//! - `GET /v1/grant/list` → 200, returns the just-created grant.
//! - `POST /v1/grant/revoke` → 200, instant revoke. Mint-time enforcement
//!   of revoked grants was retired with mint_v2 in PR #96 (issue #72);
//!   today /v1/grant/* is CRUD-only (no consume point).
//! - Re-revoke is idempotent at storage level (caller sees 400 because
//!   revoke() returns false).
//! - Cross-master revoke (different OmniAccount tries to revoke a grant
//!   they don't own) → 400 (collapsed for non-owner-info-leak).
//!
//! Smoke: tampered audit_proof would fail jwt::verify against the
//! session keypair — covered by storage-layer round-trip in
//! `crates/agentkeys-broker-server/src/jwt/issue.rs` tests.

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

const TEST_ISSUER: &str = "https://broker.grant.test";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-GRANT".into(),
        secret_access_key: "grant-secret".into(),
        session_token: "grant-session".into(),
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
        audit_db_path: tmp.path().join("audit.sqlite"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        shutdown_grace_seconds: 5,
        oidc_issuer: TEST_ISSUER.into(),
        oidc_keypair_path: tmp.path().join("oidc.json"),
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

fn master_jwt(state: &AppState, omni: &str, wallet: &str) -> String {
    mint_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        omni,
        wallet,
        "evm",
        wallet,
        3600,
    )
    .unwrap()
}

#[tokio::test]
async fn create_then_list_returns_grant() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni-master", "0xmaster-wallet");
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "daemon_address": "0xdaemonaaaa1111",
        "service":        "s3",
        "scope_path":     "bots/0xdaemonaaaa1111/",
        "expires_at":     9_999_999_999i64,
        "max_uses":       1000
    });
    let resp = client
        .post(format!("{}/v1/grant/create", h.broker_url))
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    let grant_id = created["grant_id"].as_str().unwrap().to_string();
    let audit_proof = created["audit_proof"].as_str().unwrap();
    assert!(grant_id.starts_with("grn-"));
    assert!(audit_proof.starts_with("eyJ"));

    // List
    let resp = client
        .get(format!("{}/v1/grant/list", h.broker_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let listed: Value = resp.json().await.unwrap();
    let grants = listed["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["grant_id"].as_str().unwrap(), grant_id);
    assert_eq!(grants[0]["service"].as_str().unwrap(), "s3");
    assert_eq!(grants[0]["max_uses"].as_i64().unwrap(), 1000);
    assert_eq!(grants[0]["used_count"].as_i64().unwrap(), 0);
    assert!(grants[0]["revoked_at"].is_null());
}

#[tokio::test]
async fn revoke_succeeds_for_owner_and_blocks_replay() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni-master", "0xmaster-wallet");
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "daemon_address": "0xdaemon",
        "service":        "s3",
        "scope_path":     "bots/0xdaemon/",
        "expires_at":     9_999_999_999i64,
        "max_uses":       100
    });
    let resp = client
        .post(format!("{}/v1/grant/create", h.broker_url))
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .unwrap();
    let created: Value = resp.json().await.unwrap();
    let grant_id = created["grant_id"].as_str().unwrap().to_string();

    // Revoke
    let resp = client
        .post(format!("{}/v1/grant/revoke", h.broker_url))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({ "grant_id": grant_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Re-revoke → 400.
    let resp = client
        .post(format!("{}/v1/grant/revoke", h.broker_url))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({ "grant_id": grant_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn cross_master_revoke_rejected() {
    let h = spawn_broker().await;
    let owner = master_jwt(&h.state, "0xomni-owner", "0xowner-wallet");
    let attacker = master_jwt(&h.state, "0xomni-attacker", "0xattacker-wallet");
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "daemon_address": "0xdaemon",
        "service":        "s3",
        "scope_path":     "bots/0xdaemon/",
        "expires_at":     9_999_999_999i64,
        "max_uses":       10
    });
    let resp = client
        .post(format!("{}/v1/grant/create", h.broker_url))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .unwrap();
    let created: Value = resp.json().await.unwrap();
    let grant_id = created["grant_id"].as_str().unwrap();

    let resp = client
        .post(format!("{}/v1/grant/revoke", h.broker_url))
        .bearer_auth(&attacker)
        .json(&serde_json::json!({ "grant_id": grant_id }))
        .send()
        .await
        .unwrap();
    // Attacker sees 400 (collapsed with not-found), not "wrong owner".
    assert_eq!(resp.status(), 400);

    // Owner can still revoke.
    let resp = client
        .post(format!("{}/v1/grant/revoke", h.broker_url))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "grant_id": grant_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn missing_authorization_header_returns_401() {
    let h = spawn_broker().await;
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "daemon_address": "0xdaemon",
        "service":        "s3",
        "scope_path":     "bots/",
        "expires_at":     9_999_999_999i64,
        "max_uses":       10
    });
    let resp = client
        .post(format!("{}/v1/grant/create", h.broker_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn create_rejects_past_expires_at() {
    let h = spawn_broker().await;
    let jwt = master_jwt(&h.state, "0xomni", "0xwallet");
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "daemon_address": "0xdaemon",
        "service":        "s3",
        "scope_path":     "bots/",
        "expires_at":     1i64, // 1970
        "max_uses":       10
    });
    let resp = client
        .post(format!("{}/v1/grant/create", h.broker_url))
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn list_only_returns_caller_owned_grants() {
    let h = spawn_broker().await;
    let alice = master_jwt(&h.state, "0xomni-alice", "0xa");
    let bob = master_jwt(&h.state, "0xomni-bob", "0xb");
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "daemon_address": "0xdaemon",
        "service":        "s3",
        "scope_path":     "bots/",
        "expires_at":     9_999_999_999i64,
        "max_uses":       10
    });
    // Alice creates two grants
    for _ in 0..2 {
        client
            .post(format!("{}/v1/grant/create", h.broker_url))
            .bearer_auth(&alice)
            .json(&body)
            .send()
            .await
            .unwrap();
    }
    // Bob creates one
    client
        .post(format!("{}/v1/grant/create", h.broker_url))
        .bearer_auth(&bob)
        .json(&body)
        .send()
        .await
        .unwrap();

    // Alice lists → 2
    let resp = client
        .get(format!("{}/v1/grant/list", h.broker_url))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["grants"].as_array().unwrap().len(), 2);

    // Bob lists → 1
    let resp = client
        .get(format!("{}/v1/grant/list", h.broker_url))
        .bearer_auth(&bob)
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["grants"].as_array().unwrap().len(), 1);
}
