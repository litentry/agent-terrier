//! `/v1/auth/email/*` integration tests — Phase A.1, US-018.
//!
//! Exercises the full email-link wire format end-to-end against an
//! in-process broker:
//! - `POST /v1/auth/email/request` → CLI gets `request_id`, broker
//!   sends magic link via StubEmailSender.
//! - `GET /auth/email/landing` → broker-hosted minimal HTML page,
//!   correct security headers.
//! - `POST /v1/auth/email/verify` (browser, body carries token) →
//!   200 ok + headers, status row marked verified.
//! - `GET /v1/auth/email/status/:request_id` (CLI poll) → 200 with
//!   session JWT after verify.
//! - GET on `/v1/auth/email/verify` → 405 (prefetch defense per
//!   plan §3.5.3).

#![cfg(feature = "auth-email-link")]

use std::collections::HashMap;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    config::BrokerConfig,
    create_router,
    jwt::SessionKeypair,
    oidc::OidcKeypair,
    plugins::{
        audit::{sqlite::SqliteAnchor, AuditAnchor, AuditPolicy},
        auth::{EmailLinkAuth, StubEmailSender},
        wallet::keystore::ClientSideKeystoreProvisioner,
        PluginRegistry,
    },
    state::{AppState, Tier2State},
    storage::{
        AuthNonceStore, EmailRateLimitStore, EmailTokenStore, GrantStore, IdentityLinkStore,
        WalletStore,
    },
    sts::{AssumedCredentials, StsClient, StubStsClient},
};
use serde_json::Value;
use tempfile::TempDir;

const TEST_ISSUER: &str = "https://broker.email.test";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-EMAIL".into(),
        secret_access_key: "email-secret".into(),
        session_token: "email-session".into(),
        expiration_unix: 9_999_999_999,
    }
}

async fn spawn_broker() -> (String, Arc<AppState>, Arc<StubEmailSender>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let oidc = OidcKeypair::generate_and_persist(&tmp.path().join("oidc.json")).unwrap();
    let session_kp =
        SessionKeypair::generate_and_persist(&tmp.path().join("session.json")).unwrap();

    let token_store = Arc::new(EmailTokenStore::open_in_memory().unwrap());
    let rl_store = Arc::new(EmailRateLimitStore::open_in_memory().unwrap());
    let sender = Arc::new(StubEmailSender::new());

    let plugin = Arc::new(
        EmailLinkAuth::new(
            sender.clone(),
            Arc::clone(&token_store),
            Arc::clone(&rl_store),
            "broker@example.test",
            format!("{}/auth/email/landing", TEST_ISSUER),
            tmp.path().join("ses-verify.json"),
            5,
            30,
        )
        .unwrap(),
    );

    let mut auth_map: HashMap<
        String,
        Arc<dyn agentkeys_broker_server::plugins::auth::UserAuthMethod>,
    > = HashMap::new();
    auth_map.insert("email_link".into(), plugin.clone() as _);

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
        email_link: Some(plugin.clone()),
        #[cfg(feature = "auth-oauth2")]
        oauth2: None,
    });

    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), state, sender)
}

#[tokio::test]
async fn email_request_returns_request_id_and_polls_pending() {
    let (broker_url, _state, sender) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/email/request", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"email":"alice@example.com"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    assert!(request_id.starts_with("eml-"));
    assert!(body["poll_url"].as_str().unwrap().contains(&request_id));

    // Email was "sent" — check the stub.
    let (to, landing) = sender.last_sent().expect("expected magic link to be sent");
    assert_eq!(to, "alice@example.com");
    assert!(landing.contains("#t="));

    // Poll status before the link is clicked → pending.
    let st = client
        .get(format!(
            "{}/v1/auth/email/status/{}",
            broker_url, request_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(st.status(), 200);
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "pending");
}

#[tokio::test]
async fn full_flow_browser_verify_then_cli_poll_returns_session_jwt() {
    let (broker_url, _state, sender) = spawn_broker().await;
    let client = reqwest::Client::new();

    // CLI initiates
    let resp = client
        .post(format!("{}/v1/auth/email/request", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"email":"alice@example.com"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();

    let (_, landing) = sender.last_sent().unwrap();
    let token = landing.split_once("#t=").unwrap().1.to_string();

    // Browser verifies
    let v = client
        .post(format!("{}/v1/auth/email/verify", broker_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"token":"{}"}}"#, token))
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), 200);
    assert_eq!(
        v.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(
        v.headers()
            .get("referrer-policy")
            .map(|v| v.to_str().unwrap()),
        Some("no-referrer")
    );
    let v_body: Value = v.json().await.unwrap();
    // CRITICAL: browser response must NOT carry the session JWT.
    assert!(v_body.get("session_jwt").is_none());
    assert_eq!(v_body["ok"], true);

    // CLI polls — now verified, response carries session JWT.
    let st = client
        .get(format!(
            "{}/v1/auth/email/status/{}",
            broker_url, request_id
        ))
        .send()
        .await
        .unwrap();
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "verified");
    assert!(st_body["session_jwt"].as_str().unwrap().starts_with("eyJ"));
    assert!(st_body["omni_account"].is_string());
}

#[tokio::test]
async fn verify_get_returns_405_method_not_allowed() {
    let (broker_url, _state, _sender) = spawn_broker().await;
    let client = reqwest::Client::new();
    // Magic-link prefetchers issue GET — broker MUST refuse.
    let resp = client
        .get(format!("{}/v1/auth/email/verify", broker_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    let allow = resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(allow.contains("POST"));
}

#[tokio::test]
async fn replay_token_returns_401() {
    let (broker_url, _state, sender) = spawn_broker().await;
    let client = reqwest::Client::new();

    client
        .post(format!("{}/v1/auth/email/request", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"email":"alice@example.com"}"#)
        .send()
        .await
        .unwrap();
    let (_, landing) = sender.last_sent().unwrap();
    let token = landing.split_once("#t=").unwrap().1.to_string();

    // First verify succeeds.
    let v1 = client
        .post(format!("{}/v1/auth/email/verify", broker_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"token":"{}"}}"#, token))
        .send()
        .await
        .unwrap();
    assert_eq!(v1.status(), 200);

    // Replay rejected.
    let v2 = client
        .post(format!("{}/v1/auth/email/verify", broker_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"token":"{}"}}"#, token))
        .send()
        .await
        .unwrap();
    assert_eq!(v2.status(), 401);
}

#[tokio::test]
async fn landing_page_serves_html_with_security_headers() {
    let (broker_url, _state, _sender) = spawn_broker().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/auth/email/landing", broker_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ctype.starts_with("text/html"));
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .map(|v| v.to_str().unwrap()),
        Some("no-referrer")
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("AgentKeys"));
    assert!(body.contains("/v1/auth/email/verify"));
    assert!(body.contains("window.location.hash"));
}

#[tokio::test]
async fn verify_with_garbage_token_returns_401() {
    let (broker_url, _state, _sender) = spawn_broker().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/auth/email/verify", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"token":"this-token-was-never-issued"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn unknown_request_id_returns_400() {
    let (broker_url, _state, _sender) = spawn_broker().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/v1/auth/email/status/req-never-existed",
            broker_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
