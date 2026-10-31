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
        auth::{local_outbox::LocalEmailOutbox, EmailLinkAuth, EmailSender, StubEmailSender},
        wallet::keystore::ClientSideKeystoreProvisioner,
        PluginRegistry,
    },
    state::{AppState, Tier2State},
    storage::{
        AuthNonceStore, EmailRateLimitStore, EmailTokenStore, IdentityLinkStore, SpawnContextStore,
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
    spawn_broker_with_access(Default::default()).await
}

async fn spawn_broker_with_access(
    login_access: agentkeys_broker_server::login_access::LoginAccess,
) -> (String, Arc<AppState>, Arc<StubEmailSender>) {
    spawn_broker_fixture(login_access, None, None).await
}

async fn spawn_broker_fixture(
    login_access: agentkeys_broker_server::login_access::LoginAccess,
    browser_origin: Option<&str>,
    delivery: Option<Arc<dyn EmailSender>>,
) -> (String, Arc<AppState>, Arc<StubEmailSender>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let oidc = OidcKeypair::generate_and_persist(&tmp.path().join("oidc.json")).unwrap();
    let session_kp =
        SessionKeypair::generate_and_persist(&tmp.path().join("session.json")).unwrap();

    let token_store = Arc::new(EmailTokenStore::open_in_memory().unwrap());
    let rl_store = Arc::new(EmailRateLimitStore::open_in_memory().unwrap());
    let sender = Arc::new(StubEmailSender::new());

    let plugin = Arc::new(
        EmailLinkAuth::new(
            delivery.unwrap_or_else(|| sender.clone()),
            Arc::clone(&token_store),
            Arc::clone(&rl_store),
            "broker@example.test",
            format!("{}/auth/email/landing", TEST_ISSUER),
            tmp.path().join("sender-verify.json"),
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

    auth_map.insert(
        "wallet_sig".into(),
        Arc::new(agentkeys_broker_server::plugins::auth::SiweWalletAuth::new(
            nonce_store.clone(),
            "broker.email.test",
            TEST_ISSUER,
        )),
    );
    let registry = Arc::new(PluginRegistry {
        auth: auth_map,
        wallet: Arc::new(ClientSideKeystoreProvisioner::new(Arc::clone(
            &wallet_store,
        ))),
        audit: vec![sqlite_anchor],
    });

    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));

    let signer_service =
        agentkeys_mock_server::dev_key_service::DevKeyService::from_master_secret([0x42; 32]);
    let signer_state = Arc::new(
        agentkeys_mock_server::state::AppState::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )
        .with_dev_signer(Some(signer_service))
        .with_broker_session_pubkey(Some(
            jsonwebtoken::DecodingKey::from_ec_components(
                &session_kp.public_x_b64,
                &session_kp.public_y_b64,
            )
            .unwrap(),
        )),
    );
    let signer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signer_url = format!("http://{}", signer_listener.local_addr().unwrap());
    let signer_router = agentkeys_mock_server::signer_browser_cors(
        agentkeys_mock_server::create_signer_router(signer_state),
        browser_origin.unwrap_or_default(),
    );
    tokio::spawn(async move {
        axum::serve(signer_listener, signer_router).await.unwrap();
    });
    let config = BrokerConfig {
        login_config: Some(agentkeys_protocol::auth::LoginConfig {
            chain_id: "212013".into(),
            signer_url,
            email_allowlist_enabled: login_access.is_restricted(),
        }),
        login_access,
        data_role_arn: "arn:aws:iam::000:role/test".into(),
        memory_role_arn: String::new(),
        speech_role_arn: String::new(),
        channel_role_arn: String::new(),
        channel_sts_token: String::new(),
        sts_provider: "aws".into(),
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
        client_id: agentkeys_broker_server::identity::DEFAULT_CLIENT_ID.to_string(),
        sts_audience: "sts.amazonaws.com".into(),
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
        spawn_context_store: Arc::new(SpawnContextStore::open_in_memory().unwrap()),
        wake_creates_in_flight: Default::default(),
        identity_link_store: Arc::new(IdentityLinkStore::open_in_memory().unwrap()),
        pairing_request_store: Arc::new(
            agentkeys_broker_server::storage::PairingRequestStore::open_in_memory().unwrap(),
        ),
        agent_delegation_store: Arc::new(
            agentkeys_broker_server::storage::AgentDelegationStore::open_in_memory().unwrap(),
        ),
        sandbox: None,
        accept_receipts: Default::default(),
        pending_ceremonies: Arc::new(
            agentkeys_broker_server::handlers::spawn::PendingCeremonyStore::new(),
        ),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: Arc::new(Tier2State::default()),
        email_link: Some(plugin.clone()),
        #[cfg(feature = "auth-oauth2")]
        oauth2: None,
    });

    let app = create_router(state.clone());
    let app =
        match agentkeys_broker_server::cors::browser_cors_layer(browser_origin.unwrap_or_default())
        {
            Some(layer) => app.layer(layer),
            None => app,
        };
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
    let temporary = TempDir::new().unwrap();
    let directory = temporary.path().join("outbox");
    let delivery =
        Arc::new(LocalEmailOutbox::from_configuration(true, None, directory.to_str()).unwrap());
    let (broker_url, _state, _sender) =
        spawn_broker_fixture(Default::default(), None, Some(delivery)).await;
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

    let message_path = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| !path.file_name().unwrap().to_str().unwrap().starts_with('.'))
        .unwrap();
    let original =
        agentkeys_core::protected_file::read_text(message_path.to_str().unwrap()).unwrap();
    let message: Value = serde_json::from_str(&original).unwrap();
    assert_eq!(message["recipient"], "alice@example.com");
    let landing = message["landing_url"].as_str().unwrap();
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
    let replay = client
        .post(format!("{broker_url}/v1/auth/email/verify"))
        .json(&serde_json::json!({"token":token}))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 401);
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
    let after = agentkeys_core::protected_file::read_text(message_path.to_str().unwrap()).unwrap();
    assert_eq!(original.as_str(), after.as_str());
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

fn allowlist(spec: &str) -> agentkeys_broker_server::login_access::LoginAccess {
    agentkeys_broker_server::login_access::LoginAccess::restricted(spec).unwrap()
}

#[tokio::test]
async fn allowlist_rejects_unapproved_email_before_sending() {
    let (url, _, sender) = spawn_broker_with_access(allowlist("alice@example.com")).await;
    let response = reqwest::Client::new()
        .post(format!("{url}/v1/auth/email/request"))
        .json(&serde_json::json!({"email":"mallory@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(sender.last_sent().is_none());
}

#[tokio::test]
async fn allowlist_email_login_uses_same_wallet_without_chain_or_registration() {
    let (url, state, sender) = spawn_broker_with_access(allowlist("alice@example.com")).await;
    let client = agentkeys_web_core::broker::BrokerClient::new(&url);
    let mut previous_omni = None;
    for _ in 0..2 {
        let challenge = client
            .hosted_email_request(" Alice@Example.com ")
            .await
            .unwrap();
        assert!(client
            .finish_email_login(&challenge.request_id)
            .await
            .unwrap()
            .is_none());
        let (_, landing) = sender.last_sent().unwrap();
        let token = landing.split_once("#t=").unwrap().1;
        let response = reqwest::Client::new()
            .post(format!("{url}/v1/auth/email/verify"))
            .json(&serde_json::json!({"token":token}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let session = client
            .finish_email_login(&challenge.request_id)
            .await
            .unwrap()
            .unwrap();
        let info = client.session_info(&session.session_jwt).await.unwrap();
        assert_eq!(info.omni_account, session.omni_account);
        assert_eq!(info.wallet_address, session.wallet_address);
        if let Some(previous) = &previous_omni {
            assert_eq!(previous, &info.omni_account);
        }
        previous_omni = Some(info.omni_account);
    }
    let identity = agentkeys_broker_server::identity::derive_with_client_id(
        &state.config.client_id,
        "email",
        "alice@example.com",
    );
    assert_eq!(
        state
            .identity_link_store
            .list_for_master(identity.as_str())
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn allowlist_denies_staged_tokens_from_a_removed_email() {
    use agentkeys_broker_server::plugins::auth::{ChallengeParams, UserAuthMethod};
    let (url, state, sender) = spawn_broker_with_access(allowlist("")).await;
    let plugin = state.email_link.as_ref().unwrap();
    let challenge = plugin
        .challenge(ChallengeParams {
            source_ip: None,
            extras: serde_json::json!({"email":"removed@example.com"}),
        })
        .await
        .unwrap();
    let (_, landing) = sender.last_sent().unwrap();
    let token = landing.split_once("#t=").unwrap().1;
    let response = reqwest::Client::new()
        .post(format!("{url}/v1/auth/email/verify"))
        .json(&serde_json::json!({"token":token}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let jwt = agentkeys_broker_server::jwt::issue::mint_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        "removed-omni",
        "",
        "email",
        "removed@example.com",
        300,
    )
    .unwrap();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;
    plugin
        .mark_verified(&challenge.request_id, &jwt, "removed-omni", expires_at)
        .unwrap();
    let response = reqwest::Client::new()
        .get(format!(
            "{url}/v1/auth/email/status/{}",
            challenge.request_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn allowlist_blocks_alternate_login_and_old_master_sessions() {
    let (url, state, _) = spawn_broker_with_access(allowlist("alice@example.com")).await;
    let client = reqwest::Client::new();
    let omni = "ab".repeat(32);
    let jwt = agentkeys_broker_server::jwt::issue::mint_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        &omni,
        "0x1111111111111111111111111111111111111111",
        "evm",
        "0x1111111111111111111111111111111111111111",
        300,
    )
    .unwrap();
    for path in ["/v1/auth/session", "/v1/wallet/links"] {
        let response = client
            .get(format!("{url}{path}"))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{path}");
    }
    for path in [
        "/v1/register/build",
        "/v1/register/submit",
        "/v1/accept/submit",
    ] {
        let response = client
            .post(format!("{url}{path}"))
            .bearer_auth(&jwt)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{path}");
    }
    let response = client
        .post(format!("{url}/v1/auth/passkey/start"))
        .json(&serde_json::json!({"omni_account":omni}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let response = client
        .post(format!("{url}/v1/auth/oauth2/start"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let response = client
        .get(format!("{url}/v1/auth/session"))
        .bearer_auth("forged")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn allowlist_hosted_client_refuses_an_unrestricted_broker_before_email() {
    let (url, _, sender) = spawn_broker().await;
    let client = agentkeys_web_core::broker::BrokerClient::new(url);
    assert!(client
        .hosted_email_request("alice@example.com")
        .await
        .is_err());
    assert!(sender.last_sent().is_none());
}

#[tokio::test]
async fn allowlist_verified_email_cannot_link_someone_elses_wallet() {
    let (url, state, _) = spawn_broker_with_access(allowlist("alice@example.com")).await;
    let identity = agentkeys_broker_server::identity::derive_with_client_id(
        &state.config.client_id,
        "email",
        "alice@example.com",
    );
    let token = agentkeys_broker_server::jwt::issue::mint_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        identity.as_str(),
        "",
        "email",
        "alice@example.com",
        300,
    )
    .unwrap();
    let response = reqwest::Client::new().post(format!("{url}/v1/wallet/link")).bearer_auth(token)
        .json(&serde_json::json!({"identity_type":"evm", "identity_value":"0x1111111111111111111111111111111111111111"})).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(state
        .identity_link_store
        .list_for_master(identity.as_str())
        .unwrap()
        .is_empty());
}

#[tokio::test]
#[ignore = "interactive browser fixture; loopback servers and stub email only"]
async fn hosted_browser_fixture() {
    let origin =
        std::env::var("AGENTKEYS_BROWSER_TEST_ORIGIN").expect("set browser fixture origin");
    let output = std::env::var("AGENTKEYS_BROWSER_TEST_OUTPUT").expect("set fixture output path");
    let (broker_url, _, sender) =
        spawn_broker_fixture(allowlist("alice@example.com"), Some(&origin), None).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
    while tokio::time::Instant::now() < deadline {
        let link = sender
            .last_sent()
            .map(|(_, link)| link.replace(TEST_ISSUER, &broker_url));
        std::fs::write(
            &output,
            serde_json::to_vec(
                &serde_json::json!({"broker_url":broker_url,"verification_link":link}),
            )
            .unwrap(),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn allowlist_valid_wallet_signature_cannot_bypass_email_approval() {
    let (url, _, _) = spawn_broker_with_access(allowlist("alice@example.com")).await;
    let signer =
        agentkeys_mock_server::dev_key_service::DevKeyService::from_master_secret([0x43; 32]);
    let omni = "cd".repeat(32);
    let address = signer.derive_address(&omni).unwrap();
    let client = reqwest::Client::new();
    let challenge: agentkeys_protocol::auth::WalletChallenge = client
        .post(format!("{url}/v1/auth/wallet/start"))
        .json(&agentkeys_protocol::auth::WalletStart {
            address,
            chain_id: 212013,
            source_ip: None,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (signature, _) = signer
        .sign_eip191(&omni, challenge.siwe_message.as_bytes())
        .unwrap();
    let response = client
        .post(format!("{url}/v1/auth/wallet/verify"))
        .json(&agentkeys_protocol::auth::WalletVerify {
            request_id: challenge.request_id,
            signature,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("session_jwt").is_none());
}
