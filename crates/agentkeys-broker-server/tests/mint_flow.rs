//! End-to-end tests for the broker's vertical slice:
//!   daemon bearer → broker /v1/mint-aws-creds → stub STS → temp creds.
//!
//! The mock-server is the source of truth for session validity. The STS
//! client is replaced with a stub so no test ever hits AWS.

use std::path::PathBuf;
use std::sync::Arc;

use agentkeys_broker_server::audit::{hash_token, AuditLog};
use agentkeys_broker_server::config::BrokerConfig;
use agentkeys_broker_server::create_router;
use agentkeys_broker_server::state::AppState;
use agentkeys_broker_server::sts::{AssumedCredentials, StsClient, StubStsClient};
use serde_json::Value;

const STUB_ROLE_ARN: &str = "arn:aws:iam::000000000000:role/agentkeys-agent";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-stub-AKID".into(),
        secret_access_key: "stub-secret".into(),
        session_token: "stub-session-token".into(),
        expiration_unix: 9_999_999_999,
    }
}

async fn spawn_mock_backend() -> String {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    agentkeys_mock_server::db::init_schema(&conn).unwrap();
    let state = Arc::new(agentkeys_mock_server::state::AppState::new(conn));
    let app = agentkeys_mock_server::create_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

async fn spawn_broker_with_sts(
    backend_url: String,
    sts: Arc<dyn StsClient>,
) -> (String, Arc<AppState>) {
    let config = BrokerConfig {
        daemon_access_key_id: "AKIA-fake".into(),
        daemon_secret_access_key: "fake-secret".into(),
        agent_role_arn: STUB_ROLE_ARN.into(),
        backend_url,
        audit_db_path: PathBuf::from(":memory:"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        backend_request_timeout_seconds: 5,
        shutdown_grace_seconds: 5,
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
    });
    let app = create_router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{}", addr), state)
}

async fn spawn_broker(backend_url: String) -> (String, Arc<AppState>) {
    spawn_broker_with_sts(backend_url, Arc::new(StubStsClient::ok(stub_creds()))).await
}

async fn mint_session_against_backend(backend_url: &str) -> (String, String) {
    let client = reqwest::Client::new();
    let resp: Value = client
        .post(format!("{}/session/create", backend_url))
        .json(&serde_json::json!({ "auth_token": "test-bearer-1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = resp["session"].as_str().unwrap().to_string();
    let wallet = resp["wallet"].as_str().unwrap().to_string();
    (session, wallet)
}

#[tokio::test]
async fn mint_aws_creds_happy_path_returns_creds_and_audits_ok() {
    let backend_url = spawn_mock_backend().await;
    let (session_token, wallet) = mint_session_against_backend(&backend_url).await;
    let (broker_url, broker_state) = spawn_broker(backend_url).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("Authorization", format!("Bearer {}", session_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["access_key_id"], "ASIA-stub-AKID");
    assert_eq!(body["wallet"], wallet);

    let row = broker_state.audit.last_row().unwrap().expect("audit row missing");
    assert_eq!(row.outcome, "ok");
    assert_eq!(row.requester_wallet, wallet);
    assert_eq!(row.requester_token_hash, hash_token(&session_token));
    assert!(row.outcome_detail.is_none());
}

#[tokio::test]
async fn mint_aws_creds_rejects_missing_bearer() {
    let backend_url = spawn_mock_backend().await;
    let (broker_url, _) = spawn_broker(backend_url).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mint_aws_creds_rejects_invalid_bearer_and_audits_auth_failed() {
    let backend_url = spawn_mock_backend().await;
    let (broker_url, broker_state) = spawn_broker(backend_url).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("Authorization", "Bearer this-token-was-never-minted")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let row = broker_state.audit.last_row().unwrap().expect("audit row missing");
    assert_eq!(row.outcome, "auth_failed");
    assert_eq!(row.requester_wallet, "unknown");
    assert!(row.outcome_detail.is_some());
}

#[tokio::test]
async fn mint_aws_creds_propagates_sts_error_and_audits_sts_error() {
    let backend_url = spawn_mock_backend().await;
    let (session_token, wallet) = mint_session_against_backend(&backend_url).await;
    let (broker_url, broker_state) = spawn_broker_with_sts(
        backend_url,
        Arc::new(StubStsClient::assume_failing("simulated AccessDenied")),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("Authorization", format!("Bearer {}", session_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "sts_error");

    let row = broker_state.audit.last_row().unwrap().expect("audit row missing");
    assert_eq!(row.outcome, "sts_error");
    assert_eq!(row.requester_wallet, wallet);
    assert!(row.outcome_detail.unwrap().contains("simulated AccessDenied"));
}

#[tokio::test]
async fn mint_aws_creds_handles_backend_unreachable() {
    // Backend at a port nobody is listening on.
    let dead_backend = "http://127.0.0.1:1".to_string();
    let (broker_url, broker_state) = spawn_broker(dead_backend).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/mint-aws-creds", broker_url))
        .header("Authorization", "Bearer anything")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "backend_unreachable");

    let row = broker_state.audit.last_row().unwrap().expect("audit row missing");
    // Backend down should show as backend_error in the audit log, NOT
    // auth_failed — operators chasing an outage need the distinction.
    assert_eq!(row.outcome, "backend_error");
    assert!(row.outcome_detail.is_some());
}

#[tokio::test]
async fn healthz_returns_ok_without_backend_round_trip() {
    let backend_url = spawn_mock_backend().await;
    let (broker_url, _) = spawn_broker(backend_url).await;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/healthz", broker_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn readyz_succeeds_when_backend_and_stub_sts_are_up() {
    let backend_url = spawn_mock_backend().await;
    let (broker_url, _) = spawn_broker(backend_url).await;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/readyz", broker_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn readyz_reports_503_when_sts_is_down() {
    let backend_url = spawn_mock_backend().await;
    let (broker_url, _) = spawn_broker_with_sts(
        backend_url,
        Arc::new(StubStsClient::failing("simulated bad creds")),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/readyz", broker_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["sts_ok"], false);
    assert_eq!(body["backend_ok"], true);
}

#[tokio::test]
async fn readyz_reports_503_when_backend_is_down() {
    let dead_backend = "http://127.0.0.1:1".to_string();
    let (broker_url, _) = spawn_broker(dead_backend).await;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/readyz", broker_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["backend_ok"], false);
}
