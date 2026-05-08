//! `/v1/auth/oauth2/*` integration tests — Phase A.2, US-021/022.
//!
//! Exercises the full OAuth2 wire format end-to-end against an
//! in-process broker with a `StubOAuth2Provider` swapped in for Google:
//!
//! - `POST /v1/auth/oauth2/start` → CLI gets `request_id` +
//!   `authorization_url` carrying state HMAC + PKCE challenge + nonce.
//! - `GET /auth/oauth2/callback?code=…&state=…` → broker exchanges +
//!   verifies + mints session JWT + marks pending row verified.
//!   Returns minimal HTML, security headers, NO session JWT in body.
//! - `GET /v1/auth/oauth2/status/:request_id` (CLI poll) → 200 with
//!   session JWT once the callback completes.
//!
//! Negative cases: tampered state HMAC → 401; provider error → 200
//! HTML "Sign-in cancelled"; expired/wrong-aud id_token → 401 with
//! `failed` status surfacing on the poll.

#![cfg(feature = "auth-oauth2-google")]

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    config::BrokerConfig,
    create_router,
    jwt::SessionKeypair,
    oidc::OidcKeypair,
    plugins::{
        audit::{sqlite::SqliteAnchor, AuditAnchor, AuditPolicy},
        auth::{IdentityType, OAuth2Auth, OAuth2Provider, StubOAuth2Provider},
        wallet::keystore::ClientSideKeystoreProvisioner,
        PluginRegistry,
    },
    state::{AppState, Tier2State},
    storage::{AuthNonceStore, EmailRateLimitStore, OAuth2PendingStore, GrantStore, IdempotencyStore, IdentityLinkStore, WalletStore},
    sts::{AssumedCredentials, StsClient, StubStsClient},
};
use serde_json::Value;
use tempfile::TempDir;

const TEST_ISSUER: &str = "https://broker.oauth2.test";
const TEST_REDIRECT: &str = "https://broker.oauth2.test/auth/oauth2/callback";
const TEST_CLIENT_ID: &str = "test-google-client-id";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-OAUTH".into(),
        secret_access_key: "oauth-secret".into(),
        session_token: "oauth-session".into(),
        expiration_unix: 9_999_999_999,
    }
}

async fn spawn_broker() -> (String, Arc<AppState>, Arc<StubOAuth2Provider>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let oidc = OidcKeypair::generate_and_persist(&tmp.path().join("oidc.json")).unwrap();
    let session_kp =
        SessionKeypair::generate_and_persist(&tmp.path().join("session.json")).unwrap();

    let stub_provider = Arc::new(StubOAuth2Provider::new(
        "google",
        IdentityType::OAuth2Google,
        TEST_CLIENT_ID,
    ));
    let pending_store = Arc::new(OAuth2PendingStore::open_in_memory().unwrap());
    let rl_store = Arc::new(EmailRateLimitStore::open_in_memory().unwrap());

    let plugin = Arc::new(
        OAuth2Auth::new(
            stub_provider.clone() as Arc<dyn OAuth2Provider>,
            Arc::clone(&pending_store),
            Arc::clone(&rl_store),
            vec![0u8; 32],
            TEST_REDIRECT,
            30,
        )
        .unwrap(),
    );

    let mut auth_map: HashMap<String, Arc<dyn agentkeys_broker_server::plugins::auth::UserAuthMethod>> =
        HashMap::new();
    auth_map.insert("oauth2_google".into(), plugin.clone() as _);

    let wallet_store = Arc::new(WalletStore::open_in_memory().unwrap());
    let nonce_store = Arc::new(AuthNonceStore::open_in_memory().unwrap());
    let sqlite_anchor: Arc<dyn AuditAnchor> = Arc::new(SqliteAnchor::open_in_memory().unwrap());

    let registry = Arc::new(PluginRegistry {
        auth: auth_map,
        wallet: Arc::new(ClientSideKeystoreProvisioner::new(Arc::clone(&wallet_store))),
        audit: vec![sqlite_anchor],
    });

    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));

    let config = BrokerConfig {
        data_role_arn: "arn:aws:iam::000:role/test".into(),
        backend_url: "http://127.0.0.1:1".into(),
        audit_db_path: tmp.path().join("audit.sqlite"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        backend_request_timeout_seconds: 5,
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
        idempotency_store: Arc::new(IdempotencyStore::open_in_memory().unwrap()),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: Arc::new(Tier2State::default()),
        #[cfg(feature = "auth-email-link")]
        email_link: None,
        oauth2: Some(plugin.clone()),
    });
    state.tier2.backend_reachable.store(true, Ordering::Relaxed);

    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), state, stub_provider)
}

/// Extract a query-string arg from a URL string.
fn extract_query_arg(url: &str, arg: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    for kv in q.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == arg {
                return Some(urldecode(v));
            }
        }
    }
    None
}

fn urldecode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h * 16) + l) as u8);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

#[tokio::test]
async fn start_returns_authorization_url_and_pending_status() {
    let (broker_url, _state, _stub) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    assert!(request_id.starts_with("oa2-"));
    let auth_url = body["authorization_url"].as_str().unwrap();
    assert!(auth_url.contains("state="));
    assert!(auth_url.contains("nonce="));
    assert!(auth_url.contains("challenge=") || auth_url.contains("code_challenge="));
    assert!(body["poll_url"]
        .as_str()
        .unwrap()
        .contains(&request_id));

    // Poll status before callback → pending.
    let st = client
        .get(format!("{}/v1/auth/oauth2/status/{}", broker_url, request_id))
        .send()
        .await
        .unwrap();
    assert_eq!(st.status(), 200);
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "pending");
}

#[tokio::test]
async fn full_flow_callback_then_cli_poll_returns_session_jwt() {
    let (broker_url, _state, _stub) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let state = extract_query_arg(&auth_url, "state").expect("state");

    // Browser-side: provider redirects to broker callback.
    let cb = client
        .get(format!(
            "{}/auth/oauth2/callback?code=test-code&state={}",
            broker_url,
            urlencoding_encode(&state)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb.status(), 200);
    let html = cb.text().await.unwrap();
    assert!(html.contains("Verified"), "expected verified body, got: {}", html);

    // Headers — security posture.
    // (We re-request to inspect headers explicitly.)
    let cb2 = client
        .get(format!("{}/auth/oauth2/callback?code=ignored&state=invalid", broker_url))
        .send()
        .await
        .unwrap();
    assert_eq!(cb2.status(), 401);

    // CLI poll — verified.
    let st = client
        .get(format!("{}/v1/auth/oauth2/status/{}", broker_url, request_id))
        .send()
        .await
        .unwrap();
    assert_eq!(st.status(), 200);
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "verified");
    assert!(st_body["session_jwt"].as_str().unwrap().starts_with("eyJ"));
    assert_eq!(st_body["identity_type"], "oauth2_google");
    assert_eq!(st_body["identity_value"], "stub-sub-12345");
    assert!(!st_body["omni_account"]
        .as_str()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn callback_rejects_tampered_state_hmac() {
    let (broker_url, _state, _stub) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let mut state = extract_query_arg(&auth_url, "state").expect("state");

    // Flip the last char of the sig half.
    let last = state.pop().unwrap();
    let next = if last == 'A' { 'B' } else { 'A' };
    state.push(next);

    let cb = client
        .get(format!(
            "{}/auth/oauth2/callback?code=test-code&state={}",
            broker_url,
            urlencoding_encode(&state)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb.status(), 401);
}

#[tokio::test]
async fn callback_propagates_provider_error_to_status() {
    let (broker_url, _state, stub) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let state = extract_query_arg(&auth_url, "state").expect("state");

    // Simulate provider denial — Google would redirect with ?error=user_denied.
    let cb = client
        .get(format!(
            "{}/auth/oauth2/callback?error=user_denied&state={}",
            broker_url,
            urlencoding_encode(&state)
        ))
        .send()
        .await
        .unwrap();
    // Friendly HTML page, status 200, but the pending row is `failed`.
    assert_eq!(cb.status(), 200);
    let html = cb.text().await.unwrap();
    assert!(html.contains("cancelled"), "got: {}", html);

    let st = client
        .get(format!("{}/v1/auth/oauth2/status/{}", broker_url, request_id))
        .send()
        .await
        .unwrap();
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "failed");
    assert!(st_body["reason"].as_str().unwrap().contains("user_denied"));
    let _ = stub;
}

#[tokio::test]
async fn callback_rejects_replayed_code_state_pair() {
    let (broker_url, _state, _stub) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let state = extract_query_arg(&auth_url, "state").expect("state");

    let url = format!(
        "{}/auth/oauth2/callback?code=test-code&state={}",
        broker_url,
        urlencoding_encode(&state)
    );
    let first = client.get(&url).send().await.unwrap();
    assert_eq!(first.status(), 200);
    let replay = client.get(&url).send().await.unwrap();
    assert_eq!(replay.status(), 401);
}

#[tokio::test]
async fn callback_propagates_expired_id_token_as_failed_status() {
    let (broker_url, _state, stub) = spawn_broker().await;
    use agentkeys_broker_server::plugins::auth::OAuth2Error;
    stub.set_canned_verify(Err(OAuth2Error::Expired));
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let state = extract_query_arg(&auth_url, "state").expect("state");

    let cb = client
        .get(format!(
            "{}/auth/oauth2/callback?code=test-code&state={}",
            broker_url,
            urlencoding_encode(&state)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb.status(), 401);

    // CLI poll should see `failed` so the user-facing error is structured.
    let st = client
        .get(format!("{}/v1/auth/oauth2/status/{}", broker_url, request_id))
        .send()
        .await
        .unwrap();
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "failed");
    assert!(st_body["reason"].as_str().unwrap().to_lowercase().contains("expired"));
}

#[tokio::test]
async fn callback_propagates_wrong_aud_as_failed_status() {
    let (broker_url, _state, stub) = spawn_broker().await;
    use agentkeys_broker_server::plugins::auth::OAuth2Error;
    stub.set_canned_verify(Err(OAuth2Error::WrongAud));
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let state = extract_query_arg(&auth_url, "state").expect("state");

    let _cb = client
        .get(format!(
            "{}/auth/oauth2/callback?code=test-code&state={}",
            broker_url,
            urlencoding_encode(&state)
        ))
        .send()
        .await
        .unwrap();

    let st = client
        .get(format!("{}/v1/auth/oauth2/status/{}", broker_url, request_id))
        .send()
        .await
        .unwrap();
    let st_body: Value = st.json().await.unwrap();
    assert_eq!(st_body["status"], "failed");
    assert!(st_body["reason"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("audience"));
}

#[tokio::test]
async fn callback_carries_security_headers_on_success() {
    let (broker_url, _state, _stub) = spawn_broker().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"google"}"#)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let auth_url = body["authorization_url"].as_str().unwrap().to_string();
    let state = extract_query_arg(&auth_url, "state").expect("state");

    let cb = client
        .get(format!(
            "{}/auth/oauth2/callback?code=test-code&state={}",
            broker_url,
            urlencoding_encode(&state)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb.status(), 200);
    let headers = cb.headers().clone();
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    let ct = headers.get("content-type").unwrap().to_str().unwrap();
    assert!(ct.starts_with("text/html"));

    // Body must NOT contain the session JWT.
    let html = cb.text().await.unwrap();
    assert!(
        !html.contains("eyJ"),
        "session JWT must not appear in browser response"
    );
}

#[tokio::test]
async fn unknown_provider_returns_bad_request() {
    let (broker_url, _state, _stub) = spawn_broker().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/auth/oauth2/start", broker_url))
        .header("content-type", "application/json")
        .body(r#"{"provider":"github"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// Tiny URL-encoder for query values — only handles the chars our test
/// state token may produce ('=', '+', and base64url chars).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if (b as char).is_ascii_alphanumeric()
            || b == b'-'
            || b == b'.'
            || b == b'_'
            || b == b'~'
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
