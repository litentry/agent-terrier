//! AWS-cred fetch helper for the Stage 7 broker.
//!
//! When the daemon (or CLI) is run with `--broker-url`, the operator no longer
//! has to source `scripts/stage6-demo-env.sh`. Instead, the provisioner asks the
//! broker for 1-hour scoped temp credentials right before spawning a scraper
//! subprocess, and injects them as `AWS_*` env vars into the child's environment.
//!
//! Behavior is opt-in: pass `BrokerCreds::None` (the default when no broker URL
//! is configured) and the subprocess inherits whatever `AWS_*` env the operator
//! already exported manually.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{ProvisionError, ProvisionResult};

/// Shape of the broker's `POST /v1/mint-aws-creds` response. Keep in sync with
/// `crates/agentkeys-broker-server/src/handlers/mint.rs::MintResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct AwsTempCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// Unix epoch seconds. The broker's session_duration_seconds caps this
    /// (1h default).
    pub expiration: i64,
    pub wallet: String,
}

impl AwsTempCreds {
    /// Render the creds as a `HashMap<String,String>` suitable for merging
    /// into a `tokio::process::Command` env. Adds the AWS region only when
    /// supplied — leaving it unset lets the subprocess fall back to `AWS_REGION`
    /// already in its environment.
    pub fn to_env(&self, region: Option<&str>) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("AWS_ACCESS_KEY_ID".into(), self.access_key_id.clone());
        m.insert("AWS_SECRET_ACCESS_KEY".into(), self.secret_access_key.clone());
        m.insert("AWS_SESSION_TOKEN".into(), self.session_token.clone());
        if let Some(r) = region {
            m.insert("AWS_REGION".into(), r.to_string());
            m.insert("AWS_DEFAULT_REGION".into(), r.to_string());
        }
        m
    }
}

/// Caller-side fetch. Bearer token is the daemon's own session token, which the
/// broker validates against the backend's `/session/validate` endpoint before
/// minting. Errors are mapped to `ProvisionError::Internal` because they sit
/// upstream of the subprocess spawn — the per-step tripwire/store/error codes
/// don't apply here.
pub async fn fetch_via_broker(
    broker_url: &str,
    session_token: &str,
) -> ProvisionResult<AwsTempCreds> {
    let url = format!(
        "{}/v1/mint-aws-creds",
        broker_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| ProvisionError::Internal(format!("build broker http client: {e}")))?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session_token))
        .send()
        .await
        .map_err(|e| ProvisionError::Internal(format!("broker request to {url} failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ProvisionError::Internal(format!(
            "broker {url} returned HTTP {}: {}",
            status,
            body
        )));
    }

    resp.json::<AwsTempCreds>()
        .await
        .map_err(|e| ProvisionError::Internal(format!("parse broker response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_env_emits_three_aws_keys() {
        let creds = AwsTempCreds {
            access_key_id: "ASIA-test".into(),
            secret_access_key: "secret".into(),
            session_token: "tok".into(),
            expiration: 0,
            wallet: "0xabc".into(),
        };
        let env = creds.to_env(None);
        assert_eq!(env.get("AWS_ACCESS_KEY_ID").unwrap(), "ASIA-test");
        assert_eq!(env.get("AWS_SECRET_ACCESS_KEY").unwrap(), "secret");
        assert_eq!(env.get("AWS_SESSION_TOKEN").unwrap(), "tok");
        assert!(!env.contains_key("AWS_REGION"));
    }

    #[test]
    fn to_env_includes_region_when_given() {
        let creds = AwsTempCreds {
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            session_token: "t".into(),
            expiration: 0,
            wallet: "0xabc".into(),
        };
        let env = creds.to_env(Some("us-east-1"));
        assert_eq!(env.get("AWS_REGION").unwrap(), "us-east-1");
        assert_eq!(env.get("AWS_DEFAULT_REGION").unwrap(), "us-east-1");
    }

    #[tokio::test]
    async fn fetch_via_broker_happy_path() {
        let server = stub_broker_server(StubResponse::Ok).await;
        let creds = fetch_via_broker(&server.url, "session-token").await.unwrap();
        assert_eq!(creds.access_key_id, "ASIA-stub");
        assert_eq!(creds.wallet, "0xtest");
    }

    #[tokio::test]
    async fn fetch_via_broker_propagates_unauthorized() {
        let server = stub_broker_server(StubResponse::Unauthorized).await;
        let err = fetch_via_broker(&server.url, "bogus")
            .await
            .expect_err("expected error on 401");
        let msg = err.to_string();
        assert!(msg.contains("401") || msg.contains("Unauthorized"), "msg = {msg}");
    }

    #[tokio::test]
    async fn fetch_via_broker_handles_unreachable_broker() {
        // Port 1 is reserved; nothing listens there.
        let err = fetch_via_broker("http://127.0.0.1:1", "tok")
            .await
            .expect_err("expected error on unreachable broker");
        assert!(err.to_string().contains("broker request"));
    }

    enum StubResponse {
        Ok,
        Unauthorized,
    }

    struct StubServer {
        url: String,
        _handle: tokio::task::JoinHandle<()>,
    }

    async fn stub_broker_server(response: StubResponse) -> StubServer {
        use axum::{routing::post, Json, Router};
        use serde_json::json;

        let router = match response {
            StubResponse::Ok => Router::new().route(
                "/v1/mint-aws-creds",
                post(|| async {
                    Json(json!({
                        "access_key_id": "ASIA-stub",
                        "secret_access_key": "stub-secret",
                        "session_token": "stub-token",
                        "expiration": 9_999_999_999_i64,
                        "wallet": "0xtest",
                    }))
                }),
            ),
            StubResponse::Unauthorized => Router::new().route(
                "/v1/mint-aws-creds",
                post(|| async {
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"error":"unauthorized","message":"bad bearer"})),
                    )
                }),
            ),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        StubServer {
            url: format!("http://{}", addr),
            _handle: handle,
        }
    }
}
