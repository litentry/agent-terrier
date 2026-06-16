//! AWS-cred fetch helper for the Stage 7 broker.
//!
//! Two-step daemon-side mint: fetch OIDC JWT from the broker, then exchange
//! it for short-lived AWS credentials via `AssumeRoleWithWebIdentity`
//! client-side. The JWT authenticates the STS call, so neither the broker
//! nor the daemon needs an IAM principal at runtime.
//!
//! Issue: <https://github.com/litentry/agentKeys/issues/71> (Option A).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_config::BehaviorVersion;
use aws_sdk_sts::config::Region;
use serde::Deserialize;

use crate::error::{ProvisionError, ProvisionResult};

/// Broker `POST /v1/mint-oidc-jwt` response shape. Mirrors
/// `crates/agentkeys-broker-server/src/handlers/oidc.rs::MintOidcJwtResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcJwtResponse {
    pub jwt: String,
    pub wallet: String,
    /// Unix-epoch-seconds expiration of the JWT itself, NOT the assumed-role
    /// session. JWT TTL is short (~5 min default); the assumed-role session
    /// has its own (1h-default) TTL set at AssumeRoleWithWebIdentity time.
    pub expiration: i64,
}

/// Final temp-cred shape passed to the scraper subprocess. The struct fields
/// match the response shape of the legacy `/v1/mint-aws-creds` route (deleted
/// in PR #96 / issue #72) so callers that already consume
/// `AwsTempCreds.to_env(...)` need no changes during the migration to the
/// daemon-side mint path.
#[derive(Debug, Clone)]
pub struct AwsTempCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// Unix epoch seconds. `duration_seconds` controls this — defaults to
    /// 3600 (1h). AWS caps the value at the role's MaxSessionDuration.
    pub expiration: i64,
    /// Wallet that authenticates the assumed session (the
    /// `agentkeys_user_wallet` PrincipalTag is set to this value).
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
        m.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            self.secret_access_key.clone(),
        );
        m.insert("AWS_SESSION_TOKEN".into(), self.session_token.clone());
        // Issue #83 — expose the operator's wallet so the scraper can
        // (a) build a routable signup email (`or-${wallet}-${ts}@…`)
        //     that the SES routing Lambda will move into
        //     `bots/${wallet}/inbound/`, and
        // (b) tell the email backend which per-wallet prefix to poll
        //     once the Lambda has routed.
        // Always lowercased (matches `aws_creds.rs:194` + the S3 path).
        m.insert("AGENTKEYS_USER_WALLET".into(), self.wallet.to_lowercase());
        if let Some(r) = region {
            m.insert("AWS_REGION".into(), r.to_string());
            m.insert("AWS_DEFAULT_REGION".into(), r.to_string());
        }
        m
    }
}

/// Fetch an OIDC JWT from the broker. The bearer is the daemon's own session
/// token (validated by the broker's session backend). Pulled out of
/// `fetch_via_broker` so unit tests can exercise the HTTP / bearer / parsing
/// half against an axum stub without needing to mock STS.
pub async fn fetch_oidc_jwt(
    broker_url: &str,
    session_token: &str,
) -> ProvisionResult<OidcJwtResponse> {
    let url = format!("{}/v1/mint-oidc-jwt", broker_url.trim_end_matches('/'));
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
            status, body
        )));
    }

    resp.json::<OidcJwtResponse>()
        .await
        .map_err(|e| ProvisionError::Internal(format!("parse broker jwt response: {e}")))
}

/// End-to-end caller: fetch the JWT from the broker, exchange it for AWS temp
/// creds via `AssumeRoleWithWebIdentity`, return the creds.
///
/// `role_arn` is the federated role configured in `cloud-setup.md §4.3` (e.g.
/// `arn:aws:iam::ACCOUNT:role/agentkeys-data-role`). The operator passes this
/// in via daemon env — typically `AGENTKEYS_DATA_ROLE_ARN` — because each
/// AgentKeys deployment has its own role ARN.
///
/// `region` is the AWS region for STS calls. STS is a global service but the
/// SDK still wants a region for endpoint resolution. `us-east-1` is fine
/// unless your role is region-restricted.
///
/// `session_duration_seconds`: caller controls the AWS-creds TTL. AWS clamps
/// to the role's `MaxSessionDuration` (default 3600s).
///
/// The STS client is built with **anonymous credentials** — the JWT
/// authenticates the call, the daemon needs zero AWS principals.
pub async fn fetch_via_broker(
    broker_url: &str,
    session_token: &str,
    role_arn: &str,
    region: &str,
    session_duration_seconds: i32,
) -> ProvisionResult<AwsTempCreds> {
    fetch_via_broker_with_sts_endpoint(
        broker_url,
        session_token,
        role_arn,
        region,
        session_duration_seconds,
        None,
    )
    .await
}

/// Like [`fetch_via_broker`] but with an explicit STS endpoint override
/// (same effect as the SDK's `AWS_ENDPOINT_URL_STS` env var, minus the
/// process-global env — tests inject a dead endpoint here instead of
/// `set_var`, which leaks across parallel test threads). `None` ⇒ the
/// SDK default resolution (real AWS, or whatever the ambient env says).
pub async fn fetch_via_broker_with_sts_endpoint(
    broker_url: &str,
    session_token: &str,
    role_arn: &str,
    region: &str,
    session_duration_seconds: i32,
    sts_endpoint_url: Option<&str>,
) -> ProvisionResult<AwsTempCreds> {
    let jwt_resp = fetch_oidc_jwt(broker_url, session_token).await?;
    assume_role_with_jwt(
        &jwt_resp.jwt,
        &jwt_resp.wallet,
        role_arn,
        region,
        session_duration_seconds,
        sts_endpoint_url,
        None,
    )
    .await
}

/// Convenience overload that defaults `session_duration_seconds` to 3600 (1h).
pub async fn fetch_via_broker_default_ttl(
    broker_url: &str,
    session_token: &str,
    role_arn: &str,
    region: &str,
) -> ProvisionResult<AwsTempCreds> {
    fetch_via_broker(broker_url, session_token, role_arn, region, 3600).await
}

/// Like [`fetch_via_broker_default_ttl`] but attaches an inline AssumeRole
/// **session policy** (#295 P1 §7a) — used by a delegated canonical-memory
/// READ to scope the relayed operator STS down to read-only (`s3:GetObject`),
/// so it cannot write or delete the master's canonical prefix even though the
/// underlying memory role is prefix-wide R/W. `session_policy = None` is
/// identical to `fetch_via_broker_default_ttl`.
pub async fn fetch_via_broker_scoped_default_ttl(
    broker_url: &str,
    session_token: &str,
    role_arn: &str,
    region: &str,
    session_policy: Option<&str>,
) -> ProvisionResult<AwsTempCreds> {
    let jwt_resp = fetch_oidc_jwt(broker_url, session_token).await?;
    assume_role_with_jwt(
        &jwt_resp.jwt,
        &jwt_resp.wallet,
        role_arn,
        region,
        3600,
        None,
        session_policy,
    )
    .await
}

/// Run `AssumeRoleWithWebIdentity` against the live AWS STS endpoint with the
/// given JWT and return the temp creds. Anonymous SDK config — no AWS creds
/// required on this side.
/// Run `sts:AssumeRoleWithWebIdentity` with a caller-supplied OIDC JWT, optional
/// STS endpoint override, and optional inline session policy. Public so the
/// **broker** (#295 P1 §7a) can mint an operator-tagged OIDC internally and
/// AssumeRole with a read-only, exact-object session policy WITHOUT ever handing
/// the delegate the operator session bearer (the Codex-flagged critical fix).
pub async fn assume_role_with_jwt(
    jwt: &str,
    wallet: &str,
    role_arn: &str,
    region: &str,
    session_duration_seconds: i32,
    sts_endpoint_url: Option<&str>,
    // #295 P1 §7a: an optional inline AssumeRole **session policy** (max 2048
    // chars). AWS makes the effective permission the INTERSECTION of the role's
    // identity policy and this — so a read-only (`s3:GetObject`) session policy
    // turns a prefix-wide read+write memory role into read-only, the scope-down
    // a delegated canonical read needs so a relayed STS can't write/delete the
    // master's canonical prefix. `None` ⇒ full role permissions (existing paths).
    session_policy: Option<&str>,
) -> ProvisionResult<AwsTempCreds> {
    // Anonymous SDK config — the JWT authenticates AssumeRoleWithWebIdentity.
    // TODO: replace `AnonymousCredentials` with `.no_credentials()` once we
    // bump aws-config to 1.5+ (the helper isn't in 1.0–1.4).
    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(AnonymousCredentials);
    if let Some(url) = sts_endpoint_url {
        loader = loader.endpoint_url(url);
    }
    let config = loader.load().await;
    let client = aws_sdk_sts::Client::new(&config);

    let session_name = build_session_name(wallet);
    let resp = client
        .assume_role_with_web_identity()
        .role_arn(role_arn)
        .role_session_name(&session_name)
        .web_identity_token(jwt)
        .duration_seconds(session_duration_seconds)
        .set_policy(session_policy.map(|s| s.to_string()))
        .send()
        .await
        .map_err(|e| {
            // `aws_sdk_sts::Error`'s Display impl renders only the top-level
            // variant — for `DispatchFailure` this is the useless literal
            // string "dispatch failure" with no hint of WHY. The actual
            // cause (DNS / TCP / TLS / connector-not-configured) lives in
            // the `source()` chain. Walk it + flatten into a one-line msg
            // so operators can act without grep'ing for SDK debug logs.
            let mut msg = format!("assume_role_with_web_identity({role_arn}): {e}");
            let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
            while let Some(next) = src {
                msg.push_str(&format!(" | caused by: {next}"));
                src = next.source();
            }
            ProvisionError::Internal(msg)
        })?;

    let creds = resp
        .credentials
        .ok_or_else(|| ProvisionError::Internal("STS returned no credentials".into()))?;

    Ok(AwsTempCreds {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration.secs(),
        wallet: wallet.to_lowercase(),
    })
}

/// Wallet → STS session name (max 64 chars; alphanumeric + `=,.@-_`).
/// Daemon-side STS calls only — the server-side mint path was deleted in
/// PR #96 (issue #72), so this is the sole producer of STS session names
/// in the system. The trailing micro-second timestamp gives every call a
/// unique session name even when the same wallet mints in rapid succession;
/// without it AWS returns the same temp creds for repeated calls within the
/// `DurationSeconds` window (subtle caching footgun called out in critic M1).
fn build_session_name(wallet: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let micros = now.subsec_micros();
    let safe_wallet: String = wallet
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_'))
        .take(40)
        .collect();
    let mut name = format!("agentkeys-{}-{}-{:06}", safe_wallet, secs, micros);
    if name.len() > 64 {
        name.truncate(64);
    }
    name
}

/// `ProvideCredentials` impl that always returns `Err(NoCredentials)`.
/// Used by `assume_role_with_jwt` because `AssumeRoleWithWebIdentity` is
/// JWT-authenticated and the SDK never invokes the resolver for it.
#[derive(Debug)]
struct AnonymousCredentials;

impl aws_credential_types::provider::ProvideCredentials for AnonymousCredentials {
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_credential_types::provider::future::ProvideCredentials::ready(Err(
            aws_credential_types::provider::error::CredentialsError::not_loaded(
                "anonymous (AssumeRoleWithWebIdentity uses JWT auth)",
            ),
        ))
    }
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

    #[test]
    fn build_session_name_matches_broker_format() {
        // STS session-name format invariant — daemon-side only since PR #96
        // deleted the broker's handlers/mint.rs (issue #72) (critic M1).
        let name = build_session_name("0xAbCdEf0123456789ABCDEF0123456789AbCdEf0123456789");
        assert!(name.starts_with("agentkeys-"));
        assert!(name.len() <= 64, "STS rejects session names >64 chars");
        // Includes the unix-secs + micros suffix so rapid same-wallet mints
        // get distinct session names.
        assert!(
            name.matches('-').count() >= 3,
            "expected at least 3 dashes, got {}",
            name
        );
    }

    #[test]
    fn build_session_name_strips_unsafe_chars() {
        let n = build_session_name("0xABC/123 weird");
        assert!(!n.contains('/'));
        assert!(!n.contains(' '));
    }

    #[test]
    fn build_session_name_handles_empty_wallet() {
        let n = build_session_name("");
        assert!(n.starts_with("agentkeys--"));
    }

    // ---- HTTP-side tests for fetch_oidc_jwt against an axum stub ----

    #[tokio::test]
    async fn fetch_oidc_jwt_happy_path() {
        let server = stub_broker_server(StubResponse::OkJwt).await;
        let resp = fetch_oidc_jwt(&server.url, "session-token").await.unwrap();
        assert!(resp.jwt.starts_with("eyJ"), "expected JWT-shaped string");
        assert_eq!(resp.wallet, "0xtest");
        assert_eq!(resp.expiration, 9_999_999_999);
    }

    #[tokio::test]
    async fn fetch_oidc_jwt_propagates_unauthorized() {
        let server = stub_broker_server(StubResponse::Unauthorized).await;
        let err = fetch_oidc_jwt(&server.url, "bogus")
            .await
            .expect_err("expected error on 401");
        let msg = err.to_string();
        assert!(
            msg.contains("401") || msg.contains("Unauthorized"),
            "msg = {msg}"
        );
    }

    #[tokio::test]
    async fn fetch_oidc_jwt_handles_unreachable_broker() {
        // Port 1 is reserved; nothing listens there.
        let err = fetch_oidc_jwt("http://127.0.0.1:1", "tok")
            .await
            .expect_err("expected error on unreachable broker");
        assert!(err.to_string().contains("broker request"));
    }

    enum StubResponse {
        OkJwt,
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
            StubResponse::OkJwt => Router::new().route(
                "/v1/mint-oidc-jwt",
                post(|| async {
                    Json(json!({
                        "jwt": "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzdHViIn0.fake-sig",
                        "wallet": "0xtest",
                        "expiration": 9_999_999_999_i64,
                    }))
                }),
            ),
            StubResponse::Unauthorized => Router::new().route(
                "/v1/mint-oidc-jwt",
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
