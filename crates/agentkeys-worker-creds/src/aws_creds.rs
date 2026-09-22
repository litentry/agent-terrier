//! Optional per-request AWS STS credentials passed via `X-Aws-*` headers.
//!
//! Architectural intent (arch.md §17.2 + issue #90 Q3): the broker is the
//! OIDC issuer; agents authenticate to the broker, the broker mints
//! STS creds via `AssumeRoleWithWebIdentity` tagged with the requesting
//! actor's omni. The agent forwards those creds to the worker for the
//! actual S3 op via three headers:
//!
//!   X-Aws-Access-Key-Id
//!   X-Aws-Secret-Access-Key
//!   X-Aws-Session-Token
//!
//! AWS IAM then enforces per-actor S3 scoping via `${aws:PrincipalTag/agentkeys_actor_omni}`
//! conditions (see `scripts/operator/cloud/provision-vault-role.sh`). The worker becomes
//! a passive credential relay — even a compromised worker can't read
//! another actor's data because the STS creds are scoped at the AWS
//! layer.
//!
//! Backwards compatible: when the three headers are absent, the worker
//! falls back to the default credential chain (EC2 instance profile),
//! preserving the existing stage-1 demo behavior.

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client as S3Client;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap, StatusCode},
};

/// Three header values that together form a single STS session credential.
/// Custom Debug impl (codex P3): default `#[derive(Debug)]` would log the
/// secret_access_key + session_token verbatim if anyone ever instrumented
/// the extractor with `tracing::debug!` / `dbg!`. Mask both.
#[derive(Clone)]
pub struct StsCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

impl std::fmt::Debug for StsCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only first/last 4 chars of access key (it's logged by AWS
        // anyway via CloudTrail). Fully redact secret + session token.
        let aki_len = self.access_key_id.len();
        let aki_preview = if aki_len > 8 {
            format!(
                "{}...{}",
                &self.access_key_id[..4],
                &self.access_key_id[aki_len - 4..]
            )
        } else {
            "<short>".to_string()
        };
        f.debug_struct("StsCreds")
            .field("access_key_id", &aki_preview)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .finish()
    }
}

impl StsCreds {
    /// Extract from a HeaderMap. Returns None if any of the three headers
    /// are missing (partial passthrough is an error — refuse to mint a
    /// half-authed S3 client).
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let access_key_id = headers
            .get("x-aws-access-key-id")?
            .to_str()
            .ok()?
            .to_string();
        let secret_access_key = headers
            .get("x-aws-secret-access-key")?
            .to_str()
            .ok()?
            .to_string();
        let session_token = headers
            .get("x-aws-session-token")?
            .to_str()
            .ok()?
            .to_string();
        if access_key_id.is_empty() || secret_access_key.is_empty() || session_token.is_empty() {
            return None;
        }
        Some(StsCreds {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    /// Build a per-request S3 client using these creds in the given region.
    /// The returned client is single-use; do NOT cache it across requests.
    pub async fn build_s3_client(&self, region: &str) -> S3Client {
        let creds = Credentials::new(
            self.access_key_id.clone(),
            self.secret_access_key.clone(),
            Some(self.session_token.clone()),
            None,
            "x-aws-creds-header",
        );
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .load()
            .await;
        // Per-request STS-cred client — same AWS↔TOS seam as the default client
        // so per-actor minted creds hit TOS on VE (honors AGENTKEYS_TOS_ENDPOINT).
        agentkeys_core::s3_endpoint::s3_client(&sdk_config)
    }
}

/// Axum extractor: pulls `Option<StsCreds>` from the request headers.
///
/// **Strict mode** (codex P2 — closes the downgrade-attack vector): when
/// `AGENTKEYS_WORKER_REQUIRE_STS=1` (or `=true`) is set in the worker's
/// environment, the extractor REJECTS requests missing any of the three
/// X-Aws-* headers with HTTP 401. This forces every request through the
/// OIDC federation path — no silent fallback to the broker EC2 instance
/// profile. Production deploys should set this; CI / stage-1 + stage-2
/// demos rely on the default (off) for backward compat.
///
/// Partial headers (1 or 2 of 3 present) ALWAYS reject with 401,
/// regardless of strict mode — a half-authed S3 client is never useful
/// and silently dropping the half-passed creds is the same downgrade
/// surface.
#[derive(Debug, Clone)]
pub struct OptionalStsCreds(pub Option<StsCreds>);

/// Read the strict-mode switch (`AGENTKEYS_WORKER_REQUIRE_STS=1|true`).
pub fn strict_sts_required() -> bool {
    std::env::var("AGENTKEYS_WORKER_REQUIRE_STS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The ONE credential-resolution verdict for a worker request, shared by the
/// [`OptionalStsCreds`] extractor and the handlers that can mint server-side
/// (#716 — the memory worker's own-namespace put/get redeem the delegate's cap
/// at the broker's `/v1/cap/own-sts` when the request carries a session
/// bearer instead of `X-Aws-*` headers).
///
/// - all three `X-Aws-*` headers → `Ok(Some(creds))` (the client relay);
/// - some but not all → 401 (a half-authed client is never useful, and
///   silently dropping the half is the downgrade surface);
/// - none, `server_side_mint_available` → `Ok(None)`: the handler mints its
///   own scoped creds — strict mode does NOT reject this, because the
///   server-side mint IS the OIDC federation path strict mode exists to force;
/// - none, strict → 401;
/// - none, lax → `Ok(None)`: the default credential chain (dev / stage-1).
pub fn resolve_sts_creds(
    headers: &HeaderMap,
    strict: bool,
    server_side_mint_available: bool,
) -> Result<Option<StsCreds>, (StatusCode, String)> {
    let has_any = headers.get("x-aws-access-key-id").is_some()
        || headers.get("x-aws-secret-access-key").is_some()
        || headers.get("x-aws-session-token").is_some();
    match (StsCreds::from_headers(headers), has_any) {
        (Some(c), _) => Ok(Some(c)),
        (None, true) => Err((
            StatusCode::UNAUTHORIZED,
            "partial X-Aws-* headers — must pass all three (X-Aws-Access-Key-Id, X-Aws-Secret-Access-Key, X-Aws-Session-Token) or none".to_string(),
        )),
        (None, false) if server_side_mint_available => Ok(None),
        (None, false) if strict => Err((
            StatusCode::UNAUTHORIZED,
            "AGENTKEYS_WORKER_REQUIRE_STS=1 — request must carry OIDC-minted STS creds via X-Aws-* headers".to_string(),
        )),
        (None, false) => Ok(None),
    }
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for OptionalStsCreds {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        resolve_sts_creds(&parts.headers, strict_sts_required(), false).map(OptionalStsCreds)
    }
}

/// Choose between a per-request STS client and the fallback default client.
/// If `override_creds` is Some, mints a per-request client (per-actor IAM
/// scoping). If None, clones the default client (S3Client clone is cheap —
/// internally Arc-shared SdkConfig).
pub async fn s3_for_request(
    default: &S3Client,
    region: &str,
    override_creds: Option<&StsCreds>,
) -> S3Client {
    match override_creds {
        Some(c) => c.build_s3_client(region).await,
        None => default.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn missing_headers_returns_none() {
        let h = HeaderMap::new();
        assert!(StsCreds::from_headers(&h).is_none());
    }

    #[test]
    fn partial_headers_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("x-aws-access-key-id", HeaderValue::from_static("AKIA..."));
        // missing secret + session token
        assert!(StsCreds::from_headers(&h).is_none());
    }

    #[test]
    fn all_three_headers_parse() {
        let mut h = HeaderMap::new();
        h.insert("x-aws-access-key-id", HeaderValue::from_static("AKIA..."));
        h.insert(
            "x-aws-secret-access-key",
            HeaderValue::from_static("secret"),
        );
        h.insert("x-aws-session-token", HeaderValue::from_static("token"));
        let c = StsCreds::from_headers(&h).unwrap();
        assert_eq!(c.access_key_id, "AKIA...");
        assert_eq!(c.secret_access_key, "secret");
        assert_eq!(c.session_token, "token");
    }

    #[test]
    fn empty_value_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("x-aws-access-key-id", HeaderValue::from_static(""));
        h.insert("x-aws-secret-access-key", HeaderValue::from_static("s"));
        h.insert("x-aws-session-token", HeaderValue::from_static("t"));
        assert!(StsCreds::from_headers(&h).is_none());
    }

    // codex P3: Debug must not leak secret_access_key or session_token.
    #[test]
    fn debug_redacts_secret_and_session_token() {
        let c = StsCreds {
            access_key_id: "ASIATESTKEY12345".to_string(),
            secret_access_key: "VERY-SECRET-DO-NOT-LOG".to_string(),
            session_token: "FwoGZXIvYXdzEEEa...".to_string(),
        };
        let dbg = format!("{:?}", c);
        assert!(
            !dbg.contains("VERY-SECRET-DO-NOT-LOG"),
            "Debug leaked secret_access_key"
        );
        assert!(
            !dbg.contains("FwoGZXIvYXdzEEEa"),
            "Debug leaked session_token"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug missing <redacted> marker"
        );
        // Access key prefix is OK (it's logged by AWS CloudTrail anyway).
        assert!(
            dbg.contains("ASIA"),
            "Debug should show access_key_id prefix"
        );
    }

    // #716 — the shared verdict the extractor and the server-side-mint handlers
    // both consult.
    #[test]
    fn resolver_verdicts_by_headers_strictness_and_server_side_mint() {
        let empty = HeaderMap::new();
        let mut partial = HeaderMap::new();
        partial.insert("x-aws-access-key-id", HeaderValue::from_static("AKIA"));
        let mut full = HeaderMap::new();
        full.insert("x-aws-access-key-id", HeaderValue::from_static("AKIA"));
        full.insert("x-aws-secret-access-key", HeaderValue::from_static("s"));
        full.insert("x-aws-session-token", HeaderValue::from_static("t"));

        // Full headers always win, whatever the mode.
        assert!(resolve_sts_creds(&full, true, true).unwrap().is_some());
        assert!(resolve_sts_creds(&full, false, false).unwrap().is_some());
        // Partial is ALWAYS 401 — even when a server-side mint would be possible.
        assert_eq!(
            resolve_sts_creds(&partial, false, true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            resolve_sts_creds(&partial, true, false).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        // No headers: strict without a server-side path → 401; strict WITH one
        // → the handler mints (None); lax → the default chain (None).
        assert_eq!(
            resolve_sts_creds(&empty, true, false).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        assert!(resolve_sts_creds(&empty, true, true).unwrap().is_none());
        assert!(resolve_sts_creds(&empty, false, false).unwrap().is_none());
    }

    // codex P2: extractor enforcement tests. We can't easily mock
    // axum's FromRequestParts machinery in a unit test, so just exercise
    // the underlying parser at the boundaries:
    #[test]
    fn parser_distinguishes_no_headers_from_partial() {
        let empty = HeaderMap::new();
        let mut partial = HeaderMap::new();
        partial.insert("x-aws-access-key-id", HeaderValue::from_static("AKIA"));

        assert!(StsCreds::from_headers(&empty).is_none());
        assert!(StsCreds::from_headers(&partial).is_none());

        // The extractor's job is to disambiguate: empty = backward-compat
        // (None ok unless strict), partial = ALWAYS reject. The detection
        // logic uses headers.get() presence, which we verify here:
        assert!(empty.get("x-aws-access-key-id").is_none());
        assert!(partial.get("x-aws-access-key-id").is_some());
    }
}
