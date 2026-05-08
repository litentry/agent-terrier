//! `POST /v1/auth/email/verify` — Phase A.1, US-018.
//!
//! Browser-side endpoint. The static landing page (`email_landing`)
//! reads the URL fragment `#t=<token>`, extracts the token, and POSTs
//! it here as the JSON body. Broker calls plugin.consume_token,
//! mints a session JWT bound to (omni_account, identity_type=Email,
//! identity_value=email), and stages the result via plugin.mark_verified.
//!
//! The endpoint EXPLICITLY rejects GET (405) so a magic link
//! prefetcher (email scanner, link-preview bot) cannot consume the
//! token by visiting the URL.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::env;
use crate::error::BrokerError;
use crate::identity::derive_omni_account;
use crate::jwt::issue::mint_session_jwt;
use crate::plugins::auth::IdentityType;
use crate::state::SharedState;
use crate::storage::EmailConsumeOutcome;

#[derive(Debug, Deserialize)]
pub struct EmailVerifyBody {
    pub token: String,
    /// The CLI's request_id is NOT in the URL fragment (only the token
    /// is). The landing page also doesn't have access to the request_id
    /// directly — but it's recoverable: the broker looks it up from
    /// the consumed token via `consume_token`'s outcome. So the body
    /// only needs `token`. We still accept an optional `request_id`
    /// for symmetry with US-022 OAuth2's verify body shape.
    #[serde(default)]
    pub request_id: Option<String>,
}

pub async fn email_verify(
    State(state): State<SharedState>,
    Json(body): Json<EmailVerifyBody>,
) -> Result<impl IntoResponse, BrokerError> {
    #[cfg(feature = "auth-email-link")]
    {
        let plugin = state
            .email_link
            .as_ref()
            .ok_or_else(|| {
                BrokerError::BadRequest(
                    "email_link auth method is not enabled".to_string(),
                )
            })?;

        // 1. Atomically consume the raw token.
        let outcome = plugin
            .consume_token(&body.token)
            .await
            .map_err(super::wallet_start_map_auth_err)?;
        let (request_id, email) = match outcome {
            EmailConsumeOutcome::Consumed { request_id, email } => (request_id, email),
            EmailConsumeOutcome::Expired => {
                return Err(BrokerError::Unauthorized(
                    "magic link expired (>10min after issued_at)".into(),
                ));
            }
            EmailConsumeOutcome::NotFoundOrConsumed => {
                return Err(BrokerError::Unauthorized(
                    "magic link unknown or already consumed".into(),
                ));
            }
        };
        // body.request_id (if provided) MUST match — defends against
        // an attacker who captured a token but not the original request.
        if let Some(claimed) = body.request_id {
            if claimed != request_id {
                return Err(BrokerError::Unauthorized(format!(
                    "request_id mismatch: token bound to {} but body claimed {}",
                    request_id, claimed
                )));
            }
        }

        // 2. Mint session JWT.
        let omni = derive_omni_account(IdentityType::Email.canonical(), &email);
        let ttl_seconds = std::env::var(env::BROKER_SESSION_JWT_TTL_SECONDS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(18_000);
        let token = mint_session_jwt(
            &state.session_keypair,
            &state.config.oidc_issuer,
            omni.as_str(),
            "",                                    // no wallet for email-only identity
            IdentityType::Email.canonical(),
            &email,
            ttl_seconds,
        )
        .map_err(|e| BrokerError::Internal(format!("mint session jwt: {}", e)))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let expires_at = now + ttl_seconds as i64;

        plugin
            .mark_verified(&request_id, &token, omni.as_str(), expires_at)
            .map_err(|e| BrokerError::Internal(format!("mark_verified: {}", e)))?;

        // 3. Browser response — minimal "verified" JSON; the landing
        //    page renders human-readable text. NO session JWT in this
        //    response (it lands on the CLI poll instead, plan §3.5.3).
        let mut headers = HeaderMap::new();
        headers.insert(
            "cache-control",
            HeaderValue::from_static("no-store"),
        );
        headers.insert(
            "referrer-policy",
            HeaderValue::from_static("no-referrer"),
        );
        Ok((
            StatusCode::OK,
            headers,
            Json(json!({ "ok": true })),
        ))
    }
    #[cfg(not(feature = "auth-email-link"))]
    {
        let _ = (state, body);
        Err(BrokerError::BadRequest(
            "auth-email-link feature is not compiled in".into(),
        ))
    }
}

/// `405 Method Not Allowed` handler for GET on the verify endpoint.
/// Magic-link prefetchers (link-preview bots, email scanners) issue
/// GETs, not POSTs — refusing GET is the load-bearing prefetch defense
/// from plan §3.5.3.
pub async fn email_verify_method_not_allowed() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [("allow", "POST")],
        "POST required; GET on this endpoint is rejected to defeat magic-link prefetchers",
    )
}
