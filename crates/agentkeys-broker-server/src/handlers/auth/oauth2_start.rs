//! `POST /v1/auth/oauth2/start` — Phase A.2, US-021.
//!
//! Per plan §3.5.4. CLI initiates the OAuth2 flow. Body: `{provider}`
//! (defaults to `google`). Broker mints PKCE verifier + state HMAC,
//! persists the pending row, and returns the provider-specific
//! `authorization_url` plus the `request_id` and `poll_url` so the CLI
//! can keep polling for the eventual session JWT.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::BrokerError;
use crate::plugins::auth::ChallengeParams;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct OAuth2StartBody {
    /// Provider name (e.g. `"google"`). Defaults to `"google"` for v0.
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional client-supplied IP for the per-IP rate limiter
    /// (Phase D adds X-Forwarded-For-aware extraction).
    #[serde(default)]
    pub source_ip: Option<String>,
}

pub async fn oauth2_start(
    State(state): State<SharedState>,
    Json(body): Json<OAuth2StartBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let provider = body
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("google");
    let plugin_name = format!("oauth2_{}", provider);
    let plugin = state.registry.auth.get(&plugin_name).cloned().ok_or_else(|| {
        BrokerError::BadRequest(format!(
            "oauth2 provider {:?} not enabled (set BROKER_AUTH_METHODS=…,oauth2_{} and feature auth-oauth2-{})",
            provider, provider, provider
        ))
    })?;

    let challenge = plugin
        .challenge(ChallengeParams {
            source_ip: body.source_ip,
            extras: json!({}),
        })
        .await
        .map_err(super::wallet_start_map_auth_err)?;

    let response = json!({
        "request_id":         challenge.request_id,
        "expires_in_seconds": challenge.expires_in_seconds,
        "authorization_url":  challenge.extras.get("authorization_url").cloned().unwrap_or(Value::Null),
        "poll_url":           challenge.extras.get("poll_url").cloned().unwrap_or(Value::Null),
        "provider":           challenge.extras.get("provider").cloned().unwrap_or(Value::Null),
    });
    Ok((StatusCode::OK, Json(response)))
}
