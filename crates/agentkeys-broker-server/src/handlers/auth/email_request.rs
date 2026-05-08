//! `POST /v1/auth/email/request` — Phase A.1, US-018.
//!
//! Per plan §3.5.3: CLI initiates the email-link flow with `{email}`.
//! Broker mints a 32-byte token, persists `SHA256(token)` keyed by
//! `request_id`, mails the magic link via `EmailSender`, and returns
//! `{request_id, expires_in_seconds, poll_url}` so the CLI can poll
//! `/v1/auth/email/status/{request_id}` for the staged session JWT
//! once the user clicks.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::BrokerError;
use crate::plugins::auth::ChallengeParams;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct EmailRequestBody {
    pub email: String,
    /// Optional client-supplied IP for rate-limit bookkeeping. Phase D
    /// adds X-Forwarded-For-aware extraction; Phase A.1 trusts the
    /// caller's hint.
    pub source_ip: Option<String>,
}

pub async fn email_request(
    State(state): State<SharedState>,
    Json(body): Json<EmailRequestBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let plugin = state
        .registry
        .auth
        .get("email_link")
        .cloned()
        .ok_or_else(|| {
            BrokerError::BadRequest(
                "email_link auth method is not enabled (set BROKER_AUTH_METHODS=…,email_link)"
                    .to_string(),
            )
        })?;

    let challenge = plugin
        .challenge(ChallengeParams {
            source_ip: body.source_ip,
            extras: json!({ "email": body.email }),
        })
        .await
        .map_err(super::wallet_start_map_auth_err)?;

    let response = json!({
        "request_id":         challenge.request_id,
        "expires_in_seconds": challenge.expires_in_seconds,
        "poll_url":           challenge.extras.get("poll_url").cloned().unwrap_or(Value::Null),
    });
    Ok((StatusCode::OK, Json(response)))
}
