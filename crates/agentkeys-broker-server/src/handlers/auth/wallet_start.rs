//! `POST /v1/auth/wallet/start` — SIWE challenge endpoint.
//!
//! Per plan §3.5.1. Body: `{ "address": "0x…", "chain_id": <u64> }`.
//! Returns: `{ "request_id", "siwe_message", "nonce", "expires_at_iso" }`.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::BrokerError;
use crate::plugins::auth::{ChallengeParams, UserAuthMethod};
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct WalletStartRequest {
    pub address: String,
    pub chain_id: u64,
    /// Optional client-supplied IP for rate-limit bookkeeping. Real
    /// production source IP comes from the X-Forwarded-For chain plumbed
    /// through axum middleware (out of scope for Phase 0).
    pub source_ip: Option<String>,
}

pub async fn wallet_start(
    State(state): State<SharedState>,
    Json(body): Json<WalletStartRequest>,
) -> Result<impl IntoResponse, BrokerError> {
    let plugin = lookup_wallet_sig(&state)?;
    let challenge = plugin
        .challenge(ChallengeParams {
            source_ip: body.source_ip,
            extras: json!({
                "address": body.address,
                "chain_id": body.chain_id,
            }),
        })
        .await
        .map_err(map_auth_err)?;

    // Surface the SIWE message + request_id to the caller. The nonce +
    // expiry land in the body via `extras` per plan §3.5.1.
    let response = json!({
        "request_id":         challenge.request_id,
        "expires_in_seconds": challenge.expires_in_seconds,
        "siwe_message":       challenge.extras.get("siwe_message").cloned().unwrap_or(Value::Null),
        "nonce":              challenge.extras.get("nonce").cloned().unwrap_or(Value::Null),
        "expires_at_iso":     challenge.extras.get("expires_at_iso").cloned().unwrap_or(Value::Null),
    });
    Ok((StatusCode::OK, Json(response)))
}

fn lookup_wallet_sig(state: &SharedState) -> Result<std::sync::Arc<dyn UserAuthMethod>, BrokerError> {
    state
        .registry
        .auth
        .get("wallet_sig")
        .cloned()
        .ok_or_else(|| {
            BrokerError::BadRequest(
                "wallet_sig auth method is not enabled (set BROKER_AUTH_METHODS=wallet_sig,…)"
                    .to_string(),
            )
        })
}

pub fn map_auth_err(e: crate::plugins::auth::AuthError) -> BrokerError {
    use crate::plugins::auth::AuthError as A;
    match e {
        A::InvalidRequest(s) => BrokerError::BadRequest(s),
        A::Unauthorized(s) => BrokerError::Unauthorized(s),
        A::Expired(s) => BrokerError::Unauthorized(format!("expired: {}", s)),
        A::RateLimited(s) => BrokerError::BadRequest(format!("rate limited: {}", s)),
        A::Upstream(s) => BrokerError::BackendUnreachable(format!("upstream: {}", s)),
        A::Internal(s) => BrokerError::Internal(s),
    }
}
