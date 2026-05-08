//! `POST /v1/auth/exchange` — backward-compat shim per plan §3.5.7.
//!
//! Accepts the legacy backend-validated bearer (the existing
//! `BROKER_BACKEND_URL/session/validate` path that `crate::auth::extract_caller`
//! still consumes for /v1/mint-aws-creds during the cutover) and returns
//! a fresh session JWT bound to the same identity.
//!
//! Daemon/CLI calls this once at startup, caches the session JWT, and
//! uses the JWT for all subsequent `/v1/mint-*` requests. No
//! dual-accept on the mint endpoint after US-011 lands — closes
//! Codex P0 #14 (permanent dual auth surface).
//!
//! This shim itself is removed at v1.0 alongside the legacy bearer.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::auth::{extract_bearer_token, validate_bearer_token};
use crate::env;
use crate::error::BrokerError;
use crate::identity::derive_omni_account;
use crate::jwt::issue::mint_session_jwt;
use crate::state::SharedState;

pub async fn exchange(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BrokerError> {
    // Reuse the existing legacy bearer extraction path (which calls
    // BROKER_BACKEND_URL/session/validate). Returns the wallet address
    // bound to that session.
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    let token = extract_bearer_token(auth_header)
        .ok_or_else(|| BrokerError::Unauthorized("Authorization must be `Bearer <token>`".into()))?;
    let caller = validate_bearer_token(&state.http, &state.config.backend_url, token).await?;

    // Synthesize an OmniAccount from the legacy wallet address. Since
    // the legacy bearer only carries a wallet address (no email/oauth
    // identity), identity_type is "evm" and identity_value is the
    // wallet address.
    let identity_type = "evm";
    let identity_value = caller.wallet.clone();
    let omni = derive_omni_account(identity_type, &identity_value);

    let ttl_seconds = std::env::var(env::BROKER_SESSION_JWT_TTL_SECONDS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(18_000);
    let token = mint_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        omni.as_str(),
        &caller.wallet,
        identity_type,
        &identity_value,
        ttl_seconds,
    )
    .map_err(|e| BrokerError::Internal(format!("mint session jwt during exchange: {}", e)))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at = now + ttl_seconds;

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_jwt":     token,
            "session_jwt_kid": state.session_keypair.kid,
            "expires_at":      expires_at,
            "omni_account":    omni.as_str(),
            "wallet_address":  caller.wallet,
        })),
    ))
}
