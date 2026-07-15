//! `POST /v1/auth/wallet/verify` — SIWE verify endpoint.
//!
//! Per plan §3.5.1. Body: `{ "request_id", "signature": "0x…<130 hex>" }`.
//! On success: registers a wallet binding (idempotent), mints a session
//! JWT bound to (omni_account, wallet_address), returns:
//! `{ "session_jwt", "session_jwt_kid", "expires_at", "omni_account",
//!    "wallet_address" }`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::identity::derive_with_client_id;
use crate::jwt::issue::mint_session_jwt;
use crate::plugins::auth::AuthResponse;
use crate::plugins::wallet::{WalletAddress, WalletRole};
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct WalletVerifyRequest {
    pub request_id: String,
    pub signature: String,
}

pub async fn wallet_verify(
    State(state): State<SharedState>,
    Json(body): Json<WalletVerifyRequest>,
) -> Result<impl IntoResponse, BrokerError> {
    let plugin = state
        .registry
        .auth
        .get("wallet_sig")
        .cloned()
        .ok_or_else(|| BrokerError::BadRequest("wallet_sig auth method not enabled".to_string()))?;

    let identity = plugin
        .verify(AuthResponse {
            request_id: body.request_id,
            extras: json!({ "signature": body.signature }),
        })
        .await
        .map_err(super::wallet_start_map_auth_err)?;

    // Derive OmniAccount from the verified identity (canonical bytes
    // come from IdentityType::canonical(); see plan §3.5).
    let omni = derive_with_client_id(
        &state.config.client_id,
        identity.identity_type.canonical(),
        &identity.identity_value,
    );

    // Bind the wallet (idempotent in WalletStore — same role/parent
    // returns the existing row). For wallet-sig auth the binding role
    // is Master because the wallet itself is the authenticating identity;
    // daemons get bound via Phase B recovery flow.
    let wallet_address = WalletAddress::parse(&identity.identity_value).map_err(|e| {
        BrokerError::Internal(format!(
            "verified identity is not a valid wallet address: {}",
            e
        ))
    })?;
    state
        .registry
        .wallet
        .bind_address(
            &identity,
            omni.as_str(),
            wallet_address.clone(),
            WalletRole::Master,
            None,
        )
        .await
        .map_err(|e| BrokerError::Internal(format!("wallet bind: {}", e)))?;

    // Mint session JWT.
    let ttl_seconds = std::env::var(crate::env::BROKER_SESSION_JWT_TTL_SECONDS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(18_000); // 5 hours default per env.rs doc
    let token = mint_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        omni.as_str(),
        wallet_address.as_str(),
        identity.identity_type.canonical(),
        &identity.identity_value,
        ttl_seconds,
    )
    .map_err(|e| BrokerError::Internal(format!("mint session jwt: {}", e)))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at = now + ttl_seconds;

    let response = json!({
        "session_jwt":      token,
        "session_jwt_kid":  state.session_keypair.kid,
        "expires_at":       expires_at,
        "omni_account":     omni.as_str(),
        "wallet_address":   wallet_address.as_str(),
        "identity_type":    identity.identity_type.canonical(),
        "identity_value":   identity.identity_value,
    });
    Ok((StatusCode::OK, Json(response)))
}
