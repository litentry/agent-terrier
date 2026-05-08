//! `POST /v1/wallet/link` — Phase B, US-028.
//!
//! Master attaches a verified identity (email, oauth2 sub, secondary
//! EVM wallet) to their OmniAccount. Idempotent — re-linking an
//! existing pair is a no-op.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct WalletLinkBody {
    /// Canonical identity-type string (`"email"`, `"oauth2_google"`,
    /// `"evm"`, etc.). Must be one of the IdentityType::canonical()
    /// values; future-proof, the broker accepts unknown types as long
    /// as they non-empty.
    pub identity_type: String,
    /// The identity value (email address, google sub, EVM address …).
    pub identity_value: String,
}

pub async fn wallet_link(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<WalletLinkBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = super::require_master_session(&headers, &state)?;
    let master = session.agentkeys.omni_account;

    if body.identity_type.trim().is_empty() || body.identity_value.trim().is_empty() {
        return Err(BrokerError::BadRequest(
            "identity_type + identity_value must be non-empty".into(),
        ));
    }
    // Defense-in-depth: don't let a master claim an identity that's
    // already owned by a different master. Phase E will gate this with
    // proof-of-control (per identity type); v0 falls back to whoever
    // wrote first wins.
    if let Some(existing) = state
        .identity_link_store
        .owner_of(&body.identity_type, &body.identity_value)
        .map_err(|e| BrokerError::Internal(format!("owner_of: {}", e)))?
    {
        if existing != master {
            return Err(BrokerError::Unauthorized(format!(
                "identity already linked to a different master ({})",
                existing
            )));
        }
        // Same master → idempotent no-op.
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    state
        .identity_link_store
        .link(
            &master,
            &body.identity_type,
            &body.identity_value,
            now,
        )
        .map_err(|e| BrokerError::Internal(format!("link: {}", e)))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "linked":         true,
            "omni_account":   master,
            "identity_type":  body.identity_type,
            "identity_value": body.identity_value,
            "linked_at":      now,
        })),
    ))
}
