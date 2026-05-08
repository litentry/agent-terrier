//! `POST /v1/wallet/recover/lookup` — Phase B, US-028.
//!
//! Unauthenticated lookup that returns the master OmniAccount owning a
//! given linked identity. Used by the recovery flow to discover which
//! master should be solicited to issue a recovery grant on a NEW
//! daemon address.
//!
//! The recovery flow then proceeds via the regular `/v1/grant/create`
//! endpoint signed by the original master — this ensures recovery
//! always requires master consent, defending against
//! phished-email-becomes-wallet-takeover (Codex P0 #4 from earlier).
//!
//! Lookup is unauthenticated because:
//! 1. The OmniAccount is a SHA256 hash — knowing it does not enable
//!    impersonation or enumeration of the underlying identity value.
//! 2. The user calling /recover/lookup is the legitimate party trying
//!    to reach their own master (they hold the linked identity).

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct RecoverLookupBody {
    pub identity_type: String,
    pub identity_value: String,
}

pub async fn wallet_recover_lookup(
    State(state): State<SharedState>,
    Json(body): Json<RecoverLookupBody>,
) -> Result<impl IntoResponse, BrokerError> {
    if body.identity_type.trim().is_empty() || body.identity_value.trim().is_empty() {
        return Err(BrokerError::BadRequest(
            "identity_type + identity_value must be non-empty".into(),
        ));
    }
    let owner = state
        .identity_link_store
        .owner_of(&body.identity_type, &body.identity_value)
        .map_err(|e| BrokerError::Internal(format!("owner_of: {}", e)))?;

    match owner {
        Some(omni_account) => Ok((
            StatusCode::OK,
            Json(json!({
                "linked":       true,
                "omni_account": omni_account,
                "next_step":    "Have the master OmniAccount sign POST /v1/grant/create for your new daemon address.",
            })),
        )),
        None => Ok((
            StatusCode::OK,
            Json(json!({
                "linked":    false,
                "next_step": "Identity not linked to any master. Re-authenticate with the master via /v1/auth/* and call /v1/wallet/link first.",
            })),
        )),
    }
}
