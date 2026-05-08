//! `POST /v1/grant/revoke` — Phase B, US-026.
//!
//! Master OmniAccount revokes a previously-issued grant. Instant — one
//! row update. Re-revoke is a no-op (idempotent). Cross-master revoke
//! is rejected (the master_omni_account in the session JWT must match
//! the row's master_omni_account).

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
pub struct GrantRevokeBody {
    pub grant_id: String,
}

pub async fn grant_revoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<GrantRevokeBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = super::require_session_jwt(&headers, &state)?;
    let master = session.agentkeys.omni_account;

    if body.grant_id.trim().is_empty() {
        return Err(BrokerError::BadRequest("grant_id required".into()));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let did = state
        .grant_store
        .revoke(&body.grant_id, &master, now)
        .map_err(|e| BrokerError::Internal(format!("revoke grant: {}", e)))?;

    if !did {
        // Either grant_id doesn't exist OR belongs to a different master
        // OR was already revoked. We collapse to one error to avoid
        // leaking grant existence to non-owners.
        return Err(BrokerError::BadRequest(format!(
            "grant_id {:?} not found, not owned by this master, or already revoked",
            body.grant_id
        )));
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "grant_id":   body.grant_id,
            "revoked_at": now,
        })),
    ))
}
