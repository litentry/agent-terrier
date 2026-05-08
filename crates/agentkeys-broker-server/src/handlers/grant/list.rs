//! `GET /v1/grant/list` — Phase B, US-026.
//!
//! Master OmniAccount lists their grants (active + revoked). Each row
//! carries the `audit_proof` so a client can independently verify the
//! grant content matches what the broker signed.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::error::BrokerError;
use crate::state::SharedState;

pub async fn grant_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BrokerError> {
    let session = super::require_session_jwt(&headers, &state)?;
    let master = session.agentkeys.omni_account;

    let grants = state
        .grant_store
        .list_for_master(&master)
        .map_err(|e| BrokerError::Internal(format!("list grants: {}", e)))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "owner":  master,
            "grants": grants,
        })),
    ))
}
