//! `GET /v1/wallet/links` — Phase B, US-028.
//!
//! Lists identities linked to the caller's master OmniAccount.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::error::BrokerError;
use crate::state::SharedState;

pub async fn wallet_links_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BrokerError> {
    let session = super::require_master_session(&headers, &state)?;
    let master = session.agentkeys.omni_account;

    let links = state
        .identity_link_store
        .list_for_master(&master)
        .map_err(|e| BrokerError::Internal(format!("list links: {}", e)))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "owner": master,
            "links": links,
        })),
    ))
}
