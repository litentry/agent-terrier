//! `POST /v1/agent/pairing/decline` — the master declines a claimed pairing
//! request (§10.2). Removes the pending rendezvous row so it stops appearing in
//! `/v1/agent/pairing/pending` (the agent re-pairs if it still wants in).
//!
//! Gated by the master's `J1` session bearer ONLY — **no Touch ID / K11**.
//! Declining is not an on-chain mutation (nothing is bound), so it doesn't carry
//! the biometric gate the *accept* (registerAgentDevice + setScope) does. The
//! store scopes the DELETE to the claiming master's `operator_omni`, so a master
//! can only decline its own requests, and refuses an already-bound device (that's
//! an unpair, not a decline). Idempotent: declining an already-gone request is OK.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::require_session_jwt;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct PairingDeclineBody {
    /// The `request_id` shown in the pending list (the master-side handle).
    pub request_id: String,
}

pub async fn pairing_decline(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PairingDeclineBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = require_session_jwt(&headers, &state)?;
    let master_omni = session.agentkeys.omni_account;

    let removed = state
        .pairing_request_store
        .decline(body.request_id.trim(), &master_omni)?;

    tracing::info!(
        operator_omni = %master_omni,
        request_id = %body.request_id,
        removed,
        "declined §10.2 pairing request"
    );

    // Idempotent: ok:true whether or not a row was removed (declining a gone
    // request is a no-op success — the desired end state holds either way).
    Ok((
        StatusCode::OK,
        Json(json!({ "ok": true, "request_id": body.request_id, "removed": removed })),
    ))
}
