//! `GET /v1/agent/pending-bindings` — master pulls redeemed-but-unbound agents
//! (issue #144 §10.2).
//!
//! Gated by the master's `J1` session bearer. Returns the operator's rows that
//! have been redeemed (`device_pubkey` + `pop_sig` captured) but not yet bound
//! on-chain — i.e. "agent-A wants to pair + wants `[requested_scope]`". This is
//! the substrate the production push notification carries; the master pulls it,
//! then approves with one K11 gesture (bind + scope). `device_key_hash` is
//! pre-computed so the master can submit `registerAgentDevice` without recomputing.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::unix_now;
use crate::handlers::grant::require_session_jwt;
use crate::state::SharedState;

pub async fn pending_bindings(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BrokerError> {
    let session = require_session_jwt(&headers, &state)?;
    let master_omni = session.agentkeys.omni_account;

    let rows = state.link_code_store.pending_bindings(&master_omni)?;
    let pending: Vec<_> = rows
        .into_iter()
        .map(|b| {
            // Best-effort device_key_hash so the master needn't recompute. A
            // malformed stored address (shouldn't happen — it round-tripped
            // through redeem) degrades to an empty string rather than failing
            // the whole list.
            let device_key_hash = agentkeys_core::device_crypto::device_key_hash(&b.device_pubkey)
                .unwrap_or_default();
            json!({
                "link_code": b.link_code,
                "child_omni": b.child_omni,
                "operator_omni": b.operator_omni,
                "label": b.label,
                "requested_scope": b.requested_scope,
                "device_pubkey": b.device_pubkey,
                "pop_sig": b.pop_sig,
                "device_key_hash": device_key_hash,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "pending": pending }))))
}

#[derive(Debug, Deserialize)]
pub struct AckBody {
    /// The link code whose redeemed binding the master just submitted on chain.
    pub link_code: String,
}

/// `POST /v1/agent/pending-bindings/ack` — the master acks that it submitted
/// `registerAgentDevice` for this binding, so it drops out of the pending list
/// (issue #144). Without this the rendezvous would never clear — every redeemed
/// agent would show as "pending" forever even after it's bound on chain. Scoped
/// to the master's omni; idempotent (a second ack is a no-op → `acked: false`).
pub async fn ack_binding(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = require_session_jwt(&headers, &state)?;
    let master_omni = session.agentkeys.omni_account;
    let now = unix_now()?;
    let updated = state
        .link_code_store
        .mark_bound(&body.link_code, &master_omni, now)?;
    Ok((
        StatusCode::OK,
        Json(json!({ "acked": updated > 0, "link_code": body.link_code })),
    ))
}
