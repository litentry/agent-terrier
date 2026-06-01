//! `POST /v1/agent/pairing/claim` — master claims an agent's pairing request
//! (method A §10.2, replaces master-mints-`/v1/agent/create`).
//!
//! Gated by the master's `J1` session bearer. The master scans/enters the
//! `pairing_code` the agent displayed; this is the binding act — the agent never
//! named a master, so an unclaimed request is inert (Sybil-safe). On claim the
//! broker:
//!
//! 1. derives the HDKD child omni `O_agent = SHA256(HDKD_DOMAIN || O_master || "//label")`
//!    — the master "adopts" the agent under its own omni tree;
//! 2. assigns `operator_omni` + `child_omni` + `label` + `requested_scope` onto
//!    the (previously unbound) row, marking it claimed;
//! 3. returns the captured `device_pubkey` + `device_key_hash` so the master can
//!    REVIEW the device (the M second-factor, preserved) and submit
//!    `registerAgentDevice` without recomputing the hash.
//!
//! `J1_agent` is NOT minted here — the agent mints it itself at poll time by
//! re-proving device-key possession (so no bearer secret sits at rest, and the
//! JWT TTL starts at retrieval). This handler only flips the request to claimed
//! + records the pending binding the master then approves on chain.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::unix_now;
use crate::handlers::grant::require_session_jwt;
use crate::state::SharedState;
use crate::storage::PairingClaim;

#[derive(Debug, Deserialize)]
pub struct PairingClaimBody {
    /// The `pairing_code` the agent displayed (scanned/entered by the master).
    pub pairing_code: String,
    /// HDKD child label, e.g. `"agent-a"` (`^[a-z0-9-]{1,32}$`).
    pub label: String,
    /// Scope the master intends to grant the agent (the "app manifest").
    /// Defaults to `"memory"`. Comma-separated service list mirrors
    /// `heima-scope-set.sh --services`.
    #[serde(default)]
    pub requested_scope: Option<String>,
}

pub async fn pairing_claim(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PairingClaimBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = require_session_jwt(&headers, &state)?;
    let master_omni = session.agentkeys.omni_account;

    agentkeys_core::actor_omni::validate_label(&body.label)
        .map_err(|e| BrokerError::BadRequest(format!("invalid label: {e}")))?;
    let child_omni = agentkeys_core::actor_omni::child_omni_hex(&master_omni, &body.label)
        .map_err(|e| BrokerError::BadRequest(format!("derive child omni: {e}")))?;

    let requested_scope = body
        .requested_scope
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "memory".to_string());

    let now = unix_now()?;
    let (request_id, device_pubkey, pop_sig) = match state.pairing_request_store.claim(
        &body.pairing_code,
        &master_omni,
        &child_omni,
        &body.label,
        &requested_scope,
        now,
    )? {
        PairingClaim::Claimed {
            request_id,
            device_pubkey,
            pop_sig,
        } => (request_id, device_pubkey, pop_sig),
        PairingClaim::Expired => {
            return Err(BrokerError::Unauthorized(
                "pairing request expired (>600s after the agent opened it)".into(),
            ));
        }
        PairingClaim::NotFoundOrClaimed => {
            return Err(BrokerError::Unauthorized(
                "pairing code unknown or already claimed".into(),
            ));
        }
    };

    // Best-effort device_key_hash so the master needn't recompute it for
    // registerAgentDevice. A malformed stored address (shouldn't happen — it
    // round-tripped through /request) degrades to empty rather than failing.
    let device_key_hash =
        agentkeys_core::device_crypto::device_key_hash(&device_pubkey).unwrap_or_default();

    tracing::info!(
        operator_omni = %master_omni,
        child_omni = %child_omni,
        label = %body.label,
        device = %device_pubkey,
        "claimed §10.2 pairing request — pending binding recorded, awaiting on-chain bind"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "request_id": request_id,
            "child_omni": child_omni,
            "operator_omni": master_omni,
            "label": body.label,
            "requested_scope": requested_scope,
            "device_pubkey": device_pubkey,
            "pop_sig": pop_sig,
            "device_key_hash": device_key_hash,
        })),
    ))
}
