//! `POST /v1/agent/pairing/request` — the agent opens an **unbound** pairing
//! request (method A §10.2, replaces the master-minted link code).
//!
//! No bearer: the agent has no session yet (that's the whole point of pairing).
//! It proves possession of its K10 device key via `pop_sig`, exactly as the old
//! redeem path did. The broker stores an unbound request (naming no master) and
//! returns:
//!
//! - `pairing_code` — what the agent DISPLAYS (QR / screen text); a master claims
//!   the agent by scanning/entering this. Whoever holds it binds, so it is
//!   high-entropy (144 bits) — show it only to the intended owner.
//! - `request_id` — the agent's SECRET retrieval ticket; it polls
//!   `/v1/agent/pairing/poll` with this + a fresh `pop_sig` to fetch `J1_agent`
//!   once a master claims. Never displayed.
//!
//! `pop_sig` is verified BEFORE anything is stored, so a bad signature creates no
//! row (no DoS amplification). The endpoint is unauthenticated → it MUST be
//! rate-limited + pool-capped upstream; the TTL + janitor bound the blast radius.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::unix_now;
use crate::handlers::grant::random_b64url;
use crate::state::SharedState;
use crate::storage::PAIRING_REQUEST_TTL_SECONDS;

#[derive(Debug, Deserialize)]
pub struct PairingRequestBody {
    /// The agent's K10 EVM address (`0x` + 40 hex).
    pub device_pubkey: String,
    /// EIP-191 `pop_sig` over `keccak256("agentkeys-agent-pop:" || device_key_hash)`.
    pub pop_sig: String,
}

pub async fn pairing_request(
    State(state): State<SharedState>,
    Json(body): Json<PairingRequestBody>,
) -> Result<impl IntoResponse, BrokerError> {
    // 1. Verify pop_sig FIRST (stateless), so a bad signature never creates a
    //    row — the unauthenticated endpoint can't be used to flood the pool with
    //    junk requests that don't even hold a valid device key.
    let device_key_hash = agentkeys_core::device_crypto::device_key_hash(&body.device_pubkey)
        .map_err(|e| BrokerError::BadRequest(format!("bad device_pubkey: {e}")))?;
    let pop_payload = agentkeys_core::device_crypto::agent_pop_payload(&device_key_hash);
    let recovered = agentkeys_core::device_crypto::ecrecover_eip191(&pop_payload, &body.pop_sig)
        .map_err(|e| BrokerError::Unauthorized(format!("pop_sig verify: {e}")))?;
    if recovered.to_lowercase() != body.device_pubkey.to_lowercase() {
        return Err(BrokerError::Unauthorized(format!(
            "pop_sig does not recover to device_pubkey: claimed={}, recovered={recovered}",
            body.device_pubkey
        )));
    }

    // 2. Mint the two secrets + store the UNBOUND request (operator/child_omni
    //    stay ∅ until a master claims the code). request_id is the agent's
    //    retrieval ticket (32B); pairing_code is the master-facing claim secret.
    let request_id = random_b64url(32);
    let pairing_code = random_b64url(18);
    let now = unix_now()?;
    let expires_at = now + PAIRING_REQUEST_TTL_SECONDS;
    // #224 — `issue` supersedes (deletes) any prior OPEN request for this device
    // first, so re-running `--request-pairing`/`--force` leaves exactly one open
    // request instead of accumulating duplicate pending cards. Authenticated: the
    // pop_sig above proves device-key possession, so only the holder supersedes.
    let superseded = state.pairing_request_store.issue(
        &request_id,
        &pairing_code,
        &body.device_pubkey,
        &body.pop_sig,
        now,
        expires_at,
    )?;

    tracing::info!(
        device = %body.device_pubkey,
        superseded,
        "opened §10.2 unbound pairing request — awaiting master claim{}",
        if superseded > 0 {
            " (superseded prior open request(s) for this device)"
        } else {
            ""
        }
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "request_id": request_id,
            "pairing_code": pairing_code,
            "device_key_hash": device_key_hash,
            "expires_at": expires_at,
        })),
    ))
}
