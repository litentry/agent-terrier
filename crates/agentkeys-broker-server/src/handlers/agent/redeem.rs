//! `POST /v1/auth/link-code/redeem` — agent redeems the link code (issue #144 §10.2).
//!
//! No bearer: the link code IS the bearer secret (one-time, TTL-bounded). The
//! agent proves possession of its K10 device key via `pop_sig`. On success the
//! broker mints `J1_agent` (HDKD omni, decoupled from any wallet) and records
//! the device artifact as a pending binding for the master to approve.
//!
//! Order matters: `pop_sig` is verified BEFORE the code is consumed, so an
//! invalid signature does NOT burn the (single-use) code — the agent can retry.
//! `pop_sig` proves device-key possession; the link code proves authorization.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::{session_jwt_ttl_seconds, unix_now};
use crate::jwt::issue::mint_agent_session_jwt;
use crate::state::SharedState;
use crate::storage::LinkCodeConsume;

#[derive(Debug, Deserialize)]
pub struct RedeemBody {
    pub link_code: String,
    /// The agent's K10 EVM address (`0x` + 40 hex).
    pub device_pubkey: String,
    /// EIP-191 `pop_sig` over `keccak256("agentkeys-agent-pop:" || device_key_hash)`.
    pub pop_sig: String,
}

pub async fn link_code_redeem(
    State(state): State<SharedState>,
    Json(body): Json<RedeemBody>,
) -> Result<impl IntoResponse, BrokerError> {
    // 1. Verify pop_sig FIRST (stateless — doesn't touch the code), so a bad sig
    //    leaves the single-use code unconsumed and retryable.
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

    // 2. Atomically consume the code (single-use, TTL-bounded), capturing the
    //    device artifact onto the row as a pending binding.
    let now = unix_now()?;
    let (child_omni, operator_omni, label) = match state.link_code_store.consume(
        &body.link_code,
        &body.device_pubkey,
        &body.pop_sig,
        now,
    )? {
        LinkCodeConsume::Available {
            child_omni,
            operator_omni,
            label,
            ..
        } => (child_omni, operator_omni, label),
        LinkCodeConsume::Expired => {
            return Err(BrokerError::Unauthorized(
                "link code expired (>600s after issue)".into(),
            ));
        }
        LinkCodeConsume::NotFoundOrConsumed => {
            return Err(BrokerError::Unauthorized(
                "link code unknown or already redeemed".into(),
            ));
        }
    };

    // 3. Mint J1_agent (HDKD omni + lineage). The agent authenticates with this
    //    immediately, but has NO scope until the master approves the binding.
    let derivation_path = format!("//{label}");
    let session_jwt = mint_agent_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &child_omni,
        &operator_omni,
        &derivation_path,
        &body.device_pubkey,
        session_jwt_ttl_seconds(),
    )
    .map_err(|e| BrokerError::Internal(format!("mint J1_agent: {e}")))?;

    tracing::info!(
        operator_omni = %operator_omni,
        child_omni = %child_omni,
        label = %label,
        device = %body.device_pubkey,
        "redeemed §10.2 link code — J1_agent minted, pending binding recorded"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_jwt": session_jwt,
            "child_omni": child_omni,
            "operator_omni": operator_omni,
            "label": label,
            "derivation_path": derivation_path,
            "device_key_hash": device_key_hash,
        })),
    ))
}
