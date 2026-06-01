//! `POST /v1/agent/pairing/poll` — the agent polls its pairing request and, once
//! a master has claimed it, mints + retrieves `J1_agent` (method A §10.2).
//!
//! No bearer (the agent still has no session). The agent presents its secret
//! `request_id` (the retrieval ticket from `/request`) plus a FRESH `pop_sig`
//! over its K10 device key. The broker:
//!
//! 1. verifies `pop_sig` recovers to `device_pubkey` (stateless re-proof — the
//!    agent proves it still holds the device key at retrieval time);
//! 2. looks up the request, binding the lookup to `device_pubkey` (a guessed
//!    `request_id` without the matching device key is indistinguishable from an
//!    unknown one);
//! 3. if still unclaimed → `{ "status": "pending" }` (the agent keeps polling);
//! 4. if claimed → mints `J1_agent` FRESH (HDKD omni + lineage) and returns it.
//!
//! Minting at poll time (not at the master's claim) means no bearer secret is
//! ever stored at rest, and the JWT's TTL starts when the agent actually
//! retrieves it. The agent has `J1_agent` but NO scope until the master's
//! on-chain `registerAgentDevice` + scope grant lands — the mint-oidc-jwt
//! on-chain gate still rejects every downstream mint until then.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::{session_jwt_ttl_seconds, unix_now};
use crate::jwt::issue::mint_agent_session_jwt;
use crate::state::SharedState;
use crate::storage::PairingPoll;

#[derive(Debug, Deserialize)]
pub struct PairingPollBody {
    /// The agent's secret retrieval ticket from `/v1/agent/pairing/request`.
    pub request_id: String,
    /// The agent's K10 EVM address (`0x` + 40 hex).
    pub device_pubkey: String,
    /// Fresh EIP-191 `pop_sig` over `keccak256("agentkeys-agent-pop:" || device_key_hash)`.
    pub pop_sig: String,
}

pub async fn pairing_poll(
    State(state): State<SharedState>,
    Json(body): Json<PairingPollBody>,
) -> Result<impl IntoResponse, BrokerError> {
    // 1. Verify pop_sig FIRST (stateless) — the agent re-proves device-key
    //    possession at retrieval time. A bad sig touches no state.
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

    // 2. Read request state (lookup is bound to device_pubkey inside the store).
    let now = unix_now()?;
    let (operator_omni, child_omni, label) =
        match state
            .pairing_request_store
            .poll(&body.request_id, &body.device_pubkey, now)?
        {
            PairingPoll::Pending => {
                return Ok((StatusCode::OK, Json(json!({ "status": "pending" }))));
            }
            PairingPoll::Claimed {
                operator_omni,
                child_omni,
                label,
                ..
            } => (operator_omni, child_omni, label),
            PairingPoll::Expired => {
                return Err(BrokerError::Unauthorized(
                    "pairing request expired before any master claimed it".into(),
                ));
            }
            PairingPoll::NotFound => {
                return Err(BrokerError::Unauthorized(
                    "unknown pairing request or device mismatch".into(),
                ));
            }
        };

    // 3. Mint J1_agent fresh (HDKD omni + lineage). The agent authenticates with
    //    this immediately, but has NO scope until the master approves the binding.
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
        "polled §10.2 pairing request — claimed; J1_agent minted at retrieval"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "claimed",
            "session_jwt": session_jwt,
            "child_omni": child_omni,
            "operator_omni": operator_omni,
            "label": label,
            "derivation_path": derivation_path,
            "device_key_hash": device_key_hash,
        })),
    ))
}
