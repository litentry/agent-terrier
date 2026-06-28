//! `POST /v1/agent/resolve` — a bound device re-resolves its agent session
//! (issue #367 piece 1: broker → device agent creds).
//!
//! No bearer: the device proves K10 possession with a fresh `pop_sig`, the broker
//! reads the DURABLE binding from chain (`SidecarRegistry.getDevice`) and mints a
//! FRESH `J1_agent`. This is how the device gets its bearer on EVERY boot WITHOUT
//! storing one at rest — the binding is the on-chain source of truth, and the
//! JWT's TTL starts at retrieval. It complements `/v1/agent/pairing/poll` (used
//! once, during the claim window): `/resolve` works for the lifetime of the
//! binding, long after the §10.2 request rows have expired.
//!
//! `agent_url` is the device's assigned runtime (its hermes-sandbox bridge). It is
//! `null` until a sandbox registers it (#367 piece 2); while null the device falls
//! back to its compiled `AGENT_BASE_URL`.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::session_jwt_ttl_seconds;
use crate::handlers::cap::{call_get_device, ChainContracts};
use crate::jwt::issue::mint_agent_session_jwt;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct ResolveBody {
    /// The device's K10 EVM address (`0x` + 40 hex).
    pub device_pubkey: String,
    /// EIP-191 `pop_sig` over `keccak256("agentkeys-agent-pop:" || device_key_hash)`.
    pub pop_sig: String,
}

pub async fn agent_resolve(
    State(state): State<SharedState>,
    Json(body): Json<ResolveBody>,
) -> Result<impl IntoResponse, BrokerError> {
    // 1. Re-prove K10 possession (stateless) — identical to the §10.2 poll. A bad
    //    signature touches no chain/state.
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

    // 2. Read the DURABLE binding from chain (the §10.2 request rows are long gone).
    let chain = ChainContracts::from_state(&state)
        .map_err(|e| BrokerError::Internal(format!("chain config: {e:?}")))?;
    let device = call_get_device(
        &state.http,
        &chain.rpc_url,
        &chain.registry,
        &device_key_hash,
    )
    .await
    .map_err(|e| BrokerError::Internal(format!("on-chain device read: {e:?}")))?;
    if device.registered_at == 0 {
        return Err(BrokerError::Forbidden(
            "device is not bound on-chain — pair it first (§10.2)".into(),
        ));
    }
    if device.revoked {
        return Err(BrokerError::Forbidden("device binding revoked".into()));
    }

    // 3. Mint a FRESH J1_agent from the on-chain binding (actor = child, operator =
    //    master). derivation_path is informational — the cap-mint gate keys on
    //    operator/actor/device, not the path — so "//resolved" marks this path.
    let session_jwt = mint_agent_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &device.actor_omni,
        &device.operator_omni,
        "//resolved",
        &body.device_pubkey,
        session_jwt_ttl_seconds(),
    )
    .map_err(|e| BrokerError::Internal(format!("mint J1_agent: {e}")))?;

    tracing::info!(
        device = %body.device_pubkey,
        operator_omni = %device.operator_omni,
        actor_omni = %device.actor_omni,
        "resolved §10.2 binding — J1_agent minted"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_jwt": session_jwt,
            "agent_url": serde_json::Value::Null, // #367 piece 2 populates this
            "operator_omni": device.operator_omni,
            "actor_omni": device.actor_omni,
        })),
    ))
}
