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
//! `agent_url` is the device's assigned runtime (its hermes-sandbox bridge).
//! When the broker carries sandbox-lifecycle config (#377), resolve ALSO
//! ensures the delegate's veFaaS instance exists (idempotent spawn — the
//! create-on-boot half of "create-on-pair, broker-driven") and returns the
//! gateway URL as `agent_url`, plus a `sandbox` object reporting this call's
//! ensure outcome (a spawn failure rides in `sandbox.error`; the resolve
//! itself still succeeds — the device needs its JWT regardless). On hosts
//! without sandbox config it stays `null` and the device falls back to its
//! compiled `AGENT_BASE_URL`.

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
    /// #409 D9 (spec §4.4) — the caller is a channel-endpoint DEVICE, not a
    /// runtime-hosting delegate: skip the #377 sandbox ensure. Self-declared and
    /// spawn-suppressing ONLY (it can never widen authority — a delegate that
    /// sets it just doesn't get its sandbox ensured on this call), which is why
    /// a body flag is acceptable here: the on-chain scope stores keccak service
    /// ids, so the broker cannot re-derive "channel-only" from chain the way
    /// `poll` derives it from the claim's plaintext `requested_scope`.
    #[serde(default)]
    pub is_device: bool,
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

    // 4. #377: a DELEGATE needs its runtime — ensure its hermes-sandbox instance
    //    exists (idempotent; extends the lifetime of a live one). Best-effort
    //    against the resolve: a veFaaS failure is surfaced in `sandbox.error`,
    //    never a resolve failure. #409 D9: a channel-endpoint DEVICE never
    //    spawns — the boot-path twin of the `poll.rs` scope_is_device_only gate.
    let provision = if body.is_device {
        tracing::info!(
            actor_omni = %device.actor_omni,
            "device resolve — channel endpoint, NO sandbox ensure (#409 D9: device pairing never spawns)"
        );
        None
    } else {
        crate::handlers::sandbox::ensure_for_delegate(
            &state,
            &device_key_hash,
            &device.actor_omni,
            &device.operator_omni,
        )
        .await
    };
    let (agent_url, sandbox) = match &provision {
        Some(p) => (json!(p.agent_url), p.to_json()),
        None => (serde_json::Value::Null, serde_json::Value::Null),
    };

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_jwt": session_jwt,
            "agent_url": agent_url,
            "sandbox": sandbox,
            "operator_omni": device.operator_omni,
            "actor_omni": device.actor_omni,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #409 D9 back-compat: the pre-#409 resolve body (no `is_device`) must keep
    /// deserializing with the flag defaulted FALSE (delegates keep their boot-time
    /// sandbox ensure), and an explicit `true` must parse (devices skip it).
    #[test]
    fn resolve_body_is_device_defaults_false() {
        let legacy: ResolveBody =
            serde_json::from_str(r#"{"device_pubkey":"0xabc","pop_sig":"0xdef"}"#).unwrap();
        assert!(!legacy.is_device);
        let device: ResolveBody =
            serde_json::from_str(r#"{"device_pubkey":"0xabc","pop_sig":"0xdef","is_device":true}"#)
                .unwrap();
        assert!(device.is_device);
    }
}
