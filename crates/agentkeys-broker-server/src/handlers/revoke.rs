//! The broker `/v1/revoke/build` flow: the Touch-ID-gated agent **unpair**.
//!
//! `SidecarRegistry.revokeAgentDevice` enforces `msg.sender ==
//! operatorMasterWallet[device.operatorOmni]` — for an account-master operator
//! (#225) NO EOA can sign it, including the deployer (the legacy
//! `heima-device-revoke.sh` path reverts `NotAuthorized(caller, master)` — real
//! 2026-06-11 incident). So the unpair becomes ONE
//! `P256Account.executeBatch([revokeAgentDevice])` UserOp K11-signed by the
//! master, exactly the `/v1/scope/build` posture. The companion
//! `/v1/revoke/submit` route reuses [`crate::handlers::accept::accept_submit`]
//! verbatim (the relay carries nothing accept-specific).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;

use agentkeys_core::erc4337::{AgentRegister, ScopeGrant};

use crate::handlers::accept::{
    aerr, bearer, call_entrypoint_nonce, call_operator_master_wallet, eth_address_has_code,
    load_accept_config, norm_omni, AcceptConfig, SPONSOR_WINDOW_SECS,
};
use crate::sponsored_accept::{assemble_revoke_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;

/// Broker-side mirror of `agentkeys_backend_client::protocol::BuildRevokeUserOpRequest`
/// (the broker doesn't depend on that crate; the frozen key-set test there pins the
/// shape). `POST /v1/revoke/build` body, J1_master-gated.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildRevokeRequest {
    pub operator_omni: String,
    /// The agent's on-chain `SidecarRegistry` device key hash (`0x` + 64 hex).
    pub device_key_hash: String,
}

/// Parse the wire request into the omni + device hash, carried in an
/// [`AgentRegister`] whose other fields stay empty — the revoke composer reads
/// only `device_key_hash` (and the handler reads `operator_omni` for auth).
pub fn parse_revoke(req: &BuildRevokeRequest) -> Result<(AgentRegister, ScopeGrant), String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s.trim().trim_start_matches("0x"))
            .map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    let register = AgentRegister {
        device_key_hash: h32(&req.device_key_hash, "device_key_hash")?,
        operator_omni: h32(&req.operator_omni, "operator_omni")?,
        actor_omni: [0u8; 32],
        link_code_redemption: Vec::new(),
        agent_pop_sig: Vec::new(),
    };
    let grant = ScopeGrant {
        services: Vec::new(),
        read_only: true,
        max_per_call: 0,
        max_per_period: 0,
        max_total: 0,
        period_seconds: 0,
    };
    Ok((register, grant))
}

/// **PURE** — assemble the `/v1/revoke/build` response from the request + chain
/// reads (master account + nonce) + config + the broker co-sign key.
pub fn build_revoke_response(
    req: &BuildRevokeRequest,
    master_account: [u8; 20],
    nonce: [u8; 32],
    cfg: &AcceptConfig,
    broker_sk: &k256::ecdsa::SigningKey,
    valid_until: u64,
) -> Result<BuildAcceptResponse, String> {
    let (register, grant) = parse_revoke(req)?;
    let params = AcceptUserOpParams {
        entry_point: cfg.entry_point,
        chain_id: cfg.chain_id,
        master_account,
        registry: cfg.registry,
        scope: cfg.scope,
        nonce,
        account_gas_limits: cfg.account_gas_limits,
        pre_verification_gas: cfg.pre_verification_gas,
        gas_fees: cfg.gas_fees,
        paymaster: cfg.paymaster,
        paymaster_verification_gas_limit: cfg.paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit: cfg.paymaster_post_op_gas_limit,
        valid_until,
        valid_after: 0,
        broker_signer: cfg.broker_signer,
        register: &register,
        grant: &grant,
    };
    let assembled = assemble_revoke_userop(&params, broker_sk).map_err(|e| e.to_string())?;
    Ok(assembled.into_build_response(&cfg.entry_point, cfg.chain_id))
}

/// `POST /v1/revoke/build` (J1_master) — assemble the revoke-only UserOp and
/// return the `userOpHash` the master K11-signs. Submit the signed op to
/// `/v1/revoke/submit` (the shared accept relay).
pub async fn revoke_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<BuildRevokeRequest>,
) -> Result<Json<BuildAcceptResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. J1_master auth — the session omni MUST equal the request operator_omni.
    let token = bearer(&headers)?;
    let claims = crate::jwt::verify::verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &token,
    )
    .map_err(|e| aerr(StatusCode::UNAUTHORIZED, format!("session jwt: {e}")))?;
    if norm_omni(&claims.agentkeys.omni_account) != norm_omni(&req.operator_omni) {
        return Err(aerr(StatusCode::FORBIDDEN, "operator_mismatch"));
    }

    // 2. config + co-sign key from env (shared with accept — same drift guard).
    let (cfg, broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;

    // 3. chain reads: the master P256Account + its EntryPoint nonce.
    let master_account =
        call_operator_master_wallet(&state.http, &cfg.rpc_url, &cfg.registry, &req.operator_omni)
            .await
            .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    if master_account == [0u8; 20] {
        return Err(aerr(
            StatusCode::CONFLICT,
            "operator has no master account on chain (register the master first)",
        ));
    }
    if !eth_address_has_code(&state.http, &cfg.rpc_url, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?
    {
        return Err(aerr(
            StatusCode::CONFLICT,
            format!(
                "operator master 0x{} is a legacy EOA, not a passkey P256Account — the \
                 Touch-ID unpair requires a P256Account master (a legacy-EOA master can \
                 revoke via heima-device-revoke.sh directly)",
                hex::encode(master_account)
            ),
        ));
    }
    let nonce = call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;

    // 4. assemble + co-sign.
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + SPONSOR_WINDOW_SECS;
    let resp = build_revoke_response(&req, master_account, nonce, &cfg, &broker_sk, valid_until)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn sample() -> BuildRevokeRequest {
        BuildRevokeRequest {
            operator_omni: format!("0x{}", "22".repeat(32)),
            device_key_hash: format!("0x{}", "11".repeat(32)),
        }
    }

    #[test]
    fn parses_omni_and_device_hash() {
        let (reg, grant) = parse_revoke(&sample()).unwrap();
        assert_eq!(reg.operator_omni, [0x22; 32]);
        assert_eq!(reg.device_key_hash, [0x11; 32]);
        assert_eq!(reg.actor_omni, [0u8; 32]);
        assert!(grant.services.is_empty());
        let mut bad = sample();
        bad.device_key_hash = "0x1122".into();
        assert!(parse_revoke(&bad).is_err());
    }

    #[test]
    fn build_revoke_response_assembles_the_revoke_only_op() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = AcceptConfig {
            rpc_url: "http://localhost".into(),
            chain_id: 212_013,
            entry_point: [0x66; 20],
            paymaster: None,
            broker_signer: [0x77; 20],
            registry: [0xa1; 20],
            scope: [0xa2; 20],
            account_gas_limits: crate::sponsor::pack_u128_pair(1_500_000, 2_000_000),
            pre_verification_gas: {
                let mut w = [0u8; 32];
                w[16..].copy_from_slice(&100_000u128.to_be_bytes());
                w
            },
            gas_fees: crate::sponsor::pack_u128_pair(1_000_000_000, 40_000_000_000),
            paymaster_verification_gas_limit: 200_000,
            paymaster_post_op_gas_limit: 50_000,
        };
        let master = [0x99u8; 20];
        let mut nonce = [0u8; 32];
        nonce[31] = 7;
        let resp =
            build_revoke_response(&sample(), master, nonce, &cfg, &sk, 9_999_999_999).unwrap();
        assert_eq!(resp.user_op.sender, format!("0x{}", hex::encode(master)));
        // executeBatch wrapping exactly revokeAgentDevice(0x11…) — selector pinned
        // via `cast sig "revokeAgentDevice(bytes32)"`; no setScope, no register.
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a"));
        assert!(resp
            .user_op
            .call_data
            .contains(&format!("b269f9fb{}", "11".repeat(32))));
        let set_scope_sel = hex::encode(
            &agentkeys_core::device_crypto::keccak256(
                b"setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)",
            )[..4],
        );
        assert!(!resp.user_op.call_data.contains(&set_scope_sel));
        assert!(resp.user_op_hash.starts_with("0x") && resp.user_op_hash.len() == 66);
    }
}
