//! #248 — the broker `/v1/scope/build` flow: the Touch-ID-gated scope re-grant
//! for an **already-bound** agent.
//!
//! The permissions panel's setScope becomes ONE `P256Account.executeBatch([setScope])`
//! UserOp gated by the master's K11 Touch ID — the scope-only sibling of
//! `/v1/accept/build` (no `registerAgentDevice`: the device binding exists, only
//! the grant changes). `setScope` is set-replace, so `services` is the FULL new
//! list; an empty list revokes every grant. The companion `/v1/scope/submit`
//! route reuses [`crate::handlers::accept::accept_submit`] verbatim — the relay
//! (assertion → UserOp signature → bundler → `EntryPoint.handleOps`) carries
//! nothing accept-specific.
//!
//! Auth mirrors the accept: the J1_master session omni MUST equal the request's
//! `operator_omni` (layer-1 invariant); on chain, `setScope` itself enforces
//! `msg.sender == operatorMasterWallet(operator_omni)` — the same defense pair
//! the accept batch rides.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;

use agentkeys_core::erc4337::{AgentRegister, ScopeGrant};

use crate::handlers::accept::{
    aerr, bearer, call_entrypoint_nonce, call_operator_master_wallet, eth_address_has_code,
    load_accept_config, norm_omni, service_ids, AcceptConfig, SPONSOR_WINDOW_SECS,
};
use crate::sponsored_accept::{assemble_scope_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;

/// Broker-side mirror of `agentkeys_backend_client::protocol::BuildScopeUserOpRequest`
/// (the broker doesn't depend on that crate; the frozen key-set test there pins the
/// shape). `POST /v1/scope/build` body, J1_master-gated.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildScopeRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub services: Vec<String>,
    /// Raw on-chain service ids (`0x`-hex keccak-32) the caller can't name but
    /// must keep — the scope mirror's unmatched hashes (e.g. `cred:<service>`
    /// granted at accept). Unioned into the replacement grant so a memory-toggle
    /// commit never wipes them. Defaults empty.
    #[serde(default)]
    pub preserve_service_ids: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
}

/// Parse the wire request into the omni pair + typed scope grant. The omni pair
/// rides in an [`AgentRegister`] whose device fields stay empty — the scope-only
/// composer reads only `operator_omni` / `actor_omni` from it and never touches
/// the registry.
pub fn parse_scope_grant(req: &BuildScopeRequest) -> Result<(AgentRegister, ScopeGrant), String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s.trim().trim_start_matches("0x"))
            .map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    let cap = |s: &str, name: &str| -> Result<u128, String> {
        s.parse::<u128>().map_err(|e| format!("{name}: {e}"))
    };
    let register = AgentRegister {
        device_key_hash: [0u8; 32],
        operator_omni: h32(&req.operator_omni, "operator_omni")?,
        actor_omni: h32(&req.actor_omni, "actor_omni")?,
        link_code_redemption: Vec::new(),
        agent_pop_sig: Vec::new(),
    };
    // Named services hash here; preserved ids pass through raw (they're already
    // on-chain hashes the mirror read back). Dedup so an id named on both sides
    // doesn't double up in the setScope array.
    let mut services = service_ids(&req.services);
    for (i, id) in req.preserve_service_ids.iter().enumerate() {
        let h = h32(id, &format!("preserve_service_ids[{i}]"))?;
        if !services.contains(&h) {
            services.push(h);
        }
    }
    let grant = ScopeGrant {
        services,
        read_only: req.read_only,
        max_per_call: cap(&req.max_per_call, "max_per_call")?,
        max_per_period: cap(&req.max_per_period, "max_per_period")?,
        max_total: cap(&req.max_total, "max_total")?,
        period_seconds: req.period_seconds,
    };
    Ok((register, grant))
}

/// **PURE** — assemble the `/v1/scope/build` response from the request + chain
/// reads (master account + nonce) + config + the broker co-sign key. The axum
/// handler does the auth + eth_call reads + key load, then calls this.
pub fn build_scope_response(
    req: &BuildScopeRequest,
    master_account: [u8; 20],
    nonce: [u8; 32],
    cfg: &AcceptConfig,
    broker_sk: &k256::ecdsa::SigningKey,
    valid_until: u64,
) -> Result<BuildAcceptResponse, String> {
    let (register, grant) = parse_scope_grant(req)?;
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
    let assembled = assemble_scope_userop(&params, broker_sk).map_err(|e| e.to_string())?;
    Ok(assembled.into_build_response(&cfg.entry_point, cfg.chain_id))
}

/// `POST /v1/scope/build` (J1_master) — assemble the scope-only setScope UserOp
/// and return the `userOpHash` the master K11-signs. Submit the signed op to
/// `/v1/scope/submit` (the shared accept relay).
pub async fn scope_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<BuildScopeRequest>,
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

    // 3. chain reads: the master P256Account + its EntryPoint nonce. Same
    //    EOA-master rejection as the accept — an EOA can't validate the UserOp.
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
                 Touch-ID scope grant requires a P256Account master; re-onboard through \
                 the passkey register (erc4337-register-master.sh)",
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
    let resp = build_scope_response(&req, master_account, nonce, &cfg, &broker_sk, valid_until)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn sample() -> BuildScopeRequest {
        BuildScopeRequest {
            operator_omni: format!("0x{}", "22".repeat(32)),
            actor_omni: format!("0x{}", "33".repeat(32)),
            services: vec!["memory:personal".into()],
            preserve_service_ids: Vec::new(),
            read_only: true,
            max_per_call: "1000".into(),
            max_per_period: "0".into(),
            max_total: "0".into(),
            period_seconds: 86400,
        }
    }

    // keccak256("memory:personal") — the on-chain service id (same vector as accept.rs).
    const MEMORY_PERSONAL_ID: &str =
        "0x12f2770c904838cddb30299f5c22cd28df31b34fcdb44c342cd1f96c4a38ab27";

    #[test]
    fn parses_omnis_and_keccak_service_ids() {
        let (reg, grant) = parse_scope_grant(&sample()).unwrap();
        assert_eq!(reg.operator_omni, [0x22; 32]);
        assert_eq!(reg.actor_omni, [0x33; 32]);
        // Device fields stay empty — the scope-only op never registers anything.
        assert_eq!(reg.device_key_hash, [0u8; 32]);
        assert!(reg.link_code_redemption.is_empty());
        assert!(reg.agent_pop_sig.is_empty());
        assert_eq!(
            format!("0x{}", hex::encode(grant.services[0])),
            MEMORY_PERSONAL_ID
        );
        assert!(grant.read_only);
        assert_eq!(grant.max_per_call, 1000);
    }

    #[test]
    fn empty_services_parse_to_the_revoke_all_grant() {
        let mut req = sample();
        req.services = Vec::new();
        let (_, grant) = parse_scope_grant(&req).unwrap();
        assert!(grant.services.is_empty());
    }

    /// Codex review (high): committing ZERO memory/inbox grants from the panel is
    /// NOT "denied everywhere" — the actor's preserved ids (cred/email, read back
    /// from the mirror) still ride into the set-replace, so those grants survive.
    /// This pins the on-chain truth the UI confirm text now states accurately
    /// (the old text claimed full revocation while preserving creds).
    #[test]
    fn zero_named_services_still_preserves_cred_grants() {
        let mut req = sample();
        req.services = Vec::new(); // every memory/inbox toggle off — the panel's "revoke all"
        let cred_id = format!("0x{}", "44".repeat(32));
        req.preserve_service_ids = vec![cred_id];
        let (_, grant) = parse_scope_grant(&req).unwrap();
        // The cred grant survives → the agent is NOT denied everywhere.
        assert_eq!(grant.services.len(), 1);
        assert_eq!(grant.services[0], [0x44u8; 32]);
    }

    #[test]
    fn preserve_service_ids_union_into_the_grant_without_duplicates() {
        // The mirror's unmatched hashes (e.g. cred:openrouter) survive a memory
        // commit; an id that equals a named service doesn't double up.
        let mut req = sample();
        let cred_id = format!("0x{}", "44".repeat(32));
        req.preserve_service_ids = vec![cred_id.clone(), MEMORY_PERSONAL_ID.into()];
        let (_, grant) = parse_scope_grant(&req).unwrap();
        assert_eq!(grant.services.len(), 2); // memory:personal + the cred hash
        assert!(grant.services.contains(&[0x44u8; 32]));
        let mut bad = sample();
        bad.preserve_service_ids = vec!["0x1234".into()]; // not 32 bytes
        assert!(parse_scope_grant(&bad).is_err());
    }

    #[test]
    fn rejects_bad_omnis_and_caps() {
        let mut bad = sample();
        bad.operator_omni = "0xZZ".into();
        assert!(parse_scope_grant(&bad).is_err());
        let mut short = sample();
        short.actor_omni = "0x1122".into();
        assert!(parse_scope_grant(&short).is_err());
        let mut bad_cap = sample();
        bad_cap.max_total = "not-a-number".into();
        assert!(parse_scope_grant(&bad_cap).is_err());
    }

    #[test]
    fn build_scope_response_assembles_the_scope_only_op() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = AcceptConfig {
            rpc_url: "http://localhost".into(),
            chain_id: 212_013,
            entry_point: [0x66; 20],
            paymaster: None, // unsponsored direct handleOps (the default)
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
            build_scope_response(&sample(), master, nonce, &cfg, &sk, 9_999_999_999).unwrap();
        assert_eq!(resp.user_op.sender, format!("0x{}", hex::encode(master)));
        assert!(resp.user_op_hash.starts_with("0x") && resp.user_op_hash.len() == 66);
        // executeBatch selector — the same golden-tested entry the accept uses.
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a"));
        // setScope selector is inside; registerAgentDevice is NOT.
        let set_scope_sel = hex::encode(
            &agentkeys_core::device_crypto::keccak256(
                b"setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)",
            )[..4],
        );
        let register_sel = hex::encode(
            &agentkeys_core::device_crypto::keccak256(
                b"registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)",
            )[..4],
        );
        assert!(resp.user_op.call_data.contains(&set_scope_sel));
        assert!(!resp.user_op.call_data.contains(&register_sel));
        assert_eq!(resp.user_op.paymaster_and_data, "0x");
    }
}
