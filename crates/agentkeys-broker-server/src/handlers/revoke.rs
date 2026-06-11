//! The broker `/v1/revoke/build` flow: the Touch-ID-gated agent **unpair** and
//! the #260 master-reset **fleet teardown** (same endpoint, N hashes).
//!
//! `SidecarRegistry.revokeAgentDevice` enforces `msg.sender ==
//! operatorMasterWallet[device.operatorOmni]` — for an account-master operator
//! (#225) NO EOA can sign it, including the deployer (the legacy
//! `heima-device-revoke.sh` path reverts `NotAuthorized(caller, master)` — real
//! 2026-06-11 incident). So the revoke becomes ONE
//! `P256Account.executeBatch([revokeAgentDevice × N])` UserOp K11-signed by the
//! master — one element for the per-agent unpair, every paired agent for the
//! #260 reset teardown (ONE Touch ID, run BEFORE `resetMaster` clears
//! `operatorMasterWallet` and strands the bindings). The companion
//! `/v1/revoke/submit` route reuses [`crate::handlers::accept::accept_submit`]
//! verbatim (the relay carries nothing accept-specific).
//!
//! Because `revokeAgentDevice` REVERTS on already-revoked / never-registered
//! hashes (dooming the whole batch), the handler probes `getDevice` per hash
//! and silently SKIPS those (idempotent posture: a re-run after a partial
//! ceremony converges) while rejecting cross-operator or non-agent-tier hashes
//! outright (an auth violation, never a skip).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;

use agentkeys_core::erc4337::{AgentRegister, ScopeGrant};

use crate::handlers::accept::{
    aerr, bearer, call_entrypoint_nonce, call_operator_master_wallet, eth_address_has_code,
    eth_call, load_accept_config, norm_omni, selector, AcceptConfig, SPONSOR_WINDOW_SECS,
};
use crate::sponsored_accept::{assemble_revoke_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;

/// Most devices one fleet-revoke UserOp may carry. Bounds the calldata and the
/// scaled callGasLimit; a fleet larger than this needs multiple ceremonies
/// (none exists today — typical fleets are single digits).
pub const MAX_FLEET_REVOKE_DEVICES: usize = 64;

/// callGasLimit headroom added per batched revoke beyond the first.
/// `revokeAgentDevice` is one storage flip + event (~35k incl. cold SLOADs);
/// 60k/device keeps a comfortable margin while a 64-device batch stays well
/// under the EntryPoint prefund the paymaster deposit covers.
const REVOKE_CALL_GAS_PER_EXTRA_DEVICE: u128 = 60_000;

/// Broker-side mirror of `agentkeys_backend_client::protocol::BuildRevokeUserOpRequest`
/// (the broker doesn't depend on that crate; the frozen key-set test there pins the
/// shape). `POST /v1/revoke/build` body, J1_master-gated.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildRevokeRequest {
    pub operator_omni: String,
    /// The agents' on-chain `SidecarRegistry` device key hashes (`0x` + 64 hex
    /// each). One = unpair; many = the #260 reset fleet teardown.
    pub device_key_hashes: Vec<String>,
}

/// Parse + validate the wire request: the operator omni and the deduplicated
/// (order-preserving) device hash list. Duplicates are dropped rather than
/// rejected — the SECOND `revokeAgentDevice` over the same hash would revert
/// `DeviceAlreadyRevoked` mid-batch and doom the whole op.
pub fn parse_revoke(req: &BuildRevokeRequest) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s.trim().trim_start_matches("0x"))
            .map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    let operator_omni = h32(&req.operator_omni, "operator_omni")?;
    if req.device_key_hashes.is_empty() {
        return Err("device_key_hashes must not be empty".into());
    }
    if req.device_key_hashes.len() > MAX_FLEET_REVOKE_DEVICES {
        return Err(format!(
            "device_key_hashes carries {} devices — max {MAX_FLEET_REVOKE_DEVICES} per UserOp",
            req.device_key_hashes.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut hashes = Vec::with_capacity(req.device_key_hashes.len());
    for h in &req.device_key_hashes {
        let parsed = h32(h, "device_key_hash")?;
        if seen.insert(parsed) {
            hashes.push(parsed);
        }
    }
    Ok((operator_omni, hashes))
}

/// The `getDevice` words the fleet filter reads (of the 11-word `DeviceEntry`):
/// operatorOmni (w0), tier (w6), registeredAt (w8, 0 ⇒ never registered),
/// revoked (w10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProbe {
    pub operator_omni: [u8; 32],
    pub tier: u8,
    pub registered: bool,
    pub revoked: bool,
}

/// Parse a raw `getDevice(bytes32) -> DeviceEntry` eth_call return. The
/// registry's `devices` mapping returns an all-zero entry for unknown hashes
/// (no revert), so `registered == false` is a clean signal, not an error.
pub fn parse_device_probe(raw: &str) -> Result<DeviceProbe, String> {
    let hexs = raw.trim_start_matches("0x");
    let word = |i: usize| -> Result<[u8; 32], String> {
        let s = hexs
            .get(i * 64..(i + 1) * 64)
            .ok_or_else(|| format!("getDevice short return (word {i})"))?;
        let b = hex::decode(s).map_err(|e| format!("getDevice word {i} hex: {e}"))?;
        Ok(b.try_into().expect("64 hex chars decode to 32 bytes"))
    };
    Ok(DeviceProbe {
        operator_omni: word(0)?,
        tier: word(6)?[31],
        registered: word(8)? != [0u8; 32],
        revoked: word(10)?[31] != 0,
    })
}

/// `SidecarRegistry.TIER_AGENT` — the only tier `revokeAgentDevice` accepts.
const TIER_AGENT: u8 = 2;

/// **PURE** — split the probed hashes into the batch (active agent devices of
/// THIS operator) and the skipped set (already revoked / never registered —
/// including them would revert the whole batch). Cross-operator or
/// non-agent-tier hashes are an error: the caller asked to revoke something
/// this master could never legitimately revoke.
pub fn filter_revocable(
    operator_omni: &[u8; 32],
    probed: &[([u8; 32], DeviceProbe)],
) -> Result<(Vec<[u8; 32]>, Vec<String>), String> {
    let mut included = Vec::with_capacity(probed.len());
    let mut skipped = Vec::new();
    for (hash, probe) in probed {
        if !probe.registered || probe.revoked {
            skipped.push(format!(
                "0x{}: already revoked or never registered",
                hex::encode(hash)
            ));
            continue;
        }
        if &probe.operator_omni != operator_omni {
            return Err(format!(
                "device 0x{} belongs to a different operator",
                hex::encode(hash)
            ));
        }
        if probe.tier != TIER_AGENT {
            return Err(format!(
                "device 0x{} is not an agent-tier device (tier {}) — masters are revoked via \
                 the M-of-N recovery flow, not the unpair",
                hex::encode(hash),
                probe.tier
            ));
        }
        included.push(*hash);
    }
    Ok((included, skipped))
}

/// Bump the packed `accountGasLimits` word's callGasLimit half (low 16 bytes)
/// by `extra`, leaving verificationGasLimit (high 16) untouched. The fleet
/// batch executes N revokes where the pinned default budgets one call.
fn bump_call_gas_limit(packed: [u8; 32], extra: u128) -> [u8; 32] {
    let verification = u128::from_be_bytes(packed[..16].try_into().expect("16-byte half"));
    let call = u128::from_be_bytes(packed[16..].try_into().expect("16-byte half"));
    crate::sponsor::pack_u128_pair(verification, call.saturating_add(extra))
}

/// **PURE** — assemble the `/v1/revoke/build` response from the validated hash
/// batch + chain reads (master account + nonce) + config + the broker co-sign
/// key. `device_key_hashes` MUST be the `filter_revocable` output: active,
/// deduplicated, operator-owned agent devices.
pub fn build_revoke_response(
    operator_omni: &[u8; 32],
    device_key_hashes: &[[u8; 32]],
    master_account: [u8; 20],
    nonce: [u8; 32],
    cfg: &AcceptConfig,
    broker_sk: &k256::ecdsa::SigningKey,
    valid_until: u64,
) -> Result<BuildAcceptResponse, String> {
    if device_key_hashes.is_empty() {
        return Err("nothing to revoke".into());
    }
    // The params struct is shared with accept/scope; the revoke composer reads
    // none of the register fields (hashes ride the dedicated argument).
    let register = AgentRegister {
        device_key_hash: device_key_hashes[0],
        operator_omni: *operator_omni,
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
    let extra_call_gas =
        REVOKE_CALL_GAS_PER_EXTRA_DEVICE.saturating_mul((device_key_hashes.len() - 1) as u128);
    let params = AcceptUserOpParams {
        entry_point: cfg.entry_point,
        chain_id: cfg.chain_id,
        master_account,
        registry: cfg.registry,
        scope: cfg.scope,
        nonce,
        account_gas_limits: bump_call_gas_limit(cfg.account_gas_limits, extra_call_gas),
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
    let assembled =
        assemble_revoke_userop(&params, device_key_hashes, broker_sk).map_err(|e| e.to_string())?;
    Ok(assembled.into_build_response(&cfg.entry_point, cfg.chain_id))
}

/// `POST /v1/revoke/build` (J1_master) — assemble the revoke UserOp over the
/// still-active subset of the requested devices and return the `userOpHash`
/// the master K11-signs. Submit the signed op to `/v1/revoke/submit` (the
/// shared accept relay).
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
    let (operator_omni, requested) =
        parse_revoke(&req).map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;

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

    // 4. probe each requested device; skip not-revocable, reject not-ours.
    let mut probed = Vec::with_capacity(requested.len());
    for hash in &requested {
        let data = format!("0x{}{}", selector("getDevice(bytes32)"), hex::encode(hash));
        let raw = eth_call(&state.http, &cfg.rpc_url, &cfg.registry, &data)
            .await
            .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
        let probe = parse_device_probe(&raw).map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
        probed.push((*hash, probe));
    }
    let (included, skipped) =
        filter_revocable(&operator_omni, &probed).map_err(|e| aerr(StatusCode::FORBIDDEN, e))?;
    if included.is_empty() {
        return Err(aerr(
            StatusCode::CONFLICT,
            format!(
                "nothing to revoke — every requested device is already revoked or was never \
                 registered ({})",
                skipped.join("; ")
            ),
        ));
    }
    if !skipped.is_empty() {
        tracing::info!(
            target: "agentkeys.broker.revoke",
            skipped = skipped.len(),
            included = included.len(),
            "revoke build: skipping not-revocable devices: {}",
            skipped.join("; ")
        );
    }

    let nonce = call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;

    // 5. assemble + co-sign.
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + SPONSOR_WINDOW_SECS;
    let resp = build_revoke_response(
        &operator_omni,
        &included,
        master_account,
        nonce,
        &cfg,
        &broker_sk,
        valid_until,
    )
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
            device_key_hashes: vec![format!("0x{}", "11".repeat(32))],
        }
    }

    fn probe(operator: u8, tier: u8, registered: bool, revoked: bool) -> DeviceProbe {
        DeviceProbe {
            operator_omni: [operator; 32],
            tier,
            registered,
            revoked,
        }
    }

    #[test]
    fn parses_omni_and_device_hashes_deduped() {
        let (omni, hashes) = parse_revoke(&sample()).unwrap();
        assert_eq!(omni, [0x22; 32]);
        assert_eq!(hashes, vec![[0x11; 32]]);

        // duplicates collapse (a repeat would revert DeviceAlreadyRevoked mid-batch).
        let mut multi = sample();
        multi.device_key_hashes = vec![
            format!("0x{}", "11".repeat(32)),
            format!("0x{}", "33".repeat(32)),
            format!("0x{}", "11".repeat(32)),
        ];
        let (_, hashes) = parse_revoke(&multi).unwrap();
        assert_eq!(hashes, vec![[0x11; 32], [0x33; 32]]);

        let mut bad = sample();
        bad.device_key_hashes = vec!["0x1122".into()];
        assert!(parse_revoke(&bad).is_err());

        let mut empty = sample();
        empty.device_key_hashes = vec![];
        assert!(parse_revoke(&empty).unwrap_err().contains("empty"));

        let mut over = sample();
        over.device_key_hashes = (0..=MAX_FLEET_REVOKE_DEVICES)
            .map(|i| format!("0x{:064x}", i + 1))
            .collect();
        assert!(parse_revoke(&over).unwrap_err().contains("max"));
    }

    #[test]
    fn filter_skips_revoked_and_unregistered_rejects_foreign_and_master() {
        let omni = [0x22u8; 32];
        // active agent + already-revoked + never-registered → one included, two skipped.
        let probed = vec![
            ([0x11; 32], probe(0x22, TIER_AGENT, true, false)),
            ([0x33; 32], probe(0x22, TIER_AGENT, true, true)),
            ([0x44; 32], probe(0x00, 0, false, false)),
        ];
        let (included, skipped) = filter_revocable(&omni, &probed).unwrap();
        assert_eq!(included, vec![[0x11; 32]]);
        assert_eq!(skipped.len(), 2);

        // a foreign operator's active device is an auth violation, not a skip.
        let foreign = vec![([0x55; 32], probe(0x99, TIER_AGENT, true, false))];
        assert!(filter_revocable(&omni, &foreign)
            .unwrap_err()
            .contains("different operator"));

        // a master-tier device can't ride the unpair batch.
        let master = vec![([0x66; 32], probe(0x22, 1, true, false))];
        assert!(filter_revocable(&omni, &master)
            .unwrap_err()
            .contains("not an agent-tier"));
    }

    #[test]
    fn parses_device_probe_words() {
        // 11 static words: operatorOmni, actorOmni, k11CredId, k11RpIdHash,
        // k11PubX, k11PubY, tier, roles, registeredAt, lastSignCount, revoked.
        let mut words = vec!["0".repeat(64); 11];
        words[0] = "22".repeat(32); // operatorOmni
        words[6] = format!("{:0>64}", 2); // tier = TIER_AGENT
        words[8] = format!("{:0>64}", 9); // registeredAt
        words[10] = format!("{:0>64}", 1); // revoked
        let raw = format!("0x{}", words.join(""));
        let p = parse_device_probe(&raw).unwrap();
        assert_eq!(p.operator_omni, [0x22; 32]);
        assert_eq!(p.tier, 2);
        assert!(p.registered);
        assert!(p.revoked);

        // an all-zero entry (unknown hash) parses as never-registered.
        let zeroed = format!("0x{}", "0".repeat(64 * 11));
        let p = parse_device_probe(&zeroed).unwrap();
        assert!(!p.registered && !p.revoked);

        assert!(parse_device_probe("0x1234").is_err());
    }

    fn test_cfg() -> AcceptConfig {
        AcceptConfig {
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
        }
    }

    #[test]
    fn build_revoke_response_assembles_the_revoke_only_op() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = test_cfg();
        let master = [0x99u8; 20];
        let mut nonce = [0u8; 32];
        nonce[31] = 7;
        let resp = build_revoke_response(
            &[0x22; 32],
            &[[0x11; 32]],
            master,
            nonce,
            &cfg,
            &sk,
            9_999_999_999,
        )
        .unwrap();
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
        // single device → the pinned gas limits ride unchanged.
        assert_eq!(
            resp.user_op.account_gas_limits,
            format!(
                "0x{}",
                hex::encode(crate::sponsor::pack_u128_pair(1_500_000, 2_000_000))
            )
        );
    }

    #[test]
    fn fleet_revoke_batches_every_hash_and_scales_call_gas() {
        // #260: three agents → ONE executeBatch carrying all three revokes, with
        // callGasLimit bumped 60k per device beyond the first.
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = test_cfg();
        let hashes = [[0x11u8; 32], [0x33; 32], [0x55; 32]];
        let resp = build_revoke_response(
            &[0x22; 32],
            &hashes,
            [0x99; 20],
            [0u8; 32],
            &cfg,
            &sk,
            9_999_999_999,
        )
        .unwrap();
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a"));
        for h in ["11", "33", "55"] {
            assert!(
                resp.user_op
                    .call_data
                    .contains(&format!("b269f9fb{}", h.repeat(32))),
                "missing revoke for 0x{h}…"
            );
        }
        assert_eq!(
            resp.user_op.account_gas_limits,
            format!(
                "0x{}",
                hex::encode(crate::sponsor::pack_u128_pair(
                    1_500_000,
                    2_000_000 + 2 * 60_000
                ))
            )
        );
    }

    #[test]
    fn bump_call_gas_touches_only_the_call_half() {
        let packed = crate::sponsor::pack_u128_pair(1_500_000, 2_000_000);
        let bumped = bump_call_gas_limit(packed, 120_000);
        assert_eq!(bumped, crate::sponsor::pack_u128_pair(1_500_000, 2_120_000));
    }
}
