//! #278 D6 — the broker `/v1/register/build` flow: the ONE sponsored UserOp that
//! collapses the master register ceremony.
//!
//! The legacy register is 3 chain interactions (deployer `createAccount` +
//! deployer `EntryPoint.depositTo` + a self-deposit-funded register UserOp — see
//! `e2e/scripts/erc4337-register-master.sh`). D6 collapses them into a SINGLE
//! paymaster-sponsored UserOp = `initCode` (counterfactual
//! `P256AccountFactory.createAccount` deploy) + `executeBatch([
//! registerFirstMasterDevice])`, gated by ONE master K11 Touch ID — zero deployer
//! txs in the user path. It mirrors `/v1/accept/build` (the proven sponsored-batch
//! shape); the companion `/v1/register/submit` route reuses
//! [`crate::handlers::accept::accept_submit`] verbatim (the relay carries nothing
//! register-specific — the `WireUserOp`'s non-empty `init_code` rides through
//! `wire_to_packed` → the bundler → `EntryPoint.handleOps`, which deploys the
//! account from the `initCode` before running the batch).
//!
//! Auth mirrors the accept: the J1_master session omni MUST equal the request
//! `operator_omni`. The broker DERIVES every omni-keyed value (cred-id / CREATE2
//! salt / device-key hashes via the shared `agentkeys_core::erc4337` helpers,
//! `actor_omni == operator_omni` — a first master IS the operator) so a client
//! can't drift them; the request carries only what the broker can't derive (the
//! master passkey coords, the WebAuthn `rpid_hash`, the `roles` bitmap).
//!
//! **Skip-gate = the pre-flight.** `registerFirstMasterDevice` is first-master-only
//! (`SidecarRegistry` reverts `DeviceAlreadyRegistered` once `operatorMasterWallet
//! != 0`), so the handler checks `operatorMasterWallet(omni) == 0` AND
//! `eth_getCode(predicted) == 0x` BEFORE assembling the op — a doomed (already
//! registered) request returns 409 with NO Touch ID prompt and NO gas spent. The
//! predicted sender is read from `factory.getAddress(...)` (authoritative — never
//! recomputed in Rust), which also proves the factory is correctly configured +
//! callable. (A full `eth_estimateUserOperationGas` pre-flight is not wired: the
//! v0.7 EntryPoint has no on-chain `simulateHandleOp`, the in-house bundler does
//! not implement the estimate RPC, and there is no signature at build time to
//! validate — the already-registered skip-gate is the realistic doomed-before-
//! biometric case for register.)
//!
//! Register is **sponsored-only**: a live `PAYMASTER_ADDRESS[_<CHAIN>]` is required
//! (503 otherwise). Unlike accept it has no unsponsored fallback — the whole point
//! of D6 is zero deployer txs in the user path.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;

use agentkeys_core::erc4337::{
    master_account_salt, master_cred_id_hash, master_device_key_hash,
    p256_account_factory_init_code, AgentRegister, RegisterFirstMaster, ScopeGrant,
};

use crate::handlers::accept::{
    addr20, aerr, bearer, call_entrypoint_nonce, call_operator_master_wallet, env_profile,
    eth_address_has_code, eth_call, load_accept_config, norm_omni, selector, AcceptConfig,
    SPONSOR_WINDOW_SECS,
};
use crate::sponsored_accept::{assemble_register_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;

/// #501 — is the bundler able to SUBMIT + PAY for a handleOps right now?
/// Returns `Some(reason)` only on a DEFINITE not-ready (`ready:false` from the
/// bundler's `/healthz` — missing signer/EntryPoint, or the submitter below the
/// chain gas floor), else `None`. The bundler owns the answer (it holds the
/// submitter key, so it alone knows the address + balance). Fail-OPEN: an unset
/// URL or an unreachable/garbled health response returns `None` — a truly-down
/// stack is already caught by the #435 chain probe, and a blip must never block
/// a funded register. Read the bundler's own `reason`/`missing` string verbatim
/// so the operator-facing text has ONE source (the bundler).
async fn bundler_not_ready_reason(state: &SharedState) -> Option<String> {
    let base = std::env::var("AGENTKEYS_BUNDLER_URL").ok()?;
    let url = format!("{}/healthz", base.trim_end_matches('/'));
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        state.http.get(&url).send(),
    )
    .await
    .ok()?
    .ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    // ready == true (or the field absent on an old bundler) ⇒ not our concern.
    if body.get("ready").and_then(serde_json::Value::as_bool) != Some(false) {
        return None;
    }
    // Prefer the #501 gas `reason`; fall back to the degraded `missing` list.
    if let Some(reason) = body.get("reason").and_then(serde_json::Value::as_str) {
        return Some(reason.to_string());
    }
    let missing = body
        .get("missing")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unconfigured".to_string());
    Some(format!(
        "the bundler is not ready ({missing}) — arm the submitter key / EntryPoint \
         (setup-broker-host.sh) so it can submit + pay for handleOps"
    ))
}

/// Broker-side mirror of `agentkeys_backend_client::protocol::BuildRegisterUserOpRequest`
/// (the broker doesn't depend on that crate; the frozen key-set test there pins the
/// shape). `POST /v1/register/build` body, J1_master-gated.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildRegisterRequest {
    pub operator_omni: String,
    /// Master P-256 passkey X coordinate (`0x` + 64 hex, raw big-endian word).
    pub owner_pubkey_x: String,
    /// Master P-256 passkey Y coordinate (`0x` + 64 hex).
    pub owner_pubkey_y: String,
    /// WebAuthn RP-ID hash (`sha256(rpId)`, `0x` + 64 hex) — deployment/domain
    /// specific, so the broker can't derive it.
    pub rpid_hash: String,
    /// `SidecarRegistry` role bitmap for the first master device.
    pub roles: u8,
}

/// The validated register inputs the broker can't derive (everything else —
/// cred-id / CREATE2 salt / device-key hashes, `actor_omni` — is derived from
/// `omni`). All hex fields are 32-byte words.
struct ParsedRegister {
    omni: [u8; 32],
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    rpid_hash: [u8; 32],
    roles: u8,
}

/// Parse + validate the wire request.
fn parse_register(req: &BuildRegisterRequest) -> Result<ParsedRegister, String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s.trim().trim_start_matches("0x"))
            .map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    Ok(ParsedRegister {
        omni: h32(&req.operator_omni, "operator_omni")?,
        pub_x: h32(&req.owner_pubkey_x, "owner_pubkey_x")?,
        pub_y: h32(&req.owner_pubkey_y, "owner_pubkey_y")?,
        rpid_hash: h32(&req.rpid_hash, "rpid_hash")?,
        roles: req.roles,
    })
}

/// `P256AccountFactory.getAddress(bytes32,uint256,uint256,bytes32,bytes32) -> address`
/// — the AUTHORITATIVE counterfactual master-account address (the CREATE2 sender
/// `handleOps` will deploy from the `initCode`). Never recompute the CREATE2 in
/// Rust: an off-by-a-byte preimage would bind the master to the wrong address.
#[allow(clippy::too_many_arguments)] // the 5 getAddress inputs + (http, rpc, factory) — a builder hides nothing
async fn call_factory_get_address(
    http: &reqwest::Client,
    rpc: &str,
    factory: &[u8; 20],
    cred_id_hash: &[u8; 32],
    pub_x: &[u8; 32],
    pub_y: &[u8; 32],
    rpid_hash: &[u8; 32],
    salt: &[u8; 32],
) -> Result<[u8; 20], String> {
    let mut data = format!(
        "0x{}",
        selector("getAddress(bytes32,uint256,uint256,bytes32,bytes32)")
    );
    data.push_str(&hex::encode(cred_id_hash));
    data.push_str(&hex::encode(pub_x));
    data.push_str(&hex::encode(pub_y));
    data.push_str(&hex::encode(rpid_hash));
    data.push_str(&hex::encode(salt));
    let raw = eth_call(http, rpc, factory, &data).await?;
    let hexs = raw.trim_start_matches("0x");
    if hexs.len() < 64 {
        return Err(format!("factory.getAddress short return: {raw}"));
    }
    addr20(&hexs[24..64], "factory.getAddress")
}

/// **PURE** — assemble the `/v1/register/build` response from the request +
/// the predicted account (read via `factory.getAddress`) + config + the broker
/// co-sign key. The async handler does the auth + chain reads + skip-gate, then
/// calls this. Derives the omni-keyed values (cred-id / salt / device-key hashes,
/// `actor_omni == operator_omni`) from the request omni so they can't drift.
/// `account_already_deployed` ⇒ the recover path (an earlier attempt deployed the
/// account but didn't register) — emit an EMPTY initCode so the op doesn't re-deploy.
#[allow(clippy::too_many_arguments)] // envelope inputs + the recover flag — a builder hides nothing
pub fn build_register_response(
    req: &BuildRegisterRequest,
    master_account: [u8; 20],
    nonce: [u8; 32],
    cfg: &AcceptConfig,
    factory: [u8; 20],
    account_already_deployed: bool,
    broker_sk: &k256::ecdsa::SigningKey,
    valid_until: u64,
) -> Result<BuildAcceptResponse, String> {
    let ParsedRegister {
        omni,
        pub_x,
        pub_y,
        rpid_hash,
        roles,
    } = parse_register(req)?;
    let cred_id_hash = master_cred_id_hash(&omni);
    let salt = master_account_salt(&omni);
    let device_key_hash = master_device_key_hash(&omni);

    // Recover path (account already deployed) ⇒ no counterfactual deploy in initCode.
    let init_code = if account_already_deployed {
        Vec::new()
    } else {
        p256_account_factory_init_code(&factory, &cred_id_hash, &pub_x, &pub_y, &rpid_hash, &salt)
    };
    let register = RegisterFirstMaster {
        device_key_hash,
        operator_omni: omni,
        actor_omni: omni,
        cred_id_hash,
        rpid_hash,
        pub_x,
        pub_y,
        roles,
    };

    // The shared `AcceptUserOpParams` requires register/grant intents; the register
    // composer ignores them (like `assemble_revoke_userop`), reading only the
    // envelope + `p.registry`. Dummies keep the type honest without overload.
    let dummy_register = AgentRegister {
        device_key_hash: [0u8; 32],
        operator_omni: omni,
        actor_omni: omni,
        link_code_redemption: Vec::new(),
        agent_pop_sig: Vec::new(),
    };
    let dummy_grant = ScopeGrant {
        services: Vec::new(),
        read_only: true,
        max_per_call: 0,
        max_per_period: 0,
        max_total: 0,
        period_seconds: 0,
    };
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
        register: &dummy_register,
        grant: &dummy_grant,
    };
    let assembled = assemble_register_userop(&params, init_code, &register, broker_sk)
        .map_err(|e| e.to_string())?;
    Ok(assembled.into_build_response(&cfg.entry_point, cfg.chain_id))
}

/// `POST /v1/register/build` (J1_master) — assemble the ONE sponsored master
/// register UserOp (`initCode` + `executeBatch([registerFirstMasterDevice])`) and
/// return the `userOpHash` the master K11-signs. Submit the signed op to
/// `/v1/register/submit` (the shared accept relay).
pub async fn register_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<BuildRegisterRequest>,
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

    // 2. config + co-sign key (shared with accept — same drift guard + gas profile).
    let (cfg, broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    // Register is sponsored-only: the D6 collapse's premise is zero deployer txs in
    // the user path, so it has no unsponsored fallback (unlike accept).
    if cfg.paymaster.is_none() {
        return Err(aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "register is sponsored-only — set PAYMASTER_ADDRESS[_<CHAIN>] in the broker env \
             (the #278 D6 one-op register has no unsponsored fallback; fund the VerifyingPaymaster \
             EntryPoint deposit for initCode+register)",
        ));
    }

    // 2b. #501 — the BUNDLER must be able to pay for handleOps, or the register
    //     will fail AFTER the browser has already minted a passkey (2 Touch IDs,
    //     an orphaned credential, no master). Gate HERE, before parse_register,
    //     so the daemon's preflight probe (a garbage body that never parses)
    //     hits it too → GET /v1/master/register/preflight reports register_ready
    //     false with the bundler's own reason → onboarding stops before
    //     credentials.create. Fail-open on an unreachable bundler: the #435
    //     chain probe already covers a truly-down stack, and a health-check blip
    //     must not block a funded one. 503 = the same status load_accept_config
    //     failure uses, so the preflight's 503-vs-not check is unchanged.
    if let Some(reason) = bundler_not_ready_reason(&state).await {
        return Err(aerr(StatusCode::SERVICE_UNAVAILABLE, reason));
    }

    // 3. factory address (the omni-keyed account is counterfactually deployed by it).
    let factory = addr20(
        &env_profile("P256_ACCOUNT_FACTORY_ADDRESS")
            .map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?,
        "P256_ACCOUNT_FACTORY_ADDRESS",
    )
    .map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;

    // 4. parse + derive the omni-keyed values (broker-derived → can't drift).
    let ParsedRegister {
        omni,
        pub_x,
        pub_y,
        rpid_hash,
        ..
    } = parse_register(&req).map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let cred_id_hash = master_cred_id_hash(&omni);
    let salt = master_account_salt(&omni);

    // 5. SKIP-GATE (the pre-flight) — fail BEFORE assembly so no Touch ID is wasted.
    //    registerFirstMasterDevice is first-master-only; a second call reverts.
    let existing =
        call_operator_master_wallet(&state.http, &cfg.rpc_url, &cfg.registry, &req.operator_omni)
            .await
            .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    if existing != [0u8; 20] {
        return Err(aerr(
            StatusCode::CONFLICT,
            format!(
                "operator already has a master 0x{} on chain — registerFirstMasterDevice is \
                 first-master-only (use the additional-master / recovery flow to add a device)",
                hex::encode(existing)
            ),
        ));
    }
    let predicted = call_factory_get_address(
        &state.http,
        &cfg.rpc_url,
        &factory,
        &cred_id_hash,
        &pub_x,
        &pub_y,
        &rpid_hash,
        &salt,
    )
    .await
    .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    // The account address is deterministic, so an EARLIER one-op attempt may have
    // deployed it via initCode yet had its registerFirstMasterDevice execution
    // revert — leaving getCode(predicted) != 0 while operatorMasterWallet stays 0
    // (the `existing != 0` check above already ruled out a genuine prior register).
    // That is a RECOVERABLE state, NOT "already registered": rebuild against the
    // existing account with an EMPTY initCode (no re-deploy) + the live nonce so the
    // retry can still bind. A non-zero operatorMasterWallet is the only true 409.
    let already_deployed = eth_address_has_code(&state.http, &cfg.rpc_url, &predicted)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;

    // 6. Nonce: a deployed-but-unregistered account uses its live EntryPoint nonce;
    //    a fresh (undeployed) account's first nonce is 0 (do NOT call getNonce on a
    //    non-existent sender — createAccount in the initCode is idempotent).
    let nonce = if already_deployed {
        call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &predicted)
            .await
            .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?
    } else {
        [0u8; 32]
    };

    // 7. assemble + co-sign (sponsored — co-sign over the paymaster getHash).
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + SPONSOR_WINDOW_SECS;
    let resp = build_register_response(
        &req,
        predicted,
        nonce,
        &cfg,
        factory,
        already_deployed,
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

    fn sample() -> BuildRegisterRequest {
        BuildRegisterRequest {
            operator_omni: format!("0x{}", "22".repeat(32)),
            owner_pubkey_x: format!("0x{}", "66".repeat(32)),
            owner_pubkey_y: format!("0x{}", "77".repeat(32)),
            rpid_hash: format!("0x{}", "55".repeat(32)),
            roles: 2,
        }
    }

    fn sponsored_cfg() -> AcceptConfig {
        AcceptConfig {
            rpc_url: "http://localhost".into(),
            chain_id: 212_013,
            entry_point: [0x66; 20],
            paymaster: Some([0x55; 20]), // sponsored — register requires it
            broker_signer: [0x77; 20],
            registry: [0xa1; 20],
            scope: [0xa2; 20],
            account_gas_limits: crate::sponsor::pack_u128_pair(200_000, 2_000_000),
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
    fn parses_omni_pubkey_and_rpid() {
        let p = parse_register(&sample()).unwrap();
        assert_eq!(p.omni, [0x22; 32]);
        assert_eq!(p.pub_x, [0x66; 32]);
        assert_eq!(p.pub_y, [0x77; 32]);
        assert_eq!(p.rpid_hash, [0x55; 32]);
        assert_eq!(p.roles, 2);
    }

    #[test]
    fn rejects_bad_hex_and_short_words() {
        let mut bad = sample();
        bad.operator_omni = "0xZZ".into();
        assert!(parse_register(&bad).is_err());
        let mut short = sample();
        short.owner_pubkey_x = "0x1122".into();
        assert!(parse_register(&short).is_err());
    }

    #[test]
    fn build_register_response_carries_initcode_and_register_batch() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = sponsored_cfg();
        let factory = [0xfa; 20];
        // The handler reads this via factory.getAddress; here we pass a stand-in.
        let predicted = [0x99u8; 20];
        let resp = build_register_response(
            &sample(),
            predicted,
            [0u8; 32],
            &cfg,
            factory,
            false,
            &sk,
            9_999_999_999,
        )
        .unwrap();

        // sender is the predicted counterfactual account.
        assert_eq!(resp.user_op.sender, format!("0x{}", hex::encode(predicted)));
        assert!(resp.user_op_hash.starts_with("0x") && resp.user_op_hash.len() == 66);

        // initCode = factory(20) || createAccount(...) = 184 bytes, the register-only
        // carrier (accept/scope/revoke leave it "0x"). First 20 bytes are the factory.
        let init = hex::decode(resp.user_op.init_code.trim_start_matches("0x")).unwrap();
        assert_eq!(init.len(), 184);
        assert_eq!(&init[..20], &factory);
        assert_eq!(hex::encode(&init[20..24]), "6b97f6c6"); // createAccount selector

        // callData = executeBatch([registerFirstMasterDevice]).
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a")); // executeBatch
        assert!(resp.user_op.call_data.contains("93b14d7c")); // registerFirstMasterDevice
                                                              // sponsored ⇒ non-empty paymasterAndData (129-byte envelope).
        assert_ne!(resp.user_op.paymaster_and_data, "0x");
        assert_eq!(
            hex::decode(resp.user_op.paymaster_and_data.trim_start_matches("0x"))
                .unwrap()
                .len(),
            129
        );
    }

    #[test]
    fn derivations_match_the_core_helpers_and_initcode_binds_them() {
        // The build derives cred/salt/device from the omni; pin that the initCode
        // embeds the SAME cred-id + salt the registerFirstMasterDevice call commits.
        let omni = [0x22u8; 32];
        let cred = master_cred_id_hash(&omni);
        let salt = master_account_salt(&omni);
        let _device = master_device_key_hash(&omni);
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let resp = build_register_response(
            &sample(),
            [0x99; 20],
            [0u8; 32],
            &sponsored_cfg(),
            [0xfa; 20],
            false,
            &sk,
            9_999_999_999,
        )
        .unwrap();
        let init = hex::decode(resp.user_op.init_code.trim_start_matches("0x")).unwrap();
        // initCode layout: factory(20) ‖ selector(4) ‖ cred(32) ‖ x(32) ‖ y(32) ‖ rpid(32) ‖ salt(32).
        assert_eq!(&init[24..56], &cred); // credIdHash
        assert_eq!(&init[120..152], &[0x55u8; 32]); // rpIdHash
        assert_eq!(&init[152..184], &salt); // salt
    }

    #[test]
    fn recover_path_already_deployed_emits_empty_initcode_but_same_register_batch() {
        // Deployed-but-unregistered recover (account_already_deployed=true): NO
        // re-deploy, so initCode is empty — but the executeBatch([registerFirstMaster])
        // intent is unchanged, so the op still binds the master on retry.
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let resp = build_register_response(
            &sample(),
            [0x99; 20],
            [0u8; 32],
            &sponsored_cfg(),
            [0xfa; 20],
            true, // account_already_deployed
            &sk,
            9_999_999_999,
        )
        .unwrap();
        assert_eq!(resp.user_op.init_code, "0x"); // no re-deploy
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a")); // executeBatch
        assert!(resp.user_op.call_data.contains("93b14d7c")); // registerFirstMasterDevice
                                                              // still sponsored + a deterministic hash over the (now initCode-less) op.
        assert_ne!(resp.user_op.paymaster_and_data, "0x");
        assert!(resp.user_op_hash.starts_with("0x") && resp.user_op_hash.len() == 66);
    }
}
