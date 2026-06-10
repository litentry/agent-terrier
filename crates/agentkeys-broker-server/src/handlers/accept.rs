//! #225 / #164 E7 — the broker `/v1/accept/*` flow (the Touch-ID-gated agent accept).
//!
//! The accept becomes ONE sponsored `P256Account.executeBatch([registerAgentDevice,
//! setScope])` UserOp gated by the master's K11 Touch ID. Two J1_master-gated routes:
//! `/v1/accept/build` assembles the op + returns the `userOpHash` the browser passkey
//! signs; `/v1/accept/submit` relays the signed op to `EntryPoint.handleOps`.
//!
//! **Slice 1 (this file):** the `/v1/accept/build` request type + the pure parse from
//! the wire request into the typed `agentkeys_core::erc4337` structs that the
//! sponsored-UserOp composer (`crate::sponsored_accept::assemble_accept_userop`)
//! consumes. The axum handler — J1 auth (mirroring `handlers::cap::mint_cap`), chain
//! reads of `SidecarRegistry.operatorMasterWallet` + `EntryPoint.getNonce`, the broker
//! co-sign, and the `handleOps` submit — builds on this in the next slices.

use agentkeys_core::erc4337::{AgentRegister, ScopeGrant};
use serde::Deserialize;

/// Broker-side mirror of `agentkeys_backend_client::protocol::BuildAcceptUserOpRequest`
/// (the broker doesn't depend on that crate; the frozen key-set test there pins the
/// shape). `POST /v1/accept/build` body, J1_master-gated.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildAcceptRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub device_key_hash: String,
    pub agent_pop_sig: String,
    pub link_code_redemption: String,
    pub services: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
}

/// Parse the wire request into the typed register + scope-grant args. A scope
/// `service` string becomes a `bytes32` via `keccak256(lowercase(service))` — the
/// SAME hash `heima-scope-set.sh` writes, so a service id is byte-identical on every
/// path (the terminology-source-of-truth rule, at the encoding level). The `u128`
/// caps ride as decimal strings (wire-safe past 2^53).
pub fn parse_register_and_grant(
    req: &BuildAcceptRequest,
) -> Result<(AgentRegister, ScopeGrant), String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    let raw = |s: &str, name: &str| -> Result<Vec<u8>, String> {
        hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("{name} hex: {e}"))
    };
    let cap = |s: &str, name: &str| -> Result<u128, String> {
        s.parse::<u128>().map_err(|e| format!("{name}: {e}"))
    };

    let register = AgentRegister {
        device_key_hash: h32(&req.device_key_hash, "device_key_hash")?,
        operator_omni: h32(&req.operator_omni, "operator_omni")?,
        actor_omni: h32(&req.actor_omni, "actor_omni")?,
        link_code_redemption: raw(&req.link_code_redemption, "link_code_redemption")?,
        agent_pop_sig: raw(&req.agent_pop_sig, "agent_pop_sig")?,
    };
    let services: Vec<[u8; 32]> = req
        .services
        .iter()
        .map(|s| agentkeys_core::device_crypto::keccak256(s.to_lowercase().as_bytes()))
        .collect();
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

// ─── slice 2: the /v1/accept/build handler ──────────────────────────────────

use crate::sponsored_accept::{assemble_accept_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use k256::ecdsa::SigningKey;

// Gas defaults (named constants per the no-hardcoded-values rule; override via the
// matching ACCEPT_* env vars).
//
// verificationGasLimit = 1.5M: the account's validateUserOp does an ON-CHAIN P256
// (WebAuthn) signature verify, which is gas-heavy on Heima (pure-Solidity / no cheap
// precompile). The cap MUST cover it — at 600k the verify ran out of gas INSIDE the
// account's `try checkUserOpSignature catch { SIG_FAIL }`, so the catch mapped the OOG
// to SIG_VALIDATION_FAILED and handleOps reverted AA24 ("wrong passkey" — but actually
// gas starvation; #225). 1.5M is the value the working passkey REGISTER UserOp uses.
//
// maxFeePerGas = 40 gwei: Heima's base fee is ~25 gwei, so the old 2 gwei was below
// base fee (the userOp couldn't pay actual gas). 40 gwei clears base + priority AND
// keeps the max prefund (sum of gas limits × maxFee ≈ 0.15 HEI) under the paymaster's
// 0.2 HEI EntryPoint deposit. (A future hardening reads the live base fee + buffers.)
const DEF_VERIFICATION_GAS_LIMIT: u128 = 1_500_000;
const DEF_CALL_GAS_LIMIT: u128 = 2_000_000;
const DEF_PRE_VERIFICATION_GAS: u128 = 100_000;
const DEF_MAX_PRIORITY_FEE: u128 = 1_000_000_000;
const DEF_MAX_FEE: u128 = 40_000_000_000;
const DEF_PAYMASTER_VERIFICATION_GAS: u128 = 200_000;
const DEF_PAYMASTER_POST_OP_GAS: u128 = 50_000;
const SPONSOR_WINDOW_SECS: u64 = 3600;

/// Sponsor + chain config the build handler needs beyond the request, read from the
/// broker process env (wired by setup-broker-host.sh). All addresses 20-byte.
pub struct AcceptConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub entry_point: [u8; 20],
    /// `Some` = sponsored (VerifyingPaymaster); `None` = unsponsored direct
    /// `handleOps` (the default — the VerifyingPaymaster is not deployed).
    pub paymaster: Option<[u8; 20]>,
    pub broker_signer: [u8; 20],
    pub registry: [u8; 20],
    pub scope: [u8; 20],
    pub account_gas_limits: [u8; 32],
    pub pre_verification_gas: [u8; 32],
    pub gas_fees: [u8; 32],
    pub paymaster_verification_gas_limit: u128,
    pub paymaster_post_op_gas_limit: u128,
}

fn u256_word(n: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn addr20(hex_s: &str, name: &str) -> Result<[u8; 20], String> {
    let b =
        hex::decode(hex_s.trim().trim_start_matches("0x")).map_err(|e| format!("{name}: {e}"))?;
    b.try_into()
        .map_err(|_| format!("{name} must be a 20-byte address"))
}

/// Profile-aware env read: `BASE_<CHAIN>` (e.g. `SIDECAR_REGISTRY_ADDRESS_HEIMA`),
/// falling back to the bare `BASE` — the same convention the operator env uses.
fn env_profile(base: &str) -> Result<String, String> {
    let p = std::env::var("AGENTKEYS_CHAIN")
        .unwrap_or_else(|_| "heima".into())
        .to_uppercase()
        .replace('-', "_");
    std::env::var(format!("{base}_{p}"))
        .or_else(|_| std::env::var(base))
        .map_err(|_| format!("env {base}[_{p}] not set"))
}

/// #231 drift guard — the accept-env vs compiled-chain-profile cross-check
/// `load_accept_config` enforces.
///
/// The compiled-in chain profile (`include_str!`'d `heima.json`) is the source of
/// truth for the deployed contract set; the accept env is whatever the broker host
/// was last deployed with. A mismatch means the broker is on a STALE deployment,
/// and every accept it builds is doomed to revert against the wrong contracts —
/// surfacing as a misleading "wrong passkey (SIG_VALIDATION_FAILED)" (two real
/// incidents, 2026-06-09). Pure (no env reads) so unit tests avoid process-global
/// env races.
///
/// `checks` is `(env var name, profile contract name, env-parsed address)`. A
/// contract the profile doesn't carry is skipped — a chain with no deployed
/// registry has nothing to drift from. `allow_override` (CI/test stacks whose own
/// contract deploy legitimately differs from the compiled prod profile) downgrades
/// the hard error to a `tracing::warn!`.
fn enforce_profile_drift_guard(
    profile: &agentkeys_core::chain_profile::ChainProfile,
    checks: &[(&str, &str, [u8; 20])],
    allow_override: bool,
) -> Result<(), String> {
    let mut mismatches = Vec::new();
    for (env_name, contract_name, env_addr) in checks {
        let Some(deployed) = profile.contract(contract_name) else {
            continue;
        };
        match addr20(&deployed.address, contract_name) {
            Ok(profile_addr) if &profile_addr == env_addr => {}
            Ok(_) => mismatches.push(format!(
                "accept-env {env_name}=0x{} != chain profile {} ({contract_name})",
                hex::encode(env_addr),
                deployed.address
            )),
            Err(e) => mismatches.push(format!("chain profile {contract_name}: {e}")),
        }
    }
    if mismatches.is_empty() {
        return Ok(());
    }
    let detail = mismatches.join("; ");
    if allow_override {
        tracing::warn!(
            "accept contract-address drift overridden by AGENTKEYS_ACCEPT_ALLOW_ADDR_OVERRIDE=1: {detail}"
        );
        return Ok(());
    }
    Err(format!(
        "{detail} — the broker is on a STALE deployment; re-sync: setup-broker-host.sh \
         --ref <branch> (or set AGENTKEYS_ACCEPT_ALLOW_ADDR_OVERRIDE=1 only if this \
         env's own contract deploy legitimately differs from the compiled profile, \
         e.g. the CI/test stack)"
    ))
}

/// Load the chain config + the broker submitter key from env.
///
/// `BROKER_SPONSOR_SIGNER_KEY` (hex secp256k1) is the broker EVM identity that
/// fronts the outer `EntryPoint.handleOps` tx (and, sponsored only, co-signs the
/// paymaster). **Required** — it's the funded submitter EOA.
///
/// `PAYMASTER_ADDRESS` is **optional**: set ⇒ sponsored (VerifyingPaymaster);
/// unset ⇒ **unsponsored** direct `handleOps` (the default — the paymaster isn't
/// deployed; gas comes from the account's EntryPoint deposit, the submitter is
/// the `handleOps` beneficiary). `BROKER_SPONSOR_SIGNER_ADDRESS` is optional too
/// — it defaults to the submitter key's own address (the beneficiary).
pub fn load_accept_config() -> Result<(AcceptConfig, SigningKey), String> {
    let rpc_url = std::env::var("AGENTKEYS_CHAIN_RPC_HTTP")
        .map_err(|_| "env AGENTKEYS_CHAIN_RPC_HTTP not set".to_string())?;
    let chain_id: u64 = env_profile("AGENTKEYS_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(212_013);
    let key_hex = std::env::var("BROKER_SPONSOR_SIGNER_KEY")
        .map_err(|_| "env BROKER_SPONSOR_SIGNER_KEY not set".to_string())?;
    let key_bytes = hex::decode(key_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("BROKER_SPONSOR_SIGNER_KEY hex: {e}"))?;
    let broker_sk = SigningKey::from_slice(&key_bytes)
        .map_err(|e| format!("BROKER_SPONSOR_SIGNER_KEY invalid: {e}"))?;

    // Optional paymaster: present ⇒ sponsored; absent ⇒ unsponsored (default).
    let paymaster = match env_profile("PAYMASTER_ADDRESS") {
        Ok(s) => Some(addr20(&s, "PAYMASTER_ADDRESS")?),
        Err(_) => None,
    };
    // Beneficiary / co-sign address: explicit, else the submitter key's address.
    let broker_signer = match env_profile("BROKER_SPONSOR_SIGNER_ADDRESS") {
        Ok(s) => addr20(&s, "BROKER_SPONSOR_SIGNER_ADDRESS")?,
        Err(_) => {
            let derived = agentkeys_core::device_crypto::evm_address(
                &k256::ecdsa::VerifyingKey::from(&broker_sk),
            );
            addr20(&derived, "derived broker submitter address")?
        }
    };

    let entry_point = addr20(&env_profile("ENTRYPOINT_ADDRESS")?, "ENTRYPOINT_ADDRESS")?;
    let registry = addr20(
        &env_profile("SIDECAR_REGISTRY_ADDRESS")?,
        "SIDECAR_REGISTRY_ADDRESS",
    )?;
    let scope = addr20(
        &env_profile("SCOPE_CONTRACT_ADDRESS")?,
        "SCOPE_CONTRACT_ADDRESS",
    )?;

    // #231 drift guard: refuse to serve /v1/accept/* when the accept env disagrees
    // with the compiled-in chain profile — fail loud with the re-sync command
    // instead of building doomed UserOps that surface as "wrong passkey". Profile
    // resolution mirrors env_profile's chain pick ($AGENTKEYS_CHAIN, default
    // heima); $AGENTKEYS_CHAIN_PROFILE_FILE wins when set.
    match agentkeys_core::chain_profile::ChainProfile::resolve(
        None,
        std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
        std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
            .ok()
            .as_deref(),
    ) {
        Ok((chain_profile, _src)) => {
            let allow_override = std::env::var("AGENTKEYS_ACCEPT_ALLOW_ADDR_OVERRIDE")
                .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            enforce_profile_drift_guard(
                &chain_profile,
                &[
                    ("ENTRYPOINT_ADDRESS", "EntryPoint", entry_point),
                    ("SIDECAR_REGISTRY_ADDRESS", "SidecarRegistry", registry),
                    ("SCOPE_CONTRACT_ADDRESS", "AgentKeysScope", scope),
                ],
                allow_override,
            )?;
        }
        // An unresolvable profile (operator-custom chain name with no built-in
        // JSON) has no registry to drift-check against — don't take accept down.
        Err(e) => tracing::warn!("accept drift guard skipped — chain profile unresolved: {e}"),
    }

    let cfg = AcceptConfig {
        rpc_url,
        chain_id,
        entry_point,
        paymaster,
        broker_signer,
        registry,
        scope,
        account_gas_limits: crate::sponsor::pack_u128_pair(
            DEF_VERIFICATION_GAS_LIMIT,
            DEF_CALL_GAS_LIMIT,
        ),
        pre_verification_gas: u256_word(DEF_PRE_VERIFICATION_GAS),
        gas_fees: crate::sponsor::pack_u128_pair(DEF_MAX_PRIORITY_FEE, DEF_MAX_FEE),
        paymaster_verification_gas_limit: DEF_PAYMASTER_VERIFICATION_GAS,
        paymaster_post_op_gas_limit: DEF_PAYMASTER_POST_OP_GAS,
    };
    Ok((cfg, broker_sk))
}

/// **PURE** — assemble the `/v1/accept/build` response from the request + chain reads
/// (master account + nonce) + config + the broker co-sign key. The axum handler does
/// the auth + eth_call reads + key load, then calls this.
pub fn build_accept_response(
    req: &BuildAcceptRequest,
    master_account: [u8; 20],
    nonce: [u8; 32],
    cfg: &AcceptConfig,
    broker_sk: &SigningKey,
    valid_until: u64,
) -> Result<BuildAcceptResponse, String> {
    let (register, grant) = parse_register_and_grant(req)?;
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
    let assembled = assemble_accept_userop(&params, broker_sk).map_err(|e| e.to_string())?;
    Ok(assembled.into_build_response(&cfg.entry_point, cfg.chain_id))
}

fn aerr(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

fn norm_omni(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

/// Minimal JSON-RPC `eth_call` (the broker already uses reqwest for reads).
async fn eth_call(
    http: &reqwest::Client,
    rpc: &str,
    to: &[u8; 20],
    data: &str,
) -> Result<String, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{ "to": format!("0x{}", hex::encode(to)), "data": data }, "latest"]
    });
    let resp: serde_json::Value = http
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("eth_call send: {e}"))?
        .json()
        .await
        .map_err(|e| format!("eth_call decode: {e}"))?;
    resp.get("result")
        .and_then(|r| r.as_str())
        .map(String::from)
        .ok_or_else(|| format!("eth_call no result: {resp}"))
}

fn selector(sig: &str) -> String {
    hex::encode(&agentkeys_core::device_crypto::keccak256(sig.as_bytes())[..4])
}

/// `eth_getCode(addr) != 0x` — true iff `addr` is a deployed contract. The accept
/// is an ERC-4337 `P256Account` UserOp, so the master MUST be a passkey-controlled
/// smart account, NOT a legacy EOA (the deprecated `heima-register-first-master.sh`
/// binds `operatorMasterWallet` to the deployer EOA, which has no `validateUserOp`).
async fn eth_address_has_code(
    http: &reqwest::Client,
    rpc: &str,
    addr: &[u8; 20],
) -> Result<bool, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
        "params": [format!("0x{}", hex::encode(addr)), "latest"]
    });
    let resp: serde_json::Value = http
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("eth_getCode send: {e}"))?
        .json()
        .await
        .map_err(|e| format!("eth_getCode decode: {e}"))?;
    let code = resp
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| format!("eth_getCode no result: {resp}"))?;
    Ok(code != "0x" && !code.is_empty())
}

/// `eth_getTransactionReceipt(tx).status` read directly (NOT via cast/alloy, so
/// Heima's mixHash-less receipt doesn't break parsing). `Some(true)` = success
/// (`0x1`), `Some(false)` = reverted (`0x0`), `None` = no receipt yet / RPC error.
async fn eth_receipt_status(http: &reqwest::Client, rpc: &str, tx_hash: &str) -> Option<bool> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_hash]
    });
    let resp: serde_json::Value = http
        .post(rpc)
        .json(&body)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let receipt = resp.get("result")?;
    if receipt.is_null() {
        return None;
    }
    let status = receipt.get("status")?.as_str()?;
    Some(status == "0x1")
}

/// `SidecarRegistry.operatorMasterWallet(bytes32) -> address`. Zero address ⇒ no master.
async fn call_operator_master_wallet(
    http: &reqwest::Client,
    rpc: &str,
    registry: &[u8; 20],
    operator_omni: &str,
) -> Result<[u8; 20], String> {
    let arg = format!("{:0>64}", norm_omni(operator_omni));
    let data = format!("0x{}{}", selector("operatorMasterWallet(bytes32)"), arg);
    let raw = eth_call(http, rpc, registry, &data).await?;
    let hexs = raw.trim_start_matches("0x");
    if hexs.len() < 64 {
        return Err(format!("operatorMasterWallet short return: {raw}"));
    }
    addr20(&hexs[24..64], "operatorMasterWallet")
}

/// `EntryPoint.getNonce(address sender, uint192 key=0) -> uint256`.
async fn call_entrypoint_nonce(
    http: &reqwest::Client,
    rpc: &str,
    entry_point: &[u8; 20],
    account: &[u8; 20],
) -> Result<[u8; 32], String> {
    let sender = format!("{:0>64}", hex::encode(account));
    let key = "0".repeat(64);
    let data = format!(
        "0x{}{}{}",
        selector("getNonce(address,uint192)"),
        sender,
        key
    );
    let raw = eth_call(http, rpc, entry_point, &data).await?;
    let b = hex::decode(raw.trim_start_matches("0x")).map_err(|e| format!("nonce hex: {e}"))?;
    let mut w = [0u8; 32];
    if b.len() >= 32 {
        w.copy_from_slice(&b[..32]);
    }
    Ok(w)
}

fn bearer(headers: &HeaderMap) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| aerr(StatusCode::UNAUTHORIZED, "missing bearer token"))
}

/// `POST /v1/accept/build` (J1_master) — assemble the sponsored accept-batch UserOp
/// and return the `userOpHash` the master K11-signs.
pub async fn accept_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<BuildAcceptRequest>,
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

    // 2. config + co-sign key from env.
    let (cfg, broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;

    // 3. chain reads: the master account + its EntryPoint nonce.
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
    // The accept is an ERC-4337 `P256Account` UserOp — the master MUST be a deployed
    // passkey-controlled smart account. If `operatorMasterWallet` is a legacy EOA
    // (bound by the deprecated `heima-register-first-master.sh`, which signs
    // `registerFirstMasterDevice` directly with the deployer EOA), it has no
    // `validateUserOp` and `handleOps` would revert — wasting a Touch-ID ceremony
    // and gas only to fail with a misleading "wrong passkey". Reject NOW with the
    // actionable cause (the master-model mismatch, NOT the passkey).
    if !eth_address_has_code(&state.http, &cfg.rpc_url, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?
    {
        return Err(aerr(
            StatusCode::CONFLICT,
            format!(
                "operator master 0x{} is a legacy EOA, not a passkey P256Account — the \
                 Touch-ID accept requires a P256Account master. This operator was onboarded \
                 via the deprecated EOA register (heima-register-first-master.sh); re-onboard \
                 the master through the passkey P256Account register (erc4337-register-master.sh) \
                 so operatorMasterWallet is the smart account. (No passkey selection can fix an \
                 EOA master.)",
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
    let resp = build_accept_response(&req, master_account, nonce, &cfg, &broker_sk, valid_until)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(resp))
}

// ─── slice 3: POST /v1/accept/submit → EntryPoint.handleOps (Stage B) ─────────

use crate::accept_assertion::{encode_browser_assertion_signature, BrowserAssertion};
use crate::sponsored_accept::WireUserOp;

/// Broker-side mirror of `agentkeys_backend_client::protocol::SubmitAcceptUserOpRequest`.
/// The broker encodes `assertion` into `user_op.signature` (the master's K11 WebAuthn
/// proof over `user_op_hash`) before `EntryPoint.handleOps` — the daemon forwards the
/// raw browser assertion, not a pre-encoded signature.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitAcceptRequest {
    /// The op from `/v1/accept/build` (sponsored `paymasterAndData` already filled).
    /// Its `signature` is (re)set by the broker from `assertion`.
    pub user_op: WireUserOp,
    /// The master's browser WebAuthn assertion over `user_op_hash`. The broker
    /// derives the `operator_omni` (→ the `credIdHash` signer key) from the
    /// verified J1 session, NOT a body field — the J1 omni is authoritative.
    pub assertion: BrowserAssertion,
}

const HANDLE_OPS_SIG: &str =
    "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)";

/// Build the `cast send` tuple arg for `handleOps` from a signed `WireUserOp`. The
/// hex fields map directly to the `PackedUserOperation` tuple (nonce +
/// preVerificationGas are uint256 — cast accepts 0x-hex). Pure + deterministic.
fn cast_handleops_arg(op: &WireUserOp) -> String {
    format!(
        "[({},{},{},{},{},{},{},{},{})]",
        op.sender,
        op.nonce,
        op.init_code,
        op.call_data,
        op.account_gas_limits,
        op.pre_verification_gas,
        op.gas_fees,
        op.paymaster_and_data,
        op.signature,
    )
}

/// `POST /v1/accept/submit` (J1_master) — relay the K11-signed op to
/// `EntryPoint.handleOps`. The broker is the sponsor + submitter: the
/// VerifyingPaymaster covers the account gas, the broker EOA fronts the outer tx
/// (reimbursed). The broker host ships foundry (setup-broker-host.sh), so we relay
/// via `cast send` — the repo's chain-mutation pattern, E8-proven for handleOps.
pub async fn accept_submit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SubmitAcceptRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = bearer(&headers)?;
    let claims = crate::jwt::verify::verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &token,
    )
    .map_err(|e| aerr(StatusCode::UNAUTHORIZED, format!("session jwt: {e}")))?;

    let (cfg, _sk) = load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    // NOTE: `--private-key` is ps-visible; production should move the submitter to a
    // keystore (the broker fee-payer keystore) — tracked as a follow-up.
    let key = std::env::var("BROKER_SPONSOR_SIGNER_KEY").map_err(|_| {
        aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "BROKER_SPONSOR_SIGNER_KEY not set",
        )
    })?;

    // Encode the browser WebAuthn assertion into the account UserOp signature
    // (the master's K11 proof over user_op_hash) — the daemon forwards the raw
    // assertion; the broker binds the operator-derived credIdHash here.
    // operator_omni IS the verified J1 session omni (authoritative master id).
    let operator_omni: [u8; 32] = {
        let b = hex::decode(norm_omni(&claims.agentkeys.omni_account))
            .map_err(|e| aerr(StatusCode::BAD_REQUEST, format!("session omni hex: {e}")))?;
        b.try_into()
            .map_err(|_| aerr(StatusCode::BAD_REQUEST, "session omni must be 32 bytes"))?
    };
    let sig = encode_browser_assertion_signature(&req.assertion, &operator_omni)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, format!("assertion: {e}")))?;
    let mut user_op = req.user_op;
    user_op.signature = format!("0x{}", hex::encode(&sig));

    let ep = format!("0x{}", hex::encode(cfg.entry_point));
    let beneficiary = format!("0x{}", hex::encode(cfg.broker_signer));
    let arg = cast_handleops_arg(&user_op);

    // Resolve `cast`: the broker runs as a systemd service whose PATH need not
    // include a user-dir foundry (and ProtectHome=true hides $HOME/.foundry).
    // AGENTKEYS_CAST_BIN (pinned by setup-broker-host.sh to an absolute path)
    // overrides; the bare default works when cast is on PATH (e.g. /usr/local/bin).
    let cast_bin = std::env::var("AGENTKEYS_CAST_BIN").unwrap_or_else(|_| "cast".to_string());

    // cast send handleOps — Heima-robust (mirrors erc4337-register-master.sh):
    //  • `--gas-limit` (NOT eth_estimateGas): Heima reverts the handleOps gas
    //    estimation with a bare `0x` ("Failed to estimate gas: … revert, data: 0x"),
    //    so pin the limit and skip estimation.
    //  • NO `--json`: Heima's mixHash-less receipt makes cast/alloy fail to PARSE the
    //    receipt though the tx LANDS — so read the tx hash from the human output and
    //    verify the OUTCOME via a direct eth_getTransactionReceipt, never cast's exit.
    let gas_limit =
        std::env::var("AGENTKEYS_HANDLEOPS_GAS_LIMIT").unwrap_or_else(|_| "4000000".to_string());
    let out = tokio::process::Command::new(&cast_bin)
        .args([
            "send",
            &ep,
            HANDLE_OPS_SIG,
            &arg,
            &beneficiary,
            "--private-key",
            &key,
            "--rpc-url",
            &cfg.rpc_url,
            "--legacy",
            "--gas-limit",
            &gas_limit,
        ])
        .output()
        .await
        .map_err(|e| {
            aerr(
                StatusCode::BAD_GATEWAY,
                format!(
                    "spawn {cast_bin}: {e} — install foundry on the broker host \
                     (curl -L https://foundry.paradigm.xyz | bash; foundryup) and/or set \
                     AGENTKEYS_CAST_BIN to cast's absolute path"
                ),
            )
        })?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // cast prints `transactionHash 0x…` before the receipt-parse may error.
    let tx_hash = combined
        .lines()
        .find_map(|l| l.trim().strip_prefix("transactionHash").map(str::trim))
        .filter(|h| h.starts_with("0x") && h.len() >= 66)
        .map(|h| h[..66].to_string())
        .unwrap_or_default();

    if tx_hash.is_empty() {
        // Never broadcast (bad nonce, submitter unfunded, malformed op, RPC down…).
        let tail: Vec<&str> = combined.lines().rev().take(6).collect();
        return Err(aerr(
            StatusCode::BAD_GATEWAY,
            format!(
                "handleOps did not broadcast: {}",
                tail.into_iter().rev().collect::<Vec<_>>().join(" ")
            ),
        ));
    }

    // cast waited for the receipt before its parse errored, so the tx is mined now —
    // read the status directly (mixHash-receipt-proof).
    match eth_receipt_status(&state.http, &cfg.rpc_url, &tx_hash).await {
        Some(false) => Err(aerr(
            StatusCode::BAD_GATEWAY,
            format!(
                "handleOps reverted on-chain (tx {tx_hash}) — most likely the WRONG passkey \
                 (P256Account SIG_VALIDATION_FAILED), an unregistered master, or a paymaster/scope issue"
            ),
        )),
        // Some(true) = success; None = mined-but-receipt-not-yet-visible (rare) —
        // treat as submitted (the UI can confirm on chain).
        _ => Ok(Json(serde_json::json!({ "ok": true, "tx_hash": tx_hash, "block_number": "" }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BuildAcceptRequest {
        BuildAcceptRequest {
            operator_omni: format!("0x{}", "22".repeat(32)),
            actor_omni: format!("0x{}", "33".repeat(32)),
            device_key_hash: format!("0x{}", "11".repeat(32)),
            agent_pop_sig: format!("0x{}", "55".repeat(65)),
            link_code_redemption: "0xdeadbeef".into(),
            services: vec!["memory:personal".into()],
            read_only: true,
            max_per_call: "1000".into(),
            max_per_period: "0".into(),
            max_total: "0".into(),
            period_seconds: 86400,
        }
    }

    // keccak256("memory:personal") from `cast keccak` — the on-chain service id.
    const MEMORY_PERSONAL_ID: &str =
        "0x12f2770c904838cddb30299f5c22cd28df31b34fcdb44c342cd1f96c4a38ab27";

    #[test]
    fn parses_register_fields_and_keccak_service_ids() {
        let (reg, grant) = parse_register_and_grant(&sample()).unwrap();
        assert_eq!(reg.device_key_hash, [0x11; 32]);
        assert_eq!(reg.operator_omni, [0x22; 32]);
        assert_eq!(reg.actor_omni, [0x33; 32]);
        assert_eq!(reg.link_code_redemption, hex::decode("deadbeef").unwrap());
        assert_eq!(reg.agent_pop_sig, vec![0x55u8; 65]);
        assert_eq!(
            format!("0x{}", hex::encode(grant.services[0])),
            MEMORY_PERSONAL_ID
        );
        assert!(grant.read_only);
        assert_eq!(grant.max_per_call, 1000);
        assert_eq!(grant.period_seconds, 86400);
    }

    #[test]
    fn service_ids_are_lowercased_before_hashing() {
        let mut req = sample();
        req.services = vec!["Memory:Personal".into()];
        let (_, grant) = parse_register_and_grant(&req).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(grant.services[0])),
            MEMORY_PERSONAL_ID
        );
    }

    #[test]
    fn rejects_bad_hex_and_non_numeric_caps() {
        let mut bad_hex = sample();
        bad_hex.operator_omni = "0xZZ".into();
        assert!(parse_register_and_grant(&bad_hex).is_err());

        let mut short = sample();
        short.device_key_hash = "0x1122".into(); // not 32 bytes
        assert!(parse_register_and_grant(&short).is_err());

        let mut bad_cap = sample();
        bad_cap.max_total = "not-a-number".into();
        assert!(parse_register_and_grant(&bad_cap).is_err());
    }

    #[test]
    fn build_accept_response_assembles_the_batch_op() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_signer: [u8; 20] = {
            let a =
                agentkeys_core::device_crypto::evm_address(&k256::ecdsa::VerifyingKey::from(&sk));
            hex::decode(a.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap()
        };
        let cfg = AcceptConfig {
            rpc_url: "http://localhost".into(),
            chain_id: 212_013,
            entry_point: [0x66; 20],
            paymaster: Some([0x55; 20]),
            broker_signer,
            registry: {
                let mut a = [0u8; 20];
                a[19] = 0xa1;
                a
            },
            scope: {
                let mut a = [0u8; 20];
                a[19] = 0xa2;
                a
            },
            account_gas_limits: crate::sponsor::pack_u128_pair(600_000, 2_000_000),
            pre_verification_gas: u256_word(100_000),
            gas_fees: crate::sponsor::pack_u128_pair(1_000_000_000, 2_000_000_000),
            paymaster_verification_gas_limit: 200_000,
            paymaster_post_op_gas_limit: 50_000,
        };
        let master = [0x99u8; 20];
        let mut nonce = [0u8; 32];
        nonce[31] = 7;
        let resp =
            build_accept_response(&sample(), master, nonce, &cfg, &sk, 9_999_999_999).unwrap();
        assert_eq!(resp.user_op.sender, format!("0x{}", hex::encode(master)));
        assert!(resp.user_op_hash.starts_with("0x") && resp.user_op_hash.len() == 66);
        assert_eq!(
            resp.entry_point,
            format!("0x{}", hex::encode(cfg.entry_point))
        );
        assert_eq!(resp.chain_id, 212_013);
        // the inner callData is the executeBatch (selector 47e1da2a, golden-tested in core).
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a"));
    }

    #[test]
    fn build_accept_response_unsponsored_empties_paymaster_and_data() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = AcceptConfig {
            rpc_url: "http://localhost".into(),
            chain_id: 212_013,
            entry_point: [0x66; 20],
            paymaster: None, // unsponsored direct handleOps
            broker_signer: [0x77; 20],
            registry: [0xa1; 20],
            scope: [0xa2; 20],
            account_gas_limits: crate::sponsor::pack_u128_pair(600_000, 2_000_000),
            pre_verification_gas: u256_word(100_000),
            gas_fees: crate::sponsor::pack_u128_pair(1_000_000_000, 2_000_000_000),
            paymaster_verification_gas_limit: 200_000,
            paymaster_post_op_gas_limit: 50_000,
        };
        let mut nonce = [0u8; 32];
        nonce[31] = 7;
        let resp = build_accept_response(&sample(), [0x99u8; 20], nonce, &cfg, &sk, 9_999_999_999)
            .unwrap();
        // Unsponsored ⇒ no paymasterAndData; the master still K11-signs userOpHash.
        assert_eq!(resp.user_op.paymaster_and_data, "0x");
        assert!(resp.user_op.call_data.starts_with("0x47e1da2a"));
        assert!(resp.user_op_hash.starts_with("0x") && resp.user_op_hash.len() == 66);
    }

    #[test]
    fn cast_handleops_arg_formats_the_packed_tuple() {
        let op = WireUserOp {
            sender: "0xaa".into(),
            nonce: "0x07".into(),
            init_code: "0x".into(),
            call_data: "0xdeadbeef".into(),
            account_gas_limits: "0xagl".into(),
            pre_verification_gas: "0x60".into(),
            gas_fees: "0xfee".into(),
            paymaster_and_data: "0xpmd".into(),
            signature: "0xsig".into(),
        };
        assert_eq!(
            cast_handleops_arg(&op),
            "[(0xaa,0x07,0x,0xdeadbeef,0xagl,0x60,0xfee,0xpmd,0xsig)]"
        );
    }

    // ─── #231 drift guard: accept-env vs compiled chain profile ─────────────

    fn heima_profile() -> agentkeys_core::chain_profile::ChainProfile {
        agentkeys_core::chain_profile::ChainProfile::load_builtin("heima").unwrap()
    }

    fn profile_addr20(
        profile: &agentkeys_core::chain_profile::ChainProfile,
        name: &str,
    ) -> [u8; 20] {
        addr20(&profile.contract(name).unwrap().address, name).unwrap()
    }

    #[test]
    fn drift_guard_passes_when_env_matches_profile() {
        let p = heima_profile();
        let checks = [
            (
                "ENTRYPOINT_ADDRESS",
                "EntryPoint",
                profile_addr20(&p, "EntryPoint"),
            ),
            (
                "SIDECAR_REGISTRY_ADDRESS",
                "SidecarRegistry",
                profile_addr20(&p, "SidecarRegistry"),
            ),
            (
                "SCOPE_CONTRACT_ADDRESS",
                "AgentKeysScope",
                profile_addr20(&p, "AgentKeysScope"),
            ),
        ];
        assert!(enforce_profile_drift_guard(&p, &checks, false).is_ok());
    }

    #[test]
    fn drift_guard_fails_loud_on_mismatch_naming_both_addresses() {
        let p = heima_profile();
        // the incident shape: the broker env still on a stale (pre-cutover) registry
        let stale = [0x1a; 20];
        let err = enforce_profile_drift_guard(
            &p,
            &[("SIDECAR_REGISTRY_ADDRESS", "SidecarRegistry", stale)],
            false,
        )
        .unwrap_err();
        assert!(
            err.contains(&format!(
                "SIDECAR_REGISTRY_ADDRESS=0x{}",
                hex::encode(stale)
            )),
            "{err}"
        );
        assert!(
            err.contains(&p.contract("SidecarRegistry").unwrap().address),
            "{err}"
        );
        assert!(err.contains("STALE deployment"), "{err}");
        assert!(err.contains("setup-broker-host.sh --ref"), "{err}");
    }

    #[test]
    fn drift_guard_override_downgrades_mismatch_to_warn_not_fail() {
        let p = heima_profile();
        assert!(enforce_profile_drift_guard(
            &p,
            &[("SIDECAR_REGISTRY_ADDRESS", "SidecarRegistry", [0x1a; 20])],
            true,
        )
        .is_ok());
    }

    #[test]
    fn drift_guard_skips_contracts_the_profile_does_not_carry() {
        // A chain profile with no deployed-contract registry (e.g. a local dev
        // chain) has nothing to drift from — the guard must not block accept.
        let mut p = heima_profile();
        p.contracts.clear();
        assert!(enforce_profile_drift_guard(
            &p,
            &[("SIDECAR_REGISTRY_ADDRESS", "SidecarRegistry", [0x1a; 20])],
            false,
        )
        .is_ok());
    }
}
