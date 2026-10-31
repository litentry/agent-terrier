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
    /// #408 — the actor being bound is a device (channel endpoint). Back-compat
    /// default false; drives the §14.10 ≥1-channel broker warn.
    #[serde(default)]
    pub is_device: bool,
}

/// Count channel grants (`channel-pub:<id>` / `channel-sub:<id>`) in a services
/// list — the §14.10 "≥1 channel" measure for a device accept (#408). Mirrors
/// `agentkeys_protocol::channel_grant_count`.
pub(crate) fn channel_grant_count(services: &[String]) -> usize {
    services
        .iter()
        .filter(|s| {
            let l = s.to_lowercase();
            l.starts_with("channel-pub:") || l.starts_with("channel-sub:")
        })
        .count()
}

/// On-chain scope service ids: `keccak256(lowercase(service))` per service — the
/// SAME hash `heima-scope-set.sh` writes, so a service id is byte-identical on
/// every path (the terminology-source-of-truth rule, at the encoding level).
/// Shared by the accept batch and the #248 scope-only re-grant.
pub(crate) fn service_ids(services: &[String]) -> Vec<[u8; 32]> {
    services
        .iter()
        .map(|s| agentkeys_core::device_crypto::keccak256(s.to_lowercase().as_bytes()))
        .collect()
}

/// Parse the wire request into the typed register + scope-grant args. The `u128`
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
    let grant = ScopeGrant {
        services: service_ids(&req.services),
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
use agentkeys_core::erc4337::{
    DEFAULT_CALL_GAS_LIMIT as DEF_CALL_GAS_LIMIT,
    DEFAULT_PRE_VERIFICATION_GAS as DEF_PRE_VERIFICATION_GAS,
    DEFAULT_VERIFICATION_GAS_LIMIT as DEF_VERIFICATION_GAS_LIMIT,
};
const DEF_MAX_PRIORITY_FEE: u128 = 1_000_000_000;
const DEF_MAX_FEE: u128 = 40_000_000_000;
const DEF_PAYMASTER_VERIFICATION_GAS: u128 = 200_000;
const DEF_PAYMASTER_POST_OP_GAS: u128 = 50_000;
pub(crate) const SPONSOR_WINDOW_SECS: u64 = 3600;

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

pub(crate) fn addr20(hex_s: &str, name: &str) -> Result<[u8; 20], String> {
    let b =
        hex::decode(hex_s.trim().trim_start_matches("0x")).map_err(|e| format!("{name}: {e}"))?;
    b.try_into()
        .map_err(|_| format!("{name} must be a 20-byte address"))
}

/// Profile-aware env read: `BASE_<CHAIN>` (e.g. `SIDECAR_REGISTRY_ADDRESS_HEIMA`),
/// falling back to the bare `BASE` — the same convention the operator env uses.
pub(crate) fn env_profile(base: &str) -> Result<String, String> {
    let lookup = |name: &str| std::env::var(name).ok();
    let (profile, _) = agentkeys_core::chain_profile::ChainProfile::resolve(
        None,
        lookup("AGENTKEYS_CHAIN").as_deref(),
        lookup("AGENTKEYS_CHAIN_PROFILE_FILE").as_deref(),
    )
    .map_err(|error| format!("cannot resolve chain profile: {error}"))?;
    profile_configuration(base, &profile, lookup)
}

fn profile_configuration(
    name: &str,
    profile: &agentkeys_core::chain_profile::ChainProfile,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    if let Ok(value) = resolve_profile_var(name, &profile.name, lookup) {
        return Ok(value);
    }
    if name == "AGENTKEYS_CHAIN_ID" {
        return Ok(profile.chain_id.to_string());
    }
    let contract = match name {
        "ENTRYPOINT_ADDRESS" => "EntryPoint",
        "SIDECAR_REGISTRY_ADDRESS" => "SidecarRegistry",
        "SCOPE_CONTRACT_ADDRESS" => "AgentKeysScope",
        "P256_ACCOUNT_FACTORY_ADDRESS" => "P256AccountFactory",
        _ => return Err(format!("configuration {name} is not set")),
    };
    profile
        .contracts
        .iter()
        .find(|item| item.name == contract)
        .map(|item| item.address.clone())
        .ok_or_else(|| format!("chain profile has no {contract}"))
}

/// The lookup behind [`env_profile`], injectable so it can be tested without
/// touching process env. An EMPTY (or whitespace) value counts as UNSET: the
/// test stacks pin `PAYMASTER_ADDRESS_<CHAIN>=` deliberately (`host-common.sh`
/// — the unsponsored #230 posture) and a unit's `Environment=K=` sets K to "",
/// so reading "" as a value turned every sponsored build on the VE test broker
/// into `PAYMASTER_ADDRESS must be a 20-byte address` (2026-09-10).
pub(crate) fn resolve_profile_var(
    base: &str,
    profile: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let p = profile.to_uppercase().replace('-', "_");
    let non_empty = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    non_empty(lookup(&format!("{base}_{p}")))
        .or_else(|| non_empty(lookup(base)))
        .ok_or_else(|| format!("env {base}[_{p}] not set"))
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
        "{detail} — update the custom chain profile to match the intended deployment before submitting"
    ))
}

/// Load the chain config + the broker submitter key from env.
///
/// `BROKER_SPONSOR_SIGNER_KEY` or its protected `_FILE` form supplies the EVM identity that
/// fronts the outer `EntryPoint.handleOps` tx (and, sponsored only, co-signs the
/// paymaster). **Required** — it's the funded submitter EOA.
///
/// `PAYMASTER_ADDRESS` is **optional**: set ⇒ sponsored (VerifyingPaymaster);
/// unset ⇒ **unsponsored** direct `handleOps` (the default — the paymaster isn't
/// deployed; gas comes from the account's EntryPoint deposit, the submitter is
/// the `handleOps` beneficiary). `BROKER_SPONSOR_SIGNER_ADDRESS` is optional too
/// — it defaults to the submitter key's own address (the beneficiary).
pub fn load_accept_config() -> Result<(AcceptConfig, SigningKey), String> {
    accept_config_from_lookup(|name| std::env::var(name).ok())
}

fn accept_config_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(AcceptConfig, SigningKey), String> {
    let (profile, _) = agentkeys_core::chain_profile::ChainProfile::resolve(
        None,
        lookup("AGENTKEYS_CHAIN").as_deref(),
        lookup("AGENTKEYS_CHAIN_PROFILE_FILE").as_deref(),
    )
    .map_err(|error| format!("cannot resolve accept chain profile: {error}"))?;
    let resolved_profile = Some(profile);
    let profile = resolved_profile.as_ref().expect("resolved profile");
    let env_profile = |name: &str| profile_configuration(name, profile, &lookup);
    let rpc_url = agentkeys_core::chain_profile::rpc_http_override(&profile.name, &lookup)
        .unwrap_or_else(|| profile.rpc.http.clone());
    let chain_id_env: Option<u64> = env_profile("AGENTKEYS_CHAIN_ID")
        .ok()
        .and_then(|value| value.trim().parse().ok());
    let broker_sk = agentkeys_core::secp256k1_key::from_sources(
        lookup("BROKER_SPONSOR_SIGNER_KEY"),
        lookup("BROKER_SPONSOR_SIGNER_KEY_FILE"),
    )
    .map_err(|_| "sponsor signing key is invalid, unsafe or ambiguously configured")?
    .ok_or("a sponsor signing key is required")?;

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

    let allow_override = lookup("AGENTKEYS_ACCEPT_ALLOW_ADDR_OVERRIDE")
        .is_some_and(|value| value.trim() == "1" || value.trim().eq_ignore_ascii_case("true"));
    enforce_profile_drift_guard(
        profile,
        &[
            ("ENTRYPOINT_ADDRESS", "EntryPoint", entry_point),
            ("SIDECAR_REGISTRY_ADDRESS", "SidecarRegistry", registry),
            ("SCOPE_CONTRACT_ADDRESS", "AgentKeysScope", scope),
        ],
        allow_override,
    )?;

    // #278 D6: verificationGasLimit / preVerificationGas are env > profile > default
    // (shared by accept / scope / revoke / register). The live RIP-7212 precompile
    // (#170 / #288) makes the on-chain P-256 verify ~3.4k gas — BUT the D6 register
    // also DEPLOYS the P256Account inside the UserOp (initCode), and the EntryPoint
    // runs that deploy within verificationGasLimit (~1.3M on Base). So the value must
    // cover the DEPLOY, not just the verify: Base carries ~1.6M in its profile even
    // with the cheap precompile (the earlier 200k OOG'd the deploy → AA13). Chains on
    // the pure-Solidity verifier keep the 1.5M default. Lowering it below the real
    // cost reverts inside validateUserOp as a false SIG_VALIDATION_FAILED (#225 / gap #7).
    let chain_id = crate::config::configured_chain_id(chain_id_env, resolved_profile.as_ref())
        .ok_or_else(|| "accept requires a configured chain ID".to_string())?;
    let (prof_vgl, prof_pvg) = resolved_profile
        .as_ref()
        .map(|p| (p.gas.verification_gas_limit, p.gas.pre_verification_gas))
        .unwrap_or((None, None));
    let verification_gas_limit = resolve_gas_limit(
        "ACCEPT_VERIFICATION_GAS_LIMIT",
        prof_vgl,
        DEF_VERIFICATION_GAS_LIMIT,
        env_profile,
    );
    let pre_verification_gas_amt = resolve_gas_limit(
        "ACCEPT_PRE_VERIFICATION_GAS",
        prof_pvg,
        DEF_PRE_VERIFICATION_GAS,
        env_profile,
    );
    // gas_fees come from the chain's real fee market (its compiled profile, gwei→wei),
    // with the broker DEF as the fallback for a chain with no usable profile fee
    // (legacy/anvil maxFee=0). The old hardcoded 40 gwei is Heima's base-fee scale; on
    // Base (~0.005 gwei base) it reserved a ~0.16 ETH UserOp prefund the paymaster
    // deposit can't cover — a false AA31 the moment the AA13 deploy-gas was fixed.
    let (max_priority_fee, max_fee) = resolved_profile
        .as_ref()
        .map(|p| (p.gas.max_priority_fee_gwei, p.gas.max_fee_gwei))
        .filter(|&(_, max_fee_gwei)| max_fee_gwei > 0)
        .map(|(prio_gwei, max_fee_gwei)| {
            (
                prio_gwei as u128 * 1_000_000_000,
                max_fee_gwei as u128 * 1_000_000_000,
            )
        })
        .unwrap_or((DEF_MAX_PRIORITY_FEE, DEF_MAX_FEE));

    let cfg = AcceptConfig {
        rpc_url,
        chain_id,
        entry_point,
        paymaster,
        broker_signer,
        registry,
        scope,
        account_gas_limits: crate::sponsor::pack_u128_pair(
            verification_gas_limit,
            DEF_CALL_GAS_LIMIT,
        ),
        pre_verification_gas: u256_word(pre_verification_gas_amt),
        gas_fees: crate::sponsor::pack_u128_pair(max_priority_fee, max_fee),
        paymaster_verification_gas_limit: DEF_PAYMASTER_VERIFICATION_GAS,
        paymaster_post_op_gas_limit: DEF_PAYMASTER_POST_OP_GAS,
    };
    Ok((cfg, broker_sk))
}

/// Resolve a UserOp gas limit: env `<base>[_<CHAIN>]` (operator override) wins,
/// then the compiled chain profile value, then the broker default (#278 D6). Env
/// parse failures fall through to the profile/default rather than erroring — a
/// typo'd override degrades safely instead of taking accept down.
fn resolve_gas_limit(
    env_base: &str,
    profile_val: Option<u128>,
    default: u128,
    lookup: impl Fn(&str) -> Result<String, String>,
) -> u128 {
    lookup(env_base)
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .or(profile_val)
        .unwrap_or(default)
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
    // #427 on-chain kind split: a DEVICE accept binds via `registerAgentDevice`
    // (TIER_DEVICE, no agent slot — devices only attach channels); everything
    // else is a DELEGATE and binds via the slot-consuming `registerDelegate`
    // (TIER_AGENT) — the CLI `--request-pairing` delegates included, so no
    // registration path bypasses the business quota (arch.md §17.7).
    let assembled = if req.is_device {
        assemble_accept_userop(&params, broker_sk).map_err(|e| e.to_string())?
    } else {
        crate::sponsored_accept::assemble_spawn_userop(&params, broker_sk)
            .map_err(|e| e.to_string())?
    };
    Ok(assembled.into_build_response(&cfg.entry_point, cfg.chain_id))
}

/// Read-only chain coordinates from the shared profile; no submitter key required.
pub(crate) fn load_chain_read_config() -> Result<(String, [u8; 20]), String> {
    let profile = crate::chain_config::profile()?;
    let registry = addr20(
        &crate::chain_config::contract(&profile, "SidecarRegistry")?,
        "SidecarRegistry",
    )?;
    Ok((profile.rpc.http, registry))
}

pub(crate) fn aerr(
    status: StatusCode,
    msg: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

pub(crate) fn norm_omni(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

/// Minimal JSON-RPC `eth_call` (the broker already uses reqwest for reads).
pub(crate) async fn eth_call(
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

pub(crate) fn selector(sig: &str) -> String {
    hex::encode(&agentkeys_core::device_crypto::keccak256(sig.as_bytes())[..4])
}

/// `eth_getCode(addr) != 0x` — true iff `addr` is a deployed contract. The accept
/// is an ERC-4337 `P256Account` UserOp, so the master MUST be a passkey-controlled
/// smart account, NOT a legacy EOA (the deprecated `heima-register-first-master.sh`
/// binds `operatorMasterWallet` to the deployer EOA, which has no `validateUserOp`).
pub(crate) async fn eth_address_has_code(
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

/// `SidecarRegistry.operatorMasterWallet(bytes32) -> address`. Zero address ⇒ no master.
pub(crate) async fn call_operator_master_wallet(
    http: &reqwest::Client,
    rpc: &str,
    registry: &[u8; 20],
    operator_omni: &str,
) -> Result<[u8; 20], String> {
    let operator: [u8; 32] = hex::decode(norm_omni(operator_omni))
        .map_err(|_| "invalid operator identity")?
        .try_into()
        .map_err(|_| "operator identity must be 32 bytes")?;
    let data = format!(
        "0x{}",
        hex::encode(agentkeys_core::erc4337::operator_master_wallet_calldata(
            &operator
        ))
    );
    let raw = eth_call(http, rpc, registry, &data).await?;
    let hexs = raw.trim_start_matches("0x");
    if hexs.len() < 64 {
        return Err(format!("operatorMasterWallet short return: {raw}"));
    }
    addr20(&hexs[24..64], "operatorMasterWallet")
}

/// `EntryPoint.getNonce(address sender, uint192 key=0) -> uint256`.
pub(crate) async fn call_entrypoint_nonce(
    http: &reqwest::Client,
    rpc: &str,
    entry_point: &[u8; 20],
    account: &[u8; 20],
) -> Result<[u8; 32], String> {
    let data = format!(
        "0x{}",
        hex::encode(agentkeys_core::erc4337::entrypoint_nonce_calldata(account))
    );
    let raw = eth_call(http, rpc, entry_point, &data).await?;
    let b = hex::decode(raw.trim_start_matches("0x")).map_err(|e| format!("nonce hex: {e}"))?;
    let mut w = [0u8; 32];
    if b.len() >= 32 {
        w.copy_from_slice(&b[..32]);
    }
    Ok(w)
}

pub(crate) fn bearer(headers: &HeaderMap) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
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

    // §14.10 (#408): a device claim must attach ≥1 channel. The accept CARD is the
    // hard enforcer (the UI won't submit a zero-channel device bind); the broker
    // WARNS (a grant-less device actor is inert, not dangerous — decision-10). We
    // never block here: a false negative on `is_device` must not brick a legit
    // accept, and a legitimately grant-less bind (rare) still lands.
    if req.is_device && channel_grant_count(&req.services) == 0 {
        tracing::warn!(
            actor_omni = %req.actor_omni,
            services = ?req.services,
            "accept binds a DEVICE with ZERO channel grants (§14.10) — a device is a channel \
             endpoint and should attach ≥1 channel-pub/sub grant; the resulting actor is inert \
             (no channels to publish/subscribe). The accept card should have enforced this."
        );
    }

    // 2. config + co-sign key from env.
    let (cfg, broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;

    // #427: a non-device accept binds a DELEGATE and consumes an agent slot —
    // pre-check the allowance for the loud early 409 (the contract enforces
    // atomically inside registerDelegate regardless).
    if !req.is_device {
        let (used, total) = crate::handlers::spawn::call_agent_slots(
            &state.http,
            &cfg.rpc_url,
            &cfg.registry,
            &req.operator_omni,
        )
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
        if used >= total {
            return Err(crate::handlers::spawn::allowance_exhausted_error(
                used, total,
            ));
        }
    }

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

// Receipt-poll defaults for the bundler relay (env-overridable; the bundler's
// outer tx typically mines within one Heima block ≈ 12s).
const DEF_RECEIPT_TIMEOUT_SECS: u64 = 90;
const RECEIPT_POLL_INTERVAL_SECS: u64 = 2;

/// Operator-facing message for a reverted `handleOps`, built from the bundler's
/// replayed `FailedOp` reason (#247). The in-house bundler attaches `reason` to
/// a failed `eth_getUserOperationReceipt` (the verbatim EntryPoint `AAxx ...`
/// string); the common codes map to concrete operator guidance so a funding
/// failure is never steered toward a passkey reset (the real 2026-06-10 AA31
/// incident). `None` (3rd-party bundler / replay no longer reverts) falls back
/// to the old best-guess list — explicitly labeled as a guess.
pub(crate) fn handle_ops_revert_message(reason: Option<&str>, tx_hash: &str) -> String {
    let Some(reason) = reason else {
        return format!(
            "handleOps reverted on-chain (tx {tx_hash}) — revert reason not recoverable; \
             most likely the WRONG passkey (P256Account SIG_VALIDATION_FAILED), an \
             unregistered master, or a paymaster/scope issue"
        );
    };
    let guidance = match reason.split_whitespace().next().unwrap_or("") {
        "AA21" => Some(
            "the SENDER account's EntryPoint deposit can't cover the op's prefund — a \
             funding issue, not an auth issue. Top up: cast send $ENTRYPOINT \
             'depositTo(address)' <master account> --value 0.2ether --legacy (the harness \
             auto-top-up in e2e/scripts/_erc4337_lib.sh derives the exact floor)",
        ),
        "AA31" => Some(
            "the VerifyingPaymaster's EntryPoint deposit is below the one-op prefund — a \
             funding issue, not an auth issue. Top up: bash scripts/operator/chain/heima-deploy-paymaster.sh \
             (idempotent; deposits only when below threshold)",
        ),
        "AA24" => Some(
            "the WebAuthn/P256 signature failed validation — wrong or unregistered master \
             passkey for this account (or verification-gas starvation mapped to SIG_FAIL; \
             check ACCEPT_VERIFICATION_GAS_LIMIT before re-onboarding)",
        ),
        "AA25" => Some(
            "invalid account nonce — the op was built against a stale nonce (another op \
             landed first); rebuild via /v1/accept/build and re-sign",
        ),
        "AA23" => Some(
            "the account's validateUserOp reverted or ran out of gas — check the \
             verification gas limit and the account contract, not the passkey",
        ),
        "AA91" => Some(
            "the EntryPoint's payout to the bundler beneficiary failed — on Heima this \
             usually means the EntryPoint's native balance fell near/below the \
             Existential Deposit (docs/heima-eth-gap.md gap 8); re-fund the \
             EntryPoint deposits",
        ),
        _ => None,
    };
    match guidance {
        Some(g) => format!("handleOps reverted on-chain (tx {tx_hash}): {reason} — {g}"),
        None => format!("handleOps reverted on-chain (tx {tx_hash}): {reason}"),
    }
}

pub(crate) use agentkeys_core::erc4337::wire_to_packed;

/// JSON-RPC call to the bundler (`AGENTKEYS_BUNDLER_URL`). Returns `result`.
pub(crate) async fn bundler_rpc(
    http: &reqwest::Client,
    bundler_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: serde_json::Value = http
        .post(bundler_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("bundler {method} send: {e}"))?
        .json()
        .await
        .map_err(|e| format!("bundler {method} decode: {e}"))?;
    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown bundler error");
        return Err(format!("bundler {method}: {msg}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| format!("bundler {method}: no result"))
}

fn validate_initial_registration(
    packed: &crate::sponsor::PackedUserOp,
    operator_omni: &[u8; 32],
    registry: &[u8; 20],
    factory: &[u8; 20],
) -> Result<agentkeys_core::erc4337::RegisterFirstMaster, String> {
    use agentkeys_core::erc4337::{
        decode_execute_batch, master_account_salt, master_cred_id_hash, master_device_key_hash,
        p256_account_factory_init_code, register_batch_calldata, RegisterFirstMaster,
    };
    let calls = decode_execute_batch(&packed.call_data)?;
    if calls.len() != 1
        || calls[0].dest != *registry
        || calls[0].value != 0
        || calls[0].calldata.len() != 4 + 8 * 32
    {
        return Err("unbound operator may submit only its deterministic first registration".into());
    }
    let args = &calls[0].calldata[4..];
    let word =
        |index: usize| -> [u8; 32] { args[index * 32..(index + 1) * 32].try_into().unwrap() };
    let register = RegisterFirstMaster {
        device_key_hash: master_device_key_hash(operator_omni),
        operator_omni: *operator_omni,
        actor_omni: *operator_omni,
        cred_id_hash: master_cred_id_hash(operator_omni),
        rpid_hash: word(4),
        pub_x: word(5),
        pub_y: word(6),
        roles: word(7)[31],
    };
    if packed.call_data != register_batch_calldata(registry, &register) {
        return Err(
            "first registration must bind the authenticated operator and canonical master device"
                .into(),
        );
    }
    let expected_init = p256_account_factory_init_code(
        factory,
        &register.cred_id_hash,
        &register.pub_x,
        &register.pub_y,
        &register.rpid_hash,
        &master_account_salt(operator_omni),
    );
    if !packed.init_code.is_empty() && packed.init_code != expected_init {
        return Err("first registration initCode is not the canonical operator account".into());
    }
    Ok(register)
}

fn require_bound_sender(
    packed: &crate::sponsor::PackedUserOp,
    account: &[u8; 20],
) -> Result<(), crate::error::BrokerError> {
    if packed.sender != *account || !packed.init_code.is_empty() {
        return Err(crate::error::BrokerError::Forbidden(
            "UserOp sender must be the authenticated operator's current master account".into(),
        ));
    }
    Ok(())
}

async fn resolve_submit_signer(
    state: &SharedState,
    cfg: &AcceptConfig,
    operator_omni: &[u8; 32],
    packed: &crate::sponsor::PackedUserOp,
    assertion: &BrowserAssertion,
) -> Result<[u8; 32], crate::error::BrokerError> {
    use crate::error::BrokerError;
    let account = call_operator_master_wallet(
        &state.http,
        &cfg.rpc_url,
        &cfg.registry,
        &format!("0x{}", hex::encode(operator_omni)),
    )
    .await
    .map_err(BrokerError::BackendUnreachable)?;
    let challenge = packed.user_op_hash(&cfg.entry_point, cfg.chain_id);
    if account != [0; 20] {
        require_bound_sender(packed, &account)?;
        return crate::account_signer::resolve_assertion_signer(
            &state.http,
            &cfg.rpc_url,
            &account,
            operator_omni,
            &challenge,
            assertion,
        )
        .await;
    }
    let factory = addr20(
        &env_profile("P256_ACCOUNT_FACTORY_ADDRESS").map_err(BrokerError::BackendUnreachable)?,
        "P256_ACCOUNT_FACTORY_ADDRESS",
    )
    .map_err(BrokerError::BackendUnreachable)?;
    let register = validate_initial_registration(packed, operator_omni, &cfg.registry, &factory)
        .map_err(BrokerError::Forbidden)?;
    let predicted = crate::handlers::register::call_factory_get_address(
        &state.http,
        &cfg.rpc_url,
        &factory,
        &register.cred_id_hash,
        &register.pub_x,
        &register.pub_y,
        &register.rpid_hash,
        &agentkeys_core::erc4337::master_account_salt(operator_omni),
    )
    .await
    .map_err(BrokerError::BackendUnreachable)?;
    if packed.sender != predicted {
        return Err(BrokerError::Forbidden(
            "first registration sender differs from the canonical factory account".into(),
        ));
    }
    if packed.init_code.is_empty() {
        if !eth_address_has_code(&state.http, &cfg.rpc_url, &predicted)
            .await
            .map_err(BrokerError::BackendUnreachable)?
        {
            return Err(BrokerError::Forbidden(
                "undeployed first registration requires canonical initCode".into(),
            ));
        }
        return crate::account_signer::resolve_assertion_signer(
            &state.http,
            &cfg.rpc_url,
            &predicted,
            operator_omni,
            &challenge,
            assertion,
        )
        .await;
    }
    let signer = crate::account_signer::LiveSigner {
        credential_hash: register.cred_id_hash,
        pub_x: register.pub_x,
        pub_y: register.pub_y,
        rp_id_hash: register.rpid_hash,
    };
    crate::account_signer::verify_assertion(
        &state.http,
        &cfg.rpc_url,
        &cfg.registry,
        &challenge,
        &signer,
        assertion,
    )
    .await?;
    Ok(signer.credential_hash)
}

/// `POST /v1/accept/submit` (J1_master) — relay the K11-signed op to the
/// ERC-4337 **bundler** via the standard `eth_sendUserOperation` (#230). The
/// broker keeps only the policy it owns (J1 auth + the build-side paymaster
/// co-sign); the bundler (`AGENTKEYS_BUNDLER_URL` — in-house `agentkeys-bundler`
/// or any stock one) owns the submitter EOA, nonce, gas, and the
/// `EntryPoint.handleOps` broadcast. No more `cast` spawn / foundry dependency.
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
    let bundler_url = std::env::var("AGENTKEYS_BUNDLER_URL").map_err(|_| {
        aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "AGENTKEYS_BUNDLER_URL not set — point the broker at an ERC-4337 bundler \
             (the in-house agentkeys-bundler, wired by setup-broker-host.sh, or any \
             eth_sendUserOperation-speaking service)",
        )
    })?;

    if claims.agentkeys.parent_omni.is_some() {
        return Err(aerr(StatusCode::FORBIDDEN, "master session required"));
    }
    let operator_omni: [u8; 32] = hex::decode(norm_omni(&claims.agentkeys.omni_account))
        .map_err(|error| aerr(StatusCode::BAD_REQUEST, format!("session omni: {error}")))?
        .try_into()
        .map_err(|_| aerr(StatusCode::BAD_REQUEST, "session omni must be 32 bytes"))?;
    let mut packed =
        wire_to_packed(&req.user_op).map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;
    let signer_hash = resolve_submit_signer(&state, &cfg, &operator_omni, &packed, &req.assertion)
        .await
        .map_err(|error| {
            let status = match &error {
                crate::error::BrokerError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                crate::error::BrokerError::Forbidden(_) => StatusCode::FORBIDDEN,
                crate::error::BrokerError::BadRequest(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            };
            aerr(status, error.to_string())
        })?;
    packed.signature = encode_browser_assertion_signature(&req.assertion, &signer_hash)
        .map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;

    // Relay in the CANONICAL unpacked v0.7 JSON shape (what every bundler speaks)
    // so swapping self-hosted ↔ 3rd-party needs no broker code change.
    let rpc_op = agentkeys_core::erc4337::RpcUserOp::from_packed(&packed);
    let ep = format!("0x{}", hex::encode(cfg.entry_point));
    let user_op_hash = bundler_rpc(
        &state.http,
        &bundler_url,
        "eth_sendUserOperation",
        serde_json::json!([rpc_op, ep]),
    )
    .await
    .map_err(|e| {
        // Log on the broker host: the submit error was previously returned to the
        // caller WITHOUT tracing, so a bundler rejection (e.g. a wrong-chain-id outer
        // tx the RPC refuses) left an empty broker journal and a fast, silent 502.
        tracing::warn!(
            target: "agentkeys.broker.accept",
            bundler = %bundler_url,
            error = %e,
            "submit relay: bundler eth_sendUserOperation failed — UserOp NOT broadcast"
        );
        aerr(
            StatusCode::BAD_GATEWAY,
            format!("handleOps did not broadcast: {e}"),
        )
    })?
    .as_str()
    .ok_or_else(|| {
        aerr(
            StatusCode::BAD_GATEWAY,
            "bundler returned non-string userOpHash",
        )
    })?
    .to_string();

    let expected_hash = format!(
        "0x{}",
        hex::encode(packed.user_op_hash(&cfg.entry_point, cfg.chain_id))
    );
    if !user_op_hash.eq_ignore_ascii_case(&expected_hash) {
        return Err(aerr(
            StatusCode::BAD_GATEWAY,
            "bundler returned a different user operation hash",
        ));
    }

    // Poll the bundler for the UserOperation receipt until mined or timeout.
    let timeout_secs = std::env::var("AGENTKEYS_BUNDLER_RECEIPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEF_RECEIPT_TIMEOUT_SECS);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match bundler_rpc(
            &state.http,
            &bundler_url,
            "eth_getUserOperationReceipt",
            serde_json::json!([user_op_hash]),
        )
        .await
        {
            Ok(serde_json::Value::Null) => {} // not mined yet — keep polling
            Ok(receipt) => {
                return crate::handlers::accept_receipt::verified_finalization(
                    &state,
                    &cfg,
                    operator_omni,
                    &packed,
                    &user_op_hash,
                    &receipt,
                    None,
                )
                .await
                .map(Json);
            }
            // Transient bundler/RPC hiccup mid-poll: tolerate until the deadline.
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            // Broadcast but unconfirmed — surface the hashes so the UI can confirm
            // on chain; NOT an error (the tx may still mine). No audit envelopes
            // here: we don't know whether the ops landed, and the on-chain event
            // log covers whatever eventually mines.
            tracing::warn!(
                user_op_hash = %user_op_hash,
                "submit receipt timed out — control-plane audit envelopes NOT emitted for this op"
            );
            return Ok(Json(serde_json::json!({
                "ok": true, "tx_hash": "", "block_number": "",
                "user_op_hash": user_op_hash,
                "pending": true,
            })));
        }
        tokio::time::sleep(std::time::Duration::from_secs(RECEIPT_POLL_INTERVAL_SECS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial_registration() -> (crate::sponsor::PackedUserOp, [u8; 32], [u8; 20], [u8; 20]) {
        use agentkeys_core::erc4337::*;
        let omni = [1; 32];
        let registry = [2; 20];
        let factory = [3; 20];
        let registration = RegisterFirstMaster {
            device_key_hash: master_device_key_hash(&omni),
            operator_omni: omni,
            actor_omni: omni,
            cred_id_hash: master_cred_id_hash(&omni),
            rpid_hash: [4; 32],
            pub_x: [5; 32],
            pub_y: [6; 32],
            roles: 7,
        };
        let op = PackedUserOp {
            sender: [8; 20],
            nonce: [0; 32],
            init_code: p256_account_factory_init_code(
                &factory,
                &registration.cred_id_hash,
                &registration.pub_x,
                &registration.pub_y,
                &registration.rpid_hash,
                &master_account_salt(&omni),
            ),
            call_data: register_batch_calldata(&registry, &registration),
            account_gas_limits: [0; 32],
            pre_verification_gas: [0; 32],
            gas_fees: [0; 32],
            paymaster_and_data: Vec::new(),
            signature: Vec::new(),
        };
        (op, omni, registry, factory)
    }
    #[test]
    fn submit_checks_bound_sender_and_refuses_initcode_for_bound_accounts() {
        let (mut op, _, _, _) = initial_registration();
        assert!(require_bound_sender(&op, &op.sender).is_err());
        op.init_code.clear();
        assert!(require_bound_sender(&op, &op.sender).is_ok());
        assert!(require_bound_sender(&op, &[9; 20]).is_err());
    }
    #[test]
    fn initial_submit_accepts_only_the_authenticated_operators_canonical_registration() {
        let (mut op, omni, registry, factory) = initial_registration();
        assert!(validate_initial_registration(&op, &omni, &registry, &factory).is_ok());
        assert!(validate_initial_registration(&op, &[9; 32], &registry, &factory).is_err());
        assert!(validate_initial_registration(&op, &omni, &[9; 20], &factory).is_err());
        assert!(validate_initial_registration(&op, &omni, &registry, &[9; 20]).is_err());
        op.init_code[183] ^= 1;
        assert!(validate_initial_registration(&op, &omni, &registry, &factory).is_err());
        op.init_code.clear();
        assert!(validate_initial_registration(&op, &omni, &registry, &factory).is_ok());
        op.call_data.push(0);
        assert!(validate_initial_registration(&op, &omni, &registry, &factory).is_err());
    }

    fn sample() -> BuildAcceptRequest {
        BuildAcceptRequest {
            operator_omni: format!("0x{}", "22".repeat(32)),
            actor_omni: format!("0x{}", "33".repeat(32)),
            device_key_hash: format!("0x{}", "11".repeat(32)),
            agent_pop_sig: format!("0x{}", "55".repeat(65)),
            link_code_redemption: "0xdeadbeef".into(),
            services: vec!["knowledge:personal".into()],
            is_device: false,
            read_only: true,
            max_per_call: "1000".into(),
            max_per_period: "0".into(),
            max_total: "0".into(),
            period_seconds: 86400,
        }
    }

    // keccak256("knowledge:personal") from `cast keccak` — the on-chain service id.
    const KNOWLEDGE_PERSONAL_ID: &str =
        "0x74577172636bd7db2f294f091ed93ae32597890b27de77c16ec5317bbe5e6815";

    // ── handle_ops_revert_message (#247) ─────────────────────────────────────

    #[test]
    fn aa31_maps_to_paymaster_top_up_with_no_passkey_steering() {
        let msg = handle_ops_revert_message(Some("AA31 paymaster deposit too low"), "0xfeed");
        assert!(msg.contains("AA31 paymaster deposit too low"), "{msg}");
        assert!(
            msg.contains("scripts/operator/chain/heima-deploy-paymaster.sh"),
            "{msg}"
        );
        assert!(msg.contains("0xfeed"), "{msg}");
        assert!(!msg.to_lowercase().contains("passkey"), "{msg}");
    }

    #[test]
    fn aa21_maps_to_account_deposit_top_up_with_no_passkey_steering() {
        let msg = handle_ops_revert_message(Some("AA21 didn't pay prefund"), "0xfeed");
        assert!(msg.contains("AA21 didn't pay prefund"), "{msg}");
        assert!(msg.contains("depositTo(address)"), "{msg}");
        assert!(!msg.to_lowercase().contains("passkey"), "{msg}");
    }

    #[test]
    fn aa24_still_names_the_wrong_passkey() {
        let msg = handle_ops_revert_message(Some("AA24 signature error"), "0xfeed");
        assert!(msg.contains("AA24 signature error"), "{msg}");
        assert!(msg.contains("passkey"), "{msg}");
    }

    #[test]
    fn aa25_aa23_and_aa91_get_their_own_guidance() {
        let msg = handle_ops_revert_message(Some("AA25 invalid account nonce"), "0xfeed");
        assert!(msg.contains("stale nonce"), "{msg}");
        let msg = handle_ops_revert_message(Some("AA23 reverted (or OOG)"), "0xfeed");
        assert!(msg.contains("validateUserOp"), "{msg}");
        let msg = handle_ops_revert_message(Some("AA91 failed send to beneficiary"), "0xfeed");
        assert!(msg.contains("Existential Deposit"), "{msg}");
        assert!(!msg.to_lowercase().contains("passkey"), "{msg}");
    }

    #[test]
    fn unknown_reason_is_surfaced_verbatim_without_invented_guidance() {
        let msg = handle_ops_revert_message(Some("AA95 out of gas"), "0xfeed");
        assert_eq!(
            msg,
            "handleOps reverted on-chain (tx 0xfeed): AA95 out of gas"
        );
    }

    #[test]
    fn missing_reason_falls_back_to_the_labeled_guess() {
        let msg = handle_ops_revert_message(None, "0xfeed");
        assert!(msg.contains("revert reason not recoverable"), "{msg}");
        assert!(msg.contains("WRONG passkey"), "{msg}");
        assert!(msg.contains("0xfeed"), "{msg}");
    }

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
            KNOWLEDGE_PERSONAL_ID
        );
        assert!(grant.read_only);
        assert_eq!(grant.max_per_call, 1000);
        assert_eq!(grant.period_seconds, 86400);
    }

    #[test]
    fn service_ids_are_lowercased_before_hashing() {
        let mut req = sample();
        req.services = vec!["Knowledge:Personal".into()];
        let (_, grant) = parse_register_and_grant(&req).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(grant.services[0])),
            KNOWLEDGE_PERSONAL_ID
        );
    }

    #[test]
    fn channel_grant_count_measures_device_channels() {
        // §14.10 (#408): the ≥1-channel measure — counts channel-pub/sub grants
        // (case-insensitive), ignores memory/cred. Matches the protocol helper.
        assert_eq!(channel_grant_count(&["channel-pub:cam".into()]), 1);
        assert_eq!(
            channel_grant_count(&["Channel-Sub:Display".into(), "channel-pub:touch".into()]),
            2
        );
        assert_eq!(channel_grant_count(&["knowledge:travel".into()]), 0);
        assert_eq!(channel_grant_count(&[]), 0);
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
    fn wire_to_packed_roundtrips_the_build_output() {
        // The submit path re-types the wire op into the SAME PackedUserOp the
        // build produced, so the bundler relay (RpcUserOp::from_packed) starts
        // from byte-identical fields.
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let cfg = AcceptConfig {
            rpc_url: "http://localhost".into(),
            chain_id: 212_013,
            entry_point: [0x66; 20],
            paymaster: Some([0x55; 20]),
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
        let packed = wire_to_packed(&resp.user_op).unwrap();
        // Recomputing the userOpHash from the re-typed op matches the build's.
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(packed.user_op_hash(&cfg.entry_point, cfg.chain_id))
            ),
            resp.user_op_hash
        );
        // And the canonical RPC shape round-trips it losslessly.
        let rpc = agentkeys_core::erc4337::RpcUserOp::from_packed(&packed);
        assert_eq!(rpc.to_packed().unwrap(), packed);
    }

    #[test]
    fn wire_to_packed_rejects_bad_fields() {
        let mut op = WireUserOp {
            sender: format!("0x{}", "aa".repeat(20)),
            nonce: format!("0x{}", "00".repeat(32)),
            init_code: "0x".into(),
            call_data: "0xdeadbeef".into(),
            account_gas_limits: format!("0x{}", "11".repeat(32)),
            pre_verification_gas: format!("0x{}", "00".repeat(32)),
            gas_fees: format!("0x{}", "22".repeat(32)),
            paymaster_and_data: "0x".into(),
            signature: "0x".into(),
        };
        assert!(wire_to_packed(&op).is_ok());
        op.nonce = "0x1234".into(); // not 32 bytes
        assert!(wire_to_packed(&op).is_err());
    }

    // ─── #231 drift guard: accept-env vs compiled chain profile ─────────────

    fn test_profile() -> agentkeys_core::chain_profile::ChainProfile {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../e2e/fixtures/chain-profiles/local-test.json"
        )))
        .unwrap()
    }

    fn profile_addr20(
        profile: &agentkeys_core::chain_profile::ChainProfile,
        name: &str,
    ) -> [u8; 20] {
        addr20(&profile.contract(name).unwrap().address, name).unwrap()
    }

    #[test]
    fn drift_guard_passes_when_env_matches_profile() {
        let p = test_profile();
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
        let p = test_profile();
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
        assert!(err.contains("update the custom chain profile"), "{err}");
    }

    #[test]
    fn drift_guard_override_downgrades_mismatch_to_warn_not_fail() {
        let p = test_profile();
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
        let mut p = test_profile();
        p.contracts.clear();
        assert!(enforce_profile_drift_guard(
            &p,
            &[("SIDECAR_REGISTRY_ADDRESS", "SidecarRegistry", [0x1a; 20])],
            false,
        )
        .is_ok());
    }
}

#[cfg(test)]
mod env_profile_tests {
    use super::resolve_profile_var;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn profiled_var_wins_then_bare_then_unset() {
        let e = env(&[
            ("PAYMASTER_ADDRESS_HEIMA", "0xaa"),
            ("PAYMASTER_ADDRESS", "0xbb"),
        ]);
        assert_eq!(
            resolve_profile_var("PAYMASTER_ADDRESS", "heima", &e).unwrap(),
            "0xaa"
        );
        let e = env(&[("PAYMASTER_ADDRESS", "0xbb")]);
        assert_eq!(
            resolve_profile_var("PAYMASTER_ADDRESS", "heima-paseo", &e).unwrap(),
            "0xbb"
        );
        let e = env(&[]);
        assert_eq!(
            resolve_profile_var("PAYMASTER_ADDRESS", "heima", &e).unwrap_err(),
            "env PAYMASTER_ADDRESS[_HEIMA] not set"
        );
    }

    #[test]
    fn an_empty_value_is_unset_not_an_invalid_address() {
        // The VE renderer pins the test stack's paymaster EMPTY (no paymaster
        // on the test set); the broker must read that as "unsponsored".
        let e = env(&[
            ("PAYMASTER_ADDRESS_HEIMA", ""),
            ("PAYMASTER_ADDRESS", "   "),
        ]);
        assert!(resolve_profile_var("PAYMASTER_ADDRESS", "heima", &e).is_err());
        // …while an empty profiled value still lets a bare value through.
        let e = env(&[
            ("PAYMASTER_ADDRESS_HEIMA", ""),
            ("PAYMASTER_ADDRESS", "0xcc"),
        ]);
        assert_eq!(
            resolve_profile_var("PAYMASTER_ADDRESS", "heima", &e).unwrap(),
            "0xcc"
        );
    }
}

#[cfg(test)]
mod local_configuration_tests {
    use super::*;
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    #[test]
    fn explicit_profile_and_protected_key_supply_existing_accept_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("sponsor.key");
        let key = agentkeys_core::secp256k1_key::create(key_path.to_str().unwrap()).unwrap();
        let profile_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../e2e/fixtures/chain-profiles/local-test.json"
        );
        let (profile, _) =
            agentkeys_core::chain_profile::ChainProfile::resolve(None, None, Some(profile_path))
                .unwrap();
        let values = BTreeMap::from([
            ("AGENTKEYS_CHAIN_PROFILE_FILE", profile_path.to_owned()),
            ("AGENTKEYS_CHAIN", "unused-ambient-selection".to_owned()),
            (
                "BROKER_SPONSOR_SIGNER_KEY_FILE",
                key_path.to_str().unwrap().to_owned(),
            ),
        ]);
        let load = |values: &BTreeMap<&str, String>| {
            accept_config_from_lookup(|name| values.get(name).cloned())
        };
        let (config, loaded) = load(&values).unwrap();
        assert_eq!(loaded.verifying_key(), key.verifying_key());
        assert_eq!(config.chain_id, profile.chain_id);
        assert_eq!(config.rpc_url, profile.rpc.http);
        assert!(
            config.paymaster.is_none(),
            "a profile entry must not implicitly enable sponsorship"
        );
        for (name, expected) in [
            ("EntryPoint", config.entry_point),
            ("SidecarRegistry", config.registry),
            ("AgentKeysScope", config.scope),
        ] {
            assert_eq!(
                format!("0x{}", hex::encode(expected)),
                profile
                    .contracts
                    .iter()
                    .find(|entry| entry.name == name)
                    .unwrap()
                    .address
            );
        }
        assert_eq!(
            profile_configuration("P256_ACCOUNT_FACTORY_ADDRESS", &profile, |_| None).unwrap(),
            profile
                .contracts
                .iter()
                .find(|entry| entry.name == "P256AccountFactory")
                .unwrap()
                .address
        );
        let mut inline = values.clone();
        inline.remove("BROKER_SPONSOR_SIGNER_KEY_FILE");
        assert!(load(&inline).is_err(), "the signing key remains mandatory");
        inline.insert("BROKER_SPONSOR_SIGNER_KEY", hex::encode(key.to_bytes()));
        assert_eq!(load(&inline).unwrap().0.broker_signer, config.broker_signer);
        let mut conflicting = values.clone();
        conflicting.insert(
            "BROKER_SPONSOR_SIGNER_KEY",
            "synthetic-conflicting-token".into(),
        );
        assert!(load(&conflicting).is_err());
        let mut changed = values.clone();
        changed.insert("ENTRYPOINT_ADDRESS", format!("0x{}", "ab".repeat(20)));
        assert!(
            load(&changed).is_err(),
            "profile drift guard must remain enforced"
        );
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&values).is_err());
    }
}
