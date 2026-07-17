//! The bundler JSON-RPC surface: `eth_sendUserOperation`,
//! `eth_getUserOperationReceipt`, `eth_supportedEntryPoints`, `eth_chainId`,
//! plus `/healthz`. One POST endpoint, standard JSON-RPC 2.0 envelope —
//! protocol-compatible with eth-infinitism / rundler so the broker can't tell
//! this thin submitter from a stock bundler.

use crate::legacy_tx::LegacyTx;
use agentkeys_core::device_crypto::evm_address;
use agentkeys_core::erc4337::{decode_entrypoint_revert, handle_ops_calldata, RpcUserOp};
use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Profile-aware env read: `BASE_<CHAIN>` falling back to bare `BASE` — the
/// same convention the broker's `load_accept_config` uses.
fn env_profile(base: &str) -> Result<String> {
    let p = std::env::var("AGENTKEYS_CHAIN")
        .unwrap_or_else(|_| "heima".into())
        .to_uppercase()
        .replace('-', "_");
    std::env::var(format!("{base}_{p}"))
        .or_else(|_| std::env::var(base))
        .map_err(|_| anyhow!("env {base}[_{p}] not set"))
}

/// Chain id from the compiled-in chain profile for `AGENTKEYS_CHAIN` — the SAME
/// source of truth the broker resolves against. A host that sets only
/// `AGENTKEYS_CHAIN=base` therefore gets Base's `8453`, never the legacy Heima
/// default that silently made the bundler sign + broadcast `handleOps` for the
/// wrong chain (the Base register-never-broadcast bug). Returns the id as a
/// string so it flows through the same `BundlerBootValues.chain_id` field as an
/// explicit `AGENTKEYS_CHAIN_ID[_<CHAIN>]` override; `None` only for an unknown
/// chain with no compiled profile, which `from_values` then rejects (fail loud).
fn chain_id_from_chain_profile() -> Option<String> {
    let chain = std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".into());
    agentkeys_core::chain_profile::ChainProfile::load_builtin(&chain)
        .ok()
        .map(|p| p.chain_id.to_string())
}

/// The submitter EOA's gas floor (`funding.deploy_min_wei`) from the compiled
/// chain profile — the SAME number the fleet WALLETS board reds the `bundler`
/// row at (#294/#230), so "the board says red" and "the bundler refuses" can
/// never disagree. `None` (no profile / no funding block) ⇒ the gas gate is
/// simply not enforced; it never invents a floor.
fn gas_floor_from_chain_profile() -> Option<String> {
    let chain = std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".into());
    agentkeys_core::chain_profile::ChainProfile::load_builtin(&chain)
        .ok()
        .and_then(|p| p.funding)
        .map(|f| f.deploy_min_wei)
}

fn addr20(hex_s: &str, name: &str) -> Result<[u8; 20]> {
    hex::decode(hex_s.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow!("{name}: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("{name} must be a 20-byte address"))
}

pub struct BundlerConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub entry_point: [u8; 20],
    pub signer: SigningKey,
    /// `handleOps` beneficiary — the submitter EOA's own address.
    pub beneficiary: [u8; 20],
    /// Pinned outer-tx gas limit (Heima reverts `eth_estimateGas` on handleOps).
    pub gas_limit: u128,
    /// Fixed gas price; `None` ⇒ read `eth_gasPrice` per submit (+25% headroom).
    pub gas_price: Option<u128>,
    /// #501: the submitter's gas floor (`funding.deploy_min_wei` from the chain
    /// profile). Below it `/healthz` reports `ready:false` so the broker can
    /// refuse a register BEFORE the browser mints a passkey — an out-of-gas
    /// submitter otherwise burned two Touch IDs and orphaned a credential.
    /// `None` ⇒ not enforced (no profile funding block).
    pub gas_floor_wei: Option<u128>,
}

/// Boot state. The two HOST-CONDITIONAL inputs — the EntryPoint address
/// (per-chain deploy state) and the submitter key (operator-provisioned
/// secret in `/etc/agentkeys/broker-sponsor.env`) — may legitimately be
/// absent on a host with no accept/sponsorship provisioning (e.g. the CI
/// test EC2, whose separate test contract set has no ERC-4337 infra).
/// Absent/empty ⇒ `Degraded`: the service still boots, serves `/healthz`
/// 200 (so `setup-broker-host.sh`'s probe + systemd stay green instead of
/// crash-looping), and answers RPC with an actionable error — mirroring the
/// broker's own unsponsored degradation. MALFORMED values still fail fast.
pub enum BundlerBoot {
    /// Boxed: the config (signer key + addresses) dwarfs the `Degraded`
    /// variant, and there is exactly ONE `BundlerBoot` per process.
    Ready(Box<BundlerConfig>),
    Degraded {
        chain_id: u64,
        missing: Vec<String>,
    },
}

/// Raw env values consumed by [`BundlerBoot::from_values`]. Read once from
/// process env in [`BundlerBoot::from_env`]; tests construct this struct
/// with explicit values instead — process env is global, so `set_var` in
/// one test leaks into parallel siblings (the #258/#259 deflake class).
#[derive(Debug, Default, Clone)]
pub struct BundlerBootValues {
    /// `AGENTKEYS_CHAIN_RPC_HTTP`.
    pub rpc_url: Option<String>,
    /// `AGENTKEYS_CHAIN_ID[_<CHAIN>]` override, else the compiled chain profile
    /// for `AGENTKEYS_CHAIN` (resolved in `from_process_env`). No Heima default —
    /// an unresolved id makes `from_values` fail loud rather than mis-sign.
    pub chain_id: Option<String>,
    /// `ENTRYPOINT_ADDRESS[_<CHAIN>]`.
    pub entry_point: Option<String>,
    /// `AGENTKEYS_BUNDLER_SIGNER_KEY` (falls back to
    /// `BROKER_SPONSOR_SIGNER_KEY` — today the same funded EOA submits).
    pub signer_key: Option<String>,
    /// `AGENTKEYS_HANDLEOPS_GAS_LIMIT` (default 4000000).
    pub handleops_gas_limit: Option<String>,
    /// `AGENTKEYS_BUNDLER_GAS_PRICE` (optional, wei).
    pub gas_price: Option<String>,
    /// #501: submitter gas floor (wei). `AGENTKEYS_BUNDLER_GAS_FLOOR_WEI`
    /// override, else the compiled chain profile's `funding.deploy_min_wei`
    /// (resolved in `from_process_env`). Absent ⇒ the gate is not enforced.
    pub gas_floor_wei: Option<String>,
}

impl BundlerBootValues {
    pub fn from_process_env() -> Self {
        Self {
            rpc_url: std::env::var("AGENTKEYS_CHAIN_RPC_HTTP").ok(),
            // Explicit override first (profileless chains / local dev), else the
            // compiled chain profile for AGENTKEYS_CHAIN (SoT). No Heima default.
            chain_id: env_profile("AGENTKEYS_CHAIN_ID")
                .ok()
                .or_else(chain_id_from_chain_profile),
            entry_point: env_profile("ENTRYPOINT_ADDRESS").ok(),
            signer_key: std::env::var("AGENTKEYS_BUNDLER_SIGNER_KEY")
                .or_else(|_| std::env::var("BROKER_SPONSOR_SIGNER_KEY"))
                .ok(),
            handleops_gas_limit: std::env::var("AGENTKEYS_HANDLEOPS_GAS_LIMIT").ok(),
            gas_price: std::env::var("AGENTKEYS_BUNDLER_GAS_PRICE").ok(),
            gas_floor_wei: std::env::var("AGENTKEYS_BUNDLER_GAS_FLOOR_WEI")
                .ok()
                .or_else(gas_floor_from_chain_profile),
        }
    }
}

impl BundlerBoot {
    /// Read the env vars listed on [`BundlerBootValues`] once, then
    /// validate via [`Self::from_values`].
    pub fn from_env() -> Result<Self> {
        Self::from_values(BundlerBootValues::from_process_env())
    }

    /// Pure half of [`Self::from_env`] — all validation and Degraded/Ready
    /// branching on already-read values (injectable for tests).
    ///
    /// Absent/empty EntryPoint or signer key ⇒ `Ok(Degraded)`; malformed
    /// values ⇒ `Err` (fail fast); absent RPC URL ⇒ `Err` (static infra
    /// config, always pinned in the systemd unit).
    pub fn from_values(values: BundlerBootValues) -> Result<Self> {
        let rpc_url = values.rpc_url.context("env AGENTKEYS_CHAIN_RPC_HTTP")?;
        // No silent default. The legacy `unwrap_or(212_013)` made a Base (or any
        // non-Heima) host quietly sign + broadcast `handleOps` for Heima's chain
        // id, which the target RPC rejects — the Base master-register UserOp never
        // broadcast (submitter nonce stayed 0; a fast, silent 502). `from_process_env`
        // fills this from an explicit AGENTKEYS_CHAIN_ID[_<CHAIN>] override or the
        // compiled chain profile; an unresolved/garbled id is a hard misconfig.
        let chain_id: u64 = values
            .chain_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context(
                "bundler chain id unresolved — set AGENTKEYS_CHAIN_ID[_<CHAIN>] or run with an \
                 AGENTKEYS_CHAIN that has a compiled chain profile; refusing to assume Heima (212013)",
            )?
            .parse()
            .context("AGENTKEYS_CHAIN_ID must be a u64 chain id")?;
        let mut missing = Vec::new();
        let entry_point = match values.entry_point.filter(|s| !s.trim().is_empty()) {
            Some(s) => Some(addr20(&s, "ENTRYPOINT_ADDRESS")?),
            None => {
                missing.push("ENTRYPOINT_ADDRESS[_<CHAIN>]".to_string());
                None
            }
        };
        let signer = match values.signer_key.filter(|s| !s.trim().is_empty()) {
            Some(key_hex) => Some(
                SigningKey::from_slice(
                    &hex::decode(key_hex.trim().trim_start_matches("0x"))
                        .map_err(|e| anyhow!("bundler signer key hex: {e}"))?,
                )
                .map_err(|e| anyhow!("bundler signer key invalid: {e}"))?,
            ),
            None => {
                missing.push("AGENTKEYS_BUNDLER_SIGNER_KEY (or BROKER_SPONSOR_SIGNER_KEY)".into());
                None
            }
        };
        let (Some(entry_point), Some(signer)) = (entry_point, signer) else {
            return Ok(Self::Degraded { chain_id, missing });
        };
        let beneficiary = addr20(
            &evm_address(&VerifyingKey::from(&signer)),
            "derived bundler address",
        )?;
        let gas_limit = values
            .handleops_gas_limit
            .and_then(|s| s.parse().ok())
            .unwrap_or(4_000_000);
        let gas_price = values.gas_price.and_then(|s| s.parse().ok());
        // Unparseable ⇒ None (gate off), never a guessed floor: a wrong floor
        // would either block a funded submitter or pass a broke one.
        let gas_floor_wei = values
            .gas_floor_wei
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok());
        Ok(Self::Ready(Box::new(BundlerConfig {
            rpc_url,
            chain_id,
            entry_point,
            signer,
            beneficiary,
            gas_limit,
            gas_price,
            gas_floor_wei,
        })))
    }
}

/// What `eth_sendUserOperation` recorded per userOpHash — enough to find the
/// outer tx AND to replay its calldata as `eth_call` when the receipt comes
/// back reverted (#247: recover the `FailedOp` `AAxx` reason).
struct SubmittedTx {
    tx_hash: String,
    call_data: Vec<u8>,
}

pub struct BundlerState {
    pub boot: BundlerBoot,
    pub http: reqwest::Client,
    /// userOpHash (0x-hex) → the broadcast outer tx.
    submitted: Mutex<HashMap<String, SubmittedTx>>,
    /// Serializes submits so two concurrent ops can't race the same EOA nonce.
    submit_lock: Mutex<()>,
}

impl BundlerState {
    pub fn new(boot: BundlerBoot) -> Self {
        Self {
            boot,
            http: reqwest::Client::new(),
            submitted: Mutex::new(HashMap::new()),
            submit_lock: Mutex::new(()),
        }
    }
}

pub fn build_router(state: Arc<BundlerState>) -> Router {
    Router::new()
        .route("/", post(rpc_handler))
        .route("/healthz", get(healthz))
        .with_state(state)
}

/// #501: can the submitter actually pay for a `handleOps` right now? The
/// bundler is the ONE component that can answer — it holds the key, so it
/// alone knows the address; the floor comes from the same chain profile the
/// fleet board reds against. Fail-OPEN on an unreadable balance: an RPC blip
/// must never block a funded stack, and a truly-down chain is already caught
/// upstream by the #435 chain probe.
enum GasVerdict {
    /// Funded, or the gate is not enforced (no floor / balance unreadable).
    Ok,
    /// Definitively below the floor — refuse before anything irreversible.
    Low { balance_wei: u128, floor_wei: u128 },
}

/// Format wei as a short decimal in native units (18 dp) for operator-facing
/// text — `1500000000000000000` → `1.5`. Integer math only (no f64 rounding on
/// a 30-digit balance).
fn wei_to_units(wei: u128) -> String {
    let whole = wei / 1_000_000_000_000_000_000u128;
    let frac = wei % 1_000_000_000_000_000_000u128;
    if frac == 0 {
        return whole.to_string();
    }
    let s = format!("{frac:018}");
    format!("{whole}.{}", s.trim_end_matches('0'))
}

async fn submitter_gas_verdict(state: &BundlerState, cfg: &BundlerConfig) -> GasVerdict {
    let Some(floor_wei) = cfg.gas_floor_wei else {
        return GasVerdict::Ok; // no floor configured — gate off
    };
    let addr = format!("0x{}", hex::encode(cfg.beneficiary));
    // Bounded: /healthz is read by systemd + deploy probes, so it must never
    // hang on a wedged RPC.
    let probe = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        chain_rpc(state, cfg, "eth_getBalance", json!([addr, "latest"])),
    )
    .await;
    let balance_wei = match probe {
        Ok(Ok(Value::String(hex_bal))) => {
            u128::from_str_radix(hex_bal.trim_start_matches("0x"), 16).ok()
        }
        _ => None,
    };
    match balance_wei {
        Some(bal) if bal < floor_wei => GasVerdict::Low {
            balance_wei: bal,
            floor_wei,
        },
        _ => GasVerdict::Ok, // funded, or unreadable ⇒ fail-open
    }
}

/// Operator-facing reason for a below-floor submitter — the exact string that
/// reaches the browser panel via the broker's 503 and the daemon's preflight.
fn out_of_gas_message(addr: &[u8; 20], balance_wei: u128, floor_wei: u128) -> String {
    format!(
        "bundler submitter 0x{} is OUT OF GAS: {} < {} (the chain's funding floor) — \
         top it up from the deploy wallet; the fleet WALLETS board shows this row red",
        hex::encode(addr),
        wei_to_units(balance_wei),
        wei_to_units(floor_wei),
    )
}

/// 200 in BOTH boot states — a degraded bundler is a healthy process (the
/// deploy probe + systemd must not flap); `ready:false` + `missing` tell the
/// operator exactly what to provision. #501: a Ready bundler whose submitter
/// cannot pay is ALSO `ready:false` (+ `reason`) — the broker gates the
/// register on this, so an out-of-gas stack stops BEFORE the browser mints a
/// passkey it could never register.
async fn healthz(State(state): State<Arc<BundlerState>>) -> Json<Value> {
    match &state.boot {
        BundlerBoot::Ready(cfg) => match submitter_gas_verdict(&state, cfg).await {
            GasVerdict::Ok => Json(json!({ "ok": true, "ready": true })),
            GasVerdict::Low {
                balance_wei,
                floor_wei,
            } => Json(json!({
                "ok": true,
                "ready": false,
                "reason": out_of_gas_message(&cfg.beneficiary, balance_wei, floor_wei),
            })),
        },
        BundlerBoot::Degraded { missing, .. } => {
            Json(json!({ "ok": true, "ready": false, "missing": missing }))
        }
    }
}

fn degraded_message(missing: &[String]) -> String {
    format!(
        "bundler not configured — missing env: {}. Provision the submitter key in \
         /etc/agentkeys/broker-sponsor.env and/or the EntryPoint address in \
         agentkeys-bundler.service, then restart. Until then this host runs \
         unsponsored and /v1/accept/submit is unavailable.",
        missing.join(", ")
    )
}

/// POST a JSON-RPC request and return the FULL response envelope. Raw `Value`
/// reads only — Heima's mixHash-less receipts/headers crash typed eth parsers.
/// Callers that need the raw `error` object (eth_call revert data) use this
/// directly; everyone else goes through [`chain_rpc`].
async fn chain_rpc_response(
    state: &BundlerState,
    cfg: &BundlerConfig,
    method: &str,
    params: Value,
) -> Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    state
        .http
        .post(&cfg.rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("{method} send: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("{method} decode: {e}"))
}

/// JSON-RPC call to the chain node returning `result`; a JSON-RPC `error`
/// becomes `Err`.
async fn chain_rpc(
    state: &BundlerState,
    cfg: &BundlerConfig,
    method: &str,
    params: Value,
) -> Result<Value> {
    let resp = chain_rpc_response(state, cfg, method, params).await?;
    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(anyhow!("{method} error: {err}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method} no result"))
}

/// Extract the revert blob from an `eth_call` JSON-RPC response. Geth and
/// Frontier (Heima) both put the `0x`-hex revert bytes at `error.data`;
/// absent on success and on non-revert errors (pruned state, transport).
fn rpc_revert_data(resp: &Value) -> Option<Vec<u8>> {
    let data = resp.get("error")?.get("data")?.as_str()?;
    hex::decode(data.trim().trim_start_matches("0x")).ok()
}

/// #247: replay a reverted `handleOps` tx's calldata as `eth_call` and decode
/// the EntryPoint `FailedOp` revert into its verbatim `AAxx ...` reason, so the
/// broker can report "AA31 paymaster deposit too low" instead of guessing
/// "wrong passkey" (the real 2026-06-10 incident). Tries the failing tx's
/// PARENT block first (the faithful pre-state), then `latest` (covers pruned
/// historical state and same-block interference). `None` when the replay no
/// longer reverts or yields no decodable data — never an error (best-effort
/// diagnostics must not mask the receipt itself).
async fn replay_revert_reason(
    state: &BundlerState,
    cfg: &BundlerConfig,
    call_data: &[u8],
    receipt: &Value,
) -> Option<String> {
    let call = json!({
        "from": format!("0x{}", hex::encode(cfg.beneficiary)),
        "to": format!("0x{}", hex::encode(cfg.entry_point)),
        "gas": format!("0x{:x}", cfg.gas_limit),
        "data": format!("0x{}", hex::encode(call_data)),
    });
    let parent_block = receipt
        .get("blockNumber")
        .and_then(|b| b.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .filter(|n| *n > 0)
        .map(|n| format!("0x{:x}", n - 1));
    for block in parent_block.into_iter().chain(["latest".to_string()]) {
        let Ok(resp) = chain_rpc_response(state, cfg, "eth_call", json!([call, block])).await
        else {
            continue;
        };
        if let Some(data) = rpc_revert_data(&resp) {
            return Some(
                decode_entrypoint_revert(&data)
                    .unwrap_or_else(|| format!("unrecognized revert 0x{}", hex::encode(&data))),
            );
        }
    }
    None
}

fn parse_qty_u128(v: &Value, name: &str) -> Result<u128> {
    let s = v.as_str().ok_or_else(|| anyhow!("{name} not a string"))?;
    u128::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| anyhow!("{name}: {e}"))
}

fn rpc_error(id: Value, code: i64, msg: impl Into<String>) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": id,
                 "error": { "code": code, "message": msg.into() } }))
}

fn rpc_ok(id: Value, result: Value) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn rpc_handler(
    State(state): State<Arc<BundlerState>>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!([]));
    let cfg = match &state.boot {
        BundlerBoot::Ready(cfg) => cfg,
        BundlerBoot::Degraded { chain_id, missing } => {
            return match method {
                "eth_chainId" => rpc_ok(id, json!(format!("0x{chain_id:x}"))),
                _ => rpc_error(id, -32500, degraded_message(missing)),
            };
        }
    };
    match method {
        "eth_chainId" => rpc_ok(id, json!(format!("0x{:x}", cfg.chain_id))),
        "eth_supportedEntryPoints" => {
            rpc_ok(id, json!([format!("0x{}", hex::encode(cfg.entry_point))]))
        }
        "eth_sendUserOperation" => match send_user_operation(&state, cfg, &params).await {
            Ok(user_op_hash) => rpc_ok(id, json!(user_op_hash)),
            Err(e) => {
                warn!("eth_sendUserOperation failed: {e:#}");
                rpc_error(id, -32500, format!("{e:#}"))
            }
        },
        "eth_getUserOperationReceipt" => {
            match get_user_operation_receipt(&state, cfg, &params).await {
                Ok(v) => rpc_ok(id, v),
                Err(e) => rpc_error(id, -32601, format!("{e:#}")),
            }
        }
        other => rpc_error(id, -32601, format!("method {other} not found")),
    }
}

/// `eth_sendUserOperation([userOp, entryPoint])` → broadcast
/// `handleOps([op], beneficiary)` as a signed legacy tx; returns the userOpHash.
async fn send_user_operation(
    state: &BundlerState,
    cfg: &BundlerConfig,
    params: &Value,
) -> Result<String> {
    let arr = params
        .as_array()
        .ok_or_else(|| anyhow!("params must be an array"))?;
    let op_json = arr.first().ok_or_else(|| anyhow!("missing userOp param"))?;
    let ep_param = arr
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing entryPoint param"))?;
    let ep = addr20(ep_param, "entryPoint")?;
    if ep != cfg.entry_point {
        return Err(anyhow!(
            "unsupported entryPoint {ep_param} (supported: 0x{})",
            hex::encode(cfg.entry_point)
        ));
    }
    let rpc_op: RpcUserOp =
        serde_json::from_value(op_json.clone()).map_err(|e| anyhow!("userOp shape: {e}"))?;
    let packed = rpc_op.to_packed().map_err(|e| anyhow!("userOp: {e}"))?;
    let user_op_hash = format!(
        "0x{}",
        hex::encode(packed.user_op_hash(&cfg.entry_point, cfg.chain_id))
    );

    let call_data = handle_ops_calldata(&[packed], &cfg.beneficiary);

    // One submit at a time: the EOA nonce read + broadcast must not interleave.
    let _guard = state.submit_lock.lock().await;
    let submitter = format!("0x{}", hex::encode(cfg.beneficiary));
    let nonce = parse_qty_u128(
        &chain_rpc(
            state,
            cfg,
            "eth_getTransactionCount",
            json!([submitter, "pending"]),
        )
        .await?,
        "eth_getTransactionCount",
    )?;
    let gas_price = match cfg.gas_price {
        Some(p) => p,
        // +25% headroom over the node's quote so a base-fee tick doesn't strand the tx.
        None => {
            parse_qty_u128(
                &chain_rpc(state, cfg, "eth_gasPrice", json!([])).await?,
                "eth_gasPrice",
            )? * 125
                / 100
        }
    };
    let tx = LegacyTx {
        nonce,
        gas_price,
        gas_limit: cfg.gas_limit,
        to: cfg.entry_point,
        value: 0,
        data: call_data,
        chain_id: cfg.chain_id,
    };
    let (raw, _) = tx.sign(&cfg.signer)?;
    let tx_hash = chain_rpc(
        state,
        cfg,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(raw))]),
    )
    .await?
    .as_str()
    .ok_or_else(|| anyhow!("eth_sendRawTransaction returned non-string"))?
    .to_string();
    info!(
        user_op_hash,
        tx_hash, nonce, gas_price, "handleOps broadcast"
    );
    state.submitted.lock().await.insert(
        user_op_hash.clone(),
        SubmittedTx {
            tx_hash,
            call_data: tx.data,
        },
    );
    Ok(user_op_hash)
}

/// `eth_getUserOperationReceipt([userOpHash])` — `null` until the outer tx is
/// mined; then `{ userOpHash, entryPoint, success, receipt }` with the RAW
/// chain receipt embedded (the broker reads `success` + `receipt.transactionHash`).
/// A reverted tx additionally carries `reason`: the `eth_call`-replayed
/// `FailedOp` string (#247), when recoverable.
async fn get_user_operation_receipt(
    state: &BundlerState,
    cfg: &BundlerConfig,
    params: &Value,
) -> Result<Value> {
    let hash = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing userOpHash param"))?
        .to_lowercase();
    let (tx_hash, call_data) = match state.submitted.lock().await.get(&hash) {
        Some(t) => (t.tx_hash.clone(), t.call_data.clone()),
        None => return Ok(Value::Null),
    };
    let receipt = chain_rpc(state, cfg, "eth_getTransactionReceipt", json!([tx_hash])).await?;
    if receipt.is_null() {
        return Ok(Value::Null);
    }
    let success = receipt.get("status").and_then(|s| s.as_str()) == Some("0x1");
    let mut out = json!({
        "userOpHash": hash,
        "entryPoint": format!("0x{}", hex::encode(cfg.entry_point)),
        "success": success,
        "receipt": receipt,
    });
    if !success {
        if let Some(reason) = replay_revert_reason(state, cfg, &call_data, &out["receipt"]).await {
            warn!(
                user_op_hash = hash,
                reason, "handleOps reverted — replayed FailedOp"
            );
            out["reason"] = json!(reason);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<BundlerState> {
        let cfg = BundlerConfig {
            rpc_url: "http://127.0.0.1:1".into(), // unreachable — chain calls must not be hit
            chain_id: 212_013,
            entry_point: [0x66; 20],
            signer: SigningKey::from_slice(&[0x46; 32]).unwrap(),
            beneficiary: [0x77; 20],
            gas_limit: 4_000_000,
            gas_price: Some(40_000_000_000),
            gas_floor_wei: None,
        };
        Arc::new(BundlerState::new(BundlerBoot::Ready(Box::new(cfg))))
    }

    fn degraded_state() -> Arc<BundlerState> {
        Arc::new(BundlerState::new(BundlerBoot::Degraded {
            chain_id: 212_013,
            missing: vec![
                "ENTRYPOINT_ADDRESS[_<CHAIN>]".into(),
                "AGENTKEYS_BUNDLER_SIGNER_KEY (or BROKER_SPONSOR_SIGNER_KEY)".into(),
            ],
        }))
    }

    #[tokio::test]
    async fn supported_entry_points_and_chain_id() {
        let st = test_state();
        let resp = rpc_handler(
            State(st.clone()),
            Json(json!({"jsonrpc":"2.0","id":1,"method":"eth_supportedEntryPoints","params":[]})),
        )
        .await;
        assert_eq!(
            resp.0["result"][0],
            format!("0x{}", hex::encode([0x66u8; 20]))
        );
        let resp = rpc_handler(
            State(st),
            Json(json!({"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]})),
        )
        .await;
        assert_eq!(resp.0["result"], "0x33c2d");
    }

    #[tokio::test]
    async fn send_user_operation_rejects_foreign_entry_point() {
        let st = test_state();
        let op = json!({
            "sender": format!("0x{}", "11".repeat(20)), "nonce": "0x7",
            "callData": "0xdeadbeef", "callGasLimit": "0x186a0",
            "verificationGasLimit": "0x30d40", "preVerificationGas": "0xea60",
            "maxFeePerGas": "0x77359400", "maxPriorityFeePerGas": "0x3b9aca00",
            "signature": "0x"
        });
        let resp = rpc_handler(
            State(st),
            Json(
                json!({"jsonrpc":"2.0","id":3,"method":"eth_sendUserOperation",
                        "params":[op, format!("0x{}", "99".repeat(20))]}),
            ),
        )
        .await;
        let msg = resp.0["error"]["message"].as_str().unwrap();
        assert!(msg.contains("unsupported entryPoint"), "{msg}");
    }

    #[test]
    fn rpc_revert_data_extracts_only_error_data_hex() {
        // revert: error.data carries the 0x-hex blob
        let revert = json!({"jsonrpc":"2.0","id":1,"error":{
            "code":3,"message":"execution reverted","data":"0xdeadbeef"}});
        assert_eq!(rpc_revert_data(&revert), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        // success response → None
        let ok = json!({"jsonrpc":"2.0","id":1,"result":"0x"});
        assert_eq!(rpc_revert_data(&ok), None);
        // non-revert error (no data) → None
        let pruned = json!({"jsonrpc":"2.0","id":1,"error":{
            "code":-32000,"message":"state already discarded"}});
        assert_eq!(rpc_revert_data(&pruned), None);
        // malformed data hex → None
        let bad = json!({"jsonrpc":"2.0","id":1,"error":{"code":3,"data":"0xZZ"}});
        assert_eq!(rpc_revert_data(&bad), None);
    }

    /// `cast abi-encode "f(uint256,string)" 0 "AA31 paymaster deposit too low"`
    /// behind the `FailedOp` selector — the exact blob the 2026-06-10 incident
    /// would have replayed.
    const FAILED_OP_AA31_BLOB: &str = "0x220266b600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001e41413331207061796d6173746572206465706f73697420746f6f206c6f770000";

    /// Mock chain node: receipts come back with the given `status`; every
    /// `eth_call` reverts with the `FailedOp(0, "AA31 ...")` blob.
    async fn spawn_mock_chain(status: &'static str) -> String {
        use axum::routing::post;
        async fn handle(
            axum::extract::State(status): axum::extract::State<&'static str>,
            Json(req): Json<Value>,
        ) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            match req.get("method").and_then(|m| m.as_str()).unwrap_or("") {
                "eth_getTransactionReceipt" => Json(json!({"jsonrpc":"2.0","id":id,"result":{
                    "transactionHash":"0xfeed","blockNumber":"0x10","status":status}})),
                "eth_call" => Json(json!({"jsonrpc":"2.0","id":id,"error":{
                    "code":3,"message":"execution reverted","data":FAILED_OP_AA31_BLOB}})),
                m => Json(json!({"jsonrpc":"2.0","id":id,"error":{
                    "code":-32601,"message":format!("unexpected {m}")}})),
            }
        }
        let app = Router::new().route("/", post(handle)).with_state(status);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    async fn state_with_submitted(rpc_url: String) -> Arc<BundlerState> {
        let cfg = BundlerConfig {
            rpc_url,
            chain_id: 212_013,
            entry_point: [0x66; 20],
            signer: SigningKey::from_slice(&[0x46; 32]).unwrap(),
            beneficiary: [0x77; 20],
            gas_limit: 4_000_000,
            gas_price: Some(40_000_000_000),
            gas_floor_wei: None,
        };
        let st = Arc::new(BundlerState::new(BundlerBoot::Ready(Box::new(cfg))));
        st.submitted.lock().await.insert(
            format!("0x{}", "ab".repeat(32)),
            SubmittedTx {
                tx_hash: "0xfeed".into(),
                call_data: vec![0xde, 0xad],
            },
        );
        st
    }

    #[tokio::test]
    async fn reverted_receipt_carries_the_replayed_failed_op_reason() {
        let st = state_with_submitted(spawn_mock_chain("0x0").await).await;
        let resp = rpc_handler(
            State(st),
            Json(
                json!({"jsonrpc":"2.0","id":8,"method":"eth_getUserOperationReceipt",
                        "params":[format!("0x{}", "ab".repeat(32))]}),
            ),
        )
        .await;
        let r = &resp.0["result"];
        assert_eq!(r["success"], false);
        assert_eq!(r["reason"], "AA31 paymaster deposit too low");
        assert_eq!(r["receipt"]["transactionHash"], "0xfeed");
    }

    #[tokio::test]
    async fn successful_receipt_has_no_reason_and_skips_the_replay() {
        let st = state_with_submitted(spawn_mock_chain("0x1").await).await;
        let resp = rpc_handler(
            State(st),
            Json(
                json!({"jsonrpc":"2.0","id":9,"method":"eth_getUserOperationReceipt",
                        "params":[format!("0x{}", "ab".repeat(32))]}),
            ),
        )
        .await;
        let r = &resp.0["result"];
        assert_eq!(r["success"], true);
        assert!(r.get("reason").is_none(), "{r}");
    }

    #[tokio::test]
    async fn unknown_user_op_hash_returns_null() {
        let st = test_state();
        let resp = rpc_handler(
            State(st),
            Json(
                json!({"jsonrpc":"2.0","id":4,"method":"eth_getUserOperationReceipt",
                        "params":[format!("0x{}", "ab".repeat(32))]}),
            ),
        )
        .await;
        assert!(resp.0["result"].is_null());
    }

    #[tokio::test]
    async fn unknown_method_is_minus_32601() {
        let st = test_state();
        let resp = rpc_handler(
            State(st),
            Json(
                json!({"jsonrpc":"2.0","id":5,"method":"eth_estimateUserOperationGas","params":[]}),
            ),
        )
        .await;
        assert_eq!(resp.0["error"]["code"], -32601);
    }

    // #501 — the gas gate. Mock chain returns a fixed `eth_getBalance`; the
    // healthz gate compares it to the config floor.
    async fn spawn_mock_balance(balance_hex: &'static str) -> String {
        use axum::routing::post;
        async fn handle(
            axum::extract::State(bal): axum::extract::State<&'static str>,
            Json(req): Json<Value>,
        ) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            match req.get("method").and_then(|m| m.as_str()).unwrap_or("") {
                "eth_getBalance" => Json(json!({"jsonrpc":"2.0","id":id,"result":bal})),
                m => Json(json!({"jsonrpc":"2.0","id":id,"error":{
                    "code":-32601,"message":format!("unexpected {m}")}})),
            }
        }
        let app = Router::new()
            .route("/", post(handle))
            .with_state(balance_hex);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    fn ready_state_with(rpc_url: String, gas_floor_wei: Option<u128>) -> Arc<BundlerState> {
        let cfg = BundlerConfig {
            rpc_url,
            chain_id: 212_013,
            entry_point: [0x66; 20],
            signer: SigningKey::from_slice(&[0x46; 32]).unwrap(),
            beneficiary: [0x77; 20],
            gas_limit: 4_000_000,
            gas_price: Some(40_000_000_000),
            gas_floor_wei,
        };
        Arc::new(BundlerState::new(BundlerBoot::Ready(Box::new(cfg))))
    }

    #[test]
    fn wei_to_units_formats_native_amounts() {
        assert_eq!(wei_to_units(1_000_000_000_000_000_000), "1");
        assert_eq!(wei_to_units(1_500_000_000_000_000_000), "1.5");
        assert_eq!(wei_to_units(0), "0");
        assert_eq!(wei_to_units(20_000_000_000_000_000), "0.02");
    }

    #[test]
    fn gas_floor_from_profile_and_override_parse() {
        let ep = format!("0x{}", "66".repeat(20));
        let key = format!("0x{}", "46".repeat(32));
        // Explicit override wins and parses.
        let over = BundlerBootValues {
            gas_floor_wei: Some("5000000000000000000".into()),
            ..boot_values(Some("http://127.0.0.1:1"), Some(&ep), Some(&key))
        };
        match BundlerBoot::from_values(over).unwrap() {
            BundlerBoot::Ready(c) => assert_eq!(c.gas_floor_wei, Some(5_000_000_000_000_000_000)),
            _ => panic!("expected ready"),
        }
        // Unparseable ⇒ None (gate off), never a guessed floor.
        let bad = BundlerBootValues {
            gas_floor_wei: Some("not-a-number".into()),
            ..boot_values(Some("http://127.0.0.1:1"), Some(&ep), Some(&key))
        };
        match BundlerBoot::from_values(bad).unwrap() {
            BundlerBoot::Ready(c) => assert_eq!(c.gas_floor_wei, None),
            _ => panic!("expected ready"),
        }
        // Absent ⇒ resolved from the compiled chain profile (Heima carries a
        // funding.deploy_min_wei) — from_process_env's or_else path.
        assert!(gas_floor_from_chain_profile().is_some());
    }

    #[tokio::test]
    async fn healthz_reports_not_ready_when_submitter_below_floor() {
        // Balance 0.5 HEI, floor 1 HEI → not ready, with an out-of-gas reason.
        let rpc = spawn_mock_balance("0x6f05b59d3b20000").await; // 0.5e18
        let st = ready_state_with(rpc, Some(1_000_000_000_000_000_000));
        let hz = healthz(State(st)).await;
        assert_eq!(hz.0["ready"], false, "{}", hz.0);
        let reason = hz.0["reason"].as_str().unwrap();
        assert!(reason.contains("OUT OF GAS"), "{reason}");
        assert!(reason.contains("0.5"), "{reason}");
    }

    #[tokio::test]
    async fn healthz_ready_when_submitter_at_or_above_floor() {
        let rpc = spawn_mock_balance("0x1bc16d674ec80000").await; // 2e18
        let st = ready_state_with(rpc, Some(1_000_000_000_000_000_000));
        let hz = healthz(State(st)).await;
        assert_eq!(hz.0["ready"], true, "{}", hz.0);
    }

    #[tokio::test]
    async fn healthz_fails_open_when_balance_unreadable() {
        // Unreachable RPC + a floor set ⇒ MUST NOT block (fail-open): a health
        // blip cannot take down a funded stack.
        let st = ready_state_with(
            "http://127.0.0.1:1/".into(),
            Some(1_000_000_000_000_000_000),
        );
        let hz = healthz(State(st)).await;
        assert_eq!(
            hz.0["ready"], true,
            "unreadable balance must fail open: {}",
            hz.0
        );
    }

    #[tokio::test]
    async fn healthz_ready_when_no_floor_configured() {
        // No floor ⇒ gate off, never probes the chain.
        let st = ready_state_with("http://127.0.0.1:1/".into(), None);
        let hz = healthz(State(st)).await;
        assert_eq!(hz.0["ready"], true, "{}", hz.0);
    }

    #[tokio::test]
    async fn degraded_boot_serves_healthz_and_actionable_rpc_errors() {
        let st = degraded_state();
        // /healthz stays 200-shaped (ok:true) so the deploy probe + systemd
        // don't flap on hosts with no sponsorship provisioning.
        let hz = healthz(State(st.clone())).await;
        assert_eq!(hz.0["ok"], true);
        assert_eq!(hz.0["ready"], false);
        assert!(hz.0["missing"].as_array().unwrap().len() == 2);
        // eth_chainId still answers (static config).
        let resp = rpc_handler(
            State(st.clone()),
            Json(json!({"jsonrpc":"2.0","id":6,"method":"eth_chainId","params":[]})),
        )
        .await;
        assert_eq!(resp.0["result"], "0x33c2d");
        // Submission errors actionably, naming the missing env.
        let resp = rpc_handler(
            State(st),
            Json(json!({"jsonrpc":"2.0","id":7,"method":"eth_sendUserOperation","params":[]})),
        )
        .await;
        let msg = resp.0["error"]["message"].as_str().unwrap();
        assert!(msg.contains("bundler not configured"), "{msg}");
        assert!(msg.contains("ENTRYPOINT_ADDRESS"), "{msg}");
        assert!(msg.contains("AGENTKEYS_BUNDLER_SIGNER_KEY"), "{msg}");
    }

    // Boot branching is covered through the pure `from_values` half —
    // injected values, no `set_var`/`remove_var` (process env is global;
    // mutation leaks across parallel test threads).

    fn boot_values(
        rpc: Option<&str>,
        entry_point: Option<&str>,
        signer_key: Option<&str>,
    ) -> BundlerBootValues {
        BundlerBootValues {
            rpc_url: rpc.map(str::to_string),
            entry_point: entry_point.map(str::to_string),
            signer_key: signer_key.map(str::to_string),
            // chain id is resolved (override or compiled profile) BEFORE from_values;
            // pin Heima's here so these tests exercise EntryPoint/key branching, not
            // chain-id resolution.
            chain_id: Some("212013".into()),
            ..Default::default()
        }
    }

    #[test]
    fn from_values_requires_rpc_url() {
        // Absent RPC URL (static infra config) is a hard error.
        assert!(BundlerBoot::from_values(boot_values(None, None, None)).is_err());
    }

    #[test]
    fn from_values_degrades_on_absent_entrypoint_and_key() {
        match BundlerBoot::from_values(boot_values(Some("http://127.0.0.1:1"), None, None)).unwrap()
        {
            BundlerBoot::Degraded { chain_id, missing } => {
                assert_eq!(chain_id, 212_013);
                assert_eq!(missing.len(), 2);
            }
            BundlerBoot::Ready(_) => panic!("expected Degraded"),
        }
    }

    #[test]
    fn from_values_degrades_on_empty_values() {
        // Empty-string values (unit wrote `ENTRYPOINT_ADDRESS_HEIMA=`) ⇒ Degraded too.
        match BundlerBoot::from_values(boot_values(Some("http://127.0.0.1:1"), Some(""), Some("")))
            .unwrap()
        {
            BundlerBoot::Degraded { missing, .. } => assert_eq!(missing.len(), 2),
            BundlerBoot::Ready(_) => panic!("expected Degraded on empty values"),
        }
    }

    #[test]
    fn from_values_names_only_the_missing_entrypoint() {
        let key = format!("0x{}", "46".repeat(32));
        match BundlerBoot::from_values(boot_values(Some("http://127.0.0.1:1"), None, Some(&key)))
            .unwrap()
        {
            BundlerBoot::Degraded { missing, .. } => {
                assert_eq!(missing.len(), 1);
                assert!(missing[0].contains("ENTRYPOINT_ADDRESS"));
            }
            BundlerBoot::Ready(_) => panic!("expected Degraded"),
        }
    }

    #[test]
    fn from_values_rejects_malformed_entrypoint() {
        // MALFORMED EntryPoint (present but bad) ⇒ hard error, not Degraded.
        let key = format!("0x{}", "46".repeat(32));
        assert!(BundlerBoot::from_values(boot_values(
            Some("http://127.0.0.1:1"),
            Some("0xnothex"),
            Some(&key)
        ))
        .is_err());
    }

    #[test]
    fn from_values_ready_when_complete() {
        let key = format!("0x{}", "46".repeat(32));
        let entry_point_hex = format!("0x{}", "66".repeat(20));
        match BundlerBoot::from_values(boot_values(
            Some("http://127.0.0.1:1"),
            Some(&entry_point_hex),
            Some(&key),
        ))
        .unwrap()
        {
            BundlerBoot::Ready(cfg) => assert_eq!(cfg.entry_point, [0x66; 20]),
            BundlerBoot::Degraded { missing, .. } => panic!("expected Ready, missing={missing:?}"),
        }
    }

    #[test]
    fn from_values_rejects_unresolved_chain_id() {
        // The old code silently defaulted a missing chain id to Heima's 212013, so a
        // Base host signed handleOps for the wrong chain. Now unresolved ⇒ hard error.
        let key = format!("0x{}", "46".repeat(32));
        let ep = format!("0x{}", "66".repeat(20));
        let mut v = boot_values(Some("http://127.0.0.1:1"), Some(&ep), Some(&key));
        v.chain_id = None;
        assert!(BundlerBoot::from_values(v).is_err());
    }

    #[test]
    fn compiled_profiles_pin_base_and_heima_chain_ids() {
        use agentkeys_core::chain_profile::ChainProfile;
        // The SoT the bundler now resolves against: a Base host MUST sign for 8453,
        // a Heima host for 212013 — never a hardcoded default.
        assert_eq!(ChainProfile::load_builtin("base").unwrap().chain_id, 8453);
        assert_eq!(
            ChainProfile::load_builtin("heima").unwrap().chain_id,
            212_013
        );
    }
}
