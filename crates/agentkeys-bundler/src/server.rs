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

impl BundlerBoot {
    /// Env: `AGENTKEYS_BUNDLER_SIGNER_KEY` (falls back to
    /// `BROKER_SPONSOR_SIGNER_KEY` — today the same funded EOA submits),
    /// `AGENTKEYS_CHAIN_RPC_HTTP`, `ENTRYPOINT_ADDRESS[_<CHAIN>]`,
    /// `AGENTKEYS_CHAIN_ID[_<CHAIN>]` (default 212013),
    /// `AGENTKEYS_HANDLEOPS_GAS_LIMIT` (default 4000000),
    /// `AGENTKEYS_BUNDLER_GAS_PRICE` (optional, wei).
    ///
    /// Absent/empty EntryPoint or signer key ⇒ `Ok(Degraded)`; malformed
    /// values ⇒ `Err` (fail fast); absent RPC URL ⇒ `Err` (static infra
    /// config, always pinned in the systemd unit).
    pub fn from_env() -> Result<Self> {
        let rpc_url =
            std::env::var("AGENTKEYS_CHAIN_RPC_HTTP").context("env AGENTKEYS_CHAIN_RPC_HTTP")?;
        let chain_id: u64 = env_profile("AGENTKEYS_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(212_013);
        let mut missing = Vec::new();
        let entry_point = match env_profile("ENTRYPOINT_ADDRESS")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            Some(s) => Some(addr20(&s, "ENTRYPOINT_ADDRESS")?),
            None => {
                missing.push("ENTRYPOINT_ADDRESS[_<CHAIN>]".to_string());
                None
            }
        };
        let signer = match std::env::var("AGENTKEYS_BUNDLER_SIGNER_KEY")
            .or_else(|_| std::env::var("BROKER_SPONSOR_SIGNER_KEY"))
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
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
        let gas_limit = std::env::var("AGENTKEYS_HANDLEOPS_GAS_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4_000_000);
        let gas_price = std::env::var("AGENTKEYS_BUNDLER_GAS_PRICE")
            .ok()
            .and_then(|s| s.parse().ok());
        Ok(Self::Ready(Box::new(BundlerConfig {
            rpc_url,
            chain_id,
            entry_point,
            signer,
            beneficiary,
            gas_limit,
            gas_price,
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

/// 200 in BOTH boot states — a degraded bundler is a healthy process (the
/// deploy probe + systemd must not flap); `ready:false` + `missing` tell the
/// operator exactly what to provision.
async fn healthz(State(state): State<Arc<BundlerState>>) -> Json<Value> {
    match &state.boot {
        BundlerBoot::Ready(_) => Json(json!({ "ok": true, "ready": true })),
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

    /// Single test fn (env mutation is process-global; parallel tests would race).
    #[test]
    fn from_env_degrades_on_absent_config_but_rejects_malformed() {
        let clear = || {
            for k in [
                "AGENTKEYS_CHAIN",
                "AGENTKEYS_CHAIN_RPC_HTTP",
                "ENTRYPOINT_ADDRESS",
                "ENTRYPOINT_ADDRESS_HEIMA",
                "AGENTKEYS_BUNDLER_SIGNER_KEY",
                "BROKER_SPONSOR_SIGNER_KEY",
            ] {
                std::env::remove_var(k);
            }
        };

        // Absent RPC URL (static infra config) is still a hard error.
        clear();
        assert!(BundlerBoot::from_env().is_err());

        // Absent EntryPoint + key ⇒ Degraded with both named.
        clear();
        std::env::set_var("AGENTKEYS_CHAIN_RPC_HTTP", "http://127.0.0.1:1");
        match BundlerBoot::from_env().unwrap() {
            BundlerBoot::Degraded { chain_id, missing } => {
                assert_eq!(chain_id, 212_013);
                assert_eq!(missing.len(), 2);
            }
            BundlerBoot::Ready(_) => panic!("expected Degraded"),
        }

        // Empty-string values (unit wrote `ENTRYPOINT_ADDRESS_HEIMA=`) ⇒ Degraded too.
        std::env::set_var("ENTRYPOINT_ADDRESS_HEIMA", "");
        std::env::set_var("AGENTKEYS_BUNDLER_SIGNER_KEY", "");
        match BundlerBoot::from_env().unwrap() {
            BundlerBoot::Degraded { missing, .. } => assert_eq!(missing.len(), 2),
            BundlerBoot::Ready(_) => panic!("expected Degraded on empty values"),
        }

        // Key present, EntryPoint absent ⇒ Degraded naming only the EntryPoint.
        std::env::set_var(
            "AGENTKEYS_BUNDLER_SIGNER_KEY",
            format!("0x{}", "46".repeat(32)),
        );
        match BundlerBoot::from_env().unwrap() {
            BundlerBoot::Degraded { missing, .. } => {
                assert_eq!(missing.len(), 1);
                assert!(missing[0].contains("ENTRYPOINT_ADDRESS"));
            }
            BundlerBoot::Ready(_) => panic!("expected Degraded"),
        }

        // MALFORMED EntryPoint (present but bad) ⇒ hard error, not Degraded.
        std::env::set_var("ENTRYPOINT_ADDRESS_HEIMA", "0xnothex");
        assert!(BundlerBoot::from_env().is_err());

        // Both present and well-formed ⇒ Ready.
        std::env::set_var("ENTRYPOINT_ADDRESS_HEIMA", format!("0x{}", "66".repeat(20)));
        match BundlerBoot::from_env().unwrap() {
            BundlerBoot::Ready(cfg) => assert_eq!(cfg.entry_point, [0x66; 20]),
            BundlerBoot::Degraded { missing, .. } => panic!("expected Ready, missing={missing:?}"),
        }
        clear();
    }
}
