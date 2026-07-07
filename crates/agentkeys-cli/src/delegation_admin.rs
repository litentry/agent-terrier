//! Device + sandbox sides of the §369 device→sandbox delegation (the origination
//! runtime). Three verbs, two roles:
//!
//! - **device** (holds K10): `device_resolve` re-derives the agent's `J1` each boot
//!   from the durable on-chain binding (`/v1/agent/resolve`, pop_sig-gated) and
//!   hands it to the sandbox; `device_cosign` discovers pending delegation requests
//!   (`/v1/agent/delegation/pending`) and co-signs each with K10
//!   (`/v1/agent/delegation/sign`), bounding the sandbox to `--scope`.
//! - **sandbox** (holds an ephemeral key + the `J1`): `delegation_bootstrap`
//!   generates the ephemeral key, opens a request (`/v1/agent/delegation/request`),
//!   polls until the device co-signs (`/v1/agent/delegation/poll`), and writes a
//!   `StoredDelegation` the cap-mint clients attach as the `delegation_path`.
//!
//! The K10 never leaves the device; the sandbox proves authority with the
//! device-signed delegation, which the worker re-verifies (issue #369).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentkeys_backend_client::Delegation;
use agentkeys_core::device_crypto::DeviceKey;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("build http client")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The on-disk delegation the sandbox cap-mint clients load. Self-contains the
/// ephemeral key file path so a single `--delegation-file` carries everything
/// `memory canonical-get` needs to run in delegated mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDelegation {
    /// The on-chain-bound DEVICE's `device_key_hash` (what the worker re-verifies).
    pub device_key_hash: String,
    /// The sandbox's ephemeral EVM address the device delegated to (the cap-PoP
    /// signer). Recorded for audit; the cap-mint re-derives it from the key file.
    pub sandbox_pubkey: String,
    pub scope: String,
    pub expires_at: u64,
    pub delegation_sig: String,
    /// The ephemeral key file (0600) that signs the per-request cap-PoP.
    pub ephemeral_key_file: String,
}

impl StoredDelegation {
    /// Load `(ephemeral_key, Delegation)` for a cap-mint client's `with_delegation`.
    pub fn load(path: &str) -> Result<(std::sync::Arc<DeviceKey>, Delegation)> {
        let raw = std::fs::read_to_string(expand(path))
            .with_context(|| format!("read delegation file {path}"))?;
        let stored: StoredDelegation =
            serde_json::from_str(&raw).with_context(|| format!("parse delegation file {path}"))?;
        let ephemeral = DeviceKey::load_or_generate(&stored.ephemeral_key_file, false)
            .with_context(|| format!("load ephemeral key {}", stored.ephemeral_key_file))?;
        Ok((
            std::sync::Arc::new(ephemeral),
            Delegation {
                device_key_hash: stored.device_key_hash,
                scope: stored.scope,
                expires_at: stored.expires_at,
                delegation_sig: stored.delegation_sig,
            },
        ))
    }
}

fn expand(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    p.to_string()
}

/// `agentkeys delegation resolve` (device) — re-derive `J1` from the durable
/// on-chain binding (pop_sig-gated `/v1/agent/resolve`). Emits the JSON the sandbox
/// consumes: `{session_jwt, operator_omni, actor_omni, agent_url, device_key_hash}`.
pub async fn device_resolve(broker_url: &str, key_file: &str) -> Result<String> {
    let dk = DeviceKey::load_or_generate(key_file, false)
        .with_context(|| format!("load device K10 {key_file}"))?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .post(format!("{base}/v1/agent/resolve"))
        .json(&json!({ "device_pubkey": dk.address(), "pop_sig": dk.pop_sig()? }))
        .send()
        .await
        .context("POST /v1/agent/resolve")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("device resolve failed: HTTP {status}: {text}"));
    }
    let mut v: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("device_key_hash".into(), json!(dk.device_key_hash()?));
    }
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys delegation cosign` (device) — discover pending delegation requests
/// for this device and co-sign each with K10, bounding the sandbox to `scope` and
/// `ttl_seconds`. Returns the number co-signed. With `once=false` the device polls
/// in a loop (a long-lived co-sign daemon); `once=true` drains the current queue
/// and returns (the e2e/test shape).
pub async fn device_cosign(
    broker_url: &str,
    key_file: &str,
    scope: &str,
    ttl_seconds: u64,
    once: bool,
    poll_interval_secs: u64,
) -> Result<String> {
    let dk = DeviceKey::load_or_generate(key_file, false)
        .with_context(|| format!("load device K10 {key_file}"))?;
    let base = broker_url.trim_end_matches('/');
    let mut signed_total = 0usize;
    loop {
        let pending = client()?
            .post(format!("{base}/v1/agent/delegation/pending"))
            .json(&json!({ "device_pubkey": dk.address(), "pop_sig": dk.pop_sig()? }))
            .send()
            .await
            .context("POST /v1/agent/delegation/pending")?;
        let status = pending.status();
        let text = pending.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("delegation pending failed: HTTP {status}: {text}"));
        }
        let v: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
        let rows = v
            .get("pending")
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();
        for row in &rows {
            let request_id = row
                .get("request_id")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("pending row missing request_id"))?;
            let sandbox_pubkey = row
                .get("sandbox_pubkey")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("pending row missing sandbox_pubkey"))?;
            // The device sets the FINAL scope (it may narrow what the sandbox asked
            // for — the per-spawn bound) + the expiry it signs.
            let expires_at = now_secs() + ttl_seconds;
            let delegation_sig = dk.delegation_sig(sandbox_pubkey, scope, expires_at)?;
            let sign = client()?
                .post(format!("{base}/v1/agent/delegation/sign"))
                .json(&json!({
                    "device_pubkey": dk.address(),
                    "pop_sig": dk.pop_sig()?,
                    "request_id": request_id,
                    "scope": scope,
                    "expires_at": expires_at,
                    "delegation_sig": delegation_sig,
                }))
                .send()
                .await
                .context("POST /v1/agent/delegation/sign")?;
            let s = sign.status();
            let st = sign.text().await.unwrap_or_default();
            if !s.is_success() {
                return Err(anyhow!(
                    "delegation sign failed for {request_id}: HTTP {s}: {st}"
                ));
            }
            signed_total += 1;
            eprintln!("co-signed delegation {request_id} → sandbox {sandbox_pubkey} (scope `{scope}`, ttl {ttl_seconds}s)");
        }
        if once {
            break;
        }
        tokio::time::sleep(Duration::from_secs(poll_interval_secs.max(1))).await;
    }
    Ok(json!({ "signed": signed_total }).to_string())
}

/// `agentkeys delegation bootstrap` (sandbox) — generate the ephemeral key, open a
/// delegation request, and poll until the device co-signs. Writes `out_file`
/// (a [`StoredDelegation`]) the cap-mint clients attach as the `delegation_path`,
/// and prints it. `session_bearer` is the sandbox's `J1` (from `device resolve`).
#[allow(clippy::too_many_arguments)]
pub async fn delegation_bootstrap(
    broker_url: &str,
    session_bearer: &str,
    requested_scope: &str,
    requested_ttl_seconds: u64,
    ephemeral_key_file: &str,
    out_file: &str,
    poll_attempts: u32,
    poll_interval_secs: u64,
    regen: bool,
) -> Result<String> {
    let ephemeral = DeviceKey::load_or_generate(ephemeral_key_file, regen)
        .with_context(|| format!("create ephemeral key {ephemeral_key_file}"))?;
    let base = broker_url.trim_end_matches('/');

    // 1. Open the request (J1-gated; the broker derives the device from the J1).
    let req = client()?
        .post(format!("{base}/v1/agent/delegation/request"))
        .bearer_auth(session_bearer)
        .json(&json!({
            "sandbox_pubkey": ephemeral.address(),
            "requested_scope": requested_scope,
            "requested_ttl_seconds": requested_ttl_seconds,
        }))
        .send()
        .await
        .context("POST /v1/agent/delegation/request")?;
    let status = req.status();
    let text = req.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("delegation request failed: HTTP {status}: {text}"));
    }
    let rv: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
    let request_id = rv
        .get("request_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("request response missing request_id: {text}"))?
        .to_string();
    let device_key_hash = rv
        .get("device_key_hash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("request response missing device_key_hash: {text}"))?
        .to_string();

    // 2. Poll until the device co-signs.
    for _ in 0..poll_attempts.max(1) {
        let poll = client()?
            .post(format!("{base}/v1/agent/delegation/poll"))
            .bearer_auth(session_bearer)
            .json(&json!({ "request_id": request_id }))
            .send()
            .await
            .context("POST /v1/agent/delegation/poll")?;
        let ps = poll.status();
        let pt = poll.text().await.unwrap_or_default();
        if !ps.is_success() {
            return Err(anyhow!("delegation poll failed: HTTP {ps}: {pt}"));
        }
        let pv: Value = serde_json::from_str(&pt).with_context(|| format!("parse: {pt}"))?;
        match pv.get("status").and_then(|x| x.as_str()) {
            Some("signed") => {
                let stored = StoredDelegation {
                    device_key_hash,
                    sandbox_pubkey: ephemeral.address().to_string(),
                    scope: pv
                        .get("scope")
                        .and_then(|x| x.as_str())
                        .unwrap_or(requested_scope)
                        .to_string(),
                    expires_at: pv.get("expires_at").and_then(|x| x.as_u64()).unwrap_or(0),
                    delegation_sig: pv
                        .get("delegation_sig")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| anyhow!("signed poll missing delegation_sig: {pt}"))?
                        .to_string(),
                    ephemeral_key_file: ephemeral_key_file.to_string(),
                };
                let out = expand(out_file);
                if let Some(dir) = Path::new(&out).parent() {
                    std::fs::create_dir_all(dir).ok();
                }
                std::fs::write(&out, serde_json::to_string_pretty(&stored)?)
                    .with_context(|| format!("write delegation file {out}"))?;
                return Ok(serde_json::to_string_pretty(&stored)?);
            }
            Some("pending") | None => {
                tokio::time::sleep(Duration::from_secs(poll_interval_secs.max(1))).await;
            }
            Some(other) => return Err(anyhow!("unexpected delegation poll status: {other}")),
        }
    }
    Err(anyhow!(
        "delegation request {request_id} not co-signed after {poll_attempts} polls — is the device's `delegation cosign` running?"
    ))
}
