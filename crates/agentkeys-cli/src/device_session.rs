//! Device-owned key bootstrap and broker session acquisition.
//! The shared DeviceKey owns key custody, address derivation and proof signing.
//! Actor identity comes from the broker response; clients do not rederive it.

use agentkeys_core::device_crypto::DeviceKey;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

async fn post_json(client: &reqwest::Client, url: &str, body: Value) -> Result<Value> {
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("POST {url} -> HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).with_context(|| format!("parse {url} response: {text}"))
}

fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    p.to_string()
}

/// `agentkeys agent device-session` — generate/load the in-sandbox device key,
/// mint the broker session, emit the JSON the harness feeds to the master for
/// on-chain binding. Returns the JSON string (printed by the caller).
pub async fn device_session(
    broker_url: &str,
    key_file: &str,
    link_code: &str,
    chain_id: u64,
    regen: bool,
) -> Result<String> {
    let key_path = expand_home(key_file);
    let device = DeviceKey::load_or_generate(&key_path, regen)?;
    let address = device.address();
    let device_key_hash = device.device_key_hash()?;
    let pop_sig = device.pop_sig()?;

    // wallet_sig SIWE → session JWT (omni == actor_omni)
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("build http client")?;
    let base = broker_url.trim_end_matches('/');
    let start = post_json(
        &client,
        &format!("{base}/v1/auth/wallet/start"),
        json!({ "address": address, "chain_id": chain_id }),
    )
    .await?;
    let request_id = start
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet/start missing request_id: {start}"))?;
    let siwe_message = start
        .get("siwe_message")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet/start missing siwe_message: {start}"))?;
    let sig = device.sign_eip191(siwe_message.as_bytes())?;
    let verify = post_json(
        &client,
        &format!("{base}/v1/auth/wallet/verify"),
        json!({ "request_id": request_id, "signature": sig }),
    )
    .await?;
    let session_jwt = verify
        .get("session_jwt")
        .or_else(|| verify.get("jwt"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet/verify missing session JWT: {verify}"))?;

    let actor_omni = verify
        .get("omni_account")
        .and_then(Value::as_str)
        .map(|o| format!("0x{}", o.trim_start_matches("0x")))
        .ok_or_else(|| anyhow!("wallet/verify missing omni_account: {verify}"))?;

    Ok(serde_json::to_string(&json!({
        "agent_address": address,
        "actor_omni": actor_omni,
        "device_key_hash": device_key_hash,
        "pop_sig": pop_sig,
        "session_jwt": session_jwt,
        "link_code": link_code,
        "key_file": key_path,
    }))?)
}
