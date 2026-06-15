//! Master-side §10.2 agent admin (issue #144, method A): claim agent-initiated
//! pairing requests + pull pending bindings. These are the master's half of the
//! agent-initiated ceremony — the agent half (request + retrieve) lives in the
//! daemon's `--request-pairing` / `--retrieve-pairing` one-shots.
//!
//! Both commands are gated by the master's `J1` session bearer. The on-chain
//! binding and scope grant (the "bind" and "grant" steps the operator approves
//! with one Touch ID) stay in the chain helpers (`heima-agent-create.sh
//! --from-pubkey` and `heima-scope-set.sh --webauthn`) because chain submission
//! lives in shell + `cast`; those two helpers are the deterministic two-step
//! split the test drives. `agent pending` is the production-flow rendezvous: the
//! master discovers "agent-X wants to pair, wants `[scope]`" by pulling the broker.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("build http client")
}

/// Resolve the master `J1` bearer: explicit `session_bearer` if non-empty, else
/// the stored `master` session token.
fn resolve_bearer(session_bearer: &str) -> Result<String> {
    if !session_bearer.trim().is_empty() {
        return Ok(session_bearer.trim().to_string());
    }
    let sess = agentkeys_core::session_store::load_session("master")
        .context("no --session-bearer given and no stored `master` session to fall back on")?;
    Ok(sess.token.clone())
}

/// `agentkeys agent claim` — master claims an agent's pairing request by the
/// `pairing_code` the agent displayed, binding it under the HDKD child omni for
/// `label` and declaring the scope the agent should get. The agent never named
/// the master; this claim is the binding act (Sybil-safe).
pub async fn agent_claim(
    broker_url: &str,
    pairing_code: &str,
    label: &str,
    services: &str,
    session_bearer: &str,
) -> Result<String> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .post(format!("{base}/v1/agent/pairing/claim"))
        .bearer_auth(bearer)
        .json(&json!({
            "pairing_code": pairing_code,
            "label": label,
            "requested_scope": services,
        }))
        .send()
        .await
        .context("POST /v1/agent/pairing/claim")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("agent claim failed: HTTP {status}: {text}"));
    }
    let v: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys agent pending` — master pulls claimed-but-unbound agents (the
/// production push-notification substrate). Each row is "agent-X wants to pair,
/// wants `[requested_scope]`", with the device artifact (`device_pubkey`,
/// `pop_sig`, `device_key_hash`) the master needs to submit `registerAgentDevice`,
/// keyed by `request_id`.
pub async fn agent_pending(broker_url: &str, session_bearer: &str) -> Result<String> {
    let v = agent_pending_value(broker_url, session_bearer).await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// Same as [`agent_pending`] but returns the parsed broker response
/// (`{ "pending": [PendingBinding, …] }`) for programmatic callers — the daemon
/// ui-bridge maps it to the web UI's pairing-request shape (issue #214). The CLI
/// wrapper above pretty-prints this for the operator.
pub async fn agent_pending_value(broker_url: &str, session_bearer: &str) -> Result<Value> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .get(format!("{base}/v1/agent/pending-bindings"))
        .bearer_auth(bearer)
        .send()
        .await
        .context("GET /v1/agent/pending-bindings")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("agent pending failed: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).with_context(|| format!("parse: {text}"))
}

/// `agentkeys agent ack` (programmatic) — the master acks a pending binding by
/// `request_id` after submitting `registerAgentDevice` on chain, clearing it from
/// the broker's pending list (§10.2 P.2). Used by the daemon web pairing flow
/// (#214) after a successful on-chain register.
pub async fn agent_ack(broker_url: &str, request_id: &str, session_bearer: &str) -> Result<()> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .post(format!("{base}/v1/agent/pending-bindings/ack"))
        .bearer_auth(bearer)
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .context("POST /v1/agent/pending-bindings/ack")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("agent ack failed: HTTP {status}: {text}"));
    }
    Ok(())
}
