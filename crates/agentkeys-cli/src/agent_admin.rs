//! Master-side §10.2 agent admin (issue #144): mint link codes + pull pending
//! bindings. These are the master's half of the link-code ceremony — the agent
//! half lives in the daemon's `--init-link-code` one-shot.
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
    Ok(sess.token)
}

/// `agentkeys agent create` — master mints a one-time link code bound to the
/// HDKD child omni for `label`, declaring the scope the agent should get.
pub async fn agent_create(
    broker_url: &str,
    label: &str,
    services: &str,
    session_bearer: &str,
) -> Result<String> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .post(format!("{base}/v1/agent/create"))
        .bearer_auth(bearer)
        .json(&json!({ "label": label, "requested_scope": services }))
        .send()
        .await
        .context("POST /v1/agent/create")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("agent create failed: HTTP {status}: {text}"));
    }
    let v: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys agent pending` — master pulls redeemed-but-unbound agents (the
/// production push-notification substrate). Each row is "agent-X wants to pair,
/// wants `[requested_scope]`", with the device artifact (`device_pubkey`,
/// `pop_sig`, `device_key_hash`) the master needs to submit `registerAgentDevice`.
pub async fn agent_pending(broker_url: &str, session_bearer: &str) -> Result<String> {
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
    let v: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
    Ok(serde_json::to_string_pretty(&v)?)
}
