//! #427 (epic #425 decision 6) — the broker→gate provisioning client.
//!
//! The gate (`agentkeys-gate`, #384/#332) is the USAGE plane of the two-plane
//! delegate entitlement model: every delegate LLM turn flows through it,
//! budgets are enforced deterministically (`429 budget_exceeded`, no LLM in
//! the decision), and usage rolls up per user via `GET /v1/usage` +
//! `GateTurn` (op_kind 90) audit rows. This module is the broker-side client
//! for the gate's admin surface: SPAWN provisions a per-delegate relay key
//! (+ budget from the tier entitlement), ARCHIVE disables it — a delegate
//! *exists* by the chain (the slot allowance, the existence plane) but is
//! *usable* only while gate-provisioned. The gate stays custody + metering,
//! never a control point (arch.md §22d).
//!
//! Deploy posture: the gate is VE-resident today (#384 deferred the AWS
//! deploy wiring). `AGENTKEYS_GATE_ADMIN_URL` unset ⇒ provisioning is a
//! DOCUMENTED no-op skip (the sandbox keeps the direct ark-key injection —
//! today's behavior, logged as `skip gate-not-configured`); set but
//! unreachable/refusing ⇒ a LOUD error surfaced in the ceremony summary
//! (never silent — an unmetered delegate bypasses the usage plane).

use serde::{Deserialize, Serialize};

/// Broker-side gate admin wiring, from env:
/// - `AGENTKEYS_GATE_ADMIN_URL` — the gate's admin base (e.g. `http://127.0.0.1:8077`).
/// - `AGENTKEYS_GATE_ADMIN_TOKEN` — the gate's `AGENTKEYS_GATE_ADMIN_TOKEN` bearer.
/// - `AGENTKEYS_GATE_TURN_URL` — the SANDBOX-visible turn base injected as the
///   delegate's `ARK_BASE_URL` (e.g. `https://gate.<zone>/v1`); the admin URL is
///   broker-local and often not what a sandbox can reach.
/// - `AGENTKEYS_GATE_DELEGATE_BUDGET_TOKENS` — optional per-delegate token
///   budget applied at provision time (the tier default; unset ⇒ the gate's
///   own default/unlimited-but-metered posture).
pub struct GateAdminConfig {
    pub admin_url: String,
    pub admin_token: String,
    pub turn_url: String,
    pub delegate_budget_tokens: Option<u64>,
}

/// `None` = gate not configured on this stack (the documented no-op skip).
/// `Some(Err)` never happens here — partial config (URL without token/turn
/// URL) is a hard error string so a half-wired stack fails loud, not silent.
pub fn load_gate_admin_config() -> Option<Result<GateAdminConfig, String>> {
    let admin_url = std::env::var("AGENTKEYS_GATE_ADMIN_URL").ok()?;
    let admin_url = admin_url.trim().trim_end_matches('/').to_string();
    if admin_url.is_empty() {
        return None;
    }
    let admin_token = match std::env::var("AGENTKEYS_GATE_ADMIN_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => {
            return Some(Err(
                "AGENTKEYS_GATE_ADMIN_URL is set but AGENTKEYS_GATE_ADMIN_TOKEN is not — \
                 the gate admin surface is bearer-gated; set both or neither"
                    .to_string(),
            ))
        }
    };
    let turn_url = match std::env::var("AGENTKEYS_GATE_TURN_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().trim_end_matches('/').to_string(),
        _ => {
            return Some(Err(
                "AGENTKEYS_GATE_ADMIN_URL is set but AGENTKEYS_GATE_TURN_URL is not — \
                 the sandbox needs the gate's turn base as its ARK_BASE_URL; set both"
                    .to_string(),
            ))
        }
    };
    let delegate_budget_tokens = std::env::var("AGENTKEYS_GATE_DELEGATE_BUDGET_TOKENS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    Some(Ok(GateAdminConfig {
        admin_url,
        admin_token,
        turn_url,
        delegate_budget_tokens,
    }))
}

/// `POST /v1/admin/keys` body — mirrors `agentkeys-gate`'s admin surface
/// (`crates/agentkeys-gate/src/admin.rs`; its serde tests pin this shape).
#[derive(Debug, Serialize)]
struct ProvisionKeyRequest<'a> {
    /// Stable key id — the delegate's `device_key_hash` (unique per binding,
    /// survives re-provision lookups, and is the `GateTurn` rollup dimension).
    key_id: &'a str,
    /// The OWNING user (operator omni) — the budget/rollup accumulation root.
    user_omni: &'a str,
    /// The delegate's actor omni — the per-delegate attribution dimension.
    delegate_omni: &'a str,
    device_id: &'a str,
    label: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_tokens: Option<u64>,
}

/// What the gate returns on provision: the relay-key secret is returned ONCE
/// (the broker injects it into the sandbox env and drops it).
#[derive(Debug, Deserialize)]
pub struct ProvisionedKey {
    pub key_id: String,
    pub secret: String,
}

/// Provision a per-delegate relay key at spawn. Idempotent on the gate side
/// (re-provisioning an existing enabled `key_id` rotates its secret).
pub async fn provision_delegate(
    http: &reqwest::Client,
    cfg: &GateAdminConfig,
    operator_omni: &str,
    delegate_omni: &str,
    device_key_hash: &str,
    label: &str,
) -> Result<ProvisionedKey, String> {
    let body = ProvisionKeyRequest {
        key_id: device_key_hash,
        user_omni: operator_omni,
        delegate_omni,
        device_id: device_key_hash,
        label,
        budget_tokens: cfg.delegate_budget_tokens,
    };
    let resp = http
        .post(format!("{}/v1/admin/keys", cfg.admin_url))
        .bearer_auth(&cfg.admin_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("gate provision send: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("gate provision {status}: {text}"));
    }
    resp.json::<ProvisionedKey>()
        .await
        .map_err(|e| format!("gate provision decode: {e}"))
}

/// Disable a delegate's relay key at archive (turns stop; usage history and
/// the key row remain for rollups). Idempotent — disabling a disabled or
/// unknown key returns Ok(false).
pub async fn deprovision_delegate(
    http: &reqwest::Client,
    cfg: &GateAdminConfig,
    device_key_hash: &str,
) -> Result<bool, String> {
    let resp = http
        .post(format!(
            "{}/v1/admin/keys/{}/disable",
            cfg.admin_url, device_key_hash
        ))
        .bearer_auth(&cfg.admin_token)
        .send()
        .await
        .map_err(|e| format!("gate deprovision send: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("gate deprovision {status}: {text}"));
    }
    #[derive(Deserialize)]
    struct DisableResponse {
        disabled: bool,
    }
    resp.json::<DisableResponse>()
        .await
        .map(|r| r.disabled)
        .map_err(|e| format!("gate deprovision decode: {e}"))
}
