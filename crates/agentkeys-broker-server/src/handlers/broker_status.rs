//! Operational `/readyz` handler that aggregates plugin Readiness +
//! Tier-2 reachability state per plan §7.
//!
//! Responses:
//! - 503 with `{"status":"unready", "degraded":false, "checks":[...], "ready":[...]}`
//!   if any plug-in or Tier-2 check is `Unready` (or Tier-2 still-pending
//!   for a feature-gated check that's enabled).
//! - 200 with `{"status":"degraded", "degraded":true, "checks":[...], "ready":[...]}`
//!   if any check is `Degraded` (the broker is still serving but a
//!   dependency is impaired).
//! - 200 with `{"status":"ready", "degraded":false, "checks":[], "ready":[...]}`
//!   if every check is `Ready`. The body is always self-describing —
//!   never an empty `{}` — so an operator running `curl … | jq` sees an
//!   explicit verdict instead of having to read the HTTP status code.
//!
//! Each check entry carries a `docs` URL anchor (Designer review #status-shape)
//! so an operator paged at 2am can click straight to the runbook section
//! that explains the failure mode.

use std::sync::atomic::Ordering;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::{json, Value};

use crate::plugins::Readiness;
use crate::state::SharedState;

/// Liveness probe — returns 200 unless the process is panicking/exiting.
/// Decoupled from operational state so a failed `/readyz` doesn't fail
/// liveness probes too (causing pod restarts that mask the real issue).
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness probe — aggregates every plug-in's `Readiness` + Tier-2
/// reachability flags. Returns the worst-case status.
pub async fn readyz(State(state): State<SharedState>) -> impl IntoResponse {
    // Plug-in readiness (sync — each plug-in's `ready()` is a fast probe).
    let (overall_plugin_state, plugin_checks) = state.registry.aggregate_readiness();

    // Tier-2 reachability flags (set by spawn_tier2_probes in main.rs).
    let ses_verified = state.tier2.ses_verified.load(Ordering::Relaxed);
    let evm_rpc_reachable = state.tier2.evm_rpc_reachable.load(Ordering::Relaxed);
    let evm_fee_payer_funded = state.tier2.evm_fee_payer_funded.load(Ordering::Relaxed);

    // Build the per-check JSON list. Plug-in readiness + Tier-2 flags
    // both render with the same shape so monitoring tooling can iterate
    // uniformly.
    let mut checks: Vec<Value> = Vec::with_capacity(plugin_checks.len() + 4);
    let mut ready_names: Vec<String> = Vec::new();
    let mut degraded = false;
    let mut unready = false;

    for (name, r) in &plugin_checks {
        let entry = readiness_to_json(name, r);
        match r {
            Readiness::Ready { .. } => {
                ready_names.push(name.clone());
            }
            Readiness::Degraded { .. } => {
                degraded = true;
                checks.push(entry);
            }
            Readiness::Unready { .. } => {
                unready = true;
                checks.push(entry);
            }
        }
    }

    // Tier-2 SES probe — only reported when email-link auth is enabled.
    if state.registry.auth.contains_key("email_link") {
        if ses_verified {
            ready_names.push("tier2/ses".into());
        } else {
            unready = true;
            checks.push(json!({
                "name": "tier2/ses",
                "status": "unready",
                "reason": "SES sender identity not yet verified since boot",
                "docs": runbook_anchor("ses-verification"),
            }));
        }
    }

    // Tier-2 EVM probes — only when EVM audit anchor is enabled.
    if state.registry.audit.iter().any(|a| a.name() == "evm_testnet") {
        if evm_rpc_reachable {
            ready_names.push("tier2/evm_rpc".into());
        } else {
            unready = true;
            checks.push(json!({
                "name": "tier2/evm_rpc",
                "status": "unready",
                "reason": "EVM RPC eth_chainId probe has not succeeded since boot",
                "docs": runbook_anchor("evm-rpc-reachability"),
            }));
        }
        if evm_fee_payer_funded {
            ready_names.push("tier2/evm_fee_payer".into());
        } else {
            unready = true;
            checks.push(json!({
                "name": "tier2/evm_fee_payer",
                "status": "unready",
                "reason": "EVM fee-payer balance below BROKER_EVM_FEE_PAYER_MIN_BALANCE",
                "docs": runbook_anchor("evm-fee-payer-balance"),
            }));
        }
    }

    let _ = overall_plugin_state; // captured implicitly through degraded/unready

    if unready {
        let body = json!({
            "status": "unready",
            "degraded": false,
            "checks": checks,
            "ready": ready_names,
        });
        (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
    } else if degraded {
        let body = json!({
            "status": "degraded",
            "degraded": true,
            "checks": checks,
            "ready": ready_names,
        });
        (StatusCode::OK, Json(body)).into_response()
    } else {
        // Self-describing all-green body. Earlier versions returned `{}`
        // (Designer review #status-shape) but operators piping the
        // output through `jq` saw nothing and assumed the endpoint was
        // broken — explicit `status: "ready"` removes that confusion.
        let body = json!({
            "status": "ready",
            "degraded": false,
            "checks": [],
            "ready": ready_names,
        });
        (StatusCode::OK, Json(body)).into_response()
    }
}

fn readiness_to_json(name: &str, r: &Readiness) -> Value {
    match r {
        Readiness::Ready { detail } => json!({
            "name": name,
            "status": "ready",
            "detail": detail,
            "docs": runbook_anchor(name),
        }),
        Readiness::Degraded { reason } => json!({
            "name": name,
            "status": "degraded",
            "reason": reason,
            "docs": runbook_anchor(name),
        }),
        Readiness::Unready { reason } => json!({
            "name": name,
            "status": "unready",
            "reason": reason,
            "docs": runbook_anchor(name),
        }),
    }
}

/// Per-check anchor in the operator runbook. Stage 7 phase 0 lands a
/// stub doc URL; Phase E finalizes the runbook structure (US-015) and
/// every anchor referenced here will exist as a heading in
/// `docs/operator-runbook-stage7.md`.
fn runbook_anchor(check_name: &str) -> String {
    let slug = check_name.replace(['/', '_'], "-");
    format!("https://docs.agentkeys.dev/operator-runbook-stage7#{}", slug)
}
