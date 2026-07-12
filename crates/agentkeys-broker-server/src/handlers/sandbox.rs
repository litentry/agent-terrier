//! #377 sandbox-lifecycle hooks — the glue between the delegation/pairing
//! handlers and [`ve_faas`](crate::ve_faas):
//!
//! - **spawn** (`ensure_for_delegate`): called by `/v1/agent/pairing/poll`
//!   (create-on-pair — the moment `J1_agent` is first minted) and
//!   `/v1/agent/resolve` (every device boot). Idempotent; emits ONE
//!   `SandboxSpawn` (op_kind 53) envelope when an instance was actually
//!   created.
//! - **teardown** (`teardown_for_confirmed_batch`): called by the shared
//!   submit relay after a CONFIRMED receipt, killing the instances of every
//!   device the batch `revokeAgentDevice`d (decoded from the on-chain
//!   calldata — same truth source as the #97 audit decode) and emitting one
//!   `SandboxTeardown` (op_kind 54) envelope per kill.
//!
//! Both hooks are BEST-EFFORT against the handler's main job: a veFaaS
//! failure never fails the pairing poll / resolve / submit response — the
//! error is surfaced IN the response (`sandbox.error`) and WARN-logged, never
//! swallowed. The audit emits follow the audit_emit.rs posture (best-effort,
//! loud on failure).

use agentkeys_core::audit::{
    calldata::decode_calldata, envelope_for, AuditClient, AuditEnvelope, AuditOpKind, AuditResult,
    SandboxSpawnBody, SandboxTeardownBody,
};
use agentkeys_core::erc4337::decode_execute_batch;
use serde_json::json;

use crate::state::SharedState;
use crate::ve_faas::VeFaasClient;

/// What a spawn hook hands back to its handler for the response body.
/// `agent_url` is always the configured gateway (static config — the device
/// can talk to it as soon as ANY instance is Ready); the rest reports this
/// call's ensure outcome.
pub struct SandboxProvision {
    pub agent_url: String,
    pub sandbox_id: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
}

impl SandboxProvision {
    /// The `"sandbox"` object attached to poll/resolve responses.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "sandbox_id": self.sandbox_id,
            "status": self.status,
            "error": self.error,
        })
    }
}

/// Ensure the delegate's sandbox exists (spawning it if needed) + emit the
/// `SandboxSpawn` envelope on an actual create. `None` = lifecycle disabled
/// on this host (no sandbox config) — callers return `agent_url: null` and
/// the device falls back to its compiled `AGENT_BASE_URL` (#367 semantics).
pub async fn ensure_for_delegate(
    state: &SharedState,
    device_key_hash: &str,
    actor_omni: &str,
    operator_omni: &str,
) -> Option<SandboxProvision> {
    ensure_for_delegate_with_envs(state, device_key_hash, actor_omni, operator_omni, &[]).await
}

/// #427 spawn-ceremony variant: the same ensure with the delegate identity +
/// gate-relay envs threaded into a freshly created instance.
pub async fn ensure_for_delegate_with_envs(
    state: &SharedState,
    device_key_hash: &str,
    actor_omni: &str,
    operator_omni: &str,
    extra_envs: &[(String, String)],
) -> Option<SandboxProvision> {
    let client = state.ve_faas.as_ref()?;
    let agent_url = client.agent_url().to_string();
    match client
        .ensure_for_delegate_with_envs(device_key_hash, actor_omni, extra_envs)
        .await
    {
        Ok(outcome) => {
            tracing::info!(
                device_key_hash = %device_key_hash,
                sandbox_id = %outcome.sandbox_id,
                status = %outcome.status,
                created = outcome.created,
                "#377 delegate sandbox ensured"
            );
            if outcome.created {
                emit_spawn(
                    client,
                    device_key_hash,
                    &outcome.sandbox_id,
                    actor_omni,
                    operator_omni,
                )
                .await;
            }
            Some(SandboxProvision {
                agent_url,
                sandbox_id: Some(outcome.sandbox_id),
                status: Some(outcome.status),
                error: None,
            })
        }
        Err(e) => {
            // Surfaced, never swallowed: the device still gets its JWT (the
            // handler's main job) plus the exact spawn failure to report.
            tracing::warn!(
                device_key_hash = %device_key_hash,
                error = %e,
                "#377 delegate sandbox ensure FAILED — device keeps its session; talk path may 500 no_ready_instance"
            );
            Some(SandboxProvision {
                agent_url,
                sandbox_id: None,
                status: None,
                error: Some(e.to_string()),
            })
        }
    }
}

/// The `device_key_hash` argument of every `revokeAgentDevice` in a confirmed
/// `executeBatch` calldata. Pure — same decode chain as the #97 audit emit
/// (on-chain truth, never client-claimed fields); undecodable calldata or
/// non-revoke batches yield an empty list.
pub fn revoked_device_key_hashes(call_data: &[u8]) -> Vec<String> {
    let Ok(calls) = decode_execute_batch(call_data) else {
        return Vec::new();
    };
    calls
        .iter()
        .filter_map(|call| {
            let decoded = decode_calldata(&call.calldata).ok()?;
            if decoded.contract == "SidecarRegistry" && decoded.function == "revokeAgentDevice" {
                decoded.args.first()?.value.as_str().map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

/// Teardown hook for the shared submit relay: after a CONFIRMED receipt, kill
/// the sandbox of every device the batch revoked and emit one
/// `SandboxTeardown` envelope per killed instance. Best-effort — the chain tx
/// is already final, so failures WARN (an expired instance dies on its own
/// timeout anyway; the delegate can no longer resolve a new one because the
/// binding is revoked).
pub async fn teardown_for_confirmed_batch(
    state: &SharedState,
    session_omni: [u8; 32],
    call_data: &[u8],
) {
    let Some(client) = state.ve_faas.as_ref() else {
        return;
    };
    for device_key_hash in revoked_device_key_hashes(call_data) {
        match client.kill_for_device(&device_key_hash).await {
            Ok(killed) if killed.is_empty() => {
                tracing::info!(
                    device_key_hash = %device_key_hash,
                    "#377 unpair teardown: no live sandbox for the revoked device (no-op)"
                );
            }
            Ok(killed) => {
                for sandbox_id in killed {
                    tracing::info!(
                        device_key_hash = %device_key_hash,
                        sandbox_id = %sandbox_id,
                        "#377 unpair teardown: sandbox killed"
                    );
                    // Mirrors the DeviceRevoke envelope: the master (the
                    // verified session operator) performed the unpair, so
                    // actor = operator = session omni; the device is in the body.
                    let env = envelope_for(
                        session_omni,
                        session_omni,
                        AuditOpKind::SandboxTeardown,
                        SandboxTeardownBody {
                            device_key_hash: device_key_hash.clone(),
                            sandbox_id,
                            reason: "unpair".into(),
                        },
                        AuditResult::Success,
                        None,
                        None,
                    );
                    append_best_effort(env).await;
                }
            }
            Err(e) => {
                tracing::warn!(
                    device_key_hash = %device_key_hash,
                    error = %e,
                    "#377 unpair teardown FAILED — instance dies at its veFaaS timeout; revoked binding blocks any respawn"
                );
            }
        }
    }
}

async fn emit_spawn(
    client: &VeFaasClient,
    device_key_hash: &str,
    sandbox_id: &str,
    actor_omni: &str,
    operator_omni: &str,
) {
    let (Some(actor), Some(operator)) = (omni32(actor_omni), omni32(operator_omni)) else {
        tracing::warn!(
            actor_omni = %actor_omni,
            operator_omni = %operator_omni,
            "sandbox.spawn audit emit skipped: omni not 32-byte hex"
        );
        return;
    };
    let env = envelope_for(
        actor,
        operator,
        AuditOpKind::SandboxSpawn,
        SandboxSpawnBody {
            device_key_hash: device_key_hash.to_string(),
            sandbox_id: sandbox_id.to_string(),
            function_id: client.config.function_id.clone(),
        },
        AuditResult::Success,
        None,
        None,
    );
    append_best_effort(env).await;
}

/// Same best-effort posture + worker URL resolution as
/// [`audit_emit`](crate::handlers::audit_emit): the lifecycle event already
/// happened, so an append failure WARNs and never fails the caller.
async fn append_best_effort(env: Result<AuditEnvelope, agentkeys_core::audit::AuditError>) {
    let env = match env {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "sandbox audit envelope build failed — event NOT in the audit feed");
            return;
        }
    };
    let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
        .unwrap_or_else(|_| crate::handlers::audit_emit::DEFAULT_AUDIT_WORKER_URL.to_string());
    if let Err(e) = AuditClient::new(url).append(&env).await {
        tracing::warn!(
            op_kind = env.op_kind,
            error = %e,
            "audit: durable append FAILED for a sandbox lifecycle event (best-effort) — event NOT in the audit feed"
        );
    }
}

/// Parse a `0x`-prefixed (or bare) 64-hex omni into its 32 raw bytes.
fn omni32(hex_str: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_str.trim().trim_start_matches("0x")).ok()?;
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::erc4337::{revoke_batch_calldata, scope_batch_calldata, ScopeGrant};

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }
    fn addr(last: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = last;
        a
    }

    /// A #260 fleet revoke (N devices, one batch) yields every device hash,
    /// in order — the teardown set mirrors the DeviceRevoke envelope set.
    #[test]
    fn revoke_batch_yields_all_device_hashes() {
        let batch = revoke_batch_calldata(&addr(0xa1), &[b32(0x11), b32(0x12)]);
        assert_eq!(
            revoked_device_key_hashes(&batch),
            vec![
                format!("0x{}", "11".repeat(32)),
                format!("0x{}", "12".repeat(32)),
            ]
        );
    }

    /// Non-revoke batches (e.g. a scope re-grant) and garbage calldata tear
    /// nothing down.
    #[test]
    fn non_revoke_batches_yield_nothing() {
        let grant = ScopeGrant {
            services: vec![b32(0xc1)],
            read_only: true,
            max_per_call: 1,
            max_per_period: 1,
            max_total: 1,
            period_seconds: 60,
        };
        let batch = scope_batch_calldata(&addr(0xa2), &b32(0x22), &b32(0x33), &grant);
        assert!(revoked_device_key_hashes(&batch).is_empty());
        assert!(revoked_device_key_hashes(&[0xde, 0xad]).is_empty());
        assert!(revoked_device_key_hashes(&[]).is_empty());
    }

    #[test]
    fn omni32_parses_prefixed_and_bare() {
        assert_eq!(omni32(&format!("0x{}", "ab".repeat(32))), Some([0xab; 32]));
        assert_eq!(omni32(&"cd".repeat(32)), Some([0xcd; 32]));
        assert_eq!(omni32("0x1234"), None);
        assert_eq!(omni32("not-hex"), None);
    }
}
