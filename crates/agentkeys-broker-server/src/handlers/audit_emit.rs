//! #97 phase F — control-plane audit envelopes from the submit relay.
//!
//! The shared submit handler (`/v1/accept/submit`, `/v1/scope/submit`,
//! `/v1/revoke/submit`) relays ONE master-signed `executeBatch` UserOp. After
//! the bundler receipt confirms success, this module decodes the calldata
//! that actually landed on chain and emits one `AuditEnvelope v1` per inner
//! call:
//!
//! - `registerAgentDevice` → `DeviceAdd` (role_bits = `ROLE_CAP_MINT`, the
//!   fixed role set `SidecarRegistry` assigns agent binds; attestation hash
//!   zero — agent binds carry no WebAuthn attestation)
//! - `setScope` with services → `ScopeGrant` (the FULL replacement set —
//!   set-replace semantics per #248)
//! - `setScope` with empty services → `ScopeRevoke`
//! - `revokeAgentDevice` → `DeviceRevoke`
//!
//! Decoding our own composed calldata — rather than trusting client-supplied
//! summary fields — means the audit reflects on-chain truth: a UserOp whose
//! inner ops named a different operator would have reverted on-chain
//! (`msg.sender == operatorMasterWallet` in both contracts), so a confirmed
//! receipt guarantees the calldata's omnis are authentic. An unknown inner
//! selector is skipped with a WARN (forward-compat: a future batch shape
//! never breaks the relay).
//!
//! Emission is BEST-EFFORT by design, unlike the #229 data-plane workers
//! where `AGENTKEYS_WORKER_REQUIRE_AUDIT=1` can fail closed: there the
//! response *releases data*, so withholding it enforces audit-before-release.
//! Here the chain tx ALREADY landed — failing the response can't un-land it,
//! and the on-chain event log itself remains the authoritative trail.

use agentkeys_core::audit::{
    calldata::{decode_calldata, DecodedCall},
    envelope_for, AuditClient, AuditEnvelope, AuditOpKind, AuditResult, DeviceAddBody,
    DeviceRevokeBody, ScopeGrantBody, ScopeRevokeBody,
};
use agentkeys_core::erc4337::decode_execute_batch;
use serde_json::Value;

/// `SidecarRegistry.ROLE_CAP_MINT` — the role set `registerAgentDevice`
/// assigns to every agent device (pinned by the contract, not calldata).
const AGENT_ROLE_BITS: u8 = 1;

/// Default audit-worker URL: the broker is co-located with the audit worker
/// on the broker host (same default as the data-plane workers' emitter).
/// Override with `AGENTKEYS_AUDIT_WORKER_URL` for split deployments.
/// Shared with the #377 sandbox-lifecycle emits (`handlers::sandbox`).
pub(crate) const DEFAULT_AUDIT_WORKER_URL: &str = "http://127.0.0.1:9092";

/// Decode a confirmed `executeBatch` UserOp calldata into the audit envelopes
/// for what landed. Pure — no I/O, fully unit-testable. `session_omni` is the
/// verified J1 session operator (used where the inner calldata carries no
/// omni, i.e. `revokeAgentDevice`).
pub fn envelopes_for_batch(session_omni: [u8; 32], call_data: &[u8]) -> Vec<AuditEnvelope> {
    let calls = match decode_execute_batch(call_data) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "audit: submit calldata is not a decodable executeBatch — no envelopes emitted");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(calls.len());
    for (i, call) in calls.iter().enumerate() {
        let decoded = match decode_calldata(&call.calldata) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(index = i, error = %e, "audit: unknown inner call in confirmed batch — skipped (forward-compat)");
                continue;
            }
        };
        match envelope_for_inner_call(session_omni, &decoded) {
            Ok(Some(env)) => out.push(env),
            Ok(None) => {
                tracing::warn!(index = i, function = %decoded.function, "audit: inner call has no op_kind mapping — skipped");
            }
            Err(e) => {
                tracing::warn!(index = i, function = %decoded.function, error = %e, "audit: failed to map inner call to an envelope — skipped");
            }
        }
    }
    out
}

fn envelope_for_inner_call(
    session_omni: [u8; 32],
    call: &DecodedCall,
) -> Result<Option<AuditEnvelope>, String> {
    match (call.contract.as_str(), call.function.as_str()) {
        // #427 kind split: both K10-actor registration legs share the arg
        // shape and both anchor a DeviceAdd binding row (the ceremony-level
        // DelegateSpawn 55 is the spawn finalize hook's, which carries the
        // preset/label context calldata can't).
        ("SidecarRegistry", "registerAgentDevice") | ("SidecarRegistry", "registerDelegate") => {
            // register{AgentDevice,Delegate}(deviceKeyHash, operatorOmni, actorOmni, link, pop)
            let device_key_hash = hex_string(call, 0)?;
            let operator = hex32(call, 1)?;
            let actor = hex32(call, 2)?;
            let body = DeviceAddBody {
                device_key_hash,
                role_bits: AGENT_ROLE_BITS,
                attestation_hash: format!("0x{}", "00".repeat(32)),
            };
            envelope_for(
                actor,
                operator,
                AuditOpKind::DeviceAdd,
                body,
                AuditResult::Success,
                None,
                None,
            )
            .map(Some)
            .map_err(|e| e.to_string())
        }
        ("AgentKeysScope", "setScope") => {
            // setScope(operatorOmni, agentOmni, services, readOnly, maxPerCall,
            //          maxPerPeriod, maxTotal, periodSeconds)
            let operator = hex32(call, 0)?;
            let actor = hex32(call, 1)?;
            let agent_omni = hex_string(call, 1)?;
            let service_ids = hex_array(call, 2)?;
            if service_ids.is_empty() {
                let body = ScopeRevokeBody { agent_omni };
                return envelope_for(
                    actor,
                    operator,
                    AuditOpKind::ScopeRevoke,
                    body,
                    AuditResult::Success,
                    None,
                    None,
                )
                .map(Some)
                .map_err(|e| e.to_string());
            }
            let body = ScopeGrantBody {
                agent_omni,
                service_ids,
                read_only: bool_arg(call, 3)?,
                max_per_call: uint_decimal(call, 4)?,
                max_per_period: uint_decimal(call, 5)?,
                max_total: uint_decimal(call, 6)?,
                period_seconds: u32_arg(call, 7)?,
            };
            envelope_for(
                actor,
                operator,
                AuditOpKind::ScopeGrant,
                body,
                AuditResult::Success,
                None,
                None,
            )
            .map(Some)
            .map_err(|e| e.to_string())
        }
        ("SidecarRegistry", "revokeAgentDevice") => {
            // revokeAgentDevice(deviceKeyHash) — no omni in calldata; the
            // master (the verified session operator) performed the unpair, so
            // actor = operator = session omni; the subject device is in the body.
            let body = DeviceRevokeBody {
                device_key_hash: hex_string(call, 0)?,
            };
            envelope_for(
                session_omni,
                session_omni,
                AuditOpKind::DeviceRevoke,
                body,
                AuditResult::Success,
                None,
                None,
            )
            .map(Some)
            .map_err(|e| e.to_string())
        }
        _ => Ok(None),
    }
}

/// Emit every envelope for a confirmed batch to the audit worker. Returns the
/// `envelope_hash` receipts that made it (best-effort — failures WARN and are
/// dropped from the receipt list, never fail the submit response).
pub async fn emit_for_confirmed_batch(session_omni: [u8; 32], call_data: &[u8]) -> Vec<String> {
    let envelopes = envelopes_for_batch(session_omni, call_data);
    if envelopes.is_empty() {
        return Vec::new();
    }
    let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
        .unwrap_or_else(|_| DEFAULT_AUDIT_WORKER_URL.to_string());
    let client = AuditClient::new(url);
    let mut hashes = Vec::with_capacity(envelopes.len());
    for env in &envelopes {
        match client.append(env).await {
            Ok(resp) => hashes.push(resp.envelope_hash),
            Err(e) => {
                tracing::warn!(
                    op_kind = env.op_kind,
                    error = %e,
                    "audit: durable append FAILED for a confirmed control-plane op (best-effort) — event NOT in the audit feed"
                );
            }
        }
    }
    hashes
}

// ── decoded-arg accessors ────────────────────────────────────────────────

fn arg(call: &DecodedCall, idx: usize) -> Result<&Value, String> {
    call.args
        .get(idx)
        .map(|a| &a.value)
        .ok_or_else(|| format!("{}: missing arg {idx}", call.function))
}

fn hex_string(call: &DecodedCall, idx: usize) -> Result<String, String> {
    arg(call, idx)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{}: arg {idx} not a hex string", call.function))
}

fn hex32(call: &DecodedCall, idx: usize) -> Result<[u8; 32], String> {
    let s = hex_string(call, idx)?;
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|_| format!("{}: arg {idx} not 32 bytes", call.function))
}

fn hex_array(call: &DecodedCall, idx: usize) -> Result<Vec<String>, String> {
    arg(call, idx)?
        .as_array()
        .ok_or_else(|| format!("{}: arg {idx} not an array", call.function))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{}: arg {idx} element not a string", call.function))
        })
        .collect()
}

fn bool_arg(call: &DecodedCall, idx: usize) -> Result<bool, String> {
    arg(call, idx)?
        .as_bool()
        .ok_or_else(|| format!("{}: arg {idx} not a bool", call.function))
}

/// uint128 decode: `audit::calldata` renders ≤u64 as a JSON number and wider
/// values as a decimal string — normalize both to the decimal string the
/// `ScopeGrantBody` caps carry.
fn uint_decimal(call: &DecodedCall, idx: usize) -> Result<String, String> {
    match arg(call, idx)? {
        Value::Number(n) => Ok(n.to_string()),
        Value::String(s) if !s.starts_with("0x") => Ok(s.clone()),
        other => Err(format!("{}: arg {idx} not a uint ({other})", call.function)),
    }
}

fn u32_arg(call: &DecodedCall, idx: usize) -> Result<u32, String> {
    arg(call, idx)?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("{}: arg {idx} not a u32", call.function))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::audit::TypedAuditBody;
    use agentkeys_core::erc4337::{
        accept_batch_calldata, revoke_batch_calldata, scope_batch_calldata, AgentRegister,
        ScopeGrant,
    };

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }
    fn addr(last: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = last;
        a
    }
    fn sample_register() -> AgentRegister {
        AgentRegister {
            device_key_hash: b32(0x11),
            operator_omni: b32(0x22),
            actor_omni: b32(0x33),
            link_code_redemption: vec![0xde, 0xad],
            agent_pop_sig: vec![0x55; 65],
        }
    }
    fn sample_grant(services: Vec<[u8; 32]>) -> ScopeGrant {
        ScopeGrant {
            services,
            read_only: true,
            max_per_call: 1000,
            max_per_period: u128::MAX, // forces the decimal-string uint path
            max_total: 0,
            period_seconds: 86400,
        }
    }

    /// The accept batch (register + setScope) maps to [DeviceAdd, ScopeGrant]
    /// with omnis taken from the CALLDATA (on-chain truth), not the session.
    #[test]
    fn accept_batch_maps_to_device_add_plus_scope_grant() {
        let reg = sample_register();
        let grant = sample_grant(vec![b32(0xc1), b32(0xc2)]);
        let batch = accept_batch_calldata(&addr(0xa1), &addr(0xa2), &reg, &grant);

        let envs = envelopes_for_batch(b32(0x22), &batch);
        assert_eq!(envs.len(), 2);

        assert_eq!(envs[0].op_kind, AuditOpKind::DeviceAdd as u8);
        assert_eq!(envs[0].actor_omni, b32(0x33)); // the agent being bound
        assert_eq!(envs[0].operator_omni, b32(0x22));
        match envs[0].typed_body().unwrap() {
            TypedAuditBody::DeviceAdd(b) => {
                assert_eq!(b.device_key_hash, format!("0x{}", "11".repeat(32)));
                assert_eq!(b.role_bits, AGENT_ROLE_BITS);
                assert_eq!(b.attestation_hash, format!("0x{}", "00".repeat(32)));
            }
            other => panic!("unexpected body: {other:?}"),
        }

        assert_eq!(envs[1].op_kind, AuditOpKind::ScopeGrant as u8);
        assert_eq!(envs[1].actor_omni, b32(0x33));
        match envs[1].typed_body().unwrap() {
            TypedAuditBody::ScopeGrant(b) => {
                assert_eq!(b.agent_omni, format!("0x{}", "33".repeat(32)));
                assert_eq!(
                    b.service_ids,
                    vec![
                        format!("0x{}", "c1".repeat(32)),
                        format!("0x{}", "c2".repeat(32))
                    ]
                );
                assert!(b.read_only);
                assert_eq!(b.max_per_call, "1000");
                assert_eq!(b.max_per_period, u128::MAX.to_string());
                assert_eq!(b.max_total, "0");
                assert_eq!(b.period_seconds, 86400);
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    /// A scope-only batch with an EMPTY service set is the revoke-all →
    /// ScopeRevoke (set-replace semantics, #248).
    #[test]
    fn empty_set_scope_maps_to_scope_revoke() {
        let batch = scope_batch_calldata(
            &addr(0xa2),
            &b32(0x22),
            &b32(0x33),
            &sample_grant(Vec::new()),
        );
        let envs = envelopes_for_batch(b32(0x22), &batch);
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].op_kind, AuditOpKind::ScopeRevoke as u8);
        match envs[0].typed_body().unwrap() {
            TypedAuditBody::ScopeRevoke(b) => {
                assert_eq!(b.agent_omni, format!("0x{}", "33".repeat(32)));
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    /// The unpair batch maps to DeviceRevoke with actor = operator = the
    /// verified session omni (the master performed it; calldata has no omni).
    /// A #260 FLEET revoke (N devices, one batch) yields one envelope per
    /// device.
    #[test]
    fn revoke_batch_maps_to_device_revoke_under_session_omni() {
        let batch = revoke_batch_calldata(&addr(0xa1), &[b32(0x11), b32(0x12)]);
        let envs = envelopes_for_batch(b32(0x22), &batch);
        assert_eq!(envs.len(), 2);
        for (env, expected_hash) in envs.iter().zip(["11", "12"]) {
            assert_eq!(env.op_kind, AuditOpKind::DeviceRevoke as u8);
            assert_eq!(env.actor_omni, b32(0x22));
            assert_eq!(env.operator_omni, b32(0x22));
            match env.typed_body().unwrap() {
                TypedAuditBody::DeviceRevoke(b) => {
                    assert_eq!(b.device_key_hash, format!("0x{}", expected_hash.repeat(32)));
                }
                other => panic!("unexpected body: {other:?}"),
            }
        }
    }

    /// Garbage / non-executeBatch calldata yields NO envelopes and no panic —
    /// the submit path must never 5xx because of the audit decode.
    #[test]
    fn undecodable_calldata_yields_no_envelopes() {
        assert!(envelopes_for_batch(b32(0x22), &[0xde, 0xad, 0xbe, 0xef]).is_empty());
        assert!(envelopes_for_batch(b32(0x22), &[]).is_empty());
    }
}
