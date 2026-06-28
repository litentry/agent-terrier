//! Worker-side durable audit emission (issue #229).
//!
//! Every data-plane op (store / fetch / teardown) on the cred, memory, and
//! config workers emits an `AuditEnvelope v1` to the audit-service worker
//! AFTER cap-verify and BEFORE the success response releases data — closing
//! the "plaintext fetch leaves only a tracing line" gap from the #228 review.
//! The envelope carries the service/key + a cap or ciphertext hash, NEVER
//! plaintext. Failures after cap-verify are audited too (`result: Failure`).
//!
//! Emit-vs-availability posture (staged rollout, mirrors
//! `AGENTKEYS_WORKER_REQUIRE_CAP_POP`):
//!
//! - default: best-effort — an emit failure logs a loud `tracing::warn!`
//!   (the op still succeeds) so a down audit worker doesn't take the whole
//!   data plane with it;
//! - `AGENTKEYS_WORKER_REQUIRE_AUDIT=1`: fail closed — a SUCCESS response
//!   is only released after the durable append succeeds (HTTP 502
//!   `audit_append_failed` otherwise). Flip once the audit worker is
//!   confirmed healthy on the deploy surface.
//!
//! Cap-verify failures do NOT emit: the request is unauthenticated junk at
//! that point and would let an attacker flood the audit feed for free.

use agentkeys_core::audit::{envelope_for, AuditClient, AuditOpKind, AuditResult};
use serde::Serialize;
use sha3::{Digest, Keccak256};

use crate::errors::{err_502, ApiError};
use crate::verify::CapToken;

/// Default audit-worker URL: the workers are co-located with the audit
/// worker on the broker host (its default bind per
/// `agentkeys-worker-audit/src/main.rs`). Override with
/// `AGENTKEYS_AUDIT_WORKER_URL` for split deployments.
const DEFAULT_AUDIT_WORKER_URL: &str = "http://127.0.0.1:9092";

pub struct AuditEmitter {
    client: AuditClient,
    require: bool,
}

impl AuditEmitter {
    pub fn new(audit_worker_url: impl Into<String>, require: bool) -> Self {
        Self {
            client: AuditClient::new(audit_worker_url),
            require,
        }
    }

    /// Build from env: `AGENTKEYS_AUDIT_WORKER_URL` (default co-located
    /// `http://127.0.0.1:9092`) + `AGENTKEYS_WORKER_REQUIRE_AUDIT` (default
    /// off — best-effort emit during the staged rollout).
    pub fn from_env() -> Self {
        let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
            .unwrap_or_else(|_| DEFAULT_AUDIT_WORKER_URL.to_string());
        let require = std::env::var("AGENTKEYS_WORKER_REQUIRE_AUDIT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if require {
            eprintln!(
                "==> audit: AGENTKEYS_WORKER_REQUIRE_AUDIT=1 — data-plane ops fail closed \
                 unless the durable audit append at {url} succeeds"
            );
        }
        Self::new(url, require)
    }

    /// Whether emit failures fail the op (`AGENTKEYS_WORKER_REQUIRE_AUDIT=1`).
    pub fn requires_audit(&self) -> bool {
        self.require
    }

    /// Emit one durable audit envelope for a cap-verified data-plane op.
    ///
    /// Returns the `envelope_hash` receipt (the exact 32-byte commitment
    /// `CredentialAudit.appendV2` anchors on-chain) on success. On emit
    /// failure: `Err(502 audit_append_failed)` in require mode, `Ok(None)`
    /// (+ loud warn carrying the full event coordinates) otherwise.
    pub async fn emit(
        &self,
        cap: &CapToken,
        op_kind: AuditOpKind,
        op_body: impl Serialize,
        result: AuditResult,
    ) -> Result<Option<String>, ApiError> {
        let envelope = match build_envelope(cap, op_kind, op_body, result) {
            Ok(env) => env,
            Err(reason) => return self.emit_failed(cap, op_kind, result, reason),
        };
        match self.client.append(&envelope).await {
            Ok(resp) => Ok(Some(resp.envelope_hash)),
            Err(e) => self.emit_failed(cap, op_kind, result, e.to_string()),
        }
    }

    fn emit_failed(
        &self,
        cap: &CapToken,
        op_kind: AuditOpKind,
        result: AuditResult,
        reason: String,
    ) -> Result<Option<String>, ApiError> {
        if self.require {
            return Err(err_502(
                format!(
                    "durable audit append failed for {} (AGENTKEYS_WORKER_REQUIRE_AUDIT=1): {reason}",
                    op_kind.label()
                ),
                "audit_append_failed",
            ));
        }
        tracing::warn!(
            op_kind = op_kind.label(),
            result = result as u8,
            operator_omni = %cap.payload.operator_omni,
            actor_omni = %cap.payload.actor_omni,
            service = %cap.payload.service,
            error = %reason,
            "durable audit append FAILED (best-effort mode) — event NOT in the audit feed"
        );
        Ok(None)
    }
}

fn build_envelope(
    cap: &CapToken,
    op_kind: AuditOpKind,
    op_body: impl Serialize,
    result: AuditResult,
) -> Result<agentkeys_core::audit::AuditEnvelope, String> {
    let actor =
        decode_omni_32(&cap.payload.actor_omni).map_err(|e| format!("actor_omni decode: {e}"))?;
    let operator = decode_omni_32(&cap.payload.operator_omni)
        .map_err(|e| format!("operator_omni decode: {e}"))?;
    envelope_for(actor, operator, op_kind, op_body, result, None, None).map_err(|e| e.to_string())
}

/// `keccak256(canonical cap payload JSON)` — the same canonical bytes the
/// broker signed over (`verify::verify_signature`), so the audit row binds
/// to exactly the cap the worker verified. Per the arch.md §15.3a body
/// schemas (`cap_hash`).
pub fn cap_hash(cap: &CapToken) -> String {
    let canonical = serde_json::to_vec(&cap.payload).unwrap_or_default();
    keccak_hex(&canonical)
}

/// `0x`-prefixed keccak256 — used for `payload_hash` (ciphertext) +
/// [`cap_hash`].
pub fn keccak_hex(bytes: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(bytes);
    format!("0x{}", hex::encode(h.finalize()))
}

/// All-zero placeholder hash for failure-path audits where the artifact
/// (e.g. ciphertext that never got written) doesn't exist.
pub fn zero_hash() -> String {
    format!("0x{}", "00".repeat(32))
}

fn decode_omni_32(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{CapOp, CapPayload, DataClass};

    fn sample_cap() -> CapToken {
        CapToken {
            payload: CapPayload {
                operator_omni: format!("0x{}", "aa".repeat(32)),
                actor_omni: format!("0x{}", "bb".repeat(32)),
                service: "openrouter".into(),
                op: CapOp::Fetch,
                data_class: DataClass::Credentials,
                device_key_hash: format!("0x{}", "cc".repeat(32)),
                k3_epoch: 1,
                issued_at: 1_700_000_000,
                expires_at: 1_700_000_600,
                nonce: "n-1".into(),
            },
            broker_sig: "sig".into(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    #[test]
    fn cap_hash_is_deterministic_and_binds_payload() {
        let cap = sample_cap();
        let h1 = cap_hash(&cap);
        assert_eq!(h1, cap_hash(&cap));
        assert!(h1.starts_with("0x") && h1.len() == 66);
        let mut other = sample_cap();
        other.payload.service = "stripe".into();
        assert_ne!(h1, cap_hash(&other), "different payload, different hash");
        // broker_sig is NOT part of the binding — the hash covers the
        // canonical payload bytes the broker signed.
        let mut resigned = sample_cap();
        resigned.broker_sig = "other-sig".into();
        assert_eq!(h1, cap_hash(&resigned));
    }

    #[test]
    fn build_envelope_maps_cap_omnis_and_op_kind() {
        use agentkeys_core::audit::CredFetchBody;
        let cap = sample_cap();
        let env = build_envelope(
            &cap,
            AuditOpKind::CredFetch,
            CredFetchBody {
                service: cap.payload.service.clone(),
                cap_hash: cap_hash(&cap),
            },
            AuditResult::Success,
        )
        .unwrap();
        assert_eq!(env.actor_omni, [0xbb; 32]);
        assert_eq!(env.operator_omni, [0xaa; 32]);
        assert_eq!(env.op_kind, AuditOpKind::CredFetch as u8);
        assert_eq!(env.result, AuditResult::Success);
    }

    /// Acceptance guard (#229): the audited body for a fetch carries ONLY
    /// the service + cap hash — no plaintext-bearing field can sneak in.
    #[test]
    fn fetch_audit_body_has_no_plaintext_fields() {
        use agentkeys_core::audit::CredFetchBody;
        let cap = sample_cap();
        let body = CredFetchBody {
            service: cap.payload.service.clone(),
            cap_hash: cap_hash(&cap),
        };
        let json = serde_json::to_value(&body).unwrap();
        // serde_json::Map iterates keys alphabetically.
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["cap_hash", "service"]);
    }

    #[test]
    fn bad_omni_in_cap_is_an_emit_failure_not_a_panic() {
        let mut cap = sample_cap();
        cap.payload.actor_omni = "0x1234".into(); // not 32 bytes
        let err = build_envelope(
            &cap,
            AuditOpKind::CredFetch,
            serde_json::json!({}),
            AuditResult::Success,
        )
        .unwrap_err();
        assert!(err.contains("actor_omni"));
    }
}
