//! `AuditEnvelope v1` — unified audit message format (arch.md §15.3a, issue #97).
//!
//! Every audit-producing surface in AgentKeys (creds, memory, signer,
//! broker, payment-service, email-service, SidecarRegistry, K3EpochCounter)
//! emits a single canonical envelope shape so that:
//!
//! - The chain commits only `(opKind, envelopeHash)` — small, op-kind-agnostic,
//!   no contract redeploy when a new op_kind lands.
//! - The off-chain worker (`agentkeys-worker-audit`) holds the full envelope,
//!   addressed by hash.
//! - The explorer ([`litentry/subscan-essentials`](https://github.com/litentry/subscan-essentials/issues/12))
//!   reads the chain events, fetches envelopes by hash, and renders a uniform
//!   timeline across all op_kinds.
//!
//! ## Non-break design
//!
//! Adding a new op_kind costs "uglier UI temporarily for old explorers" —
//! never "broken explorer / dropped event." Eight invariants enforced by
//! this module:
//!
//! 1. `op_kind` is a `u8`, NOT a sealed Rust enum. Decoders see an
//!    `Unknown(byte)` variant for any byte not in the canonical table.
//! 2. Envelope-level fields are stable across all op_kinds. The
//!    `AuditEnvelope` struct decodes `(version, ts_unix, actor_omni,
//!    operator_omni, op_kind, intent_text, intent_commitment, result)`
//!    for any op_kind — even one this code doesn't recognize.
//! 3. `version` is gated on envelope-level breakage only. Bumping
//!    `version` is a coordinated migration; adding a new op_kind is not.
//! 4. The `op_body` is a `ciborium::Value`. Unknown body shapes are
//!    preserved as opaque CBOR through encode/decode — caller decides
//!    whether to attempt a typed decode.
//! 5. `canonical_cbor` is deterministic (RFC 8949 §4.2.1) so
//!    `envelope_hash` is stable across encoders.
//! 6. The chain contract is op-kind-agnostic.
//! 7. The canonical op_kind table lives in arch.md §15.3a — this module's
//!    constants must match. Reviewer greps both before merging a new
//!    op_kind PR.
//! 8. Every new op_kind ships 3 tests: CBOR roundtrip + unknown-body
//!    tolerance + arch.md row.
//!
//! See [`docs/arch.md`](../../../../docs/arch.md)
//! §15.3a for the canonical schema.

pub mod bodies;
pub mod calldata;
pub mod cbor;
pub mod client;
pub mod op_kind;

pub use client::{envelope_for, AppendV2Response, AuditClient};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub use bodies::{
    CredFetchBody, CredStoreBody, CredTeardownBody, DeviceAddBody, DeviceRevokeBody,
    EmailReceiveBody, EmailSendBody, K10RotateBody, K3EpochAdvanceBody, MemoryGetBody,
    MemoryPutBody, MemoryTeardownBody, PaymentDirectBody, PaymentEscrowRedeemBody, ScopeGrantBody,
    ScopeRevokeBody, SignEip191Body, SignEip712Body,
};
pub use op_kind::AuditOpKind;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("invalid_envelope: {0}")]
    Invalid(String),

    #[error("cbor: {0}")]
    Cbor(String),

    #[error("hex_decode: {0}")]
    HexDecode(String),
}

/// Envelope version. Bump ONLY when envelope-level fields change (adding,
/// removing, or changing the type of a top-level field). Adding a new
/// op_kind variant does NOT bump this — that's the whole point of the
/// open-enum design.
pub const ENVELOPE_VERSION: u8 = 1;

/// Result of the audited operation. Open enum byte: future variants append
/// at the bottom; never reuse, never reorder. Per arch.md §15.3a.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    Success = 0,
    Failure = 1,
    NotPermitted = 2,
}

/// The canonical audit envelope. Every audit-producing surface emits one
/// of these. Encoding for chain commitment + worker storage is canonical
/// CBOR per RFC 8949 §4.2.1.
///
/// ## Fields
///
/// - `version`: `ENVELOPE_VERSION`. Decoders MUST refuse to process an
///   envelope with `version > known_max_version` and log "needs upgrade."
/// - `ts_unix`: server-side at queue time (the worker fills this if the
///   caller leaves it 0).
/// - `actor_omni`: who performed the operation. 32 raw bytes.
/// - `operator_omni`: whose data-class boundary the op touched. 32 bytes.
/// - `op_kind`: byte assignment per arch.md §15.3a canonical table.
/// - `op_body`: op-kind-specific. Opaque CBOR — readers that don't know
///   the op_kind keep it as a `ciborium::Value` and pass through.
/// - `result`: outcome of the operation.
/// - `intent_text`: optional operator-readable text. Set by PR #95 for
///   typed-data signs; arbitrary op_kinds may set this if there's a
///   meaningful human-readable intent.
/// - `intent_commitment`: optional `keccak256(intent_text || 0x7c ||
///   op_payload_digest)`. Cryptographically binds the rendered intent
///   to the op payload. Auditors verifying the commitment re-render the
///   intent from the same source (e.g. an ERC-7730 file for sign ops)
///   and check the hash matches.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEnvelope {
    pub version: u8,
    pub ts_unix: u64,
    pub actor_omni: [u8; 32],
    pub operator_omni: [u8; 32],
    pub op_kind: u8,
    pub op_body: ciborium::Value,
    pub result: AuditResult,
    pub intent_text: Option<String>,
    pub intent_commitment: Option<[u8; 32]>,
}

impl AuditEnvelope {
    /// Encode the envelope as canonical CBOR (RFC 8949 §4.2.1). Suitable
    /// for hashing — the resulting bytes are stable across encoder
    /// implementations.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, AuditError> {
        cbor::encode_canonical(self)
    }

    /// Decode an envelope from canonical CBOR. Unknown op_kinds keep
    /// `op_body` as a `ciborium::Value` for the caller to inspect.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, AuditError> {
        cbor::decode_canonical(bytes)
    }

    /// `envelope_hash = keccak256(canonical_cbor(envelope))`. This is the
    /// 32-byte commitment that lands on chain as the second arg to
    /// `CredentialAudit.appendV2(...)`.
    pub fn envelope_hash(&self) -> Result<[u8; 32], AuditError> {
        let bytes = self.to_canonical_cbor()?;
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    /// Try to decode `op_body` as the typed shape associated with this
    /// envelope's `op_kind`. Returns `None` if `op_kind` is unknown to
    /// this build of the code — the caller renders a generic row in that
    /// case (per non-break invariant #4).
    pub fn typed_body(&self) -> Option<TypedAuditBody> {
        TypedAuditBody::from_envelope(self)
    }

    /// Render the envelope as operator-facing JSON for the audit UI (#153):
    /// the envelope hash + every envelope-level field (omni / commitment bytes
    /// as `0x` hex), the `op_kind` byte plus its canonical label (`null` for an
    /// unknown future byte — the non-break path), and `op_body` as JSON. The
    /// op_body CBOR map already carries the typed field names (it was encoded
    /// from the per-op body struct), so the raw CBOR→JSON conversion yields the
    /// typed shape for known op_kinds and the opaque map for unknown ones.
    /// Never fails — an unknown op_kind still renders every envelope-level field.
    pub fn to_json(&self) -> serde_json::Value {
        let op_label = AuditOpKind::from_u8(self.op_kind).map(|k| k.label());
        let body = ciborium_to_json(&self.op_body).unwrap_or(serde_json::Value::Null);
        let hash = self
            .envelope_hash()
            .map(|h| format!("0x{}", hex::encode(h)))
            .unwrap_or_default();
        serde_json::json!({
            "envelope_hash": hash,
            "version": self.version,
            "ts_unix": self.ts_unix,
            "actor_omni": format!("0x{}", hex::encode(self.actor_omni)),
            "operator_omni": format!("0x{}", hex::encode(self.operator_omni)),
            "op_kind": self.op_kind,
            "op_kind_label": op_label,
            "op_body": body,
            "result": self.result as u8,
            "intent_text": self.intent_text,
            "intent_commitment": self
                .intent_commitment
                .map(|c| format!("0x{}", hex::encode(c))),
        })
    }
}

/// Decode canonical-CBOR envelope hex (`0x…` or bare) into operator-facing JSON
/// — the daemon `/v1/audit/:id/decode` CBOR half (#153). Thin wrapper over
/// [`AuditEnvelope::from_canonical_cbor`] + [`AuditEnvelope::to_json`].
pub fn decode_envelope_hex(cbor_hex: &str) -> Result<serde_json::Value, AuditError> {
    let trimmed = cbor_hex.trim().strip_prefix("0x").unwrap_or(cbor_hex);
    let bytes = hex::decode(trimmed).map_err(|e| AuditError::HexDecode(e.to_string()))?;
    Ok(AuditEnvelope::from_canonical_cbor(&bytes)?.to_json())
}

/// Helper: `keccak256(intent_text.as_bytes() || 0x7c || op_payload_digest)`.
/// The separator byte (`0x7c` = ASCII `|`) is a domain-separation token so
/// an adversary cannot construct an `intent_text` whose last byte fakes the
/// digest boundary. Mirrors [`clear_signing::commit_intent`].
pub fn commit_intent(intent_text: &str, op_payload_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(intent_text.as_bytes());
    hasher.update([0x7c]);
    hasher.update(op_payload_digest);
    hasher.finalize().into()
}

/// Typed view of `op_body` when this build of the code recognizes the
/// `op_kind`. Mirrors the canonical table in arch.md §15.3a.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedAuditBody {
    CredStore(CredStoreBody),
    CredFetch(CredFetchBody),
    CredTeardown(CredTeardownBody),
    MemoryPut(MemoryPutBody),
    MemoryGet(MemoryGetBody),
    MemoryTeardown(MemoryTeardownBody),
    SignEip191(SignEip191Body),
    SignEip712(SignEip712Body),
    PaymentEscrowRedeem(PaymentEscrowRedeemBody),
    PaymentDirect(PaymentDirectBody),
    ScopeGrant(ScopeGrantBody),
    ScopeRevoke(ScopeRevokeBody),
    DeviceAdd(DeviceAddBody),
    DeviceRevoke(DeviceRevokeBody),
    K10Rotate(K10RotateBody),
    EmailSend(EmailSendBody),
    EmailReceive(EmailReceiveBody),
    K3EpochAdvance(K3EpochAdvanceBody),
}

impl TypedAuditBody {
    fn from_envelope(env: &AuditEnvelope) -> Option<Self> {
        let kind = AuditOpKind::from_u8(env.op_kind)?;
        // Round-trip through serde_json to leverage ciborium → Value → struct
        // via the serde Deserialize impls on the body structs. Stable since
        // both sides use the same field names.
        let value = ciborium_to_json(&env.op_body).ok()?;
        Some(match kind {
            AuditOpKind::CredStore => Self::CredStore(serde_json::from_value(value).ok()?),
            AuditOpKind::CredFetch => Self::CredFetch(serde_json::from_value(value).ok()?),
            AuditOpKind::CredTeardown => Self::CredTeardown(serde_json::from_value(value).ok()?),
            AuditOpKind::MemoryPut => Self::MemoryPut(serde_json::from_value(value).ok()?),
            AuditOpKind::MemoryGet => Self::MemoryGet(serde_json::from_value(value).ok()?),
            AuditOpKind::MemoryTeardown => {
                Self::MemoryTeardown(serde_json::from_value(value).ok()?)
            }
            AuditOpKind::SignEip191 => Self::SignEip191(serde_json::from_value(value).ok()?),
            AuditOpKind::SignEip712 => Self::SignEip712(serde_json::from_value(value).ok()?),
            AuditOpKind::PaymentEscrowRedeem => {
                Self::PaymentEscrowRedeem(serde_json::from_value(value).ok()?)
            }
            AuditOpKind::PaymentDirect => Self::PaymentDirect(serde_json::from_value(value).ok()?),
            AuditOpKind::ScopeGrant => Self::ScopeGrant(serde_json::from_value(value).ok()?),
            AuditOpKind::ScopeRevoke => Self::ScopeRevoke(serde_json::from_value(value).ok()?),
            AuditOpKind::DeviceAdd => Self::DeviceAdd(serde_json::from_value(value).ok()?),
            AuditOpKind::DeviceRevoke => Self::DeviceRevoke(serde_json::from_value(value).ok()?),
            AuditOpKind::K10Rotate => Self::K10Rotate(serde_json::from_value(value).ok()?),
            AuditOpKind::EmailSend => Self::EmailSend(serde_json::from_value(value).ok()?),
            AuditOpKind::EmailReceive => Self::EmailReceive(serde_json::from_value(value).ok()?),
            AuditOpKind::K3EpochAdvance => {
                Self::K3EpochAdvance(serde_json::from_value(value).ok()?)
            }
        })
    }
}

/// Convert a `ciborium::Value` to a `serde_json::Value` so we can use the
/// existing `serde_json::from_value` deserializers on the body structs. The
/// alternative — `ciborium::Value::deserialized()` — only works for types
/// that derive `Deserialize` AND don't depend on `human_readable=true`. The
/// JSON detour keeps things portable.
fn ciborium_to_json(v: &ciborium::Value) -> Result<serde_json::Value, AuditError> {
    use ciborium::Value as CV;
    Ok(match v {
        CV::Null => serde_json::Value::Null,
        CV::Bool(b) => serde_json::Value::Bool(*b),
        CV::Integer(i) => {
            // ciborium::value::Integer can hold up to 128 bits; constrain to i64/u64.
            let as_i128: i128 = (*i).into();
            if as_i128 >= 0 && as_i128 <= u64::MAX as i128 {
                serde_json::Value::Number((as_i128 as u64).into())
            } else if as_i128 >= i64::MIN as i128 && as_i128 <= i64::MAX as i128 {
                serde_json::Value::Number((as_i128 as i64).into())
            } else {
                return Err(AuditError::Invalid(format!(
                    "integer out of i64 range: {as_i128}"
                )));
            }
        }
        CV::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        CV::Bytes(b) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
        CV::Text(s) => serde_json::Value::String(s.clone()),
        CV::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for x in arr {
                out.push(ciborium_to_json(x)?);
            }
            serde_json::Value::Array(out)
        }
        CV::Map(m) => {
            let mut out = serde_json::Map::with_capacity(m.len());
            for (k, val) in m {
                let key = match k {
                    CV::Text(s) => s.clone(),
                    other => format!("{other:?}"),
                };
                out.insert(key, ciborium_to_json(val)?);
            }
            serde_json::Value::Object(out)
        }
        CV::Tag(_, inner) => ciborium_to_json(inner)?,
        _ => {
            return Err(AuditError::Invalid(format!(
                "unsupported CBOR variant: {v:?}"
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_envelope() -> AuditEnvelope {
        use ciborium::Value;
        AuditEnvelope {
            version: ENVELOPE_VERSION,
            ts_unix: 1_700_000_000,
            actor_omni: [0xaa; 32],
            operator_omni: [0xbb; 32],
            op_kind: AuditOpKind::CredStore as u8,
            op_body: Value::Map(vec![
                (
                    Value::Text("service".into()),
                    Value::Text("openrouter".into()),
                ),
                (
                    Value::Text("payload_hash".into()),
                    Value::Text(format!("0x{}", "ab".repeat(32))),
                ),
            ]),
            result: AuditResult::Success,
            intent_text: Some("Store credential for openrouter".to_string()),
            intent_commitment: Some([0xcc; 32]),
        }
    }

    #[test]
    fn cbor_roundtrip_preserves_envelope() {
        let env = fixture_envelope();
        let cbor = env.to_canonical_cbor().unwrap();
        let decoded = AuditEnvelope::from_canonical_cbor(&cbor).unwrap();
        assert_eq!(env, decoded);
    }

    #[test]
    fn envelope_hash_is_deterministic() {
        let env = fixture_envelope();
        let h1 = env.envelope_hash().unwrap();
        let h2 = env.envelope_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn envelope_hash_changes_with_any_field() {
        let env = fixture_envelope();
        let baseline = env.envelope_hash().unwrap();
        let mut mutated = env.clone();
        mutated.ts_unix += 1;
        assert_ne!(mutated.envelope_hash().unwrap(), baseline);
    }

    #[test]
    fn unknown_op_kind_still_decodes_envelope_level_fields() {
        use ciborium::Value;
        // Encode an envelope with an op_kind byte that's NOT in the canonical
        // table (op_kind = 250). Decoding MUST succeed and preserve every
        // envelope-level field. typed_body() returns None.
        let mut env = fixture_envelope();
        env.op_kind = 250;
        env.op_body = Value::Map(vec![(
            Value::Text("future_field_only_v2_knows".into()),
            Value::Text("value".into()),
        )]);

        let cbor = env.to_canonical_cbor().unwrap();
        let decoded = AuditEnvelope::from_canonical_cbor(&cbor).unwrap();

        assert_eq!(decoded.op_kind, 250);
        assert_eq!(decoded.ts_unix, env.ts_unix);
        assert_eq!(decoded.actor_omni, env.actor_omni);
        assert_eq!(decoded.operator_omni, env.operator_omni);
        assert_eq!(decoded.intent_text, env.intent_text);
        assert_eq!(decoded.intent_commitment, env.intent_commitment);
        // Critical: typed_body returns None — caller renders Unknown(byte) row.
        assert!(decoded.typed_body().is_none());
    }

    #[test]
    fn version_2_decoder_refuses_unknown_envelope_version() {
        let mut env = fixture_envelope();
        env.version = 99;
        let cbor = env.to_canonical_cbor().unwrap();
        // Decoder returns Invalid("unsupported envelope version: 99")
        let err = AuditEnvelope::from_canonical_cbor(&cbor).unwrap_err();
        assert!(format!("{err}").contains("99"));
    }

    #[test]
    fn typed_body_decodes_cred_store() {
        let env = fixture_envelope();
        match env.typed_body() {
            Some(TypedAuditBody::CredStore(body)) => {
                assert_eq!(body.service, "openrouter");
            }
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    #[test]
    fn commit_intent_matches_clear_signing_commitment() {
        // Same scheme as clear_signing::commit_intent — same digest.
        let intent = "Approve 1 USDC to 0xaaaa…3333";
        let digest = [0xde; 32];
        let a = commit_intent(intent, &digest);
        let b = crate::clear_signing::commit_intent(intent, &digest);
        assert_eq!(a, b);
    }

    /// #153 acceptance bullet 4: the #137 cross-language CBOR vectors are the
    /// decode test fixtures. We build canonical envelopes via the same
    /// `envelope_for` path the #137 exporter
    /// (`examples/export_audit_vectors.rs`) uses, encode to canonical CBOR,
    /// then decode back through the real `decode_envelope_hex` daemon path and
    /// assert the operator-facing JSON. A known op_kind yields the typed body
    /// shape + label; an unknown future byte still decodes every
    /// envelope-level field with a null label (the non-break guarantee).
    #[test]
    fn decode_envelope_hex_round_trips_137_style_vectors() {
        use crate::audit::client::envelope_for;
        use crate::audit::{AuditOpKind, CredStoreBody};

        // ── known op_kind (CredStore=0), mirrors the exporter's first vector ──
        let mut env = envelope_for(
            [0x11; 32],
            [0x22; 32],
            AuditOpKind::CredStore,
            CredStoreBody {
                service: "openrouter".into(),
                payload_hash: format!("0x{}", hex::encode([0xab; 32])),
            },
            AuditResult::Success,
            Some("Store credential for openrouter".into()),
            Some([0xcc; 32]),
        )
        .unwrap();
        env.ts_unix = 1_700_000_000;

        let cbor_hex = format!("0x{}", hex::encode(env.to_canonical_cbor().unwrap()));
        let decoded = decode_envelope_hex(&cbor_hex).unwrap();

        assert_eq!(
            decoded["envelope_hash"],
            serde_json::json!(format!("0x{}", hex::encode(env.envelope_hash().unwrap())))
        );
        assert_eq!(decoded["op_kind"], serde_json::json!(0));
        assert_eq!(decoded["op_kind_label"], serde_json::json!("cred.store"));
        assert_eq!(
            decoded["op_body"]["service"],
            serde_json::json!("openrouter")
        );
        assert_eq!(
            decoded["actor_omni"],
            serde_json::json!(format!("0x{}", hex::encode([0x11; 32])))
        );
        assert_eq!(
            decoded["intent_text"],
            serde_json::json!("Store credential for openrouter")
        );
        assert_eq!(decoded["result"], serde_json::json!(0));

        // ── unknown op_kind (250) — the reserved-future canary vector ──
        let mut unknown = env.clone();
        unknown.op_kind = 250;
        unknown.op_body = ciborium::Value::Map(vec![(
            ciborium::Value::Text("future_field_only_v2_knows".into()),
            ciborium::Value::Text("opaque".into()),
        )]);
        let uhex = format!("0x{}", hex::encode(unknown.to_canonical_cbor().unwrap()));
        let udecoded = decode_envelope_hex(&uhex).unwrap();
        assert_eq!(udecoded["op_kind"], serde_json::json!(250));
        assert_eq!(udecoded["op_kind_label"], serde_json::Value::Null);
        assert_eq!(
            udecoded["op_body"]["future_field_only_v2_knows"],
            serde_json::json!("opaque")
        );
        // envelope-level fields still present despite the unknown op_kind.
        assert_eq!(
            udecoded["operator_omni"],
            serde_json::json!(format!("0x{}", hex::encode([0x22; 32])))
        );
    }
}
