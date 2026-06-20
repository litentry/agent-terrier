//! HTTP client for emitting `AuditEnvelope v1` to the audit-service worker
//! (`agentkeys-worker-audit`). Used by future emit sites in
//! credentials-service / memory-service / signer / broker / payment-service
//! / email-service / SidecarRegistry / K3EpochCounter.
//!
//! ## Why a client lives in core, not next to the worker
//!
//! Multiple emit sites in different crates need the same wire shape. Putting
//! the client in `agentkeys-core` makes the wire-level contract testable in
//! one place and shared by every emitter.
//!
//! ## Emit-and-forget semantics
//!
//! Audit emits are best-effort from the emitter's perspective — the chain
//! commitment is the durability mechanism, not the worker's in-memory map.
//! Emitters that need guaranteed delivery should either retry on transient
//! failure or fall back to direct on-chain `CredentialAudit.append`.

use serde::Deserialize;

use super::{AuditEnvelope, AuditError, AuditResult, ENVELOPE_VERSION};

/// Response from `POST /v1/audit/append/v2`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppendV2Response {
    pub ok: bool,
    pub envelope_hash: String,
}

/// Client for the audit-service worker's V2 surface.
pub struct AuditClient {
    base_url: String,
    http: reqwest::Client,
}

impl AuditClient {
    /// Construct with a worker base URL (no trailing slash). Defaults to
    /// `$AGENTKEYS_AUDIT_WORKER_URL` then `https://audit.example.invalid`
    /// — operators override per deployment.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub fn from_env() -> Self {
        let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
            .unwrap_or_else(|_| "https://audit.example.invalid".to_string());
        Self::new(url)
    }

    /// Emit a fully-constructed envelope. Returns the `envelope_hash` the
    /// worker computed (which the caller can verify locally via
    /// `envelope.envelope_hash()`).
    pub async fn append(&self, envelope: &AuditEnvelope) -> Result<AppendV2Response, AuditError> {
        let url = format!("{}/v1/audit/append/v2", self.base_url);
        let body = envelope_to_json(envelope)?;
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AuditError::Invalid(format!("POST {url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AuditError::Invalid(format!(
                "audit worker returned {status}: {text}"
            )));
        }
        resp.json::<AppendV2Response>()
            .await
            .map_err(|e| AuditError::Invalid(format!("parse append response: {e}")))
    }

    /// Fetch an envelope by its `envelope_hash` (0x-prefixed hex). Returns
    /// `None` if the worker doesn't have it (404).
    pub async fn get_envelope(&self, envelope_hash: &str) -> Result<Option<Vec<u8>>, AuditError> {
        let url = format!("{}/v1/audit/envelope/{}", self.base_url, envelope_hash);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AuditError::Invalid(format!("GET {url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AuditError::Invalid(format!(
                "audit worker returned {status}: {text}"
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AuditError::Invalid(format!("read body: {e}")))?;
        Ok(Some(bytes.to_vec()))
    }
}

/// Build the JSON shape `POST /v1/audit/append/v2` expects from an
/// `AuditEnvelope`. The wire shape mirrors the canonical CBOR but uses
/// 0x-hex strings for byte fields (matches the worker's `AppendV2Request`
/// deserializer).
fn envelope_to_json(env: &AuditEnvelope) -> Result<serde_json::Value, AuditError> {
    let op_body_json = ciborium_value_to_json(&env.op_body)?;
    let intent_commitment_hex = env
        .intent_commitment
        .map(|c| format!("0x{}", hex::encode(c)));
    Ok(serde_json::json!({
        "version": env.version,
        "ts_unix": env.ts_unix,
        "actor_omni":    format!("0x{}", hex::encode(env.actor_omni)),
        "operator_omni": format!("0x{}", hex::encode(env.operator_omni)),
        "op_kind": env.op_kind,
        "op_body": op_body_json,
        "result": env.result as u8,
        "intent_text": env.intent_text,
        "intent_commitment": intent_commitment_hex,
    }))
}

fn ciborium_value_to_json(v: &ciborium::Value) -> Result<serde_json::Value, AuditError> {
    use ciborium::Value as CV;
    Ok(match v {
        CV::Null => serde_json::Value::Null,
        CV::Bool(b) => serde_json::Value::Bool(*b),
        CV::Integer(i) => {
            let n: i128 = (*i).into();
            if n >= 0 && n <= u64::MAX as i128 {
                serde_json::Value::Number((n as u64).into())
            } else if n >= i64::MIN as i128 && n <= i64::MAX as i128 {
                serde_json::Value::Number((n as i64).into())
            } else {
                return Err(AuditError::Invalid(format!("integer {n} out of i64 range")));
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
                out.push(ciborium_value_to_json(x)?);
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
                out.insert(key, ciborium_value_to_json(val)?);
            }
            serde_json::Value::Object(out)
        }
        CV::Tag(_, inner) => ciborium_value_to_json(inner)?,
        _ => {
            return Err(AuditError::Invalid(format!(
                "unsupported CBOR variant for JSON conversion: {v:?}"
            )))
        }
    })
}

/// Convenience builder for the most common emit pattern: known op_kind,
/// typed body that serializes via `serde_json`.
pub fn envelope_for(
    actor_omni: [u8; 32],
    operator_omni: [u8; 32],
    op_kind: super::AuditOpKind,
    op_body: impl serde::Serialize,
    result: AuditResult,
    intent_text: Option<String>,
    intent_commitment: Option<[u8; 32]>,
) -> Result<AuditEnvelope, AuditError> {
    let body_json = serde_json::to_value(op_body)
        .map_err(|e| AuditError::Invalid(format!("serialize op_body: {e}")))?;
    let body_cbor = json_to_ciborium(body_json)?;
    Ok(AuditEnvelope {
        version: ENVELOPE_VERSION,
        ts_unix: 0, // worker fills if 0
        actor_omni,
        operator_omni,
        op_kind: op_kind as u8,
        op_body: body_cbor,
        result,
        intent_text,
        intent_commitment,
    })
}

fn json_to_ciborium(v: serde_json::Value) -> Result<ciborium::Value, AuditError> {
    use ciborium::Value as CV;
    Ok(match v {
        serde_json::Value::Null => CV::Null,
        serde_json::Value::Bool(b) => CV::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                CV::Integer(u.into())
            } else if let Some(i) = n.as_i64() {
                CV::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                CV::Float(f)
            } else {
                return Err(AuditError::Invalid(format!(
                    "number not representable: {n}"
                )));
            }
        }
        serde_json::Value::String(s) => CV::Text(s),
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for x in arr {
                out.push(json_to_ciborium(x)?);
            }
            CV::Array(out)
        }
        serde_json::Value::Object(o) => {
            let mut entries = Vec::with_capacity(o.len());
            for (k, v) in o {
                entries.push((CV::Text(k), json_to_ciborium(v)?));
            }
            CV::Map(entries)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditOpKind, SignEip712Body};

    #[test]
    fn envelope_for_builds_typed_body() {
        let body = SignEip712Body {
            chain_id: 1,
            verifying_contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
            primary_type: "Permit".into(),
            type_hash: format!("0x{}", "de".repeat(32)),
            domain_separator: format!("0x{}", "ad".repeat(32)),
            digest: format!("0x{}", "be".repeat(32)),
        };
        let env = envelope_for(
            [0xaa; 32],
            [0xbb; 32],
            AuditOpKind::SignEip712,
            body,
            AuditResult::Success,
            Some("Approve 1 USDC to 0xabc…123".into()),
            Some([0xcc; 32]),
        )
        .unwrap();
        assert_eq!(env.op_kind, AuditOpKind::SignEip712 as u8);
        // Confirm the body round-trips back as SignEip712Body.
        match env.typed_body().unwrap() {
            crate::audit::TypedAuditBody::SignEip712(b) => {
                assert_eq!(b.primary_type, "Permit");
                assert_eq!(b.chain_id, 1);
            }
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    #[test]
    fn envelope_for_emits_canonical_cbor() {
        // Same envelope produces same hash regardless of build path —
        // builder must not introduce non-canonical fields.
        let body = SignEip712Body {
            chain_id: 1,
            verifying_contract: "0xaaaa".into(),
            primary_type: "Permit".into(),
            type_hash: "0xdead".into(),
            domain_separator: "0xbeef".into(),
            digest: "0xcafe".into(),
        };
        let a = envelope_for(
            [0; 32],
            [0; 32],
            AuditOpKind::SignEip712,
            body.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let b = envelope_for(
            [0; 32],
            [0; 32],
            AuditOpKind::SignEip712,
            body,
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        // ts_unix=0 on both, so envelope_hash matches.
        assert_eq!(a.envelope_hash().unwrap(), b.envelope_hash().unwrap());
    }
}
