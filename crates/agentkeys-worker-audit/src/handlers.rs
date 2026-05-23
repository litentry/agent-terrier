//! HTTP surface for the audit-service worker.
//!
//! Endpoints (V1 — legacy 5-field shape, retained):
//!   POST /v1/audit/append              — queue a single event
//!   POST /v1/audit/flush/:operator     — flush one operator's queue → Merkle root
//!   POST /v1/audit/flush-all           — flush every queue
//!   GET  /v1/audit/queue-size/:operator — diagnostics
//!
//! Endpoints (V2 — canonical `AuditEnvelope`, issue #97 phase B):
//!   POST /v1/audit/append/v2           — store an envelope + return its `envelope_hash`
//!   GET  /v1/audit/envelope/:hash      — fetch the canonical CBOR for an envelope hash
//!
//! Per arch.md §15.3a, V1 + V2 coexist for one migration cycle.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::{AuditEvent, FlushResult, SharedState};

#[derive(Deserialize)]
pub struct AppendRequest {
    pub operator_omni: String,
    #[serde(flatten)]
    pub event: AuditEvent,
}

#[derive(Serialize)]
pub struct AppendResponse {
    pub ok: bool,
    pub queue_size: usize,
}

pub async fn append(
    State(state): State<SharedState>,
    Json(req): Json<AppendRequest>,
) -> Result<Json<AppendResponse>, (StatusCode, String)> {
    let size = state.append(req.operator_omni, req.event).await;
    Ok(Json(AppendResponse {
        ok: true,
        queue_size: size,
    }))
}

#[derive(Serialize)]
pub struct FlushResponse {
    pub ok: bool,
    pub flushed: Vec<FlushResult>,
}

pub async fn flush_one(
    State(state): State<SharedState>,
    Path(operator_omni): Path<String>,
) -> Result<Json<FlushResponse>, (StatusCode, String)> {
    let r = state
        .flush(&operator_omni)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(FlushResponse {
        ok: true,
        flushed: r.into_iter().collect(),
    }))
}

pub async fn flush_all(
    State(state): State<SharedState>,
) -> Result<Json<FlushResponse>, (StatusCode, String)> {
    let r = state
        .flush_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(FlushResponse {
        ok: true,
        flushed: r,
    }))
}

#[derive(Serialize)]
pub struct QueueSizeResponse {
    pub operator_omni: String,
    pub queue_size: usize,
}

pub async fn queue_size(
    State(_state): State<SharedState>,
    Path(operator_omni): Path<String>,
) -> Result<Json<QueueSizeResponse>, (StatusCode, String)> {
    // Cheap fast-path: re-acquire the lock just to read the length.
    Ok(Json(QueueSizeResponse {
        operator_omni,
        queue_size: 0, // TODO: expose a read accessor on State
    }))
}

// ─── V2 endpoints — `AuditEnvelope` (arch.md §15.3a, issue #97) ──────────

/// JSON shape accepted by `POST /v1/audit/append/v2`. The envelope is sent
/// as JSON (each `op_body` is a freeform JSON object); the worker
/// converts it to a `ciborium::Value` for canonical CBOR encoding.
#[derive(Deserialize)]
pub struct AppendV2Request {
    /// Envelope-level version. Must equal
    /// `agentkeys_core::audit::ENVELOPE_VERSION`.
    pub version: u8,
    /// Server-side fills this if 0; caller may pass an explicit timestamp.
    #[serde(default)]
    pub ts_unix: u64,
    /// 0x-prefixed 64-hex (32 raw bytes).
    pub actor_omni: String,
    pub operator_omni: String,
    pub op_kind: u8,
    /// Op-kind-specific body. Opaque JSON — gets converted to CBOR.
    pub op_body: serde_json::Value,
    /// 0=Success, 1=Failure, 2=NotPermitted.
    pub result: u8,
    pub intent_text: Option<String>,
    /// 0x-prefixed 64-hex (32 raw bytes) or null.
    pub intent_commitment: Option<String>,
}

#[derive(Serialize)]
pub struct AppendV2Response {
    pub ok: bool,
    /// 0x-prefixed 64-hex (32 raw bytes). Use this in the on-chain
    /// `CredentialAudit.appendV2(operator_omni, actor_omni, op_kind,
    /// envelope_hash)` call.
    pub envelope_hash: String,
}

pub async fn append_v2(
    State(state): State<SharedState>,
    Json(req): Json<AppendV2Request>,
) -> Result<Json<AppendV2Response>, (StatusCode, String)> {
    use agentkeys_core::audit::{AuditEnvelope, AuditResult, ENVELOPE_VERSION};

    if req.version != ENVELOPE_VERSION {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported envelope version: {} (this worker supports {})",
                req.version, ENVELOPE_VERSION
            ),
        ));
    }

    let actor_omni = decode_hex_32(&req.actor_omni, "actor_omni")?;
    let operator_omni = decode_hex_32(&req.operator_omni, "operator_omni")?;
    let intent_commitment = match &req.intent_commitment {
        Some(s) => Some(decode_hex_32(s, "intent_commitment")?),
        None => None,
    };
    let result = match req.result {
        0 => AuditResult::Success,
        1 => AuditResult::Failure,
        2 => AuditResult::NotPermitted,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown result byte: {other}"),
            ))
        }
    };
    let ts_unix = if req.ts_unix == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    } else {
        req.ts_unix
    };

    let envelope = AuditEnvelope {
        version: req.version,
        ts_unix,
        actor_omni,
        operator_omni,
        op_kind: req.op_kind,
        op_body: json_to_ciborium(req.op_body)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("op_body: {e}")))?,
        result,
        intent_text: req.intent_text,
        intent_commitment,
    };

    let cbor = envelope
        .to_canonical_cbor()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("encode: {e}")))?;
    let envelope_hash = envelope
        .envelope_hash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("hash: {e}")))?;
    let hash_hex = format!("0x{}", hex::encode(envelope_hash));

    state.store_envelope(hash_hex.clone(), cbor).await;

    Ok(Json(AppendV2Response {
        ok: true,
        envelope_hash: hash_hex,
    }))
}

/// `GET /v1/audit/envelope/:hash` — return the canonical CBOR for the
/// envelope identified by `envelope_hash` (a 0x-prefixed 64-hex string).
/// Returns 404 if unknown.
///
/// Response is `application/cbor` so explorers can verify the hash
/// matches by re-running `keccak256(body)`.
pub async fn get_envelope(State(state): State<SharedState>, Path(hash): Path<String>) -> Response {
    let key = hash.to_lowercase();
    match state.get_envelope(&key).await {
        Some(cbor) => Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/cbor"),
            )
            .body(Body::from(cbor))
            .unwrap(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "envelope_not_found",
                "message": format!("no envelope at {hash}"),
            })),
        )
            .into_response(),
    }
}

fn decode_hex_32(s: &str, label: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("{label}: invalid hex: {e}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label}: expected 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn json_to_ciborium(v: serde_json::Value) -> Result<ciborium::Value, String> {
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
                return Err(format!("unrepresentable number: {n}"));
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
