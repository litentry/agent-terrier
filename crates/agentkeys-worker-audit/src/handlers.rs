//! HTTP surface for the audit-service worker.
//!
//! Endpoints:
//!   POST /v1/audit/append              — queue a single event
//!   POST /v1/audit/flush/:operator     — flush one operator's queue → Merkle root
//!   POST /v1/audit/flush-all           — flush every queue
//!   GET  /v1/audit/queue-size/:operator — diagnostics

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

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
    Ok(Json(AppendResponse { ok: true, queue_size: size }))
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
    Ok(Json(FlushResponse { ok: true, flushed: r }))
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
