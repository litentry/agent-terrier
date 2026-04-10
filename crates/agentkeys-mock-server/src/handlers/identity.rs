use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::{extract_bearer_token, now_secs, validate_session},
    error::{AppError, AppResult},
    state::SharedState,
};

pub async fn link_identity(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let session = validate_session(&state, token)?;

    let identity_type = body
        .get("identity_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("identity_type required"))?;
    let identity_value = body
        .get("identity_value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("identity_value required"))?;
    let wallet_address = body
        .get("wallet_address")
        .and_then(|v| v.as_str())
        .unwrap_or(&session.wallet_address);

    let now = now_secs();
    let db = state.db.lock().unwrap();

    db.execute(
        "INSERT OR REPLACE INTO identity_links (wallet_address, identity_type, identity_value, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![wallet_address, identity_type, identity_value, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResolveIdentityQuery {
    pub identity_type: String,
    pub identity_value: String,
}

pub async fn resolve_identity(
    State(state): State<SharedState>,
    Query(query): Query<ResolveIdentityQuery>,
) -> AppResult<Json<Value>> {
    let db = state.db.lock().unwrap();

    let wallet: String = db
        .query_row(
            "SELECT wallet_address FROM identity_links WHERE identity_type = ?1 AND identity_value = ?2",
            params![query.identity_type, query.identity_value],
            |row| row.get(0),
        )
        .map_err(|_| AppError::not_found(format!(
            "no identity found for type={} value={}",
            query.identity_type, query.identity_value
        )))?;

    Ok(Json(json!({ "wallet_address": wallet })))
}
