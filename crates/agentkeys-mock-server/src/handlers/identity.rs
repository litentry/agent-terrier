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

pub fn resolve_identity_to_wallet(
    db: &rusqlite::Connection,
    identity_type: &str,
    identity_value: &str,
) -> Option<String> {
    match identity_type {
        "WalletAddress" | "wallet_address" => Some(identity_value.to_string()),
        _ => db
            .query_row(
                "SELECT wallet_address FROM identity_links WHERE identity_type = ?1 AND identity_value = ?2",
                params![identity_type, identity_value],
                |row| row.get(0),
            )
            .ok(),
    }
}

/// Shared typed identity → wallet resolver (Issue #13, CLAUDE.md Backend Design Principles).
/// Called from `approve_auth_request` Recover branch and `recover_session` handler.
///
/// `identity_type` must be one of `"alias"`, `"email"`, `"ens"`, `"wallet"`.
/// - `"alias"`, `"email"`, `"ens"` query `identity_links` for the matching row.
/// - `"wallet"` validates hex format AND confirms the wallet exists in `accounts`
///   before returning it (prevents 500 on later FK constraint in `sessions`).
pub fn resolve_identity_typed(
    db: &rusqlite::Connection,
    identity_type: &str,
    identity_value: &str,
) -> Result<String, crate::error::AppError> {
    match identity_type {
        "alias" | "email" | "ens" => db
            .query_row(
                "SELECT wallet_address FROM identity_links WHERE identity_type = ?1 AND identity_value = ?2",
                params![identity_type, identity_value],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| {
                crate::error::AppError::not_found(format!(
                    "no identity found for type={} value={}",
                    identity_type, identity_value
                ))
            }),
        "wallet" => {
            if !identity_value.starts_with("0x")
                || !identity_value[2..].chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(crate::error::AppError::bad_request(format!(
                    "invalid wallet address format: {}",
                    identity_value
                )));
            }
            // Wallet existence check: unknown wallets must return 404 here instead
            // of triggering a later FK constraint on INSERT INTO sessions (which
            // would surface as 500). Codex P2 on PR #21.
            let exists: bool = db
                .query_row(
                    "SELECT 1 FROM accounts WHERE wallet_address = ?1",
                    params![identity_value],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if !exists {
                return Err(crate::error::AppError::not_found(format!(
                    "no account found for wallet {}",
                    identity_value
                )));
            }
            Ok(identity_value.to_string())
        }
        other => Err(crate::error::AppError::bad_request(format!(
            "unknown identity_type '{}'. Use 'alias', 'email', 'ens', or 'wallet'.",
            other
        ))),
    }
}

pub async fn resolve_identity(
    State(state): State<SharedState>,
    Query(query): Query<ResolveIdentityQuery>,
) -> AppResult<Json<Value>> {
    let db = state.db.lock().unwrap();

    let wallet = resolve_identity_typed(&db, &query.identity_type, &query.identity_value)?;

    Ok(Json(json!({ "wallet_address": wallet })))
}
