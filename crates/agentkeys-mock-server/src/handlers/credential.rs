use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    auth::{extract_bearer_token, now_secs, validate_session},
    error::{AppError, AppResult},
    state::SharedState,
};
use agentkeys_types::Scope;

#[derive(Deserialize)]
pub struct StoreCredentialRequest {
    pub agent_id: String,
    pub service: String,
    pub ciphertext: String, // base64-encoded
}

pub async fn store_credential(
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

    let agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("agent_id required"))?;
    let service = body
        .get("service")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("service required"))?;
    let ciphertext_b64 = body
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("ciphertext required"))?;

    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ciphertext_b64,
    )
    .map_err(|e| AppError::bad_request(format!("invalid base64: {e}")))?;

    let now = now_secs();
    let db = state.db.lock().unwrap();

    // Store credential owned by the agent wallet (session wallet is the owner/parent)
    db.execute(
        "INSERT INTO credentials (wallet_address, service_name, ciphertext, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(wallet_address, service_name) DO UPDATE SET ciphertext=excluded.ciphertext, updated_at=excluded.updated_at",
        params![agent_id, service, ciphertext, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    // Audit log
    db.execute(
        "INSERT INTO audit_log (owner_wallet, agent_wallet, service_name, action, result, timestamp)
         VALUES (?1, ?2, ?3, 'store', 'ok', ?4)",
        params![session.wallet_address, agent_id, service, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ReadCredentialQuery {
    pub agent_id: String,
    pub service: String,
}

pub async fn read_credential(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ReadCredentialQuery>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let session = validate_session(&state, token)?;

    let agent_id = &query.agent_id;
    let service = &query.service;

    // Scope enforcement: if session has a scope, agent can only read its own service
    if let Some(scope_json) = &session.scope_json {
        let scope: Scope = serde_json::from_str(scope_json)
            .map_err(|e| AppError::internal(e.to_string()))?;

        // The session wallet must match the agent_id
        if session.wallet_address != *agent_id {
            let now = now_secs();
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO audit_log (owner_wallet, agent_wallet, service_name, action, result, timestamp)
                 VALUES (?1, ?2, ?3, 'read', 'DENIED', ?4)",
                params![session.wallet_address, agent_id, service, now],
            )
            .ok();
            return Err(AppError::forbidden(format!(
                "Agent {} is not authorized to read {}",
                session.wallet_address, service
            )));
        }

        // Check service is in scope
        let service_name = agentkeys_types::ServiceName(service.clone());
        if !scope.services.contains(&service_name) {
            let now = now_secs();
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO audit_log (owner_wallet, agent_wallet, service_name, action, result, timestamp)
                 VALUES (?1, ?2, ?3, 'read', 'DENIED_SCOPE', ?4)",
                params![session.wallet_address, agent_id, service, now],
            )
            .ok();
            return Err(AppError::forbidden(format!(
                "Agent {} does not have scope for service {}",
                session.wallet_address, service
            )));
        }
    }

    let db = state.db.lock().unwrap();
    let result = db.query_row(
        "SELECT ciphertext FROM credentials WHERE wallet_address = ?1 AND service_name = ?2",
        params![agent_id, service],
        |row| row.get::<_, Vec<u8>>(0),
    );

    match result {
        Err(_) => {
            let now = now_secs();
            db.execute(
                "INSERT INTO audit_log (owner_wallet, agent_wallet, service_name, action, result, timestamp)
                 VALUES (?1, ?2, ?3, 'read', 'NOT_FOUND', ?4)",
                params![session.wallet_address, agent_id, service, now],
            )
            .ok();
            Err(AppError::not_found(format!("credential not found for agent={agent_id} service={service}")))
        }
        Ok(ciphertext) => {
            let now = now_secs();
            db.execute(
                "INSERT INTO audit_log (owner_wallet, agent_wallet, service_name, action, result, timestamp)
                 VALUES (?1, ?2, ?3, 'read', 'ok', ?4)",
                params![session.wallet_address, agent_id, service, now],
            )
            .ok();
            let encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext,
            );
            Ok(Json(json!({ "ciphertext": encoded })))
        }
    }
}

pub async fn teardown_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let _session = validate_session(&state, token)?;

    let agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("agent_id required"))?;

    let db = state.db.lock().unwrap();

    // Revoke all sessions for this agent
    db.execute("UPDATE sessions SET revoked = 1 WHERE wallet_address = ?1", params![agent_id])
        .map_err(|e| AppError::internal(e.to_string()))?;

    // Delete all credentials for this agent
    db.execute("DELETE FROM credentials WHERE wallet_address = ?1", params![agent_id])
        .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}
