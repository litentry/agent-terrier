use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::{extract_bearer_token, validate_session},
    error::{AppError, AppResult},
    state::SharedState,
};

#[derive(Deserialize)]
pub struct AuditQuery {
    pub owner: Option<String>,
    pub agent: Option<String>,
    pub service: Option<String>,
}

pub async fn query_audit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let session = validate_session(&state, token)?;

    let db = state.db.lock().unwrap();

    // Restrict results to events where the session has access.
    // A session may see events where:
    //   1. owner_wallet == session.wallet (they are the owner), OR
    //   2. owner_wallet is a direct child of session.wallet (they own the child), OR
    //   3. agent_wallet == session.wallet (they are the agent in the event).
    // Use ? placeholders sequentially.
    let mut sql = String::from(
        "SELECT owner_wallet, agent_wallet, service_name, action, result, timestamp FROM audit_log
         WHERE (owner_wallet = ?
                OR owner_wallet IN (
                    SELECT wallet_address FROM sessions
                    WHERE parent_token IN (SELECT token FROM sessions WHERE wallet_address = ?)
                )
                OR agent_wallet = ?)",
    );
    // Bind slots: session wallet (owner check), session wallet (child check), session wallet (agent check)
    let mut bind_values: Vec<String> = vec![
        session.wallet_address.clone(),
        session.wallet_address.clone(),
        session.wallet_address.clone(),
    ];

    if let Some(owner) = &query.owner {
        sql.push_str(" AND owner_wallet = ?");
        bind_values.push(owner.clone());
    }
    if let Some(agent) = &query.agent {
        sql.push_str(" AND agent_wallet = ?");
        bind_values.push(agent.clone());
    }
    if let Some(service) = &query.service {
        sql.push_str(" AND service_name = ?");
        bind_values.push(service.clone());
    }

    sql.push_str(" ORDER BY timestamp DESC");

    let mut stmt = db.prepare(&sql).map_err(|e| AppError::internal(e.to_string()))?;

    let events: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(bind_values.iter()), |row| {
            Ok(json!({
                "owner": row.get::<_, String>(0)?,
                "agent": row.get::<_, String>(1)?,
                "service": row.get::<_, String>(2)?,
                "action": row.get::<_, String>(3)?,
                "result": row.get::<_, String>(4)?,
                "timestamp": row.get::<_, u64>(5)?,
            }))
        })
        .map_err(|e| AppError::internal(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({ "events": events })))
}

pub async fn shielding_key(
    State(state): State<SharedState>,
) -> AppResult<Json<Value>> {
    let pub_key_bytes = state.shielding_public_key.to_bytes().to_vec();
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pub_key_bytes);
    Ok(Json(json!({ "public_key": encoded })))
}
