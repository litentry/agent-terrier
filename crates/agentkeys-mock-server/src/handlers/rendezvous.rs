use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;

use crate::{
    auth::{extract_bearer_token, generate_token, now_secs, validate_session},
    error::{AppError, AppResult},
    state::SharedState,
};

#[derive(Deserialize)]
pub struct RegisterRendezvousRequest {
    pub daemon_pubkey: String, // base64
    pub pair_code: String,
}

pub async fn register_rendezvous(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let daemon_pubkey_b64 = body
        .get("daemon_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("daemon_pubkey required"))?;
    let pair_code = body
        .get("pair_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("pair_code required"))?;

    let daemon_pubkey = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        daemon_pubkey_b64,
    )
    .map_err(|e| AppError::bad_request(format!("invalid base64 for daemon_pubkey: {e}")))?;

    let now = now_secs();
    let db = state.db.lock().unwrap();

    // Check for collision
    let existing: bool = db
        .query_row(
            "SELECT 1 FROM rendezvous_registrations WHERE pair_code = ?1",
            params![pair_code],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if existing {
        return Err(AppError::conflict("pair code already registered"));
    }

    // Generate a secret registration token distinct from the pair_code.
    // The daemon uses this token to poll; the pair_code is the human-visible code.
    let registration_token = generate_token();

    db.execute(
        "INSERT INTO rendezvous_registrations (pair_code, registration_token, daemon_pubkey, payload, delivered, consumed, created_at, ttl_seconds)
         VALUES (?1, ?2, ?3, NULL, 0, 0, ?4, 300)",
        params![pair_code, registration_token, daemon_pubkey, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "registration_token": registration_token })))
}

#[derive(Deserialize)]
pub struct PollRendezvousQuery {
    pub token: String,
}

pub async fn poll_rendezvous(
    State(state): State<SharedState>,
    Query(query): Query<PollRendezvousQuery>,
) -> AppResult<Json<Value>> {
    let registration_token = &query.token;
    let deadline = now_secs() + 30;

    loop {
        let now = now_secs();
        if now >= deadline {
            return Ok(Json(json!({ "payload": null, "status": "timeout" })));
        }

        let row = {
            let db = state.db.lock().unwrap();
            db.query_row(
                "SELECT payload, delivered, consumed, created_at, ttl_seconds FROM rendezvous_registrations
                 WHERE registration_token = ?1",
                params![registration_token],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                    ))
                },
            )
            .ok()
        };

        match row {
            None => return Err(AppError::not_found("registration not found")),
            Some((_, _, _, created_at, ttl_seconds)) if now > created_at + ttl_seconds => {
                return Err(AppError::gone("registration expired"));
            }
            Some((_, _, consumed, _, _)) if consumed != 0 => {
                return Err(AppError::conflict("registration already consumed"));
            }
            Some((Some(payload), _, _, _, _)) => {
                let encoded =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload);
                // Mark as consumed so subsequent polls get CONSUMED / NOT_FOUND
                {
                    let db = state.db.lock().unwrap();
                    db.execute(
                        "UPDATE rendezvous_registrations SET consumed = 1 WHERE registration_token = ?1",
                        params![registration_token],
                    )
                    .ok();
                }
                return Ok(Json(json!({ "payload": encoded, "status": "delivered" })));
            }
            Some((None, _, _, _, _)) => {
                // Not yet delivered, wait
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

pub async fn deliver_rendezvous(
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

    let pair_code = body
        .get("pair_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("pair_code required"))?;
    let payload_b64 = body
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("payload required"))?;

    let payload = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload_b64)
        .map_err(|e| AppError::bad_request(format!("invalid base64 for payload: {e}")))?;

    let now = now_secs();
    let db = state.db.lock().unwrap();

    let row = db
        .query_row(
            "SELECT delivered, created_at, ttl_seconds FROM rendezvous_registrations WHERE pair_code = ?1",
            params![pair_code],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?)),
        )
        .map_err(|_| AppError::no_match("no registration found for this pair code"))?;

    let (delivered, created_at, ttl_seconds) = row;

    if now > created_at + ttl_seconds {
        return Err(AppError::gone("registration expired"));
    }

    if delivered != 0 {
        return Err(AppError::already_delivered(
            "payload already delivered for this pair code",
        ));
    }

    db.execute(
        "UPDATE rendezvous_registrations SET payload = ?1, delivered = 1 WHERE pair_code = ?2",
        params![payload, pair_code],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}
