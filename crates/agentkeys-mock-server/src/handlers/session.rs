use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    auth::{derive_pair_code_from_nonce, extract_bearer_token, generate_nonce, generate_token, generate_wallet_address, is_owner_of, now_secs, validate_session},
    error::{AppError, AppResult},
    state::SharedState,
};
use agentkeys_types::{AuthToken, Scope};
use ed25519_dalek::SigningKey;

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub auth_token: String,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session: String,
    pub wallet: String,
}

pub async fn create_session(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> AppResult<Json<CreateSessionResponse>> {
    let auth_token = body.get("auth_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("auth_token required"))?;

    // Mock validation: reject obviously bad tokens
    if auth_token.is_empty() || auth_token == "invalid" {
        return Err(AppError::unauthorized("invalid auth token"));
    }

    let db = state.db.lock().unwrap();
    let now = now_secs();

    // Check if account with this auth_token already exists
    let existing: Option<(String, String)> = db
        .query_row(
            "SELECT wallet_address, auth_token FROM accounts WHERE auth_token = ?1",
            params![auth_token],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    if let Some((wallet_address, _)) = existing {
        // Return existing session or create a new one for the existing account
        let session_token = generate_token();
        db.execute(
            "INSERT INTO sessions (token, wallet_address, parent_token, scope_json, created_at, ttl_seconds, revoked)
             VALUES (?1, ?2, NULL, NULL, ?3, ?4, 0)",
            params![session_token, wallet_address, now, 86400u64],
        )
        .map_err(|e| AppError::internal(e.to_string()))?;
        return Ok(Json(CreateSessionResponse { session: session_token, wallet: wallet_address }));
    }

    // Create new account
    let wallet_address = generate_wallet_address();
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes().to_vec();

    db.execute(
        "INSERT INTO accounts (wallet_address, auth_token, public_key, private_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![wallet_address, auth_token, public_key_bytes, private_key_bytes, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    let session_token = generate_token();
    db.execute(
        "INSERT INTO sessions (token, wallet_address, parent_token, scope_json, created_at, ttl_seconds, revoked)
         VALUES (?1, ?2, NULL, NULL, ?3, ?4, 0)",
        params![session_token, wallet_address, now, 86400u64],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(CreateSessionResponse { session: session_token, wallet: wallet_address }))
}

#[derive(Deserialize)]
pub struct CreateChildSessionRequest {
    pub scope: Scope,
}

#[derive(Serialize)]
pub struct CreateChildSessionResponse {
    pub session: String,
    pub wallet: String,
}

pub async fn create_child_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<CreateChildSessionResponse>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let parent = validate_session(&state, token)?;

    let scope: Scope = serde_json::from_value(
        body.get("scope").cloned().ok_or_else(|| AppError::bad_request("scope required"))?,
    )
    .map_err(|e| AppError::bad_request(e.to_string()))?;

    let scope_json = serde_json::to_string(&scope).map_err(|e| AppError::internal(e.to_string()))?;
    let child_wallet = generate_wallet_address();
    let child_token = generate_token();
    let now = now_secs();

    let db = state.db.lock().unwrap();

    // Create a child account entry so child wallet can own credentials
    // We reuse the parent's keypair for simplicity in mock
    let (pub_key, priv_key): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT public_key, private_key FROM accounts WHERE wallet_address = ?1",
            params![parent.wallet_address],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| AppError::internal(e.to_string()))?;

    db.execute(
        "INSERT OR IGNORE INTO accounts (wallet_address, auth_token, public_key, private_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![child_wallet, format!("child:{}", child_token), pub_key, priv_key, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    db.execute(
        "INSERT INTO sessions (token, wallet_address, parent_token, scope_json, created_at, ttl_seconds, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
        params![child_token, child_wallet, parent.token, scope_json, now, 3600u64],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(CreateChildSessionResponse { session: child_token, wallet: child_wallet }))
}

#[derive(Deserialize)]
pub struct RevokeSessionRequest {
    pub target_session: String,
}

pub async fn recover_session(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let identity_type = body
        .get("identity_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("identity_type required"))?;
    let identity_value = body
        .get("identity_value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("identity_value required"))?;
    let method = body
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("method required"))?;

    // Validate recovery method (v0.1: real WebAuthn/email verification replaces this)
    match method {
        "passkey" | "email" => {
            // Mock: accept any passkey/email recovery without proof.
            // Production (v0.1) MUST verify a real WebAuthn assertion or email magic-link
            // token here before minting a session. This mock exists only so the CLI/daemon
            // integration tests can exercise the 2FA recovery path end-to-end.
        }
        "master_approval" => {
            return Err(AppError::bad_request(
                "master_approval requires the pair/approve flow, not /session/recover",
            ));
        }
        _ => {
            return Err(AppError::bad_request(format!(
                "unknown recovery method '{}'. Use 'passkey' or 'email'.",
                method
            )));
        }
    }

    let db = state.db.lock().unwrap();

    let wallet_address: String = if identity_type == "wallet" {
        let exists: bool = db
            .query_row(
                "SELECT COUNT(*) FROM accounts WHERE wallet_address = ?1",
                params![identity_value],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !exists {
            return Err(AppError::not_found(format!(
                "no account found for wallet {}",
                identity_value
            )));
        }
        identity_value.to_string()
    } else {
        db.query_row(
            "SELECT wallet_address FROM identity_links WHERE identity_type = ?1 AND identity_value = ?2",
            params![identity_type, identity_value],
            |row| row.get(0),
        )
        .map_err(|_| {
            AppError::not_found(format!(
                "no identity found for {}={}",
                identity_type, identity_value
            ))
        })?
    };

    // Preserve scope from the most recent active session for this wallet
    let scope_json: Option<String> = db
        .query_row(
            "SELECT scope_json FROM sessions WHERE wallet_address = ?1 AND revoked = 0 ORDER BY created_at DESC LIMIT 1",
            params![wallet_address],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    let session_token = generate_token();
    let now = now_secs();

    db.execute(
        "INSERT INTO sessions (token, wallet_address, parent_token, scope_json, created_at, ttl_seconds, revoked)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, 0)",
        params![session_token, wallet_address, scope_json, now, 86400u64],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({
        "session": session_token,
        "wallet": wallet_address,
        "method": method,
    })))
}

pub async fn revoke_session(
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

    let target_token = body
        .get("target_session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("target_session required"))?;

    let db = state.db.lock().unwrap();

    // Look up the target session's wallet to verify ownership
    let target_wallet: Option<String> = db
        .query_row(
            "SELECT wallet_address FROM sessions WHERE token = ?1",
            params![target_token],
            |row| row.get(0),
        )
        .ok();

    let target_wallet = target_wallet.ok_or_else(|| AppError::not_found("target session not found"))?;

    // Ownership check: caller must own or be parent of the target session's wallet
    if !is_owner_of(&db, &session.wallet_address, &target_wallet) {
        return Err(AppError::forbidden("session does not own the target session"));
    }

    let rows_affected = db
        .execute("UPDATE sessions SET revoked = 1 WHERE token = ?1", params![target_token])
        .map_err(|e| AppError::internal(e.to_string()))?;

    if rows_affected == 0 {
        return Err(AppError::not_found("target session not found"));
    }

    Ok(Json(json!({ "ok": true })))
}
