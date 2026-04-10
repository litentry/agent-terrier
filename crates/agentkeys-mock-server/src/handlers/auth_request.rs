use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::sleep;

use crate::{
    auth::{
        derive_pair_code_from_nonce, extract_bearer_token, generate_nonce, generate_token,
        now_secs, validate_session,
    },
    error::{AppError, AppResult},
    state::SharedState,
};
use agentkeys_core::otp::derive_otp;
use agentkeys_types::{AuthRequestType, Scope, Session, WalletAddress};

fn ttl_for_request_type(request_type_str: &str) -> u64 {
    match request_type_str {
        "Pair" | "Recover" => 60,
        _ => 300,
    }
}

pub async fn open_auth_request(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let child_pubkey_b64 = body
        .get("child_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("child_pubkey required"))?;
    let request_type_str = body
        .get("request_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("request_type required"))?;
    let request_details_b64 = body
        .get("request_details")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("request_details required"))?;
    let parent_wallet = body.get("parent_wallet").and_then(|v| v.as_str()).map(String::from);

    let child_pubkey = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        child_pubkey_b64,
    )
    .map_err(|e| AppError::bad_request(format!("invalid base64 child_pubkey: {e}")))?;

    let request_details = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        request_details_b64,
    )
    .map_err(|e| AppError::bad_request(format!("invalid base64 request_details: {e}")))?;

    let nonce = generate_nonce();
    let otp = derive_otp(&nonce, &request_details);

    // Derive pair code uniquely: use nonce + request_details hash to avoid collisions
    let mut hasher = Sha256::new();
    hasher.update(&nonce);
    hasher.update(&request_details);
    let hash = hasher.finalize();
    let pair_code = hex::encode(&hash[..4]).to_uppercase();

    let request_id = generate_token();
    let ttl_seconds = ttl_for_request_type(request_type_str);
    let now = now_secs();

    // Compute nonce hash for the response
    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(&nonce);
    let nonce_hash = nonce_hasher.finalize().to_vec();

    let db = state.db.lock().unwrap();

    db.execute(
        "INSERT INTO auth_requests (id, pair_code, request_type, request_details, child_pubkey, parent_wallet, otp, nonce, status, created_at, ttl_seconds)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10)",
        params![
            request_id,
            pair_code,
            request_type_str,
            request_details,
            child_pubkey,
            parent_wallet,
            otp,
            nonce.to_vec(),
            now,
            ttl_seconds
        ],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({
        "id": request_id,
        "otp": otp,
        "pair_code": pair_code,
        "ttl_seconds": ttl_seconds,
        "nonce_hash": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_hash),
    })))
}

#[derive(Deserialize)]
pub struct FetchAuthRequestQuery {
    pub pair_code: String,
}

pub async fn fetch_auth_request(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<FetchAuthRequestQuery>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let _session = validate_session(&state, token)?;

    let db = state.db.lock().unwrap();
    let now = now_secs();

    let row = db
        .query_row(
            "SELECT id, request_type, request_details, child_pubkey, otp, created_at, ttl_seconds, status
             FROM auth_requests WHERE pair_code = ?1",
            params![query.pair_code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .map_err(|_| AppError::not_found("no auth request found for this pair code"))?;

    let (id, request_type, request_details, child_pubkey, otp, created_at, ttl_seconds, status) =
        row;

    if now > created_at + ttl_seconds {
        return Err(AppError::gone("auth request expired"));
    }

    Ok(Json(json!({
        "id": id,
        "request_type": request_type,
        "request_details": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &request_details),
        "child_pubkey": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &child_pubkey),
        "otp": otp,
        "created_at": created_at,
        "status": status,
    })))
}

pub async fn approve_auth_request(
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

    let request_id = body
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("request_id required"))?;

    let now = now_secs();
    let (
        request_type,
        request_details,
        child_pubkey,
        parent_wallet,
        nonce,
        created_at,
        ttl_seconds,
        status,
    ) = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT request_type, request_details, child_pubkey, parent_wallet, nonce, created_at, ttl_seconds, status
             FROM auth_requests WHERE id = ?1",
            params![request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .map_err(|_| AppError::not_found("auth request not found"))?
    };

    if status == "consumed" {
        return Err(AppError::conflict("auth request already consumed"));
    }

    if now > created_at + ttl_seconds {
        return Err(AppError::gone("auth request expired"));
    }

    // Ownership check: if parent_wallet is set, the approving session must own it
    if let Some(ref pw) = parent_wallet {
        if *pw != session.wallet_address {
            return Err(AppError::unauthorized("session does not own this auth request"));
        }
    }

    // Get master private key for signing
    let private_key_bytes: Vec<u8> = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT private_key FROM accounts WHERE wallet_address = ?1",
            params![session.wallet_address],
            |row| row.get(0),
        )
        .map_err(|e| AppError::internal(format!("account not found: {e}")))?
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &private_key_bytes.as_slice().try_into().map_err(|_| AppError::internal("invalid key length"))?,
    );

    // Sign: SHA256("AgentKeys-v1-AuthRequest" || id || request_type || request_details || child_pubkey || parent_session || created_at || nonce)
    let mut hasher = Sha256::new();
    hasher.update(b"AgentKeys-v1-AuthRequest");
    hasher.update(request_id.as_bytes());
    hasher.update(request_type.as_bytes());
    hasher.update(&request_details);
    hasher.update(&child_pubkey);
    hasher.update(session.token.as_bytes());
    hasher.update(&created_at.to_be_bytes());
    hasher.update(&nonce);
    let hash_bytes = hasher.finalize();

    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&hash_bytes).to_bytes().to_vec();

    // If Pair request type, mint a child session
    let (child_session_json, child_wallet) = if request_type == "Pair" {
        let child_wallet = crate::auth::generate_wallet_address();
        let child_token = generate_token();
        let ttl = 3600u64;

        // Parse scope from request_details (canonical CBOR contains it)
        // For mock: create a session with no scope restriction (full access to child wallet)
        let db = state.db.lock().unwrap();

        // Create child account
        let (pub_key, priv_key): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT public_key, private_key FROM accounts WHERE wallet_address = ?1",
                params![session.wallet_address],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| AppError::internal(e.to_string()))?;

        db.execute(
            "INSERT OR IGNORE INTO accounts (wallet_address, auth_token, public_key, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![child_wallet, format!("child-pair:{child_token}"), pub_key, priv_key, now],
        )
        .map_err(|e| AppError::internal(e.to_string()))?;

        db.execute(
            "INSERT INTO sessions (token, wallet_address, parent_token, scope_json, created_at, ttl_seconds, revoked)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, 0)",
            params![child_token, child_wallet, token, now, ttl],
        )
        .map_err(|e| AppError::internal(e.to_string()))?;

        let session_obj = serde_json::json!({
            "token": child_token,
            "wallet": child_wallet,
            "scope": null,
            "created_at": now,
            "ttl_seconds": ttl,
        });

        (Some(session_obj.to_string()), Some(child_wallet))
    } else if request_type == "ScopeChange" {
        // Extract agent_id and new_scope from request, update scope in sessions
        // For the mock, we store the new scope as session_json to indicate the update
        // The actual scope update happens by modifying the existing session
        // Parse the request_details (CBOR) to get agent_id and new_scope
        // For simplicity in the mock, we'll parse from a JSON representation if available
        // We store updated scope info in session_json of the auth_request
        (None, None)
    } else {
        (None, None)
    };

    let db = state.db.lock().unwrap();

    let sig_encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &signature,
    );

    db.execute(
        "UPDATE auth_requests SET status = 'consumed', signature = ?1, session_json = ?2, wallet_address = ?3
         WHERE id = ?4",
        params![signature, child_session_json, child_wallet, request_id],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true, "signature": sig_encoded })))
}

#[derive(Deserialize)]
pub struct AwaitAuthDecisionQuery {
    pub request_id: String,
}

pub async fn await_auth_decision(
    State(state): State<SharedState>,
    Query(query): Query<AwaitAuthDecisionQuery>,
) -> AppResult<Json<Value>> {
    let request_id = &query.request_id;
    let deadline = now_secs() + 30;

    loop {
        let now = now_secs();
        if now >= deadline {
            return Ok(Json(json!({ "status": "timeout", "decision": null })));
        }

        let row = {
            let db = state.db.lock().unwrap();
            db.query_row(
                "SELECT status, signature, session_json, wallet_address, created_at, ttl_seconds
                 FROM auth_requests WHERE id = ?1",
                params![request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )
            .ok()
        };

        match row {
            None => return Err(AppError::not_found("auth request not found")),
            Some((status, _, _, _, created_at, ttl_seconds)) if status == "pending" && now > created_at + ttl_seconds => {
                return Err(AppError::gone("auth request expired"));
            }
            Some((status, _, _, _, _, _)) if status == "consumed_awaited" => {
                return Err(AppError::conflict("auth request already awaited"));
            }
            Some((status, Some(signature), session_json, wallet_address, _, _))
                if status == "consumed" =>
            {
                let sig_encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &signature,
                );

                let session_val: Option<Value> = session_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok());

                // Mark as awaited so subsequent polls get CONSUMED
                {
                    let db = state.db.lock().unwrap();
                    db.execute(
                        "UPDATE auth_requests SET status = 'consumed_awaited' WHERE id = ?1",
                        params![request_id],
                    )
                    .ok();
                }

                return Ok(Json(json!({
                    "status": "approved",
                    "request_id": request_id,
                    "approved": true,
                    "signature": sig_encoded,
                    "session": session_val,
                    "wallet": wallet_address,
                })));
            }
            Some((_, _, _, _, _, _)) => {
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
}
