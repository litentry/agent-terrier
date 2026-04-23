use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::{extract_bearer_token, is_owner_of, now_secs, validate_session},
    error::{AppError, AppResult},
    state::SharedState,
};

fn email_domain() -> String {
    std::env::var("AGENTKEYS_EMAIL_DOMAIN").unwrap_or_else(|_| "agentkeys-email.io".to_string())
}

fn generate_inbox_address() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 3] = rng.gen();
    format!("bot-{}@{}", hex::encode(bytes), email_domain())
}

fn generate_msg_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub async fn provision_inbox(
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

    let db = state.db.lock().unwrap();

    if !is_owner_of(&db, &session.wallet_address, agent_id) {
        return Err(AppError::forbidden(format!(
            "session does not own agent {}",
            agent_id
        )));
    }

    let address = generate_inbox_address();
    let now = now_secs();

    db.execute(
        "INSERT INTO inboxes (address, agent_wallet, created_at) VALUES (?1, ?2, ?3)",
        params![address, agent_id, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "address": address, "agent_wallet": agent_id })))
}

pub async fn deliver_inbox(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let address = body
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("address required"))?;
    let from_addr = body
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("from required"))?;
    let subject = body.get("subject").and_then(|v| v.as_str());
    let message_body = body.get("body").and_then(|v| v.as_str());

    let db = state.db.lock().unwrap();

    let inbox_exists: bool = db
        .query_row(
            "SELECT 1 FROM inboxes WHERE address = ?1",
            params![address],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !inbox_exists {
        return Err(AppError::not_found(format!("inbox not found: {}", address)));
    }

    let msg_id = generate_msg_id();
    let now = now_secs();

    db.execute(
        "INSERT INTO inbox_messages (msg_id, address, from_addr, subject, body, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![msg_id, address, from_addr, subject, message_body, now],
    )
    .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "msg_id": msg_id })))
}

#[derive(Deserialize)]
pub struct ListInboxesQuery {
    pub agent_id: String,
}

pub async fn list_inboxes(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ListInboxesQuery>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let session = validate_session(&state, token)?;

    let agent_id = &query.agent_id;
    let db = state.db.lock().unwrap();

    if !is_owner_of(&db, &session.wallet_address, agent_id) {
        return Err(AppError::forbidden(format!(
            "session does not own agent {}",
            agent_id
        )));
    }

    let mut stmt = db
        .prepare("SELECT address FROM inboxes WHERE agent_wallet = ?1 ORDER BY created_at ASC")
        .map_err(|e| AppError::internal(e.to_string()))?;

    let addresses: Vec<Value> = stmt
        .query_map(params![agent_id], |row| {
            let addr: String = row.get(0)?;
            Ok(Value::String(addr))
        })
        .map_err(|e| AppError::internal(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(Value::Array(addresses)))
}

#[derive(Deserialize)]
pub struct ListMessagesQuery {
    pub address: String,
}

pub async fn list_messages(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ListMessagesQuery>,
) -> AppResult<Json<Value>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

    let session = validate_session(&state, token)?;

    let address = &query.address;
    let db = state.db.lock().unwrap();

    let agent_wallet: String = db
        .query_row(
            "SELECT agent_wallet FROM inboxes WHERE address = ?1",
            params![address],
            |row| row.get(0),
        )
        .map_err(|_| AppError::not_found(format!("inbox not found: {}", address)))?;

    if !is_owner_of(&db, &session.wallet_address, &agent_wallet) {
        return Err(AppError::forbidden(format!(
            "session does not own inbox {}",
            address
        )));
    }

    let mut stmt = db
        .prepare(
            "SELECT msg_id, from_addr, subject, body, received_at
             FROM inbox_messages
             WHERE address = ?1
             ORDER BY received_at DESC",
        )
        .map_err(|e| AppError::internal(e.to_string()))?;

    let messages: Vec<Value> = stmt
        .query_map(params![address], |row| {
            Ok(json!({
                "msg_id": row.get::<_, String>(0)?,
                "from": row.get::<_, String>(1)?,
                "subject": row.get::<_, Option<String>>(2)?,
                "body": row.get::<_, Option<String>>(3)?,
                "received_at": row.get::<_, u64>(4)?,
            }))
        })
        .map_err(|e| AppError::internal(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!(messages)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_router, db, state::AppState};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn setup() -> Router {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let state = Arc::new(AppState::new(conn));
        create_router(state)
    }

    async fn body_json(body: axum::body::Body) -> Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    async fn post_json(app: Router, path: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let json = body_json(resp.into_body()).await;
        (status, json)
    }

    async fn post_json_auth(
        app: Router,
        path: &str,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let json = body_json(resp.into_body()).await;
        (status, json)
    }

    async fn get_json_auth(app: Router, path: &str, token: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let json = body_json(resp.into_body()).await;
        (status, json)
    }

    async fn create_session(app: Router) -> (String, String, Router) {
        let (status, json) = post_json(
            app.clone(),
            "/session/create",
            json!({ "auth_token": format!("tok-{}", rand::random::<u64>()) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create session failed: {json}");
        let session = json["session"].as_str().unwrap().to_string();
        let wallet = json["wallet"].as_str().unwrap().to_string();
        (session, wallet, app)
    }

    async fn provision(app: Router, token: &str, agent_wallet: &str) -> (StatusCode, Value) {
        post_json_auth(
            app,
            "/mock/inbox/provision",
            token,
            json!({ "agent_id": agent_wallet }),
        )
        .await
    }

    #[tokio::test]
    async fn provision_returns_unique_address() {
        let app = setup();
        let (token, wallet, app) = create_session(app).await;

        let mut addresses = std::collections::HashSet::new();
        for _ in 0..10 {
            let (status, json) = provision(app.clone(), &token, &wallet).await;
            assert_eq!(status, StatusCode::OK, "provision failed: {json}");
            let addr = json["address"].as_str().unwrap().to_string();
            addresses.insert(addr);
        }
        assert_eq!(addresses.len(), 10, "expected 10 distinct addresses");
    }

    #[tokio::test]
    async fn deliver_and_fetch_roundtrip() {
        let app = setup();
        let (token, wallet, app) = create_session(app).await;

        let (status, json) = provision(app.clone(), &token, &wallet).await;
        assert_eq!(status, StatusCode::OK, "provision failed: {json}");
        let address = json["address"].as_str().unwrap().to_string();

        let (status, json) = post_json(
            app.clone(),
            "/mock/inbox/deliver",
            json!({
                "address": address,
                "from": "sender@example.com",
                "subject": "Hello",
                "body": "World",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "deliver failed: {json}");
        let msg_id = json["msg_id"].as_str().unwrap().to_string();

        let path = format!("/mock/inbox/messages?address={}", address);
        let (status, json) = get_json_auth(app.clone(), &path, &token).await;
        assert_eq!(status, StatusCode::OK, "list failed: {json}");
        let messages = json.as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["msg_id"].as_str().unwrap(), msg_id);
        assert_eq!(messages[0]["from"].as_str().unwrap(), "sender@example.com");
        assert_eq!(messages[0]["subject"].as_str().unwrap(), "Hello");
        assert_eq!(messages[0]["body"].as_str().unwrap(), "World");
    }

    #[tokio::test]
    async fn cross_session_list_denied() {
        let app = setup();

        let (token_a, wallet_a, app) = create_session(app).await;
        let (token_b, _wallet_b, app) = create_session(app).await;

        let (status, json) = provision(app.clone(), &token_a, &wallet_a).await;
        assert_eq!(status, StatusCode::OK, "provision failed: {json}");
        let address = json["address"].as_str().unwrap().to_string();

        let path = format!("/mock/inbox/messages?address={}", address);
        let (status, _) = get_json_auth(app.clone(), &path, &token_b).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "expected 403 for session B");
    }
}
