//! HTTP transport auth — issue #107 acceptance criterion #3:
//! - wrong token → 401
//! - missing X-AgentKeys-Actor → 403
//! - tool param actor != header actor → 403

mod common;

use std::sync::Arc;

use agentkeys_mcp_server::{config::Config, server::Server, transport::http_router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::MockBackend;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::util::ServiceExt;

fn router() -> axum::Router {
    let config = Config::for_tests().with_vendor_token("magiclick", "demo-tok");
    let server = Server::new(config, Arc::new(MockBackend::new()));
    http_router(Arc::new(server))
}

async fn body_json(req_body: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(req_body.to_string())).unwrap();
    let resp = router().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, v)
}

fn whoami_body(actor: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "agentkeys.identity.whoami", "arguments": {"actor": actor}},
        "id": 1
    })
}

#[tokio::test]
async fn missing_bearer_is_401() {
    let (status, _) = body_json(whoami_body("O_alice"), &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_bearer_is_401() {
    let (status, _) = body_json(
        whoami_body("O_alice"),
        &[
            ("authorization", "Bearer nope"),
            ("x-agentkeys-actor", "O_alice"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn correct_bearer_no_actor_header_is_403() {
    let (status, _) = body_json(
        whoami_body("O_alice"),
        &[("authorization", "Bearer demo-tok")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cross_actor_param_is_403_in_json_rpc_error() {
    let (status, body) = body_json(
        whoami_body("O_bob"),
        &[
            ("authorization", "Bearer demo-tok"),
            ("x-agentkeys-actor", "O_alice"),
        ],
    )
    .await;
    // The transport layer accepts the request (auth headers parsed),
    // but the tool handler returns FORBIDDEN as a JSON-RPC error.
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["error"].is_object(),
        "expected json-rpc error: {body:?}"
    );
    assert_eq!(body["error"]["code"], -32003); // FORBIDDEN
}

#[tokio::test]
async fn happy_path_returns_jsonrpc_result() {
    let (status, body) = body_json(
        whoami_body("O_alice"),
        &[
            ("authorization", "Bearer demo-tok"),
            ("x-agentkeys-actor", "O_alice"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["result"].is_object(),
        "expected jsonrpc result: {body:?}"
    );
}

#[tokio::test]
async fn tools_list_works_through_http() {
    let body = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 2
    });
    let (status, body) = body_json(
        body,
        &[
            ("authorization", "Bearer demo-tok"),
            ("x-agentkeys-actor", "O_alice"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tools = body["result"]["tools"].as_array().expect("tools array");
    assert_eq!(
        tools.len(),
        7,
        "should expose 7 active tools (M4 schema-only stubs are dispatchable via tools/call but not advertised in tools/list — see tools/mod.rs)"
    );

    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "agentkeys.identity.whoami",
        "agentkeys.memory.get",
        "agentkeys.memory.put",
        "agentkeys.permission.check",
        "agentkeys.cap.mint",
        "agentkeys.cap.revoke",
        "agentkeys.audit.append",
    ] {
        assert!(names.contains(&expected), "missing tool: {expected}");
    }
    // M4 stubs must NOT be in tools/list (callable via tools/call only).
    for stubbed in [
        "agentkeys.delegation.grant",
        "agentkeys.delegation.revoke",
        "agentkeys.approval.request",
    ] {
        assert!(
            !names.contains(&stubbed),
            "M4 stub {stubbed} should not be in tools/list"
        );
    }
}
