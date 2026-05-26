//! Schema-only tools must return the exact wire shape from issue #107:
//! `{"error": "not_implemented_in_v1", "scheduled_for": "M4", "spec_url": "..."}`.

mod common;

use std::sync::Arc;

use agentkeys_mcp_server::{auth::CallerContext, config::Config, mcp::Request, server::Server};
use common::MockBackend;
use serde_json::json;

fn server() -> Server {
    Server::new(Config::for_tests(), Arc::new(MockBackend::new()))
}

fn caller() -> CallerContext {
    CallerContext::new("magiclick", "O_alice")
}

fn call(name: &str) -> Request {
    Request {
        jsonrpc: "2.0".into(),
        method: "tools/call".into(),
        params: Some(json!({"name": name, "arguments": {}})),
        id: Some(json!(1)),
    }
}

#[tokio::test]
async fn delegation_grant_is_not_implemented_v1() {
    let resp = server()
        .dispatch(&caller(), "", call("agentkeys.delegation.grant"))
        .await;
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    let data = err.data.expect("data field");
    assert_eq!(data["error"], "not_implemented_in_v1");
    assert_eq!(data["scheduled_for"], "M4");
    assert!(data["spec_url"]
        .as_str()
        .unwrap()
        .contains("milestones-roadmap.md"));
}

#[tokio::test]
async fn delegation_revoke_is_not_implemented_v1() {
    let resp = server()
        .dispatch(&caller(), "", call("agentkeys.delegation.revoke"))
        .await;
    assert!(resp.error.is_some());
    assert_eq!(
        resp.error.unwrap().data.unwrap()["error"],
        "not_implemented_in_v1"
    );
}

#[tokio::test]
async fn approval_request_is_not_implemented_v1() {
    let resp = server()
        .dispatch(&caller(), "", call("agentkeys.approval.request"))
        .await;
    assert!(resp.error.is_some());
    assert_eq!(
        resp.error.unwrap().data.unwrap()["error"],
        "not_implemented_in_v1"
    );
}
