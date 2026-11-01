//! Integration tests for the `AuditEnvelope v2` endpoints (issue #97 phase B).
//!
//! Exercises:
//! - `POST /v1/audit/append/v2` → 200 + envelope_hash
//! - `GET /v1/audit/envelope/<hash>` → 200 application/cbor with the canonical bytes
//! - `GET /v1/audit/envelope/<unknown>` → 404 envelope_not_found
//! - End-to-end: hash returned by append matches `keccak256(canonical_cbor)` of
//!   the round-tripped envelope.

use std::sync::Arc;

use agentkeys_worker_audit::{create_router, state::State};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use sha3::{Digest, Keccak256};
use tower::ServiceExt;

fn router_with_state() -> axum::Router {
    let tmp = std::env::temp_dir();
    let state: agentkeys_worker_audit::state::SharedState =
        Arc::new(State::new(tmp.to_string_lossy().to_string()));
    create_router(state)
}

async fn post_json(
    app: axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, parsed)
}

fn valid_envelope_json() -> serde_json::Value {
    json!({
        "version": 1,
        "ts_unix": 1_700_000_000u64,
        "actor_omni":    "0x".to_string() + &"aa".repeat(32),
        "operator_omni": "0x".to_string() + &"bb".repeat(32),
        "op_kind": 21, // SignEip712
        "op_body": {
            "chain_id": 1,
            "verifying_contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "primary_type": "Permit",
            "type_hash":         "0x".to_string() + &"de".repeat(32),
            "domain_separator":  "0x".to_string() + &"ad".repeat(32),
            "digest":            "0x".to_string() + &"be".repeat(32),
        },
        "result": 0,
        "intent_text": "Approve 1 USDC to 0xaaaa…3333",
        "intent_commitment": "0x".to_string() + &"cc".repeat(32),
    })
}

#[tokio::test]
async fn append_v2_then_get_returns_canonical_cbor() {
    let app = router_with_state();
    let (status, append_resp) =
        post_json(app.clone(), "/v1/audit/append/v2", valid_envelope_json()).await;
    assert_eq!(status, StatusCode::OK);
    let hash = append_resp["envelope_hash"].as_str().unwrap().to_string();
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 2 + 64);

    // GET the envelope back.
    let get_req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/audit/envelope/{hash}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(get_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/cbor"
    );
    let cbor = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!cbor.is_empty());

    // The returned CBOR's keccak256 MUST equal the envelope_hash returned by append.
    let mut hasher = Keccak256::new();
    hasher.update(&cbor);
    let recomputed = hasher.finalize();
    let recomputed_hex = format!("0x{}", hex::encode(recomputed));
    assert_eq!(recomputed_hex, hash);
}

#[tokio::test]
async fn get_envelope_returns_404_for_unknown_hash() {
    let app = router_with_state();
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/audit/envelope/0x{}", "ff".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn append_v2_rejects_wrong_envelope_version() {
    let mut body = valid_envelope_json();
    body["version"] = json!(99);
    let (status, resp) = post_json(router_with_state(), "/v1/audit/append/v2", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The body is a plain string in this error path (not JSON), so the
    // parsed JSON is Null. Status check is the assertion.
    let _ = resp;
}

#[tokio::test]
async fn append_v2_rejects_short_actor_omni() {
    let mut body = valid_envelope_json();
    body["actor_omni"] = json!("0xdeadbeef");
    let (status, _) = post_json(router_with_state(), "/v1/audit/append/v2", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn append_v2_accepts_unknown_op_kind() {
    // Per non-break invariant #1, the worker must accept any op_kind byte
    // — even one not yet in the canonical table — and store the envelope.
    // Old workers that don't recognize new op_kinds just hold the opaque
    // body for explorers that DO know to decode it.
    let mut body = valid_envelope_json();
    body["op_kind"] = json!(250);
    body["op_body"] = json!({ "future_field": "v2-only" });
    let (status, resp) = post_json(router_with_state(), "/v1/audit/append/v2", body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(resp["envelope_hash"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn envelope_hash_is_deterministic_across_appends() {
    let body = valid_envelope_json();
    let (_, a) = post_json(router_with_state(), "/v1/audit/append/v2", body.clone()).await;
    let (_, b) = post_json(router_with_state(), "/v1/audit/append/v2", body).await;
    assert_eq!(a["envelope_hash"], b["envelope_hash"]);
}

#[tokio::test]
async fn ts_unix_zero_gets_server_assigned() {
    let mut body = valid_envelope_json();
    body["ts_unix"] = json!(0);
    let (status, resp) = post_json(router_with_state(), "/v1/audit/append/v2", body).await;
    assert_eq!(status, StatusCode::OK);
    // The hash will differ from a fixed-ts envelope because ts_unix is part
    // of the canonical CBOR. Just confirm we got a valid hash back.
    assert!(resp["envelope_hash"].as_str().unwrap().starts_with("0x"));
}
