//! `agent_admin` against a MOCK broker (an ephemeral axum server): the claim /
//! pending / ack / spawn / archive / accept client paths, with the SOFTWARE
//! P-256 passkey signing the UserOps the way headless CI does. No chain, no
//! deployed broker — the wire shapes are the protocol crate's typed responses.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use agentkeys_cli::agent_admin;

const DKH: &str = "0xabababababababababababababababababababababababababababababababab";
const CHILD: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const OPERATOR: &str = "0x1212121212121212121212121212121212121212121212121212121212121212";
const HASH: &str = "0x9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b";

#[derive(Default)]
struct Seen {
    posts: Mutex<Vec<(String, Value)>>,
}

fn user_op() -> Value {
    json!({
        "sender": "0x0000000000000000000000000000000000000001",
        "nonce": "0x0",
        "init_code": "0x",
        "call_data": "0x",
        "account_gas_limits": "0x",
        "pre_verification_gas": "0x0",
        "gas_fees": "0x",
        "paymaster_and_data": "0x",
        "signature": "0x"
    })
}

async fn record(State(seen): State<Arc<Seen>>, path: &'static str, body: Value) -> Value {
    seen.posts.lock().unwrap().push((path.to_string(), body));
    Value::Null
}

async fn mock_broker(seen: Arc<Seen>) -> String {
    let app = Router::new()
        .route(
            "/v1/agent/pairing/claim",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "claim", b.clone()).await;
                Json(json!({ "ok": true, "child_omni": CHILD, "label": b["label"], "request_id": "req-1" }))
            }),
        )
        .route(
            "/v1/agent/pending-bindings",
            get(|| async {
                Json(json!({ "pending": [ {
                    "request_id": "req-1", "label": "probe", "child_omni": CHILD,
                    "device_key_hash": DKH, "agent_pop_sig": "0x00", "requested_scope": "channel-sub:kitchen"
                } ] }))
            }),
        )
        .route(
            "/v1/agent/pending-bindings/ack",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "ack", b).await;
                Json(json!({ "ok": true }))
            }),
        )
        .route(
            "/v1/agent/spawn/build",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "spawn/build", b.clone()).await;
                Json(json!({
                    "user_op": user_op(), "user_op_hash": HASH, "entry_point": "0x0000000000000000000000000000000000000002",
                    "chain_id": 212013, "actor_omni": CHILD, "device_key_hash": DKH,
                    "chat_channel_id": "opchat-probe", "memory_ns": "app-probe", "memory_inherited": false,
                    "services": ["channel-pub:opchat-probe", "channel-sub:opchat-probe", "memory:app-probe"],
                    "slots_used": 1, "slots_total": 3
                }))
            }),
        )
        .route(
            "/v1/agent/spawn/submit",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "spawn/submit", b).await;
                Json(json!({ "ok": true, "user_op_hash": HASH, "tx_hash": "0x9b10", "block_number": "0x1" }))
            }),
        )
        .route(
            "/v1/agent/archive/build",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "archive/build", b).await;
                Json(json!({
                    "user_op": user_op(), "user_op_hash": HASH, "entry_point": "0x0000000000000000000000000000000000000002",
                    "chain_id": 212013, "device_key_hash": DKH, "resources_kept": true
                }))
            }),
        )
        .route(
            "/v1/agent/archive/submit",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "archive/submit", b).await;
                Json(json!({ "ok": true, "user_op_hash": HASH, "tx_hash": "0x9b11", "block_number": "0x2" }))
            }),
        )
        .route(
            "/v1/accept/build",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "accept/build", b).await;
                Json(json!({ "user_op": user_op(), "user_op_hash": HASH, "entry_point": "0x0000000000000000000000000000000000000002", "chain_id": 212013 }))
            }),
        )
        .route(
            "/v1/accept/submit",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s), "accept/submit", b).await;
                Json(json!({ "ok": true, "tx_hash": "0x9b12", "block_number": "0x3", "user_op_hash": HASH }))
            }),
        )
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A bearer with the omni claim `agent_spawn` reads (`agentkeys.omni_account`);
/// the signature segment is never verified client-side.
fn bearer() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload =
        URL_SAFE_NO_PAD.encode(json!({ "agentkeys": { "omni_account": OPERATOR } }).to_string());
    format!("e30.{payload}.sig")
}

fn software_key(dir: &tempfile::TempDir) -> String {
    let path = dir
        .path()
        .join("k11-software.pem")
        .to_string_lossy()
        .to_string();
    agentkeys_cli::k11_webauthn::software_webauthn_keygen(&path, "localhost")
        .expect("software passkey");
    path
}

#[tokio::test]
async fn claim_pending_and_ack_round_trip_the_rendezvous() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let body = agent_admin::agent_claim(
        &base,
        "PAIR-1234",
        "probe",
        "channel-sub:kitchen",
        &bearer(),
    )
    .await
    .expect("claim");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["child_omni"], CHILD);
    assert_eq!(v["label"], "probe");
    let pending = agent_admin::agent_pending_value(&base, &bearer())
        .await
        .expect("pending");
    assert_eq!(pending["pending"][0]["request_id"], "req-1");
    let text = agent_admin::agent_pending(&base, &bearer())
        .await
        .expect("pending text");
    assert!(text.contains("req-1"));
    agent_admin::agent_ack(&base, "req-1", &bearer())
        .await
        .expect("ack");
    let posts = seen.posts.lock().unwrap();
    let claim = posts
        .iter()
        .find(|(p, _)| p == "claim")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(claim["pairing_code"], "PAIR-1234");
    assert_eq!(claim["label"], "probe");
    assert_eq!(claim["requested_scope"], "channel-sub:kitchen");
    let ack = posts
        .iter()
        .find(|(p, _)| p == "ack")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(ack["request_id"], "req-1");
}

#[tokio::test]
async fn spawn_and_archive_sign_with_the_software_passkey_and_submit() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let key = software_key(&dir);
    let out = agent_admin::agent_spawn(
        &base,
        "probe",
        "chef",
        "",
        false,
        &key,
        "localhost",
        &bearer(),
    )
    .await
    .expect("spawn");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["spawned"], true);
    assert_eq!(v["label"], "probe");
    assert_eq!(v["actor_omni"], CHILD);
    assert_eq!(v["device_key_hash"], DKH);
    assert_eq!(v["user_op_hash"], HASH);
    let out =
        agent_admin::agent_archive(&base, DKH, true, "app-probe", &key, "localhost", &bearer())
            .await
            .expect("archive");
    assert!(out.contains(DKH), "{out}");
    let posts = seen.posts.lock().unwrap();
    let build = posts
        .iter()
        .find(|(p, _)| p == "spawn/build")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(build["label"], "probe");
    assert_eq!(build["preset_id"], "chef");
    let submit = posts
        .iter()
        .find(|(p, _)| p == "spawn/submit")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert!(
        submit["assertion"]["signature"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "{submit}"
    );
    assert_eq!(
        submit["user_op"]["sender"],
        "0x0000000000000000000000000000000000000001"
    );
    let archive = posts
        .iter()
        .find(|(p, _)| p == "archive/build")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(archive["device_key_hash"], DKH);
    assert_eq!(archive["resources_kept"], true);
    assert!(posts.iter().any(|(p, _)| p == "archive/submit"));
}

#[tokio::test]
async fn accept_signs_the_pending_binding_and_refuses_a_device_without_channels() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let key = software_key(&dir);
    // A device claim must carry ≥ 1 channel grant (D9): refused before any request.
    let err = agent_admin::agent_accept(
        &base,
        "req-1",
        "memory",
        true,
        &key,
        "localhost",
        OPERATOR,
        &bearer(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").to_lowercase().contains("channel"),
        "{err:#}"
    );
    // An unknown request id is refused after the pending read.
    let err = agent_admin::agent_accept(
        &base,
        "req-404",
        "channel-sub:kitchen",
        true,
        &key,
        "localhost",
        OPERATOR,
        &bearer(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("req-404"), "{err:#}");
    // The happy path: build → software assertion → submit.
    let out = agent_admin::agent_accept(
        &base,
        "req-1",
        "channel-sub:kitchen",
        true,
        &key,
        "localhost",
        OPERATOR,
        &bearer(),
    )
    .await
    .expect("accept");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["accepted"], true);
    assert_eq!(v["is_device"], true);
    assert_eq!(v["actor_omni"], CHILD);
    assert_eq!(v["tx_hash"], "0x9b12");
    let posts = seen.posts.lock().unwrap();
    let build = posts
        .iter()
        .find(|(p, _)| p == "accept/build")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(build["operator_omni"], OPERATOR);
    assert_eq!(build["actor_omni"], CHILD);
    assert_eq!(build["is_device"], true);
    let submit = posts
        .iter()
        .find(|(p, _)| p == "accept/submit")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert!(submit["assertion"]["authenticator_data"].as_str().is_some());
}
