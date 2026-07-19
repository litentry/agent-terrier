//! End-to-end relay flows against a mock OpenAI upstream + a mock audit
//! worker: custody (vendor key attached relay-side, caller key never
//! forwarded), metering (non-streamed + streamed with include_usage
//! injection), deterministic budgets, upstream error triage, and the
//! per-device/per-key → user rollup (#384).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use agentkeys_gate::config::{GateConfig, RelayKey, UpstreamConfig};
use agentkeys_gate::relay::Relay;
use agentkeys_gate::server;

const UPSTREAM_KEY: &str = "ark-vendor-secret";
const RELAY_KEY_1: &str = "gk_device_one";
const RELAY_KEY_2: &str = "gk_device_two";

fn user_omni() -> String {
    format!("0x{}", "aa".repeat(32))
}

/// (authorization header, request body) pairs the mock upstream captured.
type CapturedRequests = Arc<Mutex<Vec<(Option<String>, Value)>>>;

#[derive(Clone, Default)]
struct UpstreamState {
    requests: CapturedRequests,
    calls: Arc<AtomicUsize>,
    mode: Arc<Mutex<String>>,
}

async fn upstream_chat(
    State(state): State<UpstreamState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    state.requests.lock().unwrap().push((auth, body));
    let mode = state.mode.lock().unwrap().clone();
    match mode.as_str() {
        "ok" => Json(json!({
            "id": "cmpl-1", "object": "chat.completion", "created": 1, "model": "ep-doubao",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140,
                "prompt_tokens_details": {"cached_tokens": 60},
                "completion_tokens_details": {"reasoning_tokens": 15}
            }
        }))
        .into_response(),
        "stream" => {
            let sse = concat!(
                "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}],\"usage\":null}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}],\"usage\":null}\n\n",
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n",
                "data: [DONE]\n\n"
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Body::from(sse))
                .unwrap()
        }
        "http500" => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "SECRET-INTERNAL-DETAIL: shard 7 down",
        )
            .into_response(),
        "http404" => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": {"message": "model not found", "type": "invalid_request_error"}})),
        )
            .into_response(),
        other => panic!("unknown upstream mode {other}"),
    }
}

async fn upstream_models() -> Response {
    Json(json!({"object": "list", "data": [{"id": "ep-doubao"}]})).into_response()
}

async fn spawn_upstream() -> (SocketAddr, UpstreamState) {
    let state = UpstreamState {
        mode: Arc::new(Mutex::new("ok".to_string())),
        ..Default::default()
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(upstream_chat))
        .route("/v1/models", get(upstream_models))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, state)
}

#[derive(Clone, Default)]
struct AuditState {
    envelopes: Arc<Mutex<Vec<Value>>>,
}

async fn audit_append(State(state): State<AuditState>, Json(body): Json<Value>) -> Response {
    state.envelopes.lock().unwrap().push(body);
    Json(json!({"ok": true, "envelope_hash": format!("0x{}", "ee".repeat(32))})).into_response()
}

async fn spawn_audit() -> (SocketAddr, AuditState) {
    let state = AuditState::default();
    let app = Router::new()
        .route("/v1/audit/append/v2", post(audit_append))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, state)
}

fn relay_keys() -> Vec<RelayKey> {
    vec![
        RelayKey {
            key: RELAY_KEY_1.into(),
            key_id: "k1".into(),
            user_omni: user_omni(),
            device_id: "esp32-01".into(),
            label: "kid tablet".into(),
            delegate_omni: None,
            budget_tokens: None,
            disabled: false,
        },
        RelayKey {
            key: RELAY_KEY_2.into(),
            key_id: "k2".into(),
            user_omni: user_omni(),
            device_id: "esp32-02".into(),
            label: "living room".into(),
            delegate_omni: None,
            budget_tokens: None,
            disabled: false,
        },
    ]
}

struct TestGate {
    base: String,
    upstream: UpstreamState,
    audit: AuditState,
}

async fn spawn_gate(budget: Option<u64>) -> TestGate {
    let (up_addr, upstream) = spawn_upstream().await;
    let (audit_addr, audit) = spawn_audit().await;
    let config = GateConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: UpstreamConfig {
            base_url: format!("http://{up_addr}/v1"),
            api_key: UPSTREAM_KEY.into(),
            model_override: None,
        },
        keys: relay_keys(),
        user_budgets: Default::default(),
        default_budget_tokens: budget,
        admin_token: Some("admintok".into()),
        keys_file: None,
        audit_url: Some(format!("http://{audit_addr}")),
        require_audit: false,
        aws_region: "us-east-1".into(),
        speech_asr: None,
        speech_tts: None,
    };
    let relay = Arc::new(Relay::new(config));
    let app = server::router(relay);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    TestGate {
        base: format!("http://{addr}"),
        upstream,
        audit,
    }
}

fn chat_body(stream: bool) -> Value {
    json!({
        "model": "ep-doubao",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": stream,
        "temperature": 0.4
    })
}

async fn wait_for<F: Fn() -> bool>(cond: F, what: &str) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn non_streamed_turn_custody_metering_audit() {
    let gate = spawn_gate(None).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "hi");
    assert_eq!(body["usage"]["total_tokens"], 140);

    // Custody: upstream saw the VENDOR key, never the relay key; the caller's
    // extra params rode through.
    let reqs = gate.upstream.requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0.as_deref(), Some("Bearer ark-vendor-secret"));
    assert_eq!(reqs[0].1["temperature"], 0.4);
    assert!(reqs[0].1.get("stream_options").is_none());

    // Metering: rolled up to the user with device/key attribution.
    let usage: Value = client
        .get(format!("{}/v1/usage", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(usage["user_omni"], user_omni());
    assert_eq!(usage["used_tokens"], 140);
    assert_eq!(usage["totals"]["cached_tokens"], 60);
    assert_eq!(usage["totals"]["reasoning_tokens"], 15);
    assert_eq!(usage["by_device"][0]["device_id"], "esp32-01");
    assert_eq!(usage["by_api_key"][0]["api_key_id"], "k1");

    // Audit: one GateTurn (op_kind 90) envelope with the attribution + usage.
    let envs = gate.audit.envelopes.lock().unwrap().clone();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["op_kind"], 90);
    assert_eq!(envs[0]["actor_omni"], user_omni());
    assert_eq!(envs[0]["op_body"]["device_id"], "esp32-01");
    assert_eq!(envs[0]["op_body"]["api_key_id"], "k1");
    assert_eq!(envs[0]["op_body"]["total_tokens"], 140);
    assert_eq!(envs[0]["op_body"]["outcome"], "ok");
    assert_eq!(envs[0]["result"], 0);
}

#[tokio::test]
async fn streamed_turn_injects_include_usage_and_meters_after_stream() {
    let gate = spawn_gate(None).await;
    *gate.upstream.mode.lock().unwrap() = "stream".into();
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(true))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    // Byte-faithful passthrough of the SSE stream.
    assert!(text.contains("data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]"));
    assert!(text.contains("data: [DONE]"));

    // The relay injected include_usage so the final chunk carries usage.
    let reqs = gate.upstream.requests.lock().unwrap().clone();
    assert_eq!(reqs[0].1["stream_options"]["include_usage"], true);

    // Metering + audit run in the stream finalizer.
    let meter_done = {
        let audit = gate.audit.envelopes.clone();
        move || !audit.lock().unwrap().is_empty()
    };
    wait_for(meter_done, "stream finalizer audit").await;
    let envs = gate.audit.envelopes.lock().unwrap().clone();
    assert_eq!(envs[0]["op_body"]["streamed"], true);
    assert_eq!(envs[0]["op_body"]["total_tokens"], 10);

    let usage: Value = client
        .get(format!("{}/v1/usage", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(usage["used_tokens"], 10);
}

#[tokio::test]
async fn unknown_key_is_401_and_never_reaches_upstream() {
    let gate = spawn_gate(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth("gk_wrong")
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "authentication_error");
    assert_eq!(gate.upstream.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn budget_zero_denies_deterministically_without_upstream() {
    let gate = spawn_gate(Some(0)).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "insufficient_quota");
    assert_eq!(body["error"]["code"], "budget_exceeded");
    assert_eq!(gate.upstream.calls.load(Ordering::SeqCst), 0);

    let envs = gate.audit.envelopes.lock().unwrap().clone();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["op_body"]["outcome"], "denied:budget_exceeded");
    assert_eq!(envs[0]["result"], 2);
}

#[tokio::test]
async fn budget_enforced_after_accumulation() {
    // Budget 200: the first 140-token turn fits; the second is denied
    // (used 140 >= remaining check happens against 200? no — 140 < 200 so a
    // second turn runs; after 280 the third is denied).
    let gate = spawn_gate(Some(200)).await;
    let client = reqwest::Client::new();
    for _ in 0..2 {
        let resp = client
            .post(format!("{}/v1/chat/completions", gate.base))
            .bearer_auth(RELAY_KEY_1)
            .json(&chat_body(false))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    assert_eq!(gate.upstream.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn upstream_5xx_is_operator_logged_never_echoed() {
    let gate = spawn_gate(None).await;
    *gate.upstream.mode.lock().unwrap() = "http500".into();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains("SECRET-INTERNAL-DETAIL"),
        "upstream 5xx body must not be echoed: {text}"
    );
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"]["type"], "upstream_error");

    let envs = gate.audit.envelopes.lock().unwrap().clone();
    assert_eq!(envs[0]["op_body"]["outcome"], "upstream_error");
    assert_eq!(envs[0]["result"], 1);
}

#[tokio::test]
async fn upstream_4xx_is_forwarded_verbatim() {
    let gate = spawn_gate(None).await;
    *gate.upstream.mode.lock().unwrap() = "http404".into();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["message"], "model not found");
}

#[tokio::test]
async fn two_keys_roll_up_to_one_user_and_admin_sees_all() {
    let gate = spawn_gate(None).await;
    let client = reqwest::Client::new();
    for key in [RELAY_KEY_1, RELAY_KEY_2] {
        let resp = client
            .post(format!("{}/v1/chat/completions", gate.base))
            .bearer_auth(key)
            .json(&chat_body(false))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Both keys' usage accumulated to the ONE owning user.
    let usage: Value = client
        .get(format!("{}/v1/usage", gate.base))
        .bearer_auth(RELAY_KEY_2)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(usage["used_tokens"], 280);
    assert_eq!(usage["by_device"].as_array().unwrap().len(), 2);
    assert_eq!(usage["by_api_key"].as_array().unwrap().len(), 2);

    // Admin token: all-users view.
    let all: Value = client
        .get(format!("{}/v1/usage", gate.base))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 1);
    assert_eq!(all[0]["used_tokens"], 280);

    // A relay key cannot query another user.
    let other = format!("0x{}", "bb".repeat(32));
    let resp = client
        .get(format!("{}/v1/usage?user_omni={other}", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn models_passthrough_requires_a_key() {
    let gate = spawn_gate(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/models", gate.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = client
        .get(format!("{}/v1/models", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["data"][0]["id"], "ep-doubao");
}

// ─── #427 — broker-driven provisioning + per-delegate budgets ────────────────

#[tokio::test]
async fn admin_provisions_a_delegate_key_and_disable_refuses_turns() {
    let gate = spawn_gate(None).await;
    let client = reqwest::Client::new();
    let delegate_dkh = format!("0x{}", "11".repeat(32));

    // Non-admin provisioning is refused (a relay key is NOT an admin).
    let resp = client
        .post(format!("{}/v1/admin/keys", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&json!({"key_id": delegate_dkh, "user_omni": user_omni(), "device_id": delegate_dkh}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Admin provision (the broker's spawn-finalize call) → a one-shot secret.
    let resp = client
        .post(format!("{}/v1/admin/keys", gate.base))
        .bearer_auth("admintok")
        .json(&json!({
            "key_id": delegate_dkh,
            "user_omni": user_omni(),
            "delegate_omni": format!("0x{}", "cc".repeat(32)),
            "device_id": delegate_dkh,
            "label": "watchdog"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let minted: Value = resp.json().await.unwrap();
    let secret = minted["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("gk_"));

    // The minted key relays a turn and rolls up under its key_id.
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(&secret)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let usage: Value = client
        .get(format!("{}/v1/usage", gate.base))
        .bearer_auth(&secret)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(usage["by_api_key"][0]["api_key_id"], delegate_dkh);

    // Archive → disable (idempotent) → the very same secret is a plain 401.
    let resp = client
        .post(format!(
            "{}/v1/admin/keys/{delegate_dkh}/disable",
            gate.base
        ))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["disabled"], true);
    let resp = client
        .post(format!(
            "{}/v1/admin/keys/{delegate_dkh}/disable",
            gate.base
        ))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["disabled"], false);

    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(&secret)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn per_delegate_budget_429s_deterministically_under_the_user_budget() {
    // No user-level budget; the DELEGATE key carries its own 100-token ceiling.
    let gate = spawn_gate(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/admin/keys", gate.base))
        .bearer_auth("admintok")
        .json(&json!({
            "key_id": "delegate-b", "user_omni": user_omni(),
            "device_id": "delegate-b", "budget_tokens": 100u64
        }))
        .send()
        .await
        .unwrap();
    let secret = resp.json::<Value>().await.unwrap()["secret"]
        .as_str()
        .unwrap()
        .to_string();

    // First turn burns 140 tokens (over the 100 ceiling) — allowed (pre-burn
    // gate compares BEFORE the turn), second is the deterministic 429.
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(&secret)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(&secret)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "budget_exceeded");

    // The sibling boot key (same user) is untouched — the ceiling was
    // per-delegate, not per-user.
    let resp = client
        .post(format!("{}/v1/chat/completions", gate.base))
        .bearer_auth(RELAY_KEY_1)
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Denial audited as a GateTurn with the denied outcome.
    wait_for(
        || {
            gate.audit
                .envelopes
                .lock()
                .unwrap()
                .iter()
                .any(|e| e["op_body"]["outcome"] == "denied:budget_exceeded")
        },
        "denied GateTurn envelope",
    )
    .await;
}
