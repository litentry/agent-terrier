//! In-process iLink transport flow test — boots a MOCK iLink API (the
//! openclaw-weixin wire shapes) on an ephemeral port and drives the REAL
//! long-poll loop + relay core against it. No env mutation (config built
//! directly), no deployed infra, no real WeChat. The LIVE proof (a real spare
//! personal account through `--login`) is the operator gate.
//!
//! Proves, in one pass:
//! - the loop authenticates with the custodied bearer token,
//! - a bound contact's `/alias` turn is routed and ACKED with the sender's
//!   `context_token` echoed (the reply authorization),
//! - an out-of-reach ask gets the refusal text,
//! - an UNKNOWN sender is dropped SILENTLY (no send — §9 threat 1),
//! - the resumable cursor + reply tokens persist to the state file,
//! - shutdown stops the loop and fires the best-effort notifystop.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use serde_json::json;

use agentkeys_worker_channel_weixin::{
    ilink_loop, WeixinGatewayConfig, WeixinGatewayState, WeixinTransport,
};

#[derive(Default)]
struct MockIlink {
    get_updates_calls: AtomicUsize,
    notifystop_calls: AtomicUsize,
    /// (auth header, body) per sendmessage call.
    sends: Mutex<Vec<(String, serde_json::Value)>>,
    /// auth header seen on getupdates.
    getupdates_auth: Mutex<Vec<String>>,
}

async fn mock_getupdates(
    State(mock): State<Arc<MockIlink>>,
    headers: axum::http::HeaderMap,
    Json(_body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    mock.getupdates_auth.lock().unwrap().push(auth);
    let n = mock.get_updates_calls.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        // One batch: a routed turn, an out-of-reach ask, and a stranger.
        Json(json!({
            "ret": 0,
            "get_updates_buf": "cursor-1",
            "longpolling_timeout_ms": 1000,
            "msgs": [
                {"from_user_id": "wxid-kid", "message_type": 1, "message_state": 2,
                 "context_token": "ctx-kid-1", "create_time_ms": 1789000000000u64,
                 "item_list": [{"type": 1, "text_item": {"text": "/storyteller 讲个故事"}}]},
                {"from_user_id": "wxid-kid", "message_type": 1, "message_state": 2,
                 "context_token": "ctx-kid-2",
                 "item_list": [{"type": 1, "text_item": {"text": "/chef 我要吃糖"}}]},
                {"from_user_id": "wxid-stranger", "message_type": 1, "message_state": 2,
                 "context_token": "ctx-stranger",
                 "item_list": [{"type": 1, "text_item": {"text": "/storyteller hi"}}]},
                // Our own BOT echo — must be skipped (not USER-authored).
                {"from_user_id": "wxid-bot", "message_type": 2,
                 "item_list": [{"type": 1, "text_item": {"text": "echo"}}]}
            ]
        }))
    } else {
        // Quiet long-poll: short hold, no messages, same cursor.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        Json(json!({ "ret": 0, "get_updates_buf": "cursor-1", "msgs": [] }))
    }
}

async fn mock_sendmessage(
    State(mock): State<Arc<MockIlink>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    mock.sends.lock().unwrap().push((auth, body));
    Json(json!({ "ret": 0 }))
}

async fn mock_notify_ok() -> Json<serde_json::Value> {
    Json(json!({ "ret": 0 }))
}

async fn mock_notifystop(State(mock): State<Arc<MockIlink>>) -> Json<serde_json::Value> {
    mock.notifystop_calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({ "ret": 0 }))
}

async fn spawn_mock_ilink(mock: Arc<MockIlink>) -> String {
    let app = Router::new()
        .route("/ilink/bot/getupdates", post(mock_getupdates))
        .route("/ilink/bot/sendmessage", post(mock_sendmessage))
        .route("/ilink/bot/msg/notifystart", post(mock_notify_ok))
        .route("/ilink/bot/msg/notifystop", post(mock_notifystop))
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn write_registry() -> String {
    let json = r#"{
      "bound": [
        {"contact_id":"c-kid","transport":"weixin","transport_id":"wxid-kid",
         "display_name":"小明","tier":"kid","reach":["storyteller"]}
      ],
      "pending": []
    }"#;
    let path = std::env::temp_dir().join(format!("ak-ilink-reg-{}.json", std::process::id()));
    std::fs::write(&path, json).unwrap();
    path.to_string_lossy().to_string()
}

fn config(base_url: String, registry_file: String, state_file: String) -> WeixinGatewayConfig {
    WeixinGatewayConfig {
        bind: "127.0.0.1:0".into(),
        transport: WeixinTransport::Ilink,
        weixin_token: String::new(), // OA-only — unused under ilink
        weixin_app_id: String::new(),
        weixin_app_secret: None,
        ilink_bot_token: Some("test-ilink-token".into()),
        ilink_base_url: base_url,
        ilink_state_file: state_file,
        secrets_file: std::env::temp_dir()
            .join(format!("ak-ilink-flow-secrets-{}.env", std::process::id()))
            .to_string_lossy()
            .to_string(),
        ilink_bootstrap_url: agentkeys_worker_channel_weixin::ilink::ILINK_BOOTSTRAP_BASE_URL
            .into(),
        bot_agent: "AgentKeys/test".into(),
        registry_file,
        channel_worker_url: None,
        operator_omni: format!("0x{}", "ab".repeat(32)),
        audit_worker_url: None, // audit disabled — no external dep in the test
        operator_grade_aliases: vec!["spend".into()],
        parent_control_deeplink: "https://pc.local/".into(),
        rate_max: 100,
        rate_window_secs: 60,
        router_enabled: true,
        admin_token: None,
        allow_unsigned: false, // irrelevant — the iLink path never checks OA signatures
    }
}

#[tokio::test]
async fn ilink_loop_relays_replies_persists_and_stops() {
    let mock = Arc::new(MockIlink::default());
    let base_url = spawn_mock_ilink(mock.clone()).await;
    let state_file = std::env::temp_dir()
        .join(format!("ak-ilink-state-{}.json", std::process::id()))
        .to_string_lossy()
        .to_string();
    std::fs::remove_file(&state_file).ok();

    let cfg = config(base_url, write_registry(), state_file.clone());
    let state = Arc::new(WeixinGatewayState::build(cfg).unwrap());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(ilink_loop::run(state.clone(), shutdown_rx));

    // Wait until both replies (ack + refusal) land — the stranger gets NOTHING.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if mock.sends.lock().unwrap().len() >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "loop never sent the two replies"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Give the loop a beat to (wrongly) send more — the stranger must stay silent.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    {
        let sends = mock.sends.lock().unwrap();
        assert_eq!(
            sends.len(),
            2,
            "exactly ack + refusal — an unknown sender is dropped SILENTLY: {sends:?}"
        );

        let (auth, ack) = &sends[0];
        assert_eq!(auth, "Bearer test-ilink-token");
        assert_eq!(ack["msg"]["to_user_id"], "wxid-kid");
        assert_eq!(ack["msg"]["message_type"], 2);
        assert_eq!(ack["msg"]["message_state"], 2);
        let ack_text = ack["msg"]["item_list"][0]["text_item"]["text"]
            .as_str()
            .unwrap();
        assert!(
            ack_text.contains("已转达给 storyteller"),
            "routed ack names the target: {ack_text}"
        );
        // Each reply echoes THAT message's context token (per-message store-
        // then-reply order): the ack rides msg 1's token…
        assert_eq!(ack["msg"]["context_token"], "ctx-kid-1");

        let (_, refusal) = &sends[1];
        assert_eq!(refusal["msg"]["to_user_id"], "wxid-kid");
        // …and the refusal rides msg 2's.
        assert_eq!(refusal["msg"]["context_token"], "ctx-kid-2");
        let refusal_text = refusal["msg"]["item_list"][0]["text_item"]["text"]
            .as_str()
            .unwrap();
        assert!(
            refusal_text.contains("没有访问"),
            "out-of-reach ask is refused in-channel: {refusal_text}"
        );

        let gu_auth = mock.getupdates_auth.lock().unwrap();
        assert!(gu_auth.iter().all(|a| a == "Bearer test-ilink-token"));
    }

    // The cursor + reply tokens survived to disk.
    let persisted: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_file).unwrap()).unwrap();
    assert_eq!(persisted["get_updates_buf"], "cursor-1");
    assert_eq!(persisted["context_tokens"]["wxid-kid"], "ctx-kid-2");
    assert_eq!(
        persisted["context_tokens"]["wxid-stranger"], "ctx-stranger",
        "reply tokens are stored even for dropped senders (a later bind can reply)"
    );

    // Shutdown stops the loop and fires the best-effort notifystop.
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .expect("loop did not stop on shutdown")
        .unwrap();
    assert!(mock.notifystop_calls.load(Ordering::SeqCst) >= 1);

    std::fs::remove_file(&state_file).ok();
}
