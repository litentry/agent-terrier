//! In-process Telegram transport flow test (#444) — boots a MOCK Bot API on an
//! ephemeral port and drives the REAL long-poll loop + relay core against it.
//! No env mutation (config built directly), no deployed infra, no real
//! Telegram. The LIVE proof (a real BotFather bot) is the operator gate.
//!
//! Proves, in one pass — the #407 phase-2 assertions on the new transport:
//! - the loop polls with the custodied bot token (in the URL, the Bot API way),
//! - a bound contact's `/alias` turn is routed and ACKED in ENGLISH,
//! - an out-of-reach ask gets the refusal text,
//! - an operator-grade ask gets the parent-control deep-link, never data,
//! - an UNKNOWN sender is dropped SILENTLY (no send — §9 threat 1),
//! - bot-authored and NON-PRIVATE (group) messages are skipped entirely,
//! - the offset cursor + reply chat ids persist to the state file.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use agentkeys_worker_channel_weixin::{
    telegram_loop, WeixinGatewayConfig, WeixinGatewayState, WeixinTransport,
};

#[derive(Default)]
struct MockBotApi {
    get_updates_calls: AtomicUsize,
    /// (bot path segment, offset query) per getUpdates call.
    polls: Mutex<Vec<(String, String)>>,
    /// (bot path segment, body) per sendMessage call.
    sends: Mutex<Vec<(String, serde_json::Value)>>,
}

async fn mock_get_updates(
    State(mock): State<Arc<MockBotApi>>,
    Path(bot): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    mock.polls
        .lock()
        .unwrap()
        .push((bot, q.get("offset").cloned().unwrap_or_default()));
    let n = mock.get_updates_calls.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        // One batch: routed owner turn · out-of-reach kid · operator-grade ask ·
        // a stranger · a bot echo (skipped) · a group message (skipped).
        Json(json!({ "ok": true, "result": [
            {"update_id": 11, "message": {"message_id": 1,
             "from": {"id": 1001, "is_bot": false}, "chat": {"id": 1001, "type": "private"},
             "text": "/chef what's for dinner"}},
            {"update_id": 12, "message": {"message_id": 2,
             "from": {"id": 1002, "is_bot": false}, "chat": {"id": 1002, "type": "private"},
             "text": "/chef candy please"}},
            {"update_id": 13, "message": {"message_id": 3,
             "from": {"id": 1001, "is_bot": false}, "chat": {"id": 1001, "type": "private"},
             "text": "/spend how much this week"}},
            {"update_id": 14, "message": {"message_id": 4,
             "from": {"id": 1003, "is_bot": false}, "chat": {"id": 1003, "type": "private"},
             "text": "/chef hi"}},
            {"update_id": 15, "message": {"message_id": 5,
             "from": {"id": 2000, "is_bot": true}, "chat": {"id": 1001, "type": "private"},
             "text": "bot echo"}},
            {"update_id": 16, "message": {"message_id": 6,
             "from": {"id": 1001, "is_bot": false}, "chat": {"id": -777, "type": "group"},
             "text": "/chef group ask"}}
        ]}))
    } else {
        // Quiet long-poll: short hold, no updates.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        Json(json!({ "ok": true, "result": [] }))
    }
}

async fn mock_send_message(
    State(mock): State<Arc<MockBotApi>>,
    Path(bot): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    mock.sends.lock().unwrap().push((bot, body));
    Json(json!({ "ok": true, "result": {} }))
}

async fn spawn_mock_bot_api(mock: Arc<MockBotApi>) -> String {
    let app = Router::new()
        .route("/:bot/getUpdates", get(mock_get_updates))
        .route("/:bot/sendMessage", post(mock_send_message))
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
        {"contact_id":"c-owner","transport":"telegram","transport_id":"1001",
         "display_name":"Alex","tier":"owner","reach":["chef"]},
        {"contact_id":"c-kid","transport":"telegram","transport_id":"1002",
         "display_name":"Sam","tier":"kid","reach":["storyteller"]}
      ],
      "pending": []
    }"#;
    let path = std::env::temp_dir().join(format!("ak-tg-reg-{}.json", std::process::id()));
    std::fs::write(&path, json).unwrap();
    path.to_string_lossy().to_string()
}

fn config(api_base: String, registry_file: String, state_file: String) -> WeixinGatewayConfig {
    WeixinGatewayConfig {
        bind: "127.0.0.1:0".into(),
        transport: WeixinTransport::Telegram,
        weixin_token: String::new(), // OA-only — unused under telegram
        weixin_app_id: String::new(),
        weixin_app_secret: None,
        ilink_bot_token: None,
        ilink_base_url: agentkeys_worker_channel_weixin::ilink::ILINK_BOOTSTRAP_BASE_URL.into(),
        ilink_state_file: "/dev/null".into(),
        history_file: String::new(),
        activity_file: String::new(),
        secrets_file: std::env::temp_dir()
            .join(format!("ak-tg-flow-secrets-{}.env", std::process::id()))
            .to_string_lossy()
            .to_string(),
        ilink_bootstrap_url: agentkeys_worker_channel_weixin::ilink::ILINK_BOOTSTRAP_BASE_URL
            .into(),
        bot_agent: "AgentKeys/test".into(),
        telegram_bot_token: Some("123:test-tg-token".into()),
        telegram_api_base: api_base,
        telegram_state_file: state_file,
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
        allow_unsigned: false, // irrelevant — the telegram path never checks OA signatures
    }
}

#[tokio::test]
async fn telegram_loop_relays_replies_persists_and_stops() {
    let mock = Arc::new(MockBotApi::default());
    let api_base = spawn_mock_bot_api(mock.clone()).await;
    let state_file = std::env::temp_dir()
        .join(format!("ak-tg-state-{}.json", std::process::id()))
        .to_string_lossy()
        .to_string();
    std::fs::remove_file(&state_file).ok();

    let cfg = config(api_base, write_registry(), state_file.clone());
    let state = Arc::new(WeixinGatewayState::build(cfg).unwrap());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(telegram_loop::run(state.clone(), shutdown_rx));

    // Wait until the three replies (ack + refusal + deep-link) land — the
    // stranger, the bot echo, and the group message get NOTHING.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if mock.sends.lock().unwrap().len() >= 3 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "loop never sent the three replies"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Give the loop a beat to (wrongly) send more — the rest must stay silent.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    {
        let sends = mock.sends.lock().unwrap();
        assert_eq!(
            sends.len(),
            3,
            "exactly ack + refusal + deep-link — unknown/bot/group are dropped SILENTLY: {sends:?}"
        );

        // The custodied token authenticates every call (it IS the URL, Bot-API style).
        assert!(sends.iter().all(|(bot, _)| bot == "bot123:test-tg-token"));

        let (_, ack) = &sends[0];
        assert_eq!(ack["chat_id"], 1001);
        let ack_text = ack["text"].as_str().unwrap();
        assert!(
            ack_text.contains("Passed along to chef"),
            "routed ack is ENGLISH and names the target: {ack_text}"
        );

        let (_, refusal) = &sends[1];
        assert_eq!(refusal["chat_id"], 1002);
        assert!(
            refusal["text"]
                .as_str()
                .unwrap()
                .contains("don't have access"),
            "out-of-reach ask is refused in-channel: {refusal:?}"
        );

        let (_, deeplink) = &sends[2];
        assert_eq!(deeplink["chat_id"], 1001);
        let dl_text = deeplink["text"].as_str().unwrap();
        assert!(
            dl_text.contains("parent-control") && dl_text.contains("https://pc.local/"),
            "operator-grade ask gets the deep-link, never data: {dl_text}"
        );

        // The second poll acknowledged the whole batch: offset = 16 + 1.
        let polls = mock.polls.lock().unwrap();
        assert!(polls.len() >= 2);
        assert_eq!(polls[0].1, "0", "first poll starts at the fresh cursor");
        assert_eq!(polls[1].1, "17", "second poll acknowledges the batch");
    }

    // The cursor + reply chat ids survived to disk.
    let persisted: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_file).unwrap()).unwrap();
    assert_eq!(persisted["next_offset"], 17);
    assert_eq!(persisted["chat_ids"]["1001"], 1001);
    assert_eq!(
        persisted["chat_ids"]["1003"], 1003,
        "chat ids are stored even for dropped senders (a later bind can reply)"
    );

    // Shutdown stops the loop.
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .expect("loop did not stop on shutdown")
        .unwrap();

    std::fs::remove_file(&state_file).ok();
}
