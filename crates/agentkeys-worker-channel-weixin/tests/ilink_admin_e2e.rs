//! Headless ADMIN-surface e2e (#418) — the parent-control flow end-to-end, no
//! real WeChat, no QR scan, no human:
//!
//!   login/start → QR minted → login/status (wait → confirmed) → the worker
//!   WRITES ITS OWN secrets file + HOT-STARTS the inbound loop (no restart) →
//!   bind/invite → the family member echoes the code (mock transport) → the
//!   claim ack goes back in-channel → bind/pending shows claimed → the master
//!   bind/approve → contact BOUND → their next `/alias` turn relays + acks.
//!
//! Also the gates: no admin bearer → 401; approving an UNCLAIMED invite → 409;
//! an unknown sender WITHOUT a code stays silent (the §9 rule survives the
//! ceremony exception).
//!
//! Boots the REAL router + supervisor against an in-process mock iLink API the
//! test scripts (a shared inbox the test pushes messages into).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use agentkeys_worker_channel_weixin::{
    handlers, ilink_loop, WeixinGatewayConfig, WeixinGatewayState, WeixinTransport,
};

const ADMIN: &str = "test-admin-bearer";
const MINTED_TOKEN: &str = "minted@im.bot:e2e-secret";
const MINTED_BOT_ID: &str = "minted@im.bot";

#[derive(Default)]
struct MockIlink {
    status_calls: AtomicUsize,
    base_url: Mutex<String>,
    /// Messages the TEST pushes; getupdates drains them (the scriptable inbox).
    inbox: Mutex<Vec<Value>>,
    /// (auth, body) per sendmessage.
    sends: Mutex<Vec<(String, Value)>>,
    getupdates_auth: Mutex<Vec<String>>,
}

async fn mock_qrcode() -> Json<Value> {
    Json(json!({ "qrcode": "qr-admin-1", "qrcode_img_content": "https://mock.ilink/qr/admin-1" }))
}

async fn mock_status(State(m): State<Arc<MockIlink>>) -> Json<Value> {
    let n = m.status_calls.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        return Json(json!({ "status": "wait" }));
    }
    Json(json!({
        "status": "confirmed",
        "bot_token": MINTED_TOKEN,
        "ilink_bot_id": MINTED_BOT_ID,
        "baseurl": m.base_url.lock().unwrap().clone(),
        "ilink_user_id": "scanner@im.wechat"
    }))
}

async fn mock_getupdates(
    State(m): State<Arc<MockIlink>>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    m.getupdates_auth.lock().unwrap().push(auth);
    let msgs: Vec<Value> = m.inbox.lock().unwrap().drain(..).collect();
    if msgs.is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
    Json(json!({ "ret": 0, "get_updates_buf": "cursor-admin", "msgs": msgs }))
}

async fn mock_sendmessage(
    State(m): State<Arc<MockIlink>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    m.sends.lock().unwrap().push((auth, body));
    Json(json!({ "ret": 0 }))
}

async fn mock_ok() -> Json<Value> {
    Json(json!({ "ret": 0 }))
}

async fn spawn_mock(m: Arc<MockIlink>) -> String {
    let app = Router::new()
        .route("/ilink/bot/get_bot_qrcode", post(mock_qrcode))
        .route("/ilink/bot/get_qrcode_status", get(mock_status))
        .route("/ilink/bot/getupdates", post(mock_getupdates))
        .route("/ilink/bot/sendmessage", post(mock_sendmessage))
        .route("/ilink/bot/msg/notifystart", post(mock_ok))
        .route("/ilink/bot/msg/notifystop", post(mock_ok))
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    *m.base_url.lock().unwrap() = base.clone();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

fn user_msg(from: &str, text: &str, ctx: &str) -> Value {
    json!({
        "from_user_id": from, "message_type": 1, "message_state": 2,
        "context_token": ctx,
        "item_list": [{"type": 1, "text_item": {"text": text}}]
    })
}

fn temp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("ak-admin-e2e-{name}-{}", std::process::id()))
        .to_string_lossy()
        .to_string()
}

async fn wait_until<F: Fn() -> bool>(what: &str, f: F) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !f() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn parent_control_flow_login_hotswap_bind_approve_relay() {
    let mock = Arc::new(MockIlink::default());
    let ilink_base = spawn_mock(mock.clone()).await;

    let registry_file = temp("registry.json");
    std::fs::write(&registry_file, r#"{"bound":[],"pending":[]}"#).unwrap();
    let secrets_file = temp("secrets.env");
    std::fs::write(
        &secrets_file,
        "AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xfeed\nAGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=REPLACE_ME\n",
    )
    .unwrap();
    let state_file = temp("state.json");
    std::fs::remove_file(&state_file).ok();

    let cfg = WeixinGatewayConfig {
        bind: "127.0.0.1:0".into(),
        transport: WeixinTransport::Ilink,
        weixin_token: String::new(),
        weixin_app_id: String::new(),
        weixin_app_secret: None,
        // KEY: boots OFFLINE — the admin ceremony brings it online.
        ilink_bot_token: None,
        ilink_base_url: ilink_base.clone(),
        ilink_state_file: state_file.clone(),
        history_file: String::new(),
        activity_file: String::new(),
        secrets_file: secrets_file.clone(),
        // The QR ceremony boots from the bootstrap host — point it at the mock
        // (the prod default is the fixed Tencent host).
        ilink_bootstrap_url: ilink_base.clone(),
        bot_agent: "AgentKeys/test".into(),
        telegram_bot_token: None,
        telegram_api_base: agentkeys_worker_channel_weixin::telegram::TELEGRAM_API_BASE.into(),
        telegram_state_file: "/dev/null".into(),
        registry_file: registry_file.clone(),
        channel_worker_url: None,
        operator_omni: format!("0x{}", "ab".repeat(32)),
        audit_worker_url: None,
        operator_grade_aliases: vec!["spend".into()],
        parent_control_deeplink: "https://pc.local/".into(),
        rate_max: 100,
        rate_window_secs: 60,
        router_enabled: true,
        admin_token: Some(ADMIN.into()),
        allow_unsigned: false,
    };
    let state = Arc::new(WeixinGatewayState::build(cfg).unwrap());

    // The real supervisor (idles — no token yet) + the real HTTP surface.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let supervisor = tokio::spawn(ilink_loop::supervise(state.clone(), shutdown_rx));
    let app = handlers::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let http = reqwest::Client::new();
    let bearer = |r: reqwest::RequestBuilder| r.header("authorization", format!("Bearer {ADMIN}"));

    // ── gates first: no bearer → 401; wrong login id → 404 ──────────────────
    let unauth = http
        .post(format!("{gw}/v1/gateway/admin/login/start"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401, "admin surface must never be open");

    // ── status: offline before the ceremony ─────────────────────────────────
    let st: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/status")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["online"], false);
    assert_eq!(st["transport"], "ilink");

    // ── login ceremony over HTTP ─────────────────────────────────────────────
    let start: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/login/start")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(start["ok"], true);
    let login_id = start["login_id"].as_str().unwrap().to_string();
    assert!(start["qrcode_url"]
        .as_str()
        .unwrap()
        .starts_with("https://"));

    // poll 1 → wait; poll 2 → confirmed → connected (+ hot-swap).
    let s1: Value = bearer(http.get(format!(
        "{gw}/v1/gateway/admin/login/status?login_id={login_id}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(s1["status"], "wait");
    let s2: Value = bearer(http.get(format!(
        "{gw}/v1/gateway/admin/login/status?login_id={login_id}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(s2["status"], "connected", "confirmed → connected: {s2}");
    assert_eq!(s2["bot_id"], MINTED_BOT_ID);

    // #384 custody: the worker wrote its OWN secrets file (placeholder filled,
    // other keys preserved) …
    let secrets = std::fs::read_to_string(&secrets_file).unwrap();
    assert!(secrets.contains(&format!("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN={MINTED_TOKEN}")));
    assert!(secrets.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xfeed"));
    assert!(!secrets.contains("REPLACE_ME"));
    // … and the supervisor HOT-STARTED the loop on the minted token.
    wait_until("loop polls with the minted token", || {
        mock.getupdates_auth
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == &format!("Bearer {MINTED_TOKEN}"))
    })
    .await;
    let st: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/status")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["online"], true);
    assert_eq!(st["bot_id"], MINTED_BOT_ID);

    // ── bind ceremony ────────────────────────────────────────────────────────
    let invite: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/bind/invite")))
        .json(&json!({
            "contact_id": "c-grandma", "display_name": "奶奶",
            "tier": "elder", "reach": ["storyteller"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(invite["ok"], true);
    let code = invite["bind_code"].as_str().unwrap().to_string();
    assert!(invite["send_text"].as_str().unwrap().contains(&code));

    // Approving BEFORE anyone claimed → 409 bind_not_claimed.
    let early = bearer(http.post(format!("{gw}/v1/gateway/admin/bind/approve")))
        .json(&json!({ "bind_code": code }))
        .send()
        .await
        .unwrap();
    assert_eq!(early.status(), 409);

    // A stranger WITHOUT a code stays silent; the invited one echoes the code.
    mock.inbox
        .lock()
        .unwrap()
        .push(user_msg("wxid-lurker", "hello?", "ctx-lurker"));
    mock.inbox
        .lock()
        .unwrap()
        .push(user_msg("wxid-grandma", &format!("绑定 {code}"), "ctx-g1"));

    wait_until("claim ack sent to grandma", || {
        mock.sends
            .lock()
            .unwrap()
            .iter()
            .any(|(_, b)| b["msg"]["to_user_id"] == "wxid-grandma")
    })
    .await;
    {
        let sends = mock.sends.lock().unwrap();
        assert!(
            sends
                .iter()
                .all(|(_, b)| b["msg"]["to_user_id"] != "wxid-lurker"),
            "codeless stranger must get SILENCE: {sends:?}"
        );
        let (_, ack) = sends
            .iter()
            .find(|(_, b)| b["msg"]["to_user_id"] == "wxid-grandma")
            .unwrap();
        assert!(ack["msg"]["item_list"][0]["text_item"]["text"]
            .as_str()
            .unwrap()
            .contains("已收到绑定码"));
    }

    // The approve queue shows the claimed invite — D13-safe (no openid anywhere).
    let pending: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/bind/pending")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = &pending["pending"][0];
    assert_eq!(row["bind_code"], code.as_str());
    assert_eq!(row["claimed"], true);
    assert!(
        !pending.to_string().contains("wxid-grandma"),
        "pending view leaked an openid (D13 breach): {pending}"
    );

    // Master approve → BOUND.
    let approved: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/bind/approve")))
        .json(&json!({ "bind_code": code }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(approved["ok"], true);
    assert_eq!(approved["contact"]["contact_id"], "c-grandma");
    assert_eq!(approved["contact"]["tier"], "elder");

    // The NOW-BOUND contact's turn routes + acks (the full multi-user loop).
    mock.inbox
        .lock()
        .unwrap()
        .push(user_msg("wxid-grandma", "/storyteller 讲个故事", "ctx-g2"));
    wait_until("routed ack after approve", || {
        mock.sends.lock().unwrap().iter().any(|(_, b)| {
            b["msg"]["to_user_id"] == "wxid-grandma"
                && b["msg"]["item_list"][0]["text_item"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("已转达给 storyteller"))
        })
    })
    .await;

    // The registry file persisted the bound contact (a restart keeps it).
    let reg_raw = std::fs::read_to_string(&registry_file).unwrap();
    assert!(reg_raw.contains("c-grandma") && reg_raw.contains("wxid-grandma"));

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), supervisor).await;
    for f in [registry_file, secrets_file, state_file] {
        std::fs::remove_file(f).ok();
    }
}
