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

use std::collections::HashMap;
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
    /// Per-member bots: a confirmed-login payload the NEXT status poll returns
    /// (a member's own token / bot / user), and per-bearer inboxes so each
    /// bot's loop drains only its own messages.
    next_confirm: Mutex<Option<Value>>,
    inbox_by_auth: Mutex<HashMap<String, Vec<Value>>>,
    /// The field-observed shape (VE prod 2026-09-11): a send that carries no
    /// `context_token` — the only kind possible before the member's first message
    /// — does not reach them. The mock refuses it so the test proves the retry.
    reject_without_context: std::sync::atomic::AtomicBool,
}

async fn mock_qrcode() -> Json<Value> {
    Json(json!({ "qrcode": "qr-admin-1", "qrcode_img_content": "https://mock.ilink/qr/admin-1" }))
}

async fn mock_status(State(m): State<Arc<MockIlink>>) -> Json<Value> {
    if let Some(v) = m.next_confirm.lock().unwrap().take() {
        return Json(v);
    }
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
    m.getupdates_auth.lock().unwrap().push(auth.clone());
    let msgs: Vec<Value> = match m.inbox_by_auth.lock().unwrap().get_mut(&auth) {
        Some(own) => std::mem::take(own),
        None => m.inbox.lock().unwrap().drain(..).collect(),
    };
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
    let has_ctx = body["msg"]["context_token"]
        .as_str()
        .is_some_and(|c| !c.is_empty());
    if m.reject_without_context.load(Ordering::SeqCst) && !has_ctx {
        m.sends
            .lock()
            .unwrap()
            .push((auth, json!({ "rejected_no_context": body })));
        return Json(json!({ "ret": -1, "errmsg": "no context token (mock)" }));
    }
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
        ilink_tokens_file: String::new(),
        unknown_sender_hint: true,
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
        device: Default::default(),
        router: Default::default(),
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
    // #502: the daemon proxy fills the connecting master's omni server-side —
    // mirrored here. Recorded on `connected`, replacing the stale pre-stamped
    // value (the #464 hazard class this exists to fix).
    let session_omni = format!("0x{}", "cd".repeat(32));
    let start: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/login/start")))
        .json(&serde_json::json!({ "operator_omni": session_omni }))
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
    // #502: the CONNECT-recorded session omni REPLACED the stale pre-stamped
    // `0xfeed` (loudly, in the log) and persisted — restarts keep the session
    // truth, not the stale stamp.
    assert!(
        secrets.contains(&format!("AGENTKEYS_WEIXIN_OPERATOR_OMNI={session_omni}")),
        "connect-recorded omni not persisted: {secrets}"
    );
    assert!(!secrets.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xfeed"));
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
        // The codeless stranger is never routed — but is told what the bot is
        // waiting for, once (the L3 decision stays a drop; D13).
        let lurker: Vec<_> = sends
            .iter()
            .filter(|(_, b)| b["msg"]["to_user_id"] == "wxid-lurker")
            .collect();
        assert_eq!(
            lurker.len(),
            1,
            "codeless stranger gets exactly ONE bind hint: {sends:?}"
        );
        assert_eq!(
            lurker[0].1["msg"]["item_list"][0]["text_item"]["text"]
                .as_str()
                .unwrap(),
            agentkeys_worker_channel_weixin::relay::UNKNOWN_HINT_ZH
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
    // The tokens path is EMPTY in this config: the owner's bot is live but not
    // persisted — the status view must say so (a silent-until-restart loss).
    let st0: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/status")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st0["bots_unpersisted"], 1, "{st0}");

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
    // The member's half of the ceremony: the bound notice lands in her chat.
    wait_until("bound notice sent to grandma", || {
        mock.sends.lock().unwrap().iter().any(|(_, b)| {
            b["msg"]["to_user_id"] == "wxid-grandma"
                && b["msg"]["item_list"][0]["text_item"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("绑定成功") && t.contains("/storyteller"))
        })
    })
    .await;
    // …and the row records it (the code ceremony's context token made it deliverable now).
    let contacts: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/contacts")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grandma = contacts["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["contact_id"] == "c-grandma")
        .expect("grandma bound");
    assert_eq!(grandma["welcomed"], true, "{grandma}");

    // The NOW-BOUND contact's turn routes + acks (the full multi-user loop).
    // No feed is registered for the app on this gate, so the ack says the
    // message did not arrive (never «✅ 已转达»).
    mock.inbox
        .lock()
        .unwrap()
        .push(user_msg("wxid-grandma", "/storyteller 讲个故事", "ctx-g2"));
    wait_until("routed ack after approve", || {
        mock.sends.lock().unwrap().iter().any(|(_, b)| {
            b["msg"]["to_user_id"] == "wxid-grandma"
                && b["msg"]["item_list"][0]["text_item"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("没有送到 storyteller"))
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

const WIFE_TOKEN: &str = "wife@im.bot:e2e-secret-2";
const WIFE_BOT_ID: &str = "wife@im.bot";
const WIFE_USER: &str = "wife@im.wechat";

/// One bot per member (2026-09-11): the owner connects, mints an invite for
/// 太太, starts a login FOR that invite; her scan (the mock's confirmed status
/// with HER token) binds her with the invite's tier + reach, custodies her token
/// in the tokens file, starts her own inbound loop, and her `/chef` turn is
/// routed and acked ON HER OWN BOT; the revoke drops the bot again.
#[tokio::test]
async fn member_login_by_scan_binds_and_routes_on_its_own_bot() {
    let mock = Arc::new(MockIlink::default());
    let ilink_base = spawn_mock(mock.clone()).await;
    let registry_file = temp("m-registry.json");
    std::fs::write(&registry_file, r#"{"bound":[],"pending":[]}"#).unwrap();
    let secrets_file = temp("m-secrets.env");
    std::fs::write(&secrets_file, "AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xfeed\n").unwrap();
    let state_file = temp("m-state.json");
    let tokens_file = temp("m-tokens.json");
    for f in [&state_file, &tokens_file] {
        std::fs::remove_file(f).ok();
    }
    let cfg = WeixinGatewayConfig {
        ilink_tokens_file: tokens_file.clone(),
        unknown_sender_hint: true,
        bind: "127.0.0.1:0".into(),
        transport: WeixinTransport::Ilink,
        weixin_token: String::new(),
        weixin_app_id: String::new(),
        weixin_app_secret: None,
        ilink_bot_token: None,
        ilink_base_url: ilink_base.clone(),
        ilink_state_file: state_file.clone(),
        history_file: String::new(),
        activity_file: String::new(),
        secrets_file: secrets_file.clone(),
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
        device: Default::default(),
        router: Default::default(),
    };
    let state = Arc::new(WeixinGatewayState::build(cfg).unwrap());
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
    let poll_login = |login_id: String| {
        let http = http.clone();
        let gw = gw.clone();
        async move {
            for _ in 0..40 {
                let s: Value = http
                    .get(format!(
                        "{gw}/v1/gateway/admin/login/status?login_id={login_id}"
                    ))
                    .header("authorization", format!("Bearer {ADMIN}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if s["status"] != "wait" && s["status"] != "scaned" {
                    return s;
                }
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            }
            panic!("login never left wait");
        }
    };

    // ① the owner's own bot (the legacy login path — no contact id).
    let start: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/login/start")))
        .json(&json!({ "operator_omni": format!("0x{}", "cd".repeat(32)) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let owner = poll_login(start["login_id"].as_str().unwrap().to_string()).await;
    assert_eq!(owner["status"], "connected", "{owner}");

    // ② a login for an invite nobody minted is refused loudly.
    let unknown = bearer(http.post(format!("{gw}/v1/gateway/admin/login/start")))
        .json(&json!({ "contact_id": "c-nobody" }))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 422);

    // ③ invite 太太 (partner, reach chef), then a login FOR that invite.
    let inv: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/bind/invite")))
        .json(&json!({ "contact_id": "c-wife", "display_name": "太太", "tier": "partner", "reach": ["chef"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inv["ok"], true);
    *mock.next_confirm.lock().unwrap() = Some(json!({
        "status": "confirmed",
        "bot_token": WIFE_TOKEN,
        "ilink_bot_id": WIFE_BOT_ID,
        "baseurl": ilink_base.clone(),
        "ilink_user_id": WIFE_USER
    }));
    // From here every send without a context token is refused — the shape the
    // field showed: nothing can reach her bot before her first message.
    mock.reject_without_context.store(true, Ordering::SeqCst);
    // Her member state file already exists from a PREVIOUS bot (the 23:28 field
    // case: a re-connect resumed the old bot's file): its cursor and reply token
    // must never be used by her new bot — else the notice "succeeds" into nowhere.
    std::fs::write(
        agentkeys_worker_channel_weixin::bots::member_state_file(&state_file, "c-wife"),
        r#"{"bot_key":"0000000000000000","get_updates_buf":"old-cursor","context_tokens":{"wife@im.wechat":"stale-ctx"},"hint_sent_secs":{}}"#,
    )
    .unwrap();
    mock.inbox_by_auth
        .lock()
        .unwrap()
        .insert(format!("Bearer {WIFE_TOKEN}"), Vec::new());
    let start: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/login/start")))
        .json(&json!({ "contact_id": "c-wife" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(start["ok"], true, "{start}");
    let wife = poll_login(start["login_id"].as_str().unwrap().to_string()).await;
    assert_eq!(wife["status"], "connected", "{wife}");
    assert_eq!(wife["bot_id"], WIFE_BOT_ID);
    assert!(
        wife["detail"].as_str().unwrap().contains("bound:太太"),
        "{wife}"
    );

    // ④ the scan WAS the bind: tier + reach from the invite, her own bot live.
    let contacts: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/contacts")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = contacts["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["contact_id"] == "c-wife")
        .expect("wife bound");
    assert_eq!(row["tier"], "partner");
    assert_eq!(row["reach"], json!(["chef"]));
    assert_eq!(row["connected"], true);
    assert_eq!(
        row["welcomed"], false,
        "no context token yet — the notice waits for her first message: {row}"
    );
    assert!(
        !contacts.to_string().contains(WIFE_USER),
        "D13: no transport id in the contacts view"
    );
    let st: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/status")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["bots_online"], 2, "{st}");
    assert_eq!(st["bots_unpersisted"], 0, "both tokens are on disk: {st}");
    assert_eq!(
        st["open_invites"], 0,
        "the invite is consumed by the scan: {st}"
    );
    let tokens_raw = std::fs::read_to_string(&tokens_file).unwrap();
    assert!(
        tokens_raw.contains("c-wife")
            && tokens_raw.contains(WIFE_USER)
            && tokens_raw.contains(WIFE_TOKEN),
        "{tokens_raw}"
    );
    assert!(
        std::fs::read_to_string(&registry_file)
            .unwrap()
            .contains(WIFE_USER),
        "the registry row carries her transport id"
    );
    // her own loop polls with HER token; the bound notice went out on it
    wait_until("wife loop polling with her token", || {
        mock.getupdates_auth
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == &format!("Bearer {WIFE_TOKEN}"))
    })
    .await;
    // Nothing reaches her before her first message: the post-scan notice is
    // NOT sent token-less (the gate refuses that path itself — the mock's
    // rejection tripwire records any such attempt) and NEVER on the previous
    // bot's stale token. Give the bind's own attempt a beat to (wrongly) fire.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    {
        let sends = mock.sends.lock().unwrap();
        assert!(
            !sends
                .iter()
                .any(|(_, b)| b["rejected_no_context"]["msg"]["to_user_id"] == WIFE_USER),
            "a token-less send was attempted: {sends:?}"
        );
        assert!(
            !sends
                .iter()
                .any(|(_, b)| b["msg"]["to_user_id"] == WIFE_USER),
            "nothing delivered to her before her first message: {sends:?}"
        );
        assert!(
            !sends
                .iter()
                .any(|(_, b)| b["msg"]["context_token"] == "stale-ctx"),
            "the previous bot's reply token was reused: {sends:?}"
        );
    }

    // An operator re-send BEFORE her first message cannot deliver (her bot holds
    // no reply token yet) — it ARMS the acknowledgement instead, and sends nothing.
    let armed: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/contacts/welcome")))
        .json(&json!({ "contact_id": "c-wife" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(armed["ok"], true, "{armed}");
    assert_eq!(armed["sent"], false, "{armed}");
    assert!(
        armed["detail"].as_str().unwrap().contains("no reply token"),
        "{armed}"
    );
    assert!(
        !mock
            .sends
            .lock()
            .unwrap()
            .iter()
            .any(|(_, b)| b["msg"]["to_user_id"] == WIFE_USER),
        "an armed welcome sends nothing yet"
    );
    let unknown = bearer(http.post(format!("{gw}/v1/gateway/admin/contacts/welcome")))
        .json(&json!({ "contact_id": "nobody" }))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);

    // ⑤ her first turn arrives on her bot: the acknowledgement goes out FIRST
    //    (with this message's context token), then the routed ack.
    mock.inbox_by_auth
        .lock()
        .unwrap()
        .get_mut(&format!("Bearer {WIFE_TOKEN}"))
        .unwrap()
        .push(user_msg(WIFE_USER, "/chef 今晚吃什么", "ctx-w1"));
    wait_until("routed ack on the wife's bot", || {
        mock.sends.lock().unwrap().iter().any(|(auth, b)| {
            auth == &format!("Bearer {WIFE_TOKEN}")
                && b["msg"]["to_user_id"] == WIFE_USER
                && b["msg"]["item_list"][0]["text_item"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("没有送到 chef"))
        })
    })
    .await;
    {
        let sends = mock.sends.lock().unwrap();
        let hers: Vec<&str> = sends
            .iter()
            .filter(|(auth, b)| {
                auth == &format!("Bearer {WIFE_TOKEN}") && b["msg"]["to_user_id"] == WIFE_USER
            })
            .filter_map(|(_, b)| b["msg"]["item_list"][0]["text_item"]["text"].as_str())
            .collect();
        assert!(
            hers.len() == 2
                && hers[0].contains("绑定成功")
                && hers[0].contains("/chef")
                && hers[1].contains("没有送到 chef"),
            "the acknowledgement rides her first message, before the routed ack: {hers:?}"
        );
        assert!(
            sends
                .iter()
                .all(|(_, b)| b["msg"]["to_user_id"] != WIFE_USER
                    || b["msg"]["context_token"] == "ctx-w1"),
            "every delivered send to her rides her message's context token (never the stale one)"
        );
    }
    // Her loop dropped the previous bot's cursor: its file is now keyed to HER bot.
    let her_file = agentkeys_worker_channel_weixin::bots::member_state_file(&state_file, "c-wife");
    let persisted: Value =
        serde_json::from_str(&std::fs::read_to_string(&her_file).unwrap()).unwrap();
    assert_eq!(
        persisted["bot_key"],
        agentkeys_worker_channel_weixin::ilink_loop::bot_key(WIFE_TOKEN)
    );
    assert_ne!(persisted["get_updates_buf"], "old-cursor");
    let contacts: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/contacts")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = contacts["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["contact_id"] == "c-wife")
        .expect("wife bound");
    assert_eq!(row["welcomed"], true, "{row}");
    // A second message carries no second welcome. She reaches ONE app, so a
    // plain message goes straight to it (#722 single reach) — the receipt
    // rides her message's context token.
    mock.inbox_by_auth
        .lock()
        .unwrap()
        .get_mut(&format!("Bearer {WIFE_TOKEN}"))
        .unwrap()
        .push(user_msg(WIFE_USER, "你好，你是谁", "ctx-w2"));
    wait_until(
        "her plain message routes to her ONE app (single reach)",
        || {
            mock.sends.lock().unwrap().iter().any(|(auth, b)| {
                auth == &format!("Bearer {WIFE_TOKEN}")
                    && b["msg"]["context_token"] == "ctx-w2"
                    && b["msg"]["item_list"][0]["text_item"]["text"]
                        .as_str()
                        .is_some_and(|t| t.contains("没有送到 chef"))
            })
        },
    )
    .await;
    assert_eq!(
        mock.sends
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, b)| b["msg"]["to_user_id"] == WIFE_USER
                && b["msg"]["item_list"][0]["text_item"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("绑定成功")))
            .count(),
        1,
        "the acknowledgement is sent exactly once"
    );
    // An operator re-send AFTER her first message delivers now (her bot holds
    // her reply token) — the one sanctioned repeat.
    let resent: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/contacts/welcome")))
        .json(&json!({ "contact_id": "c-wife" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resent["sent"], true, "{resent}");
    wait_until("re-sent acknowledgement on her bot with her token", || {
        mock.sends
            .lock()
            .unwrap()
            .iter()
            .filter(|(auth, b)| {
                auth == &format!("Bearer {WIFE_TOKEN}")
                    && b["msg"]["to_user_id"] == WIFE_USER
                    && b["msg"]["context_token"] == "ctx-w2"
                    && b["msg"]["item_list"][0]["text_item"]["text"]
                        .as_str()
                        .is_some_and(|t| t.contains("绑定成功"))
            })
            .count()
            == 1
    })
    .await;
    assert!(
        mock.sends.lock().unwrap().iter().all(|(auth, b)| {
            !(auth == &format!("Bearer {MINTED_TOKEN}") && b["msg"]["to_user_id"] == WIFE_USER)
        }),
        "nothing to the wife ever rides the owner's bot"
    );

    // ⑥ revoke drops her bot with the contact.
    let rev: Value = bearer(http.post(format!("{gw}/v1/gateway/admin/contacts/revoke")))
        .json(&json!({ "contact_id": "c-wife" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rev["removed"], true);
    let st: Value = bearer(http.get(format!("{gw}/v1/gateway/admin/status")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["bots_online"], 1, "{st}");
    assert!(!std::fs::read_to_string(&tokens_file)
        .unwrap()
        .contains("c-wife"));

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), supervisor).await;
    for f in [registry_file, secrets_file, state_file, tokens_file] {
        std::fs::remove_file(&f).ok();
        std::fs::remove_file(format!("{f}.c-wife")).ok();
    }
}
