//! The admin API surface parent-control talks to, in-process: the real router
//! on an ephemeral port, the admin bearer gate, the contact registry reads +
//! mutations, the observability reads (monitor / history / activity), the
//! device-actor status, and the refusals (no bearer, wrong bearer, denied
//! history, the device pairing without a broker). No env mutation, no infra.

use std::sync::Arc;

use agentkeys_worker_channel_weixin::{handlers, WeixinGatewayConfig, WeixinGatewayState};

fn write_registry() -> String {
    let json = r#"{
      "bound": [
        {"contact_id":"c-owner","transport":"weixin","transport_id":"openid-owner",
         "display_name":"妈妈","tier":"owner","reach":["chef","doorkeeper"]},
        {"contact_id":"c-kid","transport":"weixin","transport_id":"openid-kid",
         "display_name":"小明","tier":"kid","reach":["storyteller"]}
      ],
      "pending": []
    }"#;
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "ak-admin-surface-{}-{seq}.json",
        std::process::id()
    ));
    std::fs::write(&path, json).unwrap();
    path.to_string_lossy().to_string()
}

fn config(registry_file: String) -> WeixinGatewayConfig {
    let dir = std::env::temp_dir().join(format!("ak-admin-surface-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    WeixinGatewayConfig {
        bind: "127.0.0.1:0".into(),
        transport: agentkeys_worker_channel_weixin::WeixinTransport::Oa,
        weixin_token: "test-token".into(),
        weixin_app_id: "wxtest".into(),
        weixin_app_secret: None,
        ilink_bot_token: None,
        ilink_base_url: agentkeys_worker_channel_weixin::ilink::ILINK_BOOTSTRAP_BASE_URL.into(),
        ilink_state_file: "/dev/null".into(),
        history_file: dir.join("history.jsonl").to_string_lossy().to_string(),
        activity_file: dir.join("activity.jsonl").to_string_lossy().to_string(),
        secrets_file: "/dev/null".into(),
        ilink_bootstrap_url: agentkeys_worker_channel_weixin::ilink::ILINK_BOOTSTRAP_BASE_URL
            .into(),
        bot_agent: "AgentKeys/test".into(),
        telegram_bot_token: None,
        telegram_api_base: agentkeys_worker_channel_weixin::telegram::TELEGRAM_API_BASE.into(),
        telegram_state_file: "/dev/null".into(),
        registry_file,
        channel_worker_url: None,
        operator_omni: format!("0x{}", "ab".repeat(32)),
        audit_worker_url: None,
        operator_grade_aliases: vec!["spend".into()],
        parent_control_deeplink: "https://pc.local/".into(),
        rate_max: 100,
        rate_window_secs: 60,
        router_enabled: true,
        admin_token: Some("admin-secret".into()),
        allow_unsigned: true,
        device: Default::default(),
    }
}

async fn spawn() -> String {
    let state = Arc::new(WeixinGatewayState::build(config(write_registry())).unwrap());
    let app = handlers::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn get(base: &str, path: &str, bearer: Option<&str>) -> (u16, serde_json::Value) {
    let mut r = reqwest::Client::new().get(format!("{base}{path}"));
    if let Some(b) = bearer {
        r = r.bearer_auth(b);
    }
    let resp = r.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn post(
    base: &str,
    path: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut r = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .json(&body);
    if let Some(b) = bearer {
        r = r.bearer_auth(b);
    }
    let resp = r.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn the_admin_bearer_gates_every_admin_route() {
    let base = spawn().await;
    for path in [
        "/v1/gateway/admin/status",
        "/v1/gateway/admin/contacts",
        "/v1/gateway/admin/monitor",
        "/v1/gateway/admin/history",
        "/v1/gateway/admin/activity",
        "/v1/gateway/admin/device/status",
    ] {
        let (status, _) = get(&base, path, None).await;
        assert!(
            status == 401 || status == 403,
            "{path} without a bearer → {status}"
        );
        let (status, _) = get(&base, path, Some("wrong")).await;
        assert!(
            status == 401 || status == 403,
            "{path} with a wrong bearer → {status}"
        );
    }
    // The public history route is denied by design (D13 — no transcript leaves the gate).
    let (status, _) = get(&base, "/v1/gateway/history", Some("admin-secret")).await;
    assert!(status >= 400, "public history is denied: {status}");
}

#[tokio::test]
async fn status_contacts_and_the_observability_reads_answer_the_console() {
    let base = spawn().await;
    let (status, st) = get(&base, "/v1/gateway/admin/status", Some("admin-secret")).await;
    assert_eq!(status, 200, "{st}");
    assert!(
        st.get("transport").is_some() || st.get("ok").is_some(),
        "{st}"
    );
    let (status, contacts) = get(&base, "/v1/gateway/admin/contacts", Some("admin-secret")).await;
    assert_eq!(status, 200, "{contacts}");
    let list = contacts["contacts"].as_array().expect("contacts array");
    assert_eq!(list.len(), 2);
    assert!(list
        .iter()
        .any(|c| c["contact_id"] == "c-kid" && c["tier"] == "kid"));
    // The D13-safe public view carries tier + reach, never openids.
    let (status, public) = get(&base, "/v1/gateway/contacts", Some("admin-secret")).await;
    assert_eq!(status, 200, "{public}");
    assert!(!public.to_string().contains("openid-owner"), "{public}");
    for path in [
        "/v1/gateway/admin/monitor",
        "/v1/gateway/admin/history",
        "/v1/gateway/admin/activity",
    ] {
        let (status, body) = get(&base, path, Some("admin-secret")).await;
        assert_eq!(status, 200, "{path}: {body}");
    }
    let (status, dev) = get(
        &base,
        "/v1/gateway/admin/device/status",
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, 200, "{dev}");
    assert_eq!(dev["configured"], false);
    assert_eq!(dev["enrolled"], false);
    assert_eq!(dev["feed_hop"], false);
    // No broker / device key on this gate: a pairing request is refused loudly.
    let (status, _) = post(
        &base,
        "/v1/gateway/admin/device/pairing-request",
        Some("admin-secret"),
        serde_json::json!({}),
    )
    .await;
    assert!(status >= 400);
}

#[tokio::test]
async fn contact_update_and_revoke_change_the_registry_the_console_reads_back() {
    let base = spawn().await;
    let (status, upd) = post(
        &base,
        "/v1/gateway/admin/contacts/update",
        Some("admin-secret"),
        serde_json::json!({ "contact_id": "c-kid", "tier": "partner", "reach": ["chef"] }),
    )
    .await;
    assert_eq!(status, 200, "{upd}");
    let (_, contacts) = get(&base, "/v1/gateway/admin/contacts", Some("admin-secret")).await;
    let kid = contacts["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["contact_id"] == "c-kid")
        .unwrap()
        .clone();
    assert_eq!(kid["tier"], "partner");
    assert_eq!(kid["reach"], serde_json::json!(["chef"]));
    // An unknown contact is a 404, never a silent no-op.
    let (status, _) = post(
        &base,
        "/v1/gateway/admin/contacts/update",
        Some("admin-secret"),
        serde_json::json!({ "contact_id": "c-nobody", "tier": "kid" }),
    )
    .await;
    assert!(status >= 400);
    let (status, rev) = post(
        &base,
        "/v1/gateway/admin/contacts/revoke",
        Some("admin-secret"),
        serde_json::json!({ "contact_id": "c-kid" }),
    )
    .await;
    assert_eq!(status, 200, "{rev}");
    let (_, contacts) = get(&base, "/v1/gateway/admin/contacts", Some("admin-secret")).await;
    assert!(!contacts["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["contact_id"] == "c-kid"));
    // A revoked contact's turn is dropped silently at the gate (unknown sender).
    let resp = reqwest::Client::new()
        .post(format!("{base}/wechat/callback"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "from": "openid-kid", "text": "/storyteller hi" }).to_string())
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    assert_eq!(body["ok"], false, "{body}");
    // Activity recorded the two control actions.
    let (status, act) = get(&base, "/v1/gateway/admin/activity", Some("admin-secret")).await;
    assert_eq!(status, 200, "{act}");
    assert!(act.to_string().contains("revoked"), "{act}");
}
