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
      "pending": [],
      "apps": [
        {"alias":"chef","channel_id":"family-chat"},
        {"alias":"doorkeeper","channel_id":"door"},
        {"alias":"storyteller","channel_id":"stories"}
      ]
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
        ilink_tokens_file: String::new(),
        unknown_sender_hint: true,
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
        router: Default::default(),
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
        serde_json::json!({ "contact_id": "c-kid", "tier": "partner",
            "channels": [{ "channel_id": "family-chat", "speak": true, "read": true }] }),
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
    assert_eq!(kid["channels"][0]["channel_id"], "family-chat");
    assert_eq!(kid["channels"][0]["speak"], true);
    assert_eq!(kid["channels"].as_array().unwrap().len(), 1, "{kid}");
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

#[tokio::test]
async fn hosted_console_requires_a_master_session_before_accessing_the_gate() {
    let base = spawn().await;
    let (status, _) = post(
        &base,
        "/v1/gateway/console",
        None,
        serde_json::json!({"operation": "status"}),
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn an_armed_operator_cannot_be_replaced_by_login_start() {
    let base = spawn().await;
    for (operator, expected) in [
        (format!("0x{}", "cc".repeat(32)), 403),
        ("malformed".into(), 400),
    ] {
        let (status, _) = post(
            &base,
            "/v1/gateway/admin/login/start",
            Some("admin-secret"),
            serde_json::json!({"operator_omni": operator}),
        )
        .await;
        assert_eq!(status, expected);
    }
}

#[derive(Clone)]
struct HostedChainFixture {
    owner: String,
    registered: bool,
    revoked: bool,
}

async fn hosted_fixture_session(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let owner = match token {
        Some("Bearer owner-session") => "ab",
        Some("Bearer other-master-session") => "cd",
        _ => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error":"master session required"})),
            )
                .into_response()
        }
    };
    axum::Json(agentkeys_protocol::auth::MasterSessionInfo {
        omni_account: format!("0x{}", owner.repeat(32)),
        wallet_address: format!("0x{}", "ef".repeat(20)),
        expires_at: 9_999_999_999,
    })
    .into_response()
}

async fn hosted_fixture_chain(
    axum::extract::State(fixture): axum::extract::State<HostedChainFixture>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    assert_eq!(body["method"], "eth_call");
    assert!(body["params"][0]["data"]
        .as_str()
        .unwrap()
        .ends_with(&"22".repeat(32)));
    let mut words: [String; 11] = std::array::from_fn(|_| "00".repeat(32));
    words[0] = fixture.owner;
    words[1] = "11".repeat(32);
    words[6] = format!("{:064x}", 3);
    words[7] = format!("{:064x}", 1);
    words[8] = format!("{:064x}", u8::from(fixture.registered));
    words[10] = format!("{:064x}", u8::from(fixture.revoked));
    axum::Json(
        serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":format!("0x{}",words.join(""))}),
    )
}

async fn spawn_hosted(fixture: HostedChainFixture, enrolled: bool) -> String {
    use axum::{
        routing::{get, post},
        Router,
    };
    let upstream = Router::new()
        .route("/v1/auth/session", get(hosted_fixture_session))
        .route("/", post(hosted_fixture_chain))
        .with_state(fixture);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });
    let registry = write_registry();
    let coordinates = format!("{registry}.device");
    std::fs::write(
        &coordinates,
        serde_json::to_vec(&serde_json::json!({
            "actor_omni": enrolled.then(|| format!("0x{}", "11".repeat(32))),
            "device_key_hash": enrolled.then(|| format!("0x{}", "22".repeat(32))),
            "broker_url": upstream_url,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut config = config(registry);
    config.device = agentkeys_worker_channel_weixin::config::DeviceConfig {
        broker_url: Some(upstream_url.clone()),
        chain_rpc_http: Some(upstream_url),
        registry_contract: Some(format!("0x{}", "33".repeat(20))),
        state_file: coordinates,
        ..Default::default()
    };
    let state = Arc::new(WeixinGatewayState::build(config).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, handlers::build_router(state))
            .await
            .unwrap();
    });
    url
}

#[tokio::test]
async fn hosted_owner_can_read_and_update_the_existing_contact_registry() {
    let base = spawn_hosted(
        HostedChainFixture {
            owner: "ab".repeat(32),
            registered: true,
            revoked: false,
        },
        true,
    )
    .await;
    for operation in [
        "status",
        "contacts",
        "channels",
        "device_status",
        "bind_pending",
        "registry_export",
    ] {
        let (status, _) = post(
            &base,
            "/v1/gateway/console",
            Some("owner-session"),
            serde_json::json!({"operation":operation}),
        )
        .await;
        assert_eq!(status, 200, "{operation}");
    }
    let (status, _) = post(
        &base,
        "/v1/gateway/console",
        Some("owner-session"),
        serde_json::json!({
            "operation":"contacts_update", "payload":{"contact_id":"c-kid","tier":"guest"}
        }),
    )
    .await;
    assert_eq!(status, 200);
    let (status, registry) = post(
        &base,
        "/v1/gateway/console",
        Some("owner-session"),
        serde_json::json!({"operation":"registry_export"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        registry["bound"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contact| contact["contact_id"] == "c-kid")
            .unwrap()["tier"],
        "guest"
    );
}

#[tokio::test]
async fn hosted_gate_independently_rejects_other_masters_and_device_sessions() {
    let base = spawn_hosted(
        HostedChainFixture {
            owner: "ab".repeat(32),
            registered: true,
            revoked: false,
        },
        true,
    )
    .await;
    for token in ["other-master-session", "device-session", "admin-secret"] {
        for body in [
            serde_json::json!({"operation":"status"}),
            serde_json::json!({"operation":"history", "payload":{}}),
            serde_json::json!({"operation":"contacts_update", "payload":{"contact_id":"c-kid","tier":"owner"}}),
        ] {
            let (status, _) = post(&base, "/v1/gateway/console", Some(token), body).await;
            assert!(status == 401 || status == 403, "{token}: {status}");
        }
    }
}

#[tokio::test]
async fn hosted_gate_refuses_unbound_revoked_unknown_and_foreign_chain_owners() {
    for (enrolled, registered, revoked, owner, expected) in [
        (false, true, false, "ab", 409),
        (true, false, false, "ab", 403),
        (true, true, true, "ab", 403),
        (true, true, false, "cd", 403),
    ] {
        let base = spawn_hosted(
            HostedChainFixture {
                owner: owner.repeat(32),
                registered,
                revoked,
            },
            enrolled,
        )
        .await;
        let (status, _) = post(
            &base,
            "/v1/gateway/console",
            Some("owner-session"),
            serde_json::json!({"operation":"registry_export"}),
        )
        .await;
        assert_eq!(status, expected);
    }
}

#[tokio::test]
async fn hosted_gate_has_no_arbitrary_admin_route_or_operator_body() {
    let base = spawn_hosted(
        HostedChainFixture {
            owner: "ab".repeat(32),
            registered: true,
            revoked: false,
        },
        true,
    )
    .await;
    for body in [
        serde_json::json!({"operation":"admin", "payload":{"path":"/v1/gateway/admin/device/pairing-request"}}),
        serde_json::json!({"operation":"login_start", "payload":{"operator_omni":format!("0x{}", "cd".repeat(32))}}),
        serde_json::json!({"operation":"registry_restore", "payload":{"registry":{}, "force":true}}),
    ] {
        let (status, _) = post(&base, "/v1/gateway/console", Some("owner-session"), body).await;
        assert_eq!(status, 422);
    }
}

#[test]
fn runtime_connect_cannot_overwrite_an_existing_household_owner() {
    let state = WeixinGatewayState::build(config(write_registry())).unwrap();
    assert!(state.set_runtime_operator_omni(&"ab".repeat(32)).is_ok());
    assert_eq!(
        state.set_runtime_operator_omni(&"cd".repeat(32)),
        Err("gateway_operator_mismatch")
    );
    assert_eq!(state.effective_operator_omni(), "ab".repeat(32));
}

#[test]
fn first_native_connect_repairs_a_legacy_stamp_then_locks_the_connected_owner() {
    let registry = write_registry();
    std::fs::write(
        &registry,
        r#"{"bound":[],"channels":[{"id":"family-chat"}]}"#,
    )
    .unwrap();
    let state = WeixinGatewayState::build(config(registry)).unwrap();
    let connected_owner = "cd".repeat(32);
    assert!(state.validate_connect_operator(&connected_owner).is_ok());
    assert!(state.set_runtime_operator_omni(&connected_owner).is_ok());
    assert_eq!(state.effective_operator_omni(), connected_owner);
    assert_eq!(
        state.validate_connect_operator(&"ab".repeat(32)),
        Err("gateway_operator_mismatch")
    );
    assert_eq!(
        state.set_runtime_operator_omni(&"ab".repeat(32)),
        Err("gateway_operator_mismatch")
    );
}

#[test]
fn persisted_bot_identity_prevents_first_connect_owner_replacement() {
    let registry = write_registry();
    std::fs::write(&registry, "{}").unwrap();
    let mut config = config(registry);
    config.transport = agentkeys_worker_channel_weixin::WeixinTransport::Ilink;
    config.ilink_bot_token = Some("fixture-existing-token".into());
    let state = WeixinGatewayState::build(config).unwrap();
    assert_eq!(
        state.validate_connect_operator(&"cd".repeat(32)),
        Err("gateway_operator_mismatch")
    );
    assert_eq!(
        state.set_runtime_operator_omni(&"cd".repeat(32)),
        Err("gateway_operator_mismatch")
    );
}

#[tokio::test]
async fn hosted_restore_cannot_overwrite_an_existing_registry() {
    let base = spawn_hosted(
        HostedChainFixture {
            owner: "ab".repeat(32),
            registered: true,
            revoked: false,
        },
        true,
    )
    .await;
    let (status, body) = post(
        &base,
        "/v1/gateway/console",
        Some("owner-session"),
        serde_json::json!({"operation":"registry_restore", "payload":{"registry":{}}}),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["reason"], "registry_not_empty");
}
