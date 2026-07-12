//! #424 §2 — the durable-copy surface: `registry/export` hands the daemon the
//! FULL contact registry (it write-throughs it into the master-only Config-class
//! doc), `registry/import` restores it onto an EMPTY (rebuilt) gateway host.
//! Gates: admin-bearer required; a NON-empty local registry refuses an import
//! without `force` (a live registry is never silently clobbered).

use std::sync::Arc;

use agentkeys_protocol::{BindInvite, Contact, ContactRegistry, ContactTier};
use agentkeys_worker_channel_weixin::{
    handlers, WeixinGatewayConfig, WeixinGatewayState, WeixinTransport,
};

const ADMIN: &str = "test-admin-bearer";

fn temp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("ak-weixin-reg-{}-{}", std::process::id(), name))
        .to_string_lossy()
        .to_string()
}

fn config_for(registry_file: &str) -> WeixinGatewayConfig {
    WeixinGatewayConfig {
        bind: "127.0.0.1:0".into(),
        transport: WeixinTransport::Ilink,
        weixin_token: String::new(),
        weixin_app_id: String::new(),
        weixin_app_secret: None,
        ilink_bot_token: None,
        ilink_base_url: "http://127.0.0.1:9".into(),
        ilink_state_file: temp("ilink-state.json"),
        history_file: String::new(),
        activity_file: String::new(),
        secrets_file: temp("secrets.env"),
        ilink_bootstrap_url: "http://127.0.0.1:9".into(),
        bot_agent: "AgentKeys/test".into(),
        registry_file: registry_file.to_string(),
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
    }
}

async fn serve(registry_file: &str) -> String {
    let state = Arc::new(WeixinGatewayState::build(config_for(registry_file)).unwrap());
    let app = handlers::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

fn seeded_registry() -> ContactRegistry {
    ContactRegistry {
        bound: vec![Contact {
            contact_id: "c-grandma".into(),
            transport: "weixin".into(),
            transport_id: "openid-grandma".into(),
            display_name: "奶奶".into(),
            tier: ContactTier::Elder,
            reach: vec!["chef".into()],
        }],
        pending: vec![],
        invites: vec![BindInvite {
            bind_code: "123456".into(),
            contact_id: "c-kid".into(),
            display_name: "小明".into(),
            tier: ContactTier::Kid,
            reach: vec![],
        }],
    }
}

#[tokio::test]
async fn export_is_admin_gated_and_returns_the_full_registry() {
    let registry_file = temp("export.json");
    std::fs::write(
        &registry_file,
        serde_json::to_string(&seeded_registry()).unwrap(),
    )
    .unwrap();
    let gw = serve(&registry_file).await;
    let http = reqwest::Client::new();

    // No bearer → 401 (never open).
    let unauth = http
        .get(format!("{gw}/v1/gateway/admin/registry/export"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);

    let exported: ContactRegistry = http
        .get(format!("{gw}/v1/gateway/admin/registry/export"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(exported.bound.len(), 1);
    assert_eq!(exported.bound[0].transport_id, "openid-grandma");
    assert_eq!(exported.invites.len(), 1);
    std::fs::remove_file(&registry_file).ok();
}

#[tokio::test]
async fn import_restores_an_empty_gateway_and_refuses_a_live_one() {
    // A rebuilt host: empty local registry.
    let registry_file = temp("import.json");
    std::fs::write(&registry_file, r#"{"bound":[],"pending":[]}"#).unwrap();
    let gw = serve(&registry_file).await;
    let http = reqwest::Client::new();

    // Restore the durable copy → 200 + counts, and it PERSISTS to the file.
    let restored: serde_json::Value = http
        .post(format!("{gw}/v1/gateway/admin/registry/import"))
        .bearer_auth(ADMIN)
        .json(&serde_json::json!({ "registry": seeded_registry() }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restored["ok"], true, "{restored}");
    assert_eq!(restored["bound"], 1);
    assert_eq!(restored["invites"], 1);
    let on_disk: ContactRegistry =
        serde_json::from_str(&std::fs::read_to_string(&registry_file).unwrap()).unwrap();
    assert_eq!(on_disk.bound[0].contact_id, "c-grandma");

    // The gateway now has live contacts — a second import must 409 (never
    // silently clobber) unless force:true.
    let refused = http
        .post(format!("{gw}/v1/gateway/admin/registry/import"))
        .bearer_auth(ADMIN)
        .json(&serde_json::json!({ "registry": {"bound": [], "pending": []} }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 409);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["reason"], "registry_not_empty");

    let forced = http
        .post(format!("{gw}/v1/gateway/admin/registry/import"))
        .bearer_auth(ADMIN)
        .json(&serde_json::json!({ "registry": {"bound": [], "pending": []}, "force": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(forced.status(), 200);
    let on_disk: ContactRegistry =
        serde_json::from_str(&std::fs::read_to_string(&registry_file).unwrap()).unwrap();
    assert!(on_disk.bound.is_empty(), "forced overwrite applied");
    std::fs::remove_file(&registry_file).ok();
}
