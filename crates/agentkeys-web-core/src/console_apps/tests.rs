use super::*;
use crate::data::DataEndpoints;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Calls {
    submit: usize,
    receipt: usize,
    fleet: usize,
    submit_error: bool,
}
fn config(base: &str) -> ConsoleConfig {
    serde_json::from_value(json!({"chain":{"name":"fixture","display":"Fixture","chainId":1,"rpc":base,"wss":"","explorer":"","tokenSymbol":"TEST","tokenDecimals":18,"finality":"fixture","contracts":[],"daemonChain":"fixture","daemonBroker":base},"signer_url":base,"config_url":base,"memory_url":base,"credential_url":base,"audit_url":base,"channel_url":base,"classify_url":base})).unwrap()
}
fn service(base: &str) -> ConsoleApps {
    ConsoleApps::new(
        BrokerClient::new(base),
        DataClient::new(DataEndpoints {
            broker_url: base.into(),
            signer_url: base.into(),
            config_url: base.into(),
            memory_url: base.into(),
            credential_url: base.into(),
            audit_url: base.into(),
            classify_url: Some(base.into()),
        }),
        config(base),
    )
}
fn session<'a>(device: &'a DeviceIdentity, operator: &'a str) -> DataSession<'a> {
    DataSession {
        bearer: "fixture-session",
        operator_omni: operator,
        actor_omni: operator,
        device,
        now_unix_seconds: 1,
    }
}
fn operation() -> Value {
    serde_json::from_str(include_str!(
        "../../../../e2e/fixtures/backend-protocol/submit_accept_userop_request.json"
    ))
    .unwrap()
}
fn stash(apps: &ConsoleApps, body: &Value, operator: &str, receipt: Option<Value>) {
    apps.pending.borrow_mut().insert(
        operation_key(body).unwrap(),
        PendingApp {
            operator: norm(operator),
            route: "/v1/agent/spawn/submit".into(),
            build: body.clone(),
            row: None,
            previous: None,
            label: "fixture".into(),
            enrollments: vec![],
            resources_kept: false,
            seals: vec![],
            receipt,
        },
    );
}
async fn fixture() -> (ConsoleApps, Arc<Mutex<Calls>>, tokio::task::JoinHandle<()>) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let router=Router::new().route("/v1/agent/spawn/submit",post(|State(calls):State<Arc<Mutex<Calls>>>|async move{let mut calls=calls.lock().unwrap();calls.submit+=1;if calls.submit_error{(StatusCode::BAD_GATEWAY,Json(json!({"error":"fixture response lost after dispatch"})))}else{(StatusCode::OK,Json(json!({"ok":true,"pending":true,"user_op_hash":"fixture-hash"})))}})).route("/v1/accept/receipt",post(|State(calls):State<Arc<Mutex<Calls>>>|async move{calls.lock().unwrap().receipt+=1;Json(json!({"ok":true,"pending":false,"user_op_hash":"fixture-hash","tx_hash":"fixture-tx"}))})).route("/v1/console/fleet",get(|State(calls):State<Arc<Mutex<Calls>>>|async move{calls.lock().unwrap().fleet+=1;(StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"fixture metadata unavailable after confirmation"})))})).with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (service(&base), calls, task)
}
#[tokio::test]
async fn pending_receipt_does_not_write_metadata_or_rebroadcast() {
    let (apps, calls, task) = fixture().await;
    let device = DeviceIdentity::from_random_bytes(&[7; 32]).unwrap();
    let session = session(&device, "operator-a");
    let body = operation();
    stash(&apps, &body, session.operator_omni, None);
    assert_eq!(
        apps.submit(&session, "/v1/agent/spawn/submit", body.clone())
            .await
            .unwrap()["pending"],
        true
    );
    {
        let calls = calls.lock().unwrap();
        assert_eq!((calls.submit, calls.receipt, calls.fleet), (1, 0, 0));
    }
    let error = apps
        .submit(&session, "/v1/agent/spawn/submit", body.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("post_confirm_failed"));
    {
        let calls = calls.lock().unwrap();
        assert_eq!((calls.submit, calls.receipt, calls.fleet), (1, 1, 1));
    }
    assert!(apps
        .submit(&session, "/v1/agent/spawn/submit", body)
        .await
        .is_err());
    {
        let calls = calls.lock().unwrap();
        assert_eq!((calls.submit, calls.receipt, calls.fleet), (1, 1, 2));
    }
    task.abort();
}
#[tokio::test]
async fn failed_ceremony_is_recovered_through_receipt_without_rebroadcast() {
    let (apps, calls, task) = fixture().await;
    let device = DeviceIdentity::from_random_bytes(&[7; 32]).unwrap();
    let session = session(&device, "operator-a");
    let body = operation();
    stash(
        &apps,
        &body,
        session.operator_omni,
        Some(json!({"ok":true,"ceremony":{"spawned":[{"error":"context missing"}]}})),
    );
    assert!(apps
        .submit(&session, "/v1/agent/spawn/submit", body)
        .await
        .is_err());
    {
        let calls = calls.lock().unwrap();
        assert_eq!((calls.submit, calls.receipt), (0, 1));
    }
    task.abort();
}
#[tokio::test]
async fn pending_action_rejects_other_operator_route_and_changed_operation_before_egress() {
    let (apps, calls, task) = fixture().await;
    let device = DeviceIdentity::from_random_bytes(&[7; 32]).unwrap();
    let owner = session(&device, "operator-a");
    let other = session(&device, "operator-b");
    let body = operation();
    stash(&apps, &body, owner.operator_omni, None);
    assert!(matches!(
        apps.submit(&other, "/v1/agent/spawn/submit", body.clone())
            .await,
        Err(DataError::Http { status: 403, .. })
    ));
    assert!(matches!(
        apps.submit(&owner, "/v1/agent/archive/submit", body.clone())
            .await,
        Err(DataError::Http { status: 403, .. })
    ));
    let mut changed = body;
    changed["user_op"]["call_data"] = json!("0xchanged");
    assert!(matches!(
        apps.submit(&owner, "/v1/agent/spawn/submit", changed).await,
        Err(DataError::Http { status: 409, .. })
    ));
    {
        let calls = calls.lock().unwrap();
        assert_eq!((calls.submit, calls.receipt, calls.fleet), (0, 0, 0));
    }
    task.abort();
}
#[tokio::test]
async fn channel_access_never_falls_back_to_master_without_console_device() {
    let (apps, calls, task) = fixture().await;
    let device = DeviceIdentity::from_random_bytes(&[7; 32]).unwrap();
    let session = session(&device, "operator-a");
    for (path, body) in [
        (
            "/v1/master/agent/chat/send",
            json!({"channel_id":"fixture","text":"hello"}),
        ),
        (
            "/v1/master/agent/chat/poll",
            json!({"channel_id":"fixture"}),
        ),
    ] {
        assert!(apps
            .request(&session, None, "POST", path, body)
            .await
            .unwrap_err()
            .to_string()
            .contains("console"));
    }
    assert!(apps
        .refresh_channel_defaults(&session, "../foreign-channel")
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid channel id"));
    assert_eq!(calls.lock().unwrap().fleet, 0);
    task.abort();
}

#[tokio::test]
async fn uncertain_initial_submission_queries_receipt_on_retry() {
    let (apps, calls, task) = fixture().await;
    calls.lock().unwrap().submit_error = true;
    let device = DeviceIdentity::from_random_bytes(&[7; 32]).unwrap();
    let session = session(&device, "operator-a");
    let body = operation();
    stash(&apps, &body, session.operator_omni, None);
    assert!(apps
        .submit(&session, "/v1/agent/spawn/submit", body.clone())
        .await
        .is_err());
    assert!(apps
        .submit(&session, "/v1/agent/spawn/submit", body)
        .await
        .is_err());
    {
        let calls = calls.lock().unwrap();
        assert_eq!((calls.submit, calls.receipt, calls.fleet), (1, 1, 1));
    }
    task.abort();
}
