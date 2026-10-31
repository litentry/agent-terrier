use agentkeys_core::{models, protected_file};
use agentkeys_gate::{
    config::{Cli, GateConfig, RelayKey},
    relay::Relay,
    server,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde_json::{json, Value};
use std::{
    process::Stdio,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

async fn synthetic_model(
    State(calls): State<Arc<AtomicUsize>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert!(!headers.contains_key("authorization"));
    assert_eq!(body["model"], models::default_chat_model());
    calls.fetch_add(1, Ordering::SeqCst);
    Json(
        json!({"choices":[{"message":{"role":"assistant","content":"synthetic answer"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}),
    )
}

#[tokio::test]
async fn public_binary_ignores_legacy_host_credentials_and_requires_caller_authentication() {
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let model = Router::new()
        .route("/v1/chat/completions", post(synthetic_model))
        .route("/v1/models", get(|| async { Json(json!({"data":[]})) }))
        .with_state(calls.clone());
    let model_task = tokio::spawn(async move {
        axum::serve(listener, model).await.unwrap();
    });
    let temporary = tempfile::tempdir().unwrap();
    let credential_file = temporary.path().join("relay.json");
    protected_file::write(credential_file.to_str().unwrap(),json!({"keys":[{"key":"synthetic-caller-token","key_id":"test","user_omni":"ab".repeat(32),"device_id":"test"}]}).to_string().as_bytes(),true).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut process = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentkeys-gate"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("ARK_API_KEY", "synthetic-host-credential")
        .env("ARK_BASE_URL", "http://127.0.0.1:1/forbidden")
        .env(
            "AGENTKEYS_INFERENCE_CREDS_DIR",
            temporary.path().join("missing"),
        )
        .args([
            "--listen",
            &address.to_string(),
            "--upstream-base-url",
            &endpoint,
            "--keys-file",
        ])
        .arg(&credential_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let base = format!("http://{address}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            process.try_wait().unwrap().is_none(),
            "gate exited before health check"
        );
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gate startup timed out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let body = json!({"messages":[{"role":"user","content":"test"}]});
    for credential in [None, Some("wrong-token")] {
        let request = client
            .post(format!("{base}/v1/chat/completions"))
            .json(&body);
        let request = match credential {
            Some(value) => request.bearer_auth(value),
            None => request,
        };
        assert_eq!(request.send().await.unwrap().status(), 401);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        client
            .post(format!("{base}/v1/chat/completions"))
            .bearer_auth("synthetic-caller-token")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        client
            .get(format!("{base}/v1/audio/voices"))
            .bearer_auth("synthetic-caller-token")
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    process.kill().await.unwrap();
    process.wait().await.unwrap();
    model_task.abort();
}

#[tokio::test]
#[ignore = "explicit qualification against installed real local models"]
async fn real_local_models_through_authenticated_gate() {
    let endpoint =
        std::env::var("AGENT_TERRIER_MODEL_ENDPOINT").expect("set explicit local model endpoint");
    models::require_local_endpoint(&endpoint).unwrap();
    let cli = Cli::try_parse_from([
        "agentkeys-gate",
        "--listen",
        "127.0.0.1:0",
        "--upstream-base-url",
        &endpoint,
    ])
    .unwrap();
    let mut config = GateConfig::from_cli(cli).unwrap();
    config.keys.push(RelayKey {
        key: "synthetic-qualification-caller".into(),
        key_id: "qualification".into(),
        user_omni: format!("0x{}", "ab".repeat(32)),
        device_id: "qualification".into(),
        label: String::new(),
        delegate_omni: None,
        budget_tokens: None,
        disabled: false,
    });
    let listener = tokio::net::TcpListener::bind(config.listen).await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let relay = Arc::new(Relay::new(config));
    let application = server::router(relay.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, application).await.unwrap();
    });
    let report = models::qualification::probe_authenticated(
        &endpoint,
        models::default_chat_model(),
        models::default_embedding_model(),
        Some("synthetic-qualification-caller"),
    )
    .await
    .unwrap();
    assert!(relay.meter.used_total(&format!("0x{}", "ab".repeat(32))) > 0);
    println!("{}", serde_json::to_string(&report).unwrap());
    task.abort();
}
