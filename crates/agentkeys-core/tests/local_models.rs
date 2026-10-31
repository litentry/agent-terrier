use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use agentkeys_core::models::{qualification::probe, require_local_endpoint, ModelClient};
use axum::{
    extract::State,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (base, task)
}

#[tokio::test]
async fn model_redirect_does_not_forward_requests_or_credentials() {
    let received = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route(
            "/v1/chat/completions",
            post(|State(received): State<Arc<AtomicUsize>>| async move {
                received.fetch_add(1, Ordering::SeqCst);
                Json(json!({"ok":true}))
            }),
        )
        .with_state(received.clone());
    let (target, target_task) = serve(router).await;
    let redirect_target = format!("{target}/chat/completions");
    let (source, source_task) = serve(Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let target = redirect_target.clone();
            async move { Redirect::temporary(&target) }
        }),
    ))
    .await;
    let client = ModelClient::new(&source, Some("synthetic-relay-token"));
    assert_eq!(client.chat(&json!({})).await.unwrap().status(), 307);
    assert_eq!(received.load(Ordering::SeqCst), 0);
    assert!(ModelClient::new(&target, None)
        .chat(&json!({}))
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(received.load(Ordering::SeqCst), 1);
    source_task.abort();
    target_task.abort();
}

#[tokio::test]
async fn missing_models_are_rejected_before_inference() {
    let received = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route(
            "/v1/models",
            get(|| async { Json(json!({"data":[{"id":"chat-fixture"}]})) }),
        )
        .route(
            "/v1/chat/completions",
            post(
                |State(received): State<Arc<AtomicUsize>>, Json(_): Json<Value>| async move {
                    received.fetch_add(1, Ordering::SeqCst);
                    Json(json!({}))
                },
            ),
        )
        .with_state(received.clone());
    let (base, task) = serve(router).await;
    let error = probe(&base, "chat-fixture", "missing-embedding")
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("missing-embedding is not installed"));
    assert_eq!(received.load(Ordering::SeqCst), 0);
    task.abort();
}

#[test]
fn local_model_probe_rejects_remote_or_credential_bearing_endpoints() {
    for endpoint in [
        "http://127.0.0.1:11434/v1",
        "http://[::1]:11434/v1",
        "http://localhost:11434/v1",
    ] {
        require_local_endpoint(endpoint).unwrap();
    }
    for endpoint in [
        "https://example.invalid/v1",
        "http://localhost.example.invalid/v1",
        "http://user:password@localhost/v1",
        "http://localhost/v1?token=placeholder",
        "file:///tmp/model",
    ] {
        assert!(require_local_endpoint(endpoint).is_err());
    }
}
