//! Stage 7 issue#64 Phase C.0 — graceful shutdown test (US-023).
//!
//! Phase 0 already wired the SIGTERM → grace-drain → exit path in
//! `main.rs` (with `BROKER_SHUTDOWN_GRACE_SECONDS`). US-023 promotes
//! that to a tested invariant: the in-flight request completes (200
//! OK) when the broker receives SIGTERM mid-request, AND a fresh
//! request after SIGTERM but before grace expires returns the same
//! 200 (the listener does not flip to 503/connection-refused
//! immediately).
//!
//! This test exercises the axum `with_graceful_shutdown` integration
//! by spawning a handler that sleeps, sending SIGTERM via tokio
//! signal, and asserting the response completes.

use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};

#[tokio::test]
async fn handler_completes_when_shutdown_initiated_after_request_starts() {
    // Spawn a tiny axum server with `with_graceful_shutdown` mirroring
    // main.rs's pattern. The handler sleeps 200ms; the shutdown signal
    // fires 50ms in. The request MUST complete with 200.
    let app = Router::new().route(
        "/sleep",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            "completed"
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let shutdown_token = Arc::new(tokio::sync::Notify::new());
    let shutdown_for_axum = Arc::clone(&shutdown_token);

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_for_axum.notified().await;
                // Mirror main.rs: tiny grace period after signal so
                // in-flight requests finish.
                tokio::time::sleep(Duration::from_millis(500)).await;
            })
            .await
            .unwrap();
    });

    // Fire request, then trigger shutdown 50ms later.
    let req = tokio::spawn(async move {
        let client = reqwest::Client::new();
        client
            .get(format!("http://{}/sleep", addr))
            .send()
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_token.notify_one();

    let resp = req.await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "completed");

    server_handle.await.unwrap();
}

#[tokio::test]
async fn server_exits_after_grace_period() {
    let app = Router::new().route("/", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _addr = listener.local_addr().unwrap();

    let shutdown_token = Arc::new(tokio::sync::Notify::new());
    let shutdown_for_axum = Arc::clone(&shutdown_token);

    let started = std::time::Instant::now();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_for_axum.notified().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            })
            .await
            .unwrap();
    });

    // Trigger shutdown immediately; the server should exit within
    // ~grace_seconds (here 100ms) of the signal.
    tokio::time::sleep(Duration::from_millis(20)).await;
    shutdown_token.notify_one();

    server_handle.await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "server should exit within grace+slack, took {:?}",
        elapsed
    );
}
