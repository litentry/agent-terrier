use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use agentkeys_core::{device_crypto::DeviceKey, protected_file};
use axum::{http::StatusCode, routing::post, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_agent_client_refuses_redirects_remote_services_and_ambient_proxies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let redirects = Arc::new(AtomicUsize::new(0));
    let proxy_calls = Arc::new(AtomicUsize::new(0));
    let status = Arc::new(AtomicUsize::new(403));
    let private_response = "synthetic-private-response-must-not-be-printed";
    let app = Router::new()
        .route(
            "/v1/agent/spawn/build",
            post({
                let calls = calls.clone();
                let status = status.clone();
                move || {
                    let calls = calls.clone();
                    let status = status.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::from_u16(status.load(Ordering::SeqCst) as u16).unwrap(),
                            [("location", "/redirect-target")],
                            private_response,
                        )
                    }
                }
            }),
        )
        .route(
            "/redirect-target",
            post({
                let redirects = redirects.clone();
                move || {
                    let redirects = redirects.clone();
                    async move {
                        redirects.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let proxy = Router::new().fallback({
        let proxy_calls = proxy_calls.clone();
        move || {
            let proxy_calls = proxy_calls.clone();
            async move {
                proxy_calls.fetch_add(1, Ordering::SeqCst);
                StatusCode::BAD_GATEWAY
            }
        }
    });
    let proxy_server = tokio::spawn(async move { axum::serve(listener, proxy).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("device.key");
    let session_path = directory.path().join("session.json");
    let device = DeviceKey::load_or_generate(key_path.to_str().unwrap(), false).unwrap();
    let operator = format!("0x{}", "12".repeat(32));
    let bearer = format!(
        "e30.{}.sig",
        URL_SAFE_NO_PAD.encode(json!({"agentkeys":{"omni_account":operator}}).to_string())
    );
    let mut session = json!({"development_only":true,"broker_url":broker,
        "account":format!("0x{}", "34".repeat(20)), "device_key_hash":device.device_key_hash().unwrap(),
        "session":{"session_jwt":bearer,"omni_account":operator,"wallet_address":format!("0x{}", "34".repeat(20)),
        "expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+300}});
    protected_file::write(
        session_path.to_str().unwrap(),
        &serde_json::to_vec(&session).unwrap(),
        true,
    )
    .unwrap();
    let run = |endpoint: &str, enabled: &str| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agentkeys"));
        command.env_clear();
        for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(name, &proxy_url);
        }
        command
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .env("AGENT_TERRIER_LOCAL_DEV", enabled)
            .args([
                "local",
                "agent",
                "--operator-omni",
                &operator,
                "--device-key-file",
                key_path.to_str().unwrap(),
                "--session-file",
                session_path.to_str().unwrap(),
                "--key-file",
                directory
                    .path()
                    .join("missing-passkey.pem")
                    .to_str()
                    .unwrap(),
                "--broker-url",
                endpoint,
                "spawn",
                "--label",
                "transport-test",
            ]);
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains(&bearer) && !error.contains(private_response));
        error
    };
    assert!(run(&broker, "1").contains("HTTP 403"));
    status.store(307, Ordering::SeqCst);
    assert!(run(&broker, "1").contains("HTTP 307"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(redirects.load(Ordering::SeqCst), 0);
    assert_eq!(proxy_calls.load(Ordering::SeqCst), 0);
    for endpoint in ["https://example.invalid", "http://192.0.2.1:9000"] {
        assert!(run(endpoint, "1").contains("loopback"));
    }
    assert!(run(&broker, "0").contains("development"));
    session["session"]["expires_at"] = json!(0);
    protected_file::replace_atomic(&session_path, &serde_json::to_vec(&session).unwrap()).unwrap();
    assert!(run(&broker, "1").contains("expired"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(proxy_calls.load(Ordering::SeqCst), 0);
    assert!(!directory.path().join("missing-passkey.pem").exists());
    server.abort();
    proxy_server.abort();
}
