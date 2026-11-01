use std::io::Write;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use agentkeys_core::{device_crypto::DeviceKey, protected_file};
use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_agent_client_refuses_redirects_remote_services_and_ambient_proxies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let redirects = Arc::new(AtomicUsize::new(0));
    let proxy_calls = Arc::new(AtomicUsize::new(0));
    let status = Arc::new(AtomicUsize::new(403));
    let bridge_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bridge_response = Arc::new(AtomicUsize::new(0));
    let private_response = "synthetic-private-response-must-not-be-printed";
    let app = Router::new()
        .route(
            "/v1/agent/bridge",
            post({
                let bridge_calls = bridge_calls.clone();
                let status = status.clone();
                let bridge_response = bridge_response.clone();
                move |headers: HeaderMap,
                          Json(request): Json<
                        agentkeys_backend_client::protocol::BridgeProxyBody,
                    >| {
                        let bridge_calls = bridge_calls.clone();
                        let status = status.clone();
                        let bridge_response = bridge_response.clone();
                        async move {
                            let body = request.body.clone();
                            bridge_calls.lock().unwrap().push((headers, request));
                            let status =
                                StatusCode::from_u16(status.load(Ordering::SeqCst) as u16).unwrap();
                            if status != StatusCode::OK {
                                return (
                                    status,
                                    [("location", "/redirect-target")],
                                    private_response,
                                )
                                    .into_response();
                            }
                            match bridge_response.load(Ordering::SeqCst) {
                                1 => Json(json!({"payload": "x".repeat(1024 * 1024 + 1)}))
                                    .into_response(),
                                2 => (StatusCode::OK, private_response).into_response(),
                                _ => Json(json!({"ok":true,"echo":body})).into_response(),
                            }
                        }
                    }
            }),
        )
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
    let invoke = |endpoint: &str, enabled: &str, action: &[&str], input: Option<&[u8]>| {
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
                "--operations-dir",
                directory.path().to_str().unwrap(),
            ])
            .args(action);
        if let Some(input) = input {
            let mut child = command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let _ = child.stdin.take().unwrap().write_all(input);
            child.wait_with_output().unwrap()
        } else {
            command.stdin(std::process::Stdio::null()).output().unwrap()
        }
    };
    let run = |endpoint: &str, enabled: &str| {
        let output = invoke(
            endpoint,
            enabled,
            &["spawn", "--label", "transport-test"],
            None,
        );
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
    let device_hash = format!("0x{}", "56".repeat(32));
    let bridge = [
        "bridge",
        "--device-key-hash",
        &device_hash,
        "--path",
        "/v1/chat",
        "--json-stdin",
    ];
    let assert_denied = |output: std::process::Output, expected: &str| {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains(&bearer) && !error.contains(private_response));
    };
    assert_denied(invoke(&broker, "1", &bridge, Some(b"{}")), "expired");
    assert!(bridge_calls.lock().unwrap().is_empty());
    session["session"]["expires_at"] = json!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300
    );
    protected_file::replace_atomic(&session_path, &serde_json::to_vec(&session).unwrap()).unwrap();
    status.store(200, Ordering::SeqCst);
    let output = invoke(
        &broker,
        "1",
        &bridge,
        Some(br#"{"text":"synthetic-turn","stream":false}"#),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["response"]["echo"]["text"], "synthetic-turn");
    {
        let requests = bridge_calls.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0["authorization"], format!("Bearer {bearer}"));
        assert_eq!(requests[0].1.operator_omni, operator);
        assert_eq!(requests[0].1.device_key_hash, device_hash);
        assert_eq!(requests[0].1.method.as_deref(), Some("POST"));
        assert_eq!(requests[0].1.path, "/v1/chat");
        assert!(requests[0].1.sandbox_id.is_none());
    }
    let health = [
        "bridge",
        "--device-key-hash",
        &device_hash,
        "--path",
        "/healthz",
        "--method",
        "GET",
    ];
    assert!(invoke(&broker, "1", &health, None).status.success());
    assert!(bridge_calls.lock().unwrap()[1].1.body.is_none());
    let before = bridge_calls.lock().unwrap().len();
    for input in [b"{malformed".as_slice(), b"[]", b"{\"stream\":true}"] {
        assert_denied(invoke(&broker, "1", &bridge, Some(input)), "bridge");
    }
    assert_denied(
        invoke(&broker, "1", &bridge, Some(&vec![b'x'; 1024 * 1024 + 1])),
        "size limit",
    );
    assert_denied(
        invoke("https://example.invalid", "1", &bridge, Some(b"{}")),
        "loopback",
    );
    assert_denied(invoke(&broker, "0", &bridge, Some(b"{}")), "development");
    assert_eq!(bridge_calls.lock().unwrap().len(), before);
    for code in [403, 307] {
        status.store(code, Ordering::SeqCst);
        assert_denied(
            invoke(&broker, "1", &bridge, Some(b"{}")),
            &format!("HTTP {code}"),
        );
    }
    status.store(200, Ordering::SeqCst);
    for kind in [1, 2] {
        bridge_response.store(kind, Ordering::SeqCst);
        assert_denied(
            invoke(&broker, "1", &bridge, Some(b"{}")),
            "bridge request failed",
        );
    }
    assert_eq!(redirects.load(Ordering::SeqCst), 0);
    assert_eq!(proxy_calls.load(Ordering::SeqCst), 0);
    assert!(!directory.path().join("missing-passkey.pem").exists());
    server.abort();
    proxy_server.abort();
}
