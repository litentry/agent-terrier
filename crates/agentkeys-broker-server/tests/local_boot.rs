use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct BrokerProcess(Child);

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn local_binary_starts_without_cloud_roles_and_retains_authentication() {
    check_local_binary(false).await;
}

#[tokio::test]
async fn local_binary_wires_the_private_email_outbox() {
    check_local_binary(true).await;
}

async fn check_local_binary(email_enabled: bool) {
    let directory = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_agentkeys-broker-server");
    let wake_path = directory.path().join("wake-token");
    agentkeys_core::protected_file::write(
        wake_path.to_str().unwrap(),
        b"synthetic-wake-token",
        true,
    )
    .unwrap();
    for purpose in ["oidc", "session"] {
        let generated = Command::new(binary)
            .env_clear()
            .args(["keygen", "--purpose", purpose, "--out"])
            .arg(directory.path().join(format!("{purpose}.json")))
            .output()
            .unwrap();
        assert!(generated.status.success());
    }
    let port_guard = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = port_guard.local_addr().unwrap().port();
    drop(port_guard);
    let endpoint = format!("http://127.0.0.1:{port}");
    let mut process = BrokerProcess(
        Command::new(binary)
            .env_clear()
            .env("BROKER_OIDC_ISSUER", &endpoint)
            .env("BROKER_CHANNEL_WAKE_TOKEN_FILE", &wake_path)
            .env("BROKER_DEV_MODE", "true")
            .env(
                "BROKER_AUTH_METHODS",
                if email_enabled {
                    "wallet_sig,email_link"
                } else {
                    "wallet_sig"
                },
            )
            .env("BROKER_EMAIL_FROM_ADDRESS", "sender@example.test")
            .env("BROKER_EMAIL_OUTBOX_DIR", directory.path().join("outbox"))
            .env(
                "BROKER_AUDIT_DB_PATH",
                directory.path().join("audit.sqlite"),
            )
            .env(
                "BROKER_OIDC_KEYPAIR_PATH",
                directory.path().join("oidc.json"),
            )
            .env(
                "BROKER_SESSION_KEYPAIR_PATH",
                directory.path().join("session.json"),
            )
            .env("AWS_CONFIG_FILE", directory.path().join("does-not-exist"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                directory.path().join("does-not-exist"),
            )
            .args(["--port", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(process.0.try_wait().unwrap().is_none(), "broker exited");
        if let Ok(response) = client.get(format!("{endpoint}/readyz")).send().await {
            if response.status() == 200 {
                let readiness: serde_json::Value = response.json().await.unwrap();
                assert_eq!(readiness["status"], "ready");
                break;
            }
            assert!(email_enabled && response.status() == 503);
        }
        assert!(Instant::now() < deadline, "broker did not become ready");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if email_enabled {
        for path in [
            directory.path().join("outbox/.readiness.json"),
            directory.path().join("sender-verify.json"),
        ] {
            assert!(agentkeys_core::protected_file::read_text(path.to_str().unwrap()).is_ok());
        }
    }
    for route in [
        "canonical-sts",
        "inbox-sts",
        "own-sts",
        "speech-sts",
        "channel-sts",
    ] {
        let response = client
            .post(format!("{endpoint}/v1/cap/{route}"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            404,
            "retired exchange remains reachable: {route}"
        );
    }
    for bearer in [None, Some("wrong-synthetic-token")] {
        let mut request = client.post(format!("{endpoint}/v1/sandbox/wake")).json(
            &agentkeys_protocol::ChannelWakeRequest {
                owner_omni: "synthetic-owner".into(),
                channel_id: "synthetic-feed".into(),
                event_ts_ms: None,
            },
        );
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let denied = request.send().await.unwrap();
        assert_eq!(denied.status(), 401);
        let body: serde_json::Value = denied.json().await.unwrap();
        assert_eq!(body["error"], "unauthorized");
        assert!(!body.to_string().contains("synthetic-wake-token"));
    }
    let control = client
        .post(format!("{endpoint}/v1/sandbox/wake"))
        .bearer_auth("synthetic-wake-token")
        .json(&agentkeys_protocol::ChannelWakeRequest {
            owner_omni: "synthetic-owner".into(),
            channel_id: "synthetic-feed".into(),
            event_ts_ms: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(control.status(), 200);
    let receipt: serde_json::Value = control.json().await.unwrap();
    assert_eq!(receipt["woken"], serde_json::json!([]));
    assert_eq!(receipt["skipped"], 0);
    let refused = client
        .post(format!("{endpoint}/v1/cap/cred-store"))
        .json(&agentkeys_protocol::BrokerCapRequest {
            operator_omni: format!("0x{}", "11".repeat(32)),
            actor_omni: format!("0x{}", "11".repeat(32)),
            device_key_hash: format!("0x{}", "22".repeat(32)),
            service: "example".into(),
            ttl_seconds: None,
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);
}
