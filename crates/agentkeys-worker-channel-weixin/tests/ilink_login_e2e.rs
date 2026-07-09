//! Headless iLink LOGIN e2e — boots a MOCK iLink QR-login API (the openclaw-
//! weixin `get_bot_qrcode` + `get_qrcode_status` wire shapes) on an ephemeral
//! port and drives the REAL `--login` state machine (`ilink_login::run_login`)
//! through `scaned → confirmed`, then the `--login-write` upsert. No real
//! WeChat, no human QR scan, no stdin (the mock never asks for a verify code).
//! The LIVE proof (a real spare personal account) stays the operator gate; this
//! pins the login wire contract + the secrets-file write so a regression in
//! either is caught headlessly in the e2e suite.
//!
//! Proves:
//! - the QR ceremony reaches `confirmed`, adopts the returned bot_token /
//!   ilink_bot_id / baseurl,
//! - `--login-write` fills the shipped `REPLACE_ME` placeholder in place, keeps
//!   the other keys, and lands `0600`,
//! - a `confirmed` that OMITS `ilink_bot_id` (a half-bind) is REFUSED loudly
//!   (upstream-plugin parity) — never written as if connected.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use agentkeys_worker_channel_weixin::ilink_login;

const BOT_TOKEN: &str = "fe17118b3cbe@im.bot:secretpart";
const BOT_ID: &str = "fe17118b3cbe@im.bot";

#[derive(Default)]
struct MockLogin {
    status_calls: AtomicUsize,
    /// When true the `confirmed` response OMITS `ilink_bot_id` (the half-bind).
    omit_bot_id: bool,
    /// The mock's own base URL, echoed back as the confirmed `baseurl`.
    base_url: Mutex<String>,
}

async fn mock_qrcode() -> Json<serde_json::Value> {
    Json(json!({ "qrcode": "qr-abc", "qrcode_img_content": "https://mock.ilink/qr/abc" }))
}

async fn mock_status(State(m): State<Arc<MockLogin>>) -> Json<serde_json::Value> {
    // First poll: scanned (verifying). Second: confirmed. No verify_code branch,
    // so run_login never reads stdin — the ceremony is fully headless.
    let n = m.status_calls.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        return Json(json!({ "status": "scaned" }));
    }
    let base = m.base_url.lock().unwrap().clone();
    let mut resp = json!({
        "status": "confirmed",
        "bot_token": BOT_TOKEN,
        "baseurl": base,
        "ilink_user_id": "o9cq803h0qm@im.wechat"
    });
    if !m.omit_bot_id {
        resp["ilink_bot_id"] = json!(BOT_ID);
    }
    Json(resp)
}

async fn spawn_mock(m: Arc<MockLogin>) -> String {
    let app = Router::new()
        .route("/ilink/bot/get_bot_qrcode", post(mock_qrcode))
        .route("/ilink/bot/get_qrcode_status", get(mock_status))
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    *m.base_url.lock().unwrap() = base.clone();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

#[tokio::test]
async fn login_reaches_confirmed_then_login_write_upserts_the_secrets_file() {
    let mock = Arc::new(MockLogin::default());
    let base = spawn_mock(mock.clone()).await;

    // 20 s guard: a route mismatch would otherwise spin to the 8-min deadline.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        ilink_login::run_login(&base, vec![]),
    )
    .await
    .expect("login did not complete in 20s (mock route mismatch?)")
    .expect("run_login errored")
    .expect("expected Some(outcome) on confirmed");

    assert_eq!(outcome.bot_token, BOT_TOKEN);
    assert_eq!(outcome.bot_id, BOT_ID);
    assert_eq!(outcome.base_url, base, "the confirmed baseurl is adopted");

    // --login-write upserts a placeholder template in place: fills the token,
    // keeps the operator omni, lands 0600.
    let path = std::env::temp_dir().join(format!("ak-login-e2e-write-{}.env", std::process::id()));
    std::fs::write(
        &path,
        "AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xfeed\n\
         AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=REPLACE_ME_from_--login\n",
    )
    .unwrap();
    let rebound = ilink_login::write_secrets_file(&path, &outcome).unwrap();
    assert!(!rebound, "filling a REPLACE_ME placeholder is not a rebind");
    let after = std::fs::read_to_string(&path).unwrap();
    assert!(after.contains(&format!("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN={BOT_TOKEN}")));
    assert!(after.contains(&format!("AGENTKEYS_WEIXIN_ILINK_BASE_URL={base}")));
    assert!(after.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xfeed"));
    assert!(!after.contains("REPLACE_ME"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn confirmed_without_bot_id_is_refused_not_written() {
    let mock = Arc::new(MockLogin {
        omit_bot_id: true,
        ..Default::default()
    });
    let base = spawn_mock(mock.clone()).await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        ilink_login::run_login(&base, vec![]),
    )
    .await
    .expect("login did not settle in 20s");

    // `.err()` drops the Ok value (no Debug needed on the secret-bearing outcome).
    let err = result
        .err()
        .expect("a confirmed WITHOUT ilink_bot_id must be refused (upstream parity)");
    assert!(
        err.to_string().contains("ilink_bot_id"),
        "the error names the missing field: {err}"
    );
}
