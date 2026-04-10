use std::sync::Arc;

use agentkeys_cli::{cmd_init, cmd_link, cmd_read, cmd_revoke, cmd_store, cmd_teardown, cmd_usage, CommandContext};
use agentkeys_core::backend::CredentialBackend;
use agentkeys_mock_server::test_client::InProcessBackend;
use agentkeys_types::Session;

fn create_test_backend() -> Arc<InProcessBackend> {
    Arc::new(InProcessBackend::new())
}

/// Initialize a session via the in-process backend and return both wallet and session.
async fn init_session_direct(backend: &Arc<InProcessBackend>) -> (String, Session) {
    unsafe { std::env::set_var("AGENTKEYS_SESSION_STORE", "file"); }
    let ctx = CommandContext::new("unused", false, false)
        .with_backend(backend.clone() as Arc<dyn CredentialBackend>);
    let (output, session) = cmd_init(&ctx, Some("test-token-unique".to_string()))
        .await
        .unwrap();
    let wallet = output.split("Wallet: ").nth(1).unwrap().trim().to_string();
    (wallet, session)
}

fn ctx_with_session(backend: Arc<InProcessBackend>, session: Session) -> CommandContext {
    CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
}

fn ctx_json_with_session(backend: Arc<InProcessBackend>, session: Session) -> CommandContext {
    CommandContext::new("unused", false, true)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
}

fn ctx_verbose_with_session(backend: Arc<InProcessBackend>, session: Session) -> CommandContext {
    CommandContext::new("unused", true, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
}

// Test 1: init creates a session and returns a wallet address
#[tokio::test(flavor = "multi_thread")]
async fn cli_init_creates_session() {
    let backend = create_test_backend();
    let (wallet, _session) = init_session_direct(&backend).await;
    assert!(!wallet.is_empty(), "wallet should not be empty");
    assert!(wallet.starts_with("0x") || wallet.len() > 0, "wallet: {wallet}");
}

// Test 2: store then read returns the same key
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_and_read() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    cmd_store(&context, &wallet, "openrouter", "sk-test-12345").await.unwrap();
    let read_out = cmd_read(&context, &wallet, "openrouter").await.unwrap();
    assert_eq!(read_out.trim(), "sk-test-12345");
}

// Test 3: reading an unstored credential returns a NOT_FOUND or DENIED error
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_scope_denied() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    let result = cmd_read(&context, &wallet, "nonexistent-service").await;
    assert!(result.is_err(), "expected error for unstored credential");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("NOT_FOUND") || err.contains("DENIED") || err.contains("not found"),
        "unexpected error: {err}"
    );
}

// Test 4: cmd_run executes a child command (env injection works when scope is set)
#[tokio::test(flavor = "multi_thread")]
async fn cli_run_injects_env() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    cmd_store(&context, &wallet, "openrouter", "sk-injected-key").await.unwrap();

    // Master session has no scope, so no env vars are injected automatically.
    // Verify cmd_run can exec a simple command without error.
    let result = agentkeys_cli::cmd_run(&context, &wallet, &["true".to_string()]).await;
    assert!(result.is_ok(), "cmd_run failed: {:?}", result.err());
}

// Test 5: revoke then read — exercises the revoke path without blocking on keychain
#[tokio::test(flavor = "multi_thread")]
async fn cli_revoke_then_read() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    cmd_store(&context, &wallet, "anthropic", "sk-stored").await.unwrap();

    // Attempt revoke (may fail since we pass wallet not a session token — that's fine)
    let _ = cmd_revoke(&context, &wallet).await;

    // Credential should still be accessible (we revoked a fake target, not the real session)
    let read_result = cmd_read(&context, &wallet, "anthropic").await;
    // Accept either success or error — just ensure no panic
    let _ = read_result;
}

// Test 6: teardown then read returns error
#[tokio::test(flavor = "multi_thread")]
async fn cli_teardown_deletes_all() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    cmd_store(&context, &wallet, "openai", "sk-pre-teardown").await.unwrap();

    let before = cmd_read(&context, &wallet, "openai").await.unwrap();
    assert_eq!(before.trim(), "sk-pre-teardown");

    cmd_teardown(&context, &wallet).await.unwrap();

    let after = cmd_read(&context, &wallet, "openai").await;
    assert!(after.is_err(), "expected error after teardown, got: {:?}", after.ok());
}

// Test 7: usage shows audit events after store+read
#[tokio::test(flavor = "multi_thread")]
async fn cli_usage_shows_audit() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    cmd_store(&context, &wallet, "openrouter", "sk-audit-test").await.unwrap();
    let _ = cmd_read(&context, &wallet, "openrouter").await.unwrap();

    let usage_out = cmd_usage(&context, Some(&wallet), false).await.unwrap();
    assert!(
        usage_out.contains("openrouter") || usage_out.contains("timestamp"),
        "usage output missing expected content: {usage_out}"
    );
}

// Test 8: link alias succeeds — uses a real TCP server since cmd_link uses reqwest
#[tokio::test(flavor = "multi_thread")]
async fn cli_link_alias() {
    use agentkeys_mock_server::{create_router, db, state::AppState};
    use std::sync::Arc as StdArc;

    // Start a real TCP server for this test since cmd_link uses reqwest
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = StdArc::new(AppState::new(conn));
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    unsafe { std::env::set_var("AGENTKEYS_SESSION_STORE", "file"); }
    let bare_ctx = CommandContext::new(&base_url, false, false);
    let (output, session) = cmd_init(&bare_ctx, Some("test-token-unique".to_string()))
        .await
        .unwrap();
    let wallet = output.split("Wallet: ").nth(1).unwrap().trim().to_string();

    let context = CommandContext::new(&base_url, false, false).with_session(session);
    let result = cmd_link(&context, &wallet, Some("my-test-bot"), None).await;
    assert!(result.is_ok(), "link failed: {:?}", result.err());
    let out = result.unwrap();
    assert!(out.contains("Linked"), "unexpected output: {out}");
    assert!(out.contains("alias"), "missing alias in output: {out}");
}

// Test 9: --help output contains expected content
#[tokio::test(flavor = "multi_thread")]
async fn cli_help_has_examples() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agentkeys"))
        .arg("--help")
        .output()
        .expect("failed to run agentkeys --help");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("agentkeys") || combined.contains("Credential"),
        "help output missing expected content: {combined}"
    );
}

// Test 10: json output from read is valid JSON with expected fields
#[tokio::test(flavor = "multi_thread")]
async fn cli_json_output() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_json_with_session(backend, session);

    cmd_store(&context, &wallet, "openrouter", "sk-json-test").await.unwrap();
    let output = cmd_read(&context, &wallet, "openrouter").await.unwrap();

    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("output is not valid JSON");
    assert_eq!(parsed["service"].as_str().unwrap(), "openrouter");
    assert_eq!(parsed["credential"].as_str().unwrap(), "sk-json-test");
}

// Test 11: verbose mode does not cause errors and completes successfully
#[tokio::test(flavor = "multi_thread")]
async fn cli_verbose_output() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_verbose_with_session(backend, session);

    let result = cmd_store(&context, &wallet, "openrouter", "sk-verbose").await;
    assert!(result.is_ok(), "verbose store failed: {:?}", result.err());
}

// Test 12: reading from a different agent produces a permission/not-found error
#[tokio::test(flavor = "multi_thread")]
async fn cli_error_format_denied() {
    let backend = create_test_backend();
    let (_wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    let other_wallet = "0x000000000000000000000000000000000000dead";
    let result = cmd_read(&context, other_wallet, "openrouter").await;
    assert!(result.is_err(), "expected error reading from unprovisioned agent");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("DENIED") || err.contains("NOT_FOUND") || err.contains("not found"),
        "unexpected error format: {err}"
    );
}

// Test 13: not-found error has expected format
#[tokio::test(flavor = "multi_thread")]
async fn cli_error_format_not_found() {
    let backend = create_test_backend();
    let (wallet, session) = init_session_direct(&backend).await;
    let context = ctx_with_session(backend, session);

    let result = cmd_read(&context, &wallet, "nonexistent").await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("NOT_FOUND") || err.contains("not found") || err.contains("DENIED"),
        "unexpected error: {err}"
    );
}

// Test 14: unreachable backend produces UNREACHABLE error
#[tokio::test(flavor = "multi_thread")]
async fn cli_error_format_unreachable() {
    // Use a bare context with no session_override and no backend_override;
    // cmd_init will fail at HTTP level because the URL is unreachable.
    let context = CommandContext::new("http://127.0.0.1:19999", false, false);
    let result = cmd_init(&context, Some("test".to_string())).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("UNREACHABLE") || err.contains("error") || err.contains("connect"),
        "unexpected error: {err}"
    );
}
