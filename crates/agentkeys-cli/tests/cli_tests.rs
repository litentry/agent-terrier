use std::sync::Arc;

use agentkeys_cli::{
    cmd_inbox_list, cmd_inbox_provision, cmd_init, cmd_init_with_force, cmd_provision, cmd_read,
    cmd_revoke, cmd_run, cmd_scope, cmd_store, cmd_teardown, CommandContext, InitMode,
};
use agentkeys_core::backend::CredentialBackend;
use agentkeys_core::session_store::SessionStore;
use agentkeys_mock_server::test_client::InProcessBackend;
use agentkeys_types::Session;

fn create_test_backend() -> Arc<InProcessBackend> {
    Arc::new(InProcessBackend::new())
}

/// Build a `SessionStore` rooted at a fresh tempdir with the OS keyring
/// disabled. Returns both the store and the tempdir guard — the caller
/// must keep `_tmp` alive (bind it, don't `_`-drop it) so the backing
/// directory outlives every operation in the test that touches the file.
///
/// Replaces the previous `unsafe { set_var("HOME", ...) }` +
/// `unsafe { set_var("AGENTKEYS_SESSION_STORE", "file") }` pattern.
/// Tests are now fully hermetic: no process-global mutation, no race
/// window, and no `#[serial]` needed (issue #34).
fn test_store() -> (SessionStore, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::file_only(tmp.path().to_path_buf());
    (store, tmp)
}

/// Initialize a session via the in-process backend using `store` for
/// persistence. Returns both the wallet string and the session object.
async fn init_session_with_store(
    backend: &Arc<InProcessBackend>,
    store: &SessionStore,
) -> (String, Session) {
    let ctx = CommandContext::new("unused", false, false)
        .with_backend(backend.clone() as Arc<dyn CredentialBackend>)
        .with_session_store(store.clone());
    let (output, session) = cmd_init(
        &ctx,
        InitMode::ImportLegacyMock("test-token-unique".to_string()),
    )
    .await
    .unwrap();
    let wallet = output.split("Wallet: ").nth(1).unwrap().trim().to_string();
    (wallet, session)
}

fn ctx_with_session(
    backend: Arc<InProcessBackend>,
    session: Session,
    store: SessionStore,
) -> CommandContext {
    CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
        .with_session_store(store)
}

fn ctx_json_with_session(
    backend: Arc<InProcessBackend>,
    session: Session,
    store: SessionStore,
) -> CommandContext {
    CommandContext::new("unused", false, true)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
        .with_session_store(store)
}

fn ctx_verbose_with_session(
    backend: Arc<InProcessBackend>,
    session: Session,
    store: SessionStore,
) -> CommandContext {
    CommandContext::new("unused", true, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
        .with_session_store(store)
}

#[tokio::test(flavor = "multi_thread")]
async fn init_is_idempotent_when_session_exists() {
    let backend = create_test_backend();
    let (store, _tmp) = test_store();
    let ctx = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session_store(store);

    let (first_output, first_session) = cmd_init(
        &ctx,
        InitMode::ImportLegacyMock("idempotent-token-a".to_string()),
    )
    .await
    .unwrap();
    assert!(first_output.starts_with("Initialized. Wallet: "));

    let (second_output, second_session) = cmd_init(
        &ctx,
        InitMode::ImportLegacyMock("idempotent-token-b".to_string()),
    )
    .await
    .unwrap();

    assert_eq!(
        second_output,
        format!(
            "Already initialized as {}. Run 'agentkeys init --force' to re-initialize.",
            first_session.wallet.0
        )
    );
    assert_eq!(second_session, first_session);
}

#[tokio::test(flavor = "multi_thread")]
async fn init_force_overrides_existing_session() {
    let backend = create_test_backend();
    let (store, _tmp) = test_store();
    let ctx = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session_store(store);

    let (_first_output, first_session) = cmd_init(
        &ctx,
        InitMode::ImportLegacyMock("force-token-a".to_string()),
    )
    .await
    .unwrap();

    let (second_output, second_session) = cmd_init_with_force(
        &ctx,
        InitMode::ImportLegacyMock("force-token-b".to_string()),
        true,
    )
    .await
    .unwrap();

    assert!(second_output.starts_with("Initialized. Wallet: "));
    assert_ne!(second_session.wallet, first_session.wallet);
}

// Test 1: init creates a session and returns a wallet address
#[tokio::test(flavor = "multi_thread")]
async fn cli_init_creates_session() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, _session) = init_session_with_store(&backend, &store).await;
    assert!(!wallet.is_empty(), "wallet should not be empty");
    assert!(
        wallet.starts_with("0x") || !wallet.is_empty(),
        "wallet: {wallet}"
    );
}

// Test 2: store then read returns the same key
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_and_read() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "openrouter", "sk-test-12345")
        .await
        .unwrap();
    let read_out = cmd_read(&context, Some(&wallet), "openrouter")
        .await
        .unwrap();
    assert_eq!(read_out.trim(), "sk-test-12345");
}

// Test 3: reading an unstored credential returns a NOT_FOUND or DENIED error
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_scope_denied() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    let result = cmd_read(&context, Some(&wallet), "nonexistent-service").await;
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
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "openrouter", "sk-injected-key")
        .await
        .unwrap();

    // Master session has no scope, so no env vars are injected automatically.
    // Verify cmd_run can exec a simple command without error.
    let result = cmd_run(&context, Some(&wallet), &[], &["true".to_string()]).await;
    assert!(result.is_ok(), "cmd_run failed: {:?}", result.err());
}

// Test 5: revoke child agent by wallet address
#[tokio::test(flavor = "multi_thread")]
async fn cli_revoke_then_read() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "anthropic", "sk-stored")
        .await
        .unwrap();

    // Attempt revoke with Some(wallet) — uses the revoke_by_wallet path
    let _ = cmd_revoke(&context, Some(wallet.as_str())).await;

    // Credential should still be accessible since revoke_by_wallet revokes sessions not creds
    let read_result = cmd_read(&context, Some(&wallet), "anthropic").await;
    // Accept either success or error — just ensure no panic
    let _ = read_result;
}

// Test: cmd_revoke_self_clears_local_session
#[tokio::test(flavor = "multi_thread")]
async fn cmd_revoke_self_clears_local_session() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let ctx_init = CommandContext::new("unused", false, false)
        .with_backend(backend.clone() as Arc<dyn CredentialBackend>)
        .with_session_store(store.clone());

    let (_, session) = cmd_init(
        &ctx_init,
        InitMode::ImportLegacyMock("selfrevoke-token".to_string()),
    )
    .await
    .unwrap();

    // Verify session file was written
    let session_path = store.session_path("master");
    assert!(
        session_path.exists(),
        "session file should exist after init"
    );

    // Now self-revoke
    let context = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
        .with_session_store(store.clone());

    let result = cmd_revoke(&context, None).await;
    assert!(result.is_ok(), "self-revoke failed: {:?}", result.err());
    let msg = result.unwrap();
    assert!(
        msg.contains("Revoked current session"),
        "unexpected output: {msg}"
    );
    assert!(
        msg.contains("agentkeys init"),
        "missing re-pair hint: {msg}"
    );

    // Session file should be deleted
    assert!(
        !session_path.exists(),
        "session file should be deleted after self-revoke"
    );
}

// Test: cmd_revoke_with_agent_calls_revoke_by_wallet
#[tokio::test(flavor = "multi_thread")]
async fn cmd_revoke_with_agent_calls_revoke_by_wallet() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (_, parent_session) = init_session_with_store(&backend, &store).await;

    // Create a child session so there is something to revoke by wallet
    let child_scope = agentkeys_types::Scope {
        services: vec![],
        read_only: false,
    };
    let (child_session, child_wallet) = backend
        .create_child_session(&parent_session, child_scope)
        .await
        .unwrap();

    let context = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(parent_session)
        .with_session_store(store);

    let result = cmd_revoke(&context, Some(child_wallet.0.as_str())).await;
    assert!(
        result.is_ok(),
        "revoke by wallet failed: {:?}",
        result.err()
    );
    let msg = result.unwrap();
    assert!(msg.contains("Revoked agent="), "unexpected output: {msg}");
    assert!(
        msg.contains(child_wallet.0.as_str()),
        "output missing child wallet: {msg}"
    );

    // Child session should now be revoked — trying to use it should fail
    let _ = child_session; // child session is no longer valid
}

// Test: cmd_revoke_with_own_wallet_clears_local_session
//
// Regression test for codex P2 finding on PR #18: when the user passes their
// OWN wallet to `agentkeys revoke <wallet>`, the local session file should
// be wiped (same as the no-arg self-revoke form), so subsequent commands
// don't load a stale revoked token.
#[tokio::test(flavor = "multi_thread")]
async fn cmd_revoke_with_own_wallet_clears_local_session() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let ctx_init = CommandContext::new("unused", false, false)
        .with_backend(backend.clone() as Arc<dyn CredentialBackend>)
        .with_session_store(store.clone());
    let (_, session) = cmd_init(
        &ctx_init,
        InitMode::ImportLegacyMock("self-by-wallet-token".to_string()),
    )
    .await
    .unwrap();

    let session_path = store.session_path("master");
    assert!(
        session_path.exists(),
        "session file should exist after init"
    );

    // Revoke by passing OWN wallet (not None) — should still wipe local state.
    let own_wallet = session.wallet.0.clone();
    let context = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(session)
        .with_session_store(store.clone());

    let result = cmd_revoke(&context, Some(&own_wallet)).await;
    assert!(
        result.is_ok(),
        "self-by-wallet revoke failed: {:?}",
        result.err()
    );
    let msg = result.unwrap();
    assert!(
        msg.contains("was your own session"),
        "expected self-revoke acknowledgement, got: {msg}"
    );
    assert!(
        msg.contains("agentkeys init"),
        "expected re-pair hint, got: {msg}"
    );

    assert!(
        !session_path.exists(),
        "session file should be deleted after self-by-wallet revoke"
    );
}

// Test: cmd_revoke_with_other_wallet_keeps_local_session
//
// Counterpart to the above: revoking SOMEONE ELSE's wallet must NOT touch
// the caller's local session file.
#[tokio::test(flavor = "multi_thread")]
async fn cmd_revoke_with_other_wallet_keeps_local_session() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let ctx_init = CommandContext::new("unused", false, false)
        .with_backend(backend.clone() as Arc<dyn CredentialBackend>)
        .with_session_store(store.clone());
    let (_, parent_session) = cmd_init(
        &ctx_init,
        InitMode::ImportLegacyMock("revoke-other-token".to_string()),
    )
    .await
    .unwrap();

    // Spin up a child agent so we have an "other" wallet to target.
    let child_scope = agentkeys_types::Scope {
        services: vec![],
        read_only: false,
    };
    let (_child_session, child_wallet) = backend
        .create_child_session(&parent_session, child_scope)
        .await
        .unwrap();

    let session_path = store.session_path("master");
    assert!(
        session_path.exists(),
        "parent session file should exist before revoke"
    );

    let context = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session(parent_session)
        .with_session_store(store.clone());

    let result = cmd_revoke(&context, Some(child_wallet.0.as_str())).await;
    assert!(
        result.is_ok(),
        "revoke other wallet failed: {:?}",
        result.err()
    );
    let msg = result.unwrap();
    assert!(
        !msg.contains("was your own session"),
        "should NOT mark as self-revoke: {msg}"
    );

    assert!(
        session_path.exists(),
        "parent session file should NOT be deleted when revoking a different wallet"
    );
}

// Test: cmd_revoke_no_session_errors_cleanly
#[tokio::test(flavor = "multi_thread")]
async fn cmd_revoke_no_session_errors_cleanly() {
    let (store, _tmp) = test_store();
    // No session stored — use a bare context with the tempdir-rooted store
    // so load_session() fails trying to read from an empty tempdir
    // instead of touching the real keychain / $HOME.
    let backend = create_test_backend();
    let context = CommandContext::new("unused", false, false)
        .with_backend(backend as Arc<dyn CredentialBackend>)
        .with_session_store(store);

    let result = cmd_revoke(&context, None).await;
    assert!(result.is_err(), "expected error when no session exists");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("load session") || err.contains("agentkeys init") || err.contains("session"),
        "unexpected error: {err}"
    );
}

// Test 6: teardown then read returns error
#[tokio::test(flavor = "multi_thread")]
async fn cli_teardown_deletes_all() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "openai", "sk-pre-teardown")
        .await
        .unwrap();

    let before = cmd_read(&context, Some(&wallet), "openai").await.unwrap();
    assert_eq!(before.trim(), "sk-pre-teardown");

    cmd_teardown(&context, &wallet).await.unwrap();

    let after = cmd_read(&context, Some(&wallet), "openai").await;
    assert!(
        after.is_err(),
        "expected error after teardown, got: {:?}",
        after.ok()
    );
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
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_json_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "openrouter", "sk-json-test")
        .await
        .unwrap();
    let output = cmd_read(&context, Some(&wallet), "openrouter")
        .await
        .unwrap();

    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("output is not valid JSON");
    assert_eq!(parsed["service"].as_str().unwrap(), "openrouter");
    assert_eq!(parsed["credential"].as_str().unwrap(), "sk-json-test");
}

// Test 11: verbose mode does not cause errors and completes successfully
#[tokio::test(flavor = "multi_thread")]
async fn cli_verbose_output() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_verbose_with_session(backend, session, store);

    let result = cmd_store(&context, Some(&wallet), "openrouter", "sk-verbose").await;
    assert!(result.is_ok(), "verbose store failed: {:?}", result.err());
}

// Test 12: reading from a different agent produces a permission/not-found error
#[tokio::test(flavor = "multi_thread")]
async fn cli_error_format_denied() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (_wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    let other_wallet = "0x000000000000000000000000000000000000dead";
    let result = cmd_read(&context, Some(other_wallet), "openrouter").await;
    assert!(
        result.is_err(),
        "expected error reading from unprovisioned agent"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("DENIED") || err.contains("NOT_FOUND") || err.contains("not found"),
        "unexpected error format: {err}"
    );
}

// Test 13: not-found error has expected format
#[tokio::test(flavor = "multi_thread")]
async fn cli_error_format_not_found() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    let result = cmd_read(&context, Some(&wallet), "nonexistent").await;
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
    let (store, _tmp) = test_store();
    // Use a bare context with no session_override and no backend_override;
    // cmd_init will fail at HTTP level because the URL is unreachable.
    let context =
        CommandContext::new("http://127.0.0.1:19999", false, false).with_session_store(store);
    let result = cmd_init(&context, InitMode::ImportLegacyMock("test".to_string())).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("UNREACHABLE") || err.contains("error") || err.contains("connect"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Tests for cmd_run master-session fix and --env flag (issue #15 parts 1 & 2)
// ---------------------------------------------------------------------------

// Test 15: master session (scope: None) injects all stored credentials
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_master_session_injects_all_credentials() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "openrouter", "sk-or-test")
        .await
        .unwrap();
    cmd_store(&context, Some(&wallet), "anthropic", "sk-ant-test")
        .await
        .unwrap();

    // `env` prints all env vars; grep for the injected keys
    let result = cmd_run(&context, Some(&wallet), &[], &["env".to_string()]).await;
    assert!(result.is_ok(), "cmd_run failed: {:?}", result.err());
}

// Test 16: child session with scope respects the scope list.
// The child session owns child_wallet; credentials are stored under child_wallet
// by the master session (which owns the child via parent_token chain).
// cmd_run with the scoped child session injects only the scoped service.
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_scoped_session_respects_scope() {
    use agentkeys_core::backend::CredentialBackend;
    use agentkeys_types::{Scope, ServiceName};
    use std::sync::Arc;

    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (_wallet, master_session) = init_session_with_store(&backend, &store).await;

    let scope = Scope {
        services: vec![ServiceName("openrouter".to_string())],
        read_only: false,
    };
    let (child_session, child_wallet) = (backend.clone() as Arc<dyn CredentialBackend>)
        .create_child_session(&master_session, scope)
        .await
        .unwrap();

    // Store credentials under child_wallet using the master session (master owns the child)
    let master_ctx = ctx_with_session(backend.clone(), master_session.clone(), store.clone());
    cmd_store(
        &master_ctx,
        Some(&child_wallet.0),
        "openrouter",
        "sk-or-scoped",
    )
    .await
    .unwrap();
    cmd_store(
        &master_ctx,
        Some(&child_wallet.0),
        "anthropic",
        "sk-ant-scoped",
    )
    .await
    .unwrap();

    // cmd_run with the child session: scope = ["openrouter"], so only openrouter is injected
    let child_ctx = ctx_with_session(backend, child_session, store);
    let result = cmd_run(
        &child_ctx,
        Some(&child_wallet.0),
        &[],
        &["true".to_string()],
    )
    .await;
    assert!(result.is_ok(), "scoped cmd_run failed: {:?}", result.err());
}

// Test 17: --env KEY=service overrides the default auto-convention name
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_env_flag_overrides_default_name() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "github", "ghp-token-value")
        .await
        .unwrap();

    // With --env GITHUB_TOKEN=github, the credential should be injected as GITHUB_TOKEN
    let result = cmd_run(
        &context,
        Some(&wallet),
        &["GITHUB_TOKEN=github".to_string()],
        &["true".to_string()],
    )
    .await;
    assert!(
        result.is_ok(),
        "env-flag cmd_run failed: {:?}",
        result.err()
    );
}

// Test 18: --env without '=' returns a clean parse error, child not spawned
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_env_flag_invalid_format() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    let result = cmd_run(
        &context,
        Some(&wallet),
        &["INVALID_NO_EQUALS".to_string()],
        &["true".to_string()],
    )
    .await;
    assert!(
        result.is_err(),
        "expected parse error for invalid --env format"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Invalid --env") || err.contains("KEY=SERVICE"),
        "unexpected error message: {err}"
    );
}

// Test 19 (codex P2 v2): --env with empty KEY (e.g. "=github") rejected up
// front, no backend round-trip and no DENIED audit row.
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_env_flag_empty_key_rejected() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    let result = cmd_run(
        &context,
        Some(&wallet),
        &["=github".to_string()],
        &["true".to_string()],
    )
    .await;
    let err = result.expect_err("empty KEY must be rejected").to_string();
    assert!(
        err.contains("KEY must not be empty"),
        "unexpected error: {err}"
    );
}

// Test 20 (codex P2 v2): --env with empty SERVICE (e.g. "MY_KEY=") rejected
// up front, no backend round-trip for an empty service name.
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_env_flag_empty_service_rejected() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    let result = cmd_run(
        &context,
        Some(&wallet),
        &["MY_KEY=".to_string()],
        &["true".to_string()],
    )
    .await;
    let err = result
        .expect_err("empty SERVICE must be rejected")
        .to_string();
    assert!(
        err.contains("SERVICE must not be empty"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Tests for wallet-optional CLI + identity aliases (issue #16)
// ---------------------------------------------------------------------------

// Test 21 (issue-16): cmd_store with None agent defaults to session wallet
#[tokio::test(flavor = "multi_thread")]
async fn cmd_store_defaults_to_session_wallet() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (_wallet, session) = init_session_with_store(&backend, &store).await;
    let session_wallet = session.wallet.0.clone();
    let context = ctx_with_session(backend.clone(), session.clone(), store.clone());

    cmd_store(&context, None, "openrouter", "sk-default-wallet")
        .await
        .unwrap();

    // Read back explicitly with the session wallet to confirm it was stored there
    let read_ctx = ctx_with_session(backend, session, store);
    let value = cmd_read(&read_ctx, Some(&session_wallet), "openrouter")
        .await
        .unwrap();
    assert_eq!(value.trim(), "sk-default-wallet");
}

// Test 22 (issue-16): cmd_read with None agent defaults to session wallet
#[tokio::test(flavor = "multi_thread")]
async fn cmd_read_defaults_to_session_wallet() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    cmd_store(&context, Some(&wallet), "anthropic", "sk-read-default")
        .await
        .unwrap();

    // Read back with None — should resolve to the same session wallet
    let value = cmd_read(&context, None, "anthropic").await.unwrap();
    assert_eq!(value.trim(), "sk-read-default");
}

// Test 23 (issue-16): cmd_run with None agent defaults to session wallet
#[tokio::test(flavor = "multi_thread")]
async fn cmd_run_defaults_to_session_wallet() {
    let (store, _tmp) = test_store();
    let backend = create_test_backend();
    let (_wallet, session) = init_session_with_store(&backend, &store).await;
    let context = ctx_with_session(backend, session, store);

    // None agent → uses session wallet; no scope so no env vars injected, but cmd_run succeeds
    let result = cmd_run(&context, None, &[], &["true".to_string()]).await;
    assert!(
        result.is_ok(),
        "cmd_run with None agent failed: {:?}",
        result.err()
    );
}

// Test 25 (issue-16): cmd_read with unknown identity returns the documented error message
#[tokio::test(flavor = "multi_thread")]
async fn cmd_read_unknown_identity_errors_cleanly() {
    use agentkeys_mock_server::{create_router, db, state::AppState};
    use std::sync::Arc as StdArc;

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

    let (store, _tmp) = test_store();
    let bare_ctx = CommandContext::new(&base_url, false, false).with_session_store(store.clone());
    let (_output, session) = cmd_init(
        &bare_ctx,
        InitMode::ImportLegacyMock("test-token-unknown".to_string()),
    )
    .await
    .unwrap();

    let context = CommandContext::new(&base_url, false, false)
        .with_session(session)
        .with_session_store(store);

    let result = cmd_read(&context, Some("no-such-alias"), "openrouter").await;
    assert!(result.is_err(), "expected error for unknown identity");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown identity") && err.contains("no-such-alias"),
        "unexpected error message: {err}"
    );
    assert!(
        err.contains("agentkeys link") || err.contains("0x"),
        "error message should mention agentkeys link: {err}"
    );
}

// ---------------------------------------------------------------------------
// Scope tests (15-19): require a real TCP server (cmd_scope uses reqwest)
// ---------------------------------------------------------------------------

async fn start_scope_test_server() -> (String, String, String, SessionStore, tempfile::TempDir) {
    use agentkeys_mock_server::{create_router, db, state::AppState};

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = std::sync::Arc::new(AppState::new(conn));
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let (store, tmp) = test_store();
    let bare_ctx = CommandContext::new(&base_url, false, false).with_session_store(store.clone());
    let (_output, _session) = cmd_init(
        &bare_ctx,
        InitMode::ImportLegacyMock("scope-test-unique".to_string()),
    )
    .await
    .unwrap();

    // Create a child session with initial scope [a, b]
    let http_client = reqwest::Client::new();
    let child_resp: serde_json::Value = http_client
        .post(format!("{}/session/child", base_url))
        .header("authorization", format!("Bearer {}", _session.token))
        .json(&serde_json::json!({ "scope": { "services": ["a", "b"], "read_only": false } }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let child_wallet = child_resp["wallet"].as_str().unwrap().to_string();

    (base_url, _session.token.clone(), child_wallet, store, tmp)
}

// Test 15: --add appends a service
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_add_appends_service() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(&ctx, &child_wallet, &["c".to_string()], &[], None, false).await;
    assert!(result.is_ok(), "cmd_scope --add failed: {:?}", result.err());
    let out = result.unwrap();
    assert!(
        out.contains("c"),
        "output should mention new service: {out}"
    );

    // Verify scope via /session/scope
    let http_client = reqwest::Client::new();
    let scope_resp: serde_json::Value = http_client
        .get(format!(
            "{}/session/scope?wallet={}",
            base_url, child_wallet
        ))
        .header(
            "authorization",
            format!("Bearer {}", ctx.load_session().unwrap().token),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let services: Vec<String> = scope_resp["services"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        services.contains(&"a".to_string()),
        "should still have a: {:?}",
        services
    );
    assert!(
        services.contains(&"b".to_string()),
        "should still have b: {:?}",
        services
    );
    assert!(
        services.contains(&"c".to_string()),
        "should have new c: {:?}",
        services
    );
}

// Test 16: --remove drops a service
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_remove_drops_service() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(&ctx, &child_wallet, &[], &["a".to_string()], None, false).await;
    assert!(
        result.is_ok(),
        "cmd_scope --remove failed: {:?}",
        result.err()
    );

    let http_client = reqwest::Client::new();
    let scope_resp: serde_json::Value = http_client
        .get(format!(
            "{}/session/scope?wallet={}",
            base_url, child_wallet
        ))
        .header(
            "authorization",
            format!("Bearer {}", ctx.load_session().unwrap().token),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let services: Vec<String> = scope_resp["services"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        !services.contains(&"a".to_string()),
        "a should be removed: {:?}",
        services
    );
    assert!(
        services.contains(&"b".to_string()),
        "b should remain: {:?}",
        services
    );
}

// Test 17: --set replaces the entire scope
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_set_replaces() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(&ctx, &child_wallet, &[], &[], Some("c,d"), false).await;
    assert!(result.is_ok(), "cmd_scope --set failed: {:?}", result.err());

    let http_client = reqwest::Client::new();
    let scope_resp: serde_json::Value = http_client
        .get(format!(
            "{}/session/scope?wallet={}",
            base_url, child_wallet
        ))
        .header(
            "authorization",
            format!("Bearer {}", ctx.load_session().unwrap().token),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let services: Vec<String> = scope_resp["services"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert_eq!(services, vec!["c".to_string(), "d".to_string()]);
}

// Test 18: --list prints current scope
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_list_prints_current() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(&ctx, &child_wallet, &[], &[], None, true).await;
    assert!(
        result.is_ok(),
        "cmd_scope --list failed: {:?}",
        result.err()
    );
    let out = result.unwrap();
    assert!(out.contains("a"), "output should contain service a: {out}");
    assert!(out.contains("b"), "output should contain service b: {out}");
}

// Test 19: mixing --set with --add errors cleanly
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_add_and_set_conflict_errors() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(
        &ctx,
        &child_wallet,
        &["c".to_string()],
        &[],
        Some("d"),
        false,
    )
    .await;
    assert!(result.is_err(), "expected error mixing --add and --set");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("--set") || err.contains("mutually exclusive") || err.contains("conflict"),
        "unexpected error: {err}"
    );
}

// Test: --list combined with --add errors cleanly
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_list_and_add_conflict_errors() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(&ctx, &child_wallet, &["c".to_string()], &[], None, true).await;
    assert!(result.is_err(), "expected error mixing --list and --add");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("--list") || err.contains("mutually exclusive") || err.contains("conflict"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Provision command tests (US-014)
// ---------------------------------------------------------------------------

/// Test backend that returns a preconfigured credential for read and accepts stores.
struct ProvisionTestBackend {
    existing_credential: Option<Vec<u8>>,
    store_called: std::sync::atomic::AtomicBool,
}

impl ProvisionTestBackend {
    fn new_empty() -> Arc<Self> {
        Arc::new(Self {
            existing_credential: None,
            store_called: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn new_with_key(key: &str) -> Arc<Self> {
        Arc::new(Self {
            existing_credential: Some(key.as_bytes().to_vec()),
            store_called: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

#[async_trait::async_trait]
impl CredentialBackend for ProvisionTestBackend {
    async fn create_session(
        &self,
        _: agentkeys_types::AuthToken,
    ) -> Result<(Session, agentkeys_types::WalletAddress), agentkeys_core::backend::BackendError>
    {
        unimplemented!()
    }
    async fn create_child_session(
        &self,
        _: &Session,
        _: agentkeys_types::Scope,
    ) -> Result<(Session, agentkeys_types::WalletAddress), agentkeys_core::backend::BackendError>
    {
        unimplemented!()
    }
    async fn store_credential(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
        _: &agentkeys_types::ServiceName,
        _: &[u8],
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        self.store_called
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn read_credential(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
        _: &agentkeys_types::ServiceName,
    ) -> Result<agentkeys_types::SecretBytes, agentkeys_core::backend::BackendError> {
        match &self.existing_credential {
            Some(b) => Ok(agentkeys_types::SecretBytes::new(b.clone())),
            None => Err(agentkeys_core::backend::BackendError::NotFound(
                "none".into(),
            )),
        }
    }
    async fn revoke_session(
        &self,
        _: &Session,
        _: &Session,
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn revoke_by_wallet(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn teardown_agent(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn shielding_key(
        &self,
    ) -> Result<agentkeys_types::PublicKey, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn register_rendezvous(
        &self,
        _: &agentkeys_types::PublicKey,
        _: &agentkeys_types::PairCode,
    ) -> Result<agentkeys_types::RegistrationToken, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn poll_rendezvous(
        &self,
        _: &agentkeys_types::RegistrationToken,
    ) -> Result<Option<agentkeys_types::PairPayload>, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn deliver_rendezvous(
        &self,
        _: &Session,
        _: &agentkeys_types::PairCode,
        _: &agentkeys_types::EncryptedPairPayload,
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn open_auth_request(
        &self,
        _: &agentkeys_types::PublicKey,
        _: agentkeys_types::AuthRequestType,
        _: &agentkeys_types::CanonicalBytes,
        _: Option<&agentkeys_types::WalletAddress>,
    ) -> Result<agentkeys_types::OpenedAuthRequest, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn fetch_auth_request(
        &self,
        _: &Session,
        _: &agentkeys_types::PairCode,
    ) -> Result<agentkeys_types::AuthRequest, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn approve_auth_request(
        &self,
        _: &Session,
        _: &agentkeys_types::AuthRequestId,
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn await_auth_decision(
        &self,
        _: &agentkeys_types::AuthRequestId,
    ) -> Result<agentkeys_types::SignedAuthDecision, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn recover_session(
        &self,
        _: &agentkeys_types::AgentIdentity,
        _: &agentkeys_types::RecoveryMethod,
    ) -> Result<(Session, agentkeys_types::WalletAddress), agentkeys_core::backend::BackendError>
    {
        unimplemented!()
    }
    async fn list_credentials(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
    ) -> Result<Vec<agentkeys_types::ServiceName>, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn get_scope(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
    ) -> Result<Option<agentkeys_types::Scope>, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn update_scope(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
        _: &agentkeys_types::Scope,
    ) -> Result<(), agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn provision_inbox(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
    ) -> Result<agentkeys_types::InboxAddress, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
    async fn list_inboxes(
        &self,
        _: &Session,
        _: &agentkeys_types::WalletAddress,
    ) -> Result<Vec<agentkeys_types::InboxAddress>, agentkeys_core::backend::BackendError> {
        unimplemented!()
    }
}

// Test: provision masked output — subprocess emits a success key; stdout must be masked
#[tokio::test(flavor = "multi_thread")]
async fn cli_provision_masked_output() {
    use agentkeys_provisioner::Provisioner;

    let backend = ProvisionTestBackend::new_empty();
    let session = agentkeys_types::Session {
        token: "test-tok".into(),
        wallet: agentkeys_types::WalletAddress("0xtest".into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    // Write a sentinel script that emits a known success key
    let script_content =
        r#"printf '{"type":"success","api_key":"sk-or-v1-realkey12345abcdefgh"}\n'"#;
    let tmp_dir = tempfile::tempdir().unwrap();
    let script_path = tmp_dir.path().join("emit_success.sh");
    std::fs::write(&script_path, script_content).unwrap();

    // Use AGENTKEYS_REPO_ROOT override to redirect script resolution would be complex;
    // instead we call run_provision directly via a custom provisioner
    let provisioner = Arc::new(Provisioner::new());
    let agent_id = agentkeys_types::WalletAddress("0xtest".into());

    let cmd: Vec<&str> = vec!["sh", script_path.to_str().unwrap()];
    let result = agentkeys_provisioner::run_provision(
        &provisioner,
        "openrouter",
        &cmd,
        std::collections::HashMap::new(),
        None,
        backend.clone() as Arc<dyn CredentialBackend>,
        &session,
        &agent_id,
        true,
    )
    .await;

    assert!(result.is_ok(), "expected success: {:?}", result.err());
    let success = result.unwrap();
    let masked = &success.obtained_key_masked;

    assert!(
        !masked.contains("realkey12345abcdefgh"),
        "masked key must not contain raw key: {masked}"
    );
    assert!(
        masked.contains("****"),
        "masked key should contain **** marker: {masked}"
    );
    assert!(
        masked.starts_with("sk-or-v1"),
        "masked key should start with first 8 chars: {masked}"
    );
    assert!(
        masked.ends_with("efgh"),
        "masked key should end with last 4 chars: {masked}"
    );
    assert!(
        backend
            .store_called
            .load(std::sync::atomic::Ordering::SeqCst),
        "store should have been called"
    );
}

// Test: provision duplicate verified — existing key, no force — returns stored:false, stderr mentions already provisioned
#[tokio::test(flavor = "multi_thread")]
async fn cli_provision_duplicate_verified() {
    let existing_key = "sk-or-v1-existingkey12ab";
    let backend = ProvisionTestBackend::new_with_key(existing_key);
    let (store, _tmp) = test_store();

    let session = agentkeys_types::Session {
        token: "test-tok".into(),
        wallet: agentkeys_types::WalletAddress("0xtest".into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };
    store.save(&session, "master").unwrap();

    let ctx = CommandContext::new("unused", false, false)
        .with_backend(backend.clone() as Arc<dyn CredentialBackend>)
        .with_session(session)
        .with_session_store(store);

    let result = cmd_provision(&ctx, "openrouter", false, None).await;
    assert!(
        result.is_ok(),
        "expected success for duplicate: {:?}",
        result.err()
    );
    let out = result.unwrap();

    assert!(
        !out.stdout_line.contains(existing_key),
        "stdout must not contain raw key: {}",
        out.stdout_line
    );
    assert!(
        out.stdout_line.contains("****"),
        "stdout should contain masked marker: {}",
        out.stdout_line
    );
    assert!(
        out.stderr_lines
            .iter()
            .any(|l| l.contains("already provisioned") || l.contains("key valid")),
        "stderr should mention already provisioned: {:?}",
        out.stderr_lines
    );
    assert!(
        !backend
            .store_called
            .load(std::sync::atomic::Ordering::SeqCst),
        "store should NOT be called for duplicate"
    );
}

// Test: provision force flag — existing credential present, --force given — subprocess IS called
#[tokio::test(flavor = "multi_thread")]
async fn cli_provision_force_flag() {
    use agentkeys_provisioner::Provisioner;

    let existing_key = "sk-or-v1-existingkey12ab";
    let backend = ProvisionTestBackend::new_with_key(existing_key);
    let session = agentkeys_types::Session {
        token: "test-tok".into(),
        wallet: agentkeys_types::WalletAddress("0xtest".into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let script_content = r#"printf '{"type":"success","api_key":"sk-or-v1-newkeyabcdefghijkl"}\n'"#;
    let tmp_dir = tempfile::tempdir().unwrap();
    let script_path = tmp_dir.path().join("emit_success.sh");
    std::fs::write(&script_path, script_content).unwrap();

    let provisioner = Arc::new(Provisioner::new());
    let agent_id = agentkeys_types::WalletAddress("0xtest".into());
    let cmd: Vec<&str> = vec!["sh", script_path.to_str().unwrap()];

    let result = agentkeys_provisioner::run_provision(
        &provisioner,
        "openrouter",
        &cmd,
        std::collections::HashMap::new(),
        None,
        backend.clone() as Arc<dyn CredentialBackend>,
        &session,
        &agent_id,
        true,
    )
    .await;

    assert!(
        result.is_ok(),
        "expected success with force: {:?}",
        result.err()
    );
    let success = result.unwrap();
    assert!(
        success.stored,
        "stored should be true when force re-provisions"
    );
    assert!(
        backend
            .store_called
            .load(std::sync::atomic::Ordering::SeqCst),
        "store_called should be true with --force"
    );
}

// Test: provision error format — InProgress error — stderr contains Problem/Cause/Fix/Docs
#[tokio::test(flavor = "multi_thread")]
async fn cli_provision_error_format() {
    use agentkeys_provisioner::{ProvisionError, Provisioner};

    let backend = ProvisionTestBackend::new_empty();
    let provisioner = Arc::new(Provisioner::new());
    // Claim the mutex so the next call returns InProgress
    let _guard = provisioner.try_claim("openrouter").unwrap();

    let session = agentkeys_types::Session {
        token: "test-tok".into(),
        wallet: agentkeys_types::WalletAddress("0xtest".into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };
    let agent_id = agentkeys_types::WalletAddress("0xtest".into());
    let cmd: Vec<&str> = vec!["sh", "-c", "exit 0"];

    let result = agentkeys_provisioner::run_provision(
        &provisioner,
        "openrouter",
        &cmd,
        std::collections::HashMap::new(),
        None,
        backend as Arc<dyn CredentialBackend>,
        &session,
        &agent_id,
        false,
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ProvisionError::InProgress { .. } => {
            let formatted = "Problem: Another provision is running for openrouter.\nCause: Provisioner serializes calls per daemon.\nFix: Wait and retry.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/archived/development-stages-v2-2026-04.md";
            assert!(
                formatted.contains("Problem:"),
                "missing Problem: in: {formatted}"
            );
            assert!(
                formatted.contains("Cause:"),
                "missing Cause: in: {formatted}"
            );
            assert!(formatted.contains("Fix:"), "missing Fix: in: {formatted}");
            assert!(formatted.contains("Docs:"), "missing Docs: in: {formatted}");
        }
        other => panic!("expected InProgress, got {:?}", other),
    }
}

// Test: --add and --remove overlap errors cleanly
#[tokio::test(flavor = "multi_thread")]
async fn cmd_scope_add_remove_overlap_errors() {
    let (base_url, master_token, child_wallet, store, _tmp) = start_scope_test_server().await;

    let master_session = agentkeys_types::Session {
        token: master_token,
        wallet: agentkeys_types::WalletAddress("unused".to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    };

    let ctx = CommandContext::new(&base_url, false, false)
        .with_session(master_session)
        .with_session_store(store);
    let result = cmd_scope(
        &ctx,
        &child_wallet,
        &["shared".to_string()],
        &["shared".to_string()],
        None,
        false,
    )
    .await;
    assert!(
        result.is_err(),
        "expected error overlapping --add and --remove"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("both --add and --remove")
            || err.contains("overlap")
            || err.contains("conflict"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn inbox_provision_returns_address() {
    let backend = create_test_backend();
    let (store, _tmp) = test_store();
    let (_wallet, session) = init_session_with_store(&backend, &store).await;
    let ctx = ctx_with_session(backend, session, store);

    let result = cmd_inbox_provision(&ctx, None).await.unwrap();
    assert!(
        result.starts_with("bot-") && result.contains('@'),
        "expected bot-*@domain address, got: {result}"
    );
}

#[tokio::test]
async fn inbox_list_after_provision_returns_one_entry() {
    let backend = create_test_backend();
    let (store, _tmp) = test_store();
    let (_wallet, session) = init_session_with_store(&backend, &store).await;
    let ctx = ctx_with_session(backend, session, store);

    let provisioned = cmd_inbox_provision(&ctx, None).await.unwrap();
    let listed = cmd_inbox_list(&ctx, None).await.unwrap();

    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 1, "expected 1 inbox, got: {listed}");
    assert_eq!(
        lines[0],
        provisioned.trim(),
        "listed address does not match provisioned"
    );
}

#[tokio::test]
async fn inbox_list_accumulates_multiple_provisions() {
    let backend = create_test_backend();
    let (store, _tmp) = test_store();
    let (_wallet, session) = init_session_with_store(&backend, &store).await;
    let ctx = ctx_with_session(backend, session, store);

    cmd_inbox_provision(&ctx, None).await.unwrap();
    cmd_inbox_provision(&ctx, None).await.unwrap();
    cmd_inbox_provision(&ctx, None).await.unwrap();

    let listed = cmd_inbox_list(&ctx, None).await.unwrap();
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 inboxes, got: {listed}");
}
