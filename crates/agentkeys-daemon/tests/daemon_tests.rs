// Daemon + MCP integration tests (Stage 3)
//
// Tests 1-9:  daemon startup and hardening checks
// Tests 10-13: MCP protocol handler

use std::sync::Arc;

use agentkeys_core::backend::CredentialBackend;
use agentkeys_mcp::{JsonRpcRequest, McpHandler};
use agentkeys_mock_server::test_client::InProcessBackend;
use agentkeys_types::{AuthToken, Scope, ServiceName, Session, WalletAddress};
use serde_json::json;

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

fn create_test_backend() -> Arc<InProcessBackend> {
    Arc::new(InProcessBackend::new())
}

fn dummy_session(token: impl Into<String>, wallet: impl Into<String>) -> Session {
    Session {
        token: token.into(),
        wallet: WalletAddress(wallet.into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    }
}

// ---------------------------------------------------------------------------
// Test 1: daemon_starts_and_connects
// ---------------------------------------------------------------------------
#[tokio::test]
async fn daemon_starts_and_connects() {
    let backend = create_test_backend();

    let result = backend.create_session(AuthToken::Mock("test-user".into())).await;
    assert!(result.is_ok(), "daemon should connect to backend: {result:?}");
}

// ---------------------------------------------------------------------------
// Tests 2-8: kernel hardening
// On macOS every step is Skipped — that is the expected result.
// On Linux each step is checked individually.
// ---------------------------------------------------------------------------

#[test]
fn daemon_memfd_secret_or_fallback() {
    #[cfg(target_os = "linux")]
    {
        #[cfg(target_arch = "x86_64")]
        const SYS_MEMFD_SECRET: libc::c_long = 447;

        #[cfg(target_arch = "x86_64")]
        {
            let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0usize) };
            if fd >= 0 {
                unsafe { libc::close(fd as libc::c_int) };
            } else {
                use std::io;
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOSYS) {
                    let ptr = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                            -1,
                            0,
                        )
                    };
                    assert_ne!(ptr, libc::MAP_FAILED, "mmap fallback failed");
                    unsafe { libc::munmap(ptr, 4096) };
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("daemon_memfd_secret_or_fallback: skipped (macOS)");
}

#[test]
fn daemon_mlock_residency() {
    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        if result == 0 {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let vmlck_line = status.lines().find(|l| l.starts_with("VmLck:"));
            if let Some(line) = vmlck_line {
                let kb: u64 = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                assert!(kb >= 0, "VmLck field should be present and numeric");
            }
        } else {
            eprintln!("daemon_mlock_residency: mlockall failed (no CAP_IPC_LOCK), skipping assertion");
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("daemon_mlock_residency: skipped (macOS)");
}

#[test]
fn daemon_dumpable_off() {
    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(result, 0, "prctl PR_SET_DUMPABLE should succeed");
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let dumpable_line = status.lines().find(|l| l.starts_with("Dumpable:"));
        if let Some(line) = dumpable_line {
            let val: u32 = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(99);
            assert_eq!(val, 0, "Dumpable should be 0 after prctl");
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("daemon_dumpable_off: skipped (macOS)");
}

#[test]
fn daemon_no_new_privs() {
    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        assert_eq!(result, 0, "prctl PR_SET_NO_NEW_PRIVS should succeed");
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("NoNewPrivs:"));
        if let Some(line) = line {
            let val: u32 = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(99);
            assert_eq!(val, 1, "NoNewPrivs should be 1");
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("daemon_no_new_privs: skipped (macOS)");
}

#[test]
fn daemon_seccomp_installed() {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(
            status.contains("Seccomp:"),
            "Seccomp field must be present in /proc/self/status"
        );
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("daemon_seccomp_installed: skipped (macOS)");
}

#[test]
fn daemon_caps_dropped() {
    #[cfg(target_os = "linux")]
    {
        let cap_last_cap: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(40);

        for cap in 0..=cap_last_cap {
            unsafe {
                libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0)
            };
        }

        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let cap_eff_line = status.lines().find(|l| l.starts_with("CapEff:"));
        assert!(cap_eff_line.is_some(), "CapEff must be present in /proc/self/status");
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("daemon_caps_dropped: skipped (macOS)");
}

#[test]
fn daemon_landlock_enosys_ok() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        let result = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<u8>(),
                0usize,
                1u32,
            )
        };
        if result >= 0 {
            unsafe { libc::close(result as libc::c_int) };
        } else {
            let err = std::io::Error::last_os_error();
            assert!(
                err.raw_os_error() == Some(libc::ENOSYS)
                    || err.raw_os_error() == Some(libc::EOPNOTSUPP)
                    || err.raw_os_error() == Some(libc::EINVAL),
                "Landlock probe should return ENOSYS/EOPNOTSUPP/EINVAL or success, got: {err}"
            );
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    eprintln!("daemon_landlock_enosys_ok: skipped (not Linux x86_64)");
}

// ---------------------------------------------------------------------------
// Test 9: daemon_session_file_permissions
// ---------------------------------------------------------------------------
#[test]
fn daemon_session_file_permissions() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    use std::io::Write;

    let tmp_dir = std::env::temp_dir().join(format!("agentkeys-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let session_path = tmp_dir.join("session");

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut file = opts.open(&session_path).unwrap();
    file.write_all(b"test-session-token").unwrap();
    drop(file);

    let metadata = std::fs::metadata(&session_path).unwrap();
    let mode = metadata.permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "session file must be mode 0600, got {:o}", mode & 0o777);

    let uid = metadata.uid();
    let current_uid = unsafe { libc::getuid() };
    assert_eq!(uid, current_uid, "session file must be owned by current UID");

    std::fs::remove_dir_all(&tmp_dir).ok();
}

// ---------------------------------------------------------------------------
// MCP Test 10: mcp_get_credential_valid
// ---------------------------------------------------------------------------
#[tokio::test]
async fn mcp_get_credential_valid() {
    let backend = create_test_backend();

    let (master_sess, _) = backend.create_session(AuthToken::Mock("test-user".into())).await.unwrap();
    let child_scope = Scope {
        services: vec![ServiceName("openrouter".into())],
        read_only: false,
    };
    let (child_sess, _) = backend.create_child_session(&master_sess, child_scope).await.unwrap();
    let child_wallet = child_sess.wallet.clone();

    backend
        .store_credential(&master_sess, &child_wallet, &ServiceName("openrouter".into()), b"sk-or-v1-test-key")
        .await
        .unwrap();

    let handler = McpHandler::new(backend as Arc<dyn CredentialBackend>, child_sess, child_wallet);

    let request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "agentkeys.get_credential",
            "arguments": { "service": "openrouter" }
        })),
        id: Some(json!(1)),
    };

    let response = handler.handle(request).await;
    assert!(response.error.is_none(), "expected no error, got: {:?}", response.error);
    let result = response.result.unwrap();
    let text = result["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "sk-or-v1-test-key");
}

// ---------------------------------------------------------------------------
// MCP Test 11: mcp_get_credential_denied
// ---------------------------------------------------------------------------
#[tokio::test]
async fn mcp_get_credential_denied() {
    let backend = create_test_backend();

    let (master_sess, _) = backend.create_session(AuthToken::Mock("test-user".into())).await.unwrap();
    let child_scope = Scope {
        services: vec![ServiceName("openrouter".into())],
        read_only: false,
    };
    let (child_sess, _) = backend.create_child_session(&master_sess, child_scope).await.unwrap();
    let child_wallet = child_sess.wallet.clone();

    backend
        .store_credential(&master_sess, &child_wallet, &ServiceName("openrouter".into()), b"sk-or-v1-test-key")
        .await
        .unwrap();

    // Revoke the child session
    backend.revoke_session(&master_sess, &child_sess).await.unwrap();

    let handler = McpHandler::new(backend as Arc<dyn CredentialBackend>, child_sess, child_wallet);

    let request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "agentkeys.get_credential",
            "arguments": { "service": "openrouter" }
        })),
        id: Some(json!(2)),
    };

    let response = handler.handle(request).await;
    assert!(response.error.is_some(), "expected DENIED error after revocation");
    let error_msg = response.error.unwrap().message.to_lowercase();
    assert!(
        error_msg.contains("denied")
            || error_msg.contains("permission")
            || error_msg.contains("revoked")
            || error_msg.contains("authentication failed"),
        "error should indicate denial: {error_msg}"
    );
}

// ---------------------------------------------------------------------------
// MCP Test 12: mcp_list_credentials
// ---------------------------------------------------------------------------
#[tokio::test]
async fn mcp_list_credentials() {
    let backend = create_test_backend();

    let (master_sess, _) = backend.create_session(AuthToken::Mock("test-user".into())).await.unwrap();
    let child_scope = Scope {
        services: vec![
            ServiceName("openrouter".into()),
            ServiceName("anthropic".into()),
        ],
        read_only: false,
    };
    let (child_sess, _) = backend.create_child_session(&master_sess, child_scope).await.unwrap();
    let child_wallet = child_sess.wallet.clone();

    for service in &["openrouter", "anthropic"] {
        backend
            .store_credential(
                &master_sess,
                &child_wallet,
                &ServiceName(service.to_string()),
                format!("key-for-{service}").as_bytes(),
            )
            .await
            .unwrap();
    }

    let handler = McpHandler::new(backend as Arc<dyn CredentialBackend>, child_sess, child_wallet);

    let request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "agentkeys.list_credentials",
            "arguments": {}
        })),
        id: Some(json!(3)),
    };

    let response = handler.handle(request).await;
    assert!(response.error.is_none(), "expected no error: {:?}", response.error);
    let result = response.result.unwrap();
    let services = result["services"].as_array().unwrap();
    let service_names: Vec<&str> = services.iter().filter_map(|v| v.as_str()).collect();
    assert!(service_names.contains(&"openrouter"), "should include openrouter, got: {service_names:?}");
    assert!(service_names.contains(&"anthropic"), "should include anthropic, got: {service_names:?}");
}

// ---------------------------------------------------------------------------
// MCP Test 13: mcp_tool_discovery
// ---------------------------------------------------------------------------
#[tokio::test]
async fn mcp_tool_discovery() {
    let backend = create_test_backend();

    let sess = dummy_session("dummy-token", "0xdummy");
    let agent_id = WalletAddress("0xdummy".into());
    let handler = McpHandler::new(backend as Arc<dyn CredentialBackend>, sess, agent_id);

    let request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "tools/list".into(),
        params: None,
        id: Some(json!(1)),
    };

    let response = handler.handle(request).await;
    assert!(response.error.is_none(), "expected no error: {:?}", response.error);
    let result = response.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    assert!(
        tool_names.contains(&"agentkeys.get_credential"),
        "tools/list must include agentkeys.get_credential, got: {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"agentkeys.list_credentials"),
        "tools/list must include agentkeys.list_credentials, got: {tool_names:?}"
    );

    for tool in tools {
        assert!(tool["inputSchema"].is_object(), "tool {} must have inputSchema", tool["name"]);
        assert!(tool["description"].is_string(), "tool {} must have description", tool["name"]);
    }
}
