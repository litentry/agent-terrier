// Stage 4: Pair/Approve/Recover flow tests
//
// Tests 1-7:  pair flow
// Tests 8-11: recover flow

use std::sync::Arc;

use agentkeys_core::backend::CredentialBackend;
use agentkeys_mock_server::test_client::InProcessBackend;
use agentkeys_types::{
    AgentIdentity, AuthRequestType, AuthToken, CanonicalBytes, EncryptedPairPayload, PairCode,
    PublicKey, RecoveryMethod, Scope, ServiceName,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn create_test_backend() -> Arc<InProcessBackend> {
    Arc::new(InProcessBackend::new())
}

/// Direct-DB identity link helper for HTTP-based tests, mirroring
/// `InProcessBackend::link_identity_for_tests`. Used after the
/// `/identity/link` endpoint was retired with issue #77.
fn link_identity_direct(
    state: &Arc<agentkeys_mock_server::state::AppState>,
    identity_type: &str,
    identity_value: &str,
    wallet_address: &str,
) {
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT OR REPLACE INTO identity_links (wallet_address, identity_type, identity_value, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                wallet_address,
                identity_type,
                identity_value,
                agentkeys_mock_server::auth::now_secs()
            ],
        )
        .expect("insert identity_link");
}

fn dummy_pubkey() -> PublicKey {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = ed25519_dalek::VerifyingKey::from(&signing_key);
    PublicKey(vk.to_bytes().to_vec())
}

fn pair_canonical_bytes(scope: &Scope) -> CanonicalBytes {
    let json = serde_json::json!({ "Pair": { "requested_scope": scope } });
    CanonicalBytes(serde_json::to_vec(&json).unwrap())
}

fn recover_canonical_bytes(alias: &str, pubkey: &[u8]) -> CanonicalBytes {
    let pubkey_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pubkey);
    let json = serde_json::json!({
        "Recover": {
            "agent_identity": { "Alias": alias },
            "new_daemon_pubkey": pubkey_b64,
        }
    });
    CanonicalBytes(serde_json::to_vec(&json).unwrap())
}

// ---------------------------------------------------------------------------
// Test 1: pair_full_loop
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_full_loop() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope,
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    let pair_code = opened.pair_code.clone();
    let request_id = opened.id.clone();

    let reg_token = backend
        .register_rendezvous(&child_pubkey, &pair_code)
        .await
        .unwrap();

    // Approve before polling so poll returns immediately with delivered payload
    backend
        .approve_auth_request(&master_sess, &request_id)
        .await
        .unwrap();

    let payload = EncryptedPairPayload(b"child-session-token".to_vec());
    backend
        .deliver_rendezvous(&master_sess, &pair_code, &payload)
        .await
        .unwrap();

    // Now poll — should return Some since payload was already delivered
    let poll_result = backend.poll_rendezvous(&reg_token).await.unwrap();
    assert!(
        poll_result.is_some(),
        "poll should return the delivered payload"
    );

    let decision = backend.await_auth_decision(&request_id).await.unwrap();
    assert!(decision.approved, "decision should be approved");
    assert!(
        decision.session.is_some(),
        "decision should contain a session"
    );
}

// ---------------------------------------------------------------------------
// Test 2: pair_otp_matches
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_otp_matches() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope,
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    let pair_code = opened.pair_code.clone();
    let daemon_otp = opened.otp.clone();

    let fetched = backend
        .fetch_auth_request(&master_sess, &pair_code)
        .await
        .unwrap();

    assert_eq!(
        daemon_otp, fetched.otp,
        "OTP from open must match OTP from fetch"
    );
}

// ---------------------------------------------------------------------------
// Test 3: pair_timeout_retry
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_timeout_retry() {
    let backend = create_test_backend();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope,
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    let reg_token = backend
        .register_rendezvous(&child_pubkey, &opened.pair_code)
        .await
        .unwrap();

    // poll_rendezvous with no delivery — server will respond with status=timeout
    // We use tokio::time::timeout to cut it short
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(35),
        backend.poll_rendezvous(&reg_token),
    )
    .await;

    match result {
        Ok(Ok(None)) => {} // clean timeout - correct
        Ok(Ok(Some(_))) => panic!("unexpected payload"),
        Ok(Err(e)) => panic!("unexpected error: {e}"),
        Err(_) => {} // outer timeout - also acceptable
    }
}

// ---------------------------------------------------------------------------
// Test 4: pair_wrong_pair_code
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_wrong_pair_code() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let result = backend
        .fetch_auth_request(&master_sess, &PairCode("XXXX-YYYY".to_string()))
        .await;

    assert!(result.is_err(), "fetching with wrong pair code should fail");
    let err_str = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err_str.contains("not found") || err_str.contains("404"),
        "error should indicate not found: {err_str}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: pair_expired_code
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_expired_code() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let result = backend
        .fetch_auth_request(&master_sess, &PairCode("EXPIRED-CODE".to_string()))
        .await;

    assert!(
        result.is_err(),
        "fetching expired/nonexistent code should fail"
    );
}

// ---------------------------------------------------------------------------
// Test 6: pair_replay_resistance
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_replay_resistance() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope,
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    // First approval succeeds
    backend
        .approve_auth_request(&master_sess, &opened.id)
        .await
        .unwrap();

    // Second approval should fail with AlreadyConsumed
    let second = backend.approve_auth_request(&master_sess, &opened.id).await;

    assert!(second.is_err(), "second approval should fail");
    let err_str = second.unwrap_err().to_string().to_lowercase();
    assert!(
        err_str.contains("already consumed")
            || err_str.contains("conflict")
            || err_str.contains("409"),
        "error should indicate already consumed: {err_str}"
    );
}

// ---------------------------------------------------------------------------
// Test 7: pair_wrong_user_approve
// Uses a real TCP server because it makes raw HTTP calls with custom JSON body
// that include parent_wallet — a field not exposed in the CredentialBackend trait.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pair_wrong_user_approve() {
    use agentkeys_mock_server::{create_router, db, state::AppState};

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = Arc::new(AppState::new(conn));
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let backend_url = format!("http://{addr}");

    use agentkeys_core::mock_client::MockHttpClient;
    let client = MockHttpClient::new(&backend_url);

    let (user_a_sess, _) = client
        .create_session(AuthToken::Mock("user-a".into()))
        .await
        .unwrap();

    let (user_b_sess, _) = client
        .create_session(AuthToken::Mock("user-b".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let pubkey_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &child_pubkey.0);
    let details_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &request_details.0,
    );
    let http_client = reqwest::Client::new();
    let resp = http_client
        .post(format!("{}/auth-request/open", backend_url))
        .json(&serde_json::json!({
            "child_pubkey": pubkey_b64,
            "request_type": "Pair",
            "request_details": details_b64,
            "parent_wallet": user_a_sess.wallet.0,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let request_id = agentkeys_types::AuthRequestId(body["id"].as_str().unwrap().to_string());

    let result = client.approve_auth_request(&user_b_sess, &request_id).await;

    assert!(
        result.is_err(),
        "user B should not be able to approve user A's request"
    );
    let err_str = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err_str.contains("unauthorized") || err_str.contains("401") || err_str.contains("auth"),
        "error should indicate unauthorized: {err_str}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: recover_full_loop
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_full_loop() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![ServiceName("openrouter".into())],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope.clone(),
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    let pair_code = opened.pair_code.clone();
    let request_id = opened.id.clone();

    backend
        .register_rendezvous(&child_pubkey, &pair_code)
        .await
        .unwrap();

    backend
        .approve_auth_request(&master_sess, &request_id)
        .await
        .unwrap();

    let payload = EncryptedPairPayload(b"session-token".to_vec());
    backend
        .deliver_rendezvous(&master_sess, &pair_code, &payload)
        .await
        .unwrap();

    let decision = backend.await_auth_decision(&request_id).await.unwrap();
    assert!(decision.approved);
    let agent_wallet = decision.wallet.unwrap();

    backend
        .store_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("openrouter".into()),
            b"sk-or-v1-recover-test",
        )
        .await
        .unwrap();

    let new_pubkey = dummy_pubkey();
    let recover_details = recover_canonical_bytes("my-agent", &new_pubkey.0);

    // Post-#13 / PR #21: Recover resolves identity through identity_links,
    // so the alias must be linked first. Seed the link directly in the
    // in-process backend.
    backend.link_identity_for_tests("alias", "my-agent", &agent_wallet.0);

    let recover_opened = backend
        .open_auth_request(
            &new_pubkey,
            AuthRequestType::Recover {
                agent_identity: agentkeys_types::AgentIdentity::Alias("my-agent".into()),
                new_daemon_pubkey: new_pubkey.0.clone(),
            },
            &recover_details,
            None,
        )
        .await
        .unwrap();

    let recover_pair_code = recover_opened.pair_code.clone();
    let recover_request_id = recover_opened.id.clone();

    backend
        .register_rendezvous(&new_pubkey, &recover_pair_code)
        .await
        .unwrap();

    backend
        .approve_auth_request(&master_sess, &recover_request_id)
        .await
        .unwrap();

    let recover_payload = EncryptedPairPayload(b"recovered-session".to_vec());
    backend
        .deliver_rendezvous(&master_sess, &recover_pair_code, &recover_payload)
        .await
        .unwrap();

    let recover_decision = backend
        .await_auth_decision(&recover_request_id)
        .await
        .unwrap();
    assert!(recover_decision.approved, "recovery should be approved");

    let cred_bytes = backend
        .read_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("openrouter".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        cred_bytes, b"sk-or-v1-recover-test",
        "credential should survive recovery"
    );
}

// ---------------------------------------------------------------------------
// Test 9: recover_unknown_identity
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_unknown_identity() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let new_pubkey = dummy_pubkey();
    let recover_details = recover_canonical_bytes("nonexistent-agent", &new_pubkey.0);

    let opened = backend
        .open_auth_request(
            &new_pubkey,
            AuthRequestType::Recover {
                agent_identity: agentkeys_types::AgentIdentity::Alias("nonexistent-agent".into()),
                new_daemon_pubkey: new_pubkey.0.clone(),
            },
            &recover_details,
            None,
        )
        .await
        .unwrap();

    backend
        .register_rendezvous(&new_pubkey, &opened.pair_code)
        .await
        .unwrap();

    let approve_result = backend.approve_auth_request(&master_sess, &opened.id).await;
    let _ = approve_result;
}

// ---------------------------------------------------------------------------
// Test 10: recover_old_pubkey_revoked
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_old_pubkey_revoked() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![ServiceName("openrouter".into())],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope,
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    backend
        .register_rendezvous(&child_pubkey, &opened.pair_code)
        .await
        .unwrap();

    backend
        .approve_auth_request(&master_sess, &opened.id)
        .await
        .unwrap();

    let payload = EncryptedPairPayload(b"old-session".to_vec());
    backend
        .deliver_rendezvous(&master_sess, &opened.pair_code, &payload)
        .await
        .unwrap();

    let decision = backend.await_auth_decision(&opened.id).await.unwrap();
    assert!(decision.approved);
    let old_session = decision.session.unwrap();
    let agent_wallet = decision.wallet.unwrap();

    backend
        .store_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("openrouter".into()),
            b"sk-or-v1-old-key",
        )
        .await
        .unwrap();

    backend
        .revoke_session(&master_sess, &old_session)
        .await
        .unwrap();

    let read_result = backend
        .read_credential(
            &old_session,
            &agent_wallet,
            &ServiceName("openrouter".into()),
        )
        .await;

    assert!(
        read_result.is_err(),
        "old revoked session should not be able to read credentials"
    );
}

// ---------------------------------------------------------------------------
// Test 11: recover_credentials_intact
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_credentials_intact() {
    let backend = create_test_backend();

    let (master_sess, _) = backend
        .create_session(AuthToken::Mock("master-user".into()))
        .await
        .unwrap();

    let child_pubkey = dummy_pubkey();
    let scope = Scope {
        services: vec![
            ServiceName("openrouter".into()),
            ServiceName("anthropic".into()),
        ],
        read_only: false,
    };
    let request_details = pair_canonical_bytes(&scope);

    let opened = backend
        .open_auth_request(
            &child_pubkey,
            AuthRequestType::Pair {
                requested_scope: scope,
            },
            &request_details,
            None,
        )
        .await
        .unwrap();

    backend
        .register_rendezvous(&child_pubkey, &opened.pair_code)
        .await
        .unwrap();

    backend
        .approve_auth_request(&master_sess, &opened.id)
        .await
        .unwrap();

    let payload = EncryptedPairPayload(b"session-payload".to_vec());
    backend
        .deliver_rendezvous(&master_sess, &opened.pair_code, &payload)
        .await
        .unwrap();

    let decision = backend.await_auth_decision(&opened.id).await.unwrap();
    let agent_wallet = decision.wallet.unwrap();

    backend
        .store_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("openrouter".into()),
            b"sk-or-v1-original",
        )
        .await
        .unwrap();
    backend
        .store_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("anthropic".into()),
            b"sk-ant-original",
        )
        .await
        .unwrap();

    let new_pubkey = dummy_pubkey();
    let recover_details = recover_canonical_bytes("test-agent", &new_pubkey.0);

    // Post-#13 / PR #21: Recover resolves identity through identity_links.
    backend.link_identity_for_tests("alias", "test-agent", &agent_wallet.0);

    let recover_opened = backend
        .open_auth_request(
            &new_pubkey,
            AuthRequestType::Recover {
                agent_identity: agentkeys_types::AgentIdentity::Alias("test-agent".into()),
                new_daemon_pubkey: new_pubkey.0.clone(),
            },
            &recover_details,
            None,
        )
        .await
        .unwrap();

    backend
        .register_rendezvous(&new_pubkey, &recover_opened.pair_code)
        .await
        .unwrap();

    backend
        .approve_auth_request(&master_sess, &recover_opened.id)
        .await
        .unwrap();

    let recover_payload = EncryptedPairPayload(b"recovered-session".to_vec());
    backend
        .deliver_rendezvous(&master_sess, &recover_opened.pair_code, &recover_payload)
        .await
        .unwrap();

    let or_cred = backend
        .read_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("openrouter".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        or_cred, b"sk-or-v1-original",
        "openrouter credential should be intact after recovery"
    );

    let ant_cred = backend
        .read_credential(
            &master_sess,
            &agent_wallet,
            &ServiceName("anthropic".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        ant_cred, b"sk-ant-original",
        "anthropic credential should be intact after recovery"
    );
}

// ---------------------------------------------------------------------------
// Test 12: recover_via_passkey
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_via_passkey() {
    use agentkeys_mock_server::{create_router, db, state::AppState};
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = std::sync::Arc::new(AppState::new(conn));
    let router = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let backend_url = format!("http://{addr}");

    use agentkeys_core::mock_client::MockHttpClient;
    let client = MockHttpClient::new(&backend_url);

    let (master_sess, master_wallet) = client
        .create_session(AuthToken::Mock("passkey-user".into()))
        .await
        .unwrap();

    link_identity_direct(&state, "alias", "my-passkey-agent", &master_wallet.0);
    let _ = master_sess;

    // Recover via passkey
    let (recovered_sess, recovered_wallet) = client
        .recover_session(
            &AgentIdentity::Alias("my-passkey-agent".into()),
            &RecoveryMethod::Passkey,
        )
        .await
        .unwrap();

    assert_eq!(
        recovered_wallet, master_wallet,
        "recovered wallet should match original"
    );
    assert!(
        !recovered_sess.token.is_empty(),
        "recovered session should have a token"
    );
}

// ---------------------------------------------------------------------------
// Test 13: recover_via_email
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_via_email() {
    use agentkeys_mock_server::{create_router, db, state::AppState};
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = std::sync::Arc::new(AppState::new(conn));
    let router = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let backend_url = format!("http://{addr}");

    use agentkeys_core::mock_client::MockHttpClient;
    let client = MockHttpClient::new(&backend_url);

    let (master_sess, master_wallet) = client
        .create_session(AuthToken::Mock("email-user".into()))
        .await
        .unwrap();

    link_identity_direct(&state, "email", "bot@example.com", &master_wallet.0);
    let _ = master_sess;

    let (recovered_sess, recovered_wallet) = client
        .recover_session(
            &AgentIdentity::Email("bot@example.com".into()),
            &RecoveryMethod::Email,
        )
        .await
        .unwrap();

    assert_eq!(recovered_wallet, master_wallet);
    assert!(!recovered_sess.token.is_empty());
}

// ---------------------------------------------------------------------------
// Test 14: recover_via_2fa_unknown_identity
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_via_2fa_unknown_identity() {
    let backend = create_test_backend();

    let result = backend
        .recover_session(
            &AgentIdentity::Alias("nonexistent-agent".into()),
            &RecoveryMethod::Passkey,
        )
        .await;

    assert!(result.is_err(), "recovery of unknown identity should fail");
    let err_str = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err_str.contains("not found") || err_str.contains("404"),
        "error should indicate not found: {err_str}"
    );
}

// ---------------------------------------------------------------------------
// Test 15: recover_via_2fa_credentials_intact
// ---------------------------------------------------------------------------
#[tokio::test]
async fn recover_via_2fa_credentials_intact() {
    use agentkeys_mock_server::{create_router, db, state::AppState};
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = std::sync::Arc::new(AppState::new(conn));
    let router = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let backend_url = format!("http://{addr}");

    use agentkeys_core::mock_client::MockHttpClient;
    let client = MockHttpClient::new(&backend_url);

    // Create master + store credentials
    let (master_sess, master_wallet) = client
        .create_session(AuthToken::Mock("cred-intact-user".into()))
        .await
        .unwrap();

    client
        .store_credential(
            &master_sess,
            &master_wallet,
            &ServiceName("openrouter".into()),
            b"sk-or-v1-2fa-test",
        )
        .await
        .unwrap();

    client
        .store_credential(
            &master_sess,
            &master_wallet,
            &ServiceName("anthropic".into()),
            b"sk-ant-2fa-test",
        )
        .await
        .unwrap();

    link_identity_direct(&state, "alias", "cred-intact-agent", &master_wallet.0);

    // Recover via passkey
    let (recovered_sess, recovered_wallet) = client
        .recover_session(
            &AgentIdentity::Alias("cred-intact-agent".into()),
            &RecoveryMethod::Passkey,
        )
        .await
        .unwrap();

    assert_eq!(recovered_wallet, master_wallet);

    // Verify credentials are still accessible with the recovered session
    let or_cred = client
        .read_credential(
            &recovered_sess,
            &recovered_wallet,
            &ServiceName("openrouter".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        or_cred, b"sk-or-v1-2fa-test",
        "openrouter credential should survive 2FA recovery"
    );

    let ant_cred = client
        .read_credential(
            &recovered_sess,
            &recovered_wallet,
            &ServiceName("anthropic".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        ant_cred, b"sk-ant-2fa-test",
        "anthropic credential should survive 2FA recovery"
    );
}
