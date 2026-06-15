use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;

use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_types::{
    AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes, EncryptedPairPayload,
    InboxAddress, OpenedAuthRequest, PairCode, PairPayload, PublicKey, RegistrationToken, Scope,
    SecretBytes, ServiceName, Session, SignedAuthDecision, WalletAddress,
};

use crate::{
    create_router, db,
    state::{AppState, SharedState},
};

/// Percent-encode the unreserved subset of RFC 3986 for query-string values.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub struct InProcessBackend {
    router: Router,
    state: SharedState,
}

impl InProcessBackend {
    pub fn new() -> Self {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let state = Arc::new(AppState::new(conn));
        let router = create_router(state.clone());
        Self { router, state }
    }

    /// Test helper: insert a row into `identity_links` without going through
    /// `/identity/link` (which would need an HTTP call + auth). Used by
    /// integration tests that need to simulate a pre-existing alias/email
    /// binding before triggering a Recover flow — required after PR #21
    /// tightened `resolve_identity_typed` to only return wallets that exist
    /// in `identity_links`.
    pub fn link_identity_for_tests(
        &self,
        identity_type: &str,
        identity_value: &str,
        wallet_address: &str,
    ) {
        let db = self.state.db.lock().unwrap();
        db.execute(
            "INSERT OR REPLACE INTO identity_links (wallet_address, identity_type, identity_value, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                wallet_address,
                identity_type,
                identity_value,
                crate::auth::now_secs()
            ],
        )
        .expect("insert identity_link");
    }

    async fn do_request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        headers: Vec<(&str, String)>,
    ) -> Result<(StatusCode, Value), BackendError> {
        let mut builder = Request::builder().uri(path).method(method);

        for (k, v) in &headers {
            builder = builder.header(*k, v.as_str());
        }

        let http_body: Body = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&b).unwrap())
        } else {
            Body::empty()
        };

        let response = self
            .router
            .clone()
            .oneshot(builder.body(http_body).unwrap())
            .await
            .map_err(|e| BackendError::Transport(format!("oneshot error: {e}")))?;

        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|e| BackendError::Transport(format!("body read error: {e}")))?;

        let json_body: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };

        if status.is_success() {
            Ok((status, json_body))
        } else {
            let msg = json_body
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            match status.as_u16() {
                401 => Err(BackendError::AuthFailed(msg)),
                403 => Err(BackendError::PermissionDenied(msg)),
                404 => Err(BackendError::NotFound(msg)),
                409 => Err(BackendError::AlreadyConsumed),
                410 => Err(BackendError::Expired),
                _ => Err(BackendError::Transport(format!("HTTP {}: {}", status, msg))),
            }
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, BackendError> {
        self.do_request("POST", path, Some(body), vec![])
            .await
            .map(|(_, j)| j)
    }

    async fn post_with_session(
        &self,
        path: &str,
        session: &Session,
        body: Value,
    ) -> Result<Value, BackendError> {
        let auth = format!("Bearer {}", session.token);
        self.do_request("POST", path, Some(body), vec![("authorization", auth)])
            .await
            .map(|(_, j)| j)
    }

    async fn get_with_session(&self, path: &str, session: &Session) -> Result<Value, BackendError> {
        let auth = format!("Bearer {}", session.token);
        self.do_request("GET", path, None, vec![("authorization", auth)])
            .await
            .map(|(_, j)| j)
    }

    async fn get_anonymous(&self, path: &str) -> Result<Value, BackendError> {
        self.do_request("GET", path, None, vec![])
            .await
            .map(|(_, j)| j)
    }

    async fn delete_with_session(
        &self,
        path: &str,
        session: &Session,
        body: Value,
    ) -> Result<Value, BackendError> {
        let auth = format!("Bearer {}", session.token);
        self.do_request("DELETE", path, Some(body), vec![("authorization", auth)])
            .await
            .map(|(_, j)| j)
    }
}

impl Default for InProcessBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialBackend for InProcessBackend {
    async fn create_session(
        &self,
        auth_token: agentkeys_types::AuthToken,
    ) -> Result<(Session, WalletAddress), BackendError> {
        let token_str = match &auth_token {
            agentkeys_types::AuthToken::Mock(s) => s.clone(),
            agentkeys_types::AuthToken::GoogleOAuth(s) => s.clone(),
            agentkeys_types::AuthToken::Passkey(_) => {
                return Err(BackendError::Transport(
                    "Passkey auth not supported by InProcessBackend".into(),
                ));
            }
        };

        let body = self
            .post("/session/create", json!({ "auth_token": token_str }))
            .await?;

        let session_token = body["session"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing session".into()))?
            .to_string();
        let wallet_str = body["wallet"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing wallet".into()))?
            .to_string();

        let wallet = WalletAddress(wallet_str);
        let session = Session {
            token: session_token,
            wallet: wallet.clone(),
            scope: None,
            created_at: 0,
            ttl_seconds: 2_592_000, // 30 days per docs/wiki/session-token.md policy
        };
        Ok((session, wallet))
    }

    async fn create_child_session(
        &self,
        parent: &Session,
        scope: Scope,
    ) -> Result<(Session, WalletAddress), BackendError> {
        let body = self
            .post_with_session("/session/child", parent, json!({ "scope": scope }))
            .await?;

        let session_token = body["session"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing session".into()))?
            .to_string();
        let wallet_str = body["wallet"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing wallet".into()))?
            .to_string();

        let wallet = WalletAddress(wallet_str);
        let session = Session {
            token: session_token,
            wallet: wallet.clone(),
            scope: Some(scope),
            created_at: 0,
            ttl_seconds: 2_592_000, // 30 days per docs/wiki/session-token.md policy
        };
        Ok((session, wallet))
    }

    async fn store_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
        ciphertext: &[u8],
    ) -> Result<(), BackendError> {
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        self.post_with_session(
            "/credential/store",
            session,
            json!({
                "agent_id": agent_id.0,
                "service": service.0,
                "ciphertext": ct_b64,
            }),
        )
        .await?;
        Ok(())
    }

    async fn read_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
    ) -> Result<SecretBytes, BackendError> {
        let path = format!(
            "/credential/read?agent_id={}&service={}",
            agent_id.0, service.0
        );
        let body = self.get_with_session(&path, session).await?;

        let ct_b64 = body["ciphertext"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing ciphertext".into()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .map_err(|e| BackendError::Transport(format!("base64 decode: {e}")))?;
        Ok(SecretBytes::new(bytes))
    }

    async fn revoke_session(
        &self,
        session: &Session,
        target: &Session,
    ) -> Result<(), BackendError> {
        self.post_with_session(
            "/session/revoke",
            session,
            json!({ "target_session": target.token }),
        )
        .await?;
        Ok(())
    }

    async fn revoke_by_wallet(
        &self,
        session: &Session,
        target_wallet: &WalletAddress,
    ) -> Result<(), BackendError> {
        self.post_with_session(
            "/session/revoke",
            session,
            json!({ "target_wallet": target_wallet.0 }),
        )
        .await?;
        Ok(())
    }

    async fn teardown_agent(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<(), BackendError> {
        self.delete_with_session(
            "/credential/teardown",
            session,
            json!({ "agent_id": agent_id.0 }),
        )
        .await?;
        Ok(())
    }

    async fn shielding_key(&self) -> Result<PublicKey, BackendError> {
        let body = self.get_anonymous("/shielding-key").await?;

        let key_b64 = body["public_key"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing public_key".into()))?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| BackendError::Transport(format!("base64 decode: {e}")))?;
        Ok(PublicKey(key_bytes))
    }

    async fn register_rendezvous(
        &self,
        daemon_pubkey: &PublicKey,
        pair_code: &PairCode,
    ) -> Result<RegistrationToken, BackendError> {
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&daemon_pubkey.0);
        let body = self
            .post(
                "/rendezvous/register",
                json!({
                    "daemon_pubkey": pubkey_b64,
                    "pair_code": pair_code.0,
                }),
            )
            .await?;

        let token = body["registration_token"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing registration_token".into()))?
            .to_string();
        Ok(RegistrationToken(token))
    }

    async fn poll_rendezvous(
        &self,
        token: &RegistrationToken,
    ) -> Result<Option<PairPayload>, BackendError> {
        let path = format!("/rendezvous/poll?token={}", token.0);
        let body = self.get_anonymous(&path).await?;

        let status = body["status"].as_str().unwrap_or("timeout");

        if status == "delivered" {
            let payload_b64 = body["payload"]
                .as_str()
                .ok_or_else(|| BackendError::Transport("missing payload".into()))?;
            let payload_bytes = base64::engine::general_purpose::STANDARD
                .decode(payload_b64)
                .map_err(|e| BackendError::Transport(format!("base64 decode: {e}")))?;
            Ok(Some(PairPayload(payload_bytes)))
        } else {
            Ok(None)
        }
    }

    async fn deliver_rendezvous(
        &self,
        session: &Session,
        pair_code: &PairCode,
        payload: &EncryptedPairPayload,
    ) -> Result<(), BackendError> {
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload.0);
        self.post_with_session(
            "/rendezvous/deliver",
            session,
            json!({
                "pair_code": pair_code.0,
                "payload": payload_b64,
            }),
        )
        .await?;
        Ok(())
    }

    async fn open_auth_request(
        &self,
        child_pubkey: &PublicKey,
        request_type: AuthRequestType,
        request_details: &CanonicalBytes,
        parent_wallet: Option<&WalletAddress>,
    ) -> Result<OpenedAuthRequest, BackendError> {
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&child_pubkey.0);
        let details_b64 = base64::engine::general_purpose::STANDARD.encode(&request_details.0);
        let request_type_str = match &request_type {
            AuthRequestType::Pair { .. } => "Pair",
            AuthRequestType::Recover { .. } => "Recover",
            AuthRequestType::ScopeChange { .. } => "ScopeChange",
            AuthRequestType::HighValueRelease { .. } => "HighValueRelease",
            AuthRequestType::KeyRotate { .. } => "KeyRotate",
        };

        let mut request_body = json!({
            "child_pubkey": pubkey_b64,
            "request_type": request_type_str,
            "request_details": details_b64,
        });

        if let AuthRequestType::Recover { agent_identity, .. } = &request_type {
            let (identity_type, identity_value) = match agent_identity {
                agentkeys_types::AgentIdentity::Alias(s) => ("alias", s.clone()),
                agentkeys_types::AgentIdentity::Email(s) => ("email", s.clone()),
                agentkeys_types::AgentIdentity::Ens(s) => ("ens", s.clone()),
                agentkeys_types::AgentIdentity::WalletAddress(w) => ("wallet", w.0.clone()),
                agentkeys_types::AgentIdentity::OAuth2 { provider, sub } => {
                    let it: &'static str = match provider.as_str() {
                        "google" => "oauth2_google",
                        "github" => "oauth2_github",
                        "apple" => "oauth2_apple",
                        _ => "oauth2_unknown",
                    };
                    (it, sub.clone())
                }
            };
            request_body["identity_type"] = json!(identity_type);
            request_body["identity_value"] = json!(identity_value);
        }

        // --parent binding from PR #22 daemon flag — orthogonal to Recover
        // typed-identity.
        if let Some(pw) = parent_wallet {
            request_body["parent_wallet"] = json!(pw.0);
        }

        let body = self.post("/auth-request/open", request_body).await?;

        let id_str = body["id"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing id".into()))?
            .to_string();
        let otp = body["otp"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing otp".into()))?
            .to_string();
        let pair_code_str = body["pair_code"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing pair_code".into()))?
            .to_string();
        let ttl_seconds = body["ttl_seconds"].as_u64().unwrap_or(60);
        let nonce_hash_b64 = body["nonce_hash"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing nonce_hash".into()))?;
        let nonce_hash = base64::engine::general_purpose::STANDARD
            .decode(nonce_hash_b64)
            .map_err(|e| BackendError::Transport(format!("base64 decode nonce_hash: {e}")))?;

        Ok(OpenedAuthRequest {
            id: AuthRequestId(id_str),
            otp,
            pair_code: PairCode(pair_code_str),
            ttl_seconds,
            nonce_hash,
        })
    }

    async fn fetch_auth_request(
        &self,
        session: &Session,
        pair_code: &PairCode,
    ) -> Result<AuthRequest, BackendError> {
        let path = format!("/auth-request/fetch?pair_code={}", pair_code.0);
        let body = self.get_with_session(&path, session).await?;

        let id_str = body["id"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing id".into()))?
            .to_string();
        let otp = body["otp"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing otp".into()))?
            .to_string();
        let created_at = body["created_at"].as_u64().unwrap_or(0);
        let child_pubkey_b64 = body["child_pubkey"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing child_pubkey".into()))?;
        let child_pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(child_pubkey_b64)
            .map_err(|e| BackendError::Transport(format!("base64 decode: {e}")))?;

        let request_type_str = body["request_type"].as_str().unwrap_or("Pair");
        let request_type = match request_type_str {
            "Recover" => AuthRequestType::Recover {
                agent_identity: agentkeys_types::AgentIdentity::Alias(
                    body["agent_identity"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string(),
                ),
                new_daemon_pubkey: child_pubkey_bytes.clone(),
            },
            "ScopeChange" => AuthRequestType::ScopeChange {
                agent_id: WalletAddress(body["agent_id"].as_str().unwrap_or("unknown").to_string()),
                new_scope: serde_json::from_value(body["new_scope"].clone()).unwrap_or(Scope {
                    services: vec![],
                    read_only: false,
                }),
            },
            "HighValueRelease" => AuthRequestType::HighValueRelease {
                agent_id: WalletAddress(body["agent_id"].as_str().unwrap_or("unknown").to_string()),
                service: ServiceName(body["service"].as_str().unwrap_or("unknown").to_string()),
                estimated_cost_cents: body["estimated_cost_cents"].as_u64().unwrap_or(0),
            },
            "KeyRotate" => AuthRequestType::KeyRotate {
                agent_id: WalletAddress(body["agent_id"].as_str().unwrap_or("unknown").to_string()),
                new_pubkey: body["new_pubkey"]
                    .as_str()
                    .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                    .unwrap_or_default(),
            },
            _ => AuthRequestType::Pair {
                requested_scope: serde_json::from_value(body["requested_scope"].clone()).unwrap_or(
                    Scope {
                        services: vec![],
                        read_only: false,
                    },
                ),
            },
        };

        Ok(AuthRequest {
            id: AuthRequestId(id_str),
            request_type,
            child_pubkey: PublicKey(child_pubkey_bytes),
            otp,
            created_at,
        })
    }

    async fn approve_auth_request(
        &self,
        session: &Session,
        request_id: &AuthRequestId,
    ) -> Result<(), BackendError> {
        self.post_with_session(
            "/auth-request/approve",
            session,
            json!({ "request_id": request_id.0 }),
        )
        .await?;
        Ok(())
    }

    async fn await_auth_decision(
        &self,
        request_id: &AuthRequestId,
    ) -> Result<SignedAuthDecision, BackendError> {
        let path = format!("/auth-request/await?request_id={}", request_id.0);
        let body = self.get_anonymous(&path).await?;

        let status = body["status"].as_str().unwrap_or("timeout");

        if status == "timeout" {
            return Err(BackendError::Transport(
                "await_auth_decision timed out".into(),
            ));
        }

        if status == "consumed" || status == "consumed_awaited" {
            return Err(BackendError::AlreadyConsumed);
        }

        let approved = body["approved"].as_bool().unwrap_or(false);
        let sig_b64 = body["signature"].as_str().unwrap_or("");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap_or_default();

        let session = body["session"].as_object().map(|_| {
            let token = body["session"]["token"].as_str().unwrap_or("").to_string();
            let wallet = body["session"]["wallet"].as_str().unwrap_or("").to_string();
            let ttl = body["session"]["ttl_seconds"].as_u64().unwrap_or(2_592_000);
            let created = body["session"]["created_at"].as_u64().unwrap_or(0);
            Session {
                token,
                wallet: WalletAddress(wallet),
                scope: None,
                created_at: created,
                ttl_seconds: ttl,
            }
        });

        let wallet = body["wallet"]
            .as_str()
            .map(|w| WalletAddress(w.to_string()));

        Ok(SignedAuthDecision {
            request_id: request_id.clone(),
            approved,
            signature,
            session,
            wallet,
        })
    }

    async fn list_credentials(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<Vec<ServiceName>, BackendError> {
        let path = format!("/credential/list?agent_id={}", agent_id.0);
        let body = self.get_with_session(&path, session).await?;

        let services = body["services"]
            .as_array()
            .ok_or_else(|| BackendError::Transport("missing services".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| ServiceName(s.to_string())))
            .collect();
        Ok(services)
    }

    async fn get_scope(
        &self,
        session: &Session,
        target_wallet: &WalletAddress,
    ) -> Result<Option<Scope>, BackendError> {
        // Percent-encode the wallet — matches the `.query()` pattern in
        // `MockHttpClient::get_scope`. Wallet strings are hex today so this is
        // safe in practice, but the consistency matters for the
        // `.github/REVIEW_GUIDELINES.md` URL-encoding invariant (pattern #3).
        let path = format!("/session/scope?wallet={}", pct_encode(&target_wallet.0));
        let result = self.get_with_session(&path, session).await;
        match result {
            Err(BackendError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
            Ok(body) => {
                if body["services"].is_null() {
                    return Ok(None);
                }
                let services: Vec<ServiceName> = body["services"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| ServiceName(s.to_string()))
                    .collect();
                let read_only = body["read_only"].as_bool().unwrap_or(false);
                Ok(Some(Scope {
                    services,
                    read_only,
                }))
            }
        }
    }

    async fn update_scope(
        &self,
        session: &Session,
        target_wallet: &WalletAddress,
        new_scope: &Scope,
    ) -> Result<(), BackendError> {
        let auth = format!("Bearer {}", session.token);
        self.do_request(
            "PUT",
            "/session/scope",
            Some(json!({
                "target_wallet": target_wallet.0,
                "scope": new_scope,
            })),
            vec![("authorization", auth)],
        )
        .await?;
        Ok(())
    }

    async fn recover_session(
        &self,
        identity: &agentkeys_types::AgentIdentity,
        method: &agentkeys_types::RecoveryMethod,
    ) -> Result<(Session, WalletAddress), BackendError> {
        let (identity_type, identity_value) = match identity {
            agentkeys_types::AgentIdentity::Alias(s) => ("alias", s.clone()),
            agentkeys_types::AgentIdentity::Email(s) => ("email", s.clone()),
            agentkeys_types::AgentIdentity::Ens(s) => ("ens", s.clone()),
            agentkeys_types::AgentIdentity::WalletAddress(w) => ("wallet", w.0.clone()),
            agentkeys_types::AgentIdentity::OAuth2 { provider, sub } => {
                let it: &'static str = match provider.as_str() {
                    "google" => "oauth2_google",
                    "github" => "oauth2_github",
                    "apple" => "oauth2_apple",
                    _ => "oauth2_unknown",
                };
                (it, sub.clone())
            }
        };
        let method_str = match method {
            agentkeys_types::RecoveryMethod::Passkey => "passkey",
            agentkeys_types::RecoveryMethod::Email => "email",
            agentkeys_types::RecoveryMethod::MasterApproval => "master_approval",
        };

        let body = self
            .post(
                "/session/recover",
                json!({
                    "identity_type": identity_type,
                    "identity_value": identity_value,
                    "method": method_str,
                }),
            )
            .await?;

        let session_token = body["session"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing session".into()))?
            .to_string();
        let wallet_str = body["wallet"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing wallet".into()))?
            .to_string();

        let wallet = WalletAddress(wallet_str);
        let session = Session {
            token: session_token,
            wallet: wallet.clone(),
            scope: None,
            created_at: 0,
            ttl_seconds: 2_592_000, // 30 days per docs/wiki/session-token.md policy
        };
        Ok((session, wallet))
    }

    async fn provision_inbox(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<InboxAddress, BackendError> {
        let body = self
            .post_with_session(
                "/mock/inbox/provision",
                session,
                json!({ "agent_id": agent_id.0 }),
            )
            .await?;
        let address = body["address"]
            .as_str()
            .ok_or_else(|| BackendError::Transport("missing address".into()))?
            .to_string();
        Ok(InboxAddress(address))
    }

    async fn list_inboxes(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<Vec<InboxAddress>, BackendError> {
        let path = format!("/mock/inbox/list?agent_id={}", pct_encode(&agent_id.0));
        let body = self.get_with_session(&path, session).await?;
        let addresses = body
            .as_array()
            .ok_or_else(|| BackendError::Transport("expected array".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| InboxAddress(s.to_string())))
            .collect();
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::backend::CredentialBackend;
    use agentkeys_types::AuthToken;

    async fn create_session_for_tests() -> (InProcessBackend, Session, WalletAddress) {
        let backend = InProcessBackend::new();
        let (session, wallet) = backend
            .create_session(AuthToken::Mock("test-token".to_string()))
            .await
            .unwrap();
        (backend, session, wallet)
    }

    #[tokio::test]
    async fn provision_inbox_returns_bot_address() {
        let (backend, session, wallet) = create_session_for_tests().await;
        let address = backend.provision_inbox(&session, &wallet).await.unwrap();
        assert!(
            address.0.starts_with("bot-") && address.0.contains('@'),
            "expected bot-*@domain address, got: {}",
            address.0
        );
    }

    #[tokio::test]
    async fn list_inboxes_returns_provisioned_addresses() {
        let (backend, session, wallet) = create_session_for_tests().await;

        let addr1 = backend.provision_inbox(&session, &wallet).await.unwrap();
        let addr2 = backend.provision_inbox(&session, &wallet).await.unwrap();

        let inboxes = backend.list_inboxes(&session, &wallet).await.unwrap();
        assert_eq!(inboxes.len(), 2, "expected 2 inboxes");
        assert!(inboxes.contains(&addr1));
        assert!(inboxes.contains(&addr2));
    }
}
