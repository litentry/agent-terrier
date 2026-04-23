use base64::Engine;
use serde_json::{json, Value};

use crate::backend::{BackendError, CredentialBackend};
use agentkeys_types::{
    AuditEvent, AuditFilter, AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes,
    EncryptedPairPayload, InboxAddress, OpenedAuthRequest, PairCode, PairPayload, PublicKey,
    RegistrationToken, Scope, ServiceName, Session, SignedAuthDecision, WalletAddress,
};

pub struct MockHttpClient {
    pub base_url: String,
    client: reqwest::Client,
}

impl MockHttpClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), client: reqwest::Client::new() }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn map_error(resp: reqwest::Response) -> BackendError {
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        let msg = body["message"].as_str().unwrap_or("unknown error").to_string();
        match status.as_u16() {
            401 => BackendError::AuthFailed(msg),
            403 => BackendError::PermissionDenied(msg),
            404 => BackendError::NotFound(msg),
            409 => BackendError::AlreadyConsumed,
            410 => BackendError::Expired,
            _ => BackendError::Transport(format!("HTTP {}: {}", status, msg)),
        }
    }

    fn session_from_token_and_wallet(token: String, wallet: WalletAddress) -> Session {
        Session {
            token,
            wallet,
            scope: None,
            created_at: 0,
            ttl_seconds: 86400,
        }
    }
}

#[async_trait::async_trait]
impl CredentialBackend for MockHttpClient {
    async fn create_session(
        &self,
        auth_token: agentkeys_types::AuthToken,
    ) -> Result<(Session, WalletAddress), BackendError> {
        let token_str = match &auth_token {
            agentkeys_types::AuthToken::Mock(s) => s.clone(),
            agentkeys_types::AuthToken::GoogleOAuth(s) => s.clone(),
            agentkeys_types::AuthToken::Passkey(_) => {
                return Err(BackendError::Internal("Passkey auth not supported by mock".into()));
            }
        };

        let resp = self
            .client
            .post(self.url("/session/create"))
            .json(&json!({ "auth_token": token_str }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let session_token = body["session"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing session".into()))?
            .to_string();
        let wallet_str = body["wallet"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing wallet".into()))?
            .to_string();

        let wallet = WalletAddress(wallet_str);
        let session = Self::session_from_token_and_wallet(session_token, wallet.clone());
        Ok((session, wallet))
    }

    async fn create_child_session(
        &self,
        parent: &Session,
        scope: Scope,
    ) -> Result<(Session, WalletAddress), BackendError> {
        let resp = self
            .client
            .post(self.url("/session/child"))
            .header("authorization", format!("Bearer {}", parent.token))
            .json(&json!({ "scope": scope }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let session_token = body["session"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing session".into()))?
            .to_string();
        let wallet_str = body["wallet"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing wallet".into()))?
            .to_string();

        let wallet = WalletAddress(wallet_str);
        let session = Session {
            token: session_token,
            wallet: wallet.clone(),
            scope: Some(scope),
            created_at: 0,
            ttl_seconds: 3600,
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

        let resp = self
            .client
            .post(self.url("/credential/store"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&json!({
                "agent_id": agent_id.0,
                "service": service.0,
                "ciphertext": ct_b64,
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        Ok(())
    }

    async fn read_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
    ) -> Result<Vec<u8>, BackendError> {
        let url = format!("/credential/read?agent_id={}&service={}", agent_id.0, service.0);

        let resp = self
            .client
            .get(self.url(&url))
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let ct_b64 = body["ciphertext"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing ciphertext".into()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .map_err(|e| BackendError::Internal(format!("base64 decode: {e}")))?;
        Ok(bytes)
    }

    async fn revoke_session(
        &self,
        session: &Session,
        target: &Session,
    ) -> Result<(), BackendError> {
        let resp = self
            .client
            .post(self.url("/session/revoke"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&json!({ "target_session": target.token }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        Ok(())
    }

    async fn revoke_by_wallet(
        &self,
        session: &Session,
        target_wallet: &WalletAddress,
    ) -> Result<(), BackendError> {
        let resp = self
            .client
            .post(self.url("/session/revoke"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&json!({ "target_wallet": target_wallet.0 }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        Ok(())
    }

    async fn teardown_agent(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<(), BackendError> {
        let resp = self
            .client
            .delete(self.url("/credential/teardown"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&json!({ "agent_id": agent_id.0 }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        Ok(())
    }

    async fn shielding_key(&self) -> Result<PublicKey, BackendError> {
        let resp = self
            .client
            .get(self.url("/shielding-key"))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let key_b64 = body["public_key"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing public_key".into()))?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| BackendError::Internal(format!("base64 decode: {e}")))?;
        Ok(PublicKey(key_bytes))
    }

    async fn query_audit(
        &self,
        session: &Session,
        filter: AuditFilter,
    ) -> Result<Vec<AuditEvent>, BackendError> {
        let mut params: Vec<String> = Vec::new();
        if let Some(owner) = &filter.owner {
            params.push(format!("owner={}", owner.0));
        }
        if let Some(agent) = &filter.agent {
            params.push(format!("agent={}", agent.0));
        }
        if let Some(service) = &filter.service {
            params.push(format!("service={}", service.0));
        }
        let path = if params.is_empty() {
            "/audit/query".to_string()
        } else {
            format!("/audit/query?{}", params.join("&"))
        };

        let resp = self
            .client
            .get(self.url(&path))
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let events = body["events"]
            .as_array()
            .ok_or_else(|| BackendError::Internal("missing events".into()))?
            .iter()
            .filter_map(|e| {
                Some(AuditEvent {
                    owner: WalletAddress(e["owner"].as_str()?.to_string()),
                    agent: WalletAddress(e["agent"].as_str()?.to_string()),
                    service: ServiceName(e["service"].as_str()?.to_string()),
                    action: e["action"].as_str()?.to_string(),
                    result: e["result"].as_str()?.to_string(),
                    timestamp: e["timestamp"].as_u64()?,
                })
            })
            .collect();
        Ok(events)
    }

    async fn register_rendezvous(
        &self,
        daemon_pubkey: &PublicKey,
        pair_code: &PairCode,
    ) -> Result<RegistrationToken, BackendError> {
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&daemon_pubkey.0);

        let resp = self
            .client
            .post(self.url("/rendezvous/register"))
            .json(&json!({
                "daemon_pubkey": pubkey_b64,
                "pair_code": pair_code.0,
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let token = body["registration_token"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing registration_token".into()))?
            .to_string();
        Ok(RegistrationToken(token))
    }

    async fn poll_rendezvous(
        &self,
        token: &RegistrationToken,
    ) -> Result<Option<PairPayload>, BackendError> {
        let url = format!("/rendezvous/poll?token={}", token.0);

        let resp = self
            .client
            .get(self.url(&url))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let status = body["status"].as_str().unwrap_or("timeout");

        if status == "delivered" {
            let payload_b64 = body["payload"]
                .as_str()
                .ok_or_else(|| BackendError::Internal("missing payload".into()))?;
            let payload_bytes = base64::engine::general_purpose::STANDARD
                .decode(payload_b64)
                .map_err(|e| BackendError::Internal(format!("base64 decode: {e}")))?;
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

        let resp = self
            .client
            .post(self.url("/rendezvous/deliver"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&json!({
                "pair_code": pair_code.0,
                "payload": payload_b64,
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
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
            };
            request_body["identity_type"] = json!(identity_type);
            request_body["identity_value"] = json!(identity_value);
        }

        // --parent binding from the daemon's --parent flag (PR #22). Orthogonal
        // to the Recover typed-identity fields above.
        if let Some(pw) = parent_wallet {
            request_body["parent_wallet"] = json!(pw.0);
        }

        let resp = self
            .client
            .post(self.url("/auth-request/open"))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let id_str = body["id"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing id".into()))?
            .to_string();
        let otp = body["otp"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing otp".into()))?
            .to_string();
        let pair_code_str = body["pair_code"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing pair_code".into()))?
            .to_string();
        let ttl_seconds = body["ttl_seconds"].as_u64().unwrap_or(60);
        let nonce_hash_b64 = body["nonce_hash"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing nonce_hash".into()))?;
        let nonce_hash = base64::engine::general_purpose::STANDARD
            .decode(nonce_hash_b64)
            .map_err(|e| BackendError::Internal(format!("base64 decode nonce_hash: {e}")))?;

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
        let url = format!("/auth-request/fetch?pair_code={}", pair_code.0);

        let resp = self
            .client
            .get(self.url(&url))
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let id_str = body["id"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing id".into()))?
            .to_string();
        let otp = body["otp"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing otp".into()))?
            .to_string();
        let created_at = body["created_at"].as_u64().unwrap_or(0);
        let child_pubkey_b64 = body["child_pubkey"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing child_pubkey".into()))?;
        let child_pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(child_pubkey_b64)
            .map_err(|e| BackendError::Internal(format!("base64 decode: {e}")))?;

        let request_type_str = body["request_type"].as_str().unwrap_or("Pair");
        let request_type = match request_type_str {
            "Recover" => AuthRequestType::Recover {
                agent_identity: agentkeys_types::AgentIdentity::Alias("unknown".into()),
                new_daemon_pubkey: child_pubkey_bytes.clone(),
            },
            "ScopeChange" => AuthRequestType::ScopeChange {
                agent_id: WalletAddress("unknown".into()),
                new_scope: Scope { services: vec![], read_only: false },
            },
            _ => AuthRequestType::Pair {
                requested_scope: Scope { services: vec![], read_only: false },
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
        let resp = self
            .client
            .post(self.url("/auth-request/approve"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&json!({ "request_id": request_id.0 }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        Ok(())
    }

    async fn await_auth_decision(
        &self,
        request_id: &AuthRequestId,
    ) -> Result<SignedAuthDecision, BackendError> {
        let url = format!("/auth-request/await?request_id={}", request_id.0);

        let resp = self
            .client
            .get(self.url(&url))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let status = body["status"].as_str().unwrap_or("timeout");

        if status == "timeout" {
            return Err(BackendError::Transport("await_auth_decision timed out".into()));
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
            let ttl = body["session"]["ttl_seconds"].as_u64().unwrap_or(3600);
            let created = body["session"]["created_at"].as_u64().unwrap_or(0);
            Session {
                token,
                wallet: WalletAddress(wallet),
                scope: None,
                created_at: created,
                ttl_seconds: ttl,
            }
        });

        let wallet = body["wallet"].as_str().map(|w| WalletAddress(w.to_string()));

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
        // Use reqwest's .query() builder for RFC 3986 percent-encoding so
        // wallet strings with reserved chars (`&`, `#`, `%`, `+`, spaces)
        // don't smuggle extra params or break the request.
        let resp = self
            .client
            .get(self.url("/credential/list"))
            .query(&[("agent_id", &agent_id.0)])
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let services = body["services"]
            .as_array()
            .ok_or_else(|| BackendError::Internal("missing services".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| ServiceName(s.to_string())))
            .collect();
        Ok(services)
    }

    async fn resolve_identity(
        &self,
        session: &Session,
        identifier: &str,
    ) -> Result<WalletAddress, BackendError> {
        let (identity_type, identity_value) = if identifier.contains('@') {
            ("email", identifier)
        } else {
            ("alias", identifier)
        };

        // reqwest's .query() builder percent-encodes both parameter names and
        // values per RFC 3986, so identities containing '+', '&', '=', '%', or
        // spaces (e.g. plus-addressed emails like "bot+prod@example.com") are
        // sent intact to the server.
        let resp = self
            .client
            .get(self.url("/identity/resolve"))
            .query(&[("identity_type", identity_type), ("identity_value", identity_value)])
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let wallet_str = body["wallet_address"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing wallet_address".into()))?
            .to_string();
        Ok(WalletAddress(wallet_str))
    }

    async fn get_scope(
        &self,
        session: &Session,
        target_wallet: &WalletAddress,
    ) -> Result<Option<Scope>, BackendError> {
        // .query() builder percent-encodes per RFC 3986 so wallet strings
        // with reserved chars don't break the request or smuggle params.
        let resp = self
            .client
            .get(self.url("/session/scope"))
            .query(&[("wallet", &target_wallet.0)])
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
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
        Ok(Some(Scope { services, read_only }))
    }

    async fn update_scope(
        &self,
        session: &Session,
        target_wallet: &WalletAddress,
        new_scope: &Scope,
    ) -> Result<(), BackendError> {
        let resp = self
            .client
            .put(self.url("/session/scope"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&serde_json::json!({
                "target_wallet": target_wallet.0,
                "scope": new_scope,
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }
        Ok(())
    }

    async fn provision_inbox(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<InboxAddress, BackendError> {
        let resp = self
            .client
            .post(self.url("/mock/inbox/provision"))
            .header("authorization", format!("Bearer {}", session.token))
            .json(&serde_json::json!({ "agent_id": agent_id.0 }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let address = body["address"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing address".into()))?
            .to_string();
        Ok(InboxAddress(address))
    }

    async fn list_inboxes(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<Vec<InboxAddress>, BackendError> {
        let resp = self
            .client
            .get(self.url("/mock/inbox/list"))
            .query(&[("agent_id", &agent_id.0)])
            .header("authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let addresses = body
            .as_array()
            .ok_or_else(|| BackendError::Internal("expected array".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| InboxAddress(s.to_string())))
            .collect();
        Ok(addresses)
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
        };
        let method_str = match method {
            agentkeys_types::RecoveryMethod::Passkey => "passkey",
            agentkeys_types::RecoveryMethod::Email => "email",
            agentkeys_types::RecoveryMethod::MasterApproval => "master_approval",
        };

        let resp = self
            .client
            .post(self.url("/session/recover"))
            .json(&json!({
                "identity_type": identity_type,
                "identity_value": identity_value,
                "method": method_str,
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Self::map_error(resp).await);
        }

        let body: Value = resp.json().await.map_err(|e| BackendError::Transport(e.to_string()))?;
        let session_token = body["session"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing session".into()))?
            .to_string();
        let wallet_str = body["wallet"]
            .as_str()
            .ok_or_else(|| BackendError::Internal("missing wallet".into()))?
            .to_string();

        let wallet = WalletAddress(wallet_str);
        let session = Self::session_from_token_and_wallet(session_token, wallet.clone());
        Ok((session, wallet))
    }
}
