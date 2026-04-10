use base64::Engine;
use serde_json::{json, Value};

use crate::backend::{BackendError, CredentialBackend};
use agentkeys_types::{
    AuditEvent, AuditFilter, AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes,
    EncryptedPairPayload, OpenedAuthRequest, PairCode, PairPayload, PublicKey, RegistrationToken,
    Scope, ServiceName, Session, SignedAuthDecision, WalletAddress,
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

    // Rendezvous and auth-request methods are stubs for Stage 4

    async fn register_rendezvous(
        &self,
        _daemon_pubkey: &PublicKey,
        _pair_code: &PairCode,
    ) -> Result<RegistrationToken, BackendError> {
        todo!("register_rendezvous: implemented in Stage 4")
    }

    async fn poll_rendezvous(
        &self,
        _token: &RegistrationToken,
    ) -> Result<Option<PairPayload>, BackendError> {
        todo!("poll_rendezvous: implemented in Stage 4")
    }

    async fn deliver_rendezvous(
        &self,
        _session: &Session,
        _pair_code: &PairCode,
        _payload: &EncryptedPairPayload,
    ) -> Result<(), BackendError> {
        todo!("deliver_rendezvous: implemented in Stage 4")
    }

    async fn open_auth_request(
        &self,
        _child_pubkey: &PublicKey,
        _request_type: AuthRequestType,
        _request_details: &CanonicalBytes,
    ) -> Result<OpenedAuthRequest, BackendError> {
        todo!("open_auth_request: implemented in Stage 4")
    }

    async fn fetch_auth_request(
        &self,
        _session: &Session,
        _pair_code: &PairCode,
    ) -> Result<AuthRequest, BackendError> {
        todo!("fetch_auth_request: implemented in Stage 4")
    }

    async fn approve_auth_request(
        &self,
        _session: &Session,
        _request_id: &AuthRequestId,
    ) -> Result<(), BackendError> {
        todo!("approve_auth_request: implemented in Stage 4")
    }

    async fn await_auth_decision(
        &self,
        _request_id: &AuthRequestId,
    ) -> Result<SignedAuthDecision, BackendError> {
        todo!("await_auth_decision: implemented in Stage 4")
    }
}
