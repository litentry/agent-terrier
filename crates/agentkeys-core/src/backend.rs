use agentkeys_types::{
    AuditEvent, AuditFilter, AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes,
    EncryptedPairPayload, OpenedAuthRequest, PairCode, PairPayload, PublicKey, RegistrationToken,
    Scope, ServiceName, Session, SignedAuthDecision, WalletAddress,
};
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("already consumed")]
    AlreadyConsumed,
    #[error("expired")]
    Expired,
    #[error("agent not found: {0}")]
    AgentNotFound(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait CredentialBackend: Send + Sync {
    async fn create_session(
        &self,
        auth_token: agentkeys_types::AuthToken,
    ) -> Result<(Session, WalletAddress), BackendError>;

    async fn create_child_session(
        &self,
        parent: &Session,
        scope: Scope,
    ) -> Result<(Session, WalletAddress), BackendError>;

    async fn store_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
        ciphertext: &[u8],
    ) -> Result<(), BackendError>;

    async fn read_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
    ) -> Result<Vec<u8>, BackendError>;

    async fn query_audit(
        &self,
        session: &Session,
        filter: AuditFilter,
    ) -> Result<Vec<AuditEvent>, BackendError>;

    async fn revoke_session(
        &self,
        session: &Session,
        target: &Session,
    ) -> Result<(), BackendError>;

    async fn teardown_agent(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<(), BackendError>;

    async fn shielding_key(&self) -> Result<PublicKey, BackendError>;

    async fn register_rendezvous(
        &self,
        daemon_pubkey: &PublicKey,
        pair_code: &PairCode,
    ) -> Result<RegistrationToken, BackendError>;

    async fn poll_rendezvous(
        &self,
        token: &RegistrationToken,
    ) -> Result<Option<PairPayload>, BackendError>;

    async fn deliver_rendezvous(
        &self,
        session: &Session,
        pair_code: &PairCode,
        payload: &EncryptedPairPayload,
    ) -> Result<(), BackendError>;

    async fn open_auth_request(
        &self,
        child_pubkey: &PublicKey,
        request_type: AuthRequestType,
        request_details: &CanonicalBytes,
    ) -> Result<OpenedAuthRequest, BackendError>;

    async fn fetch_auth_request(
        &self,
        session: &Session,
        pair_code: &PairCode,
    ) -> Result<AuthRequest, BackendError>;

    async fn approve_auth_request(
        &self,
        session: &Session,
        request_id: &AuthRequestId,
    ) -> Result<(), BackendError>;

    async fn await_auth_decision(
        &self,
        request_id: &AuthRequestId,
    ) -> Result<SignedAuthDecision, BackendError>;

    async fn recover_session(
        &self,
        identity: &agentkeys_types::AgentIdentity,
        method: &agentkeys_types::RecoveryMethod,
    ) -> Result<(Session, WalletAddress), BackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_types::AuthToken;

    struct DummyBackend;

    #[async_trait]
    impl CredentialBackend for DummyBackend {
        async fn create_session(
            &self,
            _auth_token: AuthToken,
        ) -> Result<(Session, WalletAddress), BackendError> {
            unimplemented!()
        }

        async fn create_child_session(
            &self,
            _parent: &Session,
            _scope: Scope,
        ) -> Result<(Session, WalletAddress), BackendError> {
            unimplemented!()
        }

        async fn store_credential(
            &self,
            _session: &Session,
            _agent_id: &WalletAddress,
            _service: &ServiceName,
            _ciphertext: &[u8],
        ) -> Result<(), BackendError> {
            unimplemented!()
        }

        async fn read_credential(
            &self,
            _session: &Session,
            _agent_id: &WalletAddress,
            _service: &ServiceName,
        ) -> Result<Vec<u8>, BackendError> {
            unimplemented!()
        }

        async fn query_audit(
            &self,
            _session: &Session,
            _filter: AuditFilter,
        ) -> Result<Vec<AuditEvent>, BackendError> {
            unimplemented!()
        }

        async fn revoke_session(
            &self,
            _session: &Session,
            _target: &Session,
        ) -> Result<(), BackendError> {
            unimplemented!()
        }

        async fn teardown_agent(
            &self,
            _session: &Session,
            _agent_id: &WalletAddress,
        ) -> Result<(), BackendError> {
            unimplemented!()
        }

        async fn shielding_key(&self) -> Result<PublicKey, BackendError> {
            unimplemented!()
        }

        async fn register_rendezvous(
            &self,
            _daemon_pubkey: &PublicKey,
            _pair_code: &PairCode,
        ) -> Result<RegistrationToken, BackendError> {
            unimplemented!()
        }

        async fn poll_rendezvous(
            &self,
            _token: &RegistrationToken,
        ) -> Result<Option<PairPayload>, BackendError> {
            unimplemented!()
        }

        async fn deliver_rendezvous(
            &self,
            _session: &Session,
            _pair_code: &PairCode,
            _payload: &EncryptedPairPayload,
        ) -> Result<(), BackendError> {
            unimplemented!()
        }

        async fn open_auth_request(
            &self,
            _child_pubkey: &PublicKey,
            _request_type: AuthRequestType,
            _request_details: &CanonicalBytes,
        ) -> Result<OpenedAuthRequest, BackendError> {
            unimplemented!()
        }

        async fn fetch_auth_request(
            &self,
            _session: &Session,
            _pair_code: &PairCode,
        ) -> Result<AuthRequest, BackendError> {
            unimplemented!()
        }

        async fn approve_auth_request(
            &self,
            _session: &Session,
            _request_id: &AuthRequestId,
        ) -> Result<(), BackendError> {
            unimplemented!()
        }

        async fn await_auth_decision(
            &self,
            _request_id: &AuthRequestId,
        ) -> Result<SignedAuthDecision, BackendError> {
            unimplemented!()
        }

        async fn recover_session(
            &self,
            _identity: &agentkeys_types::AgentIdentity,
            _method: &agentkeys_types::RecoveryMethod,
        ) -> Result<(Session, WalletAddress), BackendError> {
            unimplemented!()
        }
    }

    #[test]
    fn compiles() {
        let _backend: Box<dyn CredentialBackend> = Box::new(DummyBackend);
    }
}
