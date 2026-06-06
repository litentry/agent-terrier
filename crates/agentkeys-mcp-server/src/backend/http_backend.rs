//! Production `Backend` implementation — a thin delegate over the shared
//! [`agentkeys_backend_client::BackendClient`] (issue #203). All the cap-mint
//! → STS relay → worker chain logic lives in that crate; this type only adapts
//! it to the MCP server's `Backend` trait. URLs come from `Config`; the bearer
//! used for broker cap-mint is forwarded from the vendor session header.

use async_trait::async_trait;

use agentkeys_backend_client::BackendClient;

use super::{
    AuditAppendInput, AuditAppendResult, Backend, BackendError, CapMintOp, CapMintRequest,
    CapToken, MemoryGetInput, MemoryGetResult, MemoryPutInput, MemoryPutResult, RevokeResult,
};

pub struct HttpBackend {
    inner: BackendClient,
}

impl HttpBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        broker_url: Option<String>,
        memory_url: Option<String>,
        audit_url: Option<String>,
        agent_session_bearer: Option<String>,
        memory_role_arn: Option<String>,
        vault_role_arn: Option<String>,
        region: String,
    ) -> Self {
        Self {
            inner: BackendClient::new(
                broker_url,
                memory_url,
                audit_url,
                agent_session_bearer,
                memory_role_arn,
                vault_role_arn,
                region,
            ),
        }
    }
}

#[async_trait]
impl Backend for HttpBackend {
    async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        session_bearer: &str,
    ) -> Result<CapToken, BackendError> {
        self.inner.cap_mint(op, req, session_bearer).await
    }

    async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError> {
        self.inner.cap_revoke(cap_id).await
    }

    async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        self.inner.memory_put(input).await
    }

    async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        self.inner.memory_get(input).await
    }

    async fn audit_append(
        &self,
        input: AuditAppendInput,
    ) -> Result<AuditAppendResult, BackendError> {
        self.inner.audit_append(input).await
    }
}
