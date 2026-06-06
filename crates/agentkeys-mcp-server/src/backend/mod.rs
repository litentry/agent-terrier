//! Backend abstraction — the broker / worker RPCs the MCP server adapts.
//!
//! The MCP server never owns persistent state itself. Every call routes through
//! the `Backend` trait to the real broker / worker HTTP chain. Real-data-only:
//! the in-memory fixture backend was removed — the production backend IS the
//! shared `agentkeys_backend_client::BackendClient` (the trait is impl'd directly
//! on it; #207 collapsed the former `HttpBackend` delegate wrapper).
//!
//! The trait survives purely as the **test seam**: `tests/common/mod.rs`'s
//! `MockBackend` is its second impl (a tiny in-memory broker + worker), which
//! keeps unit / integration tests deterministic and free of real network deps.
//!
//! The wire **shapes** + the real HTTP chain live in [`agentkeys_backend_client`]
//! (issue #203) — the single owner shared with the daemon and the harness fixture
//! gate. This module re-exports those types so the trait and the tools keep their
//! `crate::backend::*` import paths. There is no second copy of the cap/worker
//! JSON here anymore.

use async_trait::async_trait;

use agentkeys_backend_client::BackendClient;

// One owner for every broker/worker wire shape (issue #203). Re-exported so
// existing `crate::backend::CapMintOp` / `BackendError` / … paths keep working.
pub use agentkeys_backend_client::{
    AuditAppendInput, AuditAppendResult, BackendError, CapMintOp, CapMintRequest, CapToken,
    MemoryGetInput, MemoryGetResult, MemoryPutInput, MemoryPutResult, RevokeResult,
};

#[async_trait]
pub trait Backend: Send + Sync {
    async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        session_bearer: &str,
    ) -> Result<CapToken, BackendError>;

    async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError>;

    async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError>;

    async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError>;

    async fn audit_append(
        &self,
        input: AuditAppendInput,
    ) -> Result<AuditAppendResult, BackendError>;
}

// The production backend IS the shared `agentkeys_backend_client::BackendClient`
// (issue #203 — the ONE owner of the cap-mint → STS relay → worker chain). The
// former `HttpBackend` wrapper was pure delegation boilerplate; #207 collapsed it
// by implementing `Backend` directly on `BackendClient`. The trait survives ONLY
// as the test seam — `tests/common/mod.rs`'s `MockBackend` is its second impl.
//
// (Implementing a LOCAL trait for the foreign `BackendClient` is allowed by the
// orphan rule. Each method delegates to `BackendClient`'s inherent method of the
// same name — inherent methods take priority in method-call resolution, so
// `self.cap_mint(..)` is the inherent call, never this trait method: no recursion.)
#[async_trait]
impl Backend for BackendClient {
    async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        session_bearer: &str,
    ) -> Result<CapToken, BackendError> {
        self.cap_mint(op, req, session_bearer).await
    }

    async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError> {
        self.cap_revoke(cap_id).await
    }

    async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        self.memory_put(input).await
    }

    async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        self.memory_get(input).await
    }

    async fn audit_append(
        &self,
        input: AuditAppendInput,
    ) -> Result<AuditAppendResult, BackendError> {
        self.audit_append(input).await
    }
}
