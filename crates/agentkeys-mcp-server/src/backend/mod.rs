//! Backend abstraction — the broker / worker RPCs the MCP server adapts.
//!
//! The MCP server never owns persistent state itself. Every call routes
//! through this trait to either:
//!   - the real broker / worker HTTP endpoints (`HttpBackend`), or
//!   - a `MockBackend` controlled by the test (lives under
//!     `tests/mock_backend.rs`).
//!
//! Splitting on a trait keeps unit tests deterministic and integration
//! tests free of real network dependencies.
//!
//! The wire **shapes** + the real HTTP chain now live in
//! [`agentkeys_backend_client`] (issue #203) — the single owner shared with the
//! daemon and the harness fixture gate. This module re-exports those types so
//! the trait, the tools, and `InMemoryBackend` keep their `crate::backend::*`
//! import paths, and `HttpBackend` is a thin delegate over
//! `agentkeys_backend_client::BackendClient`. There is no second copy of the
//! cap/worker JSON here anymore.

pub mod http_backend;
pub mod in_memory;

use async_trait::async_trait;

pub use http_backend::HttpBackend;
pub use in_memory::InMemoryBackend;

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
