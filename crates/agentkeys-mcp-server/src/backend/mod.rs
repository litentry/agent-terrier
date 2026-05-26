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

pub mod audit;
pub mod broker;
pub mod http_backend;
pub mod in_memory;
pub mod memory;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use http_backend::HttpBackend;
pub use in_memory::InMemoryBackend;

/// Op discriminator that maps onto the four broker cap-mint endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapMintOp {
    CredStore,
    CredFetch,
    MemoryPut,
    MemoryGet,
}

impl CapMintOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cred_store" => Some(Self::CredStore),
            "cred_fetch" => Some(Self::CredFetch),
            "memory_put" => Some(Self::MemoryPut),
            "memory_get" => Some(Self::MemoryGet),
            _ => None,
        }
    }

    pub fn broker_path(self) -> &'static str {
        match self {
            Self::CredStore => "/v1/cap/cred-store",
            Self::CredFetch => "/v1/cap/cred-fetch",
            Self::MemoryPut => "/v1/cap/memory-put",
            Self::MemoryGet => "/v1/cap/memory-get",
        }
    }

    pub fn data_class(self) -> &'static str {
        match self {
            Self::CredStore | Self::CredFetch => "credentials",
            Self::MemoryPut | Self::MemoryGet => "memory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapMintRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    pub ttl_seconds: u64,
}

/// Opaque cap-token blob — we never inspect the inside on this side; the
/// broker signs it and the worker verifies the signature. JSON value is
/// fine.
pub type CapToken = Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutInput {
    pub cap: CapToken,
    pub namespace: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetInput {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutResult {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetResult {
    pub ok: bool,
    pub plaintext_b64: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendInput {
    pub operator_omni: String,
    pub actor_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendResult {
    pub ok: bool,
    pub envelope_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResult {
    pub ok: bool,
    pub revocation: String,
    /// Present when `revocation != "online_immediate"` — tells the caller
    /// what kind of revocation actually happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("backend not configured: {0}")]
    NotConfigured(&'static str),

    #[error("backend HTTP error ({status}): {body}")]
    Http { status: u16, body: String },

    #[error("backend transport error: {0}")]
    Transport(String),

    #[error("backend response parse error: {0}")]
    Parse(String),
}

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
