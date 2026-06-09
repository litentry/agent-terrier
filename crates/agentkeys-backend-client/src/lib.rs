//! `agentkeys-backend-client` — the single owner of the broker/worker client
//! protocol (issue #203).
//!
//! It is the dual of `agentkeys-broker-server` / `agentkeys-worker-*`: where
//! those crates *serve* the cap-mint + worker endpoints, this crate *calls*
//! them. Everything the chain serializes — the four cap-mint endpoints, the
//! STS relay, worker put/get, the `memory:<ns>` service builder, and the
//! `0x`-omni normalizer — lives here once. The MCP server's `HttpBackend`
//! delegates to [`BackendClient`]; the daemon's `ui_bridge` real-memory path
//! calls it directly; the harness diffs its bash bodies against
//! [`fixtures::canonical_fixtures`]. Re-typing any of these elsewhere is a
//! compile error or a fixture mismatch, never a silent runtime drift.

pub mod client;
pub mod fixtures;
pub mod protocol;

pub use client::{BackendClient, BackendError};
pub use protocol::{
    normalize_omni_0x, service_memory, AuditAppendInput, AuditAppendResult, AuditAppendV2,
    AuditAppendV2Resp, BrokerCapRequest, CapMintOp, CapMintRequest, CapToken, ConfigGetBody,
    ConfigGetResp, ConfigPutBody, CredFetchBody, CredFetchInput, CredFetchResp, CredFetchResult,
    CredStoreBody, CredStoreInput, CredStoreResp, CredStoreResult, MemoryGetBody, MemoryGetInput,
    MemoryGetResp, MemoryGetResult, MemoryPutBody, MemoryPutInput, MemoryPutResp, MemoryPutResult,
    RevokeResult, ENVELOPE_VERSION,
};
