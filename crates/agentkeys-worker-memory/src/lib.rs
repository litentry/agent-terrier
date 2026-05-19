//! Memory-service worker — arch.md §15.2.
//!
//! Mirrors the credentials worker's cap-verify + AES-256-GCM + S3
//! semantics, but uses a separate S3 prefix (`memory/...` instead of
//! `credentials/...`) and a separate bucket (`$MEMORY_BUCKET`).
//!
//! Stage 2 deliverable per issue #90: high-frequency agent state +
//! chat history + scratch space, scoped per actor_omni.
//!
//! Shares all the cryptographic + chain-verification code with the
//! credentials worker via the `agentkeys_worker_creds` crate. Only the
//! S3 path prefix + bucket env-var name differ.

pub mod handlers;
pub mod state;

pub use state::{MemoryWorkerConfig, MemoryWorkerState};
