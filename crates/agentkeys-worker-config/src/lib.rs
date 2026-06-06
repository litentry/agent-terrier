//! Config-service worker — arch.md §15.x / #201.
//!
//! Mirrors the memory worker's cap-verify + AES-256-GCM + S3 semantics,
//! but uses a separate S3 prefix (`config/...` instead of `memory/...`),
//! a separate bucket (`$CONFIG_BUCKET`), and accepts only `DataClass::Config`
//! caps.
//!
//! Holds the policy / memory-types taxonomy (#178 §7) — the encrypted,
//! MASTER-ONLY home of the user's configured memory categories. The agent a
//! policy governs has NO config cap (access-control on the access-control);
//! master-self (`operator == actor`) means the on-chain scope check is skipped
//! at both the broker (handlers/cap.rs) and the worker (verify.rs), so the
//! master reaches only its own `bots/<O_master>/config/` prefix.
//!
//! Shares all the cryptographic + chain-verification code with the
//! credentials worker via the `agentkeys_worker_creds` crate. Only the
//! S3 path prefix + bucket env-var name + the accepted DataClass differ.

pub mod handlers;
pub mod state;

pub use state::{ConfigWorkerConfig, ConfigWorkerState};
