//! Audit-service worker — tier-A Merkle relay per arch.md §15.3.
//!
//! Accepts per-event audit appends over HTTP, batches them in memory per
//! operator, computes a Merkle tree on flush, and writes the root to the
//! on-chain CredentialAudit contract (one tx per batch — `appendRoot`).
//!
//! Tier-A vs tier-C (direct `append` per event): tier-A trades latency for
//! gas — each batch is one tx regardless of size, but events aren't visible
//! on chain until the next flush.

pub mod handlers;
pub mod merkle;
pub mod state;
