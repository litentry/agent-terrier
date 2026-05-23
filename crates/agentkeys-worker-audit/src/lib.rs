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

use axum::{
    routing::{get, post},
    Router,
};

/// Build the worker's HTTP router. Exposed for tests that want to drive
/// the V2 endpoints through `tower::ServiceExt::oneshot` without binding
/// a real TCP socket.
pub fn create_router(state: state::SharedState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/audit/append", post(handlers::append))
        .route("/v1/audit/flush/:operator_omni", post(handlers::flush_one))
        .route("/v1/audit/flush-all", post(handlers::flush_all))
        .route(
            "/v1/audit/queue-size/:operator_omni",
            get(handlers::queue_size),
        )
        .route("/v1/audit/append/v2", post(handlers::append_v2))
        .route("/v1/audit/envelope/:hash", get(handlers::get_envelope))
        .with_state(state)
}
