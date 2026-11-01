//! Classifier-service worker (#178 §15.6 / #207 items 2-3) — a COMPUTE gate.
//!
//! Turns human intent + novel entities into the **structured policy attributes**
//! a deterministic gate enforces, WITHOUT a model on the gate hot path:
//! - **TAG** (`/v1/classify/tag`) — entity → category + sensitivity (catalog).
//! - **COMPILE** (`/v1/classify/compile`) — NL sentence → proposed categories.
//!
//! It runs the SAME cap + chain-verify chain as the storage workers (isolation
//! layers 1-2) via `agentkeys_worker_creds::verify`, pinned to `CapOp::Classify`
//! and data-class-bound — but has **no S3 bucket / KEK** (layers 3-4 N/A): the
//! effect is inference over the in-process [`catalog`], not an encrypted write.
//!
//! Determinism guardrail (#178 §5): COMPILE/TAG emit **tags + proposed policy,
//! never allow/deny**. The downstream gate decides by set-membership; an unknown
//! entity is `unknown` → deny-by-default.

// The category catalog is a SHARED crate (the daemon also uses it for the
// deterministic tier-0 proposal, #207 items 5/7) — re-exported here so the
// worker's `crate::catalog::…` paths keep resolving.
pub use agentkeys_catalog as catalog;
pub mod classify;
pub mod handlers;
pub mod state;

pub use state::{ClassifyWorkerConfig, ClassifyWorkerState};
