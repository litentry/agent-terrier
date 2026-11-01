//! COMPILE output types — moved here from `agentkeys-worker-classify` so the
//! shared validator ([`crate::validate`]) and the dataset tooling can reference
//! the **one** definition without depending on the worker (which pulls axum +
//! reqwest + the cap-verify chain). The worker re-exports these from here, so
//! `agentkeys_worker_classify::classify::CompileResult` still resolves — the
//! "never re-type a wire shape in a second path" rule (AGENTS.md #203).
//!
//! The COMPILE *engine* (`compile(sentence) -> CompileResult`) stays in the
//! worker; only the pure-data result types live here.

use serde::{Deserialize, Serialize};

use crate::Sensitivity;

/// A proposed grant from a COMPILE — a `(category, sensitivity)` the master will
/// confirm (never auto-applied; the determinism guardrail keeps the model off the
/// gate). `matched` is the catalog entity / keyword that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedCategory {
    pub category: String,
    pub sensitivity: Sensitivity,
    pub matched: String,
}

/// The result of a COMPILE: the distinct categories a sentence resolved to, the
/// tokens that matched nothing (surfaced as the LLM tail), and which engine ran.
///
/// `engine` is an owned `String` (not `&'static str`) so the type round-trips
/// through `serde_json::from_value` in the dataset validator — the deterministic
/// `compile()` sets it to `"catalog-rules"`; the trained tier sets `"llm"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompileResult {
    /// Distinct categories the sentence resolved to (the proposed taxonomy).
    pub categories: Vec<ProposedCategory>,
    /// Tokens that matched no catalog entry — surfaced so the master sees what
    /// the deterministic tier-0 could NOT resolve (the LLM tail, #178 §8.1).
    pub unmatched: Vec<String>,
    /// `catalog-rules` (the deterministic tier-0) vs a future `llm` engine.
    pub engine: String,
}
