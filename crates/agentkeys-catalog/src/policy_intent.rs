//! The `PolicyIntent` request-parse profile (issue #322) — the structured output
//! of the classify cascade's **request-parse** mode, the write-side dual of the
//! memory read-engine and the open-vocabulary tail of the deterministic gate.
//!
//! It is a **strict superset-by-composition** of the landed TAG output
//! ([`crate::Classification`]) and COMPILE output ([`crate::compile::CompileResult`]),
//! expressed in the four universal-gate primitives
//! (`operation` / `resource-scope` / `quantitative-limit` / `attribute-constraint` —
//! see [`docs/research/universal-gate-pattern.md`]). It carries the request's
//! **measured** attributes, never a verdict.
//!
//! ## The determinism guardrail (load-bearing, #178 §5 / #322)
//! `PolicyIntent` deliberately has **no** `allow` / `deny` / `requires_approval` /
//! `risk` field. Those are the gate's job, derived downstream from the
//! `sensitivity`, on-chain scope-set membership, and the cap's `limits`. The model
//! emits the request's *measured* amount; the cap's `limits.max_single` (the
//! *policy* cap) lives in scope, and the gate compares them. A model output may
//! never lower a category's sensitivity floor ([`crate::Sensitivity::max`] only
//! ever raises).
//!
//! The fields are intentionally `String`-typed at the schema edge: the LLM engine
//! emits JSON strings, and the deterministic validator ([`crate::validate`])
//! constrains them — `operation` ∈ the op_kind taxonomy, `data_class` ∈ the
//! three storage classes, `sensitivity` ≥ the catalog floor. A bad value becomes
//! a crisp `ValidationError`, not a serde parse failure with no provenance.

use serde::{Deserialize, Serialize};

use crate::Sensitivity;

/// The request-parse output: a request the classifier must *parse* (not just tag
/// a single entity), expressed in the four policy primitives. Validated by
/// [`crate::validate::validate_output`] before any gate consumes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyIntent {
    /// The operation, named to align with the audit op_kind taxonomy
    /// (arch.md §15.3a) where a worker exists (`payment.direct`, `memory.put`,
    /// `scope.grant`, …), or one of the named **uncovered** surfaces
    /// (`device.control`, `credential.expose`, `sandbox.execute`) that have no
    /// op_kind yet and bind on `operation` + `resource.category`. The validator
    /// rejects any operation outside that closed set — the model cannot fabricate
    /// an op the gate doesn't know.
    pub operation: String,
    /// What the operation targets — the **real** entity (service / merchant /
    /// device id the agent cannot freely author), its catalog category, and the
    /// storage data class when one applies.
    pub resource: ResourceRef,
    /// The quantitative limit *extracted from the request* (primitive #3) — e.g.
    /// the amount a purchase names. `None` when the operation has no amount. This
    /// is the **requested** amount; the **policy** cap (`limits.max_single`) lives
    /// in the cap's scope, and the gate compares the two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
    /// Structured tags the gate checks by set-membership (primitive #4) — e.g.
    /// `mcc:4722` (travel agencies), `recipient:non-contact`. Never free prose.
    #[serde(default)]
    pub attributes: Vec<String>,
    /// The category sensitivity floor (= `catalog.floor(resource.category)`). The
    /// validator rejects any value *below* the floor — a model can raise a tier,
    /// never lower it.
    pub sensitivity: Sensitivity,
    /// Confidence in `[0,1]`. Sensitivity-weighted downstream: payments /
    /// access-control demand a higher bar + bias-to-deny.
    pub confidence: f32,
    /// The engine that produced this — `llm`, the deterministic `catalog-rules`
    /// tier-0, or `seed` (a hand-authored dataset example).
    pub engine: String,
    /// Free-text the model could **not** ground to a real entity / amount /
    /// recipient. A non-empty `unresolved` is the deny-by-default signal: the gate
    /// denies rather than guess. Adversarial "find another way" requests MUST
    /// populate this (the validator enforces it).
    #[serde(default)]
    pub unresolved: Vec<String>,
}

/// The resource an operation targets. `entity` is the **real** id (per "tag the
/// entity, not the narrative") — the model classifies on structured facts the
/// agent cannot freely author, never on its own prose description of intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceRef {
    /// The real service / merchant / device id (`trip.com`, `august-lock`,
    /// `openai`). Empty / `unknown` when the request named no groundable entity.
    pub entity: String,
    /// The catalog category for the entity (`travel`, `payments`, `access-control`)
    /// or `unknown` when unresolved. Drives the sensitivity floor.
    pub category: String,
    /// The storage data class when the operation touches one of the three gated
    /// stores (`credentials` / `memory` / `config`). `None` for surfaces with no
    /// storage data class yet — payment, device-control, message-send — which
    /// bind on `operation` + `category` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_class: Option<String>,
}

/// A quantitative limit extracted from a request (primitive #3). `currency` is a
/// 3-letter ISO-ish code (`CNY`, `USD`); `amount` is the requested figure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limit {
    pub currency: String,
    pub amount: f64,
}

impl PolicyIntent {
    /// The deny-by-default request-parse output for a request the cascade could
    /// not ground: `unknown` resource, `Sensitive`, confidence 0, the raw text
    /// surfaced in `unresolved`. The gate treats this as "not in scope + sensitive"
    /// → never auto-granted. This is the adversarial / low-confidence floor the
    /// LLM engine must fall back to rather than guess a permissive attribute.
    pub fn deny_by_default(
        operation: impl Into<String>,
        unresolved_text: impl Into<String>,
    ) -> Self {
        PolicyIntent {
            operation: operation.into(),
            resource: ResourceRef {
                entity: "unknown".into(),
                category: "unknown".into(),
                data_class: None,
            },
            limit: None,
            attributes: Vec::new(),
            sensitivity: Sensitivity::Sensitive,
            confidence: 0.0,
            engine: "llm".into(),
            unresolved: vec![unresolved_text.into()],
        }
    }
}
