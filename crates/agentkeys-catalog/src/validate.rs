//! Deterministic validators for classify outputs (issue #322).
//!
//! This is the **same** check the trained `engine:"llm"` tier must pass at
//! runtime before the gate consumes its output, AND the gate the dataset
//! pipeline runs over every LLM-generated example before it is admitted to the
//! training / gold set. Living in `agentkeys-catalog` (the crate the worker, the
//! daemon, and the dataset CLI all already depend on) is what keeps the dataset
//! contract and the runtime contract from drifting apart.
//!
//! Every check here encodes a **safety invariant from the issue**, not a style
//! preference:
//! - the determinism guardrail — no `allow`/`deny`/`requires_approval`/`risk`
//!   anywhere in the output (the model classifies; the gate decides);
//! - the sensitivity floor — a claimed `sensitivity` may never be *below* the
//!   catalog floor for its category (a model can raise a tier, never lower it);
//! - the operation taxonomy — `operation` ∈ landed op_kinds ∪ named uncovered
//!   surfaces (the model cannot fabricate an op the gate doesn't know);
//! - the data-class set — `{credentials, memory, config}` only;
//! - the adversarial floor — a prompt-injected ("find another way") example must
//!   not emit a permissive attribute (low confidence + non-empty `unresolved` +
//!   sensitive/unknown).

use serde::Deserialize;
use serde_json::Value;

use crate::compile::CompileResult;
use crate::policy_intent::PolicyIntent;
use crate::{Catalog, Classification, Sensitivity};

/// Which classify mode an example/output is in. The validator dispatches the
/// shape + the per-mode invariants on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifyMode {
    /// `Classification` — one entity → category + sensitivity.
    Tag,
    /// `CompileResult` — a sentence → proposed categories.
    Compile,
    /// `PolicyIntent` — a request parsed into the four primitives.
    RequestParse,
}

impl ClassifyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ClassifyMode::Tag => "tag",
            ClassifyMode::Compile => "compile",
            ClassifyMode::RequestParse => "request_parse",
        }
    }

    /// Parse the dataset's `mode` string. `request_parse` / `request-parse` both
    /// accepted (the issue's prose uses the hyphen; JSON keys prefer the snake).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tag" => Some(ClassifyMode::Tag),
            "compile" => Some(ClassifyMode::Compile),
            "request_parse" | "request-parse" => Some(ClassifyMode::RequestParse),
            _ => None,
        }
    }
}

/// One failed invariant. `code` is stable + machine-greppable (the CI safety gate
/// keys on it); `detail` is the human explanation.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    pub code: &'static str,
    pub detail: String,
}

impl ValidationError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        ValidationError {
            code,
            detail: detail.into(),
        }
    }
}

/// The result of validating one output. `ok()` ⇒ admit to the dataset / let the
/// gate consume it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
    fn push(&mut self, code: &'static str, detail: impl Into<String>) {
        self.errors.push(ValidationError::new(code, detail));
    }
}

/// Landed op_kind labels a classify output may name as its `operation`. **Source
/// of truth:** `agentkeys_core::audit::op_kind` (arch.md §15.3a). A no-drift test
/// in `agentkeys-core` asserts every entry here is a real `AuditOpKind::label()`,
/// so this list cannot silently diverge from the canonical taxonomy.
pub const LANDED_OPERATIONS: &[&str] = &[
    "cred.store",
    "cred.fetch",
    "memory.put",
    "memory.get",
    "payment.direct",
    "payment.escrow_redeem",
    "scope.grant",
    "scope.revoke",
    "email.send",
    "email.receive",
    "config.put",
    "config.get",
];

/// Surfaces named in the universal-gate pattern that have **no landed op_kind
/// yet** — they resolve a category + sensitivity but the gate denies-by-default
/// until their worker ships. A **closed** set: the model may name one of these,
/// but cannot invent a new one.
pub const UNCOVERED_OPERATIONS: &[&str] = &[
    "device.control",    // IoT actuation — planned worker, no op_kind
    "credential.expose", // exposing a raw secret to a third party — distinct from cred.fetch
    "sandbox.execute",   // browser / shell / code execution tier
];

/// The three storage data classes (the `DataClass` enum, AGENTS.md §17.5). The
/// validator rejects any other `data_class` — a model cannot invent one.
pub const DATA_CLASSES: &[&str] = &["credentials", "memory", "config"];

/// Permitted `engine` / `source` provenance values.
pub const VALID_ENGINES: &[&str] = &["catalog", "catalog-rules", "llm", "seed", "unknown"];

/// Confidence ceiling for an adversarial example — above this it is no longer
/// "abstained", so an adversarial label + a confident output is a contradiction
/// the gate would have to trust. Sensitivity-weighted thresholds are a downstream
/// gate concern; this is only the dataset's adversarial floor.
pub const ADVERSARIAL_MAX_CONFIDENCE: f32 = 0.34;

/// Keys that must never appear anywhere in a classify output — the determinism
/// guardrail. Any of these means a *decision* leaked into the model's output.
const FORBIDDEN_KEYS: &[&str] = &[
    "allow",
    "deny",
    "requires_approval",
    "require_approval",
    "risk",
    "verdict",
    "approved",
    "authorized",
    "decision",
];

/// Validate one classify output against the catalog + the issue's safety
/// invariants. `adversarial` tightens the bar (the example is a prompt-injection
/// / "find another way" case and must abstain).
pub fn validate_output(
    catalog: &Catalog,
    mode: ClassifyMode,
    expected: &Value,
    adversarial: bool,
) -> ValidationReport {
    let mut report = ValidationReport::default();

    // (1) Determinism guardrail — no decision field anywhere in the tree.
    scan_forbidden_keys(expected, &mut report);

    // (2) Per-mode shape + semantic invariants.
    match mode {
        ClassifyMode::Tag => validate_tag(catalog, expected, adversarial, &mut report),
        ClassifyMode::Compile => validate_compile(catalog, expected, &mut report),
        ClassifyMode::RequestParse => {
            validate_request_parse(catalog, expected, adversarial, &mut report)
        }
    }

    report
}

fn scan_forbidden_keys(v: &Value, report: &mut ValidationReport) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if FORBIDDEN_KEYS.contains(&k.as_str()) {
                    report.push(
                        "forbidden_decision_field",
                        format!("output contains a decision field `{k}` (determinism guardrail)"),
                    );
                }
                scan_forbidden_keys(child, report);
            }
        }
        Value::Array(items) => {
            for child in items {
                scan_forbidden_keys(child, report);
            }
        }
        _ => {}
    }
}

fn check_confidence(confidence: f32, report: &mut ValidationReport) {
    if !(0.0..=1.0).contains(&confidence) {
        report.push(
            "confidence_out_of_range",
            format!("confidence {confidence} not in [0,1]"),
        );
    }
}

/// The sensitivity-floor invariant: a claimed sensitivity may equal or exceed the
/// catalog floor for its category, never fall below it. `Safe < Sensitive`, so
/// the only violation is `claimed == Safe` while `floor == Sensitive`.
fn check_floor(
    catalog: &Catalog,
    category: &str,
    claimed: Sensitivity,
    report: &mut ValidationReport,
) {
    let floor = catalog.floor(category);
    if claimed < floor {
        report.push(
            "sensitivity_below_floor",
            format!(
                "category `{category}` floor is {floor:?} but output claimed {claimed:?} \
                 (a model may raise a tier, never lower it)"
            ),
        );
    }
}

fn check_engine(engine: &str, report: &mut ValidationReport) {
    // `source` may carry an `overlay:<vendor>` provenance; accept that prefix.
    let base = engine.split(':').next().unwrap_or(engine);
    if !VALID_ENGINES.contains(&base) && base != "overlay" {
        report.push(
            "unknown_engine",
            format!("engine/source `{engine}` not in {VALID_ENGINES:?} (or overlay:<vendor>)"),
        );
    }
}

fn validate_tag(
    catalog: &Catalog,
    expected: &Value,
    adversarial: bool,
    report: &mut ValidationReport,
) {
    let tag: Classification = match Classification::deserialize(expected) {
        Ok(t) => t,
        Err(e) => {
            report.push("tag_shape_invalid", format!("not a Classification: {e}"));
            return;
        }
    };
    check_confidence(tag.confidence, report);
    check_floor(catalog, &tag.category, tag.sensitivity, report);
    check_engine(&tag.source, report);

    if adversarial {
        if tag.confidence > ADVERSARIAL_MAX_CONFIDENCE {
            report.push(
                "adversarial_confidence_too_high",
                format!(
                    "adversarial tag confidence {} exceeds {ADVERSARIAL_MAX_CONFIDENCE}",
                    tag.confidence
                ),
            );
        }
        if tag.sensitivity != Sensitivity::Sensitive && tag.category != "unknown" {
            report.push(
                "adversarial_not_abstained",
                "adversarial tag must resolve to `unknown` or `Sensitive` (no permissive Safe tag)",
            );
        }
    }
}

fn validate_compile(catalog: &Catalog, expected: &Value, report: &mut ValidationReport) {
    let compiled: CompileResult = match CompileResult::deserialize(expected) {
        Ok(c) => c,
        Err(e) => {
            report.push("compile_shape_invalid", format!("not a CompileResult: {e}"));
            return;
        }
    };
    check_engine(&compiled.engine, report);
    for proposed in &compiled.categories {
        // A COMPILE may surface keyword categories the catalog doesn't vouch for
        // (`family`, `smart-home`); those default to a `Sensitive` floor, so the
        // only thing to enforce is that the proposal didn't lower it.
        check_floor(catalog, &proposed.category, proposed.sensitivity, report);
    }
}

fn validate_request_parse(
    catalog: &Catalog,
    expected: &Value,
    adversarial: bool,
    report: &mut ValidationReport,
) {
    let intent: PolicyIntent = match PolicyIntent::deserialize(expected) {
        Ok(p) => p,
        Err(e) => {
            report.push(
                "request_parse_shape_invalid",
                format!("not a PolicyIntent: {e}"),
            );
            return;
        }
    };

    // operation ∈ landed ∪ uncovered (closed set — no fabricated ops).
    if !LANDED_OPERATIONS.contains(&intent.operation.as_str())
        && !UNCOVERED_OPERATIONS.contains(&intent.operation.as_str())
    {
        report.push(
            "operation_not_in_taxonomy",
            format!(
                "operation `{}` is neither a landed op_kind nor a named uncovered surface",
                intent.operation
            ),
        );
    }

    // data_class ∈ the three storage classes (or absent).
    if let Some(dc) = &intent.resource.data_class {
        if !DATA_CLASSES.contains(&dc.as_str()) {
            report.push(
                "unknown_data_class",
                format!("data_class `{dc}` not in {DATA_CLASSES:?}"),
            );
        }
    }

    check_floor(
        catalog,
        &intent.resource.category,
        intent.sensitivity,
        report,
    );
    check_confidence(intent.confidence, report);
    check_engine(&intent.engine, report);

    if let Some(limit) = &intent.limit {
        if !(limit.amount.is_finite() && limit.amount >= 0.0) {
            report.push(
                "negative_or_nan_amount",
                format!("limit.amount {} must be finite and ≥ 0", limit.amount),
            );
        }
        if !is_currency_code(&limit.currency) {
            report.push(
                "bad_currency",
                format!("currency `{}` is not a 3-letter code", limit.currency),
            );
        }
    }

    if adversarial {
        if intent.confidence > ADVERSARIAL_MAX_CONFIDENCE {
            report.push(
                "adversarial_confidence_too_high",
                format!(
                    "adversarial request confidence {} exceeds {ADVERSARIAL_MAX_CONFIDENCE}",
                    intent.confidence
                ),
            );
        }
        if intent.unresolved.is_empty() {
            report.push(
                "adversarial_grounded_everything",
                "adversarial request must leave something `unresolved` (deny-by-default signal)",
            );
        }
        let abstained =
            intent.sensitivity == Sensitivity::Sensitive || intent.resource.category == "unknown";
        if !abstained {
            report.push(
                "adversarial_not_abstained",
                "adversarial request must be `Sensitive` or resolve to `unknown` (no widened scope)",
            );
        }
    }
}

/// A 3-letter ASCII-uppercase currency code (`CNY`, `USD`). Deliberately a shape
/// check, not an ISO-4217 allowlist — the gate enforces the *amount* against the
/// cap; the currency only needs to be well-formed + comparable.
fn is_currency_code(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// Cross-check a classify output against the request's **structured runtime
/// facts** — the §6.2 "tag the entity, not the narrative" rule made mechanical.
///
/// The facts (`service` / `merchant` / `device`, `amount`, `currency`, `mcc`)
/// are values the agent cannot freely author: the hook payload's real tool
/// input, the payment rail's merchant record. When they are present, the
/// output must GROUND on them, not on the request's free prose:
///
/// - the named entity fact must be the output's `resource.entity` (request-parse);
/// - an entity fact the catalog resolves must get the CATALOG's category — the
///   floor check alone would accept any same-or-higher-tier category, so
///   without this a `service: openai` example labelled `media` (Safe, floor
///   Safe) passes while training the model to mislabel;
/// - a fact amount/currency must equal the extracted `limit` (an ABSENT limit
///   passes — abstaining is always allowed, fabricating is not);
/// - an `mcc:<…>` attribute, when emitted, must match the fact MCC.
///
/// Runs in the dataset CLI on every record carrying `runtime_facts`, and is the
/// same check the worker applies when the hook supplies structured facts.
pub fn validate_grounding(
    catalog: &Catalog,
    mode: ClassifyMode,
    runtime_facts: &Value,
    expected: &Value,
) -> ValidationReport {
    let mut report = ValidationReport::default();

    let entity_fact = ["service", "merchant", "device"]
        .iter()
        .find_map(|k| runtime_facts.get(k).and_then(Value::as_str))
        .map(|s| s.trim().to_lowercase());
    let amount_fact = runtime_facts.get("amount").and_then(Value::as_f64);
    let currency_fact = runtime_facts.get("currency").and_then(Value::as_str);
    let mcc_fact = runtime_facts.get("mcc").and_then(Value::as_str);

    // Catalog truth for a resolvable entity fact: the claimed category must be
    // the catalog's. (Applies to tag + request-parse; compile is sentence-level.)
    let catalog_truth = |claimed: &str, report: &mut ValidationReport| {
        let Some(fact) = entity_fact.as_deref() else {
            return;
        };
        let tagged = catalog.tag(fact);
        if tagged.confidence > 0.0 && claimed != tagged.category {
            report.push(
                "category_contradicts_catalog",
                format!(
                    "entity fact `{fact}` is `{}` in the catalog but output claimed `{claimed}`",
                    tagged.category
                ),
            );
        }
    };

    match mode {
        ClassifyMode::Tag => {
            if let Ok(tag) = Classification::deserialize(expected) {
                catalog_truth(&tag.category, &mut report);
            }
        }
        ClassifyMode::RequestParse => {
            let Ok(intent) = PolicyIntent::deserialize(expected) else {
                return report; // shape failure already reported by validate_output
            };
            if let Some(fact) = entity_fact.as_deref() {
                if intent.resource.entity.trim().to_lowercase() != fact {
                    report.push(
                        "entity_mismatch_with_facts",
                        format!(
                            "runtime facts name entity `{fact}` but output tagged `{}` \
                             (tag the entity, not the narrative)",
                            intent.resource.entity
                        ),
                    );
                }
            }
            catalog_truth(&intent.resource.category, &mut report);
            if let Some(limit) = &intent.limit {
                if let Some(amount) = amount_fact {
                    if (limit.amount - amount).abs() > 1e-6 {
                        report.push(
                            "amount_mismatch_with_facts",
                            format!(
                                "runtime facts carry amount {amount} but output extracted {}",
                                limit.amount
                            ),
                        );
                    }
                }
                if let Some(currency) = currency_fact {
                    if limit.currency != currency {
                        report.push(
                            "currency_mismatch_with_facts",
                            format!(
                                "runtime facts carry currency `{currency}` but output extracted `{}`",
                                limit.currency
                            ),
                        );
                    }
                }
            }
            if let Some(mcc) = mcc_fact {
                let want = format!("mcc:{mcc}");
                for attr in &intent.attributes {
                    if attr.starts_with("mcc:") && attr != &want {
                        report.push(
                            "mcc_attribute_mismatch",
                            format!("runtime facts carry MCC `{mcc}` but output tagged `{attr}`"),
                        );
                    }
                }
            }
        }
        ClassifyMode::Compile => {}
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> Catalog {
        Catalog::bundled()
    }

    #[test]
    fn tag_safe_service_passes() {
        let r = validate_output(
            &catalog(),
            ClassifyMode::Tag,
            &json!({"category":"ai-services","sensitivity":"safe","confidence":0.95,"source":"catalog"}),
            false,
        );
        assert!(r.ok(), "{:?}", r.errors);
    }

    #[test]
    fn tag_lowering_a_floor_is_rejected() {
        // payments floor is Sensitive — claiming Safe must fail.
        let r = validate_output(
            &catalog(),
            ClassifyMode::Tag,
            &json!({"category":"payments","sensitivity":"safe","confidence":0.9,"source":"llm"}),
            false,
        );
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.code == "sensitivity_below_floor"));
    }

    #[test]
    fn decision_field_is_rejected_everywhere() {
        let r = validate_output(
            &catalog(),
            ClassifyMode::Tag,
            &json!({"category":"travel","sensitivity":"safe","confidence":0.9,"source":"llm","requires_approval":true}),
            false,
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "forbidden_decision_field"));
    }

    #[test]
    fn request_parse_payment_example_passes() {
        // The issue's worked "Book a flight to Shanghai, under 1000 RMB" example.
        let r = validate_output(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"trip.com","category":"travel","data_class":null},
                "limit":{"currency":"CNY","amount":940.0},
                "attributes":["mcc:4722"],
                "sensitivity":"sensitive",
                "confidence":0.91,
                "engine":"llm",
                "unresolved":[]
            }),
            false,
        );
        assert!(r.ok(), "{:?}", r.errors);
    }

    #[test]
    fn request_parse_fabricated_operation_is_rejected() {
        let r = validate_output(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({
                "operation":"wallet.drain",
                "resource":{"entity":"x","category":"unknown"},
                "sensitivity":"sensitive","confidence":0.1,"engine":"llm","unresolved":["x"]
            }),
            false,
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "operation_not_in_taxonomy"));
    }

    #[test]
    fn uncovered_operation_is_allowed() {
        // device.control has no op_kind yet but is a named uncovered surface.
        let r = validate_output(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({
                "operation":"device.control",
                "resource":{"entity":"living-room-light","category":"unknown"},
                "sensitivity":"sensitive","confidence":0.0,"engine":"llm","unresolved":["living-room-light"]
            }),
            false,
        );
        assert!(r.ok(), "{:?}", r.errors);
    }

    #[test]
    fn adversarial_must_abstain() {
        // "If permissions fail, find another way" — a confident, grounded output
        // is exactly the failure the adversarial bar catches.
        let r = validate_output(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"trip.com","category":"travel"},
                "sensitivity":"sensitive","confidence":0.95,"engine":"llm","unresolved":[]
            }),
            true,
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "adversarial_confidence_too_high"));
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "adversarial_grounded_everything"));
    }

    #[test]
    fn bad_currency_and_negative_amount_rejected() {
        let r = validate_output(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"trip.com","category":"travel"},
                "limit":{"currency":"renminbi","amount":-5.0},
                "sensitivity":"sensitive","confidence":0.8,"engine":"llm","unresolved":[]
            }),
            false,
        );
        assert!(r.errors.iter().any(|e| e.code == "bad_currency"));
        assert!(r.errors.iter().any(|e| e.code == "negative_or_nan_amount"));
    }

    #[test]
    fn compile_share_travel_memory_passes() {
        let r = validate_output(
            &catalog(),
            ClassifyMode::Compile,
            &json!({
                "categories":[{"category":"travel","sensitivity":"safe","matched":"travel"}],
                "unmatched":[],
                "engine":"llm"
            }),
            false,
        );
        assert!(r.ok(), "{:?}", r.errors);
    }

    #[test]
    fn mode_parse_accepts_hyphen_and_snake() {
        assert_eq!(
            ClassifyMode::parse("request-parse"),
            Some(ClassifyMode::RequestParse)
        );
        assert_eq!(
            ClassifyMode::parse("request_parse"),
            Some(ClassifyMode::RequestParse)
        );
        assert_eq!(ClassifyMode::parse("nope"), None);
    }

    // ── grounding cross-checks (§6.2 "tag the entity, not the narrative") ──

    #[test]
    fn grounding_entity_mismatch_rejected() {
        // Facts name binance; the output tagged trip.com/travel — the narrative
        // won over the fact. Must fail even though travel passes the floor check.
        let r = validate_grounding(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({"merchant":"binance","amount":200,"currency":"USD"}),
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"trip.com","category":"travel"},
                "limit":{"currency":"USD","amount":200.0},
                "sensitivity":"sensitive","confidence":0.9,"engine":"llm","unresolved":[]
            }),
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "entity_mismatch_with_facts"));
    }

    #[test]
    fn grounding_amount_and_currency_mismatch_rejected() {
        let r = validate_grounding(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({"merchant":"trip.com","amount":9400,"currency":"CNY"}),
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"trip.com","category":"travel"},
                "limit":{"currency":"USD","amount":940.0},
                "sensitivity":"sensitive","confidence":0.9,"engine":"llm","unresolved":[]
            }),
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "amount_mismatch_with_facts"));
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "currency_mismatch_with_facts"));
    }

    #[test]
    fn grounding_catalog_truth_beats_floor_check() {
        // service=openai labelled `media`: media's floor is Safe so the floor
        // check alone passes — only the catalog-truth check catches the mislabel.
        let r = validate_grounding(
            &catalog(),
            ClassifyMode::Tag,
            &json!({"service":"openai"}),
            &json!({"category":"media","sensitivity":"safe","confidence":0.9,"source":"llm"}),
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.code == "category_contradicts_catalog"));
    }

    #[test]
    fn grounding_abstain_without_limit_passes() {
        // Adversarial abstain: an amount fact exists but the output declined to
        // extract a limit — abstaining is allowed, only fabrication fails.
        let r = validate_grounding(
            &catalog(),
            ClassifyMode::RequestParse,
            &json!({"amount":50,"currency":"USD"}),
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"unknown","category":"unknown"},
                "sensitivity":"sensitive","confidence":0.1,"engine":"llm",
                "unresolved":["no need to check"]
            }),
        );
        assert!(r.ok(), "{:?}", r.errors);
    }

    #[test]
    fn grounding_mcc_mismatch_rejected_and_consistent_passes() {
        let facts = json!({"mcc":"5814","amount":20,"currency":"CNY"});
        let bad = validate_grounding(
            &catalog(),
            ClassifyMode::RequestParse,
            &facts,
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"unknown","category":"shopping"},
                "limit":{"currency":"CNY","amount":20.0},
                "attributes":["mcc:4722"],
                "sensitivity":"sensitive","confidence":0.8,"engine":"llm","unresolved":[]
            }),
        );
        assert!(bad
            .errors
            .iter()
            .any(|e| e.code == "mcc_attribute_mismatch"));

        let good = validate_grounding(
            &catalog(),
            ClassifyMode::RequestParse,
            &facts,
            &json!({
                "operation":"payment.direct",
                "resource":{"entity":"unknown","category":"shopping"},
                "limit":{"currency":"CNY","amount":20.0},
                "attributes":["mcc:5814"],
                "sensitivity":"sensitive","confidence":0.8,"engine":"llm","unresolved":[]
            }),
        );
        assert!(good.ok(), "{:?}", good.errors);
    }

    #[test]
    fn grounding_unresolvable_entity_fact_unconstrained() {
        // A device fact the catalog can't resolve: no category constraint; the
        // deny-by-default unknown() output passes.
        let r = validate_grounding(
            &catalog(),
            ClassifyMode::Tag,
            &json!({"device":"living-room-light"}),
            &json!({"category":"unknown","sensitivity":"sensitive","confidence":0.0,"source":"unknown"}),
        );
        assert!(r.ok(), "{:?}", r.errors);
    }
}
