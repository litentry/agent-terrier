//! The dataset record envelope (issue #322). One JSONL line = one example. The
//! `expected` payload is kept as a raw `serde_json::Value` and validated per-mode
//! by the shared `agentkeys_catalog::validate` — exactly how an LLM emits it
//! (untyped JSON) and how the runtime gate will re-check the trained engine's
//! output. The envelope is the only thing this crate owns; the *output* types
//! (`Classification` / `CompileResult` / `PolicyIntent`) have one home, in the
//! catalog crate.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One labelled example.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRecord {
    /// Stable id (e.g. `seed-pay-0001`) — referenced in failure reports + the
    /// gold-set provenance.
    pub id: String,
    /// `tag` | `compile` | `request_parse` — selects which output type + which
    /// invariants the validator applies.
    pub mode: String,
    /// The model's *input*: the request text + language + optional structured
    /// runtime facts (the real `tool_name`+`tool_input` / `merchant`+`mcc`+`amount`
    /// / `service` id — "tag the entity, not the narrative").
    pub input: Input,
    /// The *expected* output, validated per-mode. Raw JSON by design.
    pub expected: Value,
    /// Curation metadata: split, taxonomy class, adversarial flag, provenance.
    #[serde(default)]
    pub labels: Labels,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Input {
    pub text: String,
    /// `en` | `zh` | `mixed` — bilingual coverage is a first-class eval axis.
    #[serde(default = "default_lang")]
    pub lang: String,
    /// Optional structured facts the agent cannot freely author. When present,
    /// the classifier should ground on these over the free-text `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_facts: Option<Value>,
}

fn default_lang() -> String {
    "en".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Labels {
    /// `train` | `gold` — gold is held out of training, gates CI on regressions.
    #[serde(default)]
    pub split: String,
    /// The taxonomy class (`payment`, `memory-share`, `device-control`,
    /// `cred-exposure`, `adversarial`, …) — for per-class eval slicing.
    #[serde(default)]
    pub class: String,
    /// Prompt-injection / "find another way" example — the validator applies the
    /// stricter abstention bar.
    #[serde(default)]
    pub adversarial: bool,
    /// `seed` (hand-authored) | `llm:glm` | `llm:claude` | `llm:codex` — so a
    /// regression can be traced to its generator.
    #[serde(default)]
    pub source: String,
}
