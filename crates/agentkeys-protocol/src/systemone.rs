//! TypeSafe "System One" wire shapes (#689 / #722) — the typed-decision model
//! (Jev) behind the household router. ONE owner (D7): the model gate relays
//! this body to `https://api.typesafe.ai/v1/systemone`, the contact gate builds
//! it, and the daemon will build the same shape for the console's picks — every
//! caller compiles against these structs, so a drifted field is a compile error.
//!
//! Shape source: TypeSafe's API reference (<https://docs.typesafe.ai/api.md>).
//! A request is a `state` (string / object / array) plus a map of typed
//! questions; the answer map comes back under the same keys, each answer tagged
//! with its question type. Only `Choice` and `Score` carry `confidence`; a
//! `Noul` (yes/no) is the bare probability of yes.
//!
//! Pure serde, transport-free, wasm-safe (the same discipline as the cap-mint
//! bodies in this crate).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The gate route that relays a System One request (the caller presents its
/// `gk_` relay key; the gate attaches the TypeSafe key).
pub const SYSTEMONE_ROUTE: &str = "/v1/systemone";

/// The Jev version the router pins by default. Thresholds tuned against one
/// version belong to it (TypeSafe moves the `jev-latest` alias without notice),
/// so callers send the versioned id and move the pin on purpose.
pub const JEV_PINNED_MODEL: &str = "jev-1.13.0";

/// `POST /v1/systemone` body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneRequest {
    /// The versioned model id (or an alias) that answers.
    pub model: String,
    /// What to evaluate: a plain string, or structured data the questions
    /// point into with backticked field names.
    pub state: Value,
    /// Named questions; answers come back under the same keys. `BTreeMap` so
    /// the serialized order is stable (audit hashes, fixtures).
    pub questions: BTreeMap<String, SystemOneQuestion>,
}

/// One typed question. `instructions` and every criteria entry accept a
/// string, an object or an array (TypeSafe reads structure).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SystemOneQuestion {
    /// Yes/no — the answer is the probability of yes.
    Noul {
        instructions: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        criteria: Option<NoulCriteria>,
    },
    /// Pick ONE option from `criteria` (option key → description; at most 255).
    Choice {
        instructions: Value,
        criteria: BTreeMap<String, Value>,
    },
    /// Rate along an ordered list of level descriptions (2–10 levels).
    Score {
        instructions: Value,
        criteria: Vec<Value>,
    },
}

/// What a yes and a no mean for a `Noul`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NoulCriteria {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "true")]
    pub yes: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "false")]
    pub no: Option<Value>,
}

/// `POST /v1/systemone` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneResponse {
    /// The versioned model that actually answered (`jev-1.13.0`, never the alias).
    pub model: String,
    pub answers: BTreeMap<String, SystemOneAnswer>,
    pub usage: SystemOneUsage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SystemOneAnswer {
    Noul {
        /// 0 (no) … 1 (yes).
        noul: f64,
    },
    Choice {
        /// The highest-probability option key.
        choice: String,
        /// Every option → probability (sums to 1).
        probabilities: BTreeMap<String, f64>,
        /// 0 … 1, derived from how peaked `probabilities` is.
        confidence: f64,
    },
    Score {
        /// Probability-weighted level; may land between levels.
        score: f64,
        /// Level index (as a string key) → its description.
        legend: BTreeMap<String, String>,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
}

/// Token usage — TypeSafe bills input tokens only, but reports both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SystemOneUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl SystemOneUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

impl SystemOneResponse {
    pub fn choice(&self, key: &str) -> Option<(&str, &BTreeMap<String, f64>, f64)> {
        match self.answers.get(key)? {
            SystemOneAnswer::Choice {
                choice,
                probabilities,
                confidence,
            } => Some((choice.as_str(), probabilities, *confidence)),
            _ => None,
        }
    }

    pub fn noul(&self, key: &str) -> Option<f64> {
        match self.answers.get(key)? {
            SystemOneAnswer::Noul { noul } => Some(*noul),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The request shape TypeSafe documents (API reference, "Choice"), byte-for-
    /// byte on the keys: a drift here means the vendor's endpoint would 422 us.
    #[test]
    fn documented_choice_request_round_trips() {
        let raw = json!({
            "state": "Help! My payouts have been failing for 3 days.",
            "model": "jev-latest",
            "questions": {
                "department": {
                    "type": "choice",
                    "instructions": "Which team should handle this?",
                    "criteria": {
                        "billing": "Payments, invoicing, refunds",
                        "technical": "Bugs, outages, integrations",
                        "sales": "Pricing, upgrades, new accounts"
                    }
                },
                "is_urgent": {
                    "type": "noul",
                    "instructions": "Does this convey urgency?",
                    "criteria": {"true": "Explicitly time-sensitive", "false": "No urgency expressed"}
                },
                "frustration": {
                    "type": "score",
                    "instructions": "How frustrated is the customer?",
                    "criteria": ["Calm", "Frustrated", "Very angry"]
                }
            }
        });
        let req: SystemOneRequest = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(req.model, "jev-latest");
        assert!(matches!(
            req.questions.get("department"),
            Some(SystemOneQuestion::Choice { criteria, .. }) if criteria.len() == 3
        ));
        assert!(matches!(
            req.questions.get("is_urgent"),
            Some(SystemOneQuestion::Noul { criteria: Some(c), .. }) if c.yes.is_some() && c.no.is_some()
        ));
        let back = serde_json::to_value(&req).unwrap();
        assert_eq!(back, raw);
    }

    /// The response shape TypeSafe documents (API reference, "Answer types").
    #[test]
    fn documented_answers_decode_with_typed_accessors() {
        let raw = json!({
            "model": "jev-1.13.0",
            "answers": {
                "department": {
                    "type": "choice",
                    "choice": "billing",
                    "probabilities": {"billing": 0.88, "technical": 0.12, "sales": 0.0},
                    "confidence": 0.81
                },
                "is_urgent": {"type": "noul", "noul": 0.95},
                "frustration": {
                    "type": "score",
                    "score": 1.05,
                    "legend": {"0": "Calm", "1": "Frustrated", "2": "Very angry"},
                    "probabilities": {"0": 0.0, "1": 0.95, "2": 0.05},
                    "confidence": 0.92
                }
            },
            "usage": {"input_tokens": 318, "output_tokens": 34}
        });
        let resp: SystemOneResponse = serde_json::from_value(raw.clone()).unwrap();
        let (choice, probs, confidence) = resp.choice("department").unwrap();
        assert_eq!(choice, "billing");
        assert_eq!(probs["billing"], 0.88);
        assert_eq!(confidence, 0.81);
        assert_eq!(resp.noul("is_urgent"), Some(0.95));
        assert!(resp.choice("is_urgent").is_none(), "a noul is not a choice");
        assert_eq!(resp.usage.total(), 352);
        assert_eq!(serde_json::to_value(&resp).unwrap(), raw);
    }

    #[test]
    fn an_unknown_answer_type_is_a_decode_error_never_a_silent_default() {
        let raw = json!({
            "model": "jev-1.13.0",
            "answers": {"q": {"type": "essay", "text": "..."}},
            "usage": {"input_tokens": 1, "output_tokens": 0}
        });
        assert!(serde_json::from_value::<SystemOneResponse>(raw).is_err());
    }
}
