//! Deterministic policy engine for `agentkeys.permission.check`.
//!
//! HARD INVARIANT: no LLM, no inference, no network call. The decision is
//! a pure function of `(actor, scope, params, policy_table)`. This is the
//! whole point of Act 2 of the three-act demo per
//! `agent-iam-strategy.md` §4.3 — "policy decides, not the LLM."
//!
//! v1 ships a built-in policy table sufficient for the demo:
//!   - `memory.read` / `memory.write` — accepted for every actor
//!   - `payment.spend` — accepted if `amount_rmb <= daily_cap`; denied
//!     otherwise with the reason string the storyboard quotes
//!   - everything else — denied by default (closed-world)
//!
//! Future work (M4): per-actor / per-vendor policy overrides, time-of-day
//! windows, multi-factor approval, ask-parent flow. The `Verdict::AskParent`
//! variant is present so callers can wire it up later without a wire-format
//! break.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept,
    Deny,
    AskParent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub scope: String,
    /// Machine-readable reason code — stable across versions, used by
    /// audit + parent UI.
    pub reason: String,
    /// Human-readable explanation. Phrasing is what shows up in the
    /// parent-control UI; treat as UX-facing.
    pub explanation: String,
}

pub struct PolicyEngine {
    pub daily_spend_cap_rmb: u64,
}

impl PolicyEngine {
    pub fn new(daily_spend_cap_rmb: u64) -> Self {
        Self {
            daily_spend_cap_rmb,
        }
    }

    /// Evaluate `(actor, scope, params)` against the built-in policy table.
    /// `actor` is currently unused but kept in the signature because the
    /// follow-up M4 work key the table on actor.
    pub fn evaluate(&self, _actor: &str, scope: &str, params: &Value) -> Decision {
        match scope {
            "memory.read" | "memory.write" => Decision {
                verdict: Verdict::Accept,
                scope: scope.to_string(),
                reason: "default_allow_memory".into(),
                explanation: "memory access is allowed for the calling actor".into(),
            },
            "payment.spend" => self.evaluate_payment(scope, params),
            _ => Decision {
                verdict: Verdict::Deny,
                scope: scope.to_string(),
                reason: "scope_not_in_policy_table".into(),
                explanation: format!(
                    "scope `{scope}` is not in the policy table (closed-world default deny)"
                ),
            },
        }
    }

    fn evaluate_payment(&self, scope: &str, params: &Value) -> Decision {
        // Accept either `amount_rmb` (used in the demo storyboard) or
        // `amount` for forward-compat.
        let amount = params
            .get("amount_rmb")
            .or_else(|| params.get("amount"))
            .and_then(|v| v.as_u64());

        let Some(amount) = amount else {
            return Decision {
                verdict: Verdict::Deny,
                scope: scope.to_string(),
                reason: "missing_amount".into(),
                explanation: "payment.spend requires `amount_rmb` in params".into(),
            };
        };

        if amount > self.daily_spend_cap_rmb {
            return Decision {
                verdict: Verdict::Deny,
                scope: scope.to_string(),
                reason: "daily_spend_cap_exceeded".into(),
                explanation: format!(
                    "cap={}, requested={}, period=daily",
                    self.daily_spend_cap_rmb, amount
                ),
            };
        }

        Decision {
            verdict: Verdict::Accept,
            scope: scope.to_string(),
            reason: "within_daily_cap".into(),
            explanation: format!("amount {amount} ≤ daily cap {}", self.daily_spend_cap_rmb),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine() -> PolicyEngine {
        PolicyEngine::new(500)
    }

    #[test]
    fn memory_read_accept() {
        let d = engine().evaluate("O_a", "memory.read", &json!({}));
        assert_eq!(d.verdict, Verdict::Accept);
    }

    #[test]
    fn payment_within_cap_accept() {
        let d = engine().evaluate("O_a", "payment.spend", &json!({"amount_rmb": 200}));
        assert_eq!(d.verdict, Verdict::Accept);
    }

    #[test]
    fn payment_over_cap_denied_with_reason() {
        let d = engine().evaluate("O_a", "payment.spend", &json!({"amount_rmb": 600}));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.reason, "daily_spend_cap_exceeded");
        // Storyboard Act 2 quotes the cap/requested/period explanation.
        assert!(d.explanation.contains("cap=500"));
        assert!(d.explanation.contains("requested=600"));
    }

    #[test]
    fn payment_missing_amount_denied() {
        let d = engine().evaluate("O_a", "payment.spend", &json!({}));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.reason, "missing_amount");
    }

    #[test]
    fn unknown_scope_denied_closed_world() {
        let d = engine().evaluate("O_a", "nuke.launch", &json!({}));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.reason, "scope_not_in_policy_table");
    }
}
