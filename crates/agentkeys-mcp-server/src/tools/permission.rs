//! `agentkeys.permission.check` — deterministic verdict.
//!
//! The Act 2 storyboard hinges on this returning the right denial reason
//! for `payment.spend` over the daily cap. Implementation lives in
//! `crate::policy`; this file is the MCP wrapper.

use serde_json::{json, Value};

use crate::auth::CallerContext;
use crate::config::Config;
use crate::errors::{McpError, McpResult};
use crate::policy::PolicyEngine;

pub fn call(
    caller: &CallerContext,
    engine: &PolicyEngine,
    config: &Config,
    params: &Value,
) -> McpResult<Value> {
    let actor = params
        .get("actor")
        .and_then(|v| v.as_str())
        .or(config.default_actor.as_deref())
        .ok_or_else(|| {
            McpError::InvalidParams("missing `actor` and no MCP_DEFAULT_ACTOR set".into())
        })?;

    let scope = params
        .get("scope")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `scope`".into()))?;

    if caller.actor_omni != "*" {
        crate::auth::check_actor_param(&caller.actor_omni, actor)?;
    }

    let empty = json!({});
    let inner = params.get("params").unwrap_or(&empty);
    let decision = engine.evaluate(actor, scope, inner);
    Ok(serde_json::to_value(decision).unwrap_or(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> CallerContext {
        CallerContext::new("vendor-a", "O_kevin_001")
    }

    fn cfg() -> Config {
        Config::for_tests()
    }

    #[test]
    fn act2_payment_over_cap_denied() {
        let engine = PolicyEngine::new(500);
        let v = call(
            &caller(),
            &engine,
            &cfg(),
            &json!({
                "actor": "O_kevin_001",
                "scope": "payment.spend",
                "params": {"amount_rmb": 600}
            }),
        )
        .unwrap();
        assert_eq!(v["verdict"], "deny");
        assert_eq!(v["reason"], "daily_spend_cap_exceeded");
    }

    #[test]
    fn missing_scope_invalid_params() {
        let engine = PolicyEngine::new(500);
        let err = call(&caller(), &engine, &cfg(), &json!({"actor": "O_kevin_001"})).unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }
}
