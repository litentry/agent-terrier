//! `agentkeys.audit.append` — adapter onto worker-audit /v1/audit/append/v2.
//!
//! The MCP wire shape is `(actor, event)`. We unpack the event into the
//! worker's `AppendV2Request` shape so audit envelopes coming from MCP
//! land in the same store as on-broker emissions.

use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::CallerContext;
use crate::backend::{AuditAppendInput, Backend};
use crate::errors::{McpError, McpResult};

pub async fn call(
    caller: &CallerContext,
    backend: Arc<dyn Backend>,
    params: &Value,
) -> McpResult<Value> {
    let actor = params
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `actor`".into()))?;

    let event = params
        .get("event")
        .ok_or_else(|| McpError::InvalidParams("missing `event`".into()))?;

    let operator_omni = event
        .get("operator_omni")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `event.operator_omni`".into()))?
        .to_string();
    let op_kind = event
        .get("op_kind")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| McpError::InvalidParams("missing `event.op_kind`".into()))?
        as u8;
    let result = event
        .get("result")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| McpError::InvalidParams("missing `event.result`".into()))?
        as u8;
    let op_body = event.get("op_body").cloned().unwrap_or_else(|| json!({}));
    let intent_text = event
        .get("intent_text")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if caller.actor_omni != "*" {
        crate::auth::check_actor_param(&caller.actor_omni, actor)?;
    }

    let appended = backend
        .audit_append(AuditAppendInput {
            operator_omni,
            actor_omni: actor.to_string(),
            op_kind,
            op_body,
            result,
            intent_text,
        })
        .await
        .map_err(|e| McpError::Backend(format!("audit_append failed: {e}")))?;

    Ok(json!({
        "ok": appended.ok,
        "envelope_hash": appended.envelope_hash,
    }))
}
