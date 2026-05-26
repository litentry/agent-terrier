//! `agentkeys.cap.mint` + `agentkeys.cap.revoke` — broker adapter.

use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::CallerContext;
use crate::backend::{Backend, CapMintOp, CapMintRequest};
use crate::config::Config;
use crate::errors::{McpError, McpResult};

const DEFAULT_TTL_SECONDS: u64 = 300;

pub async fn mint(
    caller: &CallerContext,
    backend: Arc<dyn Backend>,
    config: &Config,
    session_bearer: &str,
    params: &Value,
) -> McpResult<Value> {
    let actor = params
        .get("actor")
        .and_then(|v| v.as_str())
        .or(config.default_actor.as_deref())
        .ok_or_else(|| {
            McpError::InvalidParams("missing `actor` and no MCP_DEFAULT_ACTOR set".into())
        })?;

    let op_str = params
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `op`".into()))?;
    let op = CapMintOp::parse(op_str)
        .ok_or_else(|| McpError::InvalidParams(format!("unknown op `{op_str}`")))?;

    let empty = json!({});
    let inner = params.get("params").unwrap_or(&empty);

    let operator_omni = inner
        .get("operator_omni")
        .and_then(|v| v.as_str())
        .or(config.default_operator_omni.as_deref())
        .ok_or_else(|| {
            McpError::InvalidParams(
                "missing `params.operator_omni` and no MCP_DEFAULT_OPERATOR_OMNI set".into(),
            )
        })?
        .to_string();
    let service = inner
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or(op.data_class())
        .to_string();
    let device_key_hash = inner
        .get("device_key_hash")
        .and_then(|v| v.as_str())
        .or(config.default_device_key_hash.as_deref())
        .ok_or_else(|| {
            McpError::InvalidParams(
                "missing `params.device_key_hash` and no MCP_DEFAULT_DEVICE_KEY_HASH set".into(),
            )
        })?
        .to_string();

    let ttl_seconds = params
        .get("ttl")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TTL_SECONDS);

    if caller.actor_omni != "*" {
        crate::auth::check_actor_param(&caller.actor_omni, actor)?;
    }

    let req = CapMintRequest {
        operator_omni,
        actor_omni: actor.to_string(),
        service,
        device_key_hash,
        ttl_seconds,
    };

    let cap = backend
        .cap_mint(op, req, session_bearer)
        .await
        .map_err(|e| McpError::Backend(e.to_string()))?;

    Ok(json!({
        "ok": true,
        "op": op_str,
        "data_class": op.data_class(),
        "cap": cap,
        "ttl_seconds": ttl_seconds,
    }))
}

pub async fn revoke(backend: Arc<dyn Backend>, params: &Value) -> McpResult<Value> {
    let cap_id = params
        .get("cap_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `cap_id`".into()))?;

    let result = backend
        .cap_revoke(cap_id)
        .await
        .map_err(|e| McpError::Backend(e.to_string()))?;

    Ok(serde_json::to_value(result).unwrap_or(json!({"ok": false})))
}
