//! `agentkeys.memory.get` + `agentkeys.memory.put` — namespace-scoped
//! memory access. Internally: mint a cap → call the memory worker.
//!
//! Per Phase 1 namespace scope (issue #108 partial): the namespace is
//! a request-body field, not yet a signed CapPayload field. M4 follow-up
//! lifts it into the cap so the worker can enforce cryptographically.

use base64::Engine;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::CallerContext;
use crate::backend::{Backend, CapMintOp, CapMintRequest, MemoryGetInput, MemoryPutInput};
use crate::config::Config;
use crate::errors::{McpError, McpResult};

const DEFAULT_TTL_SECONDS: u64 = 300;

/// Resolve an identity field — LLM-supplied param wins, else config default,
/// else a precise error so the operator can fix the env.
fn resolve_ident<'a>(
    params: &'a Value,
    key: &str,
    fallback: Option<&'a str>,
) -> McpResult<&'a str> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .or(fallback)
        .ok_or_else(|| {
            McpError::InvalidParams(format!(
                "missing `{key}` and no MCP_DEFAULT_{} configured \
                 — set it in /etc/agentkeys/mcp.env or pass via --{}",
                key.to_uppercase(),
                key.replace('_', "-")
            ))
        })
}

pub async fn put(
    caller: &CallerContext,
    backend: Arc<dyn Backend>,
    config: &Config,
    session_bearer: &str,
    params: &Value,
) -> McpResult<Value> {
    let actor = resolve_ident(params, "actor", config.default_actor.as_deref())?;
    let namespace = params
        .get("namespace")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `namespace`".into()))?;
    let content = params
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `content`".into()))?;
    let operator_omni = resolve_ident(
        params,
        "operator_omni",
        config.default_operator_omni.as_deref(),
    )?;
    let device_key_hash = resolve_ident(
        params,
        "device_key_hash",
        config.default_device_key_hash.as_deref(),
    )?;
    // Issue #147 (approach B): fold the namespace into the SIGNED `service`,
    // so the cap is cryptographically bound to exactly one namespace and
    // authorized via the existing on-chain `isServiceInScope` check. A
    // `memory:travel` cap cannot touch `memory:personal` — different service
    // ⇒ different scope entry, different S3 key, different AAD. No CapPayload
    // change, no broker change: the broker already signs whatever `service`
    // it's given and the worker already keys storage + scope + AAD off it.
    let service = format!("memory:{namespace}");
    let ttl_seconds = params
        .get("ttl_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TTL_SECONDS);

    if caller.actor_omni != "*" {
        crate::auth::check_actor_param(&caller.actor_omni, actor)?;
    }

    let cap_req = CapMintRequest {
        operator_omni: operator_omni.to_string(),
        actor_omni: actor.to_string(),
        service,
        device_key_hash: device_key_hash.to_string(),
        ttl_seconds,
    };
    let cap = backend
        .cap_mint(CapMintOp::MemoryPut, cap_req, session_bearer)
        .await
        .map_err(|e| McpError::Backend(format!("cap_mint failed: {e}")))?;

    let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());

    let result = backend
        .memory_put(MemoryPutInput {
            cap,
            namespace: namespace.to_string(),
            plaintext_b64,
        })
        .await
        .map_err(|e| McpError::Backend(format!("memory_put failed: {e}")))?;

    // Audit trail: every memory write is logged (actor + namespace + size).
    tracing::info!(
        op = "memory.put",
        actor = %actor,
        namespace = %namespace,
        bytes = content.len(),
        s3_key = %result.s3_key,
        "memory write"
    );

    Ok(json!({
        "ok": result.ok,
        "namespace": result.namespace,
        "s3_key": result.s3_key,
        "envelope_size": result.envelope_size,
    }))
}

pub async fn get(
    caller: &CallerContext,
    backend: Arc<dyn Backend>,
    config: &Config,
    session_bearer: &str,
    params: &Value,
) -> McpResult<Value> {
    let actor = resolve_ident(params, "actor", config.default_actor.as_deref())?;
    let namespace = params
        .get("namespace")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing `namespace`".into()))?;
    let operator_omni = resolve_ident(
        params,
        "operator_omni",
        config.default_operator_omni.as_deref(),
    )?;
    let device_key_hash = resolve_ident(
        params,
        "device_key_hash",
        config.default_device_key_hash.as_deref(),
    )?;
    // Issue #147 (approach B): fold the namespace into the SIGNED `service`,
    // so the cap is cryptographically bound to exactly one namespace and
    // authorized via the existing on-chain `isServiceInScope` check. A
    // `memory:travel` cap cannot touch `memory:personal` — different service
    // ⇒ different scope entry, different S3 key, different AAD. No CapPayload
    // change, no broker change: the broker already signs whatever `service`
    // it's given and the worker already keys storage + scope + AAD off it.
    let service = format!("memory:{namespace}");
    let ttl_seconds = params
        .get("ttl_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TTL_SECONDS);

    if caller.actor_omni != "*" {
        crate::auth::check_actor_param(&caller.actor_omni, actor)?;
    }

    let cap_req = CapMintRequest {
        operator_omni: operator_omni.to_string(),
        actor_omni: actor.to_string(),
        service,
        device_key_hash: device_key_hash.to_string(),
        ttl_seconds,
    };
    let cap = backend
        .cap_mint(CapMintOp::MemoryGet, cap_req, session_bearer)
        .await
        .map_err(|e| McpError::Backend(format!("cap_mint failed: {e}")))?;

    let result = backend
        .memory_get(MemoryGetInput {
            cap,
            namespace: namespace.to_string(),
        })
        .await
        .map_err(|e| McpError::Backend(format!("memory_get failed: {e}")))?;

    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(&result.plaintext_b64)
        .map_err(|e| McpError::Internal(format!("plaintext_b64 decode: {e}")))?;
    let content = String::from_utf8(plaintext)
        .map_err(|e| McpError::Internal(format!("plaintext utf8: {e}")))?;

    // Audit trail: every memory read is logged (actor + namespace + size).
    tracing::info!(
        op = "memory.get",
        actor = %actor,
        namespace = %namespace,
        bytes = content.len(),
        "memory read"
    );

    Ok(json!({
        "ok": result.ok,
        "namespace": result.namespace,
        "content": content,
    }))
}
