//! `agentkeys hook ...` — runtime lifecycle hook helpers.
//!
//! Invoked BY the hook scripts that `agentkeys wire` drops into a Task
//! Host's config (Hermes `~/.hermes/config.yaml`, Claude Code
//! `~/.claude/settings.json`, Codex `~/.codex/hooks.json`, …). Each
//! subcommand:
//!   1. reads the host's JSON hook payload from stdin,
//!   2. calls an AgentKeys MCP tool over HTTP (`tools/call`),
//!   3. writes the host's expected JSON decision to stdout.
//!
//! Wire protocol (Hermes / Claude-Code compatible — see
//! `docs/wiki/agent-iam-guarantee-glossary.md` §3 + the plan
//! `docs/plan/phase-1-fresh-user-wire-onboarding.md` §5.2):
//!
//! ```text
//! stdin:  {hook_event_name, tool_name, tool_input, session_id, cwd, extra}
//! stdout block:    {"decision":"block","reason":"..."}
//! stdout context:  {"context":"..."}
//! stdout no-op:    {}
//! ```
//!
//! The three guarantees these deliver (issue #133):
//!   - `check`         → PreToolUse permission gate (fails CLOSED)
//!   - `audit`         → PostToolUse audit append (never blocks)
//!   - `memory-inject` → pre_llm_call context injection (never blocks)

use std::io::{IsTerminal, Read};

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Connection + identity config for talking to the AgentKeys MCP server.
///
/// All four fields are baked into the wire-generated hook scripts at
/// `agentkeys wire` time, so the hook invocation stays a single `exec`
/// line. Flags override env; env overrides built-in demo defaults.
pub struct HookClient {
    mcp_url: String,
    vendor_token: String,
    actor: String,
    operator: String,
    /// Operator/agent session JWT forwarded to the MCP server as
    /// `X-AgentKeys-Session-Bearer`, which the http backend relays to the
    /// broker's cap-mint as `Authorization: Bearer` (arch.md §22b.4 —
    /// "cap-mint daemon→broker auth: session JWT only"). Empty in the
    /// in-memory backend (ignored there). Env-only (`AGENTKEYS_SESSION_BEARER`)
    /// — `agentkeys wire` bakes it into the generated hook scripts.
    session_bearer: String,
    http: reqwest::Client,
}

impl HookClient {
    pub fn resolve(
        mcp_url: Option<String>,
        vendor_token: Option<String>,
        actor: Option<String>,
        operator: Option<String>,
    ) -> Self {
        let mcp_url = mcp_url
            .or_else(|| std::env::var("AGENTKEYS_MCP_URL").ok())
            .unwrap_or_else(|| "http://localhost:8088/mcp".to_string());
        let vendor_token = vendor_token
            .or_else(|| std::env::var("AGENTKEYS_MCP_VENDOR_TOKEN").ok())
            .unwrap_or_else(|| "demo-tok".to_string());
        let actor = actor
            .or_else(|| std::env::var("AGENTKEYS_ACTOR_OMNI").ok())
            .unwrap_or_default();
        let operator = operator
            .or_else(|| std::env::var("AGENTKEYS_OPERATOR_OMNI").ok())
            .unwrap_or_default();
        let session_bearer = std::env::var("AGENTKEYS_SESSION_BEARER").unwrap_or_default();
        Self {
            mcp_url,
            vendor_token,
            actor,
            operator,
            session_bearer,
            http: reqwest::Client::new(),
        }
    }

    /// Call an MCP tool over HTTP, return the tool's `structuredContent`.
    async fn call_tool(&self, tool: &str, arguments: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
        });
        let mut req = self
            .http
            .post(&self.mcp_url)
            .header("authorization", format!("Bearer {}", self.vendor_token))
            .json(&body);
        if !self.actor.is_empty() {
            req = req.header("x-agentkeys-actor", &self.actor);
        }
        if !self.session_bearer.is_empty() {
            req = req.header("x-agentkeys-session-bearer", &self.session_bearer);
        }
        let resp = req.send().await.context("POST /mcp")?;
        let status = resp.status();
        let parsed: Value = resp.json().await.context("parse MCP JSON-RPC response")?;
        if let Some(err) = parsed.get("error") {
            anyhow::bail!("MCP error (http {status}): {err}");
        }
        parsed
            .get("result")
            .and_then(|r| r.get("structuredContent"))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("MCP response missing result.structuredContent"))
    }
}

fn read_stdin_payload() -> Value {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    serde_json::from_str(&buf).unwrap_or_else(|_| json!({}))
}

fn emit(value: Value) {
    println!("{value}");
}

/// Map a `permission.check` Decision to the host's hook-output JSON.
/// Pure function — unit-tested without a server.
pub fn decision_to_hook_output(decision: &Value) -> Value {
    let verdict = decision
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("deny");
    if verdict == "accept" {
        json!({})
    } else {
        let reason = decision
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("denied");
        let explanation = decision
            .get("explanation")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let msg = if explanation.is_empty() {
            reason.to_string()
        } else {
            format!("{reason}: {explanation}")
        };
        json!({"decision": "block", "reason": msg})
    }
}

/// `agentkeys hook check --scope <scope>` — PreToolUse permission gate.
///
/// Reads the host payload, extracts the tool_input as the policy params,
/// calls `agentkeys.permission.check(scope, params)`, and blocks the
/// tool call when the verdict is not `accept`. **Fails CLOSED**: if the
/// MCP server is unreachable, the tool call is blocked (this matcher is
/// only wired to high-risk tools, so failing closed is correct).
pub async fn check(
    scope: &str,
    mcp_url: Option<String>,
    vendor_token: Option<String>,
    actor: Option<String>,
    operator: Option<String>,
) -> Result<String> {
    let payload = read_stdin_payload();
    let params = payload
        .get("tool_input")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let client = HookClient::resolve(mcp_url, vendor_token, actor, operator);

    let mut args = json!({"scope": scope, "params": params});
    if !client.actor.is_empty() {
        args["actor"] = json!(client.actor);
    }

    match client.call_tool("agentkeys.permission.check", args).await {
        Ok(decision) => emit(decision_to_hook_output(&decision)),
        Err(e) => {
            eprintln!("[agentkeys hook check] MCP unreachable — failing CLOSED: {e}");
            emit(json!({
                "decision": "block",
                "reason": format!("agentkeys_unreachable: {e}")
            }));
        }
    }
    Ok(String::new())
}

/// `agentkeys hook audit` — PostToolUse audit append. Never blocks; on
/// error it logs to stderr and emits `{}` so the agent loop continues.
pub async fn audit(
    mcp_url: Option<String>,
    vendor_token: Option<String>,
    actor: Option<String>,
    operator: Option<String>,
) -> Result<String> {
    let payload = read_stdin_payload();
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let tool_input = payload
        .get("tool_input")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let client = HookClient::resolve(mcp_url, vendor_token, actor, operator);

    // op_kind 1 = generic tool-use (placeholder; the audit envelope's
    // op_kind taxonomy is owned by arch.md §15.3a). op_body carries the
    // tool name + input so the off-chain feed shows what ran.
    let event = json!({
        "operator_omni": client.operator,
        "op_kind": 1,
        "result": 0,
        "op_body": {"tool_name": tool_name, "tool_input": tool_input},
    });
    let args = json!({"actor": client.actor, "event": event});

    if let Err(e) = client.call_tool("agentkeys.audit.append", args).await {
        eprintln!("[agentkeys hook audit] audit append failed (non-fatal): {e}");
    }
    emit(json!({}));
    Ok(String::new())
}

/// `agentkeys hook memory-inject --namespaces <ns,ns>` — pre_llm_call
/// context injection. Pulls the named memory namespaces via
/// `agentkeys.memory.get`, base64-decodes them, and returns a `{context}`
/// blob the host prepends to the next LLM turn. Never blocks; a namespace
/// that errors is skipped.
pub async fn memory_inject(
    namespaces: &str,
    mcp_url: Option<String>,
    vendor_token: Option<String>,
    actor: Option<String>,
    operator: Option<String>,
) -> Result<String> {
    let client = HookClient::resolve(mcp_url, vendor_token, actor, operator);

    // Pluggable engine seam (plan §6a): the gate already authorized these bytes;
    // the engine — caller-side, no LLM in the gate — selects which lines to
    // inject within a budget. Default `passthrough` + unbounded budget injects
    // the whole namespace unchanged.
    let budget = agentkeys_memory_engine::SelectionBudget::from_env();
    let engine_name = std::env::var("AGENTKEYS_MEMORY_ENGINE").unwrap_or_default();

    // OpenViking (plan §6a, model B) is query-driven, so it only engages when a
    // query is present. We read the current turn from the host payload ONLY in
    // openviking mode, and ONLY when stdin is piped (the `is_terminal()` guard
    // means a direct interactive call can never hang — the historical no-stdin
    // rule for the default engines is preserved). When OpenViking is
    // unconfigured / has no query / errors, we fall back to a deterministic
    // engine, so OpenViking is never load-bearing for availability.
    let openviking = if engine_name.trim().eq_ignore_ascii_case("openviking") {
        agentkeys_memory_openviking::OpenVikingClient::from_env()
    } else {
        None
    };
    let query = if openviking.is_some() {
        read_turn_query()
    } else {
        None
    };
    let fallback_engine: Box<dyn agentkeys_memory_engine::MemoryEngine> = if openviking.is_some() {
        Box::new(agentkeys_memory_engine::LexicalEngine)
    } else {
        agentkeys_memory_engine::engine_from_env()
    };

    let mut chunks = Vec::new();
    for ns in namespaces
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        match client
            .call_tool("agentkeys.memory.get", json!({"namespace": ns}))
            .await
        {
            Ok(result) => {
                if let Some(raw) = extract_memory_content(&result) {
                    // #201 Phase 4: the master's blobs are now per-namespace JSON
                    // arrays; render them to injectable text (single-body blobs
                    // pass through unchanged, so the wire demo still injects).
                    let text = render_memory_blob(&raw);
                    let selected = match (&openviking, &query) {
                        (Some(ov), Some(q)) => {
                            let lines = agentkeys_memory_engine::MemoryLine::from_blob(&text);
                            match agentkeys_memory_openviking::rank_gate_bounded(
                                ov, q, &lines, &budget,
                            )
                            .await
                            {
                                Some(ranked) => ranked
                                    .into_iter()
                                    .map(|l| l.text)
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                                None => agentkeys_memory_engine::select_blob(
                                    fallback_engine.as_ref(),
                                    query.as_deref(),
                                    &text,
                                    &budget,
                                ),
                            }
                        }
                        _ => agentkeys_memory_engine::select_blob(
                            fallback_engine.as_ref(),
                            query.as_deref(),
                            &text,
                            &budget,
                        ),
                    };
                    if !selected.is_empty() {
                        chunks.push(format!("## Memory: {ns}\n{selected}"));
                    }
                }
            }
            Err(e) => {
                eprintln!("[agentkeys hook memory-inject] memory.get({ns}) failed (skipping): {e}");
            }
        }
    }

    if chunks.is_empty() {
        emit(json!({}));
    } else {
        emit(json!({"context": chunks.join("\n\n")}));
    }
    Ok(String::new())
}

/// `agentkeys memory put --namespace <ns> --content <text>` — write a memory
/// entry via `agentkeys.memory.put`. Used to SEED a namespace (e.g. the demo
/// travel/Chengdu fixture) in the REAL memory worker; the in-memory backend
/// auto-seeds the fixture, so this is only needed for `--real`. Identity
/// (actor / operator / device_key_hash) defaults from the MCP server's
/// configured defaults; the actor header is sent when known. Unlike the hook
/// helpers this surfaces errors (returns Err) so a failed seed is loud.
pub async fn memory_put(
    namespace: &str,
    content: &str,
    mcp_url: Option<String>,
    vendor_token: Option<String>,
    actor: Option<String>,
    operator: Option<String>,
) -> Result<String> {
    let client = HookClient::resolve(mcp_url, vendor_token, actor, operator);
    let mut args = json!({"namespace": namespace, "content": content});
    if !client.actor.is_empty() {
        args["actor"] = json!(client.actor);
    }
    let result = client
        .call_tool("agentkeys.memory.put", args)
        .await
        .context("memory.put")?;
    Ok(result.to_string())
}

/// Extract the `content` field of an `agentkeys.memory.get` result. The
/// MCP tool layer already base64-decodes the worker's `plaintext_b64`
/// into a UTF-8 `content` string (see
/// `agentkeys-mcp-server/src/tools/memory.rs::get`), so the hook reads it
/// directly. Pure helper, unit-tested.
pub fn extract_memory_content(result: &Value) -> Option<String> {
    result
        .get("content")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Render a decrypted `memory:<ns>` blob into injectable text, tolerating BOTH
/// the per-namespace JSON array (#201 Phase 4 — the master plant writes
/// `[{key,title,body,updated,bytes}]`) and a legacy single-body blob (pre-#201
/// or agent-written). A JSON array is flattened to one `title: body` line per
/// entry; anything else passes through unchanged, so the wire demo's
/// single-body Chengdu memory still injects (plan §4 agent-read parity). Pure
/// helper, unit-tested.
pub fn render_memory_blob(content: &str) -> String {
    if content.trim_start().starts_with('[') {
        if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(content) {
            let lines: Vec<String> = items
                .iter()
                .filter_map(|it| {
                    let body = it.get("body").and_then(|v| v.as_str()).unwrap_or("");
                    if body.trim().is_empty() {
                        return None;
                    }
                    let title = it.get("title").and_then(|v| v.as_str()).unwrap_or("");
                    Some(if title.trim().is_empty() {
                        body.to_string()
                    } else {
                        format!("{title}: {body}")
                    })
                })
                .collect();
            if !lines.is_empty() {
                return lines.join("\n");
            }
        }
    }
    content.to_string()
}

/// Read the current user turn from the host hook payload (stdin) for use as the
/// OpenViking search query. Guarded by `is_terminal()` so a direct interactive
/// call can never block on an open stdin — this only runs in openviking mode;
/// the default engines never read stdin. Returns None when stdin is a TTY,
/// empty, or carries no recognizable query field.
fn read_turn_query() -> Option<String> {
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() || buf.trim().is_empty() {
        return None;
    }
    let payload: Value = serde_json::from_str(&buf).ok()?;
    extract_query(&payload)
}

/// Pull the user's latest message from a host hook payload. Hermes'
/// `pre_llm_call` payload shape is not pinned, so we try several common field
/// names and a `messages: [{role, content}]` array (last user turn). Pure
/// helper, unit-tested.
pub fn extract_query(payload: &Value) -> Option<String> {
    for key in ["query", "prompt", "input", "user_message", "text"] {
        if let Some(s) = payload.get(key).and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                return Some(s.trim().to_string());
            }
        }
    }
    if let Some(messages) = payload.get("messages").and_then(|v| v.as_array()) {
        for message in messages.iter().rev() {
            let role = message.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role == "user" || role.is_empty() {
                if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
                    if !content.trim().is_empty() {
                        return Some(content.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_verdict_emits_empty_object() {
        let decision = json!({"verdict": "accept", "scope": "memory.read", "reason": "ok"});
        assert_eq!(decision_to_hook_output(&decision), json!({}));
    }

    #[test]
    fn deny_verdict_emits_block_with_reason_and_explanation() {
        let decision = json!({
            "verdict": "deny",
            "scope": "payment.spend",
            "reason": "daily_spend_cap_exceeded",
            "explanation": "cap=500, requested=600, period=daily"
        });
        let out = decision_to_hook_output(&decision);
        assert_eq!(out["decision"], "block");
        assert_eq!(
            out["reason"],
            "daily_spend_cap_exceeded: cap=500, requested=600, period=daily"
        );
    }

    #[test]
    fn ask_parent_verdict_blocks() {
        let decision = json!({"verdict": "ask_parent", "reason": "needs_approval"});
        let out = decision_to_hook_output(&decision);
        assert_eq!(out["decision"], "block");
        assert_eq!(out["reason"], "needs_approval");
    }

    #[test]
    fn missing_verdict_defaults_to_block() {
        let out = decision_to_hook_output(&json!({}));
        assert_eq!(out["decision"], "block");
    }

    #[test]
    fn extract_memory_content_reads_content_field() {
        let result =
            json!({"ok": true, "content": "Chengdu trip — Apr 12 to 16", "namespace": "travel"});
        assert_eq!(
            extract_memory_content(&result).as_deref(),
            Some("Chengdu trip — Apr 12 to 16")
        );
    }

    #[test]
    fn extract_memory_content_missing_field_is_none() {
        assert_eq!(extract_memory_content(&json!({"ok": true})), None);
    }

    #[test]
    fn render_memory_blob_passes_through_single_body() {
        // The wire demo seeds a single-body blob; it must inject unchanged.
        let raw = "Chengdu trip — Apr 12 to 16, hotpot at Yulin.";
        assert_eq!(render_memory_blob(raw), raw);
    }

    #[test]
    fn render_memory_blob_flattens_json_array() {
        // #201 Phase 4: a per-namespace JSON array renders one title: body line each.
        let raw = r#"[
            {"key":"chengdu-trip","title":"Chengdu trip","body":"Apr 12 to 16","updated":"2026-04-02","bytes":9},
            {"key":"customs","title":"","body":"customs note","updated":"2026-04-02","bytes":12}
        ]"#;
        assert_eq!(
            render_memory_blob(raw),
            "Chengdu trip: Apr 12 to 16\ncustoms note"
        );
    }

    #[test]
    fn render_memory_blob_non_entry_array_falls_back_to_raw() {
        // A JSON array that isn't memory entries (no `body`) passes through as-is
        // rather than rendering empty — never silently drop content.
        let raw = r#"["a","b"]"#;
        assert_eq!(render_memory_blob(raw), raw);
    }

    #[test]
    fn extract_query_tries_common_fields_and_messages() {
        assert_eq!(
            extract_query(&json!({"query": "where did I go"})).as_deref(),
            Some("where did I go")
        );
        assert_eq!(
            extract_query(&json!({"prompt": "recall the trip"})).as_deref(),
            Some("recall the trip")
        );
        assert_eq!(
            extract_query(&json!({"messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"},
                {"role": "user", "content": "what about Chengdu?"}
            ]}))
            .as_deref(),
            Some("what about Chengdu?")
        );
        // a bare pre_llm_call payload (the demo's default) carries no query
        assert_eq!(
            extract_query(&json!({"hook_event_name": "pre_llm_call"})),
            None
        );
    }
}
