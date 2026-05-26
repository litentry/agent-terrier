//! Server — owns shared state and dispatches MCP method calls.
//!
//! The server holds:
//!   - `Config` (immutable)
//!   - `Backend` trait object (HTTP impl in prod, mock in tests)
//!   - `PolicyEngine` for `permission.check`
//!
//! Every request flows through `dispatch`, which:
//!   1. Parses the JSON-RPC envelope
//!   2. Routes by method name (`initialize`, `tools/list`, `tools/call`, `ping`)
//!   3. For `tools/call`: routes again by tool name to the right handler
//!   4. Wraps the handler's `McpResult<Value>` into the MCP response envelope
//!
//! The HTTP transport handles auth headers before calling `dispatch`. The
//! stdio transport calls `dispatch` directly with a `local_stdio` caller.

use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::CallerContext;
use crate::backend::Backend;
use crate::config::Config;
use crate::errors::{McpError, McpResult};
use crate::mcp::{
    self, codes, Request, Response, ToolDescriptor, MCP_PROTOCOL_VERSION, MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
};
use crate::policy::PolicyEngine;
use crate::tools;

pub struct Server {
    pub config: Config,
    pub backend: Arc<dyn Backend>,
    pub policy: PolicyEngine,
}

impl Server {
    pub fn new(config: Config, backend: Arc<dyn Backend>) -> Self {
        let policy = PolicyEngine::new(config.default_daily_spend_cap_rmb);
        Self {
            config,
            backend,
            policy,
        }
    }

    /// Entry point for both transports. Caller has already been auth'd at
    /// the transport layer; pass `CallerContext::local_stdio()` for stdio.
    /// `session_bearer` is forwarded to broker cap-mint as `Authorization`;
    /// in stdio mode it's typically empty.
    pub async fn dispatch(
        &self,
        caller: &CallerContext,
        session_bearer: &str,
        req: Request,
    ) -> Response {
        if req.jsonrpc != mcp::JSONRPC_VERSION {
            return Response::error(
                req.id.clone(),
                codes::INVALID_REQUEST,
                format!("unsupported jsonrpc version `{}`", req.jsonrpc),
            );
        }

        let id = req.id.clone();

        match req.method.as_str() {
            "initialize" => self.handle_initialize(id, req.params),
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => {
                self.handle_tools_call(caller, session_bearer, id, req.params)
                    .await
            }
            "ping" => Response::success(id, json!({})),
            other => Response::error(
                id,
                codes::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            ),
        }
    }

    fn handle_initialize(&self, id: Option<Value>, params: Option<Value>) -> Response {
        // Negotiate protocol version: echo the client's `protocolVersion`
        // when present and recognizable, fall back to our own. Xiaozhi's
        // hosted relay sends "2024-11-05"; if we respond with a different
        // (newer) string, it closes the WS immediately as an unsupported-
        // version signal.
        const KNOWN_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26"];
        let negotiated_version = params
            .as_ref()
            .and_then(|p| p.get("protocolVersion"))
            .and_then(|v| v.as_str())
            .filter(|v| KNOWN_VERSIONS.contains(v))
            .unwrap_or(MCP_PROTOCOL_VERSION);

        Response::success(
            id,
            json!({
                "protocolVersion": negotiated_version,
                "capabilities": {
                    "tools": {"listChanged": false}
                },
                "serverInfo": {
                    "name": MCP_SERVER_NAME,
                    "version": MCP_SERVER_VERSION
                }
            }),
        )
    }

    fn handle_tools_list(&self, id: Option<Value>) -> Response {
        let tools: Vec<ToolDescriptor> = tools::all_descriptors();
        Response::success(id, json!({"tools": tools}))
    }

    async fn handle_tools_call(
        &self,
        caller: &CallerContext,
        session_bearer: &str,
        id: Option<Value>,
        params: Option<Value>,
    ) -> Response {
        let params = match params {
            Some(p) => p,
            None => {
                return McpError::InvalidParams("tools/call requires params".into())
                    .into_response(id)
            }
        };

        let name = match params.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return McpError::InvalidParams("tools/call missing `name`".into())
                    .into_response(id)
            }
        };

        let empty = json!({});
        let args = params.get("arguments").unwrap_or(&empty).clone();

        let result: McpResult<Value> = match name.as_str() {
            tools::TOOL_IDENTITY_WHOAMI => tools::identity::call(caller, &self.config, &args),
            tools::TOOL_PERMISSION_CHECK => {
                tools::permission::call(caller, &self.policy, &self.config, &args)
            }
            tools::TOOL_CAP_MINT => {
                tools::cap::mint(
                    caller,
                    self.backend.clone(),
                    &self.config,
                    session_bearer,
                    &args,
                )
                .await
            }
            tools::TOOL_CAP_REVOKE => tools::cap::revoke(self.backend.clone(), &args).await,
            tools::TOOL_MEMORY_PUT => {
                tools::memory::put(
                    caller,
                    self.backend.clone(),
                    &self.config,
                    session_bearer,
                    &args,
                )
                .await
            }
            tools::TOOL_MEMORY_GET => {
                tools::memory::get(
                    caller,
                    self.backend.clone(),
                    &self.config,
                    session_bearer,
                    &args,
                )
                .await
            }
            tools::TOOL_AUDIT_APPEND => {
                tools::audit::call(caller, self.backend.clone(), &args).await
            }
            tools::TOOL_DELEGATION_GRANT
            | tools::TOOL_DELEGATION_REVOKE
            | tools::TOOL_APPROVAL_REQUEST => Err(tools::stubs::not_implemented_v1()),
            other => Err(McpError::ToolNotFound(other.to_string())),
        };

        match result {
            Ok(value) => Response::success(
                id,
                json!({
                    "content": [
                        {"type": "text", "text": value.to_string()}
                    ],
                    "structuredContent": value,
                    "isError": false
                }),
            ),
            Err(e) => e.into_response(id),
        }
    }
}
