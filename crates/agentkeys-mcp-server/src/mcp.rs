//! JSON-RPC 2.0 + MCP protocol envelopes.
//!
//! MCP layers a tiny set of methods on top of JSON-RPC 2.0:
//!  - `initialize` — handshake; client advertises capabilities, server replies.
//!  - `tools/list` — returns the JSON-Schema for every tool.
//!  - `tools/call` — invokes one tool by name with arguments.
//!  - `ping` — keep-alive.
//!
//! This module owns the wire types only. The dispatcher in `server` decides
//! what each method does.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";
pub const MCP_PROTOCOL_VERSION: &str = "2025-03-26";
pub const MCP_SERVER_NAME: &str = "agentkeys-mcp-server";
pub const MCP_SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Response {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    pub fn error_with_data(
        id: Option<Value>,
        code: i64,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
                data: Some(data),
            }),
            id,
        }
    }
}

/// JSON-RPC 2.0 standard error codes + MCP extensions.
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// MCP application-level: tool execution failed (vs protocol error).
    pub const TOOL_ERROR: i64 = -32000;
    /// MCP application-level: auth failed.
    pub const UNAUTHORIZED: i64 = -32001;
    /// MCP application-level: actor scope mismatch.
    pub const FORBIDDEN: i64 = -32003;
}

/// MCP tool descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}
