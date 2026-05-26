//! Error envelope shared across the MCP server.
//!
//! Tool errors surface to the LLM host as JSON-RPC error responses; this
//! module owns the conversion from internal `McpError` to the wire shape
//! so individual tool handlers can stay focused on their happy path.

use crate::mcp::{codes, Response};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("backend call failed: {0}")]
    Backend(String),

    #[error("not implemented in v1")]
    NotImplementedV1 {
        scheduled_for: &'static str,
        spec_url: &'static str,
    },

    #[error("internal error: {0}")]
    Internal(String),
}

impl McpError {
    pub fn into_response(self, id: Option<Value>) -> Response {
        match self {
            McpError::InvalidParams(msg) => Response::error(id, codes::INVALID_PARAMS, msg),
            McpError::ToolNotFound(name) => Response::error(
                id,
                codes::METHOD_NOT_FOUND,
                format!("tool not found: {name}"),
            ),
            McpError::Unauthorized(msg) => Response::error(id, codes::UNAUTHORIZED, msg),
            McpError::Forbidden(msg) => Response::error(id, codes::FORBIDDEN, msg),
            McpError::Backend(msg) => Response::error(id, codes::TOOL_ERROR, msg),
            McpError::Internal(msg) => Response::error(id, codes::INTERNAL_ERROR, msg),
            McpError::NotImplementedV1 {
                scheduled_for,
                spec_url,
            } => Response::error_with_data(
                id,
                codes::TOOL_ERROR,
                "not_implemented_in_v1",
                json!({
                    "error": "not_implemented_in_v1",
                    "scheduled_for": scheduled_for,
                    "spec_url": spec_url,
                }),
            ),
        }
    }
}

pub type McpResult<T> = Result<T, McpError>;
