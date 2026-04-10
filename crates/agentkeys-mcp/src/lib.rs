use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_types::{AuditFilter, ServiceName, Session, WalletAddress};
use serde_json::{json, Value};
use std::sync::Arc;

pub mod server;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), result: Some(result), error: None, id }
    }

    pub fn error(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
            id,
        }
    }
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "agentkeys.get_credential",
            "description": "Fetch a stored credential for the given service. Returns the credential string.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "The service name (e.g. 'openrouter', 'anthropic')"
                    }
                },
                "required": ["service"]
            }
        },
        {
            "name": "agentkeys.list_credentials",
            "description": "List service names available to this agent.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }
    ])
}

pub struct McpHandler {
    backend: Arc<dyn CredentialBackend>,
    session: Session,
    agent_id: WalletAddress,
}

impl McpHandler {
    pub fn new(
        backend: Arc<dyn CredentialBackend>,
        session: Session,
        agent_id: WalletAddress,
    ) -> Self {
        Self { backend, session, agent_id }
    }

    pub async fn handle(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();
        match request.method.as_str() {
            "initialize" => JsonRpcResponse::success(
                id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "agentkeys-mcp",
                        "version": "0.1.0"
                    }
                }),
            ),
            "notifications/initialized" => {
                // Notification — no response needed but we return a dummy to simplify handler
                JsonRpcResponse::success(id, json!(null))
            }
            "tools/list" => JsonRpcResponse::success(id, json!({ "tools": tool_definitions() })),
            "tools/call" => self.handle_tool_call(id, request.params).await,
            _ => JsonRpcResponse::error(id, -32601, format!("method not found: {}", request.method)),
        }
    }

    async fn handle_tool_call(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => return JsonRpcResponse::error(id, -32602, "missing params"),
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => return JsonRpcResponse::error(id, -32602, "missing tool name"),
        };

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        match tool_name.as_str() {
            "agentkeys.get_credential" => self.get_credential(id, arguments).await,
            "agentkeys.list_credentials" => self.list_credentials(id).await,
            _ => JsonRpcResponse::error(id, -32601, format!("unknown tool: {tool_name}")),
        }
    }

    async fn get_credential(&self, id: Option<Value>, arguments: Value) -> JsonRpcResponse {
        let service_str = match arguments.get("service").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return JsonRpcResponse::error(id, -32602, "missing 'service' argument"),
        };

        let service = ServiceName(service_str);
        match self.backend.read_credential(&self.session, &self.agent_id, &service).await {
            Ok(bytes) => {
                let credential = String::from_utf8_lossy(&bytes).into_owned();
                JsonRpcResponse::success(
                    id,
                    json!({ "content": [{ "type": "text", "text": credential }] }),
                )
            }
            Err(BackendError::PermissionDenied(msg)) => {
                JsonRpcResponse::error(id, -32603, format!("DENIED: {msg}"))
            }
            Err(BackendError::AuthFailed(msg)) => {
                JsonRpcResponse::error(id, -32603, format!("DENIED: {msg}"))
            }
            Err(e) => JsonRpcResponse::error(id, -32603, e.to_string()),
        }
    }

    async fn list_credentials(&self, id: Option<Value>) -> JsonRpcResponse {
        let filter = AuditFilter {
            owner: None,
            agent: Some(self.agent_id.clone()),
            service: None,
        };

        match self.backend.query_audit(&self.session, filter).await {
            Ok(events) => {
                let mut services: Vec<String> = events
                    .into_iter()
                    .filter(|e| e.action == "store")
                    .map(|e| e.service.0)
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();
                services.sort();
                JsonRpcResponse::success(id, json!({ "services": services }))
            }
            Err(e) => JsonRpcResponse::error(id, -32603, e.to_string()),
        }
    }
}
