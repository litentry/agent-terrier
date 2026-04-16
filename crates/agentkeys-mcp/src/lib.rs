use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_provisioner::{run_provision, Provisioner};
use agentkeys_types::{AuditFilter, ServiceName, Session, WalletAddress};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
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
        },
        {
            "name": "agentkeys.provision",
            "description": "Provision (sign up and store) a new API key for a service. Runs the provisioner script and stores the result.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "The service to provision (e.g. 'openrouter')"
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Re-provision even if a credential already exists"
                    }
                },
                "required": ["service"]
            }
        }
    ])
}

pub struct McpHandler {
    backend: Arc<dyn CredentialBackend>,
    session: Session,
    agent_id: WalletAddress,
    provisioner: Arc<Provisioner>,
    repo_root: PathBuf,
}

impl McpHandler {
    pub fn new(
        backend: Arc<dyn CredentialBackend>,
        session: Session,
        agent_id: WalletAddress,
    ) -> Self {
        let repo_root = std::env::var("AGENTKEYS_REPO_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        Self {
            backend,
            session,
            agent_id,
            provisioner: Arc::new(Provisioner::new()),
            repo_root,
        }
    }

    pub fn new_with_provisioner(
        backend: Arc<dyn CredentialBackend>,
        session: Session,
        agent_id: WalletAddress,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        let repo_root = std::env::var("AGENTKEYS_REPO_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        Self { backend, session, agent_id, provisioner, repo_root }
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
            "agentkeys.provision" => self.provision_tool(id, arguments).await,
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

    async fn provision_tool(&self, id: Option<Value>, arguments: Value) -> JsonRpcResponse {
        let service = match arguments.get("service").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return JsonRpcResponse::error(id, -32602, "missing 'service' argument"),
        };
        let force = arguments.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

        let script_command: Vec<String> = match service.as_str() {
            "openrouter" => vec![
                "npx".to_string(),
                "tsx".to_string(),
                "provisioner-scripts/src/scrapers/openrouter.ts".to_string(),
            ],
            other => {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    json!({
                        "code": "SERVICE_NOT_SUPPORTED",
                        "message": format!("service '{}' not supported in Stage 5a", other)
                    })
                    .to_string(),
                );
            }
        };

        let cmd_refs: Vec<&str> = script_command.iter().map(|s| s.as_str()).collect();
        let cwd = self.repo_root.clone();

        let result = run_provision(
            &self.provisioner,
            &service,
            &cmd_refs,
            HashMap::new(),
            Some(&cwd),
            self.backend.clone(),
            &self.session,
            &self.agent_id,
            force,
        )
        .await;

        match result {
            Ok(success) => JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": json!({
                            "api_key_masked": success.obtained_key_masked,
                            "key_verified": success.key_verified,
                            "stored": success.stored,
                        }).to_string()
                    }]
                }),
            ),
            Err(e) => {
                let code = provision_error_to_mcp_code(&e);
                JsonRpcResponse::error(
                    id,
                    -32603,
                    json!({ "code": code, "message": e.to_string() }).to_string(),
                )
            }
        }
    }
}

fn provision_error_to_mcp_code(err: &agentkeys_provisioner::ProvisionError) -> &'static str {
    use agentkeys_provisioner::ProvisionError;
    match err {
        ProvisionError::InProgress { .. } => "PROVISION_IN_PROGRESS",
        ProvisionError::Tripwire { kind, .. } => {
            use agentkeys_types::TripwireKind;
            match kind {
                TripwireKind::SelectorTimeout => "TRIPWIRE_SELECTOR_TIMEOUT",
                TripwireKind::EmailTimeout => "EMAIL_TIMEOUT",
                TripwireKind::VerificationFailed => "VERIFICATION_FAILED",
                _ => "TRIPWIRE_SELECTOR_TIMEOUT",
            }
        }
        ProvisionError::StoreFailed { .. } => "PROVISION_STORE_FAILED",
        ProvisionError::VerificationFailed { .. } => "VERIFICATION_FAILED",
        _ => "PROVISION_ERROR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::backend::BackendError;
    use agentkeys_types::{
        AuditEvent, AuditFilter, AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes,
        EncryptedPairPayload, OpenedAuthRequest, PairCode, PairPayload, PublicKey,
        RegistrationToken, Scope, ServiceName, Session, SignedAuthDecision, WalletAddress,
    };
    use async_trait::async_trait;

    struct NoopBackend;

    #[async_trait]
    impl CredentialBackend for NoopBackend {
        async fn create_session(&self, _: agentkeys_types::AuthToken) -> Result<(Session, WalletAddress), BackendError> { unimplemented!() }
        async fn create_child_session(&self, _: &Session, _: Scope) -> Result<(Session, WalletAddress), BackendError> { unimplemented!() }
        async fn store_credential(&self, _: &Session, _: &WalletAddress, _: &ServiceName, _: &[u8]) -> Result<(), BackendError> { Ok(()) }
        async fn read_credential(&self, _: &Session, _: &WalletAddress, _: &ServiceName) -> Result<Vec<u8>, BackendError> { Err(BackendError::NotFound("none".into())) }
        async fn query_audit(&self, _: &Session, _: AuditFilter) -> Result<Vec<AuditEvent>, BackendError> { unimplemented!() }
        async fn revoke_session(&self, _: &Session, _: &Session) -> Result<(), BackendError> { unimplemented!() }
        async fn revoke_by_wallet(&self, _: &Session, _: &WalletAddress) -> Result<(), BackendError> { unimplemented!() }
        async fn teardown_agent(&self, _: &Session, _: &WalletAddress) -> Result<(), BackendError> { unimplemented!() }
        async fn shielding_key(&self) -> Result<PublicKey, BackendError> { unimplemented!() }
        async fn register_rendezvous(&self, _: &PublicKey, _: &PairCode) -> Result<RegistrationToken, BackendError> { unimplemented!() }
        async fn poll_rendezvous(&self, _: &RegistrationToken) -> Result<Option<PairPayload>, BackendError> { unimplemented!() }
        async fn deliver_rendezvous(&self, _: &Session, _: &PairCode, _: &EncryptedPairPayload) -> Result<(), BackendError> { unimplemented!() }
        async fn open_auth_request(&self, _: &PublicKey, _: AuthRequestType, _: &CanonicalBytes, _: Option<&WalletAddress>) -> Result<OpenedAuthRequest, BackendError> { unimplemented!() }
        async fn fetch_auth_request(&self, _: &Session, _: &PairCode) -> Result<AuthRequest, BackendError> { unimplemented!() }
        async fn approve_auth_request(&self, _: &Session, _: &AuthRequestId) -> Result<(), BackendError> { unimplemented!() }
        async fn await_auth_decision(&self, _: &AuthRequestId) -> Result<SignedAuthDecision, BackendError> { unimplemented!() }
        async fn recover_session(&self, _: &agentkeys_types::AgentIdentity, _: &agentkeys_types::RecoveryMethod) -> Result<(Session, WalletAddress), BackendError> { unimplemented!() }
        async fn list_credentials(&self, _: &Session, _: &WalletAddress) -> Result<Vec<ServiceName>, BackendError> { unimplemented!() }
        async fn resolve_identity(&self, _: &Session, _: &str) -> Result<WalletAddress, BackendError> { unimplemented!() }
        async fn get_scope(&self, _: &Session, _: &WalletAddress) -> Result<Option<Scope>, BackendError> { unimplemented!() }
        async fn update_scope(&self, _: &Session, _: &WalletAddress, _: &Scope) -> Result<(), BackendError> { unimplemented!() }
    }

    fn test_session() -> Session {
        Session {
            token: "tok".into(),
            wallet: WalletAddress("0xtest".into()),
            scope: None,
            created_at: 0,
            ttl_seconds: 86400,
        }
    }

    fn make_handler() -> McpHandler {
        McpHandler::new(
            Arc::new(NoopBackend),
            test_session(),
            WalletAddress("0xtest".into()),
        )
    }

    #[tokio::test]
    async fn provision_tool_registered() {
        let handler = make_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "tools/list".into(),
            params: None,
            id: Some(json!(1)),
        };
        let resp = handler.handle(req).await;
        assert!(resp.error.is_none(), "tools/list returned error: {:?}", resp.error);
        let tools = resp.result.unwrap();
        let tool_names: Vec<&str> = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(
            tool_names.contains(&"agentkeys.provision"),
            "agentkeys.provision not in tool list: {:?}",
            tool_names
        );
        // Verify schema has service and force fields
        let provision_tool = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "agentkeys.provision")
            .unwrap();
        assert!(provision_tool["inputSchema"]["properties"]["service"].is_object());
        assert!(provision_tool["inputSchema"]["properties"]["force"].is_object());
    }

    #[tokio::test]
    async fn provision_in_progress_error() {
        let provisioner = Arc::new(Provisioner::new());
        // Claim the mutex manually so any provision call finds it in-progress
        let _guard = provisioner.try_claim("openrouter").unwrap();

        let handler = McpHandler::new_with_provisioner(
            Arc::new(NoopBackend),
            test_session(),
            WalletAddress("0xtest".into()),
            provisioner,
        );

        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "tools/call".into(),
            params: Some(json!({
                "name": "agentkeys.provision",
                "arguments": { "service": "openrouter" }
            })),
            id: Some(json!(2)),
        };
        let resp = handler.handle(req).await;
        assert!(resp.error.is_some(), "expected error response");
        let error_msg = &resp.error.unwrap().message;
        assert!(
            error_msg.contains("PROVISION_IN_PROGRESS"),
            "expected PROVISION_IN_PROGRESS code in: {error_msg}"
        );
    }

    #[tokio::test]
    async fn provision_unknown_service_error() {
        let handler = make_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "tools/call".into(),
            params: Some(json!({
                "name": "agentkeys.provision",
                "arguments": { "service": "unknown-service-xyz" }
            })),
            id: Some(json!(3)),
        };
        let resp = handler.handle(req).await;
        assert!(resp.error.is_some(), "expected error for unknown service");
        let msg = &resp.error.unwrap().message;
        assert!(
            msg.contains("SERVICE_NOT_SUPPORTED") || msg.contains("not supported"),
            "unexpected error: {msg}"
        );
    }
}
