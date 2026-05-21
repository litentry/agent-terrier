use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_provisioner::{aws_creds::fetch_via_broker_default_ttl, run_provision, Provisioner};
use agentkeys_types::{ServiceName, Session, WalletAddress};
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
    /// Stage-7 phase-2 wiring: when `Some`, the provision tool fetches AWS
    /// temp creds from this broker URL and injects them into the scraper
    /// subprocess env. When `None`, the subprocess inherits whatever `AWS_*`
    /// vars the operator sourced manually (pre-Stage-7 fallback).
    broker_url: Option<String>,
    /// Federated role ARN — used by `fetch_via_broker` to do
    /// `AssumeRoleWithWebIdentity` client-side (issue #71 Option A). Read
    /// from `AGENTKEYS_DATA_ROLE_ARN` env at construction time. None disables
    /// broker-cred minting (same effect as `broker_url: None`).
    data_role_arn: Option<String>,
    /// AWS region for STS calls. Read from `AWS_REGION` / `AWS_DEFAULT_REGION`
    /// at construction time; defaults to `us-east-1`.
    aws_region: String,
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
            broker_url: None,
            data_role_arn: read_env_data_role_arn(),
            aws_region: read_env_aws_region(),
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
        Self {
            backend,
            session,
            agent_id,
            provisioner,
            repo_root,
            broker_url: None,
            data_role_arn: read_env_data_role_arn(),
            aws_region: read_env_aws_region(),
        }
    }

    /// Builder-style setter so the daemon can pass `--broker-url` through
    /// without forcing every caller to know about it.
    pub fn with_broker_url(mut self, broker_url: Option<String>) -> Self {
        self.broker_url = broker_url;
        self
    }

    /// Builder-style setter for the federated role ARN. Tests use this to
    /// avoid relying on process env. Production reads `AGENTKEYS_DATA_ROLE_ARN`
    /// at `McpHandler::new` time.
    pub fn with_data_role_arn(mut self, arn: Option<String>) -> Self {
        self.data_role_arn = arn;
        self
    }

    /// Builder-style setter for AWS region (mostly for tests).
    pub fn with_aws_region(mut self, region: String) -> Self {
        self.aws_region = region;
        self
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
        match self.backend.list_credentials(&self.session, &self.agent_id).await {
            Ok(services) => {
                let mut services: Vec<String> = services.into_iter().map(|s| s.0).collect();
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

        // Issue #83 — non-CDP `openrouter.ts` is stale (signup_email_otp
        // pattern against a flow that's now Clerk+password+magic-link). Route
        // through the CDP variant which handles the current flow. Prereq:
        // Chrome on CDP_URL (default http://localhost:9222).
        let script_command: Vec<String> = match service.as_str() {
            "openrouter" => vec![
                "npx".to_string(),
                "tsx".to_string(),
                "provisioner-scripts/src/scrapers/openrouter-cdp.ts".to_string(),
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

        let env = match self.broker_env_for_provision().await {
            Ok(env) => env,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    -32603,
                    json!({
                        "code": "BROKER_FETCH_FAILED",
                        "message": e.to_string()
                    })
                    .to_string(),
                );
            }
        };

        let result = run_provision(
            &self.provisioner,
            &service,
            &cmd_refs,
            env,
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

impl McpHandler {
    /// Fetch AWS temp creds from the broker (if configured) and return them
    /// as an env-var map ready to merge into the subprocess. With no broker
    /// configured, returns an empty map and the subprocess inherits whatever
    /// `AWS_*` vars the operator already exported (legacy path).
    ///
    /// Issue #71 Option A: this fetches an OIDC JWT from the broker and does
    /// `AssumeRoleWithWebIdentity` client-side. The broker holds zero AWS
    /// principals at runtime — the JWT authenticates the STS call. The
    /// federated role ARN comes from `AGENTKEYS_DATA_ROLE_ARN` env (read at
    /// `McpHandler::new` time).
    async fn broker_env_for_provision(&self) -> Result<HashMap<String, String>, BrokerEnvError> {
        let Some(broker_url) = self.broker_url.as_deref() else {
            return Ok(HashMap::new());
        };
        let role_arn = self.data_role_arn.as_deref().ok_or_else(|| {
            BrokerEnvError(
                "AGENTKEYS_DATA_ROLE_ARN env var must be set when AGENTKEYS_BROKER_URL is configured (issue #71 Option A)".into(),
            )
        })?;
        let creds = fetch_via_broker_default_ttl(
            broker_url,
            &self.session.token,
            role_arn,
            &self.aws_region,
        )
        .await
        .map_err(|e| BrokerEnvError(e.to_string()))?;
        Ok(creds.to_env(Some(&self.aws_region)))
    }
}

/// Read `AGENTKEYS_DATA_ROLE_ARN`; returns None if unset (broker mint disabled).
fn read_env_data_role_arn() -> Option<String> {
    std::env::var("AGENTKEYS_DATA_ROLE_ARN").ok().filter(|s| !s.is_empty())
}

/// Read `AWS_REGION` / `AWS_DEFAULT_REGION`; default `us-east-1`.
fn read_env_aws_region() -> String {
    std::env::var("AWS_REGION")
        .ok()
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "us-east-1".to_string())
}

#[derive(Debug)]
struct BrokerEnvError(String);

impl std::fmt::Display for BrokerEnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "broker AWS-cred fetch failed: {}", self.0)
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
        AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes,
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
        async fn get_scope(&self, _: &Session, _: &WalletAddress) -> Result<Option<Scope>, BackendError> { unimplemented!() }
        async fn update_scope(&self, _: &Session, _: &WalletAddress, _: &Scope) -> Result<(), BackendError> { unimplemented!() }
        async fn provision_inbox(&self, _: &Session, _: &WalletAddress) -> Result<agentkeys_types::InboxAddress, BackendError> { unimplemented!() }
        async fn list_inboxes(&self, _: &Session, _: &WalletAddress) -> Result<Vec<agentkeys_types::InboxAddress>, BackendError> { unimplemented!() }
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
    async fn broker_env_for_provision_returns_empty_without_broker_url() {
        let handler = make_handler();
        let env = handler.broker_env_for_provision().await.unwrap();
        assert!(
            env.is_empty(),
            "no broker_url ⇒ no AWS env injected (legacy stage6-demo path)"
        );
    }

    #[tokio::test]
    async fn broker_env_for_provision_fetches_oidc_jwt_when_broker_url_set() {
        use axum::{routing::post, Json, Router};

        // Stub broker that returns a fake OIDC JWT (issue #71 Option A — the
        // MCP handler now hops to /v1/mint-oidc-jwt instead of the retired
        // /v1/mint-aws-creds aggregator). The actual STS call from the
        // provisioner against the fake JWT will fail (real STS rejects it,
        // or with no AWS routes / proxies it errors out). What we assert
        // here is that the wiring goes through the JWT-fetch step — i.e.
        // the broker URL is hit + the bearer is forwarded + the response
        // is parsed. Coverage of the STS half lives in the live operator
        // walkthrough; the unit-test surface here is the call-site wiring.
        let router = Router::new().route(
            "/v1/mint-oidc-jwt",
            post(|| async {
                Json(json!({
                    "jwt": "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzdHViIn0.fake-sig",
                    "wallet": "0xtest",
                    "expiration": 9_999_999_999_i64,
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let broker_url = format!("http://{}", addr);

        // Point STS at a dead endpoint so the call deterministically fails
        // post-JWT-fetch instead of hitting real AWS. AWS_ENDPOINT_URL_STS
        // is the SDK's documented override.
        std::env::set_var("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:1");

        let handler = McpHandler::new(
            Arc::new(NoopBackend),
            test_session(),
            WalletAddress("0xtest".into()),
        )
        .with_broker_url(Some(broker_url))
        .with_data_role_arn(Some(
            "arn:aws:iam::000000000000:role/agentkeys-data-role".into(),
        ))
        .with_aws_region("us-east-1".into());

        let err = handler
            .broker_env_for_provision()
            .await
            .expect_err("unreachable STS endpoint must surface as error");
        let msg = err.to_string();
        // The JWT-fetch step succeeded; failure must come from the STS half.
        // Tolerant assertion — the error wrapping varies across SDK versions.
        assert!(
            msg.contains("assume_role_with_web_identity")
                || msg.contains("STS")
                || msg.contains("dispatch")
                || msg.contains("connect")
                || msg.contains("io"),
            "expected STS-side failure, got: {msg}"
        );

        std::env::remove_var("AWS_ENDPOINT_URL_STS");
    }

    #[tokio::test]
    async fn broker_env_for_provision_errors_when_role_arn_unset() {
        let handler = McpHandler::new(
            Arc::new(NoopBackend),
            test_session(),
            WalletAddress("0xtest".into()),
        )
        .with_broker_url(Some("http://127.0.0.1:1".into()))
        .with_data_role_arn(None);

        let err = handler
            .broker_env_for_provision()
            .await
            .expect_err("missing role ARN must surface as error before any HTTP call");
        let msg = err.to_string();
        assert!(
            msg.contains("AGENTKEYS_DATA_ROLE_ARN"),
            "error should reference the missing env var: {msg}"
        );
    }

    #[tokio::test]
    async fn broker_env_for_provision_surfaces_unreachable_broker() {
        let handler = McpHandler::new(
            Arc::new(NoopBackend),
            test_session(),
            WalletAddress("0xtest".into()),
        )
        .with_broker_url(Some("http://127.0.0.1:1".into()))
        .with_data_role_arn(Some(
            "arn:aws:iam::000000000000:role/agentkeys-data-role".into(),
        ));

        let err = handler
            .broker_env_for_provision()
            .await
            .expect_err("unreachable broker must error");
        assert!(
            err.to_string().contains("broker"),
            "error should reference the broker: {err}"
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
