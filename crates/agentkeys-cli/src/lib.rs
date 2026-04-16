use std::collections::HashMap;
use std::sync::Arc;

use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_core::mock_client::MockHttpClient;
pub use agentkeys_core::session_store;
use agentkeys_core::session_store::SessionStore;
use agentkeys_provisioner::{run_provision, ProvisionError, Provisioner};
use agentkeys_types::{
    AuditEvent, AuditFilter, AuthToken, Scope, ServiceName, Session, WalletAddress,
};
use anyhow::{anyhow, Context, Result};
use serde_json::json;

fn format_backend_error(err: &BackendError) -> String {
    match err {
        BackendError::PermissionDenied(msg) => {
            format!(
                "Error: DENIED\n  {}\n\n  Fix: Check the agent's scope with `agentkeys usage`",
                msg
            )
        }
        BackendError::NotFound(msg) => {
            format!("Error: NOT_FOUND\n  {}", msg)
        }
        BackendError::AuthFailed(msg) => {
            format!("Error: AUTH_FAILED\n  {}", msg)
        }
        BackendError::Transport(msg) => {
            format!("Error: UNREACHABLE\n  Backend unreachable: {}", msg)
        }
        other => format!("Error: {}", other),
    }
}

fn wrap_backend_error(err: BackendError) -> anyhow::Error {
    anyhow!("{}", format_backend_error(&err))
}

pub struct CommandContext {
    pub backend_url: String,
    pub verbose: bool,
    pub json_output: bool,
    /// Session namespace; defaults to "master". Future multi-session support uses this field.
    pub session_id: String,
    /// When set, commands use this session directly instead of loading from keychain.
    /// Used by tests to avoid OS keychain interactions.
    pub session_override: Option<Session>,
    /// When set, commands use this backend directly instead of creating a MockHttpClient.
    /// Used by tests to avoid TCP connections.
    pub backend_override: Option<Arc<dyn CredentialBackend>>,
    /// When set, commands route save/load/clear through this explicit
    /// session store instead of `SessionStore::from_env()`. Tests use this
    /// to point at a tempdir in file-only mode without mutating
    /// process-global `$HOME` / `AGENTKEYS_SESSION_STORE` (issue #34).
    pub session_store_override: Option<SessionStore>,
}

impl CommandContext {
    pub fn new(backend_url: &str, verbose: bool, json_output: bool) -> Self {
        Self {
            backend_url: backend_url.to_string(),
            verbose,
            json_output,
            session_id: "master".to_string(),
            session_override: None,
            backend_override: None,
            session_store_override: None,
        }
    }

    pub fn with_session(mut self, session: Session) -> Self {
        self.session_override = Some(session);
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn CredentialBackend>) -> Self {
        self.backend_override = Some(backend);
        self
    }

    /// Inject an explicit session store. Tests pass a tempdir-rooted
    /// file-only store here so save/load stay hermetic without touching
    /// env vars or the OS keyring.
    pub fn with_session_store(mut self, store: SessionStore) -> Self {
        self.session_store_override = Some(store);
        self
    }

    pub fn load_session(&self) -> Result<Session> {
        if let Some(ref s) = self.session_override {
            return Ok(s.clone());
        }
        // Use the legacy-aware loader so pre-#12 installs (session stored
        // under keyring account=`session` or file ~/.agentkeys/session.json)
        // stay logged in after upgrading to the wallet-namespaced layout.
        self.session_store()
            .load_with_legacy_fallback(&self.session_id)
    }

    fn backend(&self) -> Arc<dyn CredentialBackend> {
        if let Some(ref b) = self.backend_override {
            b.clone()
        } else {
            Arc::new(MockHttpClient::new(&self.backend_url))
        }
    }

    /// Resolve the session store for this context: the injected override
    /// if one is present, otherwise a fresh `SessionStore::from_env()`
    /// mirroring the pre-refactor default behaviour.
    pub fn session_store(&self) -> SessionStore {
        self.session_store_override
            .clone()
            .unwrap_or_else(SessionStore::from_env)
    }
}

pub async fn cmd_init(ctx: &CommandContext, mock_token: Option<String>) -> Result<(String, Session)> {
    let token_str = mock_token.unwrap_or_else(|| "mock-default".to_string());

    if ctx.verbose {
        eprintln!("[verbose] POST {}/session/create", ctx.backend_url);
        eprintln!("[verbose] auth_token: {}", token_str);
    }

    let backend = ctx.backend();
    let (session, wallet) = backend
        .create_session(AuthToken::Mock(token_str))
        .await
        .map_err(wrap_backend_error)?;

    // Use ctx.session_id (defaults to "master"). Honoring the field ensures
    // that any caller overriding it sees consistent save/load round-trips
    // instead of init landing under "master" and the next command looking
    // in the configured namespace (codex PR #24 v5 P2).
    ctx.session_store()
        .save(&session, &ctx.session_id)
        .context("save session to keychain")?;

    let output = format!("Initialized. Wallet: {}", wallet.0);
    Ok((output, session))
}

/// Resolve the effective wallet address for a command.
/// - `None`  → use the session's own wallet (default agent)
/// - `Some("0x...")` → parse directly as wallet address
/// - `Some(other)` → call `resolve_identity` on the backend (alias/email lookup)
async fn resolve_agent(
    backend: &Arc<dyn CredentialBackend>,
    session: &Session,
    agent: Option<&str>,
) -> Result<WalletAddress> {
    match agent {
        None => Ok(session.wallet.clone()),
        Some(arg) if arg.starts_with("0x") => Ok(WalletAddress(arg.to_string())),
        Some(arg) => backend
            .resolve_identity(session, arg)
            .await
            .map_err(|e| match e {
                BackendError::NotFound(_) => anyhow!(
                    "unknown identity '{}'. Use `agentkeys link` to create an alias or pass the 0x... wallet directly.",
                    arg
                ),
                other => wrap_backend_error(other),
            }),
    }
}

pub async fn cmd_store(ctx: &CommandContext, agent: Option<&str>, service: &str, key: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent).await?;
    let service_name = ServiceName(service.to_string());

    if ctx.verbose {
        eprintln!("[verbose] POST {}/credential/store", ctx.backend_url);
        eprintln!("[verbose] agent: {}, service: {}", agent_id.0, service);
    }

    backend
        .store_credential(&session, &agent_id, &service_name, key.as_bytes())
        .await
        .map_err(wrap_backend_error)?;

    Ok(format!("Stored credential for agent={} service={}", agent_id.0, service))
}

pub async fn cmd_read(ctx: &CommandContext, agent: Option<&str>, service: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent).await?;
    let service_name = ServiceName(service.to_string());

    if ctx.verbose {
        eprintln!("[verbose] GET {}/credential/read", ctx.backend_url);
        eprintln!("[verbose] agent: {}, service: {}", agent_id.0, service);
    }

    let bytes = backend
        .read_credential(&session, &agent_id, &service_name)
        .await
        .map_err(wrap_backend_error)?;

    let value = String::from_utf8_lossy(&bytes).to_string();

    if ctx.json_output {
        let obj = json!({ "agent": agent_id.0, "service": service, "credential": value });
        Ok(serde_json::to_string_pretty(&obj).unwrap())
    } else {
        Ok(value)
    }
}

pub async fn cmd_run(
    ctx: &CommandContext,
    agent: Option<&str>,
    env_overrides: &[String],
    cmd: &[String],
) -> Result<String> {
    if cmd.is_empty() {
        return Err(anyhow!("No command specified after --"));
    }

    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent).await?;

    // Pre-flight validation: reject any invalid --env entries BEFORE any credential
    // I/O (no network round-trips or audit log entries for a partial invocation).
    // Must run before list_credentials so a malformed override does not produce a
    // backend round-trip / DENIED audit row on the master-session path (codex P2 v2).
    for raw in env_overrides {
        let eq_pos = raw.find('=').ok_or_else(|| {
            anyhow!(
                "Invalid --env format '{}': expected KEY=SERVICE (no '=' found)",
                raw
            )
        })?;
        if eq_pos == 0 {
            return Err(anyhow!(
                "Invalid --env format '{}': KEY must not be empty",
                raw
            ));
        }
        if eq_pos + 1 == raw.len() {
            return Err(anyhow!(
                "Invalid --env format '{}': SERVICE must not be empty",
                raw
            ));
        }
    }

    let services_to_try: Vec<String> = if let Some(scope) = &session.scope {
        scope.services.iter().map(|s| s.0.clone()).collect()
    } else {
        backend
            .list_credentials(&session, &agent_id)
            .await
            .map_err(wrap_backend_error)?
            .into_iter()
            .map(|s| s.0)
            .collect()
    };

    // Track which services we've already fetched in the auto-injection pass.
    // The --env loop below reuses these values instead of issuing a second
    // read_credential for the same service, which would double-count audit
    // events and rate-limit decrements (codex P2 on PR #19).
    let mut fetched: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut env_vars: Vec<(String, String)> = Vec::new();
    let mut credential_errors: Vec<String> = Vec::new();
    for service in &services_to_try {
        let service_name = ServiceName(service.clone());
        match backend.read_credential(&session, &agent_id, &service_name).await {
            Ok(bytes) => {
                let value = String::from_utf8_lossy(&bytes).to_string();
                let env_key = format!("{}_API_KEY", service.to_uppercase().replace('-', "_"));
                fetched.insert(service.clone(), value.clone());
                env_vars.push((env_key, value));
            }
            Err(e) => {
                credential_errors.push(format!(
                    "Failed to read credential for service '{}': {}",
                    service,
                    format_backend_error(&e)
                ));
            }
        }
    }
    if !credential_errors.is_empty() {
        return Err(anyhow!("{}", credential_errors.join("\n")));
    }

    for raw in env_overrides {
        let eq_pos = raw.find('=').expect("pre-flight validation already rejected entries without '='");
        let env_key = raw[..eq_pos].to_string();
        let service = &raw[eq_pos + 1..];

        // Reuse the auto-injection fetch if we already pulled this service.
        // Only issue a fresh read_credential when --env names a service that
        // wasn't auto-injected (typical for master sessions where scope=None
        // → all stored services were already pulled, so fresh reads here are
        // for the rare case of explicit --env on a service the user never
        // stored before this run).
        let value = if let Some(cached) = fetched.get(service) {
            cached.clone()
        } else {
            let service_name = ServiceName(service.to_string());
            let bytes = backend
                .read_credential(&session, &agent_id, &service_name)
                .await
                .map_err(wrap_backend_error)?;
            let v = String::from_utf8_lossy(&bytes).to_string();
            fetched.insert(service.to_string(), v.clone());
            v
        };

        if let Some(existing) = env_vars.iter_mut().find(|(k, _)| k == &env_key) {
            existing.1 = value;
        } else {
            env_vars.push((env_key, value));
        }
    }

    if ctx.verbose {
        eprintln!(
            "[verbose] Injecting env vars: {:?}",
            env_vars.iter().map(|(k, _)| k).collect::<Vec<_>>()
        );
    }

    let mut child = std::process::Command::new(&cmd[0]);
    child.args(&cmd[1..]);
    for (k, v) in &env_vars {
        child.env(k, v);
    }

    let status = child.status().with_context(|| format!("exec {}", cmd[0]))?;
    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(anyhow!("command exited with code {}", code));
    }
    Ok(String::new())
}

pub async fn cmd_revoke(ctx: &CommandContext, agent: Option<&str>) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;

    if ctx.verbose {
        eprintln!("[verbose] POST {}/session/revoke", ctx.backend_url);
    }

    match agent {
        None => {
            let wallet_display = session.wallet.0.clone();
            ctx.backend()
                .revoke_session(&session, &session)
                .await
                .map_err(wrap_backend_error)?;
            ctx.session_store()
                .clear(&ctx.session_id)
                .context("clear local session")?;
            Ok(format!(
                "Revoked current session for wallet={}. Local session wiped. Run `agentkeys init` to re-pair.",
                wallet_display
            ))
        }
        Some(target_wallet_str) => {
            if ctx.verbose {
                eprintln!("[verbose] target wallet: {}", target_wallet_str);
            }
            let target_wallet = WalletAddress(target_wallet_str.to_string());
            ctx.backend()
                .revoke_by_wallet(&session, &target_wallet)
                .await
                .map_err(wrap_backend_error)?;

            // If the target wallet IS the caller's own wallet, the just-revoked
            // session matches the locally-cached one. Wipe local state too so
            // subsequent commands fail cleanly with "no session" instead of
            // loading the stale revoked token (codex P2 from the original review,
            // tracked at issue-17 review thread).
            //
            // Wallet addresses are compared case-insensitively because the EVM
            // canonical form (EIP-55 mixed case) can differ from the lowercase
            // form returned by the mock backend.
            let revoked_self = session.wallet.0.eq_ignore_ascii_case(target_wallet_str);
            if revoked_self {
                ctx.session_store()
                    .clear(&ctx.session_id)
                    .context("clear local session after self-revoke")?;
                Ok(format!(
                    "Revoked agent={} (was your own session — local state wiped, run `agentkeys init` to re-pair).",
                    target_wallet_str
                ))
            } else {
                Ok(format!("Revoked agent={}", target_wallet_str))
            }
        }
    }
}

pub async fn cmd_teardown(ctx: &CommandContext, agent: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let agent_id = WalletAddress(agent.to_string());

    if ctx.verbose {
        eprintln!("[verbose] DELETE {}/credential/teardown", ctx.backend_url);
        eprintln!("[verbose] agent: {}", agent);
    }

    ctx.backend()
        .teardown_agent(&session, &agent_id)
        .await
        .map_err(wrap_backend_error)?;

    Ok(format!("Torn down agent={}", agent))
}

pub async fn cmd_usage(ctx: &CommandContext, agent: Option<&str>, json_flag: bool) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;

    let filter = AuditFilter {
        owner: None,
        agent: agent.map(|a| WalletAddress(a.to_string())),
        service: None,
    };

    if ctx.verbose {
        eprintln!("[verbose] GET {}/audit/query", ctx.backend_url);
    }

    let events = ctx.backend()
        .query_audit(&session, filter)
        .await
        .map_err(wrap_backend_error)?;

    if json_flag || ctx.json_output {
        let arr: Vec<serde_json::Value> = events.iter().map(audit_event_to_json).collect();
        Ok(serde_json::to_string_pretty(&arr).unwrap())
    } else {
        Ok(format_audit_table(&events))
    }
}

fn audit_event_to_json(e: &AuditEvent) -> serde_json::Value {
    json!({
        "timestamp": e.timestamp,
        "agent": e.agent.0,
        "service": e.service.0,
        "action": e.action,
        "result": e.result,
    })
}

fn format_audit_table(events: &[AuditEvent]) -> String {
    if events.is_empty() {
        return "No audit events found.".to_string();
    }
    let header = format!(
        "{:<12} {:<20} {:<20} {:<12} {:<10}",
        "timestamp", "agent", "service", "action", "result"
    );
    let rows: Vec<String> = events
        .iter()
        .map(|e| {
            format!(
                "{:<12} {:<20} {:<20} {:<12} {:<10}",
                e.timestamp,
                truncate(&e.agent.0, 20),
                truncate(&e.service.0, 20),
                truncate(&e.action, 12),
                truncate(&e.result, 10),
            )
        })
        .collect();
    format!("{}\n{}", header, rows.join("\n"))
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

pub async fn cmd_link(
    ctx: &CommandContext,
    agent: &str,
    alias: Option<&str>,
    email: Option<&str>,
) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;

    let (identity_type, identity_value) = if let Some(a) = alias {
        ("alias", a)
    } else if let Some(e) = email {
        ("email", e)
    } else {
        return Err(anyhow!("Provide --alias or --email"));
    };

    if ctx.verbose {
        eprintln!("[verbose] POST {}/identity/link", ctx.backend_url);
        eprintln!(
            "[verbose] agent: {}, type: {}, value: {}",
            agent, identity_type, identity_value
        );
    }

    // cmd_link uses the /identity/link endpoint which is not part of the CredentialBackend
    // trait (identity linking is an extra endpoint). We route via HTTP using backend_url
    // from the context. When backend_override is set, the caller must also set backend_url
    // to a valid URL that serves the identity/link endpoint.
    // Note: adding link_identity to CredentialBackend trait is a v0.1 item.
    let http_client = reqwest::Client::new();
    let url = format!("{}/identity/link", ctx.backend_url);
    let resp = http_client
        .post(&url)
        .header("authorization", format!("Bearer {}", session.token))
        .json(&json!({
            "identity_type": identity_type,
            "identity_value": identity_value,
            "wallet_address": agent,
        }))
        .send()
        .await
        .context("POST /identity/link")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let msg = body["message"].as_str().unwrap_or("unknown error");
        return Err(anyhow!("Error: HTTP {}: {}", status, msg));
    }

    Ok(format!(
        "Linked agent={} {}={}",
        agent, identity_type, identity_value
    ))
}

pub async fn cmd_recover(ctx: &CommandContext, identity: &str, method: &str) -> Result<String> {
    let recovery_method = match method {
        "passkey" => agentkeys_types::RecoveryMethod::Passkey,
        "email" => agentkeys_types::RecoveryMethod::Email,
        other => return Err(anyhow!("Unknown recovery method '{}'. Use 'passkey' or 'email'.", other)),
    };

    let agent_identity = if identity.starts_with("0x") {
        agentkeys_types::AgentIdentity::WalletAddress(WalletAddress(identity.to_string()))
    } else if identity.contains('@') {
        agentkeys_types::AgentIdentity::Email(identity.to_string())
    } else {
        agentkeys_types::AgentIdentity::Alias(identity.to_string())
    };

    if ctx.verbose {
        eprintln!("[verbose] POST {}/session/recover", ctx.backend_url);
        eprintln!("[verbose] identity: {}, method: {}", identity, method);
    }

    let backend = ctx.backend();
    let (session, wallet) = backend
        .recover_session(&agent_identity, &recovery_method)
        .await
        .map_err(wrap_backend_error)?;

    ctx.session_store()
        .save(&session, &ctx.session_id)
        .context("save recovered session to keychain")?;

    Ok(format!("Recovered. Session restored for wallet {}", wallet.0))
}

pub async fn cmd_approve(ctx: &CommandContext, pair_code: &str, auto_yes: bool) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;

    if ctx.verbose {
        eprintln!("[verbose] GET {}/auth-request/fetch?pair_code={}", ctx.backend_url, pair_code);
    }

    let auth_request = ctx.backend()
        .fetch_auth_request(&session, &agentkeys_types::PairCode(pair_code.to_string()))
        .await
        .map_err(wrap_backend_error)?;

    let request_type_display = match &auth_request.request_type {
        agentkeys_types::AuthRequestType::Pair { requested_scope } => {
            if requested_scope.services.is_empty() {
                "Pair new agent (all services)".to_string()
            } else {
                let services: Vec<&str> =
                    requested_scope.services.iter().map(|s| s.0.as_str()).collect();
                format!("Pair new agent (services: {})", services.join(", "))
            }
        }
        agentkeys_types::AuthRequestType::Recover { agent_identity, .. } => {
            let identity = match agent_identity {
                agentkeys_types::AgentIdentity::Alias(s) => format!("alias:{s}"),
                agentkeys_types::AgentIdentity::Email(s) => format!("email:{s}"),
                agentkeys_types::AgentIdentity::Ens(s) => format!("ens:{s}"),
                agentkeys_types::AgentIdentity::WalletAddress(w) => w.0.clone(),
            };
            format!("Recover agent '{identity}'")
        }
        agentkeys_types::AuthRequestType::ScopeChange { agent_id, .. } => {
            format!("Scope change for agent {}", agent_id.0)
        }
        agentkeys_types::AuthRequestType::HighValueRelease { agent_id, service, .. } => {
            format!("High-value release: agent {} service {}", agent_id.0, service.0)
        }
        agentkeys_types::AuthRequestType::KeyRotate { agent_id, .. } => {
            format!("Key rotation for agent {}", agent_id.0)
        }
    };

    println!("Request type: {}", request_type_display);
    println!("OTP: {}", auth_request.otp);
    println!("Does this match what the daemon showed? [y/N]");

    let confirmed = if auto_yes {
        true
    } else {
        let auto_env = std::env::var("AGENTKEYS_APPROVE_AUTO").unwrap_or_default();
        if auto_env == "1" || auto_env.to_lowercase() == "true" {
            true
        } else {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            input.trim().to_lowercase() == "y"
        }
    };

    if !confirmed {
        return Err(anyhow!("Approval cancelled by user"));
    }

    if ctx.verbose {
        eprintln!("[verbose] POST {}/auth-request/approve", ctx.backend_url);
    }

    let backend = ctx.backend();

    backend
        .approve_auth_request(&session, &auth_request.id)
        .await
        .map_err(wrap_backend_error)?;

    // Deliver a rendezvous payload to unblock the daemon's poll loop.
    // The actual session data is delivered via await_auth_decision; this
    // payload just signals the daemon that approval happened.
    let pair_code_obj = agentkeys_types::PairCode(pair_code.to_string());
    let signal = agentkeys_types::EncryptedPairPayload(b"approved".to_vec());
    backend
        .deliver_rendezvous(&session, &pair_code_obj, &signal)
        .await
        .map_err(wrap_backend_error)?;

    Ok("Approved. Agent paired successfully.".to_string())
}

async fn resolve_agent_to_wallet(
    ctx: &CommandContext,
    session: &Session,
    agent: &str,
) -> Result<String> {
    if agent.starts_with("0x") {
        return Ok(agent.to_string());
    }
    // Resolve alias or email via /identity/resolve
    let (identity_type, identity_value) = if agent.contains('@') {
        ("email", agent)
    } else {
        ("alias", agent)
    };
    // reqwest's .query() builder percent-encodes per RFC 3986 so identities
    // containing '+', '&', '=', '%', spaces (e.g. plus-addressed emails like
    // "bot+prod@example.com") are sent intact to the server.
    let http_client = reqwest::Client::new();
    let resp = http_client
        .get(format!("{}/identity/resolve", ctx.backend_url))
        .query(&[("identity_type", identity_type), ("identity_value", identity_value)])
        .header("authorization", format!("Bearer {}", session.token))
        .send()
        .await
        .context("GET /identity/resolve")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let msg = body["message"].as_str().unwrap_or("not found");
        return Err(anyhow!("Error: HTTP {}: {}", status, msg));
    }
    let body: serde_json::Value = resp.json().await.context("parse identity/resolve response")?;
    let wallet = body["wallet_address"]
        .as_str()
        .ok_or_else(|| anyhow!("identity/resolve returned no wallet_address"))?
        .to_string();
    Ok(wallet)
}

pub async fn cmd_scope(
    ctx: &CommandContext,
    agent: &str,
    add: &[String],
    remove: &[String],
    set: Option<&str>,
    list: bool,
) -> Result<String> {
    if set.is_some() && (!add.is_empty() || !remove.is_empty()) {
        return Err(anyhow!(
            "Error: --set is mutually exclusive with --add and --remove. Use one or the other."
        ));
    }

    // --list is read-only. Combining it with mutating flags would silently
    // drop the mutation (the --list early-return happens before the update
    // path), so reject the combo up front with a clear error.
    if list && (set.is_some() || !add.is_empty() || !remove.is_empty()) {
        return Err(anyhow!(
            "Error: --list is mutually exclusive with --add, --remove, and --set. Use --list alone to read the current scope."
        ));
    }

    // `--add foo --remove foo` would silently no-op after mutation
    // (retain after push cancels) yet still issue a backend write with a
    // misleading "Scope updated" message. Reject up front (codex PR #29
    // v2 P2).
    if !add.is_empty() && !remove.is_empty() {
        let add_set: std::collections::HashSet<&str> = add.iter().map(|s| s.as_str()).collect();
        let overlap: Vec<&str> = remove
            .iter()
            .map(|s| s.as_str())
            .filter(|s| add_set.contains(s))
            .collect();
        if !overlap.is_empty() {
            return Err(anyhow!(
                "Error: the following services appear in both --add and --remove: {}. Pass each service to only one flag.",
                overlap.join(", ")
            ));
        }
    }

    if !list && set.is_none() && add.is_empty() && remove.is_empty() {
        return Err(anyhow!(
            "No action specified. Use --add, --remove, --set, or --list.\nRun `agentkeys scope --help` for usage."
        ));
    }

    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let target_wallet = WalletAddress(resolve_agent_to_wallet(ctx, &session, agent).await?);
    let backend = ctx.backend();

    let current_scope = backend
        .get_scope(&session, &target_wallet)
        .await
        .map_err(wrap_backend_error)?
        .unwrap_or(Scope { services: vec![], read_only: false });

    if list {
        let service_names: Vec<&str> =
            current_scope.services.iter().map(|s| s.0.as_str()).collect();
        return Ok(format!(
            "Scope for agent {}:\n  services: [{}]\n  read_only: {}",
            target_wallet.0,
            service_names.join(", "),
            current_scope.read_only
        ));
    }

    let new_scope = if let Some(set_val) = set {
        let mut services: Vec<ServiceName> = set_val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| ServiceName(s.to_string()))
            .collect();
        services.sort_by(|a, b| a.0.cmp(&b.0));
        Scope { services, read_only: current_scope.read_only }
    } else {
        let mut services: Vec<ServiceName> = current_scope.services.clone();
        for svc in add {
            let name = ServiceName(svc.clone());
            if !services.contains(&name) {
                services.push(name);
            }
        }
        services.retain(|s| !remove.contains(&s.0));
        services.sort_by(|a, b| a.0.cmp(&b.0));
        Scope { services, read_only: current_scope.read_only }
    };

    backend
        .update_scope(&session, &target_wallet, &new_scope)
        .await
        .map_err(wrap_backend_error)?;

    // `new_scope.services` is already sorted — both the --set branch
    // (line 749) and the --add/--remove branch (line 760) sort before
    // the update_scope call.
    let service_names: Vec<&str> = new_scope.services.iter().map(|s| s.0.as_str()).collect();
    Ok(format!(
        "Scope updated for agent {}. New services: [{}]",
        target_wallet.0,
        service_names.join(", ")
    ))
}

fn format_provision_error(err: &ProvisionError) -> String {
    match err {
        ProvisionError::InProgress { active_service } => format!(
            "Problem: Another provision is running for {}.\nCause: Provisioner serializes calls per daemon.\nFix: Wait and retry.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/development-stages.md",
            active_service
        ),
        ProvisionError::Tripwire { kind, step, .. } => format!(
            "Problem: A script step timed out at '{}'.\nCause: The target site's DOM may have changed (tripwire: {:?}).\nFix: Open an issue at https://github.com/litentry/agentKeys/issues with the logs.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/development-stages.md",
            step, kind
        ),
        ProvisionError::StoreFailed { obtained_key_masked, .. } => format!(
            "Problem: Credential provisioned but storage failed.\nCause: Backend store_credential returned an error.\nFix: Manually store the key with `agentkeys store <service> <key>`. Masked key for reference: {}.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/development-stages.md",
            obtained_key_masked
        ),
        ProvisionError::VerificationFailed { service, reason } => format!(
            "Problem: Key verification failed for {}.\nCause: {}.\nFix: Re-run with --force to attempt a fresh provision.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/development-stages.md",
            service, reason
        ),
        other => format!(
            "Problem: Provision failed.\nCause: {}.\nFix: Check logs and retry.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/development-stages.md",
            other
        ),
    }
}

pub struct ProvisionOutput {
    pub stdout_line: String,
    pub stderr_lines: Vec<String>,
}

pub async fn cmd_provision(
    ctx: &CommandContext,
    service: &str,
    force: bool,
    provisioner: Option<Arc<Provisioner>>,
) -> Result<ProvisionOutput> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = session.wallet.clone();

    if force {
        eprintln!("existing key present — re-provisioning (--force)");
    }

    let provisioner = provisioner.unwrap_or_else(|| Arc::new(Provisioner::new()));

    let script_command: Vec<String> = match service {
        "openrouter" => vec![
            "npx".to_string(),
            "tsx".to_string(),
            "provisioner-scripts/src/scrapers/openrouter.ts".to_string(),
        ],
        other => {
            return Err(anyhow!(
                "Problem: Service '{}' not supported.\nCause: Only 'openrouter' is supported in Stage 5a.\nFix: Use a supported service name.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/development-stages.md",
                other
            ));
        }
    };

    let cmd_refs: Vec<&str> = script_command.iter().map(|s| s.as_str()).collect();
    let repo_root = std::env::var("AGENTKEYS_REPO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());

    let mut stderr_lines: Vec<String> = Vec::new();

    let result = run_provision(
        &provisioner,
        service,
        &cmd_refs,
        HashMap::new(),
        Some(&repo_root),
        backend,
        &session,
        &agent_id,
        force,
    )
    .await;

    match result {
        Ok(success) => {
            if !success.stored {
                let msg = format!(
                    "{} already provisioned, key valid (re-verify returned true)",
                    service
                );
                stderr_lines.push(msg);
            }
            Ok(ProvisionOutput {
                stdout_line: success.obtained_key_masked,
                stderr_lines,
            })
        }
        Err(e) => {
            Err(anyhow!("{}", format_provision_error(&e)))
        }
    }
}

pub fn cmd_feedback() -> String {
    let url = "https://github.com/agentkeys/agentkeys/discussions";
    let opened = std::process::Command::new("open").arg(url).status().is_ok()
        || std::process::Command::new("xdg-open").arg(url).status().is_ok()
        || std::process::Command::new("start").arg(url).status().is_ok();
    if opened {
        format!("Opening {} in your browser", url)
    } else {
        format!("Visit: {}", url)
    }
}
