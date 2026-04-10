pub mod session_store;

use agentkeys_core::{backend::BackendError, mock_client::MockHttpClient};
use agentkeys_types::{AuditEvent, AuditFilter, AuthToken, ServiceName, Session, WalletAddress};
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
    pub client: MockHttpClient,
    pub verbose: bool,
    pub json_output: bool,
    /// When set, commands use this session directly instead of loading from keychain.
    /// Used by tests to avoid OS keychain interactions.
    pub session_override: Option<Session>,
}

impl CommandContext {
    pub fn new(backend_url: &str, verbose: bool, json_output: bool) -> Self {
        Self {
            client: MockHttpClient::new(backend_url),
            verbose,
            json_output,
            session_override: None,
        }
    }

    pub fn with_session(mut self, session: Session) -> Self {
        self.session_override = Some(session);
        self
    }

    fn load_session(&self) -> Result<Session> {
        if let Some(ref s) = self.session_override {
            return Ok(s.clone());
        }
        session_store::load_session()
    }
}

pub async fn cmd_init(ctx: &CommandContext, mock_token: Option<String>) -> Result<(String, Session)> {
    let token_str = mock_token.unwrap_or_else(|| "mock-default".to_string());

    if ctx.verbose {
        eprintln!("[verbose] POST {}/session/create", ctx.client.base_url);
        eprintln!("[verbose] auth_token: {}", token_str);
    }

    use agentkeys_core::backend::CredentialBackend;
    let (session, wallet) = ctx
        .client
        .create_session(AuthToken::Mock(token_str))
        .await
        .map_err(wrap_backend_error)?;

    session_store::save_session(&session).context("save session to keychain")?;

    let output = format!("Initialized. Wallet: {}", wallet.0);
    Ok((output, session))
}

pub async fn cmd_store(ctx: &CommandContext, agent: &str, service: &str, key: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let agent_id = WalletAddress(agent.to_string());
    let service_name = ServiceName(service.to_string());

    if ctx.verbose {
        eprintln!("[verbose] POST {}/credential/store", ctx.client.base_url);
        eprintln!("[verbose] agent: {}, service: {}", agent, service);
    }

    use agentkeys_core::backend::CredentialBackend;
    ctx.client
        .store_credential(&session, &agent_id, &service_name, key.as_bytes())
        .await
        .map_err(wrap_backend_error)?;

    Ok(format!("Stored credential for agent={} service={}", agent, service))
}

pub async fn cmd_read(ctx: &CommandContext, agent: &str, service: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let agent_id = WalletAddress(agent.to_string());
    let service_name = ServiceName(service.to_string());

    if ctx.verbose {
        eprintln!("[verbose] GET {}/credential/read", ctx.client.base_url);
        eprintln!("[verbose] agent: {}, service: {}", agent, service);
    }

    use agentkeys_core::backend::CredentialBackend;
    let bytes = ctx
        .client
        .read_credential(&session, &agent_id, &service_name)
        .await
        .map_err(wrap_backend_error)?;

    let value = String::from_utf8_lossy(&bytes).to_string();

    if ctx.json_output {
        let obj = json!({ "agent": agent, "service": service, "credential": value });
        Ok(serde_json::to_string_pretty(&obj).unwrap())
    } else {
        Ok(value)
    }
}

pub async fn cmd_run(ctx: &CommandContext, agent: &str, cmd: &[String]) -> Result<String> {
    if cmd.is_empty() {
        return Err(anyhow!("No command specified after --"));
    }

    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let agent_id = WalletAddress(agent.to_string());

    use agentkeys_core::backend::CredentialBackend;

    let services_to_try = if let Some(scope) = &session.scope {
        scope.services.iter().map(|s| s.0.clone()).collect::<Vec<_>>()
    } else {
        vec![]
    };

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for service in &services_to_try {
        let service_name = ServiceName(service.clone());
        if let Ok(bytes) = ctx.client.read_credential(&session, &agent_id, &service_name).await {
            let value = String::from_utf8_lossy(&bytes).to_string();
            let env_key = format!("{}_API_KEY", service.to_uppercase().replace('-', "_"));
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
        std::process::exit(code);
    }
    Ok(String::new())
}

pub async fn cmd_revoke(ctx: &CommandContext, agent: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;

    let target_session = Session {
        token: agent.to_string(),
        wallet: WalletAddress(agent.to_string()),
        scope: None,
        created_at: 0,
        ttl_seconds: 0,
    };

    if ctx.verbose {
        eprintln!("[verbose] POST {}/session/revoke", ctx.client.base_url);
        eprintln!("[verbose] target: {}", agent);
    }

    use agentkeys_core::backend::CredentialBackend;
    ctx.client
        .revoke_session(&session, &target_session)
        .await
        .map_err(wrap_backend_error)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(format!("Revoked agent={} at timestamp={}", agent, now))
}

pub async fn cmd_teardown(ctx: &CommandContext, agent: &str) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let agent_id = WalletAddress(agent.to_string());

    if ctx.verbose {
        eprintln!("[verbose] DELETE {}/credential/teardown", ctx.client.base_url);
        eprintln!("[verbose] agent: {}", agent);
    }

    use agentkeys_core::backend::CredentialBackend;
    ctx.client
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
        eprintln!("[verbose] GET {}/audit/query", ctx.client.base_url);
    }

    use agentkeys_core::backend::CredentialBackend;
    let events = ctx
        .client
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
        eprintln!("[verbose] POST {}/identity/link", ctx.client.base_url);
        eprintln!(
            "[verbose] agent: {}, type: {}, value: {}",
            agent, identity_type, identity_value
        );
    }

    let http_client = reqwest::Client::new();
    let url = format!("{}/identity/link", ctx.client.base_url);
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

pub fn cmd_approve(pair_code: &str) -> String {
    let _ = pair_code;
    "Approve flow ships in Stage 4.".to_string()
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
