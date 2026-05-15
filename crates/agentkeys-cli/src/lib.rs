use std::collections::HashMap;
use std::sync::Arc;

use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_core::init_flow;
use agentkeys_core::mock_client::MockHttpClient;
pub use agentkeys_core::session_store;
use agentkeys_core::session_store::SessionStore;
use agentkeys_core::signer_client::{HttpSignerClient, SignerClient, SignerClientError};
use agentkeys_provisioner::{
    aws_creds::fetch_via_broker_default_ttl, run_provision, ProvisionError, Provisioner,
};

/// Stage-7 phase-2 helper: when a broker URL is configured, fetch 1-hour
/// scoped AWS creds and return them as an env-var map ready to merge into the
/// scraper subprocess. With no broker URL, returns an empty map and the
/// subprocess inherits whatever the operator already has in its environment
/// (legacy pre-Stage-7 path: operator sources AWS_* manually).
///
/// Issue #71 Option A: this helper does the JWT-fetch + AssumeRoleWithWebIdentity
/// client-side. The broker holds zero AWS principals at runtime.
/// `AGENTKEYS_DATA_ROLE_ARN` env must be set when `broker_url.is_some()`.
async fn broker_env_for_provision(
    broker_url: Option<&str>,
    session_token: &str,
) -> Result<HashMap<String, String>> {
    let Some(url) = broker_url else {
        return Ok(HashMap::new());
    };
    let role_arn = std::env::var("AGENTKEYS_DATA_ROLE_ARN").map_err(|_| {
        anyhow!(
            "AGENTKEYS_DATA_ROLE_ARN env var must be set when --broker-url is configured (issue #71 Option A)"
        )
    })?;
    let region = std::env::var("AWS_REGION")
        .ok()
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .unwrap_or_else(|| "us-east-1".to_string());
    let creds = fetch_via_broker_default_ttl(url, session_token, &role_arn, &region).await?;
    Ok(creds.to_env(Some(&region)))
}
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
    /// Stage-7 phase-2 wiring: when set, `agentkeys provision` fetches AWS
    /// temp creds from this broker URL and injects them into the scraper
    /// subprocess env (no manual `AWS_*` env wiring required).
    pub broker_url: Option<String>,
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
            broker_url: std::env::var("AGENTKEYS_BROKER_URL").ok().filter(|s| !s.is_empty()),
        }
    }

    pub fn with_broker_url(mut self, broker_url: Option<String>) -> Self {
        self.broker_url = broker_url;
        self
    }

    /// Override the session namespace. Empty strings fall back to the
    /// `"master"` default so a forgotten `AGENTKEYS_SESSION_ID=` shell
    /// export doesn't silently write to `~/.agentkeys//session.json`.
    pub fn with_session_id(mut self, session_id: String) -> Self {
        if !session_id.is_empty() {
            self.session_id = session_id;
        }
        self
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

/// `agentkeys init` modes per issue #74 step 1.
///
/// The legacy `--mock-token` flag has been hard-cut from the CLI surface
/// per the plan's CEO-review §8 ("no deprecation runway, clean slate this
/// PR"). The internal mock-token path stays as `ImportLegacyMock` for unit
/// tests only — `agentkeys-cli/src/main.rs` does NOT route to it.
pub enum InitMode {
    /// Email-link auth: drives `POST /v1/auth/email/request` + polls
    /// `GET /v1/auth/email/status/<id>` until the operator clicks the
    /// magic link. On success, derives the EVM wallet via
    /// `POST /dev/derive-address`, links it to the email-omni via
    /// `POST /v1/wallet/link`, runs the SIWE round-trip with the signer
    /// signing on behalf of the email-omni, and saves the resulting
    /// EVM-omni session JWT.
    Email {
        email: String,
        broker_url: String,
        signer_url: String,
        chain_id: u64,
        poll_timeout_seconds: u64,
    },

    /// OAuth2/Google auth: same chain as `Email` but bootstraps via
    /// `POST /v1/auth/oauth2/start` + `GET /v1/auth/oauth2/status/<id>`.
    /// The CLI prints the authorization URL — the operator opens it in a
    /// browser, completes the flow, and the CLI's poll loop catches the
    /// callback.
    Oauth2Google {
        broker_url: String,
        signer_url: String,
        chain_id: u64,
        poll_timeout_seconds: u64,
    },

    /// Hermetic test seam — accepts a mock token and creates a legacy
    /// session via the backend's `/session/create` endpoint. No CLI flag
    /// exposes this; only `cli_tests.rs` constructs it. Production
    /// deployments cannot use this mode at all.
    #[doc(hidden)]
    ImportLegacyMock(String),
}

pub async fn cmd_init(ctx: &CommandContext, mode: InitMode) -> Result<(String, Session)> {
    match mode {
        InitMode::ImportLegacyMock(token) => init_legacy_mock(ctx, token).await,
        InitMode::Email {
            email,
            broker_url,
            signer_url,
            chain_id,
            poll_timeout_seconds,
        } => {
            init_via_email_link(
                ctx,
                &email,
                &broker_url,
                &signer_url,
                chain_id,
                poll_timeout_seconds,
            )
            .await
        }
        InitMode::Oauth2Google {
            broker_url,
            signer_url,
            chain_id,
            poll_timeout_seconds,
        } => {
            init_via_oauth2_google(
                ctx,
                &broker_url,
                &signer_url,
                chain_id,
                poll_timeout_seconds,
            )
            .await
        }
    }
}

/// Test-only: legacy `/session/create` path. Production cannot reach this
/// (CLI surface drops `--mock-token`).
async fn init_legacy_mock(ctx: &CommandContext, token: String) -> Result<(String, Session)> {
    if ctx.verbose {
        eprintln!("[verbose] POST {}/session/create", ctx.backend_url);
        eprintln!("[verbose] auth_token: {}", token);
    }

    let backend = ctx.backend();
    let (session, wallet) = backend
        .create_session(AuthToken::Mock(token))
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

/// Email-link bootstrap delegates to `init_flow::init_via_email_link`.
async fn init_via_email_link(
    ctx: &CommandContext,
    email: &str,
    broker_url: &str,
    signer_url: &str,
    chain_id: u64,
    poll_timeout_seconds: u64,
) -> Result<(String, Session)> {
    eprintln!("Magic link sent to {email}. Click the link in your inbox; the CLI is polling…");
    let result = init_flow::init_via_email_link(
        broker_url,
        signer_url,
        email,
        chain_id,
        std::time::Duration::from_secs(poll_timeout_seconds),
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;

    ctx.session_store()
        .save(&result.session, &ctx.session_id)
        .context("save EVM session to keychain")?;
    let msg = format!(
        "Initialized via email-link.\n  identity omni: {}\n  derived wallet: {}\n  evm omni:      {}",
        result.identity_omni, result.derived_wallet, result.evm_omni
    );
    Ok((msg, result.session))
}

/// OAuth2/Google bootstrap delegates to `init_flow::start_oauth2_google` +
/// `complete_oauth2_google`.
async fn init_via_oauth2_google(
    ctx: &CommandContext,
    broker_url: &str,
    signer_url: &str,
    chain_id: u64,
    poll_timeout_seconds: u64,
) -> Result<(String, Session)> {
    let start = init_flow::start_oauth2_google(broker_url)
        .await
        .map_err(|e| anyhow!("{}", e))?;
    eprintln!("Open this URL in your browser to authenticate with Google:");
    eprintln!("  {}", start.authorization_url);
    eprintln!("(Polling for callback…)");

    let result = init_flow::complete_oauth2_google(
        broker_url,
        signer_url,
        &start.request_id,
        chain_id,
        std::time::Duration::from_secs(poll_timeout_seconds),
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;

    ctx.session_store()
        .save(&result.session, &ctx.session_id)
        .context("save EVM session to keychain")?;
    let msg = format!(
        "Initialized via OAuth2-Google.\n  identity omni: {}\n  derived wallet: {}\n  evm omni:      {}",
        result.identity_omni, result.derived_wallet, result.evm_omni
    );
    Ok((msg, result.session))
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
                agentkeys_types::AgentIdentity::OAuth2 { provider, sub } => {
                    format!("oauth2_{provider}:{sub}")
                }
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

    let env = match broker_env_for_provision(ctx.broker_url.as_deref(), &session.token).await {
        Ok(env) => env,
        Err(e) => {
            return Err(anyhow!(
                "Problem: Could not fetch AWS credentials from broker.\nCause: {}.\nFix: Verify --broker-url / AGENTKEYS_BROKER_URL is reachable, your session token is current, and the broker's /readyz endpoint returns 200.\nDocs: https://github.com/litentry/agentKeys/blob/main/docs/operator-runbook-stage7.md",
                e
            ));
        }
    };

    let result = run_provision(
        &provisioner,
        service,
        &cmd_refs,
        env,
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

pub async fn cmd_inbox_provision(ctx: &CommandContext, agent: Option<&str>) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent).await?;

    if ctx.verbose {
        eprintln!("[verbose] POST {}/mock/inbox/provision", ctx.backend_url);
        eprintln!("[verbose] agent: {}", agent_id.0);
    }

    let address = backend
        .provision_inbox(&session, &agent_id)
        .await
        .map_err(wrap_backend_error)?;

    Ok(address.to_string())
}

pub async fn cmd_inbox_list(ctx: &CommandContext, agent: Option<&str>) -> Result<String> {
    let session = ctx.load_session().context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent).await?;

    if ctx.verbose {
        eprintln!("[verbose] GET {}/mock/inbox/list", ctx.backend_url);
        eprintln!("[verbose] agent: {}", agent_id.0);
    }

    let addresses = backend
        .list_inboxes(&session, &agent_id)
        .await
        .map_err(wrap_backend_error)?;

    Ok(addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("\n"))
}

/// `agentkeys signer derive` — call `/dev/derive-address` on the configured
/// signer for `omni_account` and print the derived EVM address.
///
/// The CLI treats the signer as opaque RPC: this command does not assume
/// HKDF-vs-TEE; it only enforces the wire contract from
/// `docs/spec/signer-protocol.md`. Issue #74 step 2 swaps the implementation
/// behind `signer_url`; this command keeps working unchanged.
///
/// The saved session JWT is attached as a bearer token so the signer can
/// verify the request. If no session is saved, the command fails with a
/// clear message to run `agentkeys init` first.
pub async fn cmd_signer_derive(
    ctx: &CommandContext,
    signer_url: &str,
    omni_account: &str,
) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let client = HttpSignerClient::new(signer_url).with_session_jwt(session.token);
    let derived = client
        .derive_address(omni_account)
        .await
        .map_err(format_signer_error)?;
    if ctx.json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "address":     derived.address,
            "key_version": derived.key_version,
        }))
        .unwrap())
    } else {
        Ok(format!(
            "address={} key_version={}",
            derived.address, derived.key_version
        ))
    }
}

/// `agentkeys signer sign` — call `/dev/sign-message` on the configured
/// signer for `omni_account || message_utf8`, returning the canonical
/// 65-byte EIP-191 signature plus the derived address.
///
/// The saved session JWT is attached as a bearer token so the signer can
/// verify the request. If no session is saved, the command fails with a
/// clear message to run `agentkeys init` first.
pub async fn cmd_signer_sign(
    ctx: &CommandContext,
    signer_url: &str,
    omni_account: &str,
    message: &str,
) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let client = HttpSignerClient::new(signer_url).with_session_jwt(session.token);
    let signed = client
        .sign_eip191(omni_account, message.as_bytes())
        .await
        .map_err(format_signer_error)?;
    if ctx.json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "signature":   signed.signature,
            "address":     signed.address,
            "key_version": signed.key_version,
        }))
        .unwrap())
    } else {
        Ok(format!(
            "signature={} address={} key_version={}",
            signed.signature, signed.address, signed.key_version
        ))
    }
}

/// `agentkeys whoami` — read-only summary of the current session and the
/// signer-derived wallet address (if a signer URL is supplied and the
/// session carries an `omni_account` claim).
///
/// In v0 the legacy session does not carry an omni_account, so this command
/// requires `--omni-account` explicitly when `--signer-url` is set. After
/// the daemon flow lands fully (issue #74 step 1 completion), the omni
/// will come from the session itself.
pub async fn cmd_whoami(
    ctx: &CommandContext,
    signer_url: Option<&str>,
    omni_account: Option<&str>,
) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;

    let mut out = serde_json::Map::new();
    out.insert("session_wallet".into(), json!(session.wallet.0));
    if let Some(scope) = &session.scope {
        out.insert(
            "scope_services".into(),
            json!(scope
                .services
                .iter()
                .map(|s| s.0.clone())
                .collect::<Vec<_>>()),
        );
        out.insert("scope_read_only".into(), json!(scope.read_only));
    }

    if let Some(url) = signer_url {
        let omni = omni_account.ok_or_else(|| {
            anyhow!("--signer-url requires --omni-account (will be derived from session in a later issue-74 step)")
        })?;
        let client = HttpSignerClient::new(url).with_session_jwt(session.token.clone());
        let derived = client
            .derive_address(omni)
            .await
            .map_err(format_signer_error)?;
        out.insert("omni_account".into(), json!(omni));
        out.insert("derived_address".into(), json!(derived.address));
        out.insert("key_version".into(), json!(derived.key_version));
    }

    if ctx.json_output {
        Ok(serde_json::to_string_pretty(&serde_json::Value::Object(out)).unwrap())
    } else {
        let mut lines = Vec::new();
        lines.push(format!("session_wallet: {}", session.wallet.0));
        if let Some(scope) = &session.scope {
            let svc: Vec<&str> = scope.services.iter().map(|s| s.0.as_str()).collect();
            lines.push(format!("scope: [{}] read_only={}", svc.join(", "), scope.read_only));
        }
        if let Some(url) = signer_url {
            lines.push(format!("signer_url: {}", url));
            if let Some(o) = omni_account {
                lines.push(format!("omni_account: {}", o));
            }
            if let Some(v) = out.get("derived_address") {
                lines.push(format!("derived_address: {}", v.as_str().unwrap_or("?")));
            }
            if let Some(v) = out.get("key_version") {
                lines.push(format!("key_version: {}", v));
            }
        }
        Ok(lines.join("\n"))
    }
}

fn format_signer_error(e: SignerClientError) -> anyhow::Error {
    match e {
        SignerClientError::SignerDisabled(m) => anyhow!(
            "Error: SIGNER_DISABLED\n  {}\n\n  Fix: set DEV_KEY_SERVICE_MASTER_SECRET on the mock-server (or attest the TEE worker once issue #74 step 2 ships).",
            m
        ),
        SignerClientError::Unauthorized(m) => anyhow!(
            "Error: SIGNER_UNAUTHORIZED\n  {}\n\n  Fix: run `agentkeys init` to obtain a fresh session JWT.",
            m
        ),
        SignerClientError::InvalidOmniAccount(m) => {
            anyhow!("Error: INVALID_OMNI_ACCOUNT\n  {}", m)
        }
        SignerClientError::InvalidMessageHex(m) => {
            anyhow!("Error: INVALID_MESSAGE_HEX\n  {}", m)
        }
        SignerClientError::Internal(m) => anyhow!("Error: SIGNER_INTERNAL\n  {}", m),
        SignerClientError::Transport(m) => anyhow!(
            "Error: SIGNER_UNREACHABLE\n  {}\n\n  Fix: confirm --signer-url is reachable.",
            m
        ),
        SignerClientError::Unexpected { status, error, message } => anyhow!(
            "Error: SIGNER_UNEXPECTED\n  status={} error={:?} message={:?}",
            status,
            error,
            message
        ),
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
