use std::collections::HashMap;
use std::sync::Arc;

pub mod agent_admin;
pub mod device_session;
pub mod hook;
pub mod k11;
pub mod k11_intent;
pub mod k11_webauthn;
pub mod wire;

use agentkeys_core::actor_omni::actor_omni_hex;
use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_core::init_flow;
use agentkeys_core::mock_client::MockHttpClient;
use agentkeys_core::s3_backend::{S3CredentialBackend, WriteEnvelope};
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
use agentkeys_types::{AuthToken, Scope, ServiceName, Session, WalletAddress};
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

/// Which `CredentialBackend` impl `agentkeys` should route credential CRUD
/// through. The legacy `Http` impl talks to the mock-server's
/// `/credential/*` endpoints; `S3` (issue #85) PUT/GETs encrypted blobs at
/// `s3://$BUCKET/bots/<wallet|actor_omni>/credentials/<service>.enc`.
/// `Sidecar` is the stage-1-v2 target (localhost daemon proxy mints
/// cap-tokens against the on-chain ScopeContract + SidecarRegistry); it is
/// declared here so the CLI surface is forward-compatible, but the daemon
/// implementation lands in a follow-up — calling it today returns a clear
/// "not yet implemented" error rather than silently falling back to a
/// weaker mode. Every other trait method (sessions, audit, identity,
/// scope, inbox, rendezvous, auth-requests) still goes through
/// `MockHttpClient` regardless of this flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBackendKind {
    Http,
    S3,
    Sidecar,
}

impl CredentialBackendKind {
    /// Parse the `--credential-backend` flag (case-insensitive). Unknown
    /// values return a clear operator-facing error instead of silently
    /// falling back, so a typo doesn't pretend it picked a default.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "http" | "mock" => Ok(Self::Http),
            "s3" => Ok(Self::S3),
            "sidecar" => Ok(Self::Sidecar),
            other => Err(anyhow!(
                "unknown --credential-backend '{}': expected 'http', 's3', or 'sidecar'",
                other
            )),
        }
    }
}

/// Which envelope format the S3 backend writes. Defaults to `V1` to keep
/// existing #87 deployments working unchanged; operators opt in to `V2`
/// once they've finished the dual-tag + bucket-policy migration steps in
/// `docs/spec/plans/v2-issues/issue-v2-stage-1-foundation.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeVersionFlag {
    V1,
    V2,
}

impl EnvelopeVersionFlag {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "v1" | "1" => Ok(Self::V1),
            "v2" | "2" => Ok(Self::V2),
            other => Err(anyhow!(
                "unknown --envelope-version '{}': expected 'v1' or 'v2'",
                other
            )),
        }
    }

    fn to_write_envelope(self) -> WriteEnvelope {
        match self {
            Self::V1 => WriteEnvelope::V1,
            Self::V2 => WriteEnvelope::V2,
        }
    }
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
    /// Issue #85: which `CredentialBackend` impl handles credential CRUD.
    /// Defaults to `Http` for backwards-compat during the migration window.
    pub credential_backend: CredentialBackendKind,
    /// Issue #85: S3 bucket holding `bots/<wallet>/credentials/<service>.enc`.
    /// Defaults to `AGENTKEYS_BUCKET` env var, same name cloud-setup.md
    /// uses. Required when `credential_backend == S3`.
    pub data_bucket: Option<String>,
    /// Issue #85: AWS region for the S3 client. `None` falls back to the
    /// SDK default chain (`AWS_REGION` or shared config).
    pub data_region: Option<String>,
    /// Issue #85: signer base URL for `/dev/sign-message`-driven KEK
    /// derivation. Required when `credential_backend == S3`.
    pub signer_url: Option<String>,
    /// Issue #85: 64-lowercase-hex `omni_account`, the derivation domain
    /// the signer keys off. Required when `credential_backend == S3`.
    /// Issue #74 step 2 will pull this from the session JWT directly; this
    /// is a temporary operator-supplied bridge.
    pub omni_account: Option<String>,
    /// v2 stage 1: which envelope shape `--credential-backend=s3` writes.
    /// Defaults to `V1` so legacy #87 deployments keep working; flip to
    /// `V2` per-operator post-migration. Reads always accept both formats
    /// — only writes care about this flag.
    pub envelope_version: EnvelopeVersionFlag,
    /// v2 stage 1: which EVM chain backbone to talk to. Resolved per
    /// `ChainProfile::resolve` order — CLI `--chain` flag wins over
    /// `$AGENTKEYS_CHAIN` env over the built-in default `heima`.
    /// `None` means "not yet resolved" — call `chain_profile()` to
    /// materialize. Cached after first resolution.
    pub chain_profile_cli_name: Option<String>,
    cached_chain_profile: std::sync::OnceLock<ChainProfile>,
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
            broker_url: std::env::var("AGENTKEYS_BROKER_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            credential_backend: CredentialBackendKind::Http,
            data_bucket: std::env::var("AGENTKEYS_BUCKET")
                .ok()
                .filter(|s| !s.is_empty()),
            data_region: std::env::var("AWS_REGION")
                .ok()
                .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
                .filter(|s| !s.is_empty()),
            signer_url: std::env::var("AGENTKEYS_SIGNER_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            omni_account: std::env::var("AGENTKEYS_OMNI_ACCOUNT")
                .ok()
                .filter(|s| !s.is_empty()),
            envelope_version: EnvelopeVersionFlag::V1,
            chain_profile_cli_name: None,
            cached_chain_profile: std::sync::OnceLock::new(),
        }
    }

    pub fn with_envelope_version(mut self, v: EnvelopeVersionFlag) -> Self {
        self.envelope_version = v;
        self
    }

    pub fn with_chain_profile_name(mut self, name: Option<String>) -> Self {
        self.chain_profile_cli_name = name.filter(|s| !s.is_empty());
        self.cached_chain_profile = std::sync::OnceLock::new();
        self
    }

    /// Resolve the chain profile per the documented precedence
    /// (`--chain` > `$AGENTKEYS_CHAIN` > `$AGENTKEYS_CHAIN_PROFILE_FILE` >
    /// built-in default `heima`). Cached after first call so verbose
    /// output doesn't print the resolution debug string twice.
    pub fn chain_profile(&self) -> Result<&ChainProfile> {
        if let Some(p) = self.cached_chain_profile.get() {
            return Ok(p);
        }
        let env_name = std::env::var("AGENTKEYS_CHAIN").ok();
        let env_file = std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE").ok();
        let (profile, why) = ChainProfile::resolve(
            self.chain_profile_cli_name.as_deref(),
            env_name.as_deref(),
            env_file.as_deref(),
        )
        .map_err(|e| anyhow!("failed to resolve chain profile: {e}"))?;
        if self.verbose {
            eprintln!(
                "[verbose] chain profile: {} (chain_id={}) — {}",
                profile.name, profile.chain_id, why
            );
        }
        let _ = self.cached_chain_profile.set(profile);
        Ok(self.cached_chain_profile.get().unwrap())
    }

    pub fn with_broker_url(mut self, broker_url: Option<String>) -> Self {
        self.broker_url = broker_url;
        self
    }

    pub fn with_credential_backend(mut self, kind: CredentialBackendKind) -> Self {
        self.credential_backend = kind;
        self
    }

    pub fn with_data_bucket(mut self, bucket: Option<String>) -> Self {
        self.data_bucket = bucket;
        self
    }

    pub fn with_signer_url(mut self, signer_url: Option<String>) -> Self {
        self.signer_url = signer_url;
        self
    }

    pub fn with_omni_account(mut self, omni: Option<String>) -> Self {
        self.omni_account = omni;
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

    /// Synchronous backend used by every CLI command that does NOT touch
    /// credential CRUD (sessions, audit, identity, scope, rendezvous,
    /// inbox). `--credential-backend s3` does NOT change this — those
    /// endpoints still live on the legacy mock-server. See
    /// `credential_backend()` for the credential-CRUD path.
    fn backend(&self) -> Arc<dyn CredentialBackend> {
        if let Some(ref b) = self.backend_override {
            b.clone()
        } else {
            Arc::new(MockHttpClient::new(&self.backend_url))
        }
    }

    /// Backend handling credential CRUD (`store_credential`,
    /// `read_credential`, `teardown_agent`, `list_credentials`). When
    /// `--credential-backend s3` is selected, builds an
    /// `S3CredentialBackend` against `AGENTKEYS_BUCKET` + signer. Falls
    /// back to the `Http` (mock-server) path otherwise.
    ///
    /// **AWS-creds resolution (issue #85 / codex adversarial review).**
    /// When `--broker-url` is set, this method *mints fresh
    /// OIDC-scoped AWS temp creds via the broker* and injects them
    /// directly into the S3 client. That's the only way to keep the
    /// `agentkeys_user_wallet` PrincipalTag isolation property: relying
    /// on `aws_config::defaults` would let the operator's *static* AWS
    /// admin creds drive the S3 PUT (no PrincipalTag, no per-operator
    /// scoping). It also avoids the trap where `cmd_provision` minted
    /// creds only for the scraper subprocess env, leaving the parent
    /// process's `S3CredentialBackend` with no creds at all.
    ///
    /// Without `--broker-url` the backend falls back to
    /// `aws_config::defaults` (process AWS_* env or shared config) —
    /// fine for callers who already exported `AWS_*` manually.
    ///
    /// Async because both the broker JWT-mint + STS exchange and the
    /// AWS SDK config loader are async.
    async fn credential_backend(&self) -> Result<Arc<dyn CredentialBackend>> {
        if let Some(ref b) = self.backend_override {
            return Ok(b.clone());
        }
        match self.credential_backend {
            CredentialBackendKind::Http => Ok(Arc::new(MockHttpClient::new(&self.backend_url))),
            CredentialBackendKind::S3 => {
                let bucket = self
                    .data_bucket
                    .clone()
                    .ok_or_else(|| anyhow!(
                        "--credential-backend=s3 requires --bucket or AGENTKEYS_BUCKET env"
                    ))?;
                let signer_url = self
                    .signer_url
                    .clone()
                    .ok_or_else(|| anyhow!(
                        "--credential-backend=s3 requires --signer-url or AGENTKEYS_SIGNER_URL env (for client-side KEK derivation)"
                    ))?;
                let omni = self
                    .omni_account
                    .clone()
                    .ok_or_else(|| anyhow!(
                        "--credential-backend=s3 requires --omni-account or AGENTKEYS_OMNI_ACCOUNT env (until issue #74 step 2 persists omni in the session JWT)"
                    ))?;
                let session_token = self.load_session().ok().map(|s| s.token);
                let mut signer = HttpSignerClient::new(&signer_url);
                if let Some(ref tok) = session_token {
                    signer = signer.with_session_jwt(tok.clone());
                }

                let aws_creds = self.mint_s3_credentials(session_token.as_deref()).await?;

                let backend = S3CredentialBackend::new(
                    bucket,
                    self.data_region.as_deref(),
                    aws_creds,
                    Arc::new(signer),
                    omni,
                )
                .await
                .with_write_envelope(self.envelope_version.to_write_envelope());
                Ok(Arc::new(backend))
            }
            CredentialBackendKind::Sidecar => Err(anyhow!(
                "--credential-backend=sidecar is not yet wired through. The daemon proxy + broker cap-mint endpoints + credentials-worker are shipped \
                 (run `agentkeys-daemon proxy` + `agentkeys-broker-server` + `agentkeys-worker-creds`), but the CLI→daemon `/v1/cred/*` handoff isn't stitched yet. \
                 Tracked in #91. For stage-1 use --credential-backend=s3 with --envelope-version=v2 (actor_omni-keyed paths, same envelope bytes the worker would write) \
                 or --credential-backend=http for the legacy mock-server."
            )),
        }
    }

    /// Mint broker-scoped AWS temp creds for the S3 client when the
    /// operator has a Stage-7 broker configured. When not configured,
    /// return `None` so the SDK falls back to its default cred chain.
    ///
    /// Same OIDC + `AssumeRoleWithWebIdentity` path that
    /// `broker_env_for_provision` uses for the scraper subprocess.
    /// `cmd_provision` ends up making two STS calls per run (one for
    /// the scraper, one for the parent's S3 client) — that's cheap
    /// (each session lasts an hour) and the alternative is threading
    /// the creds through the orchestrator just to avoid a second STS
    /// round-trip.
    async fn mint_s3_credentials(
        &self,
        session_token: Option<&str>,
    ) -> Result<Option<aws_credential_types::Credentials>> {
        let Some(broker_url) = self.broker_url.as_deref() else {
            return Ok(None);
        };
        let Some(token) = session_token else {
            return Err(anyhow!(
                "--credential-backend=s3 with --broker-url requires an active session (run `agentkeys init` first)"
            ));
        };
        let role_arn = std::env::var("AGENTKEYS_DATA_ROLE_ARN").map_err(|_| anyhow!(
            "--credential-backend=s3 with --broker-url requires AGENTKEYS_DATA_ROLE_ARN env (issue #71 Option A)"
        ))?;
        let region = self
            .data_region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());
        let temp = fetch_via_broker_default_ttl(broker_url, token, &role_arn, &region).await?;
        // Convert the broker-minted creds into the SDK's canonical
        // `Credentials` type so we can plug them directly into the S3
        // config builder. The expiration is informational — the SDK
        // doesn't refresh static creds, but with a 1h TTL the parent
        // process's S3 client won't outlive a single CLI invocation.
        let expiry = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(temp.expiration.max(0) as u64);
        Ok(Some(aws_credential_types::Credentials::new(
            temp.access_key_id,
            temp.secret_access_key,
            Some(temp.session_token),
            Some(expiry),
            "agentkeys-broker-oidc",
        )))
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
/// - anything else errors; alias/email lookup retired in issue #77.
fn resolve_agent(
    _backend: &Arc<dyn CredentialBackend>,
    session: &Session,
    agent: Option<&str>,
) -> Result<WalletAddress> {
    match agent {
        None => Ok(session.wallet.clone()),
        Some(arg) if arg.starts_with("0x") => Ok(WalletAddress(arg.to_string())),
        Some(arg) => Err(anyhow!(
            "unknown identity '{}'. Pass a raw 0x... wallet address (alias/email lookup retired in issue #77).",
            arg
        )),
    }
}

pub async fn cmd_store(
    ctx: &CommandContext,
    agent: Option<&str>,
    service: &str,
    key: &str,
) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    // Identity resolution (alias / email → wallet) always goes through the
    // legacy backend — issue #85's S3 path only handles credential CRUD.
    let id_backend = ctx.backend();
    let agent_id = resolve_agent(&id_backend, &session, agent)?;
    let service_name = ServiceName(service.to_string());
    let cred_backend = ctx.credential_backend().await?;

    if ctx.verbose {
        match ctx.credential_backend {
            CredentialBackendKind::Http => {
                eprintln!("[verbose] POST {}/credential/store", ctx.backend_url);
            }
            CredentialBackendKind::S3 => {
                let prefix = match ctx.envelope_version {
                    EnvelopeVersionFlag::V1 => agent_id.0.to_lowercase(),
                    EnvelopeVersionFlag::V2 => actor_omni_hex(&agent_id),
                };
                eprintln!(
                    "[verbose] PUT s3://{}/bots/{}/credentials/{}.enc (envelope={:?})",
                    ctx.data_bucket.as_deref().unwrap_or("?"),
                    prefix,
                    service,
                    ctx.envelope_version,
                );
            }
            CredentialBackendKind::Sidecar => {
                eprintln!("[verbose] PUT (sidecar) — not yet implemented");
            }
        }
        eprintln!("[verbose] agent: {}, service: {}", agent_id.0, service);
    }

    cred_backend
        .store_credential(&session, &agent_id, &service_name, key.as_bytes())
        .await
        .map_err(wrap_backend_error)?;

    Ok(format!(
        "Stored credential for agent={} service={}",
        agent_id.0, service
    ))
}

pub async fn cmd_read(ctx: &CommandContext, agent: Option<&str>, service: &str) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let id_backend = ctx.backend();
    let agent_id = resolve_agent(&id_backend, &session, agent)?;
    let service_name = ServiceName(service.to_string());
    let cred_backend = ctx.credential_backend().await?;

    if ctx.verbose {
        match ctx.credential_backend {
            CredentialBackendKind::Http => {
                eprintln!("[verbose] GET {}/credential/read", ctx.backend_url);
            }
            CredentialBackendKind::S3 => {
                // Reads try v2 first then fall back to v1 — surface both
                // paths so operators can correlate verbose output with
                // ListObjectsV2 in CloudTrail.
                eprintln!(
                    "[verbose] GET s3://{bucket}/bots/{omni}/credentials/{service}.enc (v2; falls back to wallet={wallet})",
                    bucket = ctx.data_bucket.as_deref().unwrap_or("?"),
                    omni = actor_omni_hex(&agent_id),
                    service = service,
                    wallet = agent_id.0.to_lowercase(),
                );
            }
            CredentialBackendKind::Sidecar => {
                eprintln!("[verbose] GET (sidecar) — not yet implemented");
            }
        }
        eprintln!("[verbose] agent: {}, service: {}", agent_id.0, service);
    }

    let bytes = cred_backend
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

    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let id_backend = ctx.backend();
    let agent_id = resolve_agent(&id_backend, &session, agent)?;
    let backend = ctx.credential_backend().await?;

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
    let mut fetched: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut env_vars: Vec<(String, String)> = Vec::new();
    let mut credential_errors: Vec<String> = Vec::new();
    for service in &services_to_try {
        let service_name = ServiceName(service.clone());
        match backend
            .read_credential(&session, &agent_id, &service_name)
            .await
        {
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
        let eq_pos = raw
            .find('=')
            .expect("pre-flight validation already rejected entries without '='");
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
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;

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
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let agent_id = WalletAddress(agent.to_string());

    if ctx.verbose {
        match ctx.credential_backend {
            CredentialBackendKind::Http => {
                eprintln!("[verbose] DELETE {}/credential/teardown", ctx.backend_url);
            }
            CredentialBackendKind::S3 => {
                let wallet_addr = WalletAddress(agent.to_string());
                eprintln!(
                    "[verbose] DELETE s3://{}/bots/{{{wallet},{omni}}}/credentials/*",
                    ctx.data_bucket.as_deref().unwrap_or("?"),
                    wallet = agent.to_lowercase(),
                    omni = actor_omni_hex(&wallet_addr),
                );
            }
            CredentialBackendKind::Sidecar => {
                eprintln!("[verbose] DELETE (sidecar) — not yet implemented");
            }
        }
        eprintln!("[verbose] agent: {}", agent);
    }

    ctx.credential_backend()
        .await?
        .teardown_agent(&session, &agent_id)
        .await
        .map_err(wrap_backend_error)?;

    Ok(format!("Torn down agent={}", agent))
}

pub async fn cmd_approve(ctx: &CommandContext, pair_code: &str, auto_yes: bool) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;

    if ctx.verbose {
        eprintln!(
            "[verbose] GET {}/auth-request/fetch?pair_code={}",
            ctx.backend_url, pair_code
        );
    }

    let auth_request = ctx
        .backend()
        .fetch_auth_request(&session, &agentkeys_types::PairCode(pair_code.to_string()))
        .await
        .map_err(wrap_backend_error)?;

    let request_type_display = match &auth_request.request_type {
        agentkeys_types::AuthRequestType::Pair { requested_scope } => {
            if requested_scope.services.is_empty() {
                "Pair new agent (all services)".to_string()
            } else {
                let services: Vec<&str> = requested_scope
                    .services
                    .iter()
                    .map(|s| s.0.as_str())
                    .collect();
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
        agentkeys_types::AuthRequestType::HighValueRelease {
            agent_id, service, ..
        } => {
            format!(
                "High-value release: agent {} service {}",
                agent_id.0, service.0
            )
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

fn resolve_agent_to_wallet(
    _ctx: &CommandContext,
    _session: &Session,
    agent: &str,
) -> Result<String> {
    if agent.starts_with("0x") {
        Ok(agent.to_string())
    } else {
        Err(anyhow!(
            "Agent must be a raw 0x wallet address. Alias/email lookup is no longer supported."
        ))
    }
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

    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let target_wallet = WalletAddress(resolve_agent_to_wallet(ctx, &session, agent)?);
    let backend = ctx.backend();

    let current_scope = backend
        .get_scope(&session, &target_wallet)
        .await
        .map_err(wrap_backend_error)?
        .unwrap_or(Scope {
            services: vec![],
            read_only: false,
        });

    if list {
        let service_names: Vec<&str> = current_scope
            .services
            .iter()
            .map(|s| s.0.as_str())
            .collect();
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
        Scope {
            services,
            read_only: current_scope.read_only,
        }
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
        Scope {
            services,
            read_only: current_scope.read_only,
        }
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
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let backend = ctx.credential_backend().await?;
    let agent_id = session.wallet.clone();

    if force {
        eprintln!("existing key present — re-provisioning (--force)");
    }

    let provisioner = provisioner.unwrap_or_else(|| Arc::new(Provisioner::new()));

    // Issue #83 — non-CDP `openrouter.ts` is stale (signup_email_otp pattern
    // against a flow that's now Clerk+password+magic-link). Route through the
    // CDP variant which already handles the current flow. Prereq: Chrome on
    // CDP_URL (default http://localhost:9222) — see
    // `scripts/reset-chrome-for-recording.sh` or `agentkeys-provision-demo.sh`.
    let script_command: Vec<String> = match service {
        "openrouter" => vec![
            "npx".to_string(),
            "tsx".to_string(),
            "provisioner-scripts/src/scrapers/openrouter-cdp.ts".to_string(),
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
        Err(e) => Err(anyhow!("{}", format_provision_error(&e))),
    }
}

pub async fn cmd_inbox_provision(ctx: &CommandContext, agent: Option<&str>) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent)?;

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
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;
    let backend = ctx.backend();
    let agent_id = resolve_agent(&backend, &session, agent)?;

    if ctx.verbose {
        eprintln!("[verbose] GET {}/mock/inbox/list", ctx.backend_url);
        eprintln!("[verbose] agent: {}", agent_id.0);
    }

    let addresses = backend
        .list_inboxes(&session, &agent_id)
        .await
        .map_err(wrap_backend_error)?;

    Ok(addresses
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join("\n"))
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

/// `agentkeys signer sign-typed-data` — call `/dev/sign-typed-data` on the
/// configured signer (issue #82). Reads an EIP-712 v4 JSON file (the same
/// shape MetaMask's `eth_signTypedData_v4` takes), forwards it to the
/// signer, prints the signature + each digest the signer computed.
///
/// With `--preview-7730`, the CLI also renders the operator-facing intent
/// text against the bundled ERC-7730 catalog (or the dir at
/// `$AGENTKEYS_7730_DIR`) and prints it before signing — closes the "agent
/// signed 0xdead…beef without me knowing what it was" gap that the original
/// issue #82 calls out.
pub async fn cmd_signer_sign_typed_data(
    ctx: &CommandContext,
    signer_url: &str,
    omni_account: &str,
    typed_data_file: &str,
    preview_7730: bool,
) -> Result<String> {
    let session = ctx
        .load_session()
        .context("load session (run `agentkeys init` first)")?;

    let json = std::fs::read_to_string(typed_data_file)
        .with_context(|| format!("read typed-data file {typed_data_file}"))?;
    let typed_data: agentkeys_core::clear_signing::TypedData =
        serde_json::from_str(&json).context("parse typed-data JSON")?;

    let mut preview_block: Option<agentkeys_core::clear_signing::ClearSigningPreview> = None;
    if preview_7730 {
        let catalog = load_default_catalog().context("load ERC-7730 catalog")?;
        match agentkeys_core::clear_signing::build_preview(&catalog, typed_data.clone()) {
            Ok(p) => preview_block = Some(p),
            Err(e) => eprintln!(
                "agentkeys signer sign-typed-data: ERC-7730 preview not available ({e}); signing without operator intent text"
            ),
        }
    }

    let client = HttpSignerClient::new(signer_url).with_session_jwt(session.token);
    let signed = client
        .sign_eip712(omni_account, &typed_data)
        .await
        .map_err(format_signer_error)?;

    if ctx.json_output {
        let mut body = json!({
            "signature":          signed.signature,
            "address":            signed.address,
            "primary_type_hash":  signed.primary_type_hash,
            "domain_separator":   signed.domain_separator,
            "digest":             signed.digest,
            "key_version":        signed.key_version,
        });
        if let Some(p) = preview_block.as_ref() {
            body["intent_text"] = json!(p.intent_text);
            body["intent_commitment"] = json!(format!("0x{}", hex::encode(p.intent_commitment)));
        }
        Ok(serde_json::to_string_pretty(&body).unwrap())
    } else {
        let mut out = String::new();
        if let Some(p) = preview_block.as_ref() {
            out.push_str("Operator intent (ERC-7730):\n  ");
            out.push_str(&p.intent_text);
            out.push_str("\n\nFields:\n");
            for (l, v) in &p.fields {
                out.push_str(&format!("  - {l}: {v}\n"));
            }
            out.push_str(&format!(
                "\nIntent commitment: 0x{}\n\n",
                hex::encode(p.intent_commitment)
            ));
        }
        out.push_str(&format!(
            "signature={}\naddress={}\nprimary_type_hash={}\ndomain_separator={}\ndigest={}\nkey_version={}",
            signed.signature,
            signed.address,
            signed.primary_type_hash,
            signed.domain_separator,
            signed.digest,
            signed.key_version,
        ));
        Ok(out)
    }
}

/// `agentkeys signer preview-7730` — render the operator-facing preview for
/// a typed-data JSON file WITHOUT signing (issue #82). Useful for dry-runs
/// against new ERC-7730 files before plumbing them into automated agent
/// signing.
pub async fn cmd_signer_preview_7730(
    ctx: &CommandContext,
    typed_data_file: &str,
    seven_thirty_file: Option<&str>,
) -> Result<String> {
    let json = std::fs::read_to_string(typed_data_file)
        .with_context(|| format!("read typed-data file {typed_data_file}"))?;
    let typed_data: agentkeys_core::clear_signing::TypedData =
        serde_json::from_str(&json).context("parse typed-data JSON")?;

    let catalog = match seven_thirty_file {
        Some(path) => {
            let raw =
                std::fs::read_to_string(path).with_context(|| format!("read 7730 file {path}"))?;
            let file = agentkeys_core::clear_signing::parser::parse(&raw)
                .map_err(|e| anyhow!("parse 7730 file: {e}"))?;
            let mut c = agentkeys_core::clear_signing::ClearSigningCatalog::empty();
            c.push(file);
            c
        }
        None => load_default_catalog().context("load default ERC-7730 catalog")?,
    };

    let preview = agentkeys_core::clear_signing::build_preview(&catalog, typed_data)
        .map_err(|e| anyhow!("build preview: {e}"))?;

    if ctx.json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "intent_text":       preview.intent_text,
            "intent_commitment": format!("0x{}", hex::encode(preview.intent_commitment)),
            "domain_separator":  format!("0x{}", hex::encode(preview.digests.domain_separator)),
            "primary_type_hash": format!("0x{}", hex::encode(preview.digests.primary_type_hash)),
            "digest":            format!("0x{}", hex::encode(preview.digests.final_digest)),
            "fields":            preview.fields.iter().map(|(l, v)| json!({"label": l, "value": v})).collect::<Vec<_>>(),
        }))
        .unwrap())
    } else {
        let mut out = String::new();
        out.push_str("Operator intent (ERC-7730):\n  ");
        out.push_str(&preview.intent_text);
        out.push_str("\n\nFields:\n");
        for (l, v) in &preview.fields {
            out.push_str(&format!("  - {l}: {v}\n"));
        }
        out.push_str(&format!(
            "\nDigests:\n  domain_separator:  0x{}\n  primary_type_hash: 0x{}\n  digest:            0x{}\n  intent_commitment: 0x{}",
            hex::encode(preview.digests.domain_separator),
            hex::encode(preview.digests.primary_type_hash),
            hex::encode(preview.digests.final_digest),
            hex::encode(preview.intent_commitment),
        ));
        Ok(out)
    }
}

/// Load the default ERC-7730 catalog: bundled + (if `$AGENTKEYS_7730_DIR`
/// is set) every `*.json` file in that directory. Operators ship their own
/// curated 7730 files via the env var without needing to recompile.
fn load_default_catalog() -> Result<agentkeys_core::clear_signing::ClearSigningCatalog> {
    let mut catalog = agentkeys_core::clear_signing::ClearSigningCatalog::bundled();
    if let Ok(dir) = std::env::var("AGENTKEYS_7730_DIR") {
        if !dir.is_empty() {
            catalog
                .extend_from_dir(&dir)
                .map_err(|e| anyhow!("load 7730 files from $AGENTKEYS_7730_DIR={dir}: {e}"))?;
        }
    }
    Ok(catalog)
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
    // v2 stage 1: arch.md §14.1 names the stable per-operator anchor
    // `actor_omni = SHA256("agentkeys"||"evm"||initial_master_wallet)`.
    // Surface it next to the wallet so operators can sanity-check the
    // bucket-policy PrincipalTag + S3 path their backend will use after
    // the dual-tag migration completes.
    let actor_omni = actor_omni_hex(&session.wallet);
    out.insert("agentkeys_actor_omni".into(), json!(actor_omni));
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
        lines.push(format!("agentkeys_actor_omni: {}", actor_omni));
        if let Some(scope) = &session.scope {
            let svc: Vec<&str> = scope.services.iter().map(|s| s.0.as_str()).collect();
            lines.push(format!(
                "scope: [{}] read_only={}",
                svc.join(", "),
                scope.read_only
            ));
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
        SignerClientError::InvalidTypedData(m) => {
            anyhow!(
                "Error: INVALID_TYPED_DATA\n  {}\n\n  Fix: check the EIP-712 JSON — `types` must include `EIP712Domain`, every type referenced in `primaryType` must be declared, and field values must fit their declared type (uint8 ≤ 255, int8 ∈ [-128, 127], etc.).",
                m
            )
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
        || std::process::Command::new("xdg-open")
            .arg(url)
            .status()
            .is_ok()
        || std::process::Command::new("start")
            .arg(url)
            .status()
            .is_ok();
    if opened {
        format!("Opening {} in your browser", url)
    } else {
        format!("Visit: {}", url)
    }
}
