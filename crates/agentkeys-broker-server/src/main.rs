use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    boot::{run_tier1, Tier2Profile},
    config::BrokerConfig,
    create_router,
    jwt::session::SessionKeypair,
    oidc::OidcKeypair,
    state::{AppState, Tier2State},
    sts::UnavailableStsClient,
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "agentkeys-broker-server",
    about = "AgentKeys credential broker"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(long, default_value = "8091")]
    port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// On boot, write the broker's session keypair **public key** (SPKI PEM,
    /// mode 0644) to this path. The signer service (`--signer-only`) reads
    /// it to verify bearer JWTs without holding the private key.
    ///
    /// Idempotent: re-runs overwrite the file (pubkey is stable unless the
    /// broker keypair is regenerated via `keygen --purpose session`).
    #[arg(long)]
    export_session_pubkey_to: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an ES256 keypair and persist it at --out (mode 0600).
    /// Required before first boot — Plan §6 disables silent generation.
    Keygen {
        /// Which slot the keypair will fill. Determines the persisted
        /// `purpose` tag; mismatched slots are rejected at boot.
        #[arg(long, value_enum)]
        purpose: KeygenPurpose,

        /// Destination path. Parent dirs are created. Existing files are
        /// not overwritten (refuses with an error so a re-run can't
        /// silently rotate keys out from under a running broker).
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum KeygenPurpose {
    Oidc,
    Session,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    match args.command {
        Some(Command::Keygen { purpose, out }) => return run_keygen(purpose, out),
        None => {}
    }
    agentkeys_broker_server::gate_admin::load_gate_admin_config()
        .transpose()
        .map_err(anyhow::Error::msg)?;

    let config = BrokerConfig::from_env()?;

    warn_if_non_loopback_without_tls(&args.bind);

    // Tier 1 — synchronous refuse-to-boot per plan §6. Loads keypairs,
    // validates plugin selection, opens stores, builds registry. Any
    // failure here exits with a single-line BOOT_FAIL message.
    let boot_artifacts = run_tier1(&config)?;

    // Export session pubkey if requested (issue #74 step 1b). Must happen
    // after Tier-1 so the session keypair is loaded. Overwrites on every
    // boot (pubkey is stable unless keygen was re-run).
    if let Some(ref pubkey_path) = args.export_session_pubkey_to {
        let pem = boot_artifacts
            .session_keypair
            .public_key_pem()
            .map_err(|e| anyhow::anyhow!("export session pubkey: {e}"))?;
        if let Some(parent) = pubkey_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create dirs for pubkey export: {e}"))?;
        }
        std::fs::write(pubkey_path, &pem)
            .map_err(|e| anyhow::anyhow!("write session pubkey to {pubkey_path:?}: {e}"))?;
        // mode 0644 so the agentkeys-signer service (same user) can read it
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pubkey_path, std::fs::Permissions::from_mode(0o644))
                .map_err(|e| anyhow::anyhow!("chmod 0644 {pubkey_path:?}: {e}"))?;
        }
        tracing::info!(path = %pubkey_path.display(), "wrote session pubkey PEM (signer can read it)");
    }

    let tier2_profile = Tier2Profile::from_config(&config);
    tracing::info!(
        strict = tier2_profile.strict,
        email_link = tier2_profile.email_link_enabled,
        audit_evm = tier2_profile.audit_evm_enabled,
        "Tier-1 boot complete; Tier-2 reachability checks deferred until after listener bind"
    );

    // Mint-log table opened alongside the plugin-trait audit anchors;
    // /v1/mint-oidc-jwt writes success/failure rows here via record_mint.
    let audit = AuditLog::open(&config.audit_db_path)?;

    let sandbox = agentkeys_broker_server::sandbox_backend::SandboxBackend::from_env()
        .await
        .map_err(|e| std::io::Error::other(format!("sandbox lifecycle config: {e}")))?
        .map(Arc::new);
    match &sandbox {
        Some(b) => tracing::info!(
            backend = %b.kind(),
            runtime = %b.runtime_ref(),
            "local sandbox lifecycle enabled"
        ),
        None => tracing::info!(
            "local sandbox lifecycle disabled; configure AGENT_TERRIER_SANDBOX_IMAGE to enable it"
        ),
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;

    let grace_seconds = config.shutdown_grace_seconds;
    let tier2 = Arc::new(Tier2State::default());

    let state = Arc::new(AppState {
        config,
        http,
        audit,
        sts: Arc::new(UnavailableStsClient),
        oidc: boot_artifacts.oidc_keypair,
        session_keypair: boot_artifacts.session_keypair,
        registry: boot_artifacts.registry,
        audit_policy: boot_artifacts.audit_policy,
        wallet_store: boot_artifacts.wallet_store,
        nonce_store: boot_artifacts.nonce_store,
        spawn_context_store: boot_artifacts.spawn_context_store,
        wake_creates_in_flight: Default::default(),
        identity_link_store: boot_artifacts.identity_link_store,
        pairing_request_store: boot_artifacts.pairing_request_store,
        agent_delegation_store: boot_artifacts.agent_delegation_store,
        sandbox,
        accept_receipts: Default::default(),
        pending_ceremonies: Arc::new(
            agentkeys_broker_server::handlers::spawn::PendingCeremonyStore::new(),
        ),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: Arc::clone(&tier2),
        #[cfg(feature = "auth-email-link")]
        email_link: boot_artifacts.email_link,
        #[cfg(feature = "auth-oauth2")]
        oauth2: boot_artifacts.oauth2,
    });

    // Spawn Tier-2 reachability probes asynchronously. /readyz returns
    // 503 with structured detail until each check passes; broker is
    // already serving /healthz=200 so liveness probes succeed.
    spawn_tier2_probes(Arc::clone(&state), tier2_profile);

    // #594 — auto-relaunch of expired/expiring delegate sandboxes (no-op
    // without a sandbox backend; AGENTKEYS_SANDBOX_AUTORELAUNCH=0 opts out).
    agentkeys_broker_server::lease_sweeper::spawn_if_enabled(Arc::clone(&state));

    let app = create_router(state);
    let addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("{}", serde_json::json!({"listen": listener.local_addr()?}));
    tracing::info!("broker listening on {}", addr);

    let serve_result = tokio::time::timeout(
        std::time::Duration::from_secs(60 * 60 * 24),
        axum::serve(listener, app).with_graceful_shutdown(async move {
            shutdown_signal().await;
            tokio::time::sleep(std::time::Duration::from_secs(grace_seconds)).await;
            tracing::warn!(
                grace_seconds = grace_seconds,
                "shutdown grace expired; forcing exit even if requests are still in flight"
            );
        }),
    )
    .await;

    match serve_result {
        Ok(Ok(())) => tracing::info!("broker shut down cleanly"),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => tracing::error!("broker hit max-uptime timeout (24h serve loop)"),
    }
    Ok(())
}

/// Spawn the Tier-2 reachability probes that flip the AtomicBool flags
/// on `Tier2State` as each external dependency becomes reachable.
///
/// Currently spawns, when email-link auth is compiled in and enabled, the
/// Email sender-verify probe that also persists `SenderVerificationCache` to disk so
/// the email-link plug-in's `Readiness::ready()` flips from `Degraded` to
/// `Ready`. The EVM probe lands in Phase C.
fn spawn_tier2_probes(state: Arc<AppState>, profile: agentkeys_broker_server::boot::Tier2Profile) {
    let _ = (&state, &profile);
    #[cfg(feature = "auth-email-link")]
    if profile.email_link_enabled {
        spawn_sender_verify_probe(Arc::clone(&state), profile.strict);
    }
}

/// Email sender-verify probe. Calls `verify_sender_ready()` on the
/// configured `EmailSender`, persists `SenderVerificationCache` on success so the
/// plug-in's `Readiness` flips to `Ready`, and flips the `tier2/email`
/// `AtomicBool`. Retries with exponential backoff on failure (capped at
/// 5 minutes); after a success, re-verifies every 12h so the cache stays
/// under the plug-in's 24h freshness TTL.
#[cfg(feature = "auth-email-link")]
fn spawn_sender_verify_probe(state: Arc<AppState>, strict: bool) {
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    use agentkeys_broker_server::plugins::auth::SenderVerificationCache;

    let Some(email_link) = state.email_link.clone() else {
        tracing::error!(
            "Tier-2 Email probe: email_link is in BROKER_AUTH_METHODS but the \
             concrete plug-in handle is missing from AppState — /readyz will \
             stay degraded. Indicates a build/config bug."
        );
        return;
    };

    tokio::spawn(async move {
        let mut backoff_seconds: u64 = 30;
        loop {
            match email_link.sender.verify_sender_ready().await {
                Ok(()) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let cache = SenderVerificationCache {
                        last_verified_at: now,
                        sender_email: email_link.from_address.clone(),
                    };
                    match cache.save(&email_link.sender_verify_cache_path) {
                        Ok(()) => {
                            state
                                .tier2
                                .email_sender_ready
                                .store(true, Ordering::Relaxed);
                            tracing::info!(
                                sender = %email_link.from_address,
                                path = %email_link.sender_verify_cache_path.display(),
                                "Tier-2 Email probe: sender verified; cache persisted"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                path = %email_link.sender_verify_cache_path.display(),
                                "Tier-2 Email probe: verify succeeded but cache save failed; auth/email_link readiness will stay degraded"
                            );
                        }
                    }
                    backoff_seconds = 30;
                    tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;
                }
                Err(e) => {
                    if strict {
                        tracing::error!(
                            error = %e,
                            "BROKER_REFUSE_TO_BOOT_STRICT=true and Email sender verify failed; exiting"
                        );
                        std::process::exit(1);
                    }
                    tracing::warn!(
                        error = %e,
                        retry_seconds = backoff_seconds,
                        "Tier-2 Email probe: sender verify failed; /readyz will report unready until verified"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_seconds)).await;
                    backoff_seconds = (backoff_seconds * 2).min(300);
                }
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect(
                "failed to register SIGTERM handler — running in a sandbox that blocks signals?",
            );
        sig.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

fn run_keygen(purpose: KeygenPurpose, out: PathBuf) -> anyhow::Result<()> {
    if out.exists() {
        anyhow::bail!(
            "{} already exists; refusing to overwrite. Move/remove the existing file first if rotation is intended.",
            out.display()
        );
    }
    match purpose {
        KeygenPurpose::Oidc => {
            let kp = OidcKeypair::generate_and_persist(&out)
                .map_err(|e| anyhow::anyhow!("oidc keygen failed: {e}"))?;
            eprintln!(
                "wrote oidc keypair (kid={}) to {} (mode 0600)",
                kp.kid,
                out.display()
            );
        }
        KeygenPurpose::Session => {
            let kp = SessionKeypair::generate_and_persist(&out)
                .map_err(|e| anyhow::anyhow!("session keygen failed: {e}"))?;
            eprintln!(
                "wrote session keypair (kid={}) to {} (mode 0600)",
                kp.kid,
                out.display()
            );
        }
    }
    Ok(())
}

fn warn_if_non_loopback_without_tls(bind: &str) {
    let host = bind.split(':').next().unwrap_or(bind);
    let is_loopback = match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    };
    if !is_loopback {
        tracing::warn!(
            bind = %bind,
            "broker is binding to a non-loopback address without TLS. \
             Bearer tokens and minted AWS credentials will traverse the network in cleartext. \
             Terminate TLS at a reverse proxy (nginx, ALB, Traefik) before exposing the broker."
        );
    }
}
