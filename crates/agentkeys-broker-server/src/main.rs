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
    sts::{AwsStsClient, StsClient},
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "agentkeys-broker-server", about = "AgentKeys credential broker")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(long, default_value = "8091")]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// Skip the startup STS sanity check. Useful for offline development.
    /// In production, leave this off so misconfigured creds fail fast.
    #[arg(long)]
    skip_startup_check: bool,
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

    if let Some(Command::Keygen { purpose, out }) = args.command {
        return run_keygen(purpose, out);
    }

    let config = BrokerConfig::from_env()?;

    warn_if_non_loopback_without_tls(&args.bind);

    // Tier 1 — synchronous refuse-to-boot per plan §6. Loads keypairs,
    // validates plugin selection, opens stores, builds registry. Any
    // failure here exits with a single-line BOOT_FAIL message.
    let boot_artifacts = run_tier1(&config)?;
    let tier2_profile = Tier2Profile::from_config(&config);
    tracing::info!(
        strict = tier2_profile.strict,
        email_link = tier2_profile.email_link_enabled,
        audit_evm = tier2_profile.audit_evm_enabled,
        "Tier-1 boot complete; Tier-2 reachability checks deferred until after listener bind"
    );

    // Legacy mint-log table opened alongside the plugin-trait audit anchors;
    // mint_v2 mirrors success/failure rows here for monitoring continuity.
    let audit = AuditLog::open(&config.audit_db_path)?;

    // Issue #71 OIDC-only migration: the broker mint flow uses
    // AssumeRoleWithWebIdentity, which is JWT-authenticated. The broker no
    // longer needs ANY AWS credentials at runtime for credential minting.
    // The default-chain config below is consulted only by the optional
    // `caller_identity_ok` startup probe; if no creds are configured (the
    // post-migration recommended posture), the probe logs a soft warning
    // instead of refusing to boot.
    tracing::info!("STS client: SDK default chain (creds optional after issue #71 — only the GetCallerIdentity startup probe consults them)");
    let sts = AwsStsClient::with_default_chain(&config.aws_region).await;

    if !args.skip_startup_check {
        match sts.caller_identity_ok().await {
            Ok(()) => tracing::info!("startup STS check passed"),
            Err(e) => {
                // Soft-fail: the mint flow doesn't need broker creds.
                // Operators running creds-free will see this warning at every
                // boot — pass --skip-startup-check to silence it.
                tracing::warn!(
                    error = %e,
                    "startup STS GetCallerIdentity probe failed — broker has no AWS credentials in its environment. \
                    This is the expected post-migration posture (mint flow is JWT-authenticated, see issue #71). \
                    Pass --skip-startup-check to silence this warning."
                );
            }
        }
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.backend_request_timeout_seconds))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;

    let grace_seconds = config.shutdown_grace_seconds;
    let tier2 = Arc::new(Tier2State::default());

    let state = Arc::new(AppState {
        config,
        http,
        audit,
        sts: Arc::new(sts),
        oidc: boot_artifacts.oidc_keypair,
        session_keypair: boot_artifacts.session_keypair,
        registry: boot_artifacts.registry,
        audit_policy: boot_artifacts.audit_policy,
        wallet_store: boot_artifacts.wallet_store,
        nonce_store: boot_artifacts.nonce_store,
        grant_store: boot_artifacts.grant_store,
        identity_link_store: boot_artifacts.identity_link_store,
        idempotency_store: boot_artifacts.idempotency_store,
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

    let app = create_router(state);
    let addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
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
/// Phase 0 ships only the backend probe (the only Tier-2 check whose
/// dependencies exist this early). SES + EVM probes land in Phase A.1
/// and Phase C respectively, behind their feature gates.
fn spawn_tier2_probes(
    state: Arc<AppState>,
    profile: agentkeys_broker_server::boot::Tier2Profile,
) {
    use std::sync::atomic::Ordering;
    let backend_url = profile.backend_url.clone();
    let strict = profile.strict;

    tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            loop {
                let url = format!("{}/healthz", backend_url.trim_end_matches('/'));
                let res = state
                    .http
                    .get(&url)
                    .timeout(std::time::Duration::from_secs(3))
                    .send()
                    .await;
                let ok = matches!(&res, Ok(r) if r.status().is_success());
                state.tier2.backend_reachable.store(ok, Ordering::Relaxed);
                if ok {
                    tracing::info!(url = %url, "Tier-2 backend probe: reachable");
                    break;
                }
                if strict {
                    tracing::error!(url = %url, "BROKER_REFUSE_TO_BOOT_STRICT=true and backend unreachable; exiting");
                    std::process::exit(1);
                }
                tracing::warn!(
                    url = %url,
                    "Tier-2 backend probe: unreachable; /readyz will return 503 until reachable"
                );
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
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
            .expect("failed to register SIGTERM handler — running in a sandbox that blocks signals?");
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
