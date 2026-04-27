use std::net::IpAddr;
use std::sync::Arc;

use agentkeys_broker_server::{
    audit::AuditLog,
    config::BrokerConfig,
    create_router,
    state::AppState,
    sts::{AwsStsClient, StsClient},
};
use clap::Parser;

#[derive(Parser)]
#[command(name = "agentkeys-broker-server", about = "AgentKeys credential broker")]
struct Args {
    #[arg(long, default_value = "8091")]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// Skip the startup STS sanity check. Useful for offline development.
    /// In production, leave this off so misconfigured creds fail fast.
    #[arg(long)]
    skip_startup_check: bool,
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
    let config = BrokerConfig::from_env()?;

    warn_if_non_loopback_without_tls(&args.bind);

    let audit = AuditLog::open(&config.audit_db_path)?;
    let sts = AwsStsClient::from_keys(
        &config.daemon_access_key_id,
        &config.daemon_secret_access_key,
        &config.aws_region,
    )
    .await;

    if !args.skip_startup_check {
        match sts.caller_identity_ok().await {
            Ok(()) => tracing::info!("startup STS check passed"),
            Err(e) => {
                tracing::error!(error = %e, "startup STS check failed — refusing to bind");
                anyhow::bail!(
                    "startup STS check failed: {}. Verify BROKER_DAEMON_ACCESS_KEY_ID / BROKER_DAEMON_SECRET_ACCESS_KEY / BROKER_AWS_REGION, or pass --skip-startup-check for offline dev.",
                    e
                );
            }
        }
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.backend_request_timeout_seconds))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;

    let grace_seconds = config.shutdown_grace_seconds;

    let state = Arc::new(AppState {
        config,
        http,
        audit,
        sts: Arc::new(sts),
    });

    let app = create_router(state);
    let addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("broker listening on {}", addr);

    // Wrap the graceful-shutdown future in a hard timeout so a single hung
    // request can't block process exit forever.
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

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        // expect(): if we cannot register a SIGTERM handler the process is
        // running in a hardened environment that intentionally blocks signal
        // handling. Failing loud is better than silently exiting on startup
        // (which is what `if let Ok(...)` did).
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
