use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tracing::info;

use agentkeys_worker_email::handlers;
use agentkeys_worker_email::state::State;

/// Email-service worker (arch.md §15.1).
#[derive(Parser)]
#[command(name = "agentkeys-worker-email", version)]
struct Args {
    /// Bind address.
    #[arg(
        long,
        env = "AGENTKEYS_WORKER_EMAIL_BIND",
        default_value = "127.0.0.1:9093"
    )]
    bind: String,

    /// S3 bucket holding inbound mail per-actor at bots/<actor_omni>/inbound/.
    /// Defaults to the operator's vault bucket from #83 setup.
    #[arg(long, env = "AGENTKEYS_VAULT_BUCKET")]
    inbox_bucket: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let state = Arc::new(State::new(args.inbox_bucket.clone()).await?);

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/email/send", post(handlers::send))
        .route("/v1/email/inbox/:actor_omni", get(handlers::inbox))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    info!(
        bind = %args.bind,
        bucket = %args.inbox_bucket,
        "agentkeys-worker-email listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
