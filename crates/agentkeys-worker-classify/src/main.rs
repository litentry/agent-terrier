use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_worker_classify::{handlers, ClassifyWorkerConfig, ClassifyWorkerState};
use anyhow::ensure;
use clap::Parser;

#[derive(Parser)]
#[command(name = "agentkeys-worker-classify")]
struct Args {
    #[arg(long)]
    development: bool,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    broker_public_key: PathBuf,
    #[arg(long, default_value = "")]
    browser_origins: String,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    ensure!(
        args.listen.ip().is_loopback(),
        "development classifier must listen on loopback"
    );
    let profile = ChainProfile::load_from_file(&args.profile)?;
    let config = ClassifyWorkerConfig::local(
        &profile,
        args.development,
        std::fs::read_to_string(args.broker_public_key)?,
        args.browser_origins,
    )?;
    let shared = Arc::new(ClassifyWorkerState::build(config)?);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    println!(
        "{}",
        serde_json::json!({"listen":listener.local_addr()?, "development_only":true})
    );
    axum::serve(listener, handlers::build_router(shared)).await?;
    Ok(())
}
