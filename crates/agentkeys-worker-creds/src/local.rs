use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use crate::{audit::AuditEmitter, WorkerConfig, WorkerState};
use agentkeys_core::chain_profile::ChainProfile;
use anyhow::{ensure, Result};
use clap::Parser;

const DEFAULT_LISTEN: &str = "127.0.0.1:0";

#[derive(Parser)]
pub struct LocalWorkerOptions {
    #[arg(long)]
    development: bool,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    broker_public_key: PathBuf,
    #[arg(long)]
    storage_url: String,
    #[arg(long)]
    development_kek_file: Option<String>,
    #[arg(long, default_value = "")]
    browser_origins: String,
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
}

pub async fn serve(
    options: LocalWorkerOptions,
    router: fn(Arc<WorkerState>) -> axum::Router,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    ensure!(
        options.listen.ip().is_loopback(),
        "development worker must listen on loopback"
    );
    let profile = ChainProfile::load_from_file(&options.profile)?;
    let config = WorkerConfig::local(
        &profile,
        options.development,
        std::fs::read_to_string(options.broker_public_key)?,
        options.storage_url,
        options.development_kek_file.as_deref(),
        options.browser_origins,
    )?;
    let worker = Arc::new(WorkerState::build(config, AuditEmitter::from_env())?);
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    println!(
        "{}",
        serde_json::json!({"listen":listener.local_addr()?, "development_only":true})
    );
    axum::serve(listener, router(worker)).await?;
    Ok(())
}
