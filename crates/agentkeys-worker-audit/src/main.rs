use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_worker_audit::archive::{router, Archive};
use anyhow::ensure;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    development: bool,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Args::parse();
    ensure!(
        options.listen.ip().is_loopback(),
        "local audit archive requires a loopback listener"
    );
    let profile = ChainProfile::load_from_file(&options.profile)?;
    profile.require_local_development(options.development, None)?;
    let identity = serde_json::to_string(
        &serde_json::json!({"chain_id":profile.chain_id,"contracts":profile.contracts,"version":profile.contract_set_version}),
    )?;
    let archive = Arc::new(Archive::open(
        &options.database,
        &options.token_file,
        &identity,
    )?);
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    println!(
        "{}",
        serde_json::json!({"listen":listener.local_addr()?,"development_only":true})
    );
    axum::serve(listener, router(archive)).await?;
    Ok(())
}
