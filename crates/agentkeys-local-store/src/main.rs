use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_local_store::{AuthorityConfig, LocalStore};
use agentkeys_protocol::capability::DataClass;
use anyhow::{ensure, Context, Result};
use clap::Parser;

const DEFAULT_LISTEN: &str = "127.0.0.1:0";

#[derive(Parser)]
struct Options {
    #[arg(long)]
    development: bool,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    broker_public_key: PathBuf,
    #[arg(long, value_parser = ["credentials", "memory", "config", "channel"])]
    data_class: String,
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    ensure!(
        options.listen.ip().is_loopback(),
        "local store must listen on loopback"
    );
    let profile = ChainProfile::load_from_file(&options.profile)?;
    profile.require_local_development(options.development, None)?;
    let data_class: DataClass =
        serde_json::from_value(serde_json::Value::String(options.data_class))?;
    let contract = |name: &str| {
        profile
            .contract(name)
            .map(|item| item.address.clone())
            .with_context(|| format!("profile is missing {name}"))
    };
    let authority = AuthorityConfig {
        broker_public_key: std::fs::read_to_string(&options.broker_public_key)?,
        rpc_url: profile.rpc.http.clone(),
        registry: contract("SidecarRegistry")?,
        scope: contract("AgentKeysScope")?,
        epoch: contract("K3EpochCounter")?,
    };
    let store = Arc::new(LocalStore::open(&options.database, data_class, authority)?);
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    println!(
        "{}",
        serde_json::json!({"listen": listener.local_addr()?, "data_class": data_class, "development_only": true})
    );
    axum::serve(listener, agentkeys_local_store::router(store))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
