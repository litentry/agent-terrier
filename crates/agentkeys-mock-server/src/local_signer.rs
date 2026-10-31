use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use agentkeys_core::{chain_profile::ChainProfile, protected_file};
use agentkeys_mock_server::{
    create_signer_router, db, dev_key_service::DevKeyService, state::AppState,
};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use jsonwebtoken::DecodingKey;
use zeroize::Zeroizing;

const DEFAULT_LISTEN: &str = "127.0.0.1:0";

#[derive(Parser)]
struct Options {
    #[arg(long)]
    development: bool,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    broker_public_key: PathBuf,
    #[arg(long)]
    master_secret_file: String,
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    ensure!(
        options.listen.ip().is_loopback(),
        "development signer must listen on loopback"
    );
    let profile = ChainProfile::load_from_file(&options.profile)?;
    profile.require_local_development(options.development, None)?;
    let public_key = DecodingKey::from_ec_pem(&std::fs::read(options.broker_public_key)?)
        .context("invalid broker session public key")?;
    let encoded = protected_file::read_text(&options.master_secret_file)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded.trim(), secret.as_mut())
        .context("development signer secret must contain 32 hex-encoded bytes")?;
    let connection = rusqlite::Connection::open_in_memory()?;
    db::init_schema(&connection)?;
    let state = Arc::new(
        AppState::new(connection)
            .with_dev_signer(Some(DevKeyService::from_master_secret(*secret)))
            .with_broker_session_pubkey(Some(public_key)),
    );
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    println!(
        "{}",
        serde_json::json!({"listen": listener.local_addr()?, "development_only": true})
    );
    axum::serve(listener, create_signer_router(state)).await?;
    Ok(())
}
