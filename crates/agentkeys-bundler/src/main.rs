//! ERC-4337 transaction submission with explicit local development startup.

use agentkeys_bundler::server::{build_router, BundlerBoot, BundlerBootValues, BundlerState};
use agentkeys_core::{chain_profile::ChainProfile, device_crypto, secp256k1_key};
use anyhow::{ensure, Context};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "agentkeys-bundler")]
struct Args {
    #[arg(long, env = "AGENTKEYS_BUNDLER_BIND", default_value = "127.0.0.1:9098")]
    bind: SocketAddr,
    #[arg(long, global = true)]
    development: bool,
    #[arg(long, global = true, requires = "development")]
    profile: Option<PathBuf>,
    #[arg(long, requires = "development")]
    signer_key_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Address,
}

fn development_profile(args: &Args) -> anyhow::Result<&str> {
    ensure!(args.development, "local signing requires --development");
    ensure!(
        args.bind.ip().is_loopback(),
        "local bundler must listen on loopback"
    );
    let path = args
        .profile
        .as_ref()
        .context("local bundler requires --profile")?
        .to_str()
        .context("profile path must be UTF-8")?;
    let (profile, _) = ChainProfile::resolve(None, None, Some(path))?;
    profile.require_local_development(true, None)?;
    Ok(path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    if let Some(command) = &args.command {
        development_profile(&args)?;
        let key = match command {
            Command::Keygen { out } => {
                secp256k1_key::create(out.to_str().context("key path must be UTF-8")?)?
            }
            Command::Address => secp256k1_key::read(
                args.signer_key_file
                    .as_ref()
                    .context("address requires --signer-key-file")?
                    .to_str()
                    .context("key path must be UTF-8")?,
            )?,
        };
        println!(
            "{}",
            serde_json::json!({"development_only":true,
            "address":device_crypto::evm_address(key.verifying_key())})
        );
        return Ok(());
    }
    let boot = if args.development {
        let profile = development_profile(&args)?;
        let key = args
            .signer_key_file
            .as_ref()
            .context("local bundler requires --signer-key-file")?
            .to_str()
            .context("key path must be UTF-8")?;
        let values = BundlerBootValues::from_lookup(|name| match name {
            "AGENTKEYS_CHAIN_PROFILE_FILE" => Some(profile.to_owned()),
            "AGENTKEYS_BUNDLER_SIGNER_KEY_FILE" => Some(key.to_owned()),
            _ => None,
        })?;
        let boot = BundlerBoot::from_values(values)?;
        ensure!(
            matches!(boot, BundlerBoot::Ready(_)),
            "local bundler requires a deployed EntryPoint"
        );
        boot
    } else {
        BundlerBoot::from_env()?
    };
    match &boot {
        BundlerBoot::Ready(config) => info!(
            entry_point = %format!("0x{}", hex::encode(config.entry_point)),
            beneficiary = %format!("0x{}", hex::encode(config.beneficiary)),
            chain_id = config.chain_id,
            "starting transaction submission service"
        ),
        BundlerBoot::Degraded { missing, .. } => warn!(
            missing = %missing.join(", "), "bundler configuration incomplete; transaction submission is unavailable"
        ),
    }
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    let app = build_router(Arc::new(BundlerState::new(boot)));
    println!(
        "{}",
        serde_json::json!({"listen":listener.local_addr()?.to_string(),
        "surface":"transaction-submission"})
    );
    axum::serve(listener, app).await?;
    Ok(())
}
