//! Config-service worker binary — arch.md §15.x / #201.
//!
//! Holds the policy / memory-types taxonomy (#178 §7), MASTER-ONLY.
//!
//! Required env (fail-fast):
//!   CONFIG_BUCKET             = agentkeys-config-<account-id>
//!   AWS_REGION                = us-east-1
//!   BROKER_CAP_PUBKEY_PEM     = P-256 SubjectPublicKeyInfo PEM
//!   AGENTKEYS_CHAIN_RPC_HTTP  = https://rpc.heima-parachain.heima.network
//!   SIDECAR_REGISTRY_ADDRESS_HEIMA = 0x...
//!   SCOPE_CONTRACT_ADDRESS_HEIMA   = 0x...
//!   K3_EPOCH_COUNTER_ADDRESS_HEIMA = 0x...
//!   AGENTKEYS_CONFIG_KEK_HEX  = 64-hex (stage 1 only — stage 2 swaps for
//!                                       mTLS-derived KEK from signer)

use std::net::SocketAddr;
use std::sync::Arc;

use agentkeys_worker_config::{handlers, ConfigWorkerConfig, ConfigWorkerState};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "agentkeys-worker-config")]
struct Args {
    #[arg(long, env = "WORKER_BIND", default_value = "127.0.0.1:8083")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ConfigWorkerConfig::from_env()?;
    info!(bucket = %config.config_bucket, "starting agentkeys-worker-config");
    let worker_state = ConfigWorkerState::build(config).await?;
    let shared = Arc::new(worker_state);
    let app = handlers::build_router(shared);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
