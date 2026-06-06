//! Classifier-service worker binary — #178 §15.6 / #207 items 2-3.
//!
//! A COMPUTE gate (COMPILE + TAG). No S3 bucket / KEK.
//!
//! Required env (fail-fast):
//!   BROKER_CAP_PUBKEY_PEM          = P-256 SubjectPublicKeyInfo PEM
//!   AGENTKEYS_CHAIN_RPC_HTTP       = https://rpc.heima-parachain.heima.network
//!   SIDECAR_REGISTRY_ADDRESS_HEIMA = 0x...
//!   SCOPE_CONTRACT_ADDRESS_HEIMA   = 0x...
//!   K3_EPOCH_COUNTER_ADDRESS_HEIMA = 0x...

use std::net::SocketAddr;
use std::sync::Arc;

use agentkeys_worker_classify::{handlers, ClassifyWorkerConfig, ClassifyWorkerState};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "agentkeys-worker-classify")]
struct Args {
    #[arg(long, env = "WORKER_BIND", default_value = "127.0.0.1:8085")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ClassifyWorkerConfig::from_env()?;
    info!(profile = %config.chain_profile, "starting agentkeys-worker-classify (compute gate)");
    let shared = Arc::new(ClassifyWorkerState::build(config));
    let app = handlers::build_router(shared);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
