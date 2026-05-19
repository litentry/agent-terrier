//! Memory-service worker binary — arch.md §15.2.
//!
//! Required env (fail-fast):
//!   MEMORY_BUCKET             = agentkeys-memory-<account-id>
//!   AWS_REGION                = us-east-1
//!   BROKER_CAP_PUBKEY_PEM     = P-256 SubjectPublicKeyInfo PEM
//!   AGENTKEYS_CHAIN_RPC_HTTP  = https://rpc.heima-parachain.heima.network
//!   SIDECAR_REGISTRY_ADDRESS_HEIMA = 0x...
//!   SCOPE_CONTRACT_ADDRESS_HEIMA   = 0x...
//!   K3_EPOCH_COUNTER_ADDRESS_HEIMA = 0x...
//!   AGENTKEYS_MEMORY_KEK_HEX  = 64-hex (stage 1 only — stage 2 swaps for
//!                                       mTLS-derived KEK from signer)

use std::net::SocketAddr;
use std::sync::Arc;

use agentkeys_worker_memory::{handlers, MemoryWorkerConfig, MemoryWorkerState};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "agentkeys-worker-memory")]
struct Args {
    #[arg(long, env = "WORKER_BIND", default_value = "127.0.0.1:8081")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = MemoryWorkerConfig::from_env()?;
    info!(bucket = %config.memory_bucket, "starting agentkeys-worker-memory");
    let worker_state = MemoryWorkerState::build(config).await?;
    let shared = Arc::new(worker_state);
    let app = handlers::build_router(shared);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
