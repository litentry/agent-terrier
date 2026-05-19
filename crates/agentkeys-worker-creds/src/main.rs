//! Credentials-service worker binary.
//!
//! Usage:
//!   agentkeys-worker-creds [--bind 0.0.0.0:8080]
//!
//! Required env (verified at startup, fail-fast):
//!   VAULT_BUCKET             = agentkeys-vault-<account-id>
//!   AWS_REGION               = us-east-1
//!   BROKER_CAP_PUBKEY_PEM    = P-256 SubjectPublicKeyInfo PEM (broker's K1)
//!   AGENTKEYS_CHAIN_RPC_HTTP = https://rpc.heima-parachain.heima.network
//!   SCOPE_CONTRACT_ADDRESS_HEIMA = 0x...
//!   AGENTKEYS_WORKER_KEK_HEX = 64-hex (stage 1 only — stage 2 mTLS to signer)

use std::net::SocketAddr;
use std::sync::Arc;

use agentkeys_worker_creds::{handlers, state, WorkerConfig, WorkerState};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "agentkeys-worker-creds")]
struct Args {
    #[arg(long, env = "WORKER_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = WorkerConfig::from_env()?;
    info!(bucket = %config.vault_bucket, "starting agentkeys-worker-creds");
    let worker_state = WorkerState::build(config).await?;
    let shared: state::SharedWorkerState = Arc::new(worker_state);
    let app = handlers::build_router(shared);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
