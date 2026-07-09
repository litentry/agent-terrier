//! Channel-service worker binary — #406 / `docs/spec/agent-channel-decoupling.md`.
//!
//! Durable pub/sub feeds with the NRT worker-held long-poll (§14.12).
//!
//! Required env (fail-fast):
//!   CHANNEL_BUCKET            = agentkeys-channel-<account-id>
//!   AWS_REGION                = us-east-1
//!   BROKER_CAP_PUBKEY_PEM     = P-256 SubjectPublicKeyInfo PEM
//!   AGENTKEYS_CHAIN_RPC_HTTP  = https://rpc.heima-parachain.heima.network
//!   SIDECAR_REGISTRY_ADDRESS_HEIMA = 0x...
//!   SCOPE_CONTRACT_ADDRESS_HEIMA   = 0x...
//!   K3_EPOCH_COUNTER_ADDRESS_HEIMA = 0x...
//!   AGENTKEYS_CHANNEL_KEK_HEX = 64-hex (stage 1 — the envelope KEK for
//!                                       operator-owned feeds; per-actor feeds
//!                                       reuse the same worker-held KEK today)
//! Optional:
//!   AGENTKEYS_CHANNEL_MAX_POLL_SECONDS = long-poll ceiling (default 25)

use std::net::SocketAddr;
use std::sync::Arc;

use agentkeys_worker_channel::{handlers, ChannelWorkerConfig, ChannelWorkerState};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "agentkeys-worker-channel")]
struct Args {
    #[arg(long, env = "WORKER_BIND", default_value = "127.0.0.1:8084")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ChannelWorkerConfig::from_env()?;
    info!(bucket = %config.channel_bucket, "starting agentkeys-worker-channel");
    let worker_state = ChannelWorkerState::build(config).await?;
    let shared = Arc::new(worker_state);
    let app = handlers::build_router(shared);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
