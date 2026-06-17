//! agentkeys-bundler — thin in-house ERC-4337 v0.7 bundler (#230).
//!
//! Env (absent/empty host-conditional values ⇒ DEGRADED boot, not crash —
//! /healthz serves and RPC errors actionably; malformed values fail fast):
//!   AGENTKEYS_CHAIN_RPC_HTTP     = https://rpc.heima-parachain.heima.network  (required)
//!   ENTRYPOINT_ADDRESS[_HEIMA]   = 0x…  (absent ⇒ degraded)
//!   AGENTKEYS_BUNDLER_SIGNER_KEY = 0x… (or BROKER_SPONSOR_SIGNER_KEY; absent ⇒ degraded)
//! Optional:
//!   AGENTKEYS_CHAIN_ID[_<CHAIN>]    (override; else the compiled chain profile for AGENTKEYS_CHAIN — no Heima default)
//!   AGENTKEYS_HANDLEOPS_GAS_LIMIT   (default 4000000 — Heima can't estimate handleOps)
//!   AGENTKEYS_BUNDLER_GAS_PRICE     (wei; default eth_gasPrice +25%)
//!   AGENTKEYS_BUNDLER_BIND          (default 127.0.0.1:9098 — loopback-only, PRIVATE)

use agentkeys_bundler::server::{build_router, BundlerBoot, BundlerState};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "agentkeys-bundler")]
struct Args {
    #[arg(long, env = "AGENTKEYS_BUNDLER_BIND", default_value = "127.0.0.1:9098")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let boot = BundlerBoot::from_env()?;
    match &boot {
        BundlerBoot::Ready(cfg) => info!(
            entry_point = %format!("0x{}", hex::encode(cfg.entry_point)),
            beneficiary = %format!("0x{}", hex::encode(cfg.beneficiary)),
            chain_id = cfg.chain_id,
            "starting agentkeys-bundler"
        ),
        BundlerBoot::Degraded { missing, .. } => warn!(
            missing = %missing.join(", "),
            "starting agentkeys-bundler DEGRADED — no sponsorship provisioning on this \
             host; /healthz serves, eth_sendUserOperation errors actionably. Provision \
             /etc/agentkeys/broker-sponsor.env (+ EntryPoint address) and restart."
        ),
    }
    let app = build_router(Arc::new(BundlerState::new(boot)));
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
