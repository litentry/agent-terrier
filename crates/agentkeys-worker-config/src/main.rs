use agentkeys_worker_config::handlers;
use agentkeys_worker_creds::local::{serve, LocalWorkerOptions};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve(LocalWorkerOptions::parse(), handlers::build_router).await
}
