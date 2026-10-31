use agentkeys_worker_creds::{
    handlers,
    local::{serve, LocalWorkerOptions},
};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve(LocalWorkerOptions::parse(), handlers::build_router).await
}
