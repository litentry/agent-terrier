use agentkeys_worker_creds::local::{serve, LocalWorkerOptions};
use agentkeys_worker_memory::handlers;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = LocalWorkerOptions::parse();
    options.require_development_key()?;
    serve(options, handlers::build_router).await
}
