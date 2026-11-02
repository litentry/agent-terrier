use std::path::PathBuf;

use agentkeys_runtime::docker_runtime::{DockerConfig, DockerRuntime};
use anyhow::{ensure, Context, Result};
use clap::Parser;

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    development: bool,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    namespace: String,
    #[arg(long)]
    confirm_namespace: String,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    image: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    ensure!(
        arguments.development && arguments.namespace == arguments.confirm_namespace,
        "explicit development mode and matching namespace confirmation are required"
    );
    let values = std::collections::BTreeMap::from([
        ("AGENT_TERRIER_LOCAL_DEV", "1".to_owned()),
        (
            "AGENTKEYS_CHAIN_PROFILE_FILE",
            arguments
                .profile
                .to_str()
                .context("invalid profile path")?
                .to_owned(),
        ),
        ("AGENT_TERRIER_SANDBOX_IMAGE", arguments.image),
        ("AGENT_TERRIER_RUNTIME_NAMESPACE", arguments.namespace),
        (
            "AGENT_TERRIER_DOCKER_SOCKET",
            arguments
                .socket
                .to_str()
                .context("invalid socket path")?
                .to_owned(),
        ),
    ]);
    let configuration = DockerConfig::from_lookup(|name| values.get(name).cloned())?
        .context("missing runtime configuration")?;
    let actors = DockerRuntime::reset_local(configuration).await?;
    println!(
        "{}",
        serde_json::json!({"development_only":true, "reset_actors":actors})
    );
    Ok(())
}
