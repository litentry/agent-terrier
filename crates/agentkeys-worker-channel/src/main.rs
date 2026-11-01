use std::{path::PathBuf, sync::Arc};

use agentkeys_worker_channel::{
    handlers, wake::WakeClient, ChannelWorkerConfig, ChannelWorkerState,
};
use agentkeys_worker_creds::local::{serve, LocalWorkerOptions};
use clap::Parser;

#[derive(Parser)]
struct Options {
    #[command(flatten)]
    worker: LocalWorkerOptions,
    #[command(flatten)]
    channel: ChannelWorkerConfig,
    #[arg(long, requires = "wake_token_file")]
    wake_url: Option<String>,
    #[arg(long, requires = "wake_url")]
    wake_token_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    options.worker.require_development_key()?;
    options.channel.validate()?;
    let wake = match (options.wake_url, options.wake_token_file) {
        (Some(url), Some(path)) => Some(WakeClient::local(url, &path)?),
        (None, None) => None,
        _ => anyhow::bail!("wake URL and protected token file must be configured together"),
    };
    serve(options.worker, move |worker| {
        handlers::build_router(Arc::new(
            ChannelWorkerState::new(worker, options.channel, wake)
                .expect("channel configuration was validated before serving"),
        ))
    })
    .await
}
