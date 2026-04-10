use std::sync::Arc;

use agentkeys_core::mock_client::MockHttpClient;
use agentkeys_types::WalletAddress;
use anyhow::Context;
use clap::Parser;
use tracing::info;

mod hardening;
mod session;

#[derive(Parser)]
#[command(name = "agentkeys-daemon", about = "AgentKeys sandbox sidecar daemon")]
struct Args {
    #[arg(long, env = "AGENTKEYS_BACKEND")]
    backend: String,

    #[arg(long, env = "AGENTKEYS_SESSION")]
    session: Option<String>,

    #[arg(long)]
    recover: Option<String>,

    #[arg(long)]
    stdio: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    // 1. Apply kernel hardening
    let _hardening_report = hardening::apply_hardening()?;

    // 2. Load session token
    let session_token = if let Some(token) = args.session {
        token
    } else {
        session::read_session_file().context("no session: set AGENTKEYS_SESSION or run init")?
    };

    // Persist session file with secure permissions
    session::write_session_file(&session_token)?;

    let sess = session::build_session_from_token(session_token);
    let agent_id = WalletAddress(sess.wallet.0.clone());

    // 3. Connect to backend
    let backend = Arc::new(MockHttpClient::new(args.backend));

    info!("daemon ready, session wallet={}", agent_id.0);

    // 4. Serve MCP
    if args.stdio {
        agentkeys_mcp::server::run_stdio(backend, sess, agent_id).await?;
    } else {
        // Unix socket path for future use
        info!("no --stdio flag; daemon exiting (Unix socket mode not yet implemented)");
    }

    Ok(())
}
