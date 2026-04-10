use std::sync::Arc;

use agentkeys_core::backend::CredentialBackend;
use agentkeys_core::mock_client::MockHttpClient;
use agentkeys_types::WalletAddress;
use anyhow::Context;
use clap::Parser;
use tracing::info;

mod hardening;
mod pairing;
mod session;

#[derive(Parser)]
#[command(name = "agentkeys-daemon", about = "AgentKeys sandbox sidecar daemon")]
struct Args {
    #[arg(long, env = "AGENTKEYS_BACKEND")]
    backend: String,

    #[arg(long, env = "AGENTKEYS_SESSION")]
    session: Option<String>,

    #[arg(long, help = "Recover agent by alias or wallet address (e.g. my-bot or 0x...)")]
    recover: Option<String>,

    #[arg(long)]
    stdio: bool,

    #[arg(long, default_value = "300", help = "Pair/recover poll timeout in seconds")]
    pair_timeout: u64,
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

    let backend = Arc::new(MockHttpClient::new(&args.backend));

    // 2. Determine session: env/file seam, pair flow, or recover flow
    let (sess, agent_id) = if let Some(token) = args.session {
        // TEST SEAM: session injected directly (Stage 3 compatibility)
        session::write_session_file(&token)?;
        let sess = session::build_session_from_token(token);
        let agent_id = WalletAddress(sess.wallet.0.clone());
        (sess, agent_id)
    } else if let Some(ref agent_identity) = args.recover {
        // RECOVER FLOW
        let result = pairing::run_recover_flow(&*backend, agent_identity, args.pair_timeout)
            .await
            .context("recover flow failed")?;
        session::write_session_file(&result.session.token)?;
        let agent_id = result.wallet.clone();
        (result.session, agent_id)
    } else {
        // Check for existing session file first
        match session::read_session_file() {
            Ok(token) => {
                let sess = session::build_session_from_token(token);
                let agent_id = WalletAddress(sess.wallet.0.clone());
                (sess, agent_id)
            }
            Err(_) => {
                // PAIR FLOW: no existing session, initiate pairing
                let result = pairing::run_pair_flow(&*backend, args.pair_timeout)
                    .await
                    .context("pair flow failed")?;
                session::write_session_file(&result.session.token)?;
                let agent_id = result.wallet.clone();
                (result.session, agent_id)
            }
        }
    };

    info!("daemon ready, session wallet={}", agent_id.0);

    // 3. Serve MCP
    if args.stdio {
        let dyn_backend: Arc<dyn CredentialBackend> = backend;
        agentkeys_mcp::server::run_stdio(dyn_backend, sess, agent_id).await?;
    } else {
        info!("no --stdio flag; daemon exiting (Unix socket mode not yet implemented)");
    }

    Ok(())
}
