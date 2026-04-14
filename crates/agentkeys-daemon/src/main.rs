use std::sync::Arc;

use agentkeys_core::backend::CredentialBackend;
use agentkeys_core::mock_client::MockHttpClient;
use agentkeys_core::session_store;
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

    #[arg(long, help = "Recovery method: passkey or email (skips master approval)")]
    method: Option<String>,

    #[arg(long)]
    stdio: bool,

    #[arg(long, default_value = "300", help = "Pair/recover poll timeout in seconds")]
    pair_timeout: u64,

    #[arg(
        long,
        env = "AGENTKEYS_SESSION_ID",
        help = "Custom session namespace (default: derived from wallet address)"
    )]
    session_id: Option<String>,
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
        let sess = session::build_session_from_token(token.clone());
        let agent_id = WalletAddress(sess.wallet.0.clone());
        let sid = args
            .session_id
            .clone()
            .unwrap_or_else(|| format!("daemon-{}", agent_id.0));
        session_store::save_session(&sess, &sid).context("save injected session")?;
        (sess, agent_id)
    } else if let Some(ref agent_identity) = args.recover {
        if let Some(ref method) = args.method {
            // RECOVER VIA 2FA (no master approval needed)
            let result = pairing::run_recover_2fa_flow(&*backend, agent_identity, method)
                .await
                .context("2FA recover flow failed")?;
            let agent_id = result.wallet.clone();
            let sid = args
                .session_id
                .clone()
                .unwrap_or_else(|| format!("daemon-{}", agent_id.0));
            // clean up pending entry if present
            let _ = session_store::clear_session("daemon-pending");
            session_store::save_session(&result.session, &sid)
                .context("save recovered session")?;
            (result.session, agent_id)
        } else {
            // RECOVER VIA MASTER APPROVAL
            let result = pairing::run_recover_flow(&*backend, agent_identity, args.pair_timeout)
                .await
                .context("recover flow failed")?;
            let agent_id = result.wallet.clone();
            let sid = args
                .session_id
                .clone()
                .unwrap_or_else(|| format!("daemon-{}", agent_id.0));
            let _ = session_store::clear_session("daemon-pending");
            session_store::save_session(&result.session, &sid)
                .context("save recovered session")?;
            (result.session, agent_id)
        }
    } else {
        // Try to load an existing session from a known id.
        // If --session-id was supplied, try that first; else try "daemon-pending" as a
        // sentinel that a prior run left before the wallet was resolved.
        let existing_sid = args.session_id.clone().unwrap_or_else(|| "daemon-pending".to_string());
        match session_store::load_session(&existing_sid) {
            Ok(sess) => {
                let agent_id = WalletAddress(sess.wallet.0.clone());
                (sess, agent_id)
            }
            Err(_) => {
                // PAIR FLOW: no existing session, save under pending until wallet is known
                session_store::save_session(
                    &session::build_session_from_token("pending".to_string()),
                    "daemon-pending",
                )
                .ok();
                let result = pairing::run_pair_flow(&*backend, args.pair_timeout)
                    .await
                    .context("pair flow failed")?;
                let agent_id = result.wallet.clone();
                let sid = args
                    .session_id
                    .clone()
                    .unwrap_or_else(|| format!("daemon-{}", agent_id.0));
                let _ = session_store::clear_session("daemon-pending");
                session_store::save_session(&result.session, &sid)
                    .context("save paired session")?;
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
