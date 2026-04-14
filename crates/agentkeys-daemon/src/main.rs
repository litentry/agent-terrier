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
        // Default startup: find any previously-paired daemon session.
        //
        // Order:
        //   1. If --session-id was supplied, try exactly that ID.
        //   2. Else scan `daemon-*` file-fallback entries and try each until
        //      one loads cleanly.
        //   3. If none load, run the pair flow fresh.
        //
        // Note: we intentionally do NOT write a "daemon-pending" sentinel any
        // more. The old design would save a fake session with token="pending"
        // before pair, and if pair timed out / failed, the next startup
        // loaded that fake session and skipped pairing entirely (codex P1).
        // Now: no sentinel, so a failed pair just results in a retry next
        // startup, which is what users expect.
        let try_ids: Vec<String> = if let Some(sid) = args.session_id.clone() {
            vec![sid]
        } else {
            // Deterministic sorted list. If >1 exists, require the user to
            // pick one via --session-id or AGENTKEYS_SESSION_ID rather than
            // silently restoring an arbitrary wallet (codex PR #24 P1 —
            // cross-wallet credential mix-up on multi-daemon hosts).
            let ids = session_store::list_fallback_session_ids("daemon-");
            if ids.len() > 1 {
                anyhow::bail!(
                    "multiple daemon sessions found under ~/.agentkeys ({}): pass --session-id <name> (or set AGENTKEYS_SESSION_ID) to pick one. Candidates: {}",
                    ids.len(),
                    ids.join(", ")
                );
            }
            ids
        };

        let loaded = try_ids
            .into_iter()
            .find_map(|sid| session_store::load_session(&sid).ok().map(|s| (sid, s)));

        match loaded {
            Some((_sid, sess)) => {
                let agent_id = WalletAddress(sess.wallet.0.clone());
                (sess, agent_id)
            }
            None => {
                // PAIR FLOW — no stored session found. Save only after pair
                // succeeds and the wallet is known.
                let result = pairing::run_pair_flow(&*backend, args.pair_timeout)
                    .await
                    .context("pair flow failed")?;
                let agent_id = result.wallet.clone();
                let sid = args
                    .session_id
                    .clone()
                    .unwrap_or_else(|| format!("daemon-{}", agent_id.0));
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
