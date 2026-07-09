//! WeChat gateway worker binary — #407 (+ the iLink transport driver).
//!
//! Transport selection: AGENTKEYS_WEIXIN_TRANSPORT = `oa` (default) | `ilink`.
//!
//! Required env under `oa` (fail-fast):
//!   AGENTKEYS_WEIXIN_TOKEN                  = the 公众号 callback verification token
//!   AGENTKEYS_WEIXIN_APP_ID                 = the 公众号 AppID
//! Required env under `ilink`:
//!   AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN[_FILE] = the bot token from the `--login` ceremony
//! Always required:
//!   AGENTKEYS_WEIXIN_CONTACT_REGISTRY_FILE  = master-authored contact registry JSON
//!   AGENTKEYS_WEIXIN_OPERATOR_OMNI          = the household operator omni (0x+64hex)
//! Optional:
//!   AGENTKEYS_WEIXIN_APP_SECRET[_FILE]      = the OA SENDING credential (#384 custody)
//!   AGENTKEYS_WEIXIN_ILINK_BASE_URL         = the bot's API host (login prints it)
//!   AGENTKEYS_WEIXIN_ILINK_STATE_FILE       = iLink cursor/reply-token state file
//!   AGENTKEYS_WEIXIN_BOT_AGENT              = UA-style self-id (default AgentKeys/<ver>)
//!   AGENTKEYS_WORKER_CHANNEL_URL            = the channel worker to relay into (else decision-only)
//!   AGENTKEYS_AUDIT_WORKER_URL              = durable audit sink for relay/bind rows
//!   AGENTKEYS_WEIXIN_OPERATOR_GRADE_ALIASES = comma list (default spend,usage,stats,cost,audit,billing)
//!   AGENTKEYS_WEIXIN_PARENT_CONTROL_DEEPLINK, AGENTKEYS_WEIXIN_RATE_MAX, AGENTKEYS_WEIXIN_RATE_WINDOW_SECS
//!   AGENTKEYS_WEIXIN_ALLOW_UNSIGNED=1       = TEST-ONLY OA signature bypass (mock e2e)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use agentkeys_worker_channel_weixin::{
    handlers, ilink, ilink_login, ilink_loop, WeixinGatewayConfig, WeixinGatewayState,
    WeixinTransport,
};
use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "agentkeys-worker-channel-weixin",
    about = "AgentKeys WeChat gateway worker (OA webhook / iLink personal-bot transports)"
)]
struct Cli {
    /// Run the interactive iLink QR login ceremony (scan with the spare
    /// personal-WeChat account), print the secrets-env lines, and exit.
    #[arg(long)]
    login: bool,
    /// With --login: upsert the minted credentials DIRECTLY into the gateway
    /// secrets file (rebind-safe — overwrites the managed keys in place,
    /// preserves every other line), instead of printing them to merge by hand.
    #[arg(long)]
    login_write: bool,
    /// Target for --login-write (default: the canonical secrets file). Ignored
    /// without --login-write.
    #[arg(long, value_name = "FILE", default_value = ilink_login::DEFAULT_SECRETS_FILE)]
    secrets_file: PathBuf,
    /// With --login: also dump the standalone env block to this file (0600).
    /// (For hand-merging; --login-write is the in-place alternative.)
    #[arg(long, value_name = "FILE")]
    login_out: Option<PathBuf>,
    /// With --login: override the bootstrap host.
    #[arg(long, default_value = ilink::ILINK_BOOTSTRAP_BASE_URL, value_name = "URL")]
    login_base_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if cli.login {
        // A token in the AMBIENT env (operator sourced the secrets file) lets the
        // server report an existing bind (`binded_redirect`) instead of minting a
        // duplicate. A clean shell → empty → a fresh bind.
        let existing = std::env::var("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .into_iter()
            .collect::<Vec<_>>();
        match ilink_login::run_login(&cli.login_base_url, existing).await? {
            // binded_redirect: already connected, the prior token stays valid —
            // nothing new to persist.
            None => {
                if cli.login_write {
                    println!(
                        "（未写入 {}：服务器报告该账号已绑定，沿用现有 token。\
                         如需换发新 token，请先在微信侧解绑再重试。）",
                        cli.secrets_file.display()
                    );
                }
            }
            Some(outcome) => {
                if cli.login_write {
                    let rebound = ilink_login::write_secrets_file(&cli.secrets_file, &outcome)?;
                    let what = if rebound {
                        "已重新绑定（覆盖旧 token）"
                    } else {
                        "已连接"
                    };
                    println!(
                        "\n✅ {what}，并写入 {}（#384 custody，0600）。\n{}",
                        cli.secrets_file.display(),
                        ilink_login::next_step_hint(&cli.secrets_file)
                    );
                } else {
                    ilink_login::print_secrets(&outcome, cli.login_out.as_deref())?;
                }
            }
        }
        return Ok(());
    }

    let config = WeixinGatewayConfig::from_env()?;
    let bind: SocketAddr = config.bind.parse()?;
    info!(
        transport = config.transport.as_str(),
        app_id = %config.weixin_app_id,
        "starting agentkeys-worker-channel-weixin"
    );
    let state = Arc::new(WeixinGatewayState::build(config)?);

    // The iLink SUPERVISOR rides alongside the HTTP surface (healthz + the
    // admin surface + the mock-driver callback stay up on both transports).
    // With no token it idles; the parent-control login ceremony hot-starts it.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ilink_task = if state.config.transport == WeixinTransport::Ilink {
        Some(tokio::spawn(ilink_loop::supervise(
            state.clone(),
            shutdown_rx,
        )))
    } else {
        None
    };

    let app = handlers::build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(bind = %bind, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Stop the loop cleanly (it fires the best-effort notifystop upstream).
    let _ = shutdown_tx.send(true);
    if let Some(task) = ilink_task {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}
