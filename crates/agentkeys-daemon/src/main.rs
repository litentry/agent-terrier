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

    #[arg(long, value_name = "ALIAS|WALLET", help = "Bind pair request to a specific master (alias or 0x... wallet)")]
    parent: Option<String>,

    /// URL of the operator's broker server (Stage 7).
    ///
    /// When set, AWS-credential needs (e.g. fetching verification emails from the
    /// operator's S3 bucket) are satisfied by calling the broker's
    /// `POST /v1/mint-aws-creds` with the daemon's bearer token; the daemon
    /// itself never holds long-lived AWS credentials. Leave unset to use the
    /// pre-Stage-7 path where the operator sources creds via
    /// `scripts/stage6-demo-env.sh`.
    #[arg(long, env = "AGENTKEYS_BROKER_URL")]
    broker_url: Option<String>,
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

    if let Some(ref broker_url) = args.broker_url {
        info!(broker_url = %broker_url, "broker URL configured; AWS-cred mints will route through broker");
    }

    // --parent resolution is lazy: only the pair and master-approval recover
    // paths use it, so resolving eagerly would crash non-pair startups when
    // the backend is transiently down (codex PR #22 P3). Helper is called
    // inside those branches only.

    // 2. Determine session: env/file seam, pair flow, or recover flow
    let (sess, agent_id) = if let Some(token) = args.session {
        // TEST SEAM: session injected directly (Stage 3 compatibility).
        // --parent is irrelevant here; no resolution is performed.
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
            // RECOVER VIA 2FA — no master approval, so --parent is unused.
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
            // RECOVER VIA MASTER APPROVAL — resolve --parent here, not at
            // startup (codex P3).
            let parent_wallet = resolve_parent_if_set(&args.backend, args.parent.as_deref()).await?;
            let result = pairing::run_recover_flow(
                &*backend,
                agent_identity,
                args.pair_timeout,
                parent_wallet.as_ref(),
            )
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
        let loaded = if let Some(sid) = args.session_id.clone() {
            // Explicit --session-id / AGENTKEYS_SESSION_ID — load directly.
            session_store::load_session(&sid).ok().map(|s| (sid, s))
        } else {
            // Validate candidates before raising ambiguity, so stale marker
            // directories (e.g., keyring entry deleted out-of-band) don't
            // block startup when exactly one real session is still loadable
            // (codex PR #24 v4 P2). Deterministic sorted list so any
            // ambiguity error prints candidates in stable order (codex PR
            // #24 P1 — cross-wallet credential mix-up).
            let candidates = session_store::list_fallback_session_ids("daemon-");
            let loadable: Vec<(String, _)> = candidates
                .into_iter()
                .filter_map(|sid| session_store::load_session(&sid).ok().map(|s| (sid, s)))
                .collect();

            match loadable.len() {
                0 => {
                    // Emit a hint if there are non-`daemon-*` sessions
                    // stored under ~/.agentkeys (e.g., saved via
                    // --session-id WORK on a previous run). Without it the
                    // daemon silently re-pairs and the user loses track of
                    // the credentials tied to the old wallet (codex PR #24
                    // v5 P2). Empty-prefix scan returns directory names;
                    // filter out:
                    //  - known CLI namespaces (`master`, `daemon-*`)
                    //  - rewritten storage keys (`__agk_*`) whose original
                    //    user-supplied ID is unknown — advertising them
                    //    would be misleading because re-passing the
                    //    sanitized name would re-rewrite to a different
                    //    storage key (codex PR #24 v7 P2).
                    let all = session_store::list_fallback_session_ids("");
                    let others: Vec<String> = all
                        .into_iter()
                        .filter(|s| {
                            !s.starts_with("daemon-")
                                && s != "master"
                                && !s.starts_with("__agk_")
                        })
                        .collect();
                    if !others.is_empty() {
                        eprintln!(
                            "[agentkeys-daemon] no daemon-* sessions found, but these custom session IDs exist: {}. Pass --session-id <name> to resume one instead of re-pairing.",
                            others.join(", ")
                        );
                    }
                    None
                }
                1 => Some(loadable.into_iter().next().expect("len==1")),
                _ => {
                    let ids: Vec<String> = loadable.into_iter().map(|(sid, _)| sid).collect();
                    anyhow::bail!(
                        "multiple loadable daemon sessions found under ~/.agentkeys ({}): pass --session-id <name> (or set AGENTKEYS_SESSION_ID) to pick one. Candidates: {}",
                        ids.len(),
                        ids.join(", ")
                    );
                }
            }
        };

        match loaded {
            Some((_sid, sess)) => {
                let agent_id = WalletAddress(sess.wallet.0.clone());
                (sess, agent_id)
            }
            None => {
                // PAIR FLOW — no stored session found. Resolve --parent lazily
                // here (codex PR #22 P3) so transient backend failures on the
                // --session / --recover --method paths don't crash startup.
                // `--parent` binds the pair request to a specific master so
                // the backend refuses approval from any other master.
                let parent_wallet = resolve_parent_if_set(&args.backend, args.parent.as_deref()).await?;
                let result = pairing::run_pair_flow(
                    &*backend,
                    args.pair_timeout,
                    parent_wallet.as_ref(),
                )
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
        agentkeys_mcp::server::run_stdio_with_broker(
            dyn_backend,
            sess,
            agent_id,
            args.broker_url.clone(),
        )
        .await?;
    } else {
        info!("no --stdio flag; daemon exiting (Unix socket mode not yet implemented)");
    }

    Ok(())
}

/// True IFF `s` is a strict `0x` + 40 hex-digit wallet literal. Aliases like
/// `0x-office` or `0x+bar` (both legal per `cmd_link`) fail this check and
/// go through the identity-resolution path instead (codex PR #22 P2 —
/// 0x-prefix aliases misclassified as wallets).
fn looks_like_raw_wallet(s: &str) -> bool {
    s.starts_with("0x") && s.len() == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolve `--parent` to a wallet address if set, returning `Ok(None)` when
/// the flag is absent.
///
/// Uses reqwest's `.query()` builder so aliases with reserved characters
/// (`+`, `&`, `%`, spaces) are percent-encoded per RFC 3986 (codex PR #22
/// v1 P2 — URL encoding).
///
/// All inputs — raw wallets included — go through `/identity/resolve` so
/// the backend can validate existence before the daemon opens a pair
/// request. Raw `0x...` wallets are normalized to lowercase first, which
/// matches the canonical form the backend stores; mixed-case checksummed
/// addresses therefore resolve cleanly instead of timing out at approval
/// (codex PR #22 v2 P2 — unknown wallet accepted + case mismatch).
async fn resolve_parent_if_set(
    backend_url: &str,
    parent: Option<&str>,
) -> anyhow::Result<Option<WalletAddress>> {
    let Some(raw) = parent else {
        return Ok(None);
    };

    // Pick identity_type based on shape. Raw wallets get lowercased to
    // match the backend's canonical storage form.
    let (identity_type, identity_value) = if looks_like_raw_wallet(raw) {
        ("wallet", raw.to_ascii_lowercase())
    } else {
        ("alias", raw.to_string())
    };

    let http = reqwest::Client::new();
    let resp = http
        .get(format!("{backend_url}/identity/resolve"))
        .query(&[
            ("identity_type", identity_type),
            ("identity_value", identity_value.as_str()),
        ])
        .send()
        .await
        .context("resolve --parent: HTTP request failed")?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "could not resolve --parent '{raw}' (identity_type={identity_type}): status={}",
            resp.status()
        );
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .context("resolve --parent: JSON parse failed")?;
    let wallet_str = body["wallet_address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("resolve --parent: missing wallet_address in response"))?
        .to_string();
    Ok(Some(WalletAddress(wallet_str)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_raw_wallet_accepts_canonical_hex() {
        assert!(looks_like_raw_wallet(
            "0x1234567890abcdef1234567890abcdef12345678"
        ));
        assert!(looks_like_raw_wallet(
            "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
        ));
    }

    #[test]
    fn looks_like_raw_wallet_rejects_0x_hyphen_alias() {
        // `0x-office` is a valid alias per cmd_link; must NOT be treated as
        // a literal wallet (codex PR #22 P2).
        assert!(!looks_like_raw_wallet("0x-office"));
        assert!(!looks_like_raw_wallet("0x+bar"));
    }

    #[test]
    fn looks_like_raw_wallet_rejects_short_or_non_hex() {
        assert!(!looks_like_raw_wallet("0xdeadbeef")); // too short
        assert!(!looks_like_raw_wallet(
            "0x1234567890abcdef1234567890abcdef123456789" // 41 hex chars
        ));
        assert!(!looks_like_raw_wallet(
            "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
        )); // non-hex
    }
}
