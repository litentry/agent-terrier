use std::sync::Arc;
use std::time::Duration;

use agentkeys_core::backend::CredentialBackend;
use agentkeys_core::init_flow;
use agentkeys_core::mock_client::MockHttpClient;
use agentkeys_core::session_store;
use agentkeys_types::WalletAddress;
use anyhow::Context;
use clap::Parser;
use tracing::info;

mod companion;
mod hardening;
mod pairing;
mod proxy;
mod session;

#[derive(Parser)]
#[command(name = "agentkeys-daemon", about = "AgentKeys sandbox sidecar daemon")]
struct Args {
    /// v2 stage-1 cap-token proxy mode (arch.md §6 + §15.1). When set,
    /// the daemon ignores all other args and serves the localhost cap
    /// proxy on a Unix socket (`--proxy-listen`) instead of running
    /// the legacy pairing/recover/MCP flows. `--proxy-broker-url` and
    /// `--proxy-session-jwt` provide the upstream broker auth.
    #[arg(long)]
    proxy: bool,

    /// v2 stage-2 master-companion mode (arch.md §10.3.1 + #90). Spins up
    /// a SECOND daemon instance that holds a distinct K10 + K11 credential
    /// on RP ID `companion.localhost` and serves an HTTP approval API on
    /// `127.0.0.1:9091` (configurable via `--companion-bind`). Used as the
    /// mobile-app alternative for M-of-N recovery quorum testing on the
    /// same Mac.
    #[arg(long)]
    master_companion: bool,

    /// Bind address for companion-mode HTTP server. Default 127.0.0.1:9091.
    #[arg(long, env = "AGENTKEYS_COMPANION_BIND")]
    companion_bind: Option<String>,

    /// Operator omni (hex) the companion daemon represents. Required in
    /// companion mode; should match the primary daemon's operator_omni.
    #[arg(long, env = "AGENTKEYS_COMPANION_OPERATOR_OMNI")]
    companion_operator_omni: Option<String>,

    /// On-chain device_key_hash (`keccak256(D_pub_companion)`). Required in
    /// companion mode after the operator has run `agentkeys device add` to
    /// register this companion as a 2nd master.
    #[arg(long, env = "AGENTKEYS_COMPANION_DEVICE_KEY_HASH")]
    companion_device_key_hash: Option<String>,

    /// K11 credential id for the companion's WebAuthn passkey (base64url or
    /// hex). Optional — emitted by `/v1/companion/whoami` for indexer hints.
    #[arg(long, env = "AGENTKEYS_COMPANION_K11_CRED_ID")]
    companion_k11_cred_id: Option<String>,

    /// WebAuthn RP ID the companion is bound to. Defaults to "companion.localhost".
    /// Demo bumps to "companion-v2.localhost" when prior companion is revoked.
    #[arg(long, env = "AGENTKEYS_COMPANION_RP_ID")]
    companion_rp_id: Option<String>,

    /// Unix-socket path for `--proxy` mode. Default resolves to
    /// `$XDG_RUNTIME_DIR/agentkeys-proxy.sock` or `~/.agentkeys/...`.
    #[arg(long, env = "AGENTKEYS_PROXY_SOCKET")]
    proxy_listen: Option<String>,

    /// Optional TCP bind for `--proxy` mode (container deployments).
    /// Default unset = unix-only. Set to e.g. `127.0.0.1:9090` to also
    /// listen on TCP.
    #[arg(long, env = "AGENTKEYS_PROXY_TCP")]
    proxy_tcp: Option<String>,

    /// Broker URL the proxy mints caps against.
    #[arg(long, env = "AGENTKEYS_PROXY_BROKER_URL")]
    proxy_broker_url: Option<String>,

    /// Session JWT the proxy passes as `Authorization: Bearer ...` to
    /// the broker for every cap-mint request.
    #[arg(long, env = "AGENTKEYS_PROXY_SESSION_JWT")]
    proxy_session_jwt: Option<String>,

    // backend is required for all non-proxy modes (pairing, recover,
    // MCP stdio, etc.). Proxy mode bypasses it via run_proxy_mode + the
    // explicit `args.proxy` early-return in main(). Marking it Optional
    // so `agentkeys-daemon --proxy ...` doesn't fail clap parsing when
    // AGENTKEYS_BACKEND is unset; the non-proxy branches still .expect
    // it (with a clear error message).
    #[arg(long, env = "AGENTKEYS_BACKEND")]
    backend: Option<String>,

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
    /// When set, AWS-credential needs (e.g. fetching verification emails from
    /// the operator's S3 bucket) are satisfied by the daemon-side path: fetch
    /// an OIDC JWT from the broker's `POST /v1/mint-oidc-jwt`, exchange it
    /// for AWS temp creds via `AssumeRoleWithWebIdentity` client-side (issue
    /// #71 Option A). The daemon never holds long-lived AWS credentials.
    /// Leave unset to fall back to whatever `AWS_*` env vars the operator
    /// pre-sourced (pre-Stage-7 path).
    #[arg(long, env = "AGENTKEYS_BROKER_URL")]
    broker_url: Option<String>,

    /// Issue #74 step 1: bootstrap a fresh daemon via the email-link →
    /// dev_key_service → SIWE flow. Triggers on first start when no
    /// `daemon-*` session is on disk; ignored if a saved session loads.
    #[arg(long, conflicts_with = "init_oauth2_google")]
    init_email: Option<String>,

    /// Issue #74 step 1: bootstrap a fresh daemon via the OAuth2/Google →
    /// dev_key_service → SIWE flow. Same first-start semantics as
    /// `--init-email`.
    #[arg(long = "init-oauth2-google", conflicts_with = "init_email")]
    init_oauth2_google: bool,

    /// URL of the dev_key_service signer (`/dev/derive-address` +
    /// `/dev/sign-message` per docs/spec/signer-protocol.md). Required
    /// when `--init-email` or `--init-oauth2-google` is set; defaults to
    /// `--backend` if unset.
    #[arg(long, env = "AGENTKEYS_SIGNER_URL")]
    signer_url: Option<String>,

    /// SIWE chain_id for the signer-flow bootstrap. Default mirrors
    /// the broker's wallet_sig plug-in test vectors (Base Sepolia).
    #[arg(long, default_value_t = 84532)]
    init_chain_id: u64,

    /// How long to wait for the operator to complete email-link click
    /// or OAuth2 callback before failing init.
    #[arg(long, default_value_t = 300)]
    init_poll_timeout_seconds: u64,
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

    if args.master_companion {
        return run_companion_mode(args).await;
    }

    if args.proxy {
        return run_proxy_mode(args).await;
    }

    // 1. Apply kernel hardening
    let _hardening_report = hardening::apply_hardening()?;

    // Non-proxy modes require --backend (clap made it Optional so that
    // --proxy doesn't need it; we re-validate here).
    let backend_url = args.backend.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "--backend (or AGENTKEYS_BACKEND env) required for non-proxy modes \
             (pair, recover, MCP stdio, init). For cap-token proxy mode pass --proxy."
        )
    })?;
    let backend = Arc::new(MockHttpClient::new(&backend_url));

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
            let parent_wallet = resolve_parent_if_set(&backend_url, args.parent.as_deref())?;
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
                // Issue #74 step 1: signer-flow bootstrap — when --init-email
                // or --init-oauth2-google is set AND no session is saved,
                // run the email/OAuth2 → dev_key_service → SIWE chain.
                // Otherwise fall through to the legacy pair flow (master/
                // child paradigm).
                if args.init_email.is_some() || args.init_oauth2_google {
                    let result = run_signer_flow_init(&args).await?;
                    let agent_id = WalletAddress(result.session.wallet.0.clone());
                    let sid = args
                        .session_id
                        .clone()
                        .unwrap_or_else(|| format!("daemon-{}", agent_id.0));
                    session_store::save_session(&result.session, &sid)
                        .context("save signer-flow session")?;
                    // Audit: structured tracing log so journalctl /
                    // log-aggregator captures the init event. The daemon
                    // does not have a SQL audit table of its own; the
                    // broker's audit (mint-time) and the structured log
                    // here together cover "did the daemon ever auth?"
                    info!(
                        target: "agentkeys.daemon.init",
                        identity_type = %result.identity_type,
                        identity_value = %result.identity_value,
                        identity_omni = %result.identity_omni,
                        evm_omni = %result.evm_omni,
                        derived_wallet = %result.derived_wallet,
                        "agentkeys-daemon bootstrapped via signer flow"
                    );
                    (result.session, agent_id)
                } else {
                    // PAIR FLOW — no stored session found. Resolve --parent lazily
                    // here (codex PR #22 P3) so transient backend failures on the
                    // --session / --recover --method paths don't crash startup.
                    // `--parent` binds the pair request to a specific master so
                    // the backend refuses approval from any other master.
                    let parent_wallet = resolve_parent_if_set(&backend_url, args.parent.as_deref())?;
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

/// Drive the issue-#74-step-1 bootstrap chain. Reads `--init-email` /
/// `--init-oauth2-google` / `--signer-url` / `--broker-url` /
/// `--init-chain-id` / `--init-poll-timeout-seconds` from `args` and
/// returns the resulting `InitResult` (session + identity provenance).
async fn run_signer_flow_init(args: &Args) -> anyhow::Result<init_flow::InitResult> {
    let broker_url = args.broker_url.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "agentkeys-daemon --init-email/--init-oauth2-google requires --broker-url (or AGENTKEYS_BROKER_URL)"
        )
    })?;
    let signer_url = args.signer_url.clone().unwrap_or_else(|| {
        args.backend.clone().expect(
            "--signer-url or --backend (or AGENTKEYS_SIGNER_URL/AGENTKEYS_BACKEND env) required for signer-flow init"
        )
    });
    let poll_timeout = Duration::from_secs(args.init_poll_timeout_seconds);

    if let Some(ref email) = args.init_email {
        eprintln!(
            "agentkeys-daemon: bootstrapping via email-link for {email}; click the magic link in your inbox"
        );
        init_flow::init_via_email_link(
            &broker_url,
            &signer_url,
            email,
            args.init_chain_id,
            poll_timeout,
        )
        .await
        .map_err(|e| anyhow::anyhow!("email-link bootstrap failed: {e}"))
    } else if args.init_oauth2_google {
        let start = init_flow::start_oauth2_google(&broker_url)
            .await
            .map_err(|e| anyhow::anyhow!("oauth2/start failed: {e}"))?;
        eprintln!(
            "agentkeys-daemon: open this URL in your browser to complete OAuth2/Google:\n  {}",
            start.authorization_url
        );
        init_flow::complete_oauth2_google(
            &broker_url,
            &signer_url,
            &start.request_id,
            args.init_chain_id,
            poll_timeout,
        )
        .await
        .map_err(|e| anyhow::anyhow!("oauth2 bootstrap failed: {e}"))
    } else {
        unreachable!("caller guards on init_email or init_oauth2_google being set")
    }
}

/// True IFF `s` is a strict `0x` + 40 hex-digit wallet literal. Aliases like
/// `0x-office` or `0x+bar` (both legal per `cmd_link`) fail this check and
/// go through the identity-resolution path instead (codex PR #22 P2 —
/// 0x-prefix aliases misclassified as wallets).
fn looks_like_raw_wallet(s: &str) -> bool {
    s.starts_with("0x") && s.len() == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolve `--parent` to a wallet address if set, returning `Ok(None)` when
/// the flag is absent. Only raw `0x` + 40-hex wallet literals are accepted;
/// alias/email lookup against `/identity/resolve` was retired with issue #77.
fn resolve_parent_if_set(
    _backend_url: &str,
    parent: Option<&str>,
) -> anyhow::Result<Option<WalletAddress>> {
    let Some(raw) = parent else {
        return Ok(None);
    };

    if !looks_like_raw_wallet(raw) {
        anyhow::bail!(
            "--parent '{raw}' must be a raw 0x-prefixed 40-hex wallet address (alias/email lookup retired in issue #77)"
        );
    }

    Ok(Some(WalletAddress(raw.to_ascii_lowercase())))
}

/// v2 stage-2 master-companion mode (arch.md §10.3.1 + #90). Second
/// daemon-as-mobile-app alternative for M-of-N recovery testing.
async fn run_companion_mode(args: Args) -> anyhow::Result<()> {
    let operator_omni = args.companion_operator_omni.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "--companion-operator-omni (or AGENTKEYS_COMPANION_OPERATOR_OMNI) required in master-companion mode"
        )
    })?;
    let device_key_hash = args.companion_device_key_hash.clone().unwrap_or_else(|| {
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
    });
    let k11_cred_id = args.companion_k11_cred_id.clone().unwrap_or_default();
    let companion_args = companion::CompanionArgs {
        bind: args.companion_bind.clone(),
        operator_omni,
        device_key_hash,
        k11_cred_id,
        rp_id: args.companion_rp_id.clone(),
    };
    companion::run(companion_args).await
}

/// v2 stage-1 cap-token proxy mode entry point (arch.md §6 + §15.1).
///
/// Binds a Unix socket (always) and optionally a TCP listener; serves
/// the axum router from `proxy::build_router`. The router caches caps
/// for 5 min and fails closed after 60s of broker silence.
async fn run_proxy_mode(args: Args) -> anyhow::Result<()> {
    let broker_url = args
        .proxy_broker_url
        .clone()
        .ok_or_else(|| anyhow::anyhow!(
            "--proxy-broker-url required in proxy mode (or set AGENTKEYS_PROXY_BROKER_URL)"
        ))?;
    let session_jwt = args
        .proxy_session_jwt
        .clone()
        .ok_or_else(|| anyhow::anyhow!(
            "--proxy-session-jwt required in proxy mode (or set AGENTKEYS_PROXY_SESSION_JWT)"
        ))?;

    let socket_path = args
        .proxy_listen
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(proxy::resolve_socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {parent:?}"))?;
    }
    // Best-effort: remove a stale socket file from a prior crashed run.
    let _ = std::fs::remove_file(&socket_path);

    let state = proxy::build_state(broker_url.clone(), session_jwt);
    let app = proxy::build_router(state.clone());

    info!(
        socket = %socket_path.display(),
        broker_url = %broker_url,
        "starting agentkeys-daemon in cap-proxy mode"
    );

    let unix_listener = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("bind unix socket {socket_path:?}"))?;
    // Permission-gate to the owner uid only. Stage 2 swaps for SO_PEERCRED
    // strict caller verification.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&socket_path, perms)?;
    }

    // If --proxy-tcp is set, bind that listener too and run both in parallel.
    let app_for_unix = app.clone();
    let unix_task = tokio::spawn(async move {
        // axum 0.7 doesn't ship a unix-listener helper directly; build a
        // tiny accept loop using hyper-util.
        use hyper_util::server::conn::auto::Builder;
        use hyper_util::rt::TokioIo;
        use tower::Service;
        let svc = app_for_unix.into_make_service();
        let svc = std::sync::Arc::new(tokio::sync::Mutex::new(svc));
        loop {
            let (stream, _addr) = match unix_listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error=%e, "unix accept failed");
                    continue;
                }
            };
            let svc_clone = svc.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let mut guard = svc_clone.lock().await;
                let tower_service = match guard.call(()).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error=%e, "make_service failed");
                        return;
                    }
                };
                drop(guard);
                let hyper_svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut tower_service = tower_service.clone();
                    async move { tower_service.call(req).await }
                });
                if let Err(e) = Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, hyper_svc)
                    .await
                {
                    tracing::error!(error=%e, "unix conn serve failed");
                }
            });
        }
    });

    let tcp_task = if let Some(addr) = args.proxy_tcp.as_deref() {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind TCP {addr}"))?;
        let app_for_tcp = app.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app_for_tcp).await {
                tracing::error!(error=%e, "tcp serve failed");
            }
        }))
    } else {
        None
    };

    // Wait for whichever task ends first (typically Ctrl-C kills both).
    tokio::select! {
        _ = unix_task => {},
        _ = async { if let Some(t) = tcp_task { let _ = t.await; } else { std::future::pending::<()>().await } } => {},
    }
    Ok(())
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
