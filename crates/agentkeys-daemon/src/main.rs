use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentkeys_core::backend::CredentialBackend;
use agentkeys_core::init_flow;
use agentkeys_core::mock_client::MockHttpClient;
use agentkeys_core::session_store;
use agentkeys_types::{Session, WalletAddress};
use anyhow::Context;
use clap::Parser;
use tracing::info;

mod audit_decode;
mod companion;
mod hardening;
mod master_session;
mod pairing;
mod presets;
mod proxy;
mod session;
mod ui_bridge;

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

    /// v2 stage-1 ui-bridge mode (arch.md §22c.1 web-UI surface). When
    /// set, the daemon serves the parent-control web UI's HTTP surface
    /// on `--ui-bridge-bind` (default 127.0.0.1:3114), CORS-allowing
    /// `--ui-bridge-origin` (default http://localhost:3113). Exposes
    /// /v1/k11/enroll/{begin,finish} for browser-driven WebAuthn
    /// enrollment. Independent of `--proxy` and `--master-companion`.
    #[arg(long)]
    ui_bridge: bool,

    /// Bind address for ui-bridge mode. Default 127.0.0.1:3114.
    #[arg(
        long,
        env = "AGENTKEYS_UI_BRIDGE_BIND",
        default_value = "127.0.0.1:3114"
    )]
    ui_bridge_bind: String,

    /// Origin the web UI is served from (used for CORS + WebAuthn rpOrigin).
    /// Default http://localhost:3113.
    #[arg(
        long,
        env = "AGENTKEYS_UI_BRIDGE_ORIGIN",
        default_value = "http://localhost:3113"
    )]
    ui_bridge_origin: String,

    /// WebAuthn Relying Party ID. Defaults to "localhost" for dev.
    /// In production, set to the operator's domain (e.g. "agentkeys.io").
    #[arg(long, env = "AGENTKEYS_UI_BRIDGE_RP_ID", default_value = "localhost")]
    ui_bridge_rp_id: String,

    /// WebAuthn Relying Party display name. Shown to user in the
    /// platform-authenticator UI ("agentKeys would like to register…").
    #[arg(long, env = "AGENTKEYS_UI_BRIDGE_RP_NAME", default_value = "AgentKeys")]
    ui_bridge_rp_name: String,

    /// HARNESS/TEST SEAM (web-parity, v2-demo phase 6): seed the ui-bridge
    /// onboarding session directly with an existing master J1, bypassing the
    /// interactive email + WebAuthn onboarding. Lets the harness drive the REAL
    /// plant chain with its already-registered master (pair with
    /// --master-device-key-hash + --ui-bridge-seed-omni). UNSET in normal operation.
    #[arg(long, env = "AGENTKEYS_UI_BRIDGE_SEED_SESSION_JWT")]
    ui_bridge_seed_session_jwt: Option<String>,

    /// Companion to --ui-bridge-seed-session-jwt: the master omni the seeded
    /// session authenticates as (0x-prefixed or bare; normalized to 0x).
    #[arg(long, env = "AGENTKEYS_UI_BRIDGE_SEED_OMNI")]
    ui_bridge_seed_omni: Option<String>,

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

    #[arg(
        long,
        help = "Recover agent by alias or wallet address (e.g. my-bot or 0x...)"
    )]
    recover: Option<String>,

    #[arg(
        long,
        help = "Recovery method: passkey or email (skips master approval)"
    )]
    method: Option<String>,

    #[arg(long)]
    stdio: bool,

    #[arg(
        long,
        default_value = "300",
        help = "Pair/recover poll timeout in seconds"
    )]
    pair_timeout: u64,

    #[arg(
        long,
        env = "AGENTKEYS_SESSION_ID",
        help = "Custom session namespace (default: derived from wallet address)"
    )]
    session_id: Option<String>,

    #[arg(
        long,
        value_name = "ALIAS|WALLET",
        help = "Bind pair request to a specific master (alias or 0x... wallet)"
    )]
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

    /// W3 real-memory: the memory worker base URL (e.g. https://memory.example.invalid).
    /// Unset ⇒ master-memory plant/list use the in-memory fallback (dev/no-infra).
    /// Canonical env `AGENTKEYS_WORKER_MEMORY_URL` (matches `--config-url`'s
    /// `AGENTKEYS_WORKER_CONFIG_URL` + `scripts/operator-workstation.env`).
    #[arg(long, env = "AGENTKEYS_WORKER_MEMORY_URL")]
    memory_url: Option<String>,

    /// W3 real-memory: per-actor memory IAM role ARN for the STS relay (sourced from
    /// operator-workstation.env). Required alongside --memory-url for the real chain.
    #[arg(long, env = "MEMORY_ROLE_ARN")]
    memory_role_arn: Option<String>,

    /// #201 config data class: the config worker base URL (e.g. https://config.example.invalid).
    /// Unset ⇒ the master-memory list derives categories from the in-memory cache instead of
    /// the durable, master-only Config-class taxonomy (config/memory-taxonomy.enc); dev/no-infra.
    #[arg(long, env = "AGENTKEYS_WORKER_CONFIG_URL")]
    config_url: Option<String>,

    /// #201 config data class: per-actor config IAM role ARN for the STS relay (CONFIG_ROLE_ARN,
    /// sourced from operator-workstation.env). Required alongside --config-url for the real
    /// taxonomy chain; a partial config fails loud (issue #90 discipline).
    #[arg(long, env = "CONFIG_ROLE_ARN")]
    config_role_arn: Option<String>,

    /// #207 classifier-service: the classify worker base URL (e.g. https://classify.example.invalid).
    /// Set ⇒ classification (cred auto-categorize #207 item 7, connect-time auto-distribute
    /// item 5) runs the cap-gated, audited worker TAG path. Unset ⇒ the daemon classifies
    /// against the bundled `agentkeys-catalog` tier-0 locally (deterministic, dev/no-infra).
    #[arg(long, env = "AGENTKEYS_WORKER_CLASSIFY_URL")]
    classify_url: Option<String>,

    /// #97 — the audit worker the web decode view fetches REAL `AuditEnvelope`s
    /// from (by the submit receipt hashes). Empty (the default) ⇒ the decode
    /// stays a synthesized preview; set `AGENTKEYS_AUDIT_WORKER_URL` to the audit
    /// worker base URL to fetch real envelopes. No hardcoded host default — the
    /// operator configures it explicitly (#317).
    #[arg(long, env = "AGENTKEYS_AUDIT_WORKER_URL", default_value = "")]
    audit_worker_url: String,

    /// W3 real-memory: AWS region for the STS relay.
    #[arg(long, env = "REGION", default_value = "us-east-1")]
    region: String,

    /// W3 real-memory: the on-chain-registered master device key hash (the cap-mint
    /// device binding). Must match the device registered via the W3 bootstrap.
    /// Issue #196 makes this a FALLBACK — once the K11-finish register shell-out
    /// runs, the daemon uses the freshly-registered hash automatically.
    #[arg(long, env = "AGENTKEYS_MASTER_DEVICE_KEY_HASH")]
    master_device_key_hash: Option<String>,

    /// Issue #196: path to `harness/scripts/heima-register-first-master.sh`. When
    /// set, the ui-bridge K11-finish handler shells out to it to register the
    /// master device on chain (un-stubbing `chain_tx_hash`) under the session
    /// omni, signed by the local deployer key. Unset ⇒ on-chain registration is
    /// skipped and `GET /v1/onboarding/state` reports `chain: none` (dev/no-infra).
    #[arg(long, env = "AGENTKEYS_REGISTER_MASTER_SCRIPT")]
    register_master_script: Option<String>,

    /// How long to wait for the operator to complete email-link click
    /// or OAuth2 callback before failing init.
    #[arg(long, default_value_t = 300)]
    init_poll_timeout_seconds: u64,

    /// Issue #144 §10.2 (method A): open an agent-INITIATED pairing request.
    /// Generates (or reuses) the K10 device key IN THE SANDBOX, POSTs
    /// `/v1/agent/pairing/request`, and prints `{request_id, pairing_code, …}` on
    /// stdout. The agent DISPLAYS `pairing_code` (QR / screen) for its owner to
    /// claim (the Matter/HomeKit model); `request_id` is the secret retrieval
    /// ticket for `--retrieve-pairing`. One-shot: requests and exits. Requires
    /// `--broker-url`. (The MCP/proxy surface runs as a separate process per §22c.)
    #[arg(long, conflicts_with_all = ["init_email", "init_oauth2_google", "recover", "retrieve_pairing"])]
    request_pairing: bool,

    /// Issue #144 §10.2 (method A): retrieve `J1_agent` after a master claims the
    /// pairing request. Polls `/v1/agent/pairing/poll` (until claimed or
    /// `--init-poll-timeout-seconds`), persists `J1_agent`, and prints the binding
    /// artifact on stdout for the master's already-submitted `registerAgentDevice`.
    /// Resolves `request_id` from `--request-id` or the state file written by
    /// `--request-pairing`. One-shot. Requires `--broker-url`.
    #[arg(long, conflicts_with_all = ["init_email", "init_oauth2_google", "recover"])]
    retrieve_pairing: bool,

    /// The `request_id` returned by `--request-pairing`, for `--retrieve-pairing`.
    /// If omitted, read from the per-device pairing state file
    /// (`~/.agentkeys/pairing-request-<device_pubkey>.json`).
    #[arg(long)]
    request_id: Option<String>,

    /// Replace an existing UNEXPIRED `--request-pairing` request for this device.
    /// Without it, re-running `--request-pairing` while a prior request is still
    /// claimable refuses (so it can't silently destroy the only retrieval handle,
    /// since request_id is off stdout). #224: when a new request DOES open, the
    /// broker supersedes (deletes) this device's prior OPEN broker request, so
    /// `--force` (or repeated runs) leave EXACTLY ONE open request — no duplicate
    /// pending cards accumulate on the master.
    #[arg(long)]
    force: bool,

    /// Path to the agent's K10 device-key file for the pairing flow. Defaults
    /// to the same path as `agentkeys agent device-session`
    /// (`~/.agentkeys/agent-device.key`) so the CLI + daemon share one key.
    /// Reused on retry (never auto-regenerated) so a re-run after a failed master
    /// bind/grant keeps the same `device_key_hash` (already-registered skip).
    #[arg(long, env = "AGENTKEYS_DEVICE_KEY_FILE")]
    device_key_file: Option<String>,
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

    if args.ui_bridge {
        return run_ui_bridge_mode(args).await;
    }

    // Issue #144 §10.2 (method A) one-shot pairing. Two synchronous steps mirror
    // the two broker endpoints: --request-pairing opens the request + prints the
    // code; --retrieve-pairing polls until the master claims, then persists
    // J1_agent + emits the binding artifact. Both run before the --backend
    // requirement + hardening (they need neither — only --broker-url + OS RNG).
    if args.request_pairing {
        return run_request_pairing(args).await;
    }
    if args.retrieve_pairing {
        return run_retrieve_pairing(args).await;
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
            session_store::save_session(&result.session, &sid).context("save recovered session")?;
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
            session_store::save_session(&result.session, &sid).context("save recovered session")?;
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
                            !s.starts_with("daemon-") && s != "master" && !s.starts_with("__agk_")
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
                    let parent_wallet =
                        resolve_parent_if_set(&backend_url, args.parent.as_deref())?;
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

/// Poll cadence for `--retrieve-pairing` while waiting for the master to claim.
/// Internal timing constant (not operator-facing); the overall wait is bounded by
/// `--init-poll-timeout-seconds`.
const PAIRING_POLL_INTERVAL_SECONDS: u64 = 3;

/// Default state file written by `--request-pairing` and read back by
/// `--retrieve-pairing` (so the two one-shot invocations don't have to thread
/// `request_id` by hand; `--request-id` overrides). 0600.
/// Per-DEVICE pairing state file (0600). Keyed by the K10 `device_pubkey` so two
/// concurrent `--request-pairing` under one HOME with DISTINCT device keys never
/// clobber each other's `request_id` retrieval handle (the state file is the
/// default handle now that request_id is kept off stdout). `--request-pairing`
/// writes it; `--retrieve-pairing` derives the SAME path from its own device key.
fn pairing_state_path(device_pubkey: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    format!("{home}/.agentkeys/pairing-request-{device_pubkey}.json")
}

/// Guard `--request-pairing` against silently clobbering an in-flight request for
/// the SAME device. Refuses (Err) when `existing_state` holds an UNEXPIRED
/// request and `force` is false — re-running would replace the only retrieval
/// handle (request_id is off stdout), stranding a still-claimable pairing_code.
/// Proceeds (Ok) when there is no prior state, it is expired/unparseable, or
/// `--force` is set. This guards only the LOCAL state file; once a new request
/// DOES open, the broker supersedes this device's prior OPEN row server-side
/// (#224), so the master never sees duplicate pending cards.
fn pairing_request_guard(
    existing_state: Option<&str>,
    now_secs: i64,
    force: bool,
) -> anyhow::Result<()> {
    if force {
        return Ok(());
    }
    let Some(raw) = existing_state else {
        return Ok(());
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Ok(()); // unreadable prior state is not a valid handle to protect
    };
    let expires_at = v.get("expires_at").and_then(|x| x.as_i64()).unwrap_or(0);
    if expires_at > now_secs {
        anyhow::bail!(
            "an unexpired §10.2 pairing request already exists for this device (expires in {}s) — \
             retrieve it with --retrieve-pairing, wait for it to expire, or pass --force to replace it",
            expires_at - now_secs
        );
    }
    Ok(())
}

/// Acquire an advisory lock at `<path>.lock` so two CONCURRENT `--request-pairing`
/// invocations serialize: the second is refused instead of racing key generation,
/// the unexpired-request guard, the broker POST, or the state write. Releases when
/// the returned File is dropped, so the caller holds it across the whole critical
/// section (`--force` replaces under the same lock).
fn acquire_pairing_lock(path: &str) -> anyhow::Result<std::fs::File> {
    use fs2::FileExt;
    let lock_path = format!("{path}.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("open pairing lock {lock_path}"))?;
    f.try_lock_exclusive().map_err(|_| {
        anyhow::anyhow!("another --request-pairing is in progress — retry once it finishes")
    })?;
    Ok(f)
}

/// `--request-pairing` (method A §10.2): generate (or reuse) the K10 device key
/// in the sandbox, open an agent-INITIATED pairing request at the broker, and
/// print `{pairing_code, state_file, …}` on stdout. The agent DISPLAYS
/// `pairing_code` for its owner to claim (the Matter/HomeKit model); the device
/// key NEVER leaves this machine.
///
/// Logs go to stderr; the JSON artifact is the ONLY thing on stdout, so the wire
/// harness can capture it. `request_id` — the secret retrieval ticket — is
/// DELIBERATELY kept OFF stdout (it is half of the replayable broker-poll tuple
/// `(request_id, device_pubkey, pop_sig)`); it is written only to the 0600
/// `state_file`, which `--retrieve-pairing` reads by default and from which an
/// explicit workflow can source it.
/// Default broker for the agent-side pairing one-shots (`--request-pairing` /
/// `--retrieve-pairing`) when neither `--broker-url` nor `AGENTKEYS_BROKER_URL` is
/// given. These commands ALWAYS need a broker, so prod is the sane default (override
/// with the flag/env for a test broker). Deliberately NOT applied to `--ui-bridge`,
/// where an unset `broker_url` means "fall back to pre-sourced AWS creds" (§191).
const DEFAULT_PAIRING_BROKER_URL: &str = "https://broker.example.invalid";

async fn run_request_pairing(args: Args) -> anyhow::Result<()> {
    use agentkeys_core::device_crypto::DeviceKey;

    let broker_url = args
        .broker_url
        .clone()
        .unwrap_or_else(|| DEFAULT_PAIRING_BROKER_URL.to_string());
    let base = broker_url.trim_end_matches('/').to_string();

    // Serialize the ENTIRE --request-pairing flow (K10 load/generate → guard →
    // broker POST → state write) under ONE HOME-scoped advisory lock, acquired
    // BEFORE keygen. The per-device state path isn't known until after keygen, so
    // a lock taken later can't stop two concurrent invocations from racing key
    // generation (fresh HOME: both see no key, generate different keys, race the
    // key-file write) or the state write. A second concurrent --request-pairing is
    // refused; released when `_pairing_lock` drops (fn end / early `?`-error).
    let _pairing_lock = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let lock_dir = format!("{home}/.agentkeys");
        std::fs::create_dir_all(&lock_dir).ok();
        acquire_pairing_lock(&format!("{lock_dir}/request-pairing"))?
    };

    let key_file = args
        .device_key_file
        .clone()
        .unwrap_or_else(|| "~/.agentkeys/agent-device.key".to_string());
    // Reuse the existing key on retry (no regen): a failed master claim/bind
    // must re-request with the SAME device_key_hash so the on-chain submit hits
    // the already-registered short-circuit instead of binding a second key.
    let dk =
        DeviceKey::load_or_generate(&key_file, false).context("load/generate K10 device key")?;
    let device_pubkey = dk.address().to_string();
    let device_key_hash = dk.device_key_hash().context("device_key_hash")?;
    let pop_sig = dk.pop_sig().context("pop_sig")?;

    // Refuse to clobber an in-flight (unexpired) request for this device unless
    // --force: request_id is off stdout, so a silent overwrite would strand a
    // still-claimable pairing_code with no way to retrieve it. (Concurrency is
    // already serialized by the HOME-scoped _pairing_lock above, held through
    // this guard + the POST + the state write.)
    let state_file = pairing_state_path(&device_pubkey);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    pairing_request_guard(
        std::fs::read_to_string(&state_file).ok().as_deref(),
        now_secs,
        args.force,
    )?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        // Never follow redirects: the request/poll POST bodies carry the pairing
        // credential (device_pubkey + pop_sig, and request_id for poll), and
        // reqwest re-sends a cloneable body across 307/308 — a broker/proxy
        // redirect would forward that bearer-minting tuple to another origin. A
        // 3xx is therefore fatal (classify_poll suppresses the body).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build http client")?;
    let resp = client
        .post(format!("{base}/v1/agent/pairing/request"))
        .json(&serde_json::json!({
            "device_pubkey": device_pubkey,
            "pop_sig": pop_sig,
        }))
        .send()
        .await
        .context("POST /v1/agent/pairing/request")?;
    let status = resp.status();
    // Cap the body (one-shot request, but a faulty broker/proxy shouldn't be able
    // to make us buffer an unbounded response).
    let text = read_capped_body(resp, MAX_POLL_BODY).await;
    if !status.is_success() {
        // Body is never trusted (a proxy/WAF could echo the request JSON incl.
        // pop_sig) — same suppression contract as the poll path.
        anyhow::bail!(
            "pairing request failed: {}",
            format_broker_error(status, &text)
        );
    }
    let body: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        anyhow::anyhow!(
            "unparseable request response (body suppressed; parse error at line {} col {})",
            e.line(),
            e.column()
        )
    })?;
    let request_id = body
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("request response missing request_id (body suppressed)"))?;
    let pairing_code = body
        .get("pairing_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("request response missing pairing_code (body suppressed)")
        })?;
    let expires_at = body.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);

    // Persist the request state (0600, per-device path computed + guarded above)
    // so `--retrieve-pairing` can resolve request_id without the caller threading
    // it (--request-id overrides).
    if let Some(parent) = std::path::Path::new(&state_file).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let state_json = serde_json::json!({
        "request_id": request_id,
        "pairing_code": pairing_code,
        "device_pubkey": device_pubkey,
        "expires_at": expires_at,
    })
    .to_string();
    agentkeys_core::device_crypto::write_key_0600(&state_file, &state_json)
        .context("persist pairing request state (0600)")?;

    // Human-facing prompt on stderr (logs stream): show the code to the owner.
    info!(
        target: "agentkeys.daemon.init",
        device = %device_pubkey,
        device_key_hash = %device_key_hash,
        "agentkeys-daemon opened §10.2 pairing request — show your owner the code to claim: {pairing_code}; they cross-check device_key_hash={device_key_hash} on the master before approving (#224)"
    );

    // Machine artifact on STDOUT (logs are on stderr). The owner reads
    // pairing_code to claim; request_id is NOT here (it is half the replayable
    // poll tuple) — it lives only in the 0600 state_file for --retrieve-pairing.
    println!(
        "{}",
        request_artifact(
            pairing_code,
            &device_pubkey,
            &device_key_hash,
            expires_at,
            &state_file,
            &key_file,
        )
    );
    Ok(())
}

/// `--retrieve-pairing` (method A §10.2): after the master claims the pairing
/// request, poll the broker until `J1_agent` is available, persist it, and print
/// the binding artifact the master's already-submitted `registerAgentDevice`
/// consumes. The device key NEVER leaves this machine.
///
/// Resolves `request_id` from `--request-id` or the state file written by
/// `--request-pairing`. Polls every `PAIRING_POLL_INTERVAL_SECONDS` until claimed
/// or `--init-poll-timeout-seconds`.
async fn run_retrieve_pairing(args: Args) -> anyhow::Result<()> {
    use agentkeys_core::device_crypto::DeviceKey;

    let broker_url = args
        .broker_url
        .clone()
        .unwrap_or_else(|| DEFAULT_PAIRING_BROKER_URL.to_string());
    let base = broker_url.trim_end_matches('/').to_string();

    // Load the device key FIRST: its device_pubkey keys the per-device state file
    // read below. Same key as --request-pairing (never regenerate — the broker
    // bound the request to this exact device_pubkey, and poll re-proves it).
    let key_file = args
        .device_key_file
        .clone()
        .unwrap_or_else(|| "~/.agentkeys/agent-device.key".to_string());
    let dk =
        DeviceKey::load_or_generate(&key_file, false).context("load/generate K10 device key")?;
    let device_pubkey = dk.address().to_string();
    let device_key_hash = dk.device_key_hash().context("device_key_hash")?;
    let pop_sig = dk.pop_sig().context("pop_sig")?;

    // request_id: explicit flag wins; else read the per-device state file written
    // by --request-pairing (derived from THIS device key, so it resolves to the
    // file --request-pairing wrote for the same device — concurrent requests for
    // other devices have their own files and can't be read by mistake).
    let request_id = match args.request_id.clone() {
        Some(id) => id,
        None => {
            let state_file = pairing_state_path(&device_pubkey);
            let raw = std::fs::read_to_string(&state_file).with_context(|| {
                format!("read pairing state file {state_file} (pass --request-id to override)")
            })?;
            let v: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("parse pairing state file {state_file}"))?;
            v.get("request_id")
                .and_then(|x| x.as_str())
                .map(String::from)
                .ok_or_else(|| {
                    anyhow::anyhow!("pairing state file {state_file} missing request_id")
                })?
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        // Never follow redirects: the request/poll POST bodies carry the pairing
        // credential (device_pubkey + pop_sig, and request_id for poll), and
        // reqwest re-sends a cloneable body across 307/308 — a broker/proxy
        // redirect would forward that bearer-minting tuple to another origin. A
        // 3xx is therefore fatal (classify_poll suppresses the body).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build http client")?;

    // Poll until claimed or the operator deadline. classify_poll() (below,
    // unit-tested) decides the failure class; here we drive retries. Two
    // deadline guards (codex review #182): the loop checks the deadline at the
    // TOP before sending (so we never make an extra poll after timeout), and
    // each request is bounded by the remaining time (so a hung/slow poll can't
    // overrun it). Instant = monotonic. `last_outcome` makes the give-up message
    // reflect the CURRENT state (pending vs a transient error); read at the top
    // on the first iteration, so it is never a dead assignment.
    let deadline = Instant::now() + Duration::from_secs(args.init_poll_timeout_seconds);
    let mut transient_attempts: u32 = 0;
    let mut last_outcome: Option<String> = None;
    let body: serde_json::Value = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            match &last_outcome {
                Some(reason) => anyhow::bail!(
                    "pairing poll gave up after {}s — last error was transient: {reason}",
                    args.init_poll_timeout_seconds
                ),
                None => anyhow::bail!(
                    "pairing not claimed within {}s — the master has not run `agentkeys agent claim --pairing-code <code>` yet",
                    args.init_poll_timeout_seconds
                ),
            }
        }

        // One poll, bounded by the remaining deadline so a hung/slow request
        // (or the client's own timeout) can never overrun the operator timeout.
        let poll = async {
            let resp = client
                .post(format!("{base}/v1/agent/pairing/poll"))
                .json(&serde_json::json!({
                    "request_id": request_id,
                    "device_pubkey": device_pubkey,
                    "pop_sig": pop_sig,
                }))
                .send()
                .await?;
            let status = resp.status();
            // Read any server-directed Retry-After (429 AND 5xx load-shed, e.g.
            // 503) from the header BEFORE consuming the body.
            let retry_after = retry_after_for(&resp, SystemTime::now());
            // Skip the body for retryable statuses (5xx/408/429) — classify_poll
            // suppresses it anyway, and an overloaded/malicious broker must not be
            // able to make every retry download a huge/slow body until the
            // deadline. Success/fatal bodies are read but capped.
            let text = read_poll_body(resp).await;
            Ok::<_, reqwest::Error>((status, retry_after, text))
        };

        let (class, retry_after) = match tokio::time::timeout(remaining, poll).await {
            Err(_elapsed) => (
                PollClass::Transient("poll exceeded the remaining pairing deadline".to_string()),
                None,
            ),
            Ok(Err(e)) => (PollClass::Transient(format!("send: {e}")), None),
            Ok(Ok((status, retry_after, text))) => (classify_poll(status, &text), retry_after),
        };

        match class {
            PollClass::Claimed(v) => break v,
            PollClass::Fatal(reason) => anyhow::bail!(
                "pairing poll rejected by broker ({reason}) — a stale pairing state file or \
                 wrong --device-key-file will not resolve by waiting; re-run --request-pairing"
            ),
            PollClass::Pending => {
                last_outcome = None;
                transient_attempts = 0;
                info!(
                    target: "agentkeys.daemon.init",
                    "§10.2 pairing request still pending — waiting for the master to claim…"
                );
                sleep_within_deadline(Duration::from_secs(PAIRING_POLL_INTERVAL_SECONDS), deadline)
                    .await;
            }
            PollClass::Transient(reason) => {
                transient_attempts += 1;
                let wait = poll_retry_wait(retry_after, transient_attempts);
                let wait_secs = wait.as_secs();
                info!(
                    target: "agentkeys.daemon.init",
                    "§10.2 pairing poll transient (retry in ~{wait_secs}s): {reason}"
                );
                last_outcome = Some(reason);
                sleep_within_deadline(wait, deadline).await;
            }
        }
    };

    // Validate the claimed binding BEFORE logging, deriving session_id, or
    // emitting any field on stdout — these public fields are attacker-
    // influenceable under the untrusted-body model, so a reflected token must
    // never reach a log or the master's stdout.
    let ClaimedBinding {
        session_jwt,
        child_omni,
        operator_omni,
        derivation_path,
    } = validate_claimed_binding(&body)?;

    // Persist J1_agent so a daemon restart resumes (Session.wallet = K10 address;
    // the HDKD omni rides inside the J1 claims, not in Session.wallet).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sess = Session {
        token: session_jwt.clone(),
        wallet: WalletAddress(device_pubkey.clone()),
        scope: None,
        created_at: now,
        ttl_seconds: 18_000,
    };
    let sid = args
        .session_id
        .clone()
        .unwrap_or_else(|| format!("daemon-{child_omni}"));
    session_store::save_session(&sess, &sid).context("save pairing session")?;

    // Finding 2 (adversarial review): keep the bearer IN the sandbox. Write the
    // session JWT to an owner-only (0600) file that the in-sandbox MCP server reads
    // directly via --agent-session-bearer-file, and DO NOT print it on stdout — the
    // master captures stdout and would otherwise expose the bearer in its shell +
    // the sandbox process list (`ps`). Only PUBLIC binding fields leave the box.
    let session_file = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let dir = format!("{home}/.agentkeys");
        std::fs::create_dir_all(&dir).ok();
        // Per-ACTOR bearer path: pairing a second actor under the same HOME must
        // NOT overwrite the first actor's bearer (a stale artifact + an
        // overwritten file would pair actor A with JWT B → STS identity skew).
        session_bearer_path(&dir, &child_omni)
    };
    agentkeys_core::device_crypto::write_key_0600(&session_file, &session_jwt)
        .context("persist agent session jwt (0600)")?;

    info!(
        target: "agentkeys.daemon.init",
        child_omni = %child_omni,
        operator_omni = %operator_omni,
        device = %device_pubkey,
        session_id = %sid,
        "agentkeys-daemon retrieved §10.2 pairing — J1_agent persisted"
    );

    // Binding artifact on STDOUT (logs are on stderr). Same fields the master's
    // chain helper consumes; pop_sig + device_key_hash let the master submit
    // registerAgentDevice without re-deriving.
    //
    // request_id is DELIBERATELY omitted: the broker poll authenticates with the
    // tuple (request_id, device_pubkey, pop_sig) and mints a fresh J1_agent on
    // every claimed poll (the claimed row is not consumed, pop_sig is static), so
    // emitting request_id here would put a replayable bearer-minting credential
    // on stdout — which the master captures and which can surface in `ps`/logs —
    // defeating the "bearer stays in the sandbox" boundary. The master does not
    // need it (registerAgentDevice keys off omni + device + pop_sig; the agent
    // already holds request_id in its 0600 pairing-state file for polling).
    // (The broker-side replay window itself is tracked as a separate follow-up.)
    println!(
        "{}",
        binding_artifact(
            &device_pubkey,
            &child_omni,
            &operator_omni,
            &derivation_path,
            &device_key_hash,
            &pop_sig,
            &session_file,
            &key_file,
        )
    );
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
async fn run_ui_bridge_mode(args: Args) -> anyhow::Result<()> {
    let state = ui_bridge::build_state(
        &args.ui_bridge_rp_id,
        &args.ui_bridge_origin,
        &args.ui_bridge_rp_name,
        args.broker_url.clone(),
        args.signer_url.clone(),
        args.init_chain_id,
        args.memory_url.clone(),
        args.memory_role_arn.clone(),
        args.config_url.clone(),
        args.config_role_arn.clone(),
        args.classify_url.clone(),
        Some(args.audit_worker_url.clone()).filter(|u| !u.trim().is_empty()),
        args.region.clone(),
        args.master_device_key_hash.clone(),
        args.register_master_script.clone(),
        // Issue #220: root master-session persistence at ~/.agentkeys (None when no
        // $HOME resolves → persistence disabled, never a surprising relative path).
        master_session::MasterSessionStore::from_home_env(),
    )
    .with_context(|| {
        format!(
            "ui-bridge: webauthn build failed (rp_id={}, origin={})",
            args.ui_bridge_rp_id, args.ui_bridge_origin
        )
    })?;
    // Issue #220: the harness seed (--ui-bridge-seed-*) and on-disk rehydration are
    // mutually EXCLUSIVE. An explicit seed is authoritative, so we must NOT also
    // rehydrate a (possibly stale) on-disk session whose omni / registered device
    // would shadow the seed's omni and corrupt cap-mint. Seed XOR rehydrate.
    if let (Some(j1), Some(omni)) = (
        args.ui_bridge_seed_session_jwt.clone(),
        args.ui_bridge_seed_omni.clone(),
    ) {
        // Harness web-parity seam (v2-demo phase 6): seed the onboarding session so
        // the parity phase drives the REAL plant chain with the harness's already-
        // registered master, without interactive onboarding/WebAuthn. Pair with
        // --master-device-key-hash. The seed is ephemeral (never persisted).
        let omni = if omni.starts_with("0x") {
            omni
        } else {
            format!("0x{omni}")
        };
        *state.onboarding_session.write().await = Some(ui_bridge::OnboardingSession {
            email: "harness-web-parity@local".to_string(),
            omni,
            j1,
            wallet: String::new(),
        });
        info!("ui-bridge: SEEDED onboarding session (harness web-parity seam) — interactive onboarding bypassed");
    } else {
        // Normal path: rehydrate the master session from disk BEFORE serving. A
        // still-valid J1 → zero-prompt restore (no re-onboarding, no
        // --master-device-key-hash); an expired J1 → the coords load so
        // /v1/onboarding/state reports session: "expired" and the web app prompts
        // exactly one passkey re-auth.
        ui_bridge::rehydrate_master_session(&state).await;
    }
    let app = ui_bridge::build_router(state, &args.ui_bridge_origin);

    let listener = tokio::net::TcpListener::bind(&args.ui_bridge_bind)
        .await
        .with_context(|| format!("ui-bridge: bind TCP {}", args.ui_bridge_bind))?;

    info!(
        bind = %args.ui_bridge_bind,
        origin = %args.ui_bridge_origin,
        rp_id = %args.ui_bridge_rp_id,
        "ui-bridge serving"
    );

    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_proxy_mode(args: Args) -> anyhow::Result<()> {
    let broker_url = args.proxy_broker_url.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "--proxy-broker-url required in proxy mode (or set AGENTKEYS_PROXY_BROKER_URL)"
        )
    })?;
    let session_jwt = args.proxy_session_jwt.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "--proxy-session-jwt required in proxy mode (or set AGENTKEYS_PROXY_SESSION_JWT)"
        )
    })?;

    let socket_path = args
        .proxy_listen
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(proxy::resolve_socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
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
        use hyper_util::rt::TokioIo;
        use hyper_util::server::conn::auto::Builder;
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
                let hyper_svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let mut tower_service = tower_service.clone();
                        async move { tower_service.call(req).await }
                    },
                );
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

// ── §10.2 pairing-poll response classification (codex review #182) ───────────
// Pure, unit-testable helpers behind run_retrieve_pairing's poll loop.

/// Classification of a single pairing-poll response. Pure over `(status, body)`
/// so it is unit-testable without HTTP.
#[derive(Debug)]
enum PollClass {
    /// 2xx `status: "claimed"` — carries the binding artifact (incl. J1_agent).
    Claimed(serde_json::Value),
    /// 2xx not-yet-claimed — keep waiting for the master.
    Pending,
    /// Retry until the deadline. The reason is PRE-REDACTED — it never contains a
    /// 2xx body, because a claimed 2xx carries `session_jwt`; logging it would
    /// leak the bearer token (codex review #182, high finding).
    Transient(String),
    /// Definitive 4xx (bad device_pubkey/pop_sig, expired/unknown request,
    /// device mismatch) — fail fast; waiting cannot fix it.
    Fatal(String),
}

/// Cap a response body for safe logging (avoid dumping huge error pages).
fn truncate_body(body: &str) -> String {
    const MAX: usize = 300;
    if body.chars().count() <= MAX {
        body.to_string()
    } else {
        let head: String = body.chars().take(MAX).collect();
        format!("{head}…[{} bytes total]", body.len())
    }
}

/// Closed allowlist of broker error KINDS (mirrors
/// `agentkeys-broker-server`'s `BrokerError::status_and_kind`). The fatal
/// branch logs the `error` field ONLY when it exactly matches one of these
/// short, broker-controlled category strings; any other value (a token,
/// reflected request_id/pop_sig, proxy/WAF text, or a wrongly-statused claimed
/// payload) is suppressed to status-only. The set degrades gracefully: a kind
/// missing here is logged as "unrecognized" — never leaked — so drift from the
/// broker only costs log detail, never correctness.
const KNOWN_BROKER_ERROR_KINDS: &[&str] = &[
    "unauthorized",
    "forbidden",
    "backend_unreachable",
    "sts_error",
    "audit_error",
    "bad_request",
    "internal",
];

/// Classify a pairing-poll response. 4xx → fail fast; 5xx/408/429 → transient;
/// a 2xx that fails to parse is transient but its body is SUPPRESSED (a claimed
/// 2xx contains `session_jwt`). 4xx/5xx bodies are broker error messages (no
/// token), capped for logging.
fn classify_poll(status: reqwest::StatusCode, body: &str) -> PollClass {
    if status.is_success() {
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(v) => match v.get("status").and_then(|s| s.as_str()) {
                Some("claimed") => {
                    // Validate required fields BEFORE returning Claimed, so the
                    // caller never interpolates a claimed body (it carries
                    // session_jwt). A parse-VALID schema mismatch — e.g. a
                    // non-string session_jwt — must not slip through as Claimed.
                    if v.get("session_jwt").and_then(|t| t.as_str()).is_some() {
                        PollClass::Claimed(v)
                    } else {
                        PollClass::Fatal(
                            "claimed response missing a valid string session_jwt \
                             (body suppressed — possible token/schema drift)"
                                .to_string(),
                        )
                    }
                }
                // Only an explicit "pending" keeps waiting; a missing/unknown
                // success status (e.g. "expired", an error envelope) is a
                // protocol/state error → fail fast.
                Some("pending") => PollClass::Pending,
                // Known statuses (claimed/pending) are matched above, so `other`
                // is by definition unrecognized. Do NOT interpolate the value: a
                // reflected `{"status":"session_jwt=..."}` would leak it (same
                // class as the fatal error-value leak). Log only whether status
                // was missing vs present-but-unrecognized — never the value or
                // the body.
                other => {
                    let detail = if other.is_none() {
                        "missing"
                    } else {
                        "unrecognized"
                    };
                    PollClass::Fatal(format!(
                        "unexpected poll status ({detail}; value + body suppressed)"
                    ))
                }
            },
            // Body is unparseable JSON. Do NOT format the serde error's Display
            // (a body-derived string): surface only its line/column integers,
            // which provably cannot carry a token. Keeps the boundary airtight —
            // no body-derived string is logged on ANY poll path.
            Err(e) => PollClass::Transient(format!(
                "unparseable success response (body suppressed; parse error at line {} col {})",
                e.line(),
                e.column()
            )),
        }
    } else if is_retryable_status(status) {
        // Retryable failure: suppress the response body entirely. A faulty
        // gateway/proxy can echo diagnostics, request metadata, or even a
        // misclassified claimed payload (carrying session_jwt) in a 5xx/408/429
        // body — none of which belongs in daemon logs. The status/class alone
        // is enough to drive the retry. (4xx Fatal below keeps its capped body:
        // it is the broker's actionable rejection reason and is not retried.)
        PollClass::Transient(format!("HTTP {status} (transient; body suppressed)"))
    } else {
        // Fatal (4xx/3xx + any other non-success, non-retryable status). The body
        // is never trusted — format_broker_error surfaces only an allowlisted
        // broker error KIND and suppresses everything else to status-only.
        PollClass::Fatal(format_broker_error(status, body))
    }
}

/// Format a non-success broker HTTP response for safe logging, shared by the poll
/// path (classify_poll's fatal branch) and the request path. The body is NEVER
/// trusted: a reverse proxy / WAF / stale route / reflected payload can echo a
/// token, request_id, or pop_sig. Parse the broker envelope ({"error": <kind>})
/// and surface the `error` field ONLY when its VALUE is one of the closed set of
/// known broker kinds (allowlisting the field NAME alone is not enough — e.g.
/// `{"error":"pop_sig=..."}` would leak); otherwise suppress to status-only.
fn format_broker_error(status: reqwest::StatusCode, body: &str) -> String {
    let kind = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .filter(|k| KNOWN_BROKER_ERROR_KINDS.contains(&k.as_str()));
    match kind {
        // truncate_body is a no-op on these short closed-set literals; kept as a
        // defensive second layer against any future kind drift.
        Some(k) => format!("HTTP {status}: {}", truncate_body(&k)),
        None => format!("HTTP {status} (body suppressed — unrecognized error kind)"),
    }
}

/// Parse a `Retry-After` header into a delay from `now`. Handles BOTH RFC 7231
/// forms: delta-seconds (`"120"`) and an HTTP-date
/// (`"Wed, 21 Oct 2026 07:28:00 GMT"`), so a proxy throttling with a future date
/// is honored instead of being ignored. A past/now date or an unparseable value
/// yields `None`, and the caller floors the wait at the jittered backoff.
fn parse_retry_after(header_val: Option<&str>, now: SystemTime) -> Option<Duration> {
    let raw = header_val?.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // HTTP-date form — honor only a FUTURE instant (past date → None → backoff).
    httpdate::parse_http_date(raw)
        .ok()?
        .duration_since(now)
        .ok()
}

/// Capped exponential backoff (base = poll interval) with sub-second jitter, so
/// many unauthenticated pollers don't retry in lockstep and extend a broker
/// overload (codex review #182, medium finding). `attempt` starts at 1.
fn backoff_with_jitter(attempt: u32) -> Duration {
    let base = PAIRING_POLL_INTERVAL_SECONDS.max(1);
    let factor = 1u64 << attempt.min(4); // ×2 … ×16
    let secs = base.saturating_mul(factor).min(30);
    let jitter_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 1000)
        .unwrap_or(0);
    Duration::from_secs(secs) + Duration::from_millis(jitter_ms)
}

/// Sleep `dur`, but never past `deadline`, so the next iteration's deadline
/// check fires promptly.
async fn sleep_within_deadline(dur: Duration, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    tokio::time::sleep(dur.min(remaining)).await;
}

/// Effective wait before the next transient retry. Floors at the jittered
/// backoff so a broker/proxy `Retry-After: 0` (or any value below the backoff)
/// can't disable backoff and let the loop hammer the broker until the deadline;
/// a LONGER `Retry-After` is still honored (codex review #182).
fn poll_retry_wait(retry_after: Option<Duration>, attempt: u32) -> Duration {
    let backoff = backoff_with_jitter(attempt);
    retry_after.map_or(backoff, |ra| ra.max(backoff))
}

/// Max bytes to buffer from a poll/request response body. A broker JSON envelope
/// is tiny; this bounds the allocation if a broker/proxy streams a huge body.
const MAX_POLL_BODY: usize = 64 * 1024;

/// Statuses classify_poll treats as retryable (body suppressed): 5xx, 408, 429.
/// Shared so the poll path can SKIP reading the body for these — an overloaded or
/// malicious broker must not be able to make every retry download a huge/slow
/// body until the deadline (codex review #182).
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Read at most `max` bytes of a response body by streaming chunks, so an
/// oversized body is never fully buffered. Returns lossy UTF-8.
async fn read_capped_body(mut resp: reqwest::Response, max: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = max.saturating_sub(buf.len());
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // hit the cap mid-chunk
                }
            }
            Ok(None) => break, // EOF
            Err(_) => break,   // transport error mid-body: use what we have
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Read a poll response body ONLY when the classifier will use it. Retryable
/// statuses (5xx/408/429) suppress the body anyway, so skip the download
/// entirely; success/fatal bodies are read but capped at `MAX_POLL_BODY`.
async fn read_poll_body(resp: reqwest::Response) -> String {
    if is_retryable_status(resp.status()) {
        return String::new();
    }
    read_capped_body(resp, MAX_POLL_BODY).await
}

/// Extract a server-directed `Retry-After` cooldown for any retryable response
/// that may legally carry it — NOT just 429. A `503 Service Unavailable` plus
/// `Retry-After: <delay>` is the standard load-shed/maintenance signal; honoring
/// it (via poll_retry_wait's max(header, backoff)) stops every daemon from
/// hammering an overloaded broker on local backoff. Non-retryable statuses have
/// no cooldown to honor.
fn retry_after_for(resp: &reqwest::Response, now: SystemTime) -> Option<Duration> {
    if !is_retryable_status(resp.status()) {
        return None;
    }
    parse_retry_after(
        resp.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        now,
    )
}

/// True iff `s` is a 64-char lowercase-hex omni address — the exact shape
/// `agentkeys_core::actor_omni::{actor_omni_hex,child_omni_hex}` emit. Rejects
/// reflected tokens, `0x`-prefixed values, uppercase, and any non-hex.
fn is_omni_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True iff `s` is a `//<label>` derivation path with a valid HDKD label
/// (`^[a-z0-9-]{1,32}$`), matching the broker's `format!("//{label}")`.
fn is_derivation_path(s: &str) -> bool {
    match s.strip_prefix("//") {
        Some(label) => {
            !label.is_empty()
                && label.len() <= 32
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }
        None => false,
    }
}

/// The PUBLIC binding fields the daemon logs + emits on stdout after a claimed
/// pairing. `classify_poll` only guarantees `session_jwt` is a string; the other
/// three fields are still attacker-influenceable under the same untrusted-body
/// model, and a reflected token in `child_omni`/`operator_omni`/`derivation_path`
/// would otherwise be logged AND printed to the master's stdout. Validate each
/// to its exact shape; a malformed identity is a protocol error.
struct ClaimedBinding {
    session_jwt: String,
    child_omni: String,
    operator_omni: String,
    derivation_path: String,
}

// Manual Debug that REDACTS session_jwt — never derive it, or a future
// `debug!("{binding:?}")` would dump the bearer. The public fields are already
// validated to safe shapes (64-hex omni / //label), so they print as-is.
impl std::fmt::Debug for ClaimedBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimedBinding")
            .field("session_jwt", &"<redacted>")
            .field("child_omni", &self.child_omni)
            .field("operator_omni", &self.operator_omni)
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}

/// Extract + validate the claimed-pairing binding from a 2xx claimed body.
/// Error messages never echo a field value (it could carry a token).
fn validate_claimed_binding(body: &serde_json::Value) -> anyhow::Result<ClaimedBinding> {
    let session_jwt = body
        .get("session_jwt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("claimed poll response missing session_jwt (body suppressed)")
        })?;
    let child_omni = body
        .get("child_omni")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let operator_omni = body
        .get("operator_omni")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let derivation_path = body
        .get("derivation_path")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if !is_omni_hex(child_omni) {
        anyhow::bail!("claimed poll response has a malformed child_omni (value suppressed)");
    }
    if !is_omni_hex(operator_omni) {
        anyhow::bail!("claimed poll response has a malformed operator_omni (value suppressed)");
    }
    if !is_derivation_path(derivation_path) {
        anyhow::bail!("claimed poll response has a malformed derivation_path (value suppressed)");
    }
    // Defense-in-depth HDKD check: child_omni MUST equal the deterministic
    // child_omni_hex(operator_omni, label). This rejects a shape-valid-but-
    // impossible tuple (corrupt/stale broker or a terminating proxy) HERE, before
    // run_retrieve_pairing saves the bearer + prints the artifact the master feeds
    // to registerAgentDevice — otherwise the master could register/grant an actor
    // that is not the HDKD child of the returned (operator_omni, path). The label
    // charset was validated by is_derivation_path above; values are suppressed.
    let label = derivation_path.strip_prefix("//").unwrap_or_default();
    let expected_child =
        agentkeys_core::actor_omni::child_omni_hex(operator_omni, label).map_err(|_| {
            anyhow::anyhow!("claimed binding: child_omni recompute failed (values suppressed)")
        })?;
    if expected_child != child_omni {
        anyhow::bail!(
            "claimed binding child_omni does not match HDKD(operator_omni, label) (values suppressed)"
        );
    }
    Ok(ClaimedBinding {
        session_jwt: session_jwt.to_string(),
        child_omni: child_omni.to_string(),
        operator_omni: operator_omni.to_string(),
        derivation_path: derivation_path.to_string(),
    })
}

/// The PUBLIC binding artifact emitted on stdout after a claimed pairing — the
/// fields the master's chain helper needs for `registerAgentDevice`. `request_id`
/// is intentionally NOT included: the broker poll authenticates with
/// (request_id, device_pubkey, pop_sig) and mints a fresh J1_agent on every
/// claimed poll, so emitting request_id would put a replayable bearer-minting
/// credential on stdout. session_jwt is likewise absent (it stays in the 0600
/// session file inside the sandbox).
#[allow(clippy::too_many_arguments)]
fn binding_artifact(
    agent_address: &str,
    actor_omni: &str,
    operator_omni: &str,
    derivation_path: &str,
    device_key_hash: &str,
    pop_sig: &str,
    session_file: &str,
    key_file: &str,
) -> serde_json::Value {
    serde_json::json!({
        "agent_address": agent_address,
        "actor_omni": actor_omni,
        "operator_omni": operator_omni,
        "derivation_path": derivation_path,
        "device_key_hash": device_key_hash,
        "pop_sig": pop_sig,
        "session_file": session_file,
        "key_file": key_file,
    })
}

/// The stdout artifact for `--request-pairing`. `request_id` is intentionally
/// NOT included — it is half the replayable broker-poll tuple
/// (request_id, device_pubkey, pop_sig), and the daemon already writes it to the
/// 0600 `state_file` that `--retrieve-pairing` reads by default. `pairing_code`
/// (the master's claim code) is NOT a poll credential and stays.
fn request_artifact(
    pairing_code: &str,
    agent_address: &str,
    device_key_hash: &str,
    expires_at: i64,
    state_file: &str,
    key_file: &str,
) -> serde_json::Value {
    serde_json::json!({
        "pairing_code": pairing_code,
        "agent_address": agent_address,
        "device_key_hash": device_key_hash,
        "expires_at": expires_at,
        "state_file": state_file,
        "key_file": key_file,
    })
}

/// Per-actor path for the 0600 session-bearer file, scoped by `child_omni` (the
/// validated 64-hex actor id — a safe filename). Pairing a second actor under the
/// same HOME thus writes a DISTINCT file instead of overwriting the first actor's
/// bearer, which would otherwise skew actor↔JWT (per-actor isolation). Re-pairing
/// the SAME actor reuses the same path (it overwrites only its own bearer).
fn session_bearer_path(dir: &str, child_omni: &str) -> String {
    format!("{dir}/agent-session-{child_omni}.jwt")
}

#[cfg(test)]
mod pairing_poll_tests {
    use super::{
        acquire_pairing_lock, backoff_with_jitter, binding_artifact, classify_poll,
        format_broker_error, is_derivation_path, is_omni_hex, is_retryable_status,
        pairing_request_guard, pairing_state_path, parse_retry_after, poll_retry_wait,
        read_poll_body, request_artifact, retry_after_for, session_bearer_path, truncate_body,
        validate_claimed_binding, PollClass, MAX_POLL_BODY, PAIRING_POLL_INTERVAL_SECONDS,
    };
    use reqwest::StatusCode;
    use std::time::{Duration, SystemTime};

    #[test]
    fn claimed_2xx_is_claimed() {
        let body = r#"{"status":"claimed","session_jwt":"tok"}"#;
        assert!(matches!(
            classify_poll(StatusCode::OK, body),
            PollClass::Claimed(_)
        ));
    }

    #[test]
    fn pending_2xx_is_pending() {
        assert!(matches!(
            classify_poll(StatusCode::OK, r#"{"status":"pending"}"#),
            PollClass::Pending
        ));
    }

    #[test]
    fn only_explicit_pending_is_pending() {
        // Unknown / missing / non-"pending" success status must NOT silently
        // wait — it fails fast (protocol/state error). The status VALUE is never
        // logged: a reflected `{"status":"session_jwt=..."}` must not leak (same
        // class as the fatal error-value leak).
        for body in ["{}", r#"{"foo":1}"#] {
            match classify_poll(StatusCode::OK, body) {
                PollClass::Fatal(reason) => assert!(
                    reason.contains("missing"),
                    "missing status should report 'missing', got {reason}"
                ),
                other => panic!("body {body} should fail fast, got {other:?}"),
            }
        }

        let long_leak = format!(r#"{{"status":"{}"}}"#, "SENTINEL_JWT".repeat(40));
        for body in [
            r#"{"status":"expired"}"#, // rejected/expired state
            r#"{"status":"error","detail":"nope"}"#,
            r#"{"status":"SENTINEL_JWT"}"#, // identifier-shaped token
            r#"{"status":"session_jwt=SENTINEL_JWT"}"#, // key=value leak
            long_leak.as_str(),             // long reflected string
        ] {
            match classify_poll(StatusCode::OK, body) {
                PollClass::Fatal(reason) => {
                    assert!(
                        !reason.contains("SENTINEL_JWT"),
                        "unknown status leaked its value: {reason}"
                    );
                    assert!(
                        reason.contains("unrecognized"),
                        "present-but-unknown status should report 'unrecognized', got {reason}"
                    );
                }
                other => panic!("body {body} should fail fast, got {other:?}"),
            }
        }
    }

    #[test]
    fn claimed_2xx_with_non_string_session_jwt_is_fatal_no_leak() {
        // A parse-VALID claimed body whose session_jwt is the wrong shape must
        // not become Claimed (the caller would otherwise dump it), and the
        // token-bearing body must not appear in the error.
        let body = r#"{"status":"claimed","session_jwt":{"token":"SECRET-OBJ-TOKEN"}}"#;
        match classify_poll(StatusCode::OK, body) {
            PollClass::Fatal(reason) => assert!(
                !reason.contains("SECRET-OBJ-TOKEN"),
                "token leaked into fatal reason: {reason}"
            ),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn malformed_claimed_2xx_never_leaks_token() {
        // A truncated claimed payload that fails to parse must not echo the body.
        let body = r#"{"status":"claimed","session_jwt":"SUPER-SECRET-TOKEN""#;
        match classify_poll(StatusCode::OK, body) {
            PollClass::Transient(reason) => assert!(
                !reason.contains("SUPER-SECRET-TOKEN"),
                "session token leaked into log reason: {reason}"
            ),
            other => panic!("expected Transient, got {other:?}"),
        }
    }

    #[test]
    fn server_errors_are_transient() {
        // A faulty gateway could echo a misclassified claimed payload (with a
        // token) inside a 5xx body — the transient reason must never carry it.
        let leaky_body = r#"<html>err {"session_jwt":"SENTINEL_TOKEN_LEAK"}</html>"#;
        for s in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            match classify_poll(s, leaky_body) {
                PollClass::Transient(reason) => assert!(
                    !reason.contains("SENTINEL_TOKEN_LEAK"),
                    "transient reason for {s} leaked the response body: {reason}"
                ),
                other => panic!("status {s} should be transient, got {other:?}"),
            }
        }
    }

    #[test]
    fn timeout_and_rate_limit_are_transient() {
        // Same suppression contract for 408/429: status only, never the body.
        let leaky_body = r#"{"session_jwt":"SENTINEL_TOKEN_LEAK"}"#;
        for s in [StatusCode::REQUEST_TIMEOUT, StatusCode::TOO_MANY_REQUESTS] {
            match classify_poll(s, leaky_body) {
                PollClass::Transient(reason) => assert!(
                    !reason.contains("SENTINEL_TOKEN_LEAK"),
                    "transient reason for {s} leaked the response body: {reason}"
                ),
                other => panic!("status {s} should be transient, got {other:?}"),
            }
        }
    }

    #[test]
    fn client_errors_fail_fast() {
        for s in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
        ] {
            assert!(
                matches!(
                    classify_poll(s, r#"{"error":"bad pop_sig"}"#),
                    PollClass::Fatal(_)
                ),
                "status {s} should fail fast"
            );
        }
    }

    #[test]
    fn fatal_non_success_bodies_never_leak_secrets() {
        // A fatal (4xx/3xx) body whose provenance we can't trust — proxy/WAF,
        // stale route, or a wrongly-statused claimed payload — must NEVER be
        // logged. Only the broker envelope's short `error` kind is allowed
        // through; everything else (session_jwt/request_id/pop_sig) is dropped.
        let secrets = ["SENTINEL_JWT", "SENTINEL_REQ_ID", "SENTINEL_POP_SIG"];

        // (a) No broker envelope (raw reflected/claimed payload) → fully suppressed.
        let no_envelope = r#"{"session_jwt":"SENTINEL_JWT","request_id":"SENTINEL_REQ_ID","pop_sig":"SENTINEL_POP_SIG"}"#;
        for s in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::MOVED_PERMANENTLY, // 3xx also lands in the fatal branch
        ] {
            match classify_poll(s, no_envelope) {
                PollClass::Fatal(reason) => {
                    for secret in secrets {
                        assert!(
                            !reason.contains(secret),
                            "fatal reason for {s} leaked {secret}: {reason}"
                        );
                    }
                    assert!(
                        reason.contains("body suppressed"),
                        "fatal reason for {s} should be suppressed, got {reason}"
                    );
                }
                other => panic!("status {s} should be fatal, got {other:?}"),
            }
        }

        // (b) Broker envelope with a KNOWN kind + sibling secret → logs ONLY the
        //     known kind, never the sibling secret.
        let known = r#"{"error":"forbidden","message":"...","session_jwt":"SENTINEL_JWT"}"#;
        match classify_poll(StatusCode::FORBIDDEN, known) {
            PollClass::Fatal(reason) => {
                assert!(
                    reason.contains("forbidden"),
                    "fatal reason should surface the known broker error kind: {reason}"
                );
                for secret in secrets {
                    assert!(
                        !reason.contains(secret),
                        "fatal reason leaked {secret}: {reason}"
                    );
                }
            }
            other => panic!("403 with known kind should be fatal, got {other:?}"),
        }

        // (c)-(e) An `error` field whose VALUE is not a known broker kind is
        // suppressed — allowlisting the field NAME alone is not enough. Covers:
        // an identifier-shaped token, a key=value leak, a long reflected string,
        // and arbitrary proxy text.
        let long_leak = format!(r#"{{"error":"{}"}}"#, "SENTINEL_JWT".repeat(40));
        for body in [
            r#"{"error":"SENTINEL_JWT"}"#,
            r#"{"error":"session_jwt=SENTINEL_JWT"}"#,
            long_leak.as_str(),
            r#"{"error":"some unexpected proxy message"}"#,
        ] {
            match classify_poll(StatusCode::BAD_REQUEST, body) {
                PollClass::Fatal(reason) => {
                    assert!(
                        !reason.contains("SENTINEL_JWT"),
                        "fatal reason leaked an unrecognized error value: {reason}"
                    );
                    assert!(
                        reason.contains("body suppressed"),
                        "unrecognized error value should be suppressed, got {reason}"
                    );
                }
                other => panic!("400 with unknown error value should be fatal, got {other:?}"),
            }
        }
    }

    #[test]
    fn retry_after_parses_delta_and_http_date() {
        let epoch = SystemTime::UNIX_EPOCH;
        // delta-seconds form (now-independent).
        assert_eq!(
            parse_retry_after(Some("5"), epoch),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            parse_retry_after(Some("  12 "), epoch),
            Some(Duration::from_secs(12))
        );
        // HTTP-date form, relative to `now`. A FUTURE date longer than local
        // backoff is honored (the point of finding #2 — no retry storm).
        assert_eq!(
            parse_retry_after(Some("Thu, 01 Jan 1970 01:00:00 GMT"), epoch),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_retry_after(Some("Thu, 01 Jan 1970 00:00:10 GMT"), epoch),
            Some(Duration::from_secs(10))
        );
        // A PAST date yields None → caller floors at jittered backoff.
        let later = epoch + Duration::from_secs(100);
        assert_eq!(
            parse_retry_after(Some("Thu, 01 Jan 1970 00:00:10 GMT"), later),
            None
        );
        // Garbage / missing → None.
        assert_eq!(parse_retry_after(Some("garbage"), epoch), None);
        assert_eq!(parse_retry_after(None, epoch), None);
    }

    #[test]
    fn binding_artifact_omits_replayable_request_id() {
        // The stdout artifact must NOT carry request_id: with it, the tuple
        // (request_id, device_pubkey=agent_address, pop_sig) replays the broker
        // poll to mint a fresh J1_agent. Nor may it carry the session_jwt.
        let art = binding_artifact(
            "0xdevice",
            "childomni",
            "operomni",
            "//hermes",
            "dkh",
            "popsig",
            "/s.jwt",
            "/k.json",
        );
        assert!(
            art.get("request_id").is_none(),
            "artifact must not expose request_id (replayable poll credential): {art}"
        );
        assert!(
            art.get("session_jwt").is_none(),
            "artifact must not expose the bearer"
        );
        // The fields the master legitimately needs are still present.
        for k in ["agent_address", "pop_sig", "device_key_hash", "actor_omni"] {
            assert!(art.get(k).is_some(), "artifact missing required field {k}");
        }
    }

    #[test]
    fn request_artifact_omits_replayable_request_id() {
        // --request-pairing stdout must NOT carry request_id (half the replayable
        // poll tuple); it lives only in the 0600 state_file. pairing_code (claim
        // code, not a poll credential) and the state_file path stay.
        let art = request_artifact("paircode", "0xdevice", "dkh", 123, "/state.json", "/k.json");
        assert!(
            art.get("request_id").is_none(),
            "request artifact must not expose request_id: {art}"
        );
        for k in ["pairing_code", "state_file", "agent_address"] {
            assert!(art.get(k).is_some(), "request artifact missing field {k}");
        }
    }

    #[test]
    fn format_broker_error_suppresses_untrusted_bodies() {
        // A 307 proxy body echoing the request JSON (incl. pop_sig) must NOT leak
        // through the request path's non-2xx error.
        let reflected = r#"{"device_pubkey":"0xabc","pop_sig":"SENTINEL_POP_SIG"}"#;
        let out = format_broker_error(StatusCode::TEMPORARY_REDIRECT, reflected);
        assert!(
            !out.contains("SENTINEL_POP_SIG"),
            "format_broker_error leaked pop_sig: {out}"
        );
        // An `error` field whose VALUE is not a known kind is suppressed too.
        let leaky_kind = r#"{"error":"pop_sig=SENTINEL_POP_SIG"}"#;
        assert!(
            !format_broker_error(StatusCode::BAD_REQUEST, leaky_kind).contains("SENTINEL_POP_SIG"),
            "unknown error-kind value leaked"
        );
        // A KNOWN broker kind is surfaced for operator diagnostics.
        let known = r#"{"error":"bad_request","message":"..."}"#;
        assert!(format_broker_error(StatusCode::BAD_REQUEST, known).contains("bad_request"));
    }

    #[test]
    fn session_bearer_path_is_per_actor() {
        let dir = "/h/.agentkeys";
        let omni_a = "a".repeat(64);
        let omni_b = "b".repeat(64);
        let a = session_bearer_path(dir, &omni_a);
        let b = session_bearer_path(dir, &omni_b);
        // Two distinct actors → distinct bearer files (no cross-actor overwrite).
        assert_ne!(a, b, "two actors must not share a bearer file: {a}");
        assert!(a.contains(&omni_a) && b.contains(&omni_b));
        // Re-pairing the SAME actor reuses its own path (overwrites only itself).
        assert_eq!(a, session_bearer_path(dir, &omni_a));
    }

    #[test]
    fn pairing_state_path_is_per_device() {
        // Two distinct device keys → distinct state files, so two concurrent
        // --request-pairing for different devices can't clobber each other's
        // request_id retrieval handle.
        let a = pairing_state_path("0xaaaa1111");
        let b = pairing_state_path("0xbbbb2222");
        assert_ne!(a, b, "distinct devices must not share a state file: {a}");
        assert!(a.contains("0xaaaa1111") && b.contains("0xbbbb2222"));
        assert!(a.ends_with(".json"));
        // Same device → stable path (--request-pairing and --retrieve-pairing
        // derive the same handle from the same device key).
        assert_eq!(a, pairing_state_path("0xaaaa1111"));
    }

    #[test]
    fn pairing_request_guard_protects_unexpired_handle() {
        let unexpired = r#"{"request_id":"x","expires_at":1000}"#;
        // Unexpired (now < expires_at) + no --force → refuse (no silent clobber).
        assert!(pairing_request_guard(Some(unexpired), 500, false).is_err());
        // --force overrides.
        assert!(pairing_request_guard(Some(unexpired), 500, true).is_ok());
        // Expired → safe to replace.
        assert!(pairing_request_guard(Some(unexpired), 2000, false).is_ok());
        // No prior state → proceed.
        assert!(pairing_request_guard(None, 500, false).is_ok());
        // Unreadable prior state is not a handle worth protecting → proceed.
        assert!(pairing_request_guard(Some("not json"), 500, false).is_ok());
    }

    #[test]
    fn acquire_pairing_lock_serializes_concurrent_requests() {
        let base = std::env::temp_dir().join(format!("akd-pairlock-{}", std::process::id()));
        let path = base.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(format!("{path}.lock"));
        // First acquisition succeeds and HOLDS the lock.
        let held = acquire_pairing_lock(&path).expect("first lock acquires");
        // A concurrent acquisition is refused while the first is held (serializes
        // the whole --request-pairing flow: keygen → guard → POST → state write).
        assert!(
            acquire_pairing_lock(&path).is_err(),
            "concurrent --request-pairing must be refused while one is in progress"
        );
        // After the first releases, a new acquisition succeeds.
        drop(held);
        assert!(
            acquire_pairing_lock(&path).is_ok(),
            "lock must re-acquire after release"
        );
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn is_retryable_status_covers_5xx_408_429_only() {
        for s in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert!(is_retryable_status(s), "{s} should be retryable");
        }
        for s in [
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::MOVED_PERMANENTLY,
        ] {
            assert!(!is_retryable_status(s), "{s} should NOT be retryable");
        }
    }

    #[tokio::test]
    async fn read_poll_body_skips_retryable_and_caps_success() {
        use axum::{routing::get, Router};
        // Bodies far larger than the cap, served on a retryable 503 and a 200.
        let big = "x".repeat(MAX_POLL_BODY * 4);
        let big503 = big.clone();
        let big200 = big;
        let app = Router::new()
            .route(
                "/r",
                get(move || {
                    let b = big503.clone();
                    async move { (axum::http::StatusCode::SERVICE_UNAVAILABLE, b) }
                }),
            )
            .route(
                "/ok",
                get(move || {
                    let b = big200.clone();
                    async move { b }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();

        // Retryable 503: the body is NOT read (empty), no matter how large.
        let resp = client.get(format!("http://{addr}/r")).send().await.unwrap();
        assert!(is_retryable_status(resp.status()));
        let body = read_poll_body(resp).await;
        assert!(
            body.is_empty(),
            "retryable body must be skipped, got {} bytes",
            body.len()
        );

        // Success 200: body is read but capped at MAX_POLL_BODY (not the full size).
        let resp = client
            .get(format!("http://{addr}/ok"))
            .send()
            .await
            .unwrap();
        let body = read_poll_body(resp).await;
        assert!(!body.is_empty());
        assert!(
            body.len() <= MAX_POLL_BODY,
            "success body must be capped at {MAX_POLL_BODY}, got {}",
            body.len()
        );
    }

    #[tokio::test]
    async fn retry_after_for_honors_503_load_shed() {
        use axum::{http::header::RETRY_AFTER, routing::get, Router};
        let app = Router::new()
            .route(
                "/down",
                get(|| async {
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        [(RETRY_AFTER, "300")],
                        "down",
                    )
                }),
            )
            .route("/ok", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();

        // 503 + Retry-After: 300 is honored even though it is NOT a 429.
        let resp = client
            .get(format!("http://{addr}/down"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            retry_after_for(&resp, SystemTime::UNIX_EPOCH),
            Some(Duration::from_secs(300)),
            "503 Retry-After must be honored, not just 429"
        );
        // A success response has no cooldown to honor.
        let resp = client
            .get(format!("http://{addr}/ok"))
            .send()
            .await
            .unwrap();
        assert_eq!(retry_after_for(&resp, SystemTime::UNIX_EPOCH), None);
    }

    #[test]
    fn backoff_is_capped_and_nondecreasing() {
        let a1 = backoff_with_jitter(1);
        let a_big = backoff_with_jitter(10);
        assert!(a1 >= Duration::from_secs(1));
        assert!(
            a_big <= Duration::from_secs(31),
            "backoff not capped: {a_big:?}"
        );
        assert!(a_big >= a1, "backoff should not shrink with attempts");
    }

    #[test]
    fn truncate_caps_long_bodies() {
        let long = "x".repeat(2000);
        let out = truncate_body(&long);
        assert!(out.chars().count() < 400);
        assert!(out.contains("bytes total"));
        assert_eq!(truncate_body("short"), "short");
    }

    #[test]
    fn omni_and_path_validators_reject_reflected_tokens() {
        // Valid shapes (64-char lowercase hex omni; //label path) pass.
        assert!(is_omni_hex(&"0123456789abcdef".repeat(4)));
        assert!(is_omni_hex(&"a".repeat(64)));
        assert!(is_derivation_path("//hermes"));
        assert!(is_derivation_path("//agent-01"));

        // Reflected tokens / wrong shapes are rejected — these would otherwise
        // be logged + printed on stdout from a claimed body.
        let upper_hex = "A".repeat(64); // uppercase hex
        let short_hex = "a".repeat(63); // wrong length
        for bad in [
            "session_jwt=SENTINEL_JWT",
            "eyJhbGciOiJIUzI1NiJ9.payload.sig", // JWT-shaped (dots)
            "SENTINEL_JWT",
            "0xabcdef", // 0x prefix + short
            upper_hex.as_str(),
            short_hex.as_str(),
            "",
        ] {
            assert!(!is_omni_hex(bad), "is_omni_hex must reject {bad}");
        }
        for bad in [
            "//session_jwt=SENTINEL_JWT", // label charset
            "//UPPER",
            "/hermes", // single slash
            "//",      // empty label
            "session_jwt=x",
            "",
        ] {
            assert!(
                !is_derivation_path(bad),
                "is_derivation_path must reject {bad}"
            );
        }
    }

    #[test]
    fn claimed_binding_rejects_reflected_tokens_in_public_fields() {
        // 64-char lowercase hex operator omni; child is its REAL HDKD derivation
        // (the semantic check requires child_omni == HDKD(operator, label)).
        let operator = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let child = agentkeys_core::actor_omni::child_omni_hex(operator, "hermes").unwrap();
        let ok = serde_json::json!({
            "session_jwt": "tok",
            "child_omni": child.clone(),
            "operator_omni": operator,
            "derivation_path": "//hermes",
        });
        assert!(validate_claimed_binding(&ok).is_ok());

        // A reflected token in ANY public field is rejected at the shape check,
        // and the error never echoes the offending value.
        for field in ["child_omni", "operator_omni", "derivation_path"] {
            let mut v = ok.clone();
            v[field] = serde_json::json!("session_jwt=SENTINEL_JWT");
            let err = validate_claimed_binding(&v)
                .expect_err("reflected token must be rejected")
                .to_string();
            assert!(
                !err.contains("SENTINEL_JWT"),
                "{field} value leaked into error: {err}"
            );
        }

        // Missing session_jwt is rejected (before any field/HDKD check) without
        // echoing the body.
        let no_jwt = serde_json::json!({
            "child_omni": child.clone(), "operator_omni": operator, "derivation_path": "//hermes",
        });
        assert!(validate_claimed_binding(&no_jwt).is_err());
    }

    #[test]
    fn claimed_binding_rejects_hdkd_child_mismatch() {
        // All fields are individually well-shaped (64-hex omnis, //label), but
        // child_omni is NOT the HDKD derivation of (operator_omni, label) — a
        // corrupt/stale broker or terminating-proxy response. Reject it locally.
        let operator = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let wrong_child = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let v = serde_json::json!({
            "session_jwt": "tok",
            "child_omni": wrong_child,
            "operator_omni": operator,
            "derivation_path": "//hermes",
        });
        let err = validate_claimed_binding(&v)
            .expect_err("HDKD child mismatch must be rejected")
            .to_string();
        assert!(
            err.contains("HDKD") || err.contains("does not match"),
            "should reject HDKD mismatch, got: {err}"
        );
        assert!(
            !err.contains("ffffffff"),
            "error must not echo the bad value: {err}"
        );
    }

    #[test]
    fn retry_after_zero_does_not_disable_backoff() {
        // A broker/proxy `Retry-After: 0` must NOT zero the wait (which would let
        // the loop hammer the broker); it floors at the jittered backoff.
        let w = poll_retry_wait(Some(Duration::ZERO), 1);
        assert!(
            w >= Duration::from_secs(PAIRING_POLL_INTERVAL_SECONDS),
            "zero Retry-After must floor at backoff, got {w:?}"
        );
        // A longer Retry-After is honored.
        let long = Duration::from_secs(3600);
        assert_eq!(poll_retry_wait(Some(long), 1), long);
        // No header → pure backoff, still nonzero.
        assert!(poll_retry_wait(None, 2) > Duration::ZERO);
    }
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
