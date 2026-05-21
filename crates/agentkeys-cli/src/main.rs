use agentkeys_cli::{
    cmd_approve, cmd_feedback, cmd_inbox_list, cmd_inbox_provision, cmd_init,
    cmd_provision, cmd_read, cmd_revoke, cmd_run, cmd_scope, cmd_signer_derive,
    cmd_signer_preview_7730, cmd_signer_sign, cmd_signer_sign_typed_data, cmd_store, cmd_teardown,
    cmd_whoami, CommandContext,
    CredentialBackendKind, EnvelopeVersionFlag, InitMode,
};


use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentkeys",
    version,
    about = "Credential management for AI agents",
    long_about = "agentkeys — secure credential storage and injection for AI agents.\n\nThe --agent flag on store/read/run accepts a 0x... wallet, a linked alias, or a linked email. Omit it to default to the current session wallet.\n\nExamples:\n  agentkeys init --email alice@example.com --broker-url https://broker.example --signer-url https://signer.example\n  agentkeys init --oauth2-google         --broker-url https://broker.example --signer-url https://signer.example\n  agentkeys store openrouter sk-or-...                    (session wallet)\n  agentkeys store --agent 0xAGENT openrouter sk-or-...    (specific wallet)\n  agentkeys read --agent my-bot openrouter                (linked alias)\n  agentkeys run -- python my_agent.py                     (session wallet)\n  agentkeys usage 0xAGENT\n  agentkeys revoke 0xAGENT\n  agentkeys teardown 0xAGENT"
)]
struct Cli {
    #[arg(long, default_value = "http://localhost:8090", help = "Backend URL")]
    backend: String,

    #[arg(long, help = "Show verbose HTTP request/response details")]
    verbose: bool,

    #[arg(long, help = "Output machine-readable JSON where supported")]
    json: bool,

    #[arg(
        long,
        env = "AGENTKEYS_BROKER_URL",
        help = "Stage 7 broker URL — when set, `provision` fetches AWS temp creds via the broker's /v1/mint-oidc-jwt + client-side AssumeRoleWithWebIdentity (issue #71 Option A)"
    )]
    broker_url: Option<String>,

    #[arg(
        long,
        env = "AGENTKEYS_SESSION_ID",
        default_value = "master",
        help = "Session namespace under ~/.agentkeys/<id>/session.json. Defaults to \"master\". Use distinct ids to hold multiple concurrent sessions (e.g. --session-id=alice and --session-id=bob) without overwriting each other."
    )]
    session_id: String,

    #[arg(
        long,
        env = "AGENTKEYS_CREDENTIAL_BACKEND",
        default_value = "http",
        help = "Where credential CRUD lands. 'http' (default) talks to the legacy mock-server. 's3' encrypts client-side and PUTs to s3://$AGENTKEYS_BUCKET/bots/<wallet|actor_omni>/credentials/<service>.enc, gated by the OIDC-assumed agentkeys-data-role + PrincipalTag isolation. 'sidecar' (stage-1 v2 — not yet implemented) talks to the localhost daemon proxy. The legacy backend still handles sessions, audit, identity, and scope regardless of this flag."
    )]
    credential_backend: String,

    #[arg(
        long,
        env = "AGENTKEYS_ENVELOPE_VERSION",
        default_value = "v1",
        help = "v2 stage 1 — which envelope shape --credential-backend=s3 writes. 'v1' (default) keys S3 path + AAD off the master wallet (legacy #87 layout). 'v2' keys both off actor_omni_hex per arch.md §14.4 — stable across K3 rotation. Reads always accept BOTH formats during the migration window, so this flag only affects writes."
    )]
    envelope_version: String,

    #[arg(
        long,
        env = "AGENTKEYS_CHAIN",
        help = "v2 stage 1 — which EVM chain backbone to talk to. Built-in profiles: heima (default), heima-paseo, base, base-sepolia, ethereum, sepolia, anvil. Operator-custom chains: set $AGENTKEYS_CHAIN_PROFILE_FILE to a JSON file path. Run `agentkeys chain list` to enumerate built-ins; `agentkeys chain show <name>` to inspect one."
    )]
    chain: Option<String>,

    #[arg(
        long,
        env = "AGENTKEYS_BUCKET",
        help = "S3 bucket holding bots/<wallet>/credentials/<service>.enc. Required when --credential-backend=s3."
    )]
    bucket: Option<String>,

    #[arg(
        long,
        env = "AGENTKEYS_SIGNER_URL",
        help = "Signer base URL — when --credential-backend=s3 is set, the S3 backend calls /dev/sign-message under --omni-account to derive a deterministic per-(wallet, service) KEK for client-side AES-256-GCM."
    )]
    signer_url: Option<String>,

    #[arg(
        long,
        env = "AGENTKEYS_OMNI_ACCOUNT",
        help = "64-lowercase-hex omni_account for KEK derivation when --credential-backend=s3. Issue #74 step 2 will pull this from the session JWT automatically."
    )]
    omni_account: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Initialize a new session via email-link or OAuth2/Google",
        long_about = "Authenticate the operator's identity, derive the managed EVM wallet via the dev_key_service signer, link it to the broker, and save the resulting EVM session JWT in the OS keychain. The legacy --mock-token path was hard-cut in issue #74 step 1; the only production paths are --email and --oauth2-google.\n\nExamples:\n  agentkeys init --email alice@example.com --broker-url https://broker.example --signer-url https://signer.example\n  agentkeys init --oauth2-google         --broker-url https://broker.example --signer-url https://signer.example"
    )]
    Init {
        /// Email address for the email-link flow. Mutually exclusive with --oauth2-google.
        #[arg(long, conflicts_with = "oauth2_google")]
        email: Option<String>,

        /// Initiate the OAuth2/Google flow. Mutually exclusive with --email.
        #[arg(long = "oauth2-google", conflicts_with = "email")]
        oauth2_google: bool,

        /// Broker URL (the server hosting `/v1/auth/{email,oauth2,wallet}/{request,start,verify,status}`).
        #[arg(long, env = "AGENTKEYS_BROKER_URL")]
        broker_url: Option<String>,

        /// Signer URL (the server hosting `/dev/derive-address` + `/dev/sign-message`
        /// per docs/spec/signer-protocol.md). Defaults to --backend if unset.
        #[arg(long, env = "AGENTKEYS_SIGNER_URL")]
        signer_url: Option<String>,

        /// SIWE chain_id. Defaults to 84532 (Base Sepolia) which the
        /// broker's wallet_sig plug-in already accepts in tests.
        #[arg(long, default_value_t = 84532)]
        chain_id: u64,

        /// How long to wait for the operator to complete the email-link
        /// click or OAuth2 callback before failing the init.
        #[arg(long, default_value_t = 300)]
        poll_timeout_seconds: u64,
    },

    #[command(
        about = "Store a credential for an agent+service",
        long_about = "Encrypt and store an API key for a given agent and service.\n\nOmit --agent to default to the session wallet. --agent accepts a 0x... wallet address, a linked alias, or a linked email.\n\nNote on the --agent FLAG (vs a positional): clap does not support an optional leading positional followed by required positionals — it either panics at parse time or consumes the first required arg as the agent. An --agent flag is the only disambiguation that works without a subcommand split.\n\nExamples:\n  agentkeys store openrouter sk-or-v1-abc123                (session wallet)\n  agentkeys store --agent my-bot openrouter sk-or-v1-abc123 (resolve alias)\n  agentkeys store --agent 0xAGENT anthropic sk-ant-abc123   (literal wallet)"
    )]
    Store {
        #[arg(long, help = "Agent wallet address, alias, or email (defaults to session wallet)")]
        agent: Option<String>,
        #[arg(help = "Service name (e.g. openrouter, anthropic)")]
        service: String,
        #[arg(help = "API key or credential value")]
        key: String,
    },

    #[command(
        about = "Read a credential for an agent+service",
        long_about = "Retrieve and print the stored credential. Omit --agent to default to the session wallet.\n\nExamples:\n  agentkeys read openrouter                     (session wallet)\n  agentkeys read --agent my-bot openrouter      (resolve alias)\n  agentkeys read --json --agent 0xAGENT openrouter (literal wallet)"
    )]
    Read {
        #[arg(long, help = "Agent wallet address, alias, or email (defaults to session wallet)")]
        agent: Option<String>,
        #[arg(help = "Service name")]
        service: String,
    },

    #[command(
        about = "Run a command with credentials injected as env vars",
        long_about = "Load credentials for the agent and inject them as SERVICE_API_KEY env vars. Omit --agent to default to the session wallet. Use --env KEY=service to map non-standard env-var names (e.g. GITHUB_TOKEN).\n\nExamples:\n  agentkeys run -- python my_agent.py                      (session wallet)\n  agentkeys run --agent my-bot -- node server.js           (resolve alias)\n  agentkeys run --agent 0xAGENT -- node server.js          (literal wallet)\n  agentkeys run --env GITHUB_TOKEN=github -- bash deploy.sh"
    )]
    Run {
        #[arg(long, help = "Agent wallet address, alias, or email (defaults to session wallet)")]
        agent: Option<String>,
        #[arg(long = "env", value_name = "KEY=SERVICE", action = clap::ArgAction::Append, help = "Map env var name to service (e.g. GITHUB_TOKEN=github)")]
        env: Vec<String>,
        #[arg(last = true, help = "Command to execute")]
        cmd: Vec<String>,
    },

    #[command(
        about = "Revoke a session",
        long_about = "Revoke a session. Without arguments, revokes the current session and wipes the local keychain entry (you must run `agentkeys init` again). With a wallet address, revokes all active sessions for that child agent (ownership check enforced).\n\nExamples:\n  agentkeys revoke\n  agentkeys revoke 0xCHILD_WALLET"
    )]
    Revoke {
        #[arg(help = "Child agent wallet address to revoke (omit to revoke your own current session)", required = false)]
        agent: Option<String>,
    },

    #[command(
        about = "Tear down all credentials for an agent",
        long_about = "Delete all stored credentials and revoke all sessions for an agent.\n\nExamples:\n  agentkeys teardown 0xAGENT"
    )]
    Teardown {
        #[arg(help = "Agent wallet address")]
        agent: String,
    },

    #[command(
        about = "Approve a pairing request",
        long_about = "Approve a pending pair request by its pair code.\n\nExamples:\n  agentkeys approve PAIR-CODE-123\n  agentkeys approve PAIR-CODE-123 --yes"
    )]
    Approve {
        #[arg(help = "Pair code to approve")]
        pair_code: String,
        #[arg(long, help = "Auto-confirm without interactive prompt")]
        yes: bool,
    },

    #[command(
        about = "Edit or list the scope of a child agent",
        long_about = "Add, remove, replace, or list the services in a child agent's scope.\n\nExamples:\n  agentkeys scope 0xAGENT --add openrouter\n  agentkeys scope 0xAGENT --remove anthropic\n  agentkeys scope 0xAGENT --set openrouter,anthropic\n  agentkeys scope 0xAGENT --list"
    )]
    Scope {
        #[arg(help = "Agent wallet address, alias, or email")]
        agent: String,
        #[arg(long, help = "Add a service to the scope (repeatable)")]
        add: Vec<String>,
        #[arg(long, help = "Remove a service from the scope (repeatable)")]
        remove: Vec<String>,
        #[arg(long, help = "Replace the entire scope with a comma-separated list of services")]
        set: Option<String>,
        #[arg(long, help = "List the current scope without making changes")]
        list: bool,
    },

    #[command(
        about = "Provision (sign up and store) an API key for a service",
        long_about = "Run the provisioner script to sign up for a service and store the credential.\n\nExamples:\n  agentkeys provision openrouter\n  agentkeys provision openrouter --force"
    )]
    Provision {
        #[arg(help = "Service name to provision (e.g. openrouter)")]
        service: String,
        #[arg(long, help = "Re-provision even if a credential already exists")]
        force: bool,
    },

    #[command(
        about = "Open the feedback forum in your browser",
        long_about = "Open https://github.com/agentkeys/agentkeys/discussions in the default browser.\n\nExamples:\n  agentkeys feedback"
    )]
    Feedback,

    #[command(
        about = "Manage agent inbox addresses",
        long_about = "Provision or list inbox addresses for an agent.\n\nOmit --agent to default to the session wallet.\n\nExamples:\n  agentkeys inbox provision\n  agentkeys inbox provision --agent 0xAGENT\n  agentkeys inbox list\n  agentkeys inbox list --agent 0xAGENT"
    )]
    Inbox {
        #[command(subcommand)]
        action: InboxAction,
    },

    #[command(
        about = "Show the active session, scope, and (optionally) signer-derived wallet",
        long_about = "Read-only summary of the current session.\n\nWith --signer-url and --omni-account, also calls the signer to print the derived EVM address. Useful for verifying the signer wire is reachable and the omni→address mapping is what you expect.\n\nExamples:\n  agentkeys whoami\n  agentkeys whoami --signer-url http://localhost:8090 --omni-account <64hex>"
    )]
    Whoami {
        #[arg(long, env = "AGENTKEYS_SIGNER_URL", help = "URL of the signer service (dev_key_service or TEE worker)")]
        signer_url: Option<String>,
        #[arg(long, help = "OmniAccount (64-hex-char SHA256 digest) to resolve via the signer")]
        omni_account: Option<String>,
    },

    #[command(
        about = "Talk to the signer edge (dev_key_service or TEE worker)",
        long_about = "Subcommands that exercise the wire contract from docs/spec/signer-protocol.md. The CLI treats the signer as opaque RPC; the same commands work against the HKDF dev backend and the future TEE backend.\n\nExamples:\n  agentkeys signer derive --signer-url http://localhost:8090 --omni-account <64hex>\n  agentkeys signer sign   --signer-url http://localhost:8090 --omni-account <64hex> --message 'siwe-msg'"
    )]
    Signer {
        #[command(subcommand)]
        action: SignerAction,
    },

    #[command(
        about = "Inspect available EVM chain profiles (v2 stage 1)",
        long_about = "AgentKeys's chain layer is pluggable per arch.md §22. Each named profile bundles chain ID, RPC endpoints, explorer URL, finality model, and gas config. Use --chain <name> on the top-level CLI to select one for any chain-aware operation (device register, scope grant, contract deploy). The 'list' subcommand prints all built-ins; 'show' dumps one profile's full JSON.\n\nOperator-custom chains: ship your own JSON and point at it via $AGENTKEYS_CHAIN_PROFILE_FILE.\n\nExamples:\n  agentkeys chain list\n  agentkeys chain show heima\n  agentkeys --chain base chain show"
    )]
    Chain {
        #[command(subcommand)]
        action: ChainAction,
    },

    #[command(
        about = "K11 (WebAuthn) enrollment + assertion (v2 stage 1 — stub mode)",
        long_about = "Real WebAuthn ceremony or deterministic stub.\n\nReal mode (--webauthn): opens the operator's default browser, runs the platform-authenticator ceremony (macOS: Touch ID against the Secure Enclave passkey), persists the real attested credential to ~/.agentkeys/k11/<omni>.json. The assert path binds to the application message via challenge = sha256(message), producing a real WebAuthn assertion verifiable off-chain today and on-chain after Heima ships EIP-7212 P-256 precompile.\n\nStub mode (default — for CI / non-attested envs): produces deterministic bytes that just satisfy the on-chain `k11Assertion.length != 0` gate (per arch.md §22b.1 stage-1 simplifications inventory). On mainnet (AGENTKEYS_CHAIN=heima) stub mode prints a WARN.\n\nExamples:\n  agentkeys k11 enroll  --webauthn --operator-omni 0x<64-hex>\n  agentkeys k11 assert  --webauthn --operator-omni 0x<64-hex> --message-hex 0xdeadbeef\n  agentkeys k11 enroll  --operator-omni 0x<64-hex>     # stub (CI)\n  agentkeys k11 assert  --operator-omni 0x<64-hex> --message-hex 0xdeadbeef"
    )]
    K11 {
        #[command(subcommand)]
        action: K11Action,
    },
}

#[derive(Subcommand)]
enum K11Action {
    #[command(about = "Enroll a K11 credential for an operator (stub by default; --webauthn for real Touch ID ceremony)")]
    Enroll {
        #[arg(long, help = "Operator omni-account hex (0x + 64 hex chars)")]
        operator_omni: String,
        /// Run the real WebAuthn ceremony in the operator's default browser.
        /// macOS: triggers the Touch ID prompt against the platform passkey.
        /// Without this flag the command writes a deterministic stub
        /// (for CI / non-attested environments).
        #[arg(long)]
        webauthn: bool,
        /// WebAuthn RP ID. Default "localhost" (primary master). Companion
        /// daemon mode uses "companion.localhost" so the platform keychain
        /// creates a distinct passkey on the same Mac.
        #[arg(long, default_value = "localhost")]
        rp_id: String,
    },
    #[command(about = "Produce a K11 assertion over a message (stub by default; --webauthn for real Touch ID)")]
    Assert {
        #[arg(long, help = "Operator omni-account hex (0x + 64 hex chars)")]
        operator_omni: String,
        #[arg(long, help = "Hex-encoded message to sign over (with or without 0x prefix)")]
        message_hex: String,
        /// Run the real WebAuthn ceremony. The application message is
        /// SHA-256-hashed and used as the WebAuthn challenge so the
        /// assertion is cryptographically bound to this exact message.
        #[arg(long)]
        webauthn: bool,
        /// WebAuthn RP ID. Must match the rp_id used at enrollment time.
        #[arg(long, default_value = "localhost")]
        rp_id: String,
        /// Emit the chain-ready assertion struct as JSON (r, s, pubX, pubY,
        /// authData, clientDataJSON, challengeLocation, signCount) instead
        /// of the raw concatenated bytes. The contract's K11Verifier needs
        /// these fields as separate args.
        #[arg(long)]
        emit_chain_payload: bool,
        /// **Operator-readable description** of what's about to be authorized,
        /// rendered prominently on the WebAuthn confirmation page so the
        /// operator sees the intent in plain English before pressing Touch ID
        /// (otherwise they only see the raw 32-byte challenge hex). Only
        /// applies with `--webauthn`; ignored in stub mode.
        ///
        /// Examples:
        ///   --intent-text "Grant agent demo-agent access to openrouter"
        ///   --intent-text "Revoke companion master device 0xabcd…1234"
        #[arg(long, help = "Operator-readable intent shown on the WebAuthn confirmation page (with --webauthn)")]
        intent_text: Option<String>,
        /// Per-field detail rows rendered under the headline `--intent-text`,
        /// repeatable. Each value is `Label=Value`. Common rows: service,
        /// agent, K3 epoch, max_calls, expires_at.
        ///
        /// Examples:
        ///   --intent-field "Service=openrouter"
        ///   --intent-field "Max calls / hour=100"
        ///   --intent-field "K3 epoch=1"
        #[arg(long = "intent-field", help = "Repeatable per-field detail row as `Label=Value` (with --webauthn)")]
        intent_fields: Vec<String>,
        /// Typed K11 operation intent (preferred over `--intent-text` +
        /// `--intent-field`). One JSON blob describing the operation; the
        /// CLI renders it to a uniform K11IntentContext via the shared
        /// [`k11_intent`] module, so role bitfields become readable
        /// permission names ("CAP_MINT | RECOVERY"), 0-means-unlimited
        /// amounts render as "unlimited", hashes are truncated for the
        /// prompt, and chain IDs get human-readable labels — all
        /// without per-script string surgery.
        ///
        /// When BOTH `--intent-op-json` and `--intent-text` are passed,
        /// the typed JSON wins (single source of truth).
        ///
        /// Examples:
        ///   --intent-op-json '{"kind":"set_recovery_threshold","operator_omni":"0x…","new_threshold":2,"chain_id":212013,"operator_nonce":4,"asserting":{"kind":"primary","device_key_hash":"0x…"}}'
        #[arg(
            long = "intent-op-json",
            help = "Typed K11 operation intent as JSON (preferred over --intent-text + --intent-field)"
        )]
        intent_op_json: Option<String>,
    },
}

#[derive(Subcommand)]
enum ChainAction {
    #[command(about = "List built-in chain profile names")]
    List,
    #[command(about = "Print one profile's full JSON (omit name to use the resolved profile)")]
    Show {
        #[arg(help = "Profile name (heima | heima-paseo | base | base-sepolia | ethereum | sepolia | anvil)")]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum SignerAction {
    #[command(
        about = "Derive the EVM address for an OmniAccount via the signer",
        long_about = "Calls /dev/derive-address on the configured signer.\n\nExamples:\n  agentkeys signer derive --signer-url http://localhost:8090 --omni-account <64hex>"
    )]
    Derive {
        #[arg(long, env = "AGENTKEYS_SIGNER_URL", help = "URL of the signer service")]
        signer_url: String,
        #[arg(long, help = "OmniAccount (64-hex-char SHA256 digest)")]
        omni_account: String,
    },

    #[command(
        about = "Sign a UTF-8 message under the keypair derived from an OmniAccount",
        long_about = "Calls /dev/sign-message on the configured signer. The message is sent as UTF-8 bytes — the signer wraps them in EIP-191.\n\nExamples:\n  agentkeys signer sign --signer-url http://localhost:8090 --omni-account <64hex> --message 'hello'"
    )]
    Sign {
        #[arg(long, env = "AGENTKEYS_SIGNER_URL", help = "URL of the signer service")]
        signer_url: String,
        #[arg(long, help = "OmniAccount (64-hex-char SHA256 digest)")]
        omni_account: String,
        #[arg(long, help = "Message to sign (sent as UTF-8 bytes)")]
        message: String,
    },

    #[command(
        name = "sign-typed-data",
        about = "EIP-712 typed-data sign (issue #82)",
        long_about = "Calls /dev/sign-typed-data on the configured signer. The file at --typed-data-file is an EIP-712 v4 JSON object (matches MetaMask `eth_signTypedData_v4`).\n\nThe signer parses the typed-data internally and computes the digest — callers MUST NOT pass a pre-hashed value.\n\nWith --preview-7730, the CLI also renders the operator-facing intent text against the bundled ERC-7730 catalog (override the dir via $AGENTKEYS_7730_DIR) and prints it before signing.\n\nExamples:\n  agentkeys signer sign-typed-data --signer-url http://localhost:8090 --omni-account <64hex> --typed-data-file ./permit.json\n  agentkeys signer sign-typed-data ... --preview-7730"
    )]
    SignTypedData {
        #[arg(long, env = "AGENTKEYS_SIGNER_URL", help = "URL of the signer service")]
        signer_url: String,
        #[arg(long, help = "OmniAccount (64-hex-char SHA256 digest)")]
        omni_account: String,
        #[arg(long, help = "Path to a JSON file containing the EIP-712 v4 typed-data")]
        typed_data_file: String,
        /// Render the operator-facing intent text + per-field preview against
        /// the bundled ERC-7730 catalog (override via $AGENTKEYS_7730_DIR).
        #[arg(long)]
        preview_7730: bool,
    },

    #[command(
        name = "preview-7730",
        about = "Render the ERC-7730 preview for a typed-data file WITHOUT signing (issue #82)",
        long_about = "Useful for dry-runs against new ERC-7730 files before plumbing them into automated agent signing. Loads the bundled catalog (and $AGENTKEYS_7730_DIR if set) by default; --7730-file pins a single file.\n\nExamples:\n  agentkeys signer preview-7730 --typed-data-file ./permit.json\n  agentkeys signer preview-7730 --typed-data-file ./permit.json --7730-file ./erc20-permit-usdc.json"
    )]
    Preview7730 {
        #[arg(long, help = "Path to a JSON file containing the EIP-712 v4 typed-data")]
        typed_data_file: String,
        // Explicit `long = "7730-file"` because clap derives the flag
        // name from the Rust field ident, which would yield
        // `--seven-thirty-file`. The docs + long_about advertise
        // `--7730-file`; this override matches. Codex P2 finding on PR #95.
        #[arg(
            long = "7730-file",
            help = "Optional: pin to a single ERC-7730 file instead of the bundled catalog"
        )]
        seven_thirty_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum InboxAction {
    #[command(
        about = "Provision a new inbox address for an agent",
        long_about = "Provision a new inbox email address for an agent and print the address.\n\nOmit --agent to default to the session wallet.\n\nExamples:\n  agentkeys inbox provision\n  agentkeys inbox provision --agent 0xAGENT"
    )]
    Provision {
        #[arg(long, help = "Agent wallet address, alias, or email (defaults to session wallet)")]
        agent: Option<String>,
    },

    #[command(
        about = "List inbox addresses provisioned for an agent",
        long_about = "List all inbox email addresses provisioned for an agent, one per line.\n\nOmit --agent to default to the session wallet.\n\nExamples:\n  agentkeys inbox list\n  agentkeys inbox list --agent 0xAGENT"
    )]
    List {
        #[arg(long, help = "Agent wallet address, alias, or email (defaults to session wallet)")]
        agent: Option<String>,
    },
}

async fn cmd_chain(ctx: &CommandContext, action: &ChainAction) -> anyhow::Result<String> {
    use agentkeys_core::chain_profile::ChainProfile;
    match action {
        ChainAction::List => Ok(ChainProfile::list_builtin_names().join("\n")),
        ChainAction::Show { name } => {
            let profile = match name {
                Some(n) => ChainProfile::load_builtin(n)
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                None => ctx.chain_profile()?.clone(),
            };
            serde_json::to_string_pretty(&profile)
                .map_err(|e| anyhow::anyhow!("serialize profile: {e}"))
        }
    }
}

/// `agentkeys k11 enroll/assert` — stage-1 stub mode by default.
///
/// Stage-1 simplification per arch.md §22b.1 (stage-1 simplifications
/// inventory — K11 stub bytes; issue #90 for stage-2 hardening): deterministic stub bytes
/// satisfy the on-chain `k11Assertion.length != 0` gate without a real
/// WebAuthn authenticator. Stage 2 (#90) swaps in `webauthn-rs` + Touch ID.
///
/// Stub-mode toggle: `AGENTKEYS_K11_STUB=1` (default). Setting it to `0`
/// errors out today — real WebAuthn is a stage-2 deliverable.
async fn cmd_k11(action: &K11Action) -> anyhow::Result<String> {
    let stub_env = std::env::var("AGENTKEYS_K11_STUB")
        .map(|v| v != "0")
        .unwrap_or(true);

    // Resolve mode: --webauthn flag wins over AGENTKEYS_K11_STUB env.
    let use_webauthn = matches!(action,
        K11Action::Enroll { webauthn: true, .. } | K11Action::Assert { webauthn: true, .. });

    if !use_webauthn && !stub_env {
        anyhow::bail!(
            "K11 stub mode disabled (AGENTKEYS_K11_STUB=0) and --webauthn not passed. \
             Either pass --webauthn for the real Touch ID ceremony, or set \
             AGENTKEYS_K11_STUB=1 to use the deterministic stub."
        );
    }

    // Stage-1 stub-on-mainnet protection (codex audit follow-up):
    //   chain == heima + stub mode + no explicit opt-in → HARD ERROR.
    //   chain == heima + stub mode + AGENTKEYS_ALLOW_STAGE1_STUBS=1 → WARN.
    //   other chains (heima-paseo, anvil, etc.) + stub mode → no message
    //     (it's the expected dev/CI behaviour).
    // Per arch.md §22b.1 — stage-1 simplifications inventory.
    if !use_webauthn {
        let chain = std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".into());
        let allow_stubs = std::env::var("AGENTKEYS_ALLOW_STAGE1_STUBS")
            .map(|v| v != "0")
            .unwrap_or(false);
        if chain == "heima" {
            if !allow_stubs {
                anyhow::bail!(
                    "K11 stub mode is NOT permitted on chain=heima (mainnet). The stub \
                     bytes only satisfy the on-chain k11Assertion.length != 0 gate — they \
                     are not a real WebAuthn assertion and any operator who reads them \
                     later cannot distinguish them from a real ceremony. \
                     \n\nOptions: \
                     \n  1. Pass --webauthn for a real Touch ID ceremony (recommended). \
                     \n  2. Set AGENTKEYS_ALLOW_STAGE1_STUBS=1 to opt into stub mode \
                     (emits a WARN; for staging/test runs only). \
                     \n  3. Switch to AGENTKEYS_CHAIN=heima-paseo or anvil for dev work. \
                     \n\nSee arch.md §22b.1 + issue #90 for stage-2 hardening."
                );
            }
            eprintln!(
                "==> ⚠️  WARN: K11 stub mode active on chain={chain} (AGENTKEYS_ALLOW_STAGE1_STUBS=1). \
                 The bytes you're about to produce are NOT a real WebAuthn assertion. \
                 See arch.md §22b.1 + issue #90."
            );
        }
    }

    match action {
        K11Action::Enroll { operator_omni, webauthn, rp_id } => {
            if *webauthn {
                let enrollment = agentkeys_cli::k11_webauthn::enroll_webauthn_with_rp(
                    operator_omni, rp_id,
                )
                .await
                .map_err(|e| anyhow::anyhow!("k11 webauthn enroll: {e}"))?;
                serde_json::to_string_pretty(&enrollment)
                    .map_err(|e| anyhow::anyhow!("serialize: {e}"))
            } else {
                let enrollment = agentkeys_cli::k11::enroll(operator_omni)
                    .map_err(|e| anyhow::anyhow!("k11 enroll: {e}"))?;
                serde_json::to_string_pretty(&enrollment)
                    .map_err(|e| anyhow::anyhow!("serialize: {e}"))
            }
        }
        K11Action::Assert {
            operator_omni,
            message_hex,
            webauthn,
            rp_id,
            emit_chain_payload,
            intent_text,
            intent_fields,
            intent_op_json,
        } => {
            let msg = hex::decode(message_hex.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("decode --message-hex: {e}"))?;
            // Typed-intent path takes precedence over the raw flags. When
            // `--intent-op-json` is passed, parse to K11OpIntent + render
            // via the shared formatter. Otherwise fall back to the legacy
            // `--intent-text` + `--intent-field` raw path.
            let intent_ctx = if let Some(json) = intent_op_json.as_deref() {
                let op = agentkeys_cli::k11_intent::K11OpIntent::from_json(json)
                    .map_err(|e| anyhow::anyhow!("--intent-op-json: {e}"))?;
                op.render()
            } else {
                // Parse repeatable `Label=Value` rows into a K11IntentContext.
                // Split on the FIRST `=` so values may contain `=`. Rows
                // without `=` are rejected with a clear error so the
                // operator doesn't silently get a mis-rendered intent field.
                let mut k11_fields: Vec<(String, String)> =
                    Vec::with_capacity(intent_fields.len());
                for raw in intent_fields {
                    let (label, value) = match raw.split_once('=') {
                        Some((l, v)) => (l.trim().to_string(), v.trim().to_string()),
                        None => anyhow::bail!(
                            "--intent-field must be `Label=Value` (no `=` found in {raw:?})"
                        ),
                    };
                    if label.is_empty() {
                        anyhow::bail!("--intent-field has empty label (in {raw:?})");
                    }
                    k11_fields.push((label, value));
                }
                agentkeys_cli::k11_webauthn::K11IntentContext {
                    text: intent_text.clone(),
                    fields: k11_fields,
                }
            };

            if *webauthn {
                if *emit_chain_payload {
                    // The contract reconstructs `expected_challenge` from
                    // operation params + nonce; the CLI caller passes the
                    // exact 32 bytes via --message-hex.
                    if msg.len() != 32 {
                        anyhow::bail!(
                            "--emit-chain-payload requires --message-hex to be a 32-byte challenge \
                             (got {} bytes). The contract expects the message to BE the challenge \
                             (operation params hashed); the WebAuthn ceremony then signs over \
                             sha256(authData || sha256(clientDataJSON)) with clientDataJSON.challenge \
                             = base64url(msg).",
                            msg.len()
                        );
                    }
                    let mut challenge = [0u8; 32];
                    challenge.copy_from_slice(&msg);
                    let payload =
                        agentkeys_cli::k11_webauthn::assert_webauthn_for_chain_with_intent(
                            operator_omni,
                            challenge,
                            rp_id,
                            intent_ctx,
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("k11 webauthn assert: {e}"))?;
                    serde_json::to_string_pretty(&payload)
                        .map_err(|e| anyhow::anyhow!("serialize: {e}"))
                } else {
                    let assertion = agentkeys_cli::k11_webauthn::assert_webauthn_with_intent(
                        operator_omni,
                        &msg,
                        rp_id,
                        intent_ctx,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("k11 webauthn assert: {e}"))?;
                    Ok(format!("0x{}", hex::encode(assertion)))
                }
            } else {
                // Stub mode ignores intent (no UI to render it on).
                let _ = intent_ctx;
                let assertion = agentkeys_cli::k11::assert_stub(operator_omni, &msg)
                    .map_err(|e| anyhow::anyhow!("k11 assert: {e}"))?;
                Ok(format!("0x{}", hex::encode(assertion)))
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cred_kind = match CredentialBackendKind::parse(&cli.credential_backend) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let envelope_version = match EnvelopeVersionFlag::parse(&cli.envelope_version) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let ctx = CommandContext::new(&cli.backend, cli.verbose, cli.json)
        .with_broker_url(cli.broker_url.clone())
        .with_session_id(cli.session_id.clone())
        .with_credential_backend(cred_kind)
        .with_envelope_version(envelope_version)
        .with_chain_profile_name(cli.chain.clone())
        .with_data_bucket(cli.bucket.clone())
        .with_signer_url(cli.signer_url.clone())
        .with_omni_account(cli.omni_account.clone());

    let result: anyhow::Result<String> = match &cli.command {
        Commands::Init {
            email,
            oauth2_google,
            broker_url,
            signer_url,
            chain_id,
            poll_timeout_seconds,
        } => {
            let broker_opt = broker_url.clone().or_else(|| ctx.broker_url.clone());
            let signer = signer_url.clone().unwrap_or_else(|| ctx.backend_url.clone());
            let mode_result: anyhow::Result<InitMode> = match (email, *oauth2_google) {
                (Some(addr), false) => broker_opt
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "agentkeys init: missing --broker-url (or AGENTKEYS_BROKER_URL)"
                        )
                    })
                    .map(|broker| InitMode::Email {
                        email: addr.clone(),
                        broker_url: broker,
                        signer_url: signer.clone(),
                        chain_id: *chain_id,
                        poll_timeout_seconds: *poll_timeout_seconds,
                    }),
                (None, true) => broker_opt
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "agentkeys init: missing --broker-url (or AGENTKEYS_BROKER_URL)"
                        )
                    })
                    .map(|broker| InitMode::Oauth2Google {
                        broker_url: broker,
                        signer_url: signer.clone(),
                        chain_id: *chain_id,
                        poll_timeout_seconds: *poll_timeout_seconds,
                    }),
                (Some(_), true) => unreachable!("clap conflicts_with prevents both"),
                (None, false) => Err(anyhow::anyhow!(
                    "agentkeys init: pass --email <addr> or --oauth2-google (the legacy --mock-token flag was hard-cut in issue #74 step 1)"
                )),
            };
            match mode_result {
                Ok(mode) => cmd_init(&ctx, mode).await.map(|(msg, _session)| msg),
                Err(e) => Err(e),
            }
        }
        Commands::Store { agent, service, key } => cmd_store(&ctx, agent.as_deref(), service, key).await,
        Commands::Read { agent, service } => cmd_read(&ctx, agent.as_deref(), service).await,
        Commands::Run { agent, env, cmd } => cmd_run(&ctx, agent.as_deref(), env, cmd).await,
        Commands::Revoke { agent } => cmd_revoke(&ctx, agent.as_deref()).await,
        Commands::Teardown { agent } => cmd_teardown(&ctx, agent).await,
        Commands::Approve { pair_code, yes } => cmd_approve(&ctx, pair_code, *yes).await,
        Commands::Scope { agent, add, remove, set, list } => {
            cmd_scope(&ctx, agent, add, remove, set.as_deref(), *list).await
        }
        Commands::Provision { service, force } => {
            cmd_provision(&ctx, service, *force, None).await.map(|out| {
                for line in &out.stderr_lines {
                    eprintln!("{}", line);
                }
                out.stdout_line
            })
        }
        Commands::Feedback => Ok(cmd_feedback()),
        Commands::Inbox { action } => match action {
            InboxAction::Provision { agent } => {
                cmd_inbox_provision(&ctx, agent.as_deref()).await
            }
            InboxAction::List { agent } => {
                cmd_inbox_list(&ctx, agent.as_deref()).await
            }
        },
        Commands::Whoami { signer_url, omni_account } => {
            cmd_whoami(&ctx, signer_url.as_deref(), omni_account.as_deref()).await
        }
        Commands::Signer { action } => match action {
            SignerAction::Derive { signer_url, omni_account } => {
                cmd_signer_derive(&ctx, signer_url, omni_account).await
            }
            SignerAction::Sign { signer_url, omni_account, message } => {
                cmd_signer_sign(&ctx, signer_url, omni_account, message).await
            }
            SignerAction::SignTypedData {
                signer_url,
                omni_account,
                typed_data_file,
                preview_7730,
            } => {
                cmd_signer_sign_typed_data(
                    &ctx,
                    signer_url,
                    omni_account,
                    typed_data_file,
                    *preview_7730,
                )
                .await
            }
            SignerAction::Preview7730 { typed_data_file, seven_thirty_file } => {
                cmd_signer_preview_7730(&ctx, typed_data_file, seven_thirty_file.as_deref()).await
            }
        },
        Commands::Chain { action } => cmd_chain(&ctx, action).await,
        Commands::K11 { action } => cmd_k11(action).await,
    };

    match result {
        Ok(output) => {
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
}
