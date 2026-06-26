use agentkeys_cli::{
    cmd_approve, cmd_feedback, cmd_inbox_list, cmd_inbox_provision, cmd_init_with_force,
    cmd_provision, cmd_read, cmd_revoke, cmd_run, cmd_scope, cmd_signer_derive,
    cmd_signer_preview_7730, cmd_signer_sign, cmd_signer_sign_typed_data, cmd_store, cmd_teardown,
    cmd_whoami, CommandContext, CredentialBackendKind, EnvelopeVersionFlag, InitMode,
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

        /// Re-run initialization even when a usable local session already exists.
        #[arg(long)]
        force: bool,
    },

    #[command(
        about = "Store a credential for an agent+service",
        long_about = "Encrypt and store an API key for a given agent and service.\n\nOmit --agent to default to the session wallet. --agent accepts a 0x... wallet address, a linked alias, or a linked email.\n\nNote on the --agent FLAG (vs a positional): clap does not support an optional leading positional followed by required positionals — it either panics at parse time or consumes the first required arg as the agent. An --agent flag is the only disambiguation that works without a subcommand split.\n\nExamples:\n  agentkeys store openrouter sk-or-v1-abc123                (session wallet)\n  agentkeys store --agent my-bot openrouter sk-or-v1-abc123 (resolve alias)\n  agentkeys store --agent 0xAGENT anthropic sk-ant-abc123   (literal wallet)"
    )]
    Store {
        #[arg(
            long,
            help = "Agent wallet address, alias, or email (defaults to session wallet)"
        )]
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
        #[arg(
            long,
            help = "Agent wallet address, alias, or email (defaults to session wallet)"
        )]
        agent: Option<String>,
        #[arg(help = "Service name")]
        service: String,
    },

    #[command(
        about = "Run a command with credentials injected as env vars",
        long_about = "Load credentials for the agent and inject them as SERVICE_API_KEY env vars. Omit --agent to default to the session wallet. Use --env KEY=service to map non-standard env-var names (e.g. GITHUB_TOKEN).\n\nExamples:\n  agentkeys run -- python my_agent.py                      (session wallet)\n  agentkeys run --agent my-bot -- node server.js           (resolve alias)\n  agentkeys run --agent 0xAGENT -- node server.js          (literal wallet)\n  agentkeys run --env GITHUB_TOKEN=github -- bash deploy.sh"
    )]
    Run {
        #[arg(
            long,
            help = "Agent wallet address, alias, or email (defaults to session wallet)"
        )]
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
        #[arg(
            help = "Child agent wallet address to revoke (omit to revoke your own current session)",
            required = false
        )]
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
        #[arg(
            long,
            help = "Replace the entire scope with a comma-separated list of services"
        )]
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
        #[arg(
            long,
            env = "AGENTKEYS_SIGNER_URL",
            help = "URL of the signer service (dev_key_service or TEE worker)"
        )]
        signer_url: Option<String>,
        #[arg(
            long,
            help = "OmniAccount (64-hex-char SHA256 digest) to resolve via the signer"
        )]
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

    #[command(
        about = "Wire a Task Host runtime with AgentKeys IAM-guarantee hooks",
        long_about = "Provision a Task Host (Phase 1.a: Hermes) so AgentKeys hooks fire on its tool-call lifecycle — turning the MCP tools into IAM guarantees the LLM cannot bypass. Idempotent: re-runs are no-ops modulo drift; --check-only reports drift without writing.\n\nWrites hook scripts to ~/.<runtime>/agent-hooks/, appends a managed `hooks:` block to the runtime config, and pre-approves first-use consent.\n\nExamples:\n  agentkeys wire hermes\n  agentkeys wire hermes --check-only\n  agentkeys wire hermes --actor-omni 0x<64hex> --namespaces travel,personal"
    )]
    Wire {
        /// Task Host runtime to wire. Phase 1.a ships `hermes`.
        runtime: String,

        /// Report drift without writing (nightly drift check / dry run).
        #[arg(long)]
        check_only: bool,

        /// Actor omni the hooks act for. Defaults to the in-memory demo actor.
        #[arg(
            long,
            env = "AGENTKEYS_ACTOR_OMNI",
            default_value = "0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7"
        )]
        actor_omni: String,

        /// Operator omni for audit-row attribution. Defaults to demo operator.
        #[arg(
            long,
            env = "AGENTKEYS_OPERATOR_OMNI",
            default_value = "0x07e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8"
        )]
        operator_omni: String,

        /// Comma-separated memory namespaces the pre_llm_call hook injects.
        #[arg(long, default_value = "travel")]
        namespaces: String,

        /// Scope the pre_tool_call permission gate checks.
        #[arg(long, default_value = "payment.spend")]
        payment_scope: String,

        /// AgentKeys MCP server URL the hooks call.
        #[arg(
            long,
            env = "AGENTKEYS_MCP_URL",
            default_value = "http://localhost:8088/mcp"
        )]
        mcp_url: String,

        /// Vendor bearer token for the MCP server.
        #[arg(long, env = "AGENTKEYS_MCP_VENDOR_TOKEN", default_value = "demo-tok")]
        vendor_token: String,

        /// Operator/agent session JWT baked into the hook scripts (forwarded
        /// to the broker cap-mint via the MCP server, arch.md §22b.4). Leave
        /// empty for the in-memory backend. JWTs expire — re-run wire to refresh.
        #[arg(long, env = "AGENTKEYS_SESSION_BEARER", default_value = "")]
        session_bearer: String,

        /// Memory engine baked into the pre_llm_call hook: `passthrough`
        /// (inject the whole namespace, default) or `lexical` (deterministic
        /// recency/relevance selection). Plan §6a / arch.md §22.
        #[arg(long, env = "AGENTKEYS_MEMORY_ENGINE", default_value = "passthrough")]
        memory_engine: String,

        /// Cap how many memory lines the engine injects (omit = unbounded).
        #[arg(long, env = "AGENTKEYS_MEMORY_MAX_LINES")]
        memory_max_lines: Option<u32>,

        /// OpenViking server URL, baked into the hook as OPENVIKING_ENDPOINT
        /// when --memory-engine openviking (plan §6a). e.g. http://127.0.0.1:1933
        #[arg(long, env = "OPENVIKING_ENDPOINT")]
        openviking_endpoint: Option<String>,

        /// Optional OpenViking API key, baked as OPENVIKING_API_KEY when
        /// --memory-engine openviking.
        #[arg(long, env = "OPENVIKING_API_KEY")]
        openviking_api_key: Option<String>,
    },

    #[command(
        about = "Runtime lifecycle hook helpers (called BY wire-generated scripts)",
        long_about = "These subcommands are invoked by the hook scripts `agentkeys wire` drops into a Task Host. Each reads the host's JSON hook payload from stdin, calls an AgentKeys MCP tool, and writes the host's expected JSON decision to stdout. You normally never run these by hand.\n\n  check         — PreToolUse permission gate (fails CLOSED)\n  audit         — PostToolUse audit append (never blocks)\n  memory-inject — pre_llm_call context injection (never blocks)"
    )]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    #[command(
        about = "Memory namespace helpers (e.g. SEED a namespace in the real worker)",
        long_about = "Direct memory operations against the AgentKeys MCP server. `put` writes an entry — used to SEED a namespace (e.g. the demo travel fixture) in the REAL memory worker; in-memory mode auto-seeds the fixture, so this is only needed for the real backend. Identity (actor / operator / device_key_hash) defaults from the MCP server's configured defaults."
    )]
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },
    /// Agent-side device bootstrap (interim §10.2 — full ceremony: issue #144).
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Credential fetch (#216) — the agent pulls its authorized `cred:<service>`
    /// from the vault to *use* it (e.g. its LLM key) at wire time.
    Cred {
        #[command(subcommand)]
        action: CredAction,
    },
}

#[derive(Subcommand)]
enum CredAction {
    /// Fetch + decrypt a stored credential's secret (#216). Gated by the actor's
    /// `cred:<service>` scope; prints the plaintext to stdout. The agent's
    /// identity/session come from the wire context (flags or env).
    Fetch {
        /// The credential service id (e.g. `openrouter`). OPTIONAL — when omitted,
        /// it is resolved from the off-chain cred manifest (#216): `--select N`
        /// (1-based) picks from the authorized list, else the master-designated
        /// default (the no-UI path). An explicit service is used as-is (still
        /// on-chain-verified at fetch).
        service: Option<String>,
        /// Pick the Nth authorized service (1-based) from the cred manifest
        /// instead of the master-designated default. Ignored when a service is
        /// given explicitly.
        #[arg(long)]
        select: Option<usize>,
        /// Cred-manifest path (authorized service names + default). Default:
        /// $AGENTKEYS_CRED_MANIFEST or ~/.agentkeys/cred-manifest.json.
        #[arg(long, env = "AGENTKEYS_CRED_MANIFEST")]
        manifest: Option<String>,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator_omni: String,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor_omni: String,
        #[arg(long, env = "AGENTKEYS_DEVICE_KEY_HASH")]
        device_key_hash: String,
        #[arg(long, env = "AGENTKEYS_SESSION_BEARER")]
        session_bearer: String,
        #[arg(long, env = "AGENTKEYS_BROKER_URL")]
        broker_url: String,
        #[arg(long, env = "AGENTKEYS_WORKER_CRED_URL")]
        cred_url: String,
        #[arg(long, env = "VAULT_ROLE_ARN")]
        vault_role_arn: String,
        #[arg(long, env = "REGION", default_value = "us-east-1")]
        region: String,
    },
    /// List the agent's authorized credential services from the off-chain
    /// manifest (#216). The chain stores only keccak(service) hashes — it can
    /// verify a known name but not enumerate names — so the manifest is the
    /// discovery layer. Marks the master-designated default.
    List {
        #[arg(long, env = "AGENTKEYS_CRED_MANIFEST")]
        manifest: Option<String>,
    },
    /// Record the off-chain cred manifest (#216): the authorized service names +
    /// the master-designated default (public NAMES only — never secrets). The
    /// master/operator runs this at grant time so the agent's no-arg `cred fetch`
    /// picks the designated default LLM key.
    Manifest {
        /// Comma-separated authorized service names in order (e.g.
        /// `openrouter,anthropic`).
        #[arg(long)]
        services: String,
        /// The default service (the no-UI LLM key). Defaults to the first in
        /// `--services`.
        #[arg(long)]
        default: Option<String>,
        #[arg(long, env = "AGENTKEYS_CRED_MANIFEST")]
        manifest: Option<String>,
    },
    /// Vault a credential (#216, the store half of `fetch`). Master-self by
    /// default (operator == actor); seeds the agent's authorized key (e.g. the
    /// LLM key the agent later cred-fetches). Prints the worker S3 key.
    Store {
        /// The credential service id (e.g. `openrouter`).
        service: String,
        /// The secret to vault. Prefer `--secret-env NAME` to keep it off argv.
        #[arg(long, conflicts_with = "secret_env")]
        secret: Option<String>,
        /// Read the secret from this env var instead of `--secret` (keeps the
        /// plaintext out of the process list / shell history).
        #[arg(long)]
        secret_env: Option<String>,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator_omni: String,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor_omni: String,
        #[arg(long, env = "AGENTKEYS_DEVICE_KEY_HASH")]
        device_key_hash: String,
        #[arg(long, env = "AGENTKEYS_SESSION_BEARER")]
        session_bearer: String,
        #[arg(long, env = "AGENTKEYS_BROKER_URL")]
        broker_url: String,
        #[arg(long, env = "AGENTKEYS_WORKER_CRED_URL")]
        cred_url: String,
        #[arg(long, env = "VAULT_ROLE_ARN")]
        vault_role_arn: String,
        #[arg(long, env = "REGION", default_value = "us-east-1")]
        region: String,
    },
}

#[derive(Subcommand)]
enum K11Action {
    #[command(
        about = "Enroll a K11 credential for an operator (stub by default; --webauthn for real Touch ID ceremony)"
    )]
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
    #[command(
        about = "Produce a K11 assertion over a message (stub by default; --webauthn for real Touch ID)"
    )]
    Assert {
        #[arg(long, help = "Operator omni-account hex (0x + 64 hex chars)")]
        operator_omni: String,
        #[arg(
            long,
            help = "Hex-encoded message to sign over (with or without 0x prefix)"
        )]
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
        #[arg(
            long,
            help = "Operator-readable intent shown on the WebAuthn confirmation page (with --webauthn)"
        )]
        intent_text: Option<String>,
        /// Per-field detail rows rendered under the headline `--intent-text`,
        /// repeatable. Each value is `Label=Value`. Common rows: service,
        /// agent, K3 epoch, max_calls, expires_at.
        ///
        /// Examples:
        ///   --intent-field "Service=openrouter"
        ///   --intent-field "Max calls / hour=100"
        ///   --intent-field "K3 epoch=1"
        #[arg(
            long = "intent-field",
            help = "Repeatable per-field detail row as `Label=Value` (with --webauthn)"
        )]
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
    #[command(
        name = "software-keygen",
        about = "Software WebAuthn authenticator (#164 headless/CI register): load-or-generate a software P-256 passkey at --key-file and print PUBX/PUBY/RPIDHASH (eval-able). Rust replacement for erc4337-webauthn-sign.py keygen — no python. NOT a hardware/Touch ID passkey and NOT the deprecated EOA path."
    )]
    SoftwareKeygen {
        #[arg(
            long,
            help = "Path to the software passkey file (PKCS#8 PEM; never overwritten)"
        )]
        key_file: String,
        #[arg(long, default_value = "localhost", help = "WebAuthn RP ID")]
        rp_id: String,
        #[arg(
            long = "derive-from",
            help = "Derive the new key DETERMINISTICALLY from this seed file's bytes (e.g. the deployer EVM key file) instead of OsRng — same seed → same passkey → same P256Account address, so an ephemeral CI runner can re-create the registered master passkey on every run (#250). Only used when --key-file does not exist yet (an existing key file always wins). The derived passkey is exactly as strong as custody of the seed file."
        )]
        derive_from: Option<String>,
    },
    #[command(
        name = "software-sign",
        about = "Software WebAuthn authenticator (#164 headless/CI): sign a 32-byte userOpHash with the --key-file passkey, printing AUTHDATA/CDJ/CHALLENGE_LOC/R/S (eval-able) — a byte-identical WebAuthn assertion the on-chain K11Verifier accepts. Rust replacement for erc4337-webauthn-sign.py sign."
    )]
    SoftwareSign {
        #[arg(
            long,
            help = "Path to the software passkey file (from software-keygen)"
        )]
        key_file: String,
        #[arg(
            long,
            help = "32-byte userOpHash hex (with or without 0x) to sign over"
        )]
        userop_hash: String,
        #[arg(
            long,
            default_value = "localhost",
            help = "WebAuthn RP ID (must match keygen)"
        )]
        rp_id: String,
    },
    #[command(
        name = "webauthn-keygen",
        about = "Hardware WebAuthn authenticator (#164 LOCAL register): load-or-enroll the operator's hardware K11 (Secure Enclave / Touch ID) and print PUBX/PUBY/RPIDHASH (eval-able). Triggers a Touch ID *create* ceremony if not yet enrolled. The SECURE local counterpart to software-keygen — the private key never leaves the platform authenticator (no on-disk key)."
    )]
    WebauthnKeygen {
        #[arg(
            long,
            help = "Operator omni (0x + 64 hex) — locates the enrolled credential"
        )]
        operator_omni: String,
        #[arg(long, default_value = "localhost", help = "WebAuthn RP ID")]
        rp_id: String,
    },
    #[command(
        name = "webauthn-userop-sign",
        about = "Hardware WebAuthn authenticator (#164 LOCAL register): sign a 32-byte userOpHash with the operator's hardware K11 — a real Touch ID *get* ceremony — printing AUTHDATA/CDJ/CHALLENGE_LOC/R/S (eval-able). challenge == userOpHash (raw), so it drops into the same handleOps path as software-sign. The SECURE local counterpart to software-sign."
    )]
    WebauthnUseropSign {
        #[arg(
            long,
            help = "Operator omni (0x + 64 hex) — locates the enrolled credential"
        )]
        operator_omni: String,
        #[arg(
            long,
            help = "32-byte userOpHash hex (with or without 0x) to sign over"
        )]
        userop_hash: String,
        #[arg(
            long,
            default_value = "localhost",
            help = "WebAuthn RP ID (must match keygen)"
        )]
        rp_id: String,
        #[arg(
            long,
            help = "Operator-readable intent shown on the confirmation page above the raw hash"
        )]
        intent_text: Option<String>,
    },
}

#[derive(Subcommand)]
enum ChainAction {
    #[command(about = "List built-in chain profile names")]
    List,
    #[command(about = "Print one profile's full JSON (omit name to use the resolved profile)")]
    Show {
        #[arg(
            help = "Profile name (heima | heima-paseo | base | base-sepolia | ethereum | sepolia | anvil)"
        )]
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
        #[arg(
            long,
            help = "Path to a JSON file containing the EIP-712 v4 typed-data"
        )]
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
        #[arg(
            long,
            help = "Path to a JSON file containing the EIP-712 v4 typed-data"
        )]
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
        #[arg(
            long,
            help = "Agent wallet address, alias, or email (defaults to session wallet)"
        )]
        agent: Option<String>,
    },

    #[command(
        about = "List inbox addresses provisioned for an agent",
        long_about = "List all inbox email addresses provisioned for an agent, one per line.\n\nOmit --agent to default to the session wallet.\n\nExamples:\n  agentkeys inbox list\n  agentkeys inbox list --agent 0xAGENT"
    )]
    List {
        #[arg(
            long,
            help = "Agent wallet address, alias, or email (defaults to session wallet)"
        )]
        agent: Option<String>,
    },
}

/// Hook helper subcommands. Invoked by wire-generated scripts; read the
/// host JSON payload from stdin, call an MCP tool, write the host decision
/// JSON to stdout. Common connection flags fall back to env then demo
/// defaults: --mcp-url (AGENTKEYS_MCP_URL), --vendor-token
/// (AGENTKEYS_MCP_VENDOR_TOKEN), --actor (AGENTKEYS_ACTOR_OMNI),
/// --operator (AGENTKEYS_OPERATOR_OMNI).
#[derive(Subcommand)]
enum HookAction {
    #[command(about = "PreToolUse permission gate (fails CLOSED if MCP unreachable)")]
    Check {
        /// Scope to check (e.g. payment.spend).
        #[arg(long)]
        scope: String,
        #[arg(long, env = "AGENTKEYS_MCP_URL")]
        mcp_url: Option<String>,
        #[arg(long, env = "AGENTKEYS_MCP_VENDOR_TOKEN")]
        vendor_token: Option<String>,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor: Option<String>,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator: Option<String>,
    },

    #[command(about = "PostToolUse audit append (never blocks)")]
    Audit {
        #[arg(long, env = "AGENTKEYS_MCP_URL")]
        mcp_url: Option<String>,
        #[arg(long, env = "AGENTKEYS_MCP_VENDOR_TOKEN")]
        vendor_token: Option<String>,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor: Option<String>,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator: Option<String>,
    },

    #[command(
        name = "memory-inject",
        about = "pre_llm_call context injection from memory namespaces (never blocks)"
    )]
    MemoryInject {
        /// Comma-separated memory namespaces to inject.
        #[arg(long, default_value = "travel")]
        namespaces: String,
        #[arg(long, env = "AGENTKEYS_MCP_URL")]
        mcp_url: Option<String>,
        #[arg(long, env = "AGENTKEYS_MCP_VENDOR_TOKEN")]
        vendor_token: Option<String>,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor: Option<String>,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator: Option<String>,
    },
}

#[derive(Subcommand)]
enum MemoryAction {
    /// Write a memory entry — SEED a namespace (e.g. the demo travel fixture).
    /// Reaches the real memory worker in --real mode (in-memory auto-seeds).
    #[command(about = "Write/seed a memory namespace entry via agentkeys.memory.put")]
    Put {
        /// Namespace to write (e.g. `travel`).
        #[arg(long)]
        namespace: String,
        /// Plaintext content to store.
        #[arg(long)]
        content: String,
        #[arg(long, env = "AGENTKEYS_MCP_URL")]
        mcp_url: Option<String>,
        #[arg(long, env = "AGENTKEYS_MCP_VENDOR_TOKEN")]
        vendor_token: Option<String>,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor: Option<String>,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator: Option<String>,
    },
    /// #295 P1 — delegate-side READ of the MASTER's CANONICAL memory namespace
    /// (the master-hub distribution channel). Gated by the actor's on-chain
    /// `memory:<ns>` scope grant; prints the decrypted plaintext. Unlike `put`
    /// (which routes through the MCP server), this is the delegated-fetch path —
    /// §7a (A'): the delegate sends ONLY its OWN session + the cap to the memory
    /// worker and gets back plaintext, NEVER S3 creds. The WORKER fetches the
    /// exact-object scoped STS server-side, so the delegate can't bypass the
    /// worker's audit/chain re-verify nor hold the operator session. Needs the
    /// broker + memory-worker URLs and the DELEGATE's own session (NOT the
    /// master's). Identity/session come from flags or env.
    CanonicalGet {
        /// The memory namespace to read (e.g. `travel`). Carried as the cap
        /// `service` and the worker S3 key suffix.
        #[arg(long)]
        namespace: String,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator_omni: String,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor_omni: String,
        #[arg(long, env = "AGENTKEYS_DEVICE_KEY_HASH")]
        device_key_hash: String,
        #[arg(long, env = "AGENTKEYS_SESSION_BEARER")]
        session_bearer: String,
        #[arg(long, env = "AGENTKEYS_BROKER_URL")]
        broker_url: String,
        #[arg(long, env = "AGENTKEYS_WORKER_MEMORY_URL")]
        memory_url: String,
        #[arg(long, env = "REGION", default_value = "us-east-1")]
        region: String,
    },
    /// #339 P2 — PUSH a learning into the master's absorption inbox (the
    /// master-hub "push" channel): a proposal the master later CURATES into
    /// canonical memory (a pull-request, never a blind write). Gated by the
    /// DELEGATE's on-chain `inbox:<ns>` grant (DISTINCT from the `memory:<ns>`
    /// read grant) and run under the delegate's OWN session (A', §8): the worker
    /// writes server-side under a broker-minted scoped STS, so the delegate holds
    /// no S3 creds and provenance is worker-stamped. Identity/session from flags or env.
    InboxPush {
        /// The bare memory namespace the proposal targets (e.g. `travel`). Built
        /// into the cap `service` as `inbox:<ns>`; the master curates it into
        /// canonical `memory:<ns>`.
        #[arg(long)]
        namespace: String,
        /// The proposed memory key within the namespace (e.g. `night-light-rule`).
        #[arg(long)]
        key: String,
        /// The proposed memory body — the learning text the master will review.
        #[arg(long)]
        body: String,
        #[arg(long, env = "AGENTKEYS_OPERATOR_OMNI")]
        operator_omni: String,
        #[arg(long, env = "AGENTKEYS_ACTOR_OMNI")]
        actor_omni: String,
        #[arg(long, env = "AGENTKEYS_DEVICE_KEY_HASH")]
        device_key_hash: String,
        #[arg(long, env = "AGENTKEYS_SESSION_BEARER")]
        session_bearer: String,
        #[arg(long, env = "AGENTKEYS_BROKER_URL")]
        broker_url: String,
        #[arg(long, env = "AGENTKEYS_WORKER_MEMORY_URL")]
        memory_url: String,
        #[arg(long, env = "REGION", default_value = "us-east-1")]
        region: String,
    },
    /// #339 P2 — LIST the master's absorption-inbox curate queue: every delegate
    /// proposal awaiting review. The MASTER-side twin of `inbox-push`; it drives
    /// the LOCAL DAEMON (which holds the master session + owns the curate merge),
    /// so the daemon must be running with an active master session (authenticate
    /// in the web app). Provenance shown is worker-stamped — unforgeable.
    InboxList {
        #[arg(long, env = "AGENTKEYS_DAEMON_URL", default_value_t = agentkeys_cli::inbox_curate::DEFAULT_DAEMON_URL.to_string())]
        daemon_url: String,
    },
    /// #339 P2 — VIEW one inbox proposal's full body before curating (from `inbox-list`).
    InboxView {
        /// The proposal's `s3_key` (copy it from `inbox-list`).
        #[arg(long)]
        s3_key: String,
        #[arg(long, env = "AGENTKEYS_DAEMON_URL", default_value_t = agentkeys_cli::inbox_curate::DEFAULT_DAEMON_URL.to_string())]
        daemon_url: String,
    },
    /// #339 P2 — ACCEPT (curate) one proposal INTO canonical memory (per-namespace
    /// MERGE), then GC the inbox object. The master's pull-request "merge".
    InboxAccept {
        /// The proposal's `s3_key` (copy it from `inbox-list`).
        #[arg(long)]
        s3_key: String,
        #[arg(long, env = "AGENTKEYS_DAEMON_URL", default_value_t = agentkeys_cli::inbox_curate::DEFAULT_DAEMON_URL.to_string())]
        daemon_url: String,
    },
    /// #339 P2 — REJECT (discard) one proposal; canonical memory is left untouched.
    InboxReject {
        /// The proposal's `s3_key` (copy it from `inbox-list`).
        #[arg(long)]
        s3_key: String,
        #[arg(long, env = "AGENTKEYS_DAEMON_URL", default_value_t = agentkeys_cli::inbox_curate::DEFAULT_DAEMON_URL.to_string())]
        daemon_url: String,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Generate (or reuse) THIS machine's secp256k1 device key, mint a broker
    /// session via wallet_sig SIWE, and print the JSON the master needs to bind
    /// the device on-chain (device_key_hash + pop_sig). Runs in the sandbox so
    /// the agent key is never born on the master. Interim §10.2 (issue #144).
    #[command(
        about = "Mint this agent's device session (in-sandbox keygen + wallet_sig) — emits JSON"
    )]
    DeviceSession {
        #[arg(
            long,
            env = "AGENTKEYS_BROKER_URL",
            help = "Broker base URL (OIDC issuer)"
        )]
        broker_url: String,
        #[arg(
            long,
            default_value = "~/.agentkeys/agent-device.key",
            help = "Device key file — sandbox-local, 0600, NEVER leaves the agent"
        )]
        key_file: String,
        #[arg(
            long,
            default_value = "",
            help = "One-time link code from the master (echoed into the output for binding)"
        )]
        link_code: String,
        #[arg(
            long,
            default_value_t = 1,
            help = "SIWE chain_id replay nonce (not a chain hop)"
        )]
        chain_id: u64,
        #[arg(long, help = "Force a fresh device key → fresh pairing (new omni)")]
        regen: bool,
    },
    /// Master claims an agent's §10.2 pairing request by the `pairing_code` the
    /// agent displayed, binding it under the HDKD child omni for `--label` and
    /// declaring the scope the agent should get. The agent retrieves J1 via
    /// `agentkeys-daemon --retrieve-pairing`. (issue #144, method A)
    #[command(about = "Master: claim an agent pairing request by its code (HDKD child omni)")]
    Claim {
        #[arg(long, help = "The pairing_code the agent displayed (scan / enter)")]
        pairing_code: String,
        #[arg(long, help = "HDKD child label, e.g. agent-a (^[a-z0-9-]{1,32}$)")]
        label: String,
        #[arg(
            long,
            default_value = "memory",
            help = "Scope the agent should get (the app-manifest); granted at approve"
        )]
        services: String,
        #[arg(
            long,
            env = "AGENTKEYS_BROKER_URL",
            help = "Broker base URL (OIDC issuer)"
        )]
        broker_url: String,
        #[arg(
            long,
            default_value = "",
            help = "Master J1 bearer (defaults to the stored `master` session)"
        )]
        session_bearer: String,
    },
    /// Master pulls redeemed-but-unbound agents — "agent-X wants to pair + wants
    /// [scope]" — the production push-notification substrate. Each row carries
    /// the device artifact the master submits with registerAgentDevice. (issue #144)
    #[command(about = "Master: list agents awaiting binding approval")]
    Pending {
        #[arg(
            long,
            env = "AGENTKEYS_BROKER_URL",
            help = "Broker base URL (OIDC issuer)"
        )]
        broker_url: String,
        #[arg(
            long,
            default_value = "",
            help = "Master J1 bearer (defaults to the stored `master` session)"
        )]
        session_bearer: String,
    },
}

async fn cmd_chain(ctx: &CommandContext, action: &ChainAction) -> anyhow::Result<String> {
    use agentkeys_core::chain_profile::ChainProfile;
    match action {
        ChainAction::List => Ok(ChainProfile::list_builtin_names().join("\n")),
        ChainAction::Show { name } => {
            let profile = match name {
                Some(n) => ChainProfile::load_builtin(n).map_err(|e| anyhow::anyhow!("{e}"))?,
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
    // Software WebAuthn authenticator (#164 headless/CI) — real P-256 crypto, NOT
    // the stub and NOT the EOA path, so it bypasses the stub-mode gating below.
    if matches!(
        action,
        K11Action::SoftwareKeygen { .. } | K11Action::SoftwareSign { .. }
    ) {
        // Load-bearing security notice → STDERR (stdout is eval-able by the harness).
        // The software passkey signs with an ON-DISK P-256 key: no Secure-Enclave
        // boundary and no biometric gate, so anyone who can read the key file can sign
        // as this credential. It is a CI / headless / throwaway-TEST stand-in ONLY — it
        // does NOT forge a hardware K11 (a different keypair lives in the Secure Enclave;
        // the on-chain registry binds to that pubkey). A real operator master MUST use a
        // hardware authenticator (`agentkeys k11 enroll --webauthn` → Touch ID). The
        // cryptographic enforcement that REFUSES a software credential at master
        // enrollment — WebAuthn attestation verification — is the stage-2 (#90) hardening
        // (arch.md §22b.1); until it lands, the software path is fenced by policy.
        eprintln!(
            "==> ⚠️  WARN: software P-256 passkey — the key is ON DISK (no hardware \
             boundary, no biometric). Anyone who can read the key file can sign as this \
             credential, so use it for CI / headless / throwaway-TEST masters ONLY. A real \
             operator master MUST use a hardware authenticator (`agentkeys k11 enroll \
             --webauthn`, Touch ID). It does NOT impersonate a hardware K11 — it signs with \
             its own keypair. See arch.md §9 / §22b.1 (attestation verification = stage-2 #90)."
        );
    }
    match action {
        K11Action::SoftwareKeygen {
            key_file,
            rp_id,
            derive_from,
        } => {
            let (x, y, h) = agentkeys_cli::k11_webauthn::software_webauthn_keygen_with_derive(
                key_file,
                rp_id,
                derive_from.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("software-keygen: {e}"))?;
            return Ok(format!("PUBX=0x{x}\nPUBY=0x{y}\nRPIDHASH=0x{h}"));
        }
        K11Action::SoftwareSign {
            key_file,
            userop_hash,
            rp_id,
        } => {
            let (ad, cdj, loc, r, s) =
                agentkeys_cli::k11_webauthn::software_webauthn_sign(key_file, userop_hash, rp_id)
                    .map_err(|e| anyhow::anyhow!("software-sign: {e}"))?;
            return Ok(format!(
                "AUTHDATA=0x{ad}\nCDJ=0x{cdj}\nCHALLENGE_LOC={loc}\nR=0x{r}\nS=0x{s}"
            ));
        }
        // Hardware WebAuthn authenticator (#164 LOCAL register) — real Touch ID, the
        // private key sealed in the Secure Enclave. Same eval-able output as the
        // software path, so the harness submit flow is identical.
        K11Action::WebauthnKeygen {
            operator_omni,
            rp_id,
        } => {
            let (x, y, h) =
                agentkeys_cli::k11_webauthn::hardware_webauthn_keygen(operator_omni, rp_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("webauthn-keygen: {e}"))?;
            return Ok(format!("PUBX=0x{x}\nPUBY=0x{y}\nRPIDHASH=0x{h}"));
        }
        K11Action::WebauthnUseropSign {
            operator_omni,
            userop_hash,
            rp_id,
            intent_text,
        } => {
            let (ad, cdj, loc, r, s) = agentkeys_cli::k11_webauthn::hardware_webauthn_userop_sign(
                operator_omni,
                userop_hash,
                rp_id,
                intent_text.clone(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("webauthn-userop-sign: {e}"))?;
            return Ok(format!(
                "AUTHDATA=0x{ad}\nCDJ=0x{cdj}\nCHALLENGE_LOC={loc}\nR=0x{r}\nS=0x{s}"
            ));
        }
        _ => {}
    }

    let stub_env = std::env::var("AGENTKEYS_K11_STUB")
        .map(|v| v != "0")
        .unwrap_or(true);

    // Resolve mode: --webauthn flag wins over AGENTKEYS_K11_STUB env.
    let use_webauthn = matches!(
        action,
        K11Action::Enroll { webauthn: true, .. } | K11Action::Assert { webauthn: true, .. }
    );

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
        // Software/hardware passkey actions return early in the dispatch above.
        K11Action::SoftwareKeygen { .. }
        | K11Action::SoftwareSign { .. }
        | K11Action::WebauthnKeygen { .. }
        | K11Action::WebauthnUseropSign { .. } => {
            unreachable!("software/hardware passkey actions are handled by the early dispatch")
        }
        K11Action::Enroll {
            operator_omni,
            webauthn,
            rp_id,
        } => {
            if *webauthn {
                let enrollment =
                    agentkeys_cli::k11_webauthn::enroll_webauthn_with_rp(operator_omni, rp_id)
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
                let mut k11_fields: Vec<(String, String)> = Vec::with_capacity(intent_fields.len());
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
            force,
        } => {
            let broker_opt = broker_url.clone().or_else(|| ctx.broker_url.clone());
            let signer = signer_url
                .clone()
                .unwrap_or_else(|| ctx.backend_url.clone());
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
                Ok(mode) => cmd_init_with_force(&ctx, mode, *force)
                    .await
                    .map(|(msg, _session)| msg),
                Err(e) => Err(e),
            }
        }
        Commands::Store {
            agent,
            service,
            key,
        } => cmd_store(&ctx, agent.as_deref(), service, key).await,
        Commands::Read { agent, service } => cmd_read(&ctx, agent.as_deref(), service).await,
        Commands::Run { agent, env, cmd } => cmd_run(&ctx, agent.as_deref(), env, cmd).await,
        Commands::Revoke { agent } => cmd_revoke(&ctx, agent.as_deref()).await,
        Commands::Teardown { agent } => cmd_teardown(&ctx, agent).await,
        Commands::Approve { pair_code, yes } => cmd_approve(&ctx, pair_code, *yes).await,
        Commands::Scope {
            agent,
            add,
            remove,
            set,
            list,
        } => cmd_scope(&ctx, agent, add, remove, set.as_deref(), *list).await,
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
            InboxAction::Provision { agent } => cmd_inbox_provision(&ctx, agent.as_deref()).await,
            InboxAction::List { agent } => cmd_inbox_list(&ctx, agent.as_deref()).await,
        },
        Commands::Whoami {
            signer_url,
            omni_account,
        } => cmd_whoami(&ctx, signer_url.as_deref(), omni_account.as_deref()).await,
        Commands::Signer { action } => match action {
            SignerAction::Derive {
                signer_url,
                omni_account,
            } => cmd_signer_derive(&ctx, signer_url, omni_account).await,
            SignerAction::Sign {
                signer_url,
                omni_account,
                message,
            } => cmd_signer_sign(&ctx, signer_url, omni_account, message).await,
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
            SignerAction::Preview7730 {
                typed_data_file,
                seven_thirty_file,
            } => cmd_signer_preview_7730(&ctx, typed_data_file, seven_thirty_file.as_deref()).await,
        },
        Commands::Chain { action } => cmd_chain(&ctx, action).await,
        Commands::K11 { action } => cmd_k11(action).await,
        Commands::Wire {
            runtime,
            check_only,
            actor_omni,
            operator_omni,
            namespaces,
            payment_scope,
            mcp_url,
            vendor_token,
            session_bearer,
            memory_engine,
            memory_max_lines,
            openviking_endpoint,
            openviking_api_key,
        } => agentkeys_cli::wire::cmd_wire(
            runtime,
            agentkeys_cli::wire::WireRequest {
                actor: actor_omni.clone(),
                operator: operator_omni.clone(),
                namespaces: namespaces.clone(),
                payment_scope: payment_scope.clone(),
                mcp_url: mcp_url.clone(),
                vendor_token: vendor_token.clone(),
                session_bearer: session_bearer.clone(),
                memory_engine: memory_engine.clone(),
                memory_max_lines: *memory_max_lines,
                memory_engine_endpoint: openviking_endpoint.clone(),
                memory_engine_api_key: openviking_api_key.clone(),
                check_only: *check_only,
            },
        ),
        Commands::Hook { action } => match action {
            HookAction::Check {
                scope,
                mcp_url,
                vendor_token,
                actor,
                operator,
            } => {
                agentkeys_cli::hook::check(
                    scope,
                    mcp_url.clone(),
                    vendor_token.clone(),
                    actor.clone(),
                    operator.clone(),
                )
                .await
            }
            HookAction::Audit {
                mcp_url,
                vendor_token,
                actor,
                operator,
            } => {
                agentkeys_cli::hook::audit(
                    mcp_url.clone(),
                    vendor_token.clone(),
                    actor.clone(),
                    operator.clone(),
                )
                .await
            }
            HookAction::MemoryInject {
                namespaces,
                mcp_url,
                vendor_token,
                actor,
                operator,
            } => {
                agentkeys_cli::hook::memory_inject(
                    namespaces,
                    mcp_url.clone(),
                    vendor_token.clone(),
                    actor.clone(),
                    operator.clone(),
                )
                .await
            }
        },
        Commands::Memory { action } => match action {
            MemoryAction::Put {
                namespace,
                content,
                mcp_url,
                vendor_token,
                actor,
                operator,
            } => {
                agentkeys_cli::hook::memory_put(
                    namespace,
                    content,
                    mcp_url.clone(),
                    vendor_token.clone(),
                    actor.clone(),
                    operator.clone(),
                )
                .await
            }
            MemoryAction::CanonicalGet {
                namespace,
                operator_omni,
                actor_omni,
                device_key_hash,
                session_bearer,
                broker_url,
                memory_url,
                region,
            } => {
                agentkeys_cli::cred_admin::memory_canonical_get(
                    namespace,
                    operator_omni,
                    actor_omni,
                    device_key_hash,
                    session_bearer,
                    broker_url,
                    memory_url,
                    region,
                )
                .await
            }
            MemoryAction::InboxPush {
                namespace,
                key,
                body,
                operator_omni,
                actor_omni,
                device_key_hash,
                session_bearer,
                broker_url,
                memory_url,
                region,
            } => {
                agentkeys_cli::cred_admin::memory_inbox_push(
                    namespace,
                    key,
                    body,
                    operator_omni,
                    actor_omni,
                    device_key_hash,
                    session_bearer,
                    broker_url,
                    memory_url,
                    region,
                )
                .await
            }
            MemoryAction::InboxList { daemon_url } => {
                agentkeys_cli::inbox_curate::inbox_list(daemon_url).await
            }
            MemoryAction::InboxView { s3_key, daemon_url } => {
                agentkeys_cli::inbox_curate::inbox_view(daemon_url, s3_key).await
            }
            MemoryAction::InboxAccept { s3_key, daemon_url } => {
                agentkeys_cli::inbox_curate::inbox_accept(daemon_url, s3_key).await
            }
            MemoryAction::InboxReject { s3_key, daemon_url } => {
                agentkeys_cli::inbox_curate::inbox_reject(daemon_url, s3_key).await
            }
        },
        Commands::Agent { action } => match action {
            AgentAction::DeviceSession {
                broker_url,
                key_file,
                link_code,
                chain_id,
                regen,
            } => {
                agentkeys_cli::device_session::device_session(
                    broker_url, key_file, link_code, *chain_id, *regen,
                )
                .await
            }
            AgentAction::Claim {
                pairing_code,
                label,
                services,
                broker_url,
                session_bearer,
            } => {
                agentkeys_cli::agent_admin::agent_claim(
                    broker_url,
                    pairing_code,
                    label,
                    services,
                    session_bearer,
                )
                .await
            }
            AgentAction::Pending {
                broker_url,
                session_bearer,
            } => agentkeys_cli::agent_admin::agent_pending(broker_url, session_bearer).await,
        },
        Commands::Cred { action } => match action {
            CredAction::Fetch {
                service,
                select,
                manifest,
                operator_omni,
                actor_omni,
                device_key_hash,
                session_bearer,
                broker_url,
                cred_url,
                vault_role_arn,
                region,
            } => {
                // #216 default-key selection (off-chain). Resolve which service to
                // fetch — explicit > --select N (1-based) > master-designated
                // default — from the cred manifest, then fetch it (still on-chain
                // verified). An explicit service needs no manifest.
                let mpath = agentkeys_cli::cred_admin::cred_manifest_path(manifest.as_deref());
                match agentkeys_types::CredManifest::load(&mpath)
                    .map_err(|e| anyhow::anyhow!("load cred manifest {}: {e}", mpath.display()))
                    .and_then(|m| {
                        m.resolve(service.as_deref(), *select)
                            .map_err(|e| anyhow::anyhow!("{e}"))
                    }) {
                    Ok(resolved) => {
                        agentkeys_cli::cred_admin::cred_fetch(
                            &resolved,
                            operator_omni,
                            actor_omni,
                            device_key_hash,
                            session_bearer,
                            broker_url,
                            cred_url,
                            vault_role_arn,
                            region,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            CredAction::Store {
                service,
                secret,
                secret_env,
                operator_omni,
                actor_omni,
                device_key_hash,
                session_bearer,
                broker_url,
                cred_url,
                vault_role_arn,
                region,
            } => {
                let resolved: anyhow::Result<String> = match (secret, secret_env) {
                    (Some(s), _) => Ok(s.clone()),
                    (None, Some(env_name)) => std::env::var(env_name).map_err(|_| {
                        anyhow::anyhow!("--secret-env {env_name} is not set in the environment")
                    }),
                    (None, None) => Err(anyhow::anyhow!(
                        "provide the secret via --secret <value> or --secret-env <ENV_NAME>"
                    )),
                };
                match resolved {
                    Ok(secret_value) => agentkeys_cli::cred_admin::cred_store(
                        service,
                        &secret_value,
                        operator_omni,
                        actor_omni,
                        device_key_hash,
                        session_bearer,
                        broker_url,
                        cred_url,
                        vault_role_arn,
                        region,
                    )
                    .await
                    .map(|s3_key| format!("stored `{service}` → {s3_key}")),
                    Err(e) => Err(e),
                }
            }
            CredAction::List { manifest } => {
                let mpath = agentkeys_cli::cred_admin::cred_manifest_path(manifest.as_deref());
                agentkeys_cli::cred_admin::cred_list(&mpath)
            }
            CredAction::Manifest {
                services,
                default,
                manifest,
            } => {
                let mpath = agentkeys_cli::cred_admin::cred_manifest_path(manifest.as_deref());
                agentkeys_cli::cred_admin::cred_manifest_write(&mpath, services, default.clone())
            }
        },
    };

    match result {
        Ok(output) => {
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        Err(err) => {
            // {:#} prints the FULL anyhow context chain (e.g.
            // "memory.put: MCP error (http 200): ... 502 ... s3_put"), not just
            // the top context ("memory.put") — without it the real cause of a
            // failed command is invisible (the harness only saw "memory.put").
            eprintln!("{:#}", err);
            std::process::exit(1);
        }
    }
}
