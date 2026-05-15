use agentkeys_cli::{
    cmd_approve, cmd_feedback, cmd_inbox_list, cmd_inbox_provision, cmd_init, cmd_link,
    cmd_provision, cmd_read, cmd_recover, cmd_revoke, cmd_run, cmd_scope, cmd_signer_derive,
    cmd_signer_sign, cmd_store, cmd_teardown, cmd_usage, cmd_whoami, CommandContext, InitMode,
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
        about = "Show audit log for credential usage",
        long_about = "Query the audit log for credential read/write events.\n\nExamples:\n  agentkeys usage\n  agentkeys usage 0xAGENT\n  agentkeys usage --json 0xAGENT"
    )]
    Usage {
        #[arg(help = "Filter by agent wallet address (optional)")]
        agent: Option<String>,
        #[arg(long, help = "Output as JSON array")]
        json: bool,
    },

    #[command(
        about = "Link an identity (alias or email) to an agent",
        long_about = "Associate a human-readable alias or email with an agent's wallet address.\n\nExamples:\n  agentkeys link 0xAGENT --alias my-bot\n  agentkeys link 0xAGENT --email bot@example.com"
    )]
    Link {
        #[arg(help = "Agent wallet address")]
        agent: String,
        #[arg(long, help = "Human-readable alias")]
        alias: Option<String>,
        #[arg(long, help = "Email address to link")]
        email: Option<String>,
    },

    #[command(
        about = "Recover a session via 2FA (passkey or email)",
        long_about = "Recover a master or agent session using a second-factor recovery method.\n\nExamples:\n  agentkeys recover my-bot --method passkey\n  agentkeys recover bot@example.com --method email\n  agentkeys recover 0xAGENT --method passkey"
    )]
    Recover {
        #[arg(help = "Agent identity (alias, email, or wallet address)")]
        identity: String,
        #[arg(long, help = "Recovery method: passkey or email")]
        method: String,
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let ctx = CommandContext::new(&cli.backend, cli.verbose, cli.json)
        .with_broker_url(cli.broker_url.clone())
        .with_session_id(cli.session_id.clone());

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
        Commands::Usage { agent, json } => {
            cmd_usage(&ctx, agent.as_deref(), *json).await
        }
        Commands::Link { agent, alias, email } => {
            cmd_link(&ctx, agent, alias.as_deref(), email.as_deref()).await
        }
        Commands::Recover { identity, method } => cmd_recover(&ctx, identity, method).await,
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
        },
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
