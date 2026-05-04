use agentkeys_cli::{
    cmd_approve, cmd_feedback, cmd_inbox_list, cmd_inbox_provision, cmd_init, cmd_link,
    cmd_provision, cmd_read, cmd_recover, cmd_revoke, cmd_run, cmd_scope, cmd_store, cmd_teardown,
    cmd_usage, CommandContext,
};


use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentkeys",
    version,
    about = "Credential management for AI agents",
    long_about = "agentkeys — secure credential storage and injection for AI agents.\n\nThe --agent flag on store/read/run accepts a 0x... wallet, a linked alias, or a linked email. Omit it to default to the current session wallet.\n\nExamples:\n  agentkeys init --mock-token mytoken\n  agentkeys store openrouter sk-or-...                    (session wallet)\n  agentkeys store --agent 0xAGENT openrouter sk-or-...    (specific wallet)\n  agentkeys read --agent my-bot openrouter                (linked alias)\n  agentkeys run -- python my_agent.py                     (session wallet)\n  agentkeys run --agent 0xAGENT -- python my_agent.py     (specific wallet)\n  agentkeys usage 0xAGENT\n  agentkeys revoke 0xAGENT\n  agentkeys teardown 0xAGENT"
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
        help = "Stage 7 broker URL — when set, `provision` fetches AWS temp creds from the broker (replaces stage6-demo-env.sh)"
    )]
    broker_url: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Initialize a new session",
        long_about = "Authenticate with the backend and store the session token in the OS keychain.\n\nExamples:\n  agentkeys init\n  agentkeys init --mock-token my-test-token"
    )]
    Init {
        #[arg(long, help = "Use a mock authentication token (for testing)")]
        mock_token: Option<String>,
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
        .with_broker_url(cli.broker_url.clone());

    let result: anyhow::Result<String> = match &cli.command {
        Commands::Init { mock_token } => {
            cmd_init(&ctx, mock_token.clone()).await.map(|(msg, _session)| msg)
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
