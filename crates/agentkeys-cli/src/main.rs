use agentkeys_cli::{
    cmd_approve, cmd_feedback, cmd_init, cmd_link, cmd_read, cmd_recover, cmd_revoke, cmd_run,
    cmd_store, cmd_teardown, cmd_usage, CommandContext,
};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentkeys",
    version,
    about = "Credential management for AI agents",
    long_about = "agentkeys — secure credential storage and injection for AI agents.\n\nExamples:\n  agentkeys init --mock-token mytoken\n  agentkeys store 0xAGENT openrouter sk-or-...\n  agentkeys read 0xAGENT openrouter\n  agentkeys run 0xAGENT -- python my_agent.py\n  agentkeys usage 0xAGENT\n  agentkeys revoke 0xAGENT\n  agentkeys teardown 0xAGENT"
)]
struct Cli {
    #[arg(long, default_value = "http://localhost:8090", help = "Backend URL")]
    backend: String,

    #[arg(long, help = "Show verbose HTTP request/response details")]
    verbose: bool,

    #[arg(long, help = "Output machine-readable JSON where supported")]
    json: bool,

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
        long_about = "Encrypt and store an API key for a given agent and service.\n\nExamples:\n  agentkeys store 0xAGENT openrouter sk-or-v1-abc123\n  agentkeys store 0xAGENT anthropic sk-ant-abc123"
    )]
    Store {
        #[arg(help = "Agent wallet address")]
        agent: String,
        #[arg(help = "Service name (e.g. openrouter, anthropic)")]
        service: String,
        #[arg(help = "API key or credential value")]
        key: String,
    },

    #[command(
        about = "Read a credential for an agent+service",
        long_about = "Retrieve and print the stored credential.\n\nExamples:\n  agentkeys read 0xAGENT openrouter\n  agentkeys read --json 0xAGENT openrouter"
    )]
    Read {
        #[arg(help = "Agent wallet address")]
        agent: String,
        #[arg(help = "Service name")]
        service: String,
    },

    #[command(
        about = "Run a command with credentials injected as env vars",
        long_about = "Load credentials for the agent and inject them as SERVICE_API_KEY env vars.\n\nExamples:\n  agentkeys run 0xAGENT -- python my_agent.py\n  agentkeys run 0xAGENT -- node server.js"
    )]
    Run {
        #[arg(help = "Agent wallet address")]
        agent: String,
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
        about = "Open the feedback forum in your browser",
        long_about = "Open https://github.com/agentkeys/agentkeys/discussions in the default browser.\n\nExamples:\n  agentkeys feedback"
    )]
    Feedback,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let ctx = CommandContext::new(&cli.backend, cli.verbose, cli.json);

    let result: anyhow::Result<String> = match &cli.command {
        Commands::Init { mock_token } => {
            cmd_init(&ctx, mock_token.clone()).await.map(|(msg, _session)| msg)
        }
        Commands::Store { agent, service, key } => cmd_store(&ctx, agent, service, key).await,
        Commands::Read { agent, service } => cmd_read(&ctx, agent, service).await,
        Commands::Run { agent, cmd } => cmd_run(&ctx, agent, cmd).await,
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
        Commands::Feedback => Ok(cmd_feedback()),
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
