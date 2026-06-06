//! Entry point — parse CLI, build a `Server`, run the chosen transport.

use clap::Parser;
use std::sync::Arc;

use agentkeys_backend_client::BackendClient;
use agentkeys_mcp_server::{
    backend::Backend,
    config::{BackendKind, Cli, Config, Transport},
    server::Server,
    transport,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires a process-level CryptoProvider. tokio-tungstenite
    // pulls rustls in with no provider feature; without this install_default
    // the McpEndpoint transport panics on the first wss:// connect.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Log to stderr — stdio transport reserves stdout exclusively for
    // JSON-RPC frames. Mixing tracing output into stdout corrupts the
    // wire and Claude Desktop / Claude Code disconnect immediately.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config = Config::from_cli(cli)?;

    // Real-data-only: the MCP server has exactly one backend — the real HTTP
    // chain (broker cap-mint → per-actor STS → worker → S3), which IS the shared
    // `agentkeys_backend_client::BackendClient` (#203/#207 collapsed the former
    // `HttpBackend` delegate; `Backend` is impl'd directly on `BackendClient`).
    // The in-memory fixture backend was removed.
    let backend: Arc<dyn Backend> = match config.backend {
        BackendKind::Http => Arc::new(BackendClient::new(
            config.broker_url.clone(),
            config.memory_url.clone(),
            config.audit_url.clone(),
            config.agent_session_bearer.clone(),
            config.memory_role_arn.clone(),
            config.vault_role_arn.clone(),
            config.aws_region.clone(),
        )),
    };
    let server = Arc::new(Server::new(config.clone(), backend));

    match config.transport {
        Transport::Http => {
            let app = transport::http_router(server);
            let listener = tokio::net::TcpListener::bind(&config.listen).await?;
            tracing::info!(addr = %config.listen, "agentkeys-mcp-server listening (HTTP)");
            axum::serve(listener, app).await?;
        }
        Transport::Stdio => {
            tracing::info!("agentkeys-mcp-server running (stdio)");
            transport::run_stdio(server).await?;
        }
        Transport::McpEndpoint => {
            let url = config.mcp_endpoint.clone().expect(
                "mcp_endpoint required for McpEndpoint transport — validated in Config::from_cli",
            );
            // Don't log the raw URL — it carries the bearer JWT.
            // run_mcp_endpoint redacts internally.
            let host = url
                .split("://")
                .nth(1)
                .and_then(|rest| rest.split(['/', '?']).next())
                .unwrap_or("?");
            tracing::info!(host, "agentkeys-mcp-server running (mcp-endpoint)");
            transport::run_mcp_endpoint(server, url).await?;
        }
    }

    Ok(())
}
