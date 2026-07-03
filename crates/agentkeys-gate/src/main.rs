//! Entry point — parse CLI/env once, build the relay, serve.

use std::sync::Arc;

use clap::Parser;

use agentkeys_gate::{
    config::{Cli, GateConfig},
    relay::Relay,
    server,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 needs a process-level CryptoProvider before any HTTPS work
    // (the upstream LLM call via reqwest rustls-tls). Install `ring` explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config = GateConfig::from_cli(cli)?;

    if config.keys.is_empty() {
        tracing::warn!(
            "no relay keys configured (AGENTKEYS_GATE_KEYS_FILE) — every request will 401; \
             there is no anonymous mode in the custody relay (usage must attribute to a user)"
        );
    }
    if config.audit_url.is_none() {
        tracing::warn!(
            "no audit worker configured (AGENTKEYS_AUDIT_URL) — GateTurn rows will NOT be \
             appended; metering stays process-local only"
        );
    }
    tracing::info!(
        upstream = %config.upstream.base_url,
        model_override = ?config.upstream.model_override,
        keys = config.keys.len(),
        default_budget = ?config.default_budget_tokens,
        "metered key-custody relay configured"
    );

    let listen = config.listen;
    let relay = Arc::new(Relay::new(config));
    let app = server::router(relay);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(addr = %listen, "agentkeys-gate listening (OpenAI-compatible egress relay)");
    axum::serve(listener, app).await?;

    Ok(())
}
