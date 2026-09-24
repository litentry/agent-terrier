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
    // #519 speech relay arming — LOUD either way (a disarmed leg 503s).
    match (&config.speech_asr, &config.speech_tts) {
        (Some(_), Some(_)) => tracing::info!("speech relay ARMED (asr + tts families resolved)"),
        (asr, tts) => tracing::warn!(
            asr = asr.is_some(),
            tts = tts.is_some(),
            "speech relay partially/un-configured — missing legs will 503 \
             (provision with rotate-inference-cred.sh asr|tts)"
        ),
    }

    // #722 System One relay arming — LOUD either way (a disarmed leg 503s and
    // the contact gate's router runs its deterministic tier).
    match &config.systemone {
        Some(ts) => {
            tracing::info!(base = %ts.base_url, "systemone (Jev) relay ARMED (typesafe family resolved)")
        }
        None => tracing::warn!(
            "systemone (Jev) relay NOT configured — /v1/systemone will 503 until the typesafe \
             family is provisioned (rotate-inference-cred.sh typesafe, or TYPESAFE_API_KEY)"
        ),
    }

    let listen = config.listen;
    let relay = Arc::new(Relay::new(config));
    let app = server::router(relay);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(addr = %listen, "agentkeys-gate listening (OpenAI-compatible egress relay)");
    axum::serve(listener, app).await?;

    Ok(())
}
