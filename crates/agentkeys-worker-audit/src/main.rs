use std::sync::Arc;

use clap::Parser;
use tracing::info;

use agentkeys_worker_audit::state::State;

/// Audit-service worker — tier-A Merkle relay (arch.md §15.3).
#[derive(Parser)]
#[command(name = "agentkeys-worker-audit", version)]
struct Args {
    /// Bind address. Default 127.0.0.1:9092 (creds worker is 9094, memory 9095).
    #[arg(
        long,
        env = "AGENTKEYS_WORKER_AUDIT_BIND",
        default_value = "127.0.0.1:9092"
    )]
    bind: String,

    /// Directory for per-batch leaves JSONL files. Default /tmp.
    #[arg(
        long,
        env = "AGENTKEYS_WORKER_AUDIT_LEAVES_DIR",
        default_value = "/tmp"
    )]
    leaves_dir: String,

    /// Periodic flush interval, in seconds. Default 300 (5 min). Set to 0 to
    /// disable the timer (manual flush via /v1/audit/flush-all only).
    #[arg(
        long,
        env = "AGENTKEYS_WORKER_AUDIT_FLUSH_INTERVAL_SECS",
        default_value_t = 300
    )]
    flush_interval_secs: u64,
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
    let state = Arc::new(State::new(args.leaves_dir.clone()));

    // Spawn the periodic flusher if configured.
    if args.flush_interval_secs > 0 {
        let state = state.clone();
        let interval = args.flush_interval_secs;
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(interval));
            t.tick().await; // skip immediate fire
            loop {
                t.tick().await;
                match state.flush_all().await {
                    Ok(rs) if !rs.is_empty() => {
                        for r in rs {
                            info!(
                                operator_omni = %r.operator_omni,
                                entries = r.entry_count,
                                root = %r.merkle_root_hex,
                                leaves = %r.leaves_path,
                                "auto-flush: Merkle root ready for on-chain appendRoot"
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::error!(error=%e, "flush failed"),
                }
                // V2 envelope batches (#229) — anchor inputs for appendRootV2.
                match state.flush_v2_all().await {
                    Ok(rs) if !rs.is_empty() => {
                        for r in rs {
                            info!(
                                operator_omni = %r.operator_omni,
                                entries = r.entry_count,
                                root = %r.merkle_root_hex,
                                op_kind_bitmap = %r.op_kind_bitmap_hex,
                                leaves = %r.leaves_path,
                                "auto-flush: V2 Merkle root ready for on-chain appendRootV2"
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::error!(error=%e, "v2 flush failed"),
                }
            }
        });
    }

    let app = agentkeys_worker_audit::create_router(state);

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    info!(bind = %args.bind, "agentkeys-worker-audit listening");
    axum::serve(listener, app).await?;
    Ok(())
}
