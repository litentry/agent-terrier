use agentkeys_mock_server::{
    create_router, create_signer_router, db, dev_key_service::DevKeyService, state::AppState,
};
use clap::Parser;
use jsonwebtoken::DecodingKey;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "8090")]
    port: u16,

    /// When set, the server runs in signer-only mode: it serves ONLY
    /// `/dev/derive-address`, `/dev/sign-message`, and `/healthz`.
    /// All other endpoints (session, credential, audit, etc.) are absent.
    /// Intended for the dedicated `signer.litentry.org` listener (:8092).
    #[arg(long)]
    signer_only: bool,

    /// Path to the broker's ES256 session public key PEM file.
    /// When provided together with `--signer-only`, the signer reads this key
    /// at boot and uses it to verify the `Authorization: Bearer <jwt>` header
    /// on every `/dev/*` request.
    ///
    /// Default: `/var/lib/agentkeys/.agentkeys/broker/session-keypair.pub.pem`
    /// (the path the broker writes when started with `--export-session-pubkey-to`).
    #[arg(
        long,
        default_value = "/var/lib/agentkeys/.agentkeys/broker/session-keypair.pub.pem"
    )]
    broker_session_pubkey_path: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();

    // Load the dev signer from `DEV_KEY_SERVICE_MASTER_SECRET`. Unset →
    // `/dev/*` returns 503; malformed → fail boot loud (operator error).
    let dev_signer = match DevKeyService::from_env() {
        Ok(opt) => {
            if opt.is_some() {
                eprintln!(
                    "[mock-server] dev_key_service ENABLED (DEV ONLY — replace with TEE worker per issue #74 step 2)"
                );
            } else {
                eprintln!(
                    "[mock-server] dev_key_service disabled (set DEV_KEY_SERVICE_MASTER_SECRET to enable)"
                );
            }
            opt
        }
        Err(e) => {
            eprintln!("[mock-server] FATAL: invalid DEV_KEY_SERVICE_MASTER_SECRET: {e}");
            std::process::exit(2);
        }
    };

    // In signer-only mode, load the broker's session pubkey for JWT bearer
    // verification. If the file is missing, fail boot loud — the operator
    // must ensure the broker has written the pubkey before starting the signer.
    let broker_session_pubkey = if args.signer_only {
        match load_broker_pubkey(&args.broker_session_pubkey_path) {
            Ok(key) => {
                eprintln!(
                    "[mock-server] signer-only mode: broker session pubkey loaded from {}",
                    args.broker_session_pubkey_path.display()
                );
                Some(key)
            }
            Err(e) => {
                eprintln!(
                    "[mock-server] FATAL: cannot load broker session pubkey from {}: {e}",
                    args.broker_session_pubkey_path.display()
                );
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    let state = Arc::new(
        AppState::new(conn)
            .with_dev_signer(dev_signer)
            .with_broker_session_pubkey(broker_session_pubkey),
    );

    let bind_addr = if args.signer_only {
        // Signer-only listener binds to loopback — nginx fronts it publicly.
        format!("127.0.0.1:{}", args.port)
    } else {
        format!("0.0.0.0:{}", args.port)
    };

    let app = if args.signer_only {
        eprintln!(
            "[mock-server] signer-only mode: serving /dev/* + /healthz on {}",
            bind_addr
        );
        create_signer_router(state)
    } else {
        create_router(state)
    };

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    println!("Mock server running on {}", bind_addr);
    axum::serve(listener, app).await.unwrap();
}

/// Load a PEM-encoded EC public key for use as a JWT decoding key.
fn load_broker_pubkey(path: &PathBuf) -> Result<DecodingKey, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    DecodingKey::from_ec_pem(&pem)
        .map_err(|e| format!("parse EC PEM from {}: {e}", path.display()))
}
