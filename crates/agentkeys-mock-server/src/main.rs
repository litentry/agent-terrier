use agentkeys_mock_server::{create_router, db, state::AppState};
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "8090")]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = Arc::new(AppState::new(conn));

    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .unwrap();
    println!("Mock server running on port {}", args.port);
    axum::serve(listener, app).await.unwrap();
}
