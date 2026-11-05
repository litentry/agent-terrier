//! Protected local audit archive and shared envelope helpers.
//!
//! The executable serves `archive::router`; the in-memory Merkle router below
//! remains a component fixture for existing protocol tests.

pub mod archive;
pub mod handlers;
pub mod merkle;
pub mod state;

use axum::{
    routing::{get, post},
    Router,
};

/// Build the worker's HTTP router. Exposed for tests that want to drive
/// the V2 endpoints through `tower::ServiceExt::oneshot` without binding
/// a real TCP socket.
pub fn create_router(state: state::SharedState) -> Router {
    create_router_with_origins(
        state,
        &std::env::var("AGENTKEYS_BROWSER_ORIGINS").unwrap_or_default(),
    )
}

pub fn create_router_with_origins(state: state::SharedState, origins: &str) -> Router {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};
    let origins = agentkeys_protocol::browser_origins::parse_browser_origins(origins)
        .into_iter()
        .filter_map(|origin| HeaderValue::from_str(&origin).ok())
        .collect::<Vec<_>>();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(
            agentkeys_protocol::browser_origins::WORKER_CORS_HEADERS
                .iter()
                .map(|header| HeaderName::from_static(header))
                .collect::<Vec<_>>(),
        );
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/audit/append", post(handlers::append))
        .route("/v1/audit/flush/:operator_omni", post(handlers::flush_one))
        .route("/v1/audit/flush-all", post(handlers::flush_all))
        .route(
            "/v1/audit/queue-size/:operator_omni",
            get(handlers::queue_size),
        )
        .route("/v1/audit/append/v2", post(handlers::append_v2))
        .route("/v1/audit/envelope/:hash", get(handlers::get_envelope))
        .layer(cors)
        .with_state(state)
}
