//! `GET /metrics` — Phase D-rest, US-036.
//!
//! Returns Prometheus-exposition-format text body with the broker's
//! atomic counters. Gated behind `BROKER_METRICS_ENABLED=true` —
//! disabled deployments return 404.

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};

use crate::env;
use crate::state::SharedState;

pub async fn metrics_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let enabled = std::env::var(env::BROKER_METRICS_ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false);
    if !enabled {
        return (StatusCode::NOT_FOUND, HeaderMap::new(), String::new());
    }
    let body = state.metrics.render_prometheus();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, body)
}
