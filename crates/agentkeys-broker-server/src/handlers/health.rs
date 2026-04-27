use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::state::SharedState;

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn readyz(State(state): State<SharedState>) -> impl IntoResponse {
    let backend_ok = state
        .http
        .get(format!("{}/health", state.config.backend_url.trim_end_matches('/')))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let sts_ok = state.sts.caller_identity_ok().await.is_ok();

    if backend_ok && sts_ok {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "backend_ok": backend_ok,
                "sts_ok": sts_ok,
            })),
        )
            .into_response()
    }
}
