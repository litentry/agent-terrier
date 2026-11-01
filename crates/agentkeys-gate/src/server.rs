//! HTTP transport. The OpenAI-compatible caller routes (`/v1/chat/completions`,
//! `/v1/embeddings`, `/v1/models`, `/v1/usage`) + the speech/voices legs +
//! `/healthz` (liveness) and `/readyz` (the upstream account answers).

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::auth;
use crate::error::GateError;
use crate::relay::{Relay, TurnOutput};

pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/chat/completions", post(chat_completions))
        // #572 — the embeddings relay (same gk_ auth + budgets; the
        // in-sandbox OpenViking engine's metered embedding egress).
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/embeddings/multimodal", post(embeddings_multimodal))
        // #653 — the web-search relay (SearXNG behind the gate; engine set
        // pinned by config — Bing by deployment default).
        .route("/v1/search", post(search))
        // #722 — the System One decision relay: the household router's typed
        // pick through the gate-held key of the provider the model names (Jev
        // or Kev). 503 for a provider this gate holds no key for.
        .route(agentkeys_protocol::SYSTEMONE_ROUTE, post(systemone))
        .route(
            agentkeys_protocol::SYSTEMONE_MODELS_ROUTE,
            get(systemone_models),
        )
        .route("/v1/models", get(models))
        .route("/v1/usage", get(usage))
        // Authenticated JSON audio API; adapter is optional.
        .route("/v1/audio/transcriptions", post(audio_transcriptions))
        .route("/v1/audio/speech", post(audio_speech))
        // Authenticated optional speech catalog.
        .route("/v1/audio/voices", get(audio_voices))
        // #427 — broker-driven per-delegate provisioning (admin bearer): spawn
        // mints a relay key, archive disables it. See `admin.rs`.
        .route("/v1/admin/keys", post(crate::admin::provision_key))
        .route(
            "/v1/admin/keys/:key_id/disable",
            post(crate::admin::disable_key),
        )
        // Inline-base64 audio clips overflow axum's ~2 MB default (a 60 s wav
        // is ~1.9 MB before base64). 8 MB bounds a clip without inviting bulk.
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(relay)
}

/// #519 — ASR leg: authenticate the gk_ relay key, then call the injected speech adapter.
async fn audio_transcriptions(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Json(req): Json<crate::speech::TranscribeRequest>,
) -> Response {
    let caller = match authenticate_live(&relay, &headers) {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };
    match relay.handle_transcribe(&caller, req).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(key = %caller.key_id, error = %e, "transcription failed");
            error_response(e)
        }
    }
}

/// #519 — TTS leg.
async fn audio_speech(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Json(req): Json<crate::speech::SpeakRequest>,
) -> Response {
    let caller = match authenticate_live(&relay, &headers) {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };
    match relay.handle_speak(&caller, req).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(key = %caller.key_id, error = %e, "synthesis failed");
            error_response(e)
        }
    }
}

async fn audio_voices(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    if let Err(e) = authenticate_live(&relay, &headers) {
        return error_response(e);
    }
    match relay.speech.voices().await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "voices catalog failed");
            error_response(e)
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// Readiness requires usable credential persistence and no standing upstream refusal.
async fn readyz(State(relay): State<Arc<Relay>>) -> Response {
    if !relay.keys.is_available() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status":"unready", "credential_persistence_failed":true
            })),
        )
            .into_response();
    }
    match relay.upstream_account.current() {
        None => Json(serde_json::json!({ "status": "ready" })).into_response(),
        Some(refusal) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "unready",
                "upstream_account_refused": refusal,
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use crate::config::{Cli, GateConfig};
    use clap::Parser;

    #[tokio::test]
    async fn failed_persistence_disables_readiness_and_caller_access() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let path = state.join("keys.json");
        agentkeys_core::protected_file::write(path.to_str().unwrap(),
            serde_json::json!({"keys":[{"key":"synthetic-test-key","key_id":"actor","user_omni":"ab".repeat(32),"device_id":"device"}]}).to_string().as_bytes(),true).unwrap();
        let config = GateConfig::from_cli(
            Cli::try_parse_from(["gate", "--keys-file", path.to_str().unwrap()]).unwrap(),
        )
        .unwrap();
        let relay = Arc::new(Relay::new(config));
        assert_eq!(readyz(State(relay.clone())).await.status(), StatusCode::OK);
        assert!(relay.keys.authenticate("synthetic-test-key").is_ok());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(state).unwrap();
        assert!(relay.keys.disable("actor").is_err());
        assert_eq!(
            readyz(State(relay.clone())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(relay.keys.authenticate("synthetic-test-key").is_err());
    }
}

fn auth_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

fn error_response(err: GateError) -> Response {
    let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(err.to_api_error())).into_response()
}

fn full_response(status: u16, content_type: String, body: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn chat_completions(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match authenticate_live(&relay, &headers) {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };
    match relay.handle_chat(&caller, &body).await {
        Ok(TurnOutput::Full {
            status,
            content_type,
            body,
        }) => full_response(status, content_type, body),
        Ok(TurnOutput::Stream {
            status,
            content_type,
            rx,
        }) => Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from_stream(rx))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(e) => {
            tracing::warn!(key = %caller.key_id, error = %e, "turn failed");
            error_response(e)
        }
    }
}

/// #572 — the embeddings relay leg. Embeddings never stream, so a Stream
/// output here is a relay bug, surfaced as a 500 rather than hung.
async fn embeddings(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    embeddings_leg(relay, headers, body, false).await
}

/// #639 — the multimodal twin: OpenViking 0.4.16 appends `/embeddings/multimodal`
/// for explicit compatible adapters; same auth, metering and budgets.
async fn embeddings_multimodal(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    embeddings_leg(relay, headers, body, true).await
}

async fn embeddings_leg(
    relay: Arc<Relay>,
    headers: HeaderMap,
    body: Bytes,
    multimodal: bool,
) -> Response {
    let caller = match authenticate_live(&relay, &headers) {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };
    match relay.handle_embeddings(&caller, &body, multimodal).await {
        Ok(TurnOutput::Full {
            status,
            content_type,
            body,
        }) => full_response(status, content_type, body),
        Ok(TurnOutput::Stream { .. }) => error_response(GateError::Internal(
            "embeddings relay produced a stream".into(),
        )),
        Err(e) => {
            tracing::warn!(key = %caller.key_id, error = %e, "embeddings call failed");
            error_response(e)
        }
    }
}

/// #653 — the web-search relay leg. Searches never stream.
async fn search(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match authenticate_live(&relay, &headers) {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };
    match relay.handle_search(&caller, &body).await {
        Ok(TurnOutput::Full {
            status,
            content_type,
            body,
        }) => full_response(status, content_type, body),
        Ok(TurnOutput::Stream { .. }) => {
            error_response(GateError::Internal("search relay produced a stream".into()))
        }
        Err(e) => {
            tracing::warn!(key = %caller.key_id, error = %e, "search call failed");
            error_response(e)
        }
    }
}

/// #722 — the System One decision relay leg. Decisions never stream.
async fn systemone(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match authenticate_live(&relay, &headers) {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };
    match relay.handle_systemone(&caller, &body).await {
        Ok(TurnOutput::Full {
            status,
            content_type,
            body,
        }) => full_response(status, content_type, body),
        Ok(TurnOutput::Stream { .. }) => error_response(GateError::Internal(
            "systemone relay produced a stream".into(),
        )),
        Err(e) => {
            tracing::warn!(key = %caller.key_id, error = %e, "systemone call failed");
            error_response(e)
        }
    }
}

/// Resolve the bearer against the LIVE key registry (#427 — the store, not
/// the boot snapshot: broker-minted keys authenticate, disabled keys refuse).
fn authenticate_live(
    relay: &Relay,
    headers: &HeaderMap,
) -> Result<crate::config::RelayKey, GateError> {
    let token = auth::bearer(auth_header(headers))?;
    relay.keys.authenticate(token)
}

/// #722 — `GET /v1/systemone/models`: every decision-model provider's server,
/// armed or not, for the contact gate's router view (a live relay key or the
/// admin token).
async fn systemone_models(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    if authenticate_live(&relay, &headers).is_err()
        && !auth::is_admin(&relay.config, auth_header(&headers))
    {
        return error_response(GateError::Unauthorized("unknown relay key".into()));
    }
    (StatusCode::OK, Json(relay.systemone_models().await)).into_response()
}

async fn models(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    if authenticate_live(&relay, &headers).is_err()
        && !auth::is_admin(&relay.config, auth_header(&headers))
    {
        return error_response(GateError::Unauthorized("unknown relay key".into()));
    }
    match relay.models().await {
        Ok((status, content_type, body)) => full_response(status, content_type, body),
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct UsageQuery {
    user_omni: Option<String>,
}

/// Rollup endpoint (#384): a relay key sees ITS user's summary; the admin
/// token sees any user (`?user_omni=`) or all users.
async fn usage(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Query(q): Query<UsageQuery>,
) -> Response {
    let header = auth_header(&headers);
    if auth::is_admin(&relay.config, header) {
        return match q.user_omni {
            Some(user) => {
                let budget = relay.config.budget_for(&user);
                Json(relay.meter.summary(&user, budget)).into_response()
            }
            None => {
                let summaries = relay.meter.summaries(|u| relay.config.budget_for(u));
                Json(summaries).into_response()
            }
        };
    }
    match authenticate_live(&relay, &headers) {
        Ok(key) => {
            if let Some(requested) = &q.user_omni {
                if requested != &key.user_omni {
                    return error_response(GateError::Forbidden(
                        "relay keys may only query their own user".into(),
                    ));
                }
            }
            let budget = relay.config.budget_for(&key.user_omni);
            Json(relay.meter.summary(&key.user_omni, budget)).into_response()
        }
        Err(e) => error_response(e),
    }
}
