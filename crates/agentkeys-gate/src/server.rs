//! HTTP transport. Three caller-facing routes (`/v1/chat/completions`,
//! `/v1/models`, `/v1/usage`) + `/healthz` for the load balancer.

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
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/models", get(models))
        .route("/v1/usage", get(usage))
        // #519 — the speech relay legs (same gk_ auth; gate-held Doubao app
        // tokens per #386). JSON→JSON with base64 audio — channel-ready, not
        // an OpenAI-compatible surface. See `speech.rs`.
        .route("/v1/audio/transcriptions", post(audio_transcriptions))
        .route("/v1/audio/speech", post(audio_speech))
        // #527 — the TTS voices catalog (gk_-authed; gate-held IAM per the
        // custody decision in voices.rs). 503 when unconfigured.
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

/// #519 — ASR leg: authenticate the gk_ relay key, then relay to Doubao.
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

/// #527 — the TTS voices catalog. gk_-authed (any live relay key); the gate
/// V4-signs ListBigModelTTSTimbres with its held IAM credential. 503 when the
/// IAM credential is unconfigured (never a silent empty list).
async fn audio_voices(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    if let Err(e) = authenticate_live(&relay, &headers) {
        return error_response(e);
    }
    match crate::voices::fetch_voices(relay.voices.as_ref()).await {
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

/// Resolve the bearer against the LIVE key registry (#427 — the store, not
/// the boot snapshot: broker-minted keys authenticate, disabled keys refuse).
fn authenticate_live(
    relay: &Relay,
    headers: &HeaderMap,
) -> Result<crate::config::RelayKey, GateError> {
    let token = auth::bearer(auth_header(headers))?;
    relay.keys.authenticate(token)
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
