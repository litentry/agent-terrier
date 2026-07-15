//! `GET /auth/oauth2/callback` — Phase A.2, US-021.
//!
//! Provider-side redirect target. Google sends `?code=…&state=…` (or
//! `?error=…&state=…` on user denial). The handler:
//!
//! 1. If `error` is present, looks up the request_id from the state
//!    payload (no DB consume — we want the failed status visible to the
//!    CLI) and marks the pending row `failed`.
//! 2. Otherwise, calls `OAuth2Auth::handle_callback` which atomically
//!    consumes the row, exchanges the code at the provider, verifies
//!    the id_token (signature/iss/aud/exp/nonce), and returns the
//!    derived sub.
//! 3. The handler mints a session JWT, calls `mark_verified` on the
//!    pending row, and renders a minimal "Verified — return to your
//!    terminal" HTML page with `Cache-Control: no-store` +
//!    `Referrer-Policy: no-referrer`.
//!
//! The session JWT NEVER reaches the browser response — same posture as
//! plan §3.5.3 EmailLink. The CLI gets it via the polling endpoint.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;

use crate::env;
use crate::error::BrokerError;
use crate::identity::derive_with_client_id;
use crate::jwt::issue::mint_session_jwt;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct OAuth2CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default, rename = "error_description")]
    pub error_description: Option<String>,
}

pub async fn oauth2_callback(
    State(state): State<SharedState>,
    Query(q): Query<OAuth2CallbackQuery>,
) -> Result<impl IntoResponse, BrokerError> {
    #[cfg(feature = "auth-oauth2")]
    {
        let plugin = state.oauth2.as_ref().ok_or_else(|| {
            BrokerError::BadRequest(
                "oauth2 plugin not enabled (set BROKER_AUTH_METHODS=…,oauth2_<provider>)".into(),
            )
        })?;

        // 1. Provider-side rejection (user denied, etc.).
        if let Some(err) = q.error.as_deref() {
            // Best-effort: parse the state payload to find the request_id
            // so the CLI poll learns about the failure. We do NOT consume
            // the pending row on error — the CLI may want to retry.
            let reason = q
                .error_description
                .clone()
                .map(|d| format!("{}: {}", err, d))
                .unwrap_or_else(|| err.to_string());
            if let Some(state_token) = q.state.as_deref() {
                let now = unix_now();
                if let Ok(payload) = plugin.verify_state(state_token, now) {
                    let _ = plugin.pending_store.mark_failed(&payload.rid, &reason);
                }
            }
            return Ok(callback_html_response(
                StatusCode::OK,
                format!(
                    "Sign-in cancelled: {}. You may close this tab and try again.",
                    err
                ),
            ));
        }

        // 2. Happy path — code + state required.
        let code = q.code.as_deref().ok_or_else(|| {
            BrokerError::BadRequest("oauth2 callback missing 'code' query param".into())
        })?;
        let state_token = q.state.as_deref().ok_or_else(|| {
            BrokerError::BadRequest("oauth2 callback missing 'state' query param".into())
        })?;

        let now = unix_now();
        let outcome = match plugin.handle_callback(code, state_token, now).await {
            Ok(o) => o,
            Err(e) => {
                // Codex round-1 Vector 6 P1 mitigation: only mark_failed
                // when THIS invocation actually consumed the row.
                // owned_request_id=None means the failure happened
                // pre-consume (bad state, already-consumed by a
                // concurrent callback) — touching the row would clobber
                // a legitimate flow still in flight.
                if let Some(rid) = e.owned_request_id.as_deref() {
                    let _ = plugin.pending_store.mark_failed(rid, &e.inner.to_string());
                }
                return Err(super::wallet_start_map_auth_err(e.inner));
            }
        };

        // 3. Mint session JWT bound to (omni_account, identity_type, sub).
        let omni = derive_with_client_id(
            &state.config.client_id,
            outcome.identity_type.canonical(),
            &outcome.sub,
        );
        let ttl_seconds = std::env::var(env::BROKER_SESSION_JWT_TTL_SECONDS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(18_000);
        let session_jwt = mint_session_jwt(
            &state.session_keypair,
            &state.config.oidc_issuer,
            omni.as_str(),
            "", // no wallet for oauth2-only identity (Phase B grants will fill this in)
            outcome.identity_type.canonical(),
            &outcome.sub,
            ttl_seconds,
        )
        .map_err(|e| BrokerError::Internal(format!("mint session jwt: {}", e)))?;
        let expires_at = now + ttl_seconds as i64;

        plugin
            .pending_store
            .mark_verified(
                &outcome.request_id,
                &session_jwt,
                omni.as_str(),
                &outcome.sub,
                expires_at,
            )
            .map_err(|e| BrokerError::Internal(format!("mark_verified: {}", e)))?;

        // 4. Browser response — minimal HTML, security headers per plan
        //    §3.5.3/§3.5.4. Session JWT lands on CLI poll, not here.
        Ok(callback_html_response(
            StatusCode::OK,
            "Verified — return to your terminal.".to_string(),
        ))
    }
    #[cfg(not(feature = "auth-oauth2"))]
    {
        let _ = (state, q);
        Err(BrokerError::BadRequest(
            "auth-oauth2 feature is not compiled in".into(),
        ))
    }
}

fn callback_html_response(status: StatusCode, msg: String) -> (StatusCode, HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>AgentKeys — OAuth2</title><style>body{{font-family:system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:1rem}}h1{{font-size:1.5rem}}</style></head><body><h1>{}</h1></body></html>"#,
        html_escape(&msg)
    );
    (status, headers, body)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
