//! `GET /v1/auth/email/status/{request_id}` — Phase A.1, US-018.
//!
//! CLI poll endpoint. Returns `{status: pending|verified|failed}`.
//! When `status == "verified"`, the response carries the session JWT
//! and the verified `omni_account`. This is the load-bearing
//! browser→CLI handoff per plan §3.5.3 — the session JWT NEVER appears
//! in the browser-facing response of `/v1/auth/email/verify`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::error::BrokerError;
use crate::state::SharedState;

pub async fn email_status(
    State(state): State<SharedState>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, BrokerError> {
    #[cfg(feature = "auth-email-link")]
    {
        let plugin = state.email_link.as_ref().ok_or_else(|| {
            BrokerError::BadRequest("email_link auth method is not enabled".to_string())
        })?;
        let status = plugin
            .token_store
            .peek_status(&request_id)
            .map_err(super::wallet_start_map_auth_err)?;

        use crate::storage::EmailRequestStatus;
        let body = match status {
            EmailRequestStatus::Pending => json!({ "status": "pending" }),
            EmailRequestStatus::Verified {
                session_jwt,
                omni_account,
                expires_at,
            } => json!({
                "status":            "verified",
                "session_jwt":       session_jwt,
                "session_jwt_kid":   state.session_keypair.kid,
                "expires_at":        expires_at,
                "omni_account":      omni_account,
            }),
            EmailRequestStatus::Failed { reason } => json!({
                "status": "failed",
                "reason": reason,
            }),
            EmailRequestStatus::Unknown => {
                return Err(BrokerError::BadRequest(format!(
                    "unknown request_id: {}",
                    request_id
                )));
            }
        };
        Ok((StatusCode::OK, Json(body)))
    }
    #[cfg(not(feature = "auth-email-link"))]
    {
        let _ = (state, request_id);
        Err(BrokerError::BadRequest(
            "auth-email-link feature is not compiled in".into(),
        ))
    }
}
