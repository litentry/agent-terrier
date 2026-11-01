//! `GET /v1/auth/oauth2/status/{request_id}` — Phase A.2, US-021.
//!
//! CLI poll endpoint. Returns `{status: pending|verified|failed}`. When
//! `verified`, the response carries the session JWT, omni_account, and
//! identity_value (the Google `sub`). Mirrors `email_status` (US-018) so
//! a CLI sharing one polling loop across email/oauth2 flows sees the
//! same shape.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::error::BrokerError;
use crate::state::SharedState;

pub async fn oauth2_status(
    State(state): State<SharedState>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, BrokerError> {
    #[cfg(feature = "auth-oauth2")]
    {
        let plugin = state
            .oauth2
            .as_ref()
            .ok_or_else(|| BrokerError::BadRequest("oauth2 plugin not enabled".to_string()))?;
        use crate::storage::OAuth2PendingStatus;
        let status = plugin
            .pending_store
            .peek_status(&request_id)
            .map_err(super::wallet_start_map_auth_err)?;
        let body = match status {
            OAuth2PendingStatus::Pending => json!({ "status": "pending" }),
            OAuth2PendingStatus::Verified {
                session_jwt,
                omni_account,
                identity_value,
                expires_at,
            } => json!({
                "status":          "verified",
                "session_jwt":     session_jwt,
                "session_jwt_kid": state.session_keypair.kid,
                "expires_at":      expires_at,
                "omni_account":    omni_account,
                "identity_type":   plugin.provider.identity_type().canonical(),
                "identity_value":  identity_value,
            }),
            OAuth2PendingStatus::Failed { reason } => json!({
                "status": "failed",
                "reason": reason,
            }),
            OAuth2PendingStatus::Unknown => {
                return Err(BrokerError::BadRequest(format!(
                    "unknown request_id: {}",
                    request_id
                )));
            }
        };
        Ok((StatusCode::OK, Json(body)))
    }
    #[cfg(not(feature = "auth-oauth2"))]
    {
        let _ = (state, request_id);
        Err(BrokerError::BadRequest(
            "auth-oauth2 feature is not compiled in".into(),
        ))
    }
}
