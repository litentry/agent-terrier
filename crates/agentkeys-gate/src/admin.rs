//! Authenticated relay-key provisioning and revocation.

use std::sync::Arc;

pub use agentkeys_protocol::model_relay::{DisableKeyResponse, ProvisionKeyRequest};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::GateError;
use crate::relay::Relay;

fn auth_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

fn error_response(err: GateError) -> Response {
    let status = axum::http::StatusCode::from_u16(err.status())
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(err.to_api_error())).into_response()
}

/// `POST /v1/admin/keys` (admin bearer) — provision/rotate a relay key.
pub async fn provision_key(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Json(req): Json<ProvisionKeyRequest>,
) -> Response {
    if !auth::is_admin(&relay.config, auth_header(&headers)) {
        return error_response(GateError::Unauthorized("admin token required".into()));
    }
    match relay.keys.provision(
        &req.key_id,
        &req.user_omni,
        req.delegate_omni.clone(),
        &req.device_id,
        &req.label,
        req.budget_tokens,
    ) {
        Ok(minted) => {
            tracing::info!(
                key_id = %minted.key_id,
                user = %req.user_omni,
                delegate = %req.delegate_omni.as_deref().unwrap_or("-"),
                budget = ?req.budget_tokens,
                "admin: relay key provisioned"
            );
            Json(minted).into_response()
        }
        Err(e) => error_response(e),
    }
}

/// `POST /v1/admin/keys/:key_id/disable` (admin bearer) — deprovision.
pub async fn disable_key(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    if !auth::is_admin(&relay.config, auth_header(&headers)) {
        return error_response(GateError::Unauthorized("admin token required".into()));
    }
    match relay.keys.disable(&key_id) {
        Ok(disabled) => {
            tracing::info!(key_id = %key_id, disabled, "admin: relay key disable");
            Json(DisableKeyResponse { key_id, disabled }).into_response()
        }
        Err(e) => error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The broker and relay use this same wire contract.
    #[test]
    fn provision_request_shape_is_pinned() {
        let req: ProvisionKeyRequest = serde_json::from_value(serde_json::json!({
            "key_id": format!("0x{}", "11".repeat(32)),
            "user_omni": "aa".repeat(32),
            "delegate_omni": "cc".repeat(32),
            "device_id": format!("0x{}", "11".repeat(32)),
            "label": "watchdog",
            "budget_tokens": 500u64
        }))
        .unwrap();
        assert_eq!(req.label, "watchdog");
        assert_eq!(req.budget_tokens, Some(500));
        // Optional fields default.
        let min: ProvisionKeyRequest = serde_json::from_value(serde_json::json!({
            "key_id": "k", "user_omni": "u", "device_id": "d"
        }))
        .unwrap();
        assert!(min.delegate_omni.is_none());
        assert!(min.budget_tokens.is_none());
        assert!(min.label.is_empty());
    }

    #[test]
    fn disable_response_shape_is_pinned() {
        let json = serde_json::to_value(DisableKeyResponse {
            key_id: "k".into(),
            disabled: true,
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({"key_id": "k", "disabled": true}));
    }
}
