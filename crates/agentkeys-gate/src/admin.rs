//! #427 — the admin provisioning surface the BROKER drives at spawn/archive
//! (epic #425 decision 6): `POST /v1/admin/keys` mints a per-delegate relay
//! key (upsert; the secret is returned ONCE), `POST /v1/admin/keys/:id/disable`
//! deprovisions it (turns refuse; usage history stays for rollups). Both are
//! gated by the SAME operator admin bearer that guards the all-users usage
//! view (`AGENTKEYS_GATE_ADMIN_TOKEN`) — its first mutating use, which is why
//! every mutation write-throughs to the 0600 keys file (durability) and the
//! gate remains custody + metering (provisioning changes WHO is metered,
//! never what a caller may do).
//!
//! The request/response shapes are pinned by the serde tests below — the
//! broker-side client (`agentkeys-broker-server/src/gate_admin.rs`) mirrors
//! them (#203 one-owner posture at the field level).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::error::GateError;
use crate::relay::Relay;

/// `POST /v1/admin/keys` body.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionKeyRequest {
    /// Stable key id — the broker uses the delegate's `device_key_hash`.
    pub key_id: String,
    /// The OWNING user omni — the budget/rollup accumulation root.
    pub user_omni: String,
    /// The delegate actor omni (per-delegate attribution dimension).
    #[serde(default)]
    pub delegate_omni: Option<String>,
    pub device_id: String,
    #[serde(default)]
    pub label: String,
    /// Per-delegate token ceiling UNDER the user budget (the tier default the
    /// broker passes; unset = only the user-level budget applies).
    #[serde(default)]
    pub budget_tokens: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DisableKeyResponse {
    pub key_id: String,
    /// `true` = a live key was disabled; `false` = unknown/already disabled
    /// (idempotent).
    pub disabled: bool,
}

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

    /// Pin the wire shape the broker's `gate_admin.rs` client mirrors.
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
