use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Caller is authenticated but lacks permission for this specific
    /// action — e.g. a revoked/expired/exhausted grant (Phase B). Maps
    /// to HTTP 403 (Codex Phase A.2 round-3 Vector 4 P2 mitigation).
    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("backend unreachable: {0}")]
    BackendUnreachable(String),

    #[error("sts error: {0}")]
    StsError(String),

    #[error("audit error: {0}")]
    AuditError(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl BrokerError {
    fn status_and_kind(&self) -> (StatusCode, &'static str) {
        match self {
            BrokerError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            BrokerError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            BrokerError::BackendUnreachable(_) => (StatusCode::BAD_GATEWAY, "backend_unreachable"),
            BrokerError::StsError(_) => (StatusCode::BAD_GATEWAY, "sts_error"),
            BrokerError::AuditError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_error"),
            BrokerError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            BrokerError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        let (status, kind) = self.status_and_kind();
        let body = Json(json!({ "error": kind, "message": self.to_string() }));
        (status, body).into_response()
    }
}

pub type BrokerResult<T> = Result<T, BrokerError>;
