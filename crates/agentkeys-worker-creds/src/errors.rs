//! Shared HTTP error responses for storage workers.

use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

pub type ApiError = (StatusCode, Json<ErrorBody>);

fn err(status: StatusCode, msg: impl Into<String>, reason: &'static str) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: msg.into(),
            reason,
            detail: None,
        }),
    )
}

pub fn err_400(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::BAD_REQUEST, msg, reason)
}

pub fn err_403(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::FORBIDDEN, msg, reason)
}

pub fn err_401(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::UNAUTHORIZED, msg, reason)
}

pub fn err_409(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::CONFLICT, msg, reason)
}

pub fn err_404(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::NOT_FOUND, msg, reason)
}

pub fn err_413(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::PAYLOAD_TOO_LARGE, msg, reason)
}

pub fn err_500(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::INTERNAL_SERVER_ERROR, msg, reason)
}

pub fn err_502(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::BAD_GATEWAY, msg, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_errors_omit_detail_key() {
        let response = err_502("storage unavailable", "storage_unavailable");
        assert_eq!(response.0, StatusCode::BAD_GATEWAY);
        let body = serde_json::to_value(&response.1 .0).unwrap();
        assert_eq!(body["error"], "storage unavailable");
        assert_eq!(body["reason"], "storage_unavailable");
        assert!(body.get("detail").is_none());
        assert_eq!(body.as_object().unwrap().len(), 2);
    }
}
