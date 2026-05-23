//! Shared HTTP-error response helpers. Used by both the credentials
//! worker AND the memory worker (which depends on this crate as a lib)
//! so the wire-shape of error responses stays consistent across
//! per-data-class workers per arch.md §17.

use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub reason: &'static str,
}

pub type ApiError = (StatusCode, Json<ErrorBody>);

pub fn err_400(msg: impl Into<String>, reason: &'static str) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: msg.into(),
            reason,
        }),
    )
}

pub fn err_403(msg: impl Into<String>, reason: &'static str) -> ApiError {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: msg.into(),
            reason,
        }),
    )
}

pub fn err_500(msg: impl Into<String>, reason: &'static str) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: msg.into(),
            reason,
        }),
    )
}

pub fn err_502(msg: impl Into<String>, reason: &'static str) -> ApiError {
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorBody {
            error: msg.into(),
            reason,
        }),
    )
}
