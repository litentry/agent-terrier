//! Shared HTTP-error response helpers. Used by the credentials worker AND
//! the other per-data-class workers (memory / config / classify depend on
//! this crate as a lib) so the wire-shape of error responses stays
//! consistent across workers per arch.md §17.

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub reason: &'static str,
    /// Structured machine-readable diagnostic (#284) — attached only by paths
    /// that have one (today: the fetch handlers' `s3_get` 502s, which carry
    /// per-vault-attempt S3 error codes). Omitted from the JSON when `None`,
    /// so callers keying on `error`/`reason` see an unchanged envelope.
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

/// 404 — used by the data-class workers' GET handlers when the requested object
/// does not exist (S3 `NoSuchKey`). Distinct from `err_502` so a CALLER (e.g.
/// the daemon's read-modify-write plant, #201 Phase 4) can tell "never written"
/// apart from a real S3/transport failure and NOT overwrite durable data on a
/// transient error.
pub fn err_404(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::NOT_FOUND, msg, reason)
}

pub fn err_500(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::INTERNAL_SERVER_ERROR, msg, reason)
}

pub fn err_502(msg: impl Into<String>, reason: &'static str) -> ApiError {
    err(StatusCode::BAD_GATEWAY, msg, reason)
}

/// One vault-candidate S3 GetObject attempt, embedded in the fetch handlers'
/// `s3_get` 502 `detail.attempts` (#284). Carries WHICH vault was tried
/// (`agent-own` = the actor's own prefix, #228; `operator` = the #216
/// delegated fallback), the vault owner's omni (already a signed cap field —
/// not secret), and the S3 error class — never key contents.
#[derive(Debug, Serialize)]
pub struct S3FetchAttempt {
    pub vault: &'static str,
    pub owner_omni: String,
    /// The S3 service error code (`NoSuchKey` / `AccessDenied` /
    /// `ExpiredToken` / ...), or a `transport_*` class when the request never
    /// produced a service response. See [`s3_error_code`].
    pub s3_code: String,
    /// The S3 service error message when present (the AccessDenied messages
    /// name the denied action + resource ARN — the actionable half).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_message: Option<String>,
}

impl S3FetchAttempt {
    pub fn from_sdk_err<E, R>(vault: &'static str, owner_omni: &str, e: &SdkError<E, R>) -> Self
    where
        E: ProvideErrorMetadata,
    {
        Self {
            vault,
            owner_omni: owner_omni.to_string(),
            s3_code: s3_error_code(e),
            s3_message: s3_error_message(e),
        }
    }
}

/// The fetch handlers' `s3_get` 502 (#284). `reason` stays `"s3_get"` for
/// caller compatibility; the per-vault-attempt diagnostics ride in `detail`
/// so a remote caller (CI runner, daemon) can tell `NoSuchKey` vs
/// `AccessDenied` vs expired-STS apart without a broker-host journalctl
/// session.
pub fn err_502_s3_get(bucket: &str, attempts: Vec<S3FetchAttempt>) -> ApiError {
    let summary = attempts
        .iter()
        .map(|a| format!("{}({})={}", a.vault, a.owner_omni, a.s3_code))
        .collect::<Vec<_>>()
        .join("; ");
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorBody {
            error: format!(
                "s3 GetObject failed for {} vault candidate(s): {summary}",
                attempts.len()
            ),
            reason: "s3_get",
            detail: Some(serde_json::json!({
                "bucket": bucket,
                "attempts": attempts,
            })),
        }),
    )
}

/// The S3 service error CODE from the SDK error metadata (`NoSuchKey` /
/// `AccessDenied` / `ExpiredToken` / `NoSuchBucket` / ...), falling back to a
/// coarse transport class when the request never reached a service response.
pub fn s3_error_code<E, R>(e: &SdkError<E, R>) -> String
where
    E: ProvideErrorMetadata,
{
    if let Some(code) = e.code() {
        return code.to_string();
    }
    match e {
        SdkError::ConstructionFailure(_) => "transport_construction".to_string(),
        SdkError::TimeoutError(_) => "transport_timeout".to_string(),
        SdkError::DispatchFailure(_) => "transport_dispatch".to_string(),
        SdkError::ResponseError(_) => "transport_response".to_string(),
        _ => "unknown".to_string(),
    }
}

/// The S3 service error message when present and non-empty.
pub fn s3_error_message<E, R>(e: &SdkError<E, R>) -> Option<String>
where
    E: ProvideErrorMetadata,
{
    e.message().filter(|m| !m.is_empty()).map(str::to_string)
}

/// Human-readable "CODE — message" S3 error summary (falls back to the SDK
/// Display when no service code is available). Moved here from the config
/// worker (#201) so every data-class worker surfaces the REAL S3 error —
/// `AccessDenied` (role missing S3 Get/Put on the prefix, or a PrincipalTag
/// mismatch), `NoSuchBucket` (bucket not provisioned), a region mismatch —
/// instead of the SDK's generic "service error" the operator can't act on.
pub fn s3_error_summary<E, R>(e: &SdkError<E, R>) -> String
where
    E: ProvideErrorMetadata,
{
    match (e.code(), e.message()) {
        (Some(code), Some(msg)) if !msg.is_empty() => format!("{code} — {msg}"),
        (Some(code), _) => code.to_string(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::error::ErrorMetadata;
    use aws_sdk_s3::operation::get_object::GetObjectError;

    fn body_json(err: &ApiError) -> serde_json::Value {
        serde_json::to_value(&err.1 .0).unwrap()
    }

    /// An SdkError carrying a service error code + message, the shape a real
    /// S3 4xx/5xx response parses into. `R = ()` is fine — the helpers are
    /// generic over the raw-response type.
    fn mock_service_err(code: &str) -> SdkError<GetObjectError, ()> {
        let meta = ErrorMetadata::builder()
            .code(code)
            .message("mock detail")
            .build();
        SdkError::service_error(GetObjectError::generic(meta), ())
    }

    #[test]
    fn s3_get_502_body_carries_per_attempt_detail() {
        // The #284 shape: NoSuchKey on the agent-own vault, AccessDenied on
        // the operator fallback — previously collapsed into one stringified
        // "service error" that made the two indistinguishable from a runner.
        let attempts = vec![
            S3FetchAttempt {
                vault: "agent-own",
                owner_omni: "0xagent".into(),
                s3_code: "NoSuchKey".into(),
                s3_message: None,
            },
            S3FetchAttempt {
                vault: "operator",
                owner_omni: "0xmaster".into(),
                s3_code: "AccessDenied".into(),
                s3_message: Some("User is not authorized to perform s3:GetObject".into()),
            },
        ];
        let err = err_502_s3_get("vault-bucket", attempts);
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);

        let body = body_json(&err);
        // Compatibility: reason stays "s3_get", error stays a string.
        assert_eq!(body["reason"], "s3_get");
        let msg = body["error"].as_str().unwrap();
        assert!(msg.contains("NoSuchKey"), "error names the s3 code: {msg}");
        assert!(
            msg.contains("AccessDenied"),
            "error names both codes: {msg}"
        );
        assert!(msg.contains("0xagent") && msg.contains("0xmaster"));

        assert_eq!(body["detail"]["bucket"], "vault-bucket");
        let attempts = body["detail"]["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0]["vault"], "agent-own");
        assert_eq!(attempts[0]["owner_omni"], "0xagent");
        assert_eq!(attempts[0]["s3_code"], "NoSuchKey");
        assert!(attempts[0].get("s3_message").is_none());
        assert_eq!(attempts[1]["vault"], "operator");
        assert_eq!(attempts[1]["owner_omni"], "0xmaster");
        assert_eq!(attempts[1]["s3_code"], "AccessDenied");
        assert!(attempts[1]["s3_message"]
            .as_str()
            .unwrap()
            .contains("not authorized"));
    }

    #[test]
    fn plain_errors_omit_detail_key() {
        // Pre-#284 envelope unchanged: exactly {error, reason}, no detail key.
        let err = err_502("boom", "s3_get");
        let body = body_json(&err);
        assert_eq!(body["error"], "boom");
        assert_eq!(body["reason"], "s3_get");
        assert!(body.get("detail").is_none());
        assert_eq!(body.as_object().unwrap().len(), 2);
    }

    #[test]
    fn s3_error_code_extracts_service_code_from_sdk_error() {
        for code in ["NoSuchKey", "AccessDenied", "ExpiredToken"] {
            let e = mock_service_err(code);
            assert_eq!(s3_error_code(&e), code);
            let attempt = S3FetchAttempt::from_sdk_err("agent-own", "0xab", &e);
            assert_eq!(attempt.s3_code, code);
            assert_eq!(attempt.s3_message.as_deref(), Some("mock detail"));
            assert_eq!(s3_error_summary(&e), format!("{code} — mock detail"));
        }
    }

    #[test]
    fn s3_error_code_classifies_transport_failures() {
        let e = SdkError::<GetObjectError, ()>::timeout_error("mock timeout");
        assert_eq!(s3_error_code(&e), "transport_timeout");
        assert_eq!(s3_error_message(&e), None);
    }
}
