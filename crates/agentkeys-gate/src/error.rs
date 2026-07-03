//! Relay error type. Library errors use `thiserror` (AGENTS.md convention); the
//! HTTP layer maps each variant to an OpenAI-shaped error envelope + status so
//! an OpenAI client (Hermes' provider) parses relay errors like upstream errors.
//!
//! "No silent fallback": an unreachable/5xx upstream is a LOUD 502 (full body
//! operator-logged, never echoed to the caller); a budget denial is a
//! deterministic 429 `budget_exceeded` — no LLM in the decision (#332).

use crate::openai::ApiError;

#[derive(thiserror::Error, Debug)]
pub enum GateError {
    /// Inbound request rejected before any upstream work (missing/unknown
    /// relay key).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated but not allowed (e.g. non-admin querying another user).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Malformed request the relay can't act on.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// The caller's user is at/over its token budget — the deterministic
    /// denial of #332 (`denied: budget_exceeded`).
    #[error("budget exceeded: {0}")]
    Budget(String),

    /// The upstream LLM failed (unreachable, 5xx, or unparseable). The full
    /// upstream body is operator-logged at the call site; this message stays
    /// safe to echo.
    #[error("upstream error: {0}")]
    Upstream(String),

    /// Audit append failed AND `AGENTKEYS_GATE_REQUIRE_AUDIT=1` — the turn is
    /// failed because it could not be recorded (tamper-evident audit is the
    /// product).
    #[error("audit error: {0}")]
    Audit(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl GateError {
    pub fn status(&self) -> u16 {
        match self {
            GateError::Unauthorized(_) => 401,
            GateError::Forbidden(_) => 403,
            GateError::BadRequest(_) => 400,
            GateError::Budget(_) => 429,
            GateError::Upstream(_) => 502,
            GateError::Audit(_) | GateError::Internal(_) => 500,
        }
    }

    /// The OpenAI `error.type` discriminator the caller's client expects.
    fn openai_type(&self) -> &'static str {
        match self {
            GateError::Unauthorized(_) => "authentication_error",
            GateError::Forbidden(_) => "permission_error",
            GateError::BadRequest(_) => "invalid_request_error",
            GateError::Budget(_) => "insufficient_quota",
            GateError::Upstream(_) => "upstream_error",
            GateError::Audit(_) | GateError::Internal(_) => "api_error",
        }
    }

    fn code(&self) -> Option<&'static str> {
        match self {
            GateError::Budget(_) => Some("budget_exceeded"),
            _ => None,
        }
    }

    pub fn to_api_error(&self) -> ApiError {
        let mut err = ApiError::new(self.openai_type(), self.to_string());
        err.error.code = self.code().map(str::to_string);
        err
    }
}

pub type GateResult<T> = Result<T, GateError>;
