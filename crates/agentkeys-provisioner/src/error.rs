use agentkeys_types::{ProvisionErrorCode, TripwireKind};
use thiserror::Error;

pub type ProvisionResult<T> = Result<T, ProvisionError>;

#[derive(Debug, Error)]
pub enum ProvisionError {
    #[error("provision already in progress for service: {active_service}")]
    InProgress { active_service: String },

    #[error("subprocess spawn failed: {0}")]
    SpawnFailed(#[from] std::io::Error),

    #[error("subprocess exited with non-zero status before emitting success or error event")]
    SubprocessFailed { exit_code: Option<i32>, stderr: String },

    #[error("subprocess emitted malformed event line: {line} ({source})")]
    MalformedEvent {
        line: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("subprocess exceeded {timeout_secs}s wall-clock timeout")]
    Timeout { timeout_secs: u64 },

    #[error("tripwire fired: {kind:?} at step {step} ({elapsed_ms}ms)")]
    Tripwire {
        kind: TripwireKind,
        step: String,
        elapsed_ms: u64,
    },

    #[error("verification failed for service {service}: {reason}")]
    VerificationFailed { service: String, reason: String },

    #[error("verification endpoint down for service {service}: retry later")]
    VerificationEndpointDown { service: String },

    #[error("store_credential failed after successful provision; key recovery required: {obtained_key_masked} — {source}")]
    StoreFailed {
        obtained_key_masked: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("internal error: {0}")]
    Internal(String),
}

impl ProvisionError {
    pub fn to_code(&self) -> ProvisionErrorCode {
        match self {
            Self::InProgress { .. } => ProvisionErrorCode::ProvisionInProgress,
            Self::SpawnFailed(_) => ProvisionErrorCode::Internal,
            Self::SubprocessFailed { .. } => ProvisionErrorCode::TripwireExhausted,
            Self::MalformedEvent { .. } => ProvisionErrorCode::MalformedEvent,
            Self::Timeout { .. } => ProvisionErrorCode::Timeout,
            Self::Tripwire { .. } => ProvisionErrorCode::TripwireExhausted,
            Self::VerificationFailed { .. } => ProvisionErrorCode::StoreFailed,
            Self::VerificationEndpointDown { .. } => ProvisionErrorCode::VerificationEndpointDown,
            Self::StoreFailed { .. } => ProvisionErrorCode::StoreFailed,
            Self::Internal(_) => ProvisionErrorCode::Internal,
        }
    }
}
