//! ES256 JWT keypair management with **purpose tagging**.
//!
//! Per Stage 7 plan §3.5.6 + Codex/eng review #7 mitigation: we carry two
//! distinct ES256 keypairs in this broker — one signs OIDC JWTs that AWS
//! STS verifies (existing `crate::oidc::OidcKeypair`), the other signs
//! session JWTs that the broker itself verifies (the new `SessionKeypair`).
//!
//! These keypairs MUST NOT be co-mingled. If an operator accidentally
//! pointed `BROKER_SESSION_KEYPAIR_PATH` at the OIDC keypair file, the
//! broker would sign session JWTs with the OIDC key — meaning AWS IAM
//! would accept session JWTs as OIDC tokens (same `kid`, same key).
//!
//! Defense: the on-disk JSON carries a `"purpose"` field; load-time
//! validation refuses to read a keypair that has the wrong purpose for
//! the slot it's being loaded into.
//!
//! Backwards-compat: the legacy OIDC keypair file format has no `purpose`
//! field. `OidcKeypair::load` accepts a missing `purpose` as `"oidc"` so
//! pre-Stage-7 deployments continue to boot. New keypairs always include
//! the `purpose` field. After one minor version, missing-purpose load
//! becomes a hard error.

pub mod issue;
pub mod session;
pub mod verify;

use serde::{Deserialize, Serialize};

/// Stable kebab-case purpose tag persisted in the keypair JSON. Renaming
/// is a breaking change for every existing on-disk keypair.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeypairPurpose {
    /// Signs JWTs that AWS STS verifies via JWKS (the public OIDC issuer keypair).
    Oidc,
    /// Signs broker-internal session JWTs verified locally by the broker.
    Session,
}

impl KeypairPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeypairPurpose::Oidc => "oidc",
            KeypairPurpose::Session => "session",
        }
    }

    pub fn kid_prefix(&self) -> &'static str {
        match self {
            KeypairPurpose::Oidc => "ak-oidc",
            KeypairPurpose::Session => "ak-session",
        }
    }
}

/// Error type for purpose-mismatch on keypair load.
#[derive(Debug, thiserror::Error)]
pub enum KeypairPurposeError {
    #[error("keypair at {path} has purpose {actual:?} but slot expects {expected:?}")]
    PurposeMismatch {
        path: String,
        expected: KeypairPurpose,
        actual: KeypairPurpose,
    },
    #[error("keypair at {path} has no purpose field — refusing to load (run with --legacy-allow-untagged once to migrate)")]
    PurposeMissing { path: String },
}

pub use session::SessionKeypair;
