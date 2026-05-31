//! Capability-grant endpoints (Phase B, US-025/026/027).
//!
//! Per plan §3.5.5: grants are first-class data. The master OmniAccount
//! authorizes a daemon to mint AWS creds for a specific (service,
//! scope_path) combination, bounded by `expires_at` + `max_uses`. The
//! `audit_proof` is a broker-signed JWT over the grant content — DB
//! exfiltration cannot produce a verified-but-tampered grant.

pub mod create;
pub mod list;
pub mod revoke;

use axum::http::HeaderMap;

use crate::error::BrokerError;
use crate::jwt::verify::{verify_session_jwt, SessionClaims};
use crate::state::SharedState;

/// Generate a base64url-no-pad random identifier — used for `grant_id`.
pub(crate) fn random_b64url(byte_len: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut buf = vec![0u8; byte_len];
    getrandom::getrandom(&mut buf).expect("OS RNG failed");
    URL_SAFE_NO_PAD.encode(buf)
}

/// Extract + verify a session JWT from `Authorization: Bearer <jwt>`.
/// Used by every grant endpoint and by the §10.2 agent handlers (issue #144).
pub(crate) fn require_session_jwt(
    headers: &HeaderMap,
    state: &SharedState,
) -> Result<SessionClaims, BrokerError> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            BrokerError::Unauthorized("missing or malformed Authorization header".into())
        })?;
    verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, bearer)
}
