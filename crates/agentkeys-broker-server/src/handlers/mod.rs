pub mod accept;
pub mod agent;
pub mod audit_emit;
pub mod auth;
pub mod broker_status;
pub mod canonical_sts;
pub mod cap;
pub mod channel_sts;
pub mod inbox_sts;
pub mod metrics;
pub mod oidc;
pub mod presets;
pub mod register;
pub mod revoke;
pub mod sandbox;
pub mod scope;
pub mod spawn;
pub mod speech_sts;
pub mod wallet;

use axum::http::HeaderMap;

use crate::error::BrokerError;
use crate::jwt::verify::{verify_session_jwt, SessionClaims};
use crate::state::SharedState;

/// Generate a base64url-no-pad random identifier — request ids, pairing codes.
/// (Lived in the retired `/v1/grant` module until #547 removed it.)
pub(crate) fn random_b64url(byte_len: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut buf = vec![0u8; byte_len];
    getrandom::getrandom(&mut buf).expect("OS RNG failed");
    URL_SAFE_NO_PAD.encode(buf)
}

/// Extract + verify a session JWT from `Authorization: Bearer <jwt>`.
/// Used by the §10.2 agent handlers (issue #144) and the #369 delegation
/// handlers.
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
