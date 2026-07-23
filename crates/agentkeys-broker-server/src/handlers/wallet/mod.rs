//! Wallet endpoints (Phase B, US-028).
//!
//! Per plan §3.5.5 + §Phase B: master-gated wallet recovery.
//! Recovery is NOT email-only re-binding (Codex P0 #4 mitigation):
//! - `POST /v1/wallet/link` — master attaches a verified identity
//!   (email, oauth2 sub, secondary EVM wallet) to their OmniAccount.
//! - `GET /v1/wallet/links` — master lists their attached identities.
//! - `POST /v1/wallet/recover/lookup` — non-authenticated lookup that
//!   returns the master OmniAccount owning a given linked identity.
//!   The actual re-authorization is then the original master's on-chain
//!   ceremony (§10.2 pairing claim / #427 spawn — K11-signed register +
//!   scope; the former `/v1/grant/create` step was removed with the
//!   unenforced GrantStore, #547).
//!
//! There is NO endpoint that takes a "fresh email auth" and rebinds the
//! master wallet — that flow would let a phished email become wallet
//! takeover. The master always signs the recovery authorization.

pub mod link;
pub mod links_list;
pub mod recover_lookup;

use axum::http::HeaderMap;

use crate::error::BrokerError;
use crate::jwt::verify::{verify_session_jwt, SessionClaims};
use crate::state::SharedState;

/// Extract + verify session JWT from `Authorization: Bearer <jwt>`.
/// Used by master-gated wallet endpoints (link + links_list). The
/// recover_lookup endpoint is intentionally unauthenticated.
pub(super) fn require_master_session(
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
