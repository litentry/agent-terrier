//! SQLite-backed storage modules for the pluggable broker.
//!
//! Each submodule owns one table. Schema lives co-located with the
//! reader/writer code. Phase 0 ships the wallets table; auth_nonces
//! lands in US-006, email_tokens in Phase A.1, oauth_pending in Phase
//! A.2, grants + identity_links in Phase B.

pub mod auth_nonces;
// `email_rate_limits` is bucket-id-generic — reused by both EmailLink
// (Phase A.1) and OAuth2 (Phase A.2). Compiled in when either feature
// is enabled. V0.1-FOLLOWUPS: rename to `rate_limits` to drop the
// historical email-only association.
#[cfg(any(feature = "auth-email-link", feature = "auth-oauth2"))]
pub mod email_rate_limits;
#[cfg(feature = "auth-email-link")]
pub mod email_tokens;
pub mod grants;
pub mod identity_links;
// Issue #144 — §10.2 agent-initiated pairing requests + pending-binding records
// (method A). Unconditional (the agent bootstrap is core, not feature-gated).
#[cfg(feature = "auth-oauth2")]
pub mod oauth_pending;
pub mod pairing_requests;
#[cfg(any(feature = "auth-email-link", feature = "auth-oauth2"))]
pub mod rate_limit_mints;
pub mod wallets;

pub use auth_nonces::{AuthNonceStore, ConsumeOutcome};
#[cfg(any(feature = "auth-email-link", feature = "auth-oauth2"))]
pub use email_rate_limits::{EmailRateLimitStore, RateLimitOutcome};
#[cfg(feature = "auth-email-link")]
pub use email_tokens::{EmailConsumeOutcome, EmailRequestStatus, EmailTokenStore};
pub use grants::{Grant, GrantConsumeOutcome, GrantStore};
pub use identity_links::{IdentityLink, IdentityLinkStore};
#[cfg(feature = "auth-oauth2")]
pub use oauth_pending::{OAuth2PendingConsume, OAuth2PendingStatus, OAuth2PendingStore};
pub use pairing_requests::{
    PairingClaim, PairingPoll, PairingRequestStore, PendingBinding, PAIRING_REQUEST_TTL_SECONDS,
};
#[cfg(any(feature = "auth-email-link", feature = "auth-oauth2"))]
pub use rate_limit_mints::MintRateLimiter;
pub use wallets::WalletStore;
