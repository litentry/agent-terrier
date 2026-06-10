//! Stage 7 auth endpoints (plan §3.5).
//!
//! - `POST /v1/auth/wallet/start` — SIWE challenge.
//! - `POST /v1/auth/wallet/verify` — SIWE verify → session JWT.
//! - `POST /v1/auth/passkey/start` — master passkey re-auth challenge (#242).
//! - `POST /v1/auth/passkey/verify` — chain-verified assertion → session JWT.

#[cfg(feature = "auth-email-link")]
pub mod email_landing;
#[cfg(feature = "auth-email-link")]
pub mod email_request;
#[cfg(feature = "auth-email-link")]
pub mod email_status;
#[cfg(feature = "auth-email-link")]
pub mod email_verify;
#[cfg(feature = "auth-oauth2")]
pub mod oauth2_callback;
#[cfg(feature = "auth-oauth2")]
pub mod oauth2_start;
#[cfg(feature = "auth-oauth2")]
pub mod oauth2_status;
pub mod passkey_start;
pub mod passkey_verify;
pub mod wallet_start;
pub mod wallet_verify;

pub(super) use wallet_start::map_auth_err as wallet_start_map_auth_err;
