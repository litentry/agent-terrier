//! `UserAuthMethod` trait — re-exported as the parent module.
//!
//! NOTE: this file replaces what used to be `plugins/auth.rs` so we can host
//! per-method implementations as submodules (`wallet_sig`, `email_link`,
//! `oauth2`). The trait + supporting types are unchanged from the
//! pre-restructure file.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::Readiness;

#[cfg(feature = "auth-email-link")]
pub mod email_link;
#[cfg(feature = "auth-oauth2")]
pub mod oauth2;
#[cfg(feature = "auth-wallet-sig")]
pub mod wallet_sig;

#[cfg(feature = "auth-email-link")]
pub use email_link::{EmailLinkAuth, EmailSendError, EmailSender, SesVerifyCache, StubEmailSender};
#[cfg(feature = "auth-oauth2")]
pub use oauth2::{
    OAuth2Auth, OAuth2Error, OAuth2Provider, StubOAuth2Provider, TokenExchangeOutcome,
    VerifiedIdToken,
};
#[cfg(feature = "auth-wallet-sig")]
pub use wallet_sig::SiweWalletAuth;

/// Stable, machine-readable label for the kind of identity an auth method
/// proves control of. Used as one of the SHA256 inputs for OmniAccount
/// derivation, so renaming is a breaking change for stored OmniAccounts.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    Evm,
    Email,
    OAuth2Google,
    OAuth2Github,
    OAuth2Apple,
}

impl IdentityType {
    pub fn canonical(&self) -> &'static str {
        match self {
            IdentityType::Evm => "evm",
            IdentityType::Email => "email",
            IdentityType::OAuth2Google => "oauth2_google",
            IdentityType::OAuth2Github => "oauth2_github",
            IdentityType::OAuth2Apple => "oauth2_apple",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub identity_type: IdentityType,
    pub identity_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeParams {
    pub source_ip: Option<String>,
    pub extras: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub request_id: String,
    pub expires_in_seconds: u64,
    pub extras: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub request_id: String,
    pub extras: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("expired: {0}")]
    Expired(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[async_trait]
pub trait UserAuthMethod: Send + Sync {
    fn name(&self) -> &'static str;
    fn ready(&self) -> Readiness;
    async fn challenge(&self, params: ChallengeParams) -> Result<AuthChallenge, AuthError>;
    async fn verify(&self, response: AuthResponse) -> Result<VerifiedIdentity, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_type_canonical_strings_are_stable() {
        assert_eq!(IdentityType::Evm.canonical(), "evm");
        assert_eq!(IdentityType::Email.canonical(), "email");
        assert_eq!(IdentityType::OAuth2Google.canonical(), "oauth2_google");
        assert_eq!(IdentityType::OAuth2Github.canonical(), "oauth2_github");
        assert_eq!(IdentityType::OAuth2Apple.canonical(), "oauth2_apple");
    }
}
