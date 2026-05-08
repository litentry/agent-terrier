//! `WalletProvisioner` trait — the wallet layer of the pluggable broker.
//!
//! For v0 the only enabled provisioner is `ClientSideKeystore` (broker only
//! stores `(omni_account, address, role)`; the user holds the seed in their
//! OS keychain). Future provisioners may include SmartContractAa,
//! HeimaTeeProvisioner, or AwsNitro. See plan §3.5.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::auth::VerifiedIdentity;
use super::Readiness;

#[cfg(feature = "wallet-keystore")]
pub mod keystore;

#[cfg(feature = "wallet-keystore")]
pub use keystore::ClientSideKeystoreProvisioner;

/// EVM-style wallet address (0x-prefixed lowercase hex).
///
/// Newtype so the type system can distinguish between addresses and other
/// hex strings, and so we can centralize normalization (lowercase, length
/// check) in one place.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WalletAddress(String);

impl WalletAddress {
    /// Construct from a 0x-prefixed hex string. Normalizes to lowercase.
    /// Returns an error if the string is not a 42-char `0x[0-9a-fA-F]{40}`.
    pub fn parse(s: &str) -> Result<Self, WalletError> {
        if s.len() != 42 || !s.starts_with("0x") {
            return Err(WalletError::InvalidAddress(s.to_string()));
        }
        if !s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WalletError::InvalidAddress(s.to_string()));
        }
        Ok(Self(s.to_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WalletAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Role of a wallet binding within the master/daemon model.
///
/// A `Master` wallet authorizes capability grants; a `Daemon` wallet
/// consumes them. Recovery (Phase B) re-binds a daemon to a new address
/// after master sign-off.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WalletRole {
    Master,
    Daemon,
}

impl WalletRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Master => "master",
            Self::Daemon => "daemon",
        }
    }

    pub fn parse(s: &str) -> Result<Self, WalletError> {
        match s {
            "master" => Ok(Self::Master),
            "daemon" => Ok(Self::Daemon),
            _ => Err(WalletError::InvalidRole(s.to_string())),
        }
    }
}

/// A wallet binding row stored by the wallet provisioner.
///
/// `parent_address` is `Some` only for daemons, naming the master wallet
/// that authorized the daemon's existence (via a capability grant in
/// Phase B).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletBinding {
    pub omni_account: String,
    pub address: WalletAddress,
    pub role: WalletRole,
    pub parent_address: Option<WalletAddress>,
    pub created_at: u64,
}

/// Errors a wallet provisioner may return.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid role: {0}")]
    InvalidRole(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("not found")]
    NotFound,
    #[error("internal: {0}")]
    Internal(String),
}

#[async_trait]
pub trait WalletProvisioner: Send + Sync {
    /// Stable kebab-case name. E.g. `"client_keystore"`.
    fn name(&self) -> &'static str;

    /// Operational state. **MUST NOT default to `Ready`** — implementations
    /// verify their backing store is reachable.
    fn ready(&self) -> Readiness;

    /// Bind a wallet address to a verified identity.
    ///
    /// Idempotent: re-binding the same `(omni_account, address, role)`
    /// returns the existing row. A different role for the same address
    /// returns `WalletError::Storage("role mismatch")`.
    async fn bind_address(
        &self,
        identity: &VerifiedIdentity,
        omni_account: &str,
        address: WalletAddress,
        role: WalletRole,
        parent_address: Option<WalletAddress>,
    ) -> Result<WalletBinding, WalletError>;

    /// Look up all wallet bindings for an OmniAccount. Used by the mint
    /// endpoint to verify the per-call daemon signature came from a wallet
    /// the verified identity actually owns.
    async fn lookup_by_omni_account(
        &self,
        omni_account: &str,
    ) -> Result<Vec<WalletBinding>, WalletError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_address_parse_normalizes_to_lowercase() {
        let a = WalletAddress::parse("0xABCDef0123456789abcdef0123456789ABCDef00").unwrap();
        assert_eq!(a.as_str(), "0xabcdef0123456789abcdef0123456789abcdef00");
    }

    #[test]
    fn wallet_address_parse_rejects_bad_input() {
        assert!(WalletAddress::parse("0xshort").is_err());
        assert!(WalletAddress::parse("nopre0123456789abcdef0123456789abcdef0123").is_err());
        assert!(WalletAddress::parse("0xZZZZef0123456789abcdef0123456789abcdef00").is_err());
    }

    #[test]
    fn wallet_role_round_trip() {
        assert_eq!(WalletRole::parse("master").unwrap(), WalletRole::Master);
        assert_eq!(WalletRole::parse("daemon").unwrap(), WalletRole::Daemon);
        assert!(WalletRole::parse("nonsense").is_err());
        assert_eq!(WalletRole::Master.as_str(), "master");
    }
}
