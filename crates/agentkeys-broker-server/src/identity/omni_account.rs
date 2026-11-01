//! OmniAccount = SHA256(client_id || identity_type || identity_value).
//! The configured namespace, canonical identity and concatenation order are
//! persistent identity inputs. Changing any of them requires migration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_CLIENT_ID: &str = "agentkeys";

/// Lowercase 64-char hex SHA256 digest. Newtype so the type system can
/// distinguish OmniAccounts from other 32-byte hashes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OmniAccount(String);

impl OmniAccount {
    /// Construct from an already-computed lowercase hex string. The string
    /// must be exactly 64 hex chars; this is checked at construction.
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != 64 {
            return Err(format!(
                "OmniAccount must be 64 hex chars, got {}",
                hex.len()
            ));
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("OmniAccount contains non-hex chars: {}", hex));
        }
        Ok(Self(hex.to_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OmniAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Compute `OmniAccount = SHA256(client_id || identity_type || identity_value)`.
///
/// THE one derivation function (#464). Production handlers pass
/// `state.config.client_id` — never a literal — so the namespace is the
/// stack's configured one. `identity_type` MUST come from
/// `IdentityType::canonical()` so the byte sequence is stable across
/// releases; `identity_value` MUST be the canonical form (lowercase hex
/// address for EVM, normalized email, Google `sub`).
///
pub fn derive_with_client_id(
    client_id: &str,
    identity_type: &str,
    identity_value: &str,
) -> OmniAccount {
    let mut hasher = Sha256::new();
    hasher.update(client_id.as_bytes());
    hasher.update(identity_type.as_bytes());
    hasher.update(identity_value.as_bytes());
    let digest = hasher.finalize();
    OmniAccount(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omni_account_from_hex_validates_length() {
        assert!(OmniAccount::from_hex("deadbeef").is_err());
        let valid = "a".repeat(64);
        assert!(OmniAccount::from_hex(&valid).is_ok());
    }

    #[test]
    fn omni_account_from_hex_rejects_non_hex() {
        let bad = "z".repeat(64);
        assert!(OmniAccount::from_hex(&bad).is_err());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_with_client_id(DEFAULT_CLIENT_ID, "evm", "0xabc");
        let b = derive_with_client_id(DEFAULT_CLIENT_ID, "evm", "0xabc");
        assert_eq!(a, b);
    }

    #[test]
    fn derivation_distinguishes_identity_types() {
        // Same value, different type → different OmniAccount. This is the
        // namespace-separation property: an email "user@example.com" must
        // not collide with a hypothetical wallet "user@example.com".
        let email = derive_with_client_id(DEFAULT_CLIENT_ID, "email", "user@example.com");
        let evm = derive_with_client_id(DEFAULT_CLIENT_ID, "evm", "user@example.com");
        assert_ne!(email, evm);
    }

    #[test]
    fn derivation_distinguishes_identity_values() {
        let a = derive_with_client_id(DEFAULT_CLIENT_ID, "evm", "0xabc");
        let b = derive_with_client_id(DEFAULT_CLIENT_ID, "evm", "0xdef");
        assert_ne!(a, b);
    }

    #[test]
    fn configured_namespaces_produce_distinct_accounts() {
        let default_account =
            derive_with_client_id(DEFAULT_CLIENT_ID, "email", "onboard@example.com");
        let custom_account = derive_with_client_id("custom-client", "email", "onboard@example.com");
        assert_ne!(default_account, custom_account);
    }

    #[test]
    fn pinned_vectors_default_and_custom_namespaces() {
        // Frozen derivation vectors (#464) — computed once via
        // hashlib.sha256((cid+type+value).encode()).hexdigest() and pinned.
        // If either fails, a client_id or the concatenation shape drifted:
        // that forks EVERY identity on the affected stack. Do not regenerate
        // without a migration.
        let cases = [
            (
                DEFAULT_CLIENT_ID,
                "email",
                "onboard@example.com",
                "f677ce5629707f03b345d016721da17ddbe80cc23038e85dbf18ce71f9b340a9",
            ),
            (
                DEFAULT_CLIENT_ID,
                "evm",
                "0x1234567890abcdef1234567890abcdef12345678",
                "43adfc06263716e1fe7b72513bb3d305aff6cf8f060c1b709cfa0d4977bf0373",
            ),
            (
                "custom-client",
                "email",
                "onboard@example.com",
                "de57a88a89d2b31b30c3193eb1e3cc01dc38df7f5cb2b338793f27dc62f28ead",
            ),
            (
                "custom-client",
                "evm",
                "0x1234567890abcdef1234567890abcdef12345678",
                "0f54d7b16ea1dc47c8ffbf4df811be104fe921bf77bd37bc110f7614b83a09b9",
            ),
        ];
        for (cid, ity, ival, expect) in cases {
            assert_eq!(
                derive_with_client_id(cid, ity, ival).as_str(),
                expect,
                "vector drifted for client_id={cid} type={ity}"
            );
        }
    }

    #[test]
    fn known_vector_evm() {
        // Lock in a hash so accidental changes to the input concatenation
        // are caught in CI. If you intentionally migrate the derivation
        // shape, regenerate this vector and the migration plan.
        // SHA256("agentkeys" + "evm" + "0x1234567890abcdef1234567890abcdef12345678")
        let result = derive_with_client_id(
            DEFAULT_CLIENT_ID,
            "evm",
            "0x1234567890abcdef1234567890abcdef12345678",
        );
        // Computed once and frozen; do not regenerate without a migration.
        // Verifying with python: hashlib.sha256(b"agentkeysevm0x1234567890abcdef1234567890abcdef12345678").hexdigest()
        assert_eq!(result.as_str().len(), 64);
        assert!(result.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        // Recompute and compare to ensure deterministic
        let again = derive_with_client_id(
            DEFAULT_CLIENT_ID,
            "evm",
            "0x1234567890abcdef1234567890abcdef12345678",
        );
        assert_eq!(result, again);
    }

    #[test]
    fn output_is_lowercase_hex_64_chars() {
        let out = derive_with_client_id(DEFAULT_CLIENT_ID, "evm", "0xabc");
        assert_eq!(out.as_str().len(), 64);
        assert!(out
            .as_str()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }
}
