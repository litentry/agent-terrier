//! `actor_omni` — the durable per-actor cryptographic anchor.
//!
//! Per `docs/spec/architecture.md` §14 (credential storage v2):
//!
//! ```text
//! actor_omni = SHA256("agentkeys" || "evm" || initial_master_wallet_K3_v1)
//! ```
//!
//! Once SIWE-bound at first init, this 32-byte digest is **frozen for the
//! life of the operator** — it never rotates when K3 rotates, never changes
//! when the master wallet rotates, never changes when devices come or go.
//! It is the stable identifier used everywhere v2 keys identity off:
//!
//! - S3 path: `bots/<actor_omni_hex>/credentials/<service>.enc`
//! - AWS PrincipalTag: `agentkeys_actor_omni = <actor_omni_hex>`
//! - On-chain scope index in `ScopeContract`
//! - AEAD AAD binding in v2 envelopes
//!
//! By contrast, `current_master_wallet` rotates with K3 (it is `HKDF(K3_v[n],
//! master_omni)`), so wallet-keyed paths break on every rotation. Keying off
//! `actor_omni` makes K3 rotation a zero-migration event.
//!
//! ## v1 vs v2 helpers
//!
//! - `actor_omni_from_wallet` — the v2 derivation used by stage 1+. Output
//!   is 32 bytes (the SHA-256 digest) or lower-hex (`actor_omni_hex`) for
//!   path-shaped consumers.
//! - In v1 (today's `S3CredentialBackend`), the path keys off
//!   `lower(wallet)` directly. The migration plan (issue v2-stage-1)
//!   reads from BOTH paths during the transition, with v2 winning on
//!   conflict.

use sha2::{Digest, Sha256};

use agentkeys_types::WalletAddress;

/// Domain-tag bytes spliced before the wallet inside the SHA-256 input.
/// MUST match arch.md §14.1 / §14.4 exactly — never adjust without bumping
/// every consumer at once (S3 path, PrincipalTag, AEAD AAD, scope key).
const DOMAIN: &[u8] = b"agentkeys";
const CHAIN_LABEL: &[u8] = b"evm";

/// Compute the 32-byte `actor_omni` for an operator's initial master wallet
/// per arch.md §14.1. Wallet bytes are lowercased to match the JWT claim
/// shape and the bucket-policy PrincipalTag (`agentkeys_actor_omni` is
/// always lowercase hex).
pub fn actor_omni_from_wallet(wallet: &WalletAddress) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(CHAIN_LABEL);
    hasher.update(wallet.0.to_lowercase().as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Lower-hex (64-char) representation of `actor_omni`. This is what AWS
/// PrincipalTag carries, what S3 paths use, and what the JWT
/// `omni_account` claim serializes as.
pub fn actor_omni_hex(wallet: &WalletAddress) -> String {
    hex::encode(actor_omni_from_wallet(wallet))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_wallet() {
        let wallet = WalletAddress("0xabcDEF".into());
        let a = actor_omni_hex(&wallet);
        let b = actor_omni_hex(&wallet);
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_on_wallet_hex() {
        let upper = WalletAddress("0xAbCdEf1234567890aBcDeF1234567890aBcDeF12".into());
        let lower = WalletAddress("0xabcdef1234567890abcdef1234567890abcdef12".into());
        assert_eq!(actor_omni_hex(&upper), actor_omni_hex(&lower));
    }

    #[test]
    fn distinct_for_different_wallets() {
        let a = WalletAddress("0xaaaa".into());
        let b = WalletAddress("0xbbbb".into());
        assert_ne!(actor_omni_hex(&a), actor_omni_hex(&b));
    }

    #[test]
    fn hex_is_64_chars() {
        let wallet = WalletAddress("0xabc".into());
        let hex = actor_omni_hex(&wallet);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pinned_known_value_for_zero_wallet() {
        // Pin one known value so a future drive-by edit to the domain tag
        // immediately trips this test. Recompute only if arch.md §14.1
        // intentionally changes the derivation.
        let wallet = WalletAddress("0x0000000000000000000000000000000000000000".into());
        let hex = actor_omni_hex(&wallet);
        let expected_input = b"agentkeysevm0x0000000000000000000000000000000000000000";
        let mut hasher = Sha256::new();
        hasher.update(expected_input);
        let expected = hex::encode(hasher.finalize());
        assert_eq!(hex, expected);
    }
}
