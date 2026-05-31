//! `actor_omni` — the durable per-actor cryptographic anchor.
//!
//! Per `docs/arch.md` §14 (credential storage v2):
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

/// Domain tag for HDKD child-omni derivation (issue #144 / arch.md §6.2).
/// Distinct from `DOMAIN` so a wallet-omni and a child-omni can never collide.
const HDKD_DOMAIN: &[u8] = b"agentkeys-hdkd-v1";

/// Validate an HDKD child label (`^[a-z0-9-]{1,32}$`). The label is spliced into
/// the child-omni digest AND stored/echoed on chain + in JWT claims, so it must
/// be a tight charset (no path separators, no whitespace, no uppercase).
pub fn validate_label(label: &str) -> anyhow::Result<()> {
    if label.is_empty() || label.len() > 32 {
        return Err(anyhow::anyhow!(
            "label must be 1..=32 chars, got {}",
            label.len()
        ));
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(anyhow::anyhow!("label must match ^[a-z0-9-]+$: {label}"));
    }
    Ok(())
}

/// HDKD child actor omni (issue #144 / arch.md §6.2):
///
/// ```text
/// O_child = SHA256(HDKD_DOMAIN || O_parent_bytes || "//" || label)
/// ```
///
/// **PUBLIC + recomputable** (decision 2): anyone holding the parent omni + label
/// can recompute the child — unforgeability comes from the master-gated
/// `/v1/agent/create` (needs `J1_master`) + the master-submitted on-chain binding,
/// NOT from a secret. The agent's K10 device key is decoupled from this omni.
/// `master_omni` is the parent's 32 raw omni bytes (NOT the hex ASCII).
pub fn child_omni(master_omni: &[u8; 32], label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HDKD_DOMAIN);
    hasher.update(master_omni);
    hasher.update(b"//");
    hasher.update(label.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// [`child_omni`] over a hex parent omni (`0x`-prefixed or not), returning the
/// child as **un-prefixed** 64-char lowercase hex — matching the `omni_account`
/// JWT claim, the `agentkeys_actor_omni` PrincipalTag, and the `bots/<hex>/...`
/// S3 prefix. Does NOT validate the label; call [`validate_label`] first.
pub fn child_omni_hex(master_omni_hex: &str, label: &str) -> anyhow::Result<String> {
    let h = master_omni_hex.trim();
    let h = h.strip_prefix("0x").unwrap_or(h);
    let bytes = hex::decode(h).map_err(|e| anyhow::anyhow!("parent omni not hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "parent omni must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut master = [0u8; 32];
    master.copy_from_slice(&bytes);
    Ok(hex::encode(child_omni(&master, label)))
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

    #[test]
    fn child_omni_pinned_known_value() {
        // Frozen vector: a drive-by edit to HDKD_DOMAIN or the input layout
        // trips this immediately. Recompute only on an intentional §6.2 change.
        let master = [0u8; 32];
        let got = child_omni(&master, "agent-a");
        let mut hasher = Sha256::new();
        hasher.update(b"agentkeys-hdkd-v1");
        hasher.update(master);
        hasher.update(b"//");
        hasher.update(b"agent-a");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(got, expected);
    }

    #[test]
    fn child_omni_hex_is_un_prefixed_64_and_prefix_agnostic() {
        let parent = "00".repeat(32);
        let c = child_omni_hex(&parent, "agent-a").unwrap();
        assert_eq!(c.len(), 64);
        assert!(!c.starts_with("0x"));
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()));
        // A 0x-prefixed parent yields the identical child.
        assert_eq!(
            c,
            child_omni_hex(&format!("0x{parent}"), "agent-a").unwrap()
        );
    }

    #[test]
    fn child_omni_distinct_per_label_and_parent() {
        let p1 = "11".repeat(32);
        let p2 = "22".repeat(32);
        assert_ne!(
            child_omni_hex(&p1, "agent-a").unwrap(),
            child_omni_hex(&p1, "agent-b").unwrap()
        );
        assert_ne!(
            child_omni_hex(&p1, "agent-a").unwrap(),
            child_omni_hex(&p2, "agent-a").unwrap()
        );
    }

    #[test]
    fn child_omni_hex_rejects_bad_parent_len() {
        assert!(child_omni_hex("0xdeadbeef", "agent-a").is_err());
    }

    #[test]
    fn validate_label_accepts_good_rejects_bad() {
        assert!(validate_label("agent-a").is_ok());
        assert!(validate_label("a1-b2-c3").is_ok());
        assert!(validate_label("").is_err());
        assert!(validate_label("Agent-A").is_err()); // uppercase
        assert!(validate_label("agent/a").is_err()); // path sep
        assert!(validate_label("agent a").is_err()); // whitespace
        assert!(validate_label(&"a".repeat(33)).is_err()); // too long
    }
}
