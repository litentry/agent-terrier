//! ============================================================================
//! DEV ONLY — REPLACE WITH TEE WORKER (issue #74 step 2)
//! ============================================================================
//!
//! HKDF-backed signer for development and CI. The master secret lives in a
//! plain environment variable, which is fine for local dev and the demo
//! deployment but is unacceptable for any environment where compromise of
//! the host shell environment would be a security incident.
//!
//! Production deployments MUST replace this module with a TEE-backed
//! signer (issue #74 step 2). The wire shape is locked by
//! `docs/spec/signer-protocol.md` so the swap is mechanical.
//!
//! What this module does:
//! 1. Loads a 32-byte master secret from `DEV_KEY_SERVICE_MASTER_SECRET`
//!    (hex). Refuses to enable if the env var is unset or malformed.
//! 2. Derives a deterministic secp256k1 keypair from `omni_account` via
//!    HKDF-SHA256 using a versioned info string
//!    (`[key_version_byte] || "agentkeys-evm-wallet" || omni_bytes`).
//! 3. Computes the EVM address from the derived public key (keccak256 of
//!    uncompressed pubkey, last 20 bytes, lowercase hex).
//! 4. Signs arbitrary byte messages under the EIP-191 envelope and returns
//!    the canonical 65-byte `r || s || v` signature with `v ∈ {0, 1}`.
//!
//! The signing key is never persisted, never logged, never returned over
//! the wire. The address and signatures are the only externally visible
//! products.
//!
//! See `docs/spec/signer-protocol.md` for the v0 wire contract.

use hkdf::Hkdf;
use k256::ecdsa::SigningKey;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

/// Stable salt input to the HKDF extract step. Pinning the salt locks the
/// derivation domain to "agentkeys signer v0" — distinct from any other
/// HKDF use of the same master secret in any unrelated AgentKeys subsystem.
const HKDF_SALT: &[u8] = b"agentkeys-signer-v0";

/// Info-string suffix appended after the version byte. Pinning this keeps
/// the v0 derivation domain stable; never change without a `KEY_VERSION`
/// bump.
const HKDF_INFO_SUFFIX: &[u8] = b"agentkeys-evm-wallet";

/// Current key-derivation version. Future master-secret rotation bumps this
/// byte; producing a different address from the same omni_account while
/// keeping the wire shape identical. Reserved range:
/// * `0x01..=0x7f` for production rotations
/// * `0x80..=0xff` for staging / testing
pub const KEY_VERSION: u8 = 0x01;

/// Required env var name. Production builds (when the TEE worker exists)
/// MUST refuse to honor this env var; the TEE worker has its own sealed
/// secret and ignores it.
pub const MASTER_SECRET_ENV_VAR: &str = "DEV_KEY_SERVICE_MASTER_SECRET";

/// Errors that the signer can surface to the HTTP layer.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("invalid_omni_account: {0}")]
    InvalidOmniAccount(String),

    #[error("invalid_message_hex: {0}")]
    InvalidMessageHex(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl SignerError {
    /// Stable machine-readable code, matching `signer-protocol.md`'s error
    /// envelope.
    pub fn code(&self) -> &'static str {
        match self {
            SignerError::InvalidOmniAccount(_) => "invalid_omni_account",
            SignerError::InvalidMessageHex(_) => "invalid_message_hex",
            SignerError::Internal(_) => "internal",
        }
    }

    /// HTTP status the handler should return.
    pub fn http_status(&self) -> u16 {
        match self {
            SignerError::InvalidOmniAccount(_) | SignerError::InvalidMessageHex(_) => 400,
            SignerError::Internal(_) => 500,
        }
    }
}

/// HKDF-backed dev signer. **DEV ONLY.**
///
/// Holds the 32-byte master secret in process memory. Construct one per
/// process at boot via `DevKeyService::from_env()` and share it through
/// `Arc` if multiple call sites need it.
pub struct DevKeyService {
    master_secret: [u8; 32],
}

impl DevKeyService {
    /// **DEV ONLY.** Load the master secret from
    /// `DEV_KEY_SERVICE_MASTER_SECRET` (hex). Returns `Ok(None)` if the env
    /// var is unset (callers translate this to 503 `signer_disabled` per
    /// the wire contract). Returns `Err` if the env var is set but
    /// malformed (wrong length, non-hex) — that is an operator error and
    /// should fail the boot, not silently disable the signer.
    pub fn from_env() -> Result<Option<Self>, String> {
        let raw = match std::env::var(MASTER_SECRET_ENV_VAR) {
            Ok(s) if s.is_empty() => return Ok(None),
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let bytes = hex::decode(raw.trim_start_matches("0x"))
            .map_err(|e| format!("{MASTER_SECRET_ENV_VAR} is not valid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "{MASTER_SECRET_ENV_VAR} must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut master_secret = [0u8; 32];
        master_secret.copy_from_slice(&bytes);
        Ok(Some(Self { master_secret }))
    }

    /// **DEV ONLY.** Construct directly from a 32-byte master secret (used
    /// by tests; production must go through `from_env()`).
    pub fn from_master_secret(master_secret: [u8; 32]) -> Self {
        Self { master_secret }
    }

    /// **DEV ONLY.** Derive the secp256k1 signing key for an `omni_account`
    /// per the v0 derivation rule:
    ///   `HKDF-SHA256(ikm=master_secret, salt="agentkeys-signer-v0",
    ///                info=[KEY_VERSION] || "agentkeys-evm-wallet" || omni_bytes,
    ///                okm=32)`.
    ///
    /// On the vanishingly rare chance the 32-byte HKDF output is rejected
    /// by `secp256k1::SecretKey::from_slice` (probability ≈ 2⁻¹²⁸), we
    /// extend the HKDF output with an additional byte and try again, up to
    /// `MAX_HKDF_RETRIES` times. In practice this never fires.
    fn derive_signing_key(&self, omni_bytes: &[u8; 32]) -> Result<SigningKey, SignerError> {
        const MAX_HKDF_RETRIES: u8 = 16;

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &self.master_secret);

        for retry in 0..MAX_HKDF_RETRIES {
            // Build info: [KEY_VERSION] || "agentkeys-evm-wallet" || omni_bytes ||
            //             optional retry counter (only when retry > 0)
            let mut info = Vec::with_capacity(1 + HKDF_INFO_SUFFIX.len() + 32 + 1);
            info.push(KEY_VERSION);
            info.extend_from_slice(HKDF_INFO_SUFFIX);
            info.extend_from_slice(omni_bytes);
            if retry > 0 {
                info.push(retry);
            }

            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm)
                .map_err(|e| SignerError::Internal(format!("HKDF expand failed: {e}")))?;

            match SigningKey::from_slice(&okm) {
                Ok(sk) => return Ok(sk),
                Err(_) => continue,
            }
        }

        Err(SignerError::Internal(
            "HKDF output rejected as secp256k1 scalar after 16 retries (vanishingly rare; bug?)".into(),
        ))
    }

    /// **DEV ONLY.** Derive the EVM address (lowercase hex,
    /// `0x` + 40 chars) for an `omni_account`.
    pub fn derive_address(&self, omni_account: &str) -> Result<String, SignerError> {
        let omni_bytes = parse_omni_account(omni_account)?;
        let sk = self.derive_signing_key(&omni_bytes)?;
        Ok(address_for_signing_key(&sk))
    }

    /// **DEV ONLY.** Sign `message_bytes` under EIP-191 with the keypair
    /// derived from `omni_account`. Returns the canonical 65-byte signature
    /// (`r || s || v`, `v ∈ {0, 1}`) as a 0x-prefixed lowercase hex string,
    /// alongside the address that the signature recovers to.
    pub fn sign_eip191(
        &self,
        omni_account: &str,
        message_bytes: &[u8],
    ) -> Result<(String, String), SignerError> {
        let omni_bytes = parse_omni_account(omni_account)?;
        let sk = self.derive_signing_key(&omni_bytes)?;
        let address = address_for_signing_key(&sk);

        // EIP-191: keccak256("\x19Ethereum Signed Message:\n" || len || message).
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message_bytes.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message_bytes);
        let digest = hasher.finalize();

        // Sign and recover the recovery id. k256's
        // `sign_prehash_recoverable` returns a low-s normalized signature
        // and a recovery id in {0, 1}.
        let (sig, recovery_id) = sk
            .sign_prehash_recoverable(&digest)
            .map_err(|e| SignerError::Internal(format!("signing failed: {e}")))?;

        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());
        debug_assert_eq!(sig_bytes.len(), 65, "EIP-191 signature must be 65 bytes");

        let signature_hex = format!("0x{}", hex::encode(&sig_bytes));
        Ok((signature_hex, address))
    }
}

/// Parse an `omni_account` from the wire format (64 lowercase hex chars,
/// no `0x` prefix per `signer-protocol.md`) into its raw 32 bytes. Tolerates
/// uppercase hex but rejects any other deviation.
fn parse_omni_account(omni_account: &str) -> Result<[u8; 32], SignerError> {
    if omni_account.len() != 64 {
        return Err(SignerError::InvalidOmniAccount(format!(
            "must be 64 hex chars, got {}",
            omni_account.len()
        )));
    }
    let bytes = hex::decode(omni_account)
        .map_err(|e| SignerError::InvalidOmniAccount(format!("not valid hex: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// EVM address from a secp256k1 verifying key: keccak256 of the
/// uncompressed public key (skipping the leading 0x04 marker), take the
/// last 20 bytes, return `0x` + 40 lowercase hex chars.
fn address_for_signing_key(sk: &SigningKey) -> String {
    let vk = sk.verifying_key();
    let encoded_point = vk.to_encoded_point(false);
    let pubkey_bytes = encoded_point.as_bytes();
    debug_assert_eq!(pubkey_bytes.len(), 65, "uncompressed secp256k1 pubkey is 65 bytes");
    debug_assert_eq!(pubkey_bytes[0], 0x04, "uncompressed marker");

    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]);
    let pubkey_hash = hasher.finalize();
    format!("0x{}", hex::encode(&pubkey_hash[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    fn fixed_master_secret() -> [u8; 32] {
        // Deterministic test fixture; do NOT use this in any environment.
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    fn fixed_signer() -> DevKeyService {
        DevKeyService::from_master_secret(fixed_master_secret())
    }

    fn fixed_omni() -> String {
        // 64 hex chars, all 0xab.
        "ab".repeat(32)
    }

    #[test]
    fn derive_address_is_deterministic() {
        let s = fixed_signer();
        let a1 = s.derive_address(&fixed_omni()).unwrap();
        let a2 = s.derive_address(&fixed_omni()).unwrap();
        assert_eq!(a1, a2);
        assert!(a1.starts_with("0x"));
        assert_eq!(a1.len(), 42);
        // lowercase
        assert_eq!(a1, a1.to_lowercase());
    }

    #[test]
    fn different_omni_yields_different_address() {
        let s = fixed_signer();
        let a = s.derive_address(&fixed_omni()).unwrap();
        let b = s.derive_address(&"cd".repeat(32)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_master_secret_yields_different_address() {
        let s1 = DevKeyService::from_master_secret([0x11; 32]);
        let s2 = DevKeyService::from_master_secret([0x22; 32]);
        let a1 = s1.derive_address(&fixed_omni()).unwrap();
        let a2 = s2.derive_address(&fixed_omni()).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn rejects_short_omni() {
        let s = fixed_signer();
        let res = s.derive_address("deadbeef");
        assert!(matches!(res, Err(SignerError::InvalidOmniAccount(_))));
    }

    #[test]
    fn rejects_non_hex_omni() {
        let s = fixed_signer();
        let res = s.derive_address(&"z".repeat(64));
        assert!(matches!(res, Err(SignerError::InvalidOmniAccount(_))));
    }

    #[test]
    fn sign_address_matches_derive_address() {
        let s = fixed_signer();
        let omni = fixed_omni();
        let derived = s.derive_address(&omni).unwrap();
        let (_sig, signed_addr) = s.sign_eip191(&omni, b"hello").unwrap();
        assert_eq!(derived, signed_addr);
    }

    #[test]
    fn signature_is_65_bytes_canonical_v() {
        let s = fixed_signer();
        let (sig_hex, _addr) = s.sign_eip191(&fixed_omni(), b"hello").unwrap();
        assert!(sig_hex.starts_with("0x"));
        let raw = hex::decode(sig_hex.trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 65);
        // canonical v ∈ {0, 1}
        assert!(raw[64] == 0 || raw[64] == 1, "v byte = {}", raw[64]);
    }

    #[test]
    fn signature_recovers_to_derived_address() {
        let s = fixed_signer();
        let omni = fixed_omni();
        let message = b"siwe-test-message";
        let (sig_hex, derived_addr) = s.sign_eip191(&omni, message).unwrap();

        // Reproduce the broker's ecrecover path.
        let raw = hex::decode(sig_hex.trim_start_matches("0x")).unwrap();
        let recovery_id = RecoveryId::try_from(raw[64]).unwrap();
        let signature = Signature::from_slice(&raw[..64]).unwrap();

        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message);
        let digest = h.finalize();

        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
        let encoded_point = vk.to_encoded_point(false);
        let pubkey_bytes = encoded_point.as_bytes();
        let mut h2 = Keccak256::new();
        h2.update(&pubkey_bytes[1..]);
        let pubkey_hash = h2.finalize();
        let recovered = format!("0x{}", hex::encode(&pubkey_hash[12..]));

        assert_eq!(recovered, derived_addr);
    }

    /// Combined serial test for `from_env`. Tests that mutate process-global
    /// env vars cannot run in parallel — a sibling test inside the same
    /// binary would observe the wrong state. We sequence all three branches
    /// (unset, malformed, valid) inside a single test and use a process-wide
    /// `Mutex` to serialize against any future `from_env` call sites.
    #[test]
    fn from_env_unset_then_invalid_then_valid() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        let prev = std::env::var(MASTER_SECRET_ENV_VAR).ok();

        // Branch 1: unset → Ok(None).
        std::env::remove_var(MASTER_SECRET_ENV_VAR);
        assert!(matches!(DevKeyService::from_env(), Ok(None)));

        // Branch 2: malformed (too short hex) → Err.
        std::env::set_var(MASTER_SECRET_ENV_VAR, "deadbeef");
        assert!(DevKeyService::from_env().is_err());

        // Branch 3: valid 32-byte hex → Ok(Some(svc)) and derive succeeds.
        std::env::set_var(MASTER_SECRET_ENV_VAR, "00".repeat(32));
        let svc = DevKeyService::from_env().unwrap().unwrap();
        let _ = svc.derive_address(&fixed_omni()).unwrap();

        // Restore prior env state.
        match prev {
            Some(p) => std::env::set_var(MASTER_SECRET_ENV_VAR, p),
            None => std::env::remove_var(MASTER_SECRET_ENV_VAR),
        }
    }

    #[test]
    fn signer_error_codes_match_protocol() {
        assert_eq!(
            SignerError::InvalidOmniAccount("x".into()).code(),
            "invalid_omni_account"
        );
        assert_eq!(
            SignerError::InvalidMessageHex("x".into()).code(),
            "invalid_message_hex"
        );
        assert_eq!(SignerError::Internal("x".into()).code(), "internal");
    }
}
