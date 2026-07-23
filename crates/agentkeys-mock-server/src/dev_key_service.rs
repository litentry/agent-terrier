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

/// #552 — the DELEGATE K10 derivation domain. A delegate's device key is
/// DERIVED from its `actor_omni` under this distinct info suffix, so the
/// signer custodies delegate keys with ZERO stored state and the K10 is a
/// DIFFERENT key from the same actor's K4 wallet (`HKDF_INFO_SUFFIX`) — a
/// device-key compromise can never sign wallet ops and vice-versa. Pinned:
/// changing it re-keys every signer-custodied delegate (their on-chain
/// `device_key_hash` bindings would orphan); never change without a
/// `KEY_VERSION` bump + a re-registration ceremony plan.
const DEVICE_HKDF_INFO_SUFFIX: &[u8] = b"agentkeys-k10-device";

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

    /// Issue #82 — typed-data signing rejected the EIP-712 payload before
    /// any signing happened (malformed JSON, unknown type, value out of
    /// range for declared type).
    #[error("invalid_typed_data: {0}")]
    InvalidTypedData(String),

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
            SignerError::InvalidTypedData(_) => "invalid_typed_data",
            SignerError::Internal(_) => "internal",
        }
    }

    /// HTTP status the handler should return.
    pub fn http_status(&self) -> u16 {
        match self {
            SignerError::InvalidOmniAccount(_)
            | SignerError::InvalidMessageHex(_)
            | SignerError::InvalidTypedData(_) => 400,
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
        Self::from_optional_secret_hex(std::env::var(MASTER_SECRET_ENV_VAR).ok())
    }

    /// Value half of `from_env`, split out so the unset / malformed / valid
    /// branches are testable by injection — process env is global, and
    /// `set_var`/`remove_var` in one test leaks into parallel siblings.
    fn from_optional_secret_hex(raw: Option<String>) -> Result<Option<Self>, String> {
        let raw = match raw {
            Some(s) if s.is_empty() => return Ok(None),
            Some(s) => s,
            None => return Ok(None),
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
        self.derive_signing_key_in_domain(HKDF_INFO_SUFFIX, omni_bytes)
    }

    /// Domain-parameterized derivation core: the wallet (`HKDF_INFO_SUFFIX`)
    /// and delegate-K10 (`DEVICE_HKDF_INFO_SUFFIX`, #552) domains share the
    /// retry loop but can never collide (distinct info strings).
    fn derive_signing_key_in_domain(
        &self,
        info_suffix: &[u8],
        omni_bytes: &[u8; 32],
    ) -> Result<SigningKey, SignerError> {
        const MAX_HKDF_RETRIES: u8 = 16;

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &self.master_secret);

        for retry in 0..MAX_HKDF_RETRIES {
            // Build info: [KEY_VERSION] || info_suffix || omni_bytes ||
            //             optional retry counter (only when retry > 0)
            let mut info = Vec::with_capacity(1 + info_suffix.len() + 32 + 1);
            info.push(KEY_VERSION);
            info.extend_from_slice(info_suffix);
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
            "HKDF output rejected as secp256k1 scalar after 16 retries (vanishingly rare; bug?)"
                .into(),
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
        eip191_sign_with(&sk, message_bytes)
    }

    /// #552 — derive the DELEGATE K10 EVM address for an `actor_omni`
    /// (device domain — a DIFFERENT key from the same actor's K4 wallet).
    pub fn derive_device_address(&self, actor_omni: &str) -> Result<String, SignerError> {
        let omni_bytes = parse_omni_account(actor_omni)?;
        let sk = self.derive_signing_key_in_domain(DEVICE_HKDF_INFO_SUFFIX, &omni_bytes)?;
        Ok(address_for_signing_key(&sk))
    }

    /// #552 — sign `message_bytes` under EIP-191 with the DELEGATE K10
    /// derived from `actor_omni`. Same signature semantics as
    /// [`Self::sign_eip191`], device derivation domain.
    pub fn sign_device_eip191(
        &self,
        actor_omni: &str,
        message_bytes: &[u8],
    ) -> Result<(String, String), SignerError> {
        let omni_bytes = parse_omni_account(actor_omni)?;
        let sk = self.derive_signing_key_in_domain(DEVICE_HKDF_INFO_SUFFIX, &omni_bytes)?;
        eip191_sign_with(&sk, message_bytes)
    }

    /// **DEV ONLY.** EIP-712 typed-data sign (issue #82). Returns the
    /// signature, the recovered address, and the digests the signer
    /// computed internally so the caller can cross-reference against an
    /// ERC-7730 metadata file for audit.
    ///
    /// The signer parses `typed_data` itself and computes the digest from
    /// `keccak256("\x19\x01" || domain_separator || hashStruct(primaryType,
    /// message))`. It never accepts a caller-supplied prehash — that is
    /// what makes the signer's signature a meaningful claim about *what
    /// was signed*, not just *that something was signed*.
    pub fn sign_eip712(
        &self,
        omni_account: &str,
        typed_data: agentkeys_core::clear_signing::TypedData,
    ) -> Result<Eip712SignResult, SignerError> {
        let omni_bytes = parse_omni_account(omni_account)?;
        let sk = self.derive_signing_key(&omni_bytes)?;
        let address = address_for_signing_key(&sk);

        let digests = agentkeys_core::clear_signing::compute_digests(&typed_data)
            .map_err(|e| SignerError::InvalidTypedData(e.to_string()))?;

        let (sig, recovery_id) = sk
            .sign_prehash_recoverable(&digests.final_digest)
            .map_err(|e| SignerError::Internal(format!("signing failed: {e}")))?;

        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());
        debug_assert_eq!(sig_bytes.len(), 65, "EIP-712 signature must be 65 bytes");

        Ok(Eip712SignResult {
            signature: format!("0x{}", hex::encode(&sig_bytes)),
            address,
            primary_type_hash: format!("0x{}", hex::encode(digests.primary_type_hash)),
            domain_separator: format!("0x{}", hex::encode(digests.domain_separator)),
            digest: format!("0x{}", hex::encode(digests.final_digest)),
        })
    }
}

/// Result of `sign_eip712`. Each digest is emitted alongside the signature
/// so an audit trail can cross-reference against the ERC-7730 metadata
/// file pinned to the same domain separator + primary type hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712SignResult {
    pub signature: String,
    pub address: String,
    pub primary_type_hash: String,
    pub domain_separator: String,
    pub digest: String,
}

/// Parse an `omni_account` from the wire format (64 lowercase hex chars,
/// no `0x` prefix per `signer-protocol.md`) into its raw 32 bytes. Tolerates
/// uppercase hex but rejects any other deviation.
/// EIP-191 sign `message_bytes` with `sk`:
/// keccak256("\x19Ethereum Signed Message:\n" || len || message), canonical
/// 65-byte `r || s || v` (`v ∈ {0, 1}`) as 0x-hex, plus the signer address.
/// ONE implementation for both the wallet and device (#552) domains.
fn eip191_sign_with(
    sk: &SigningKey,
    message_bytes: &[u8],
) -> Result<(String, String), SignerError> {
    let address = address_for_signing_key(sk);
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message_bytes.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message_bytes);
    let digest = hasher.finalize();

    // k256's `sign_prehash_recoverable` returns a low-s normalized signature
    // and a recovery id in {0, 1}.
    let (sig, recovery_id) = sk
        .sign_prehash_recoverable(&digest)
        .map_err(|e| SignerError::Internal(format!("signing failed: {e}")))?;

    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recovery_id.to_byte());
    debug_assert_eq!(sig_bytes.len(), 65, "EIP-191 signature must be 65 bytes");

    Ok((format!("0x{}", hex::encode(&sig_bytes)), address))
}

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
    debug_assert_eq!(
        pubkey_bytes.len(),
        65,
        "uncompressed secp256k1 pubkey is 65 bytes"
    );
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

    // `from_env` branch coverage goes through `from_optional_secret_hex`
    // (the value half) — injection instead of `set_var`/`remove_var`, so
    // the three branches are independent parallel-safe tests.

    #[test]
    fn master_secret_unset_or_empty_is_ok_none() {
        assert!(matches!(
            DevKeyService::from_optional_secret_hex(None),
            Ok(None)
        ));
        assert!(matches!(
            DevKeyService::from_optional_secret_hex(Some(String::new())),
            Ok(None)
        ));
    }

    #[test]
    fn master_secret_malformed_is_err() {
        // Too short (8 bytes, not 32).
        assert!(DevKeyService::from_optional_secret_hex(Some("deadbeef".into())).is_err());
        // Not hex at all.
        assert!(DevKeyService::from_optional_secret_hex(Some("zz".repeat(32))).is_err());
    }

    #[test]
    fn master_secret_valid_hex_constructs_signer() {
        let svc = DevKeyService::from_optional_secret_hex(Some("00".repeat(32)))
            .unwrap()
            .unwrap();
        let _ = svc.derive_address(&fixed_omni()).unwrap();
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
        assert_eq!(
            SignerError::InvalidTypedData("x".into()).code(),
            "invalid_typed_data"
        );
        assert_eq!(SignerError::Internal("x".into()).code(), "internal");
    }

    /// Issue #82 — typed-data sign produces a signature that recovers to
    /// the same address `derive_address` returns, AND emits the EIP-712
    /// digests in the result envelope.
    #[test]
    fn sign_eip712_recovers_to_derived_address() {
        use agentkeys_core::clear_signing::{TypeField, TypedData};
        use std::collections::BTreeMap;

        let s = fixed_signer();
        let omni = fixed_omni();
        let derived = s.derive_address(&omni).unwrap();

        let mut types: BTreeMap<String, Vec<TypeField>> = BTreeMap::new();
        types.insert(
            "EIP712Domain".into(),
            vec![
                TypeField {
                    name: "name".into(),
                    ty: "string".into(),
                },
                TypeField {
                    name: "version".into(),
                    ty: "string".into(),
                },
                TypeField {
                    name: "chainId".into(),
                    ty: "uint256".into(),
                },
                TypeField {
                    name: "verifyingContract".into(),
                    ty: "address".into(),
                },
            ],
        );
        types.insert(
            "Permit".into(),
            vec![
                TypeField {
                    name: "owner".into(),
                    ty: "address".into(),
                },
                TypeField {
                    name: "spender".into(),
                    ty: "address".into(),
                },
                TypeField {
                    name: "value".into(),
                    ty: "uint256".into(),
                },
                TypeField {
                    name: "nonce".into(),
                    ty: "uint256".into(),
                },
                TypeField {
                    name: "deadline".into(),
                    ty: "uint256".into(),
                },
            ],
        );
        let td = TypedData {
            types,
            primary_type: "Permit".into(),
            domain: serde_json::json!({
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            }),
            message: serde_json::json!({
                "owner":   "0x1111111111111111111111111111111111111111",
                "spender": "0xaaaabbbbccccddddeeeeffff0000111122223333",
                "value":   "1500000",
                "nonce":   "0",
                "deadline": "1900000000",
            }),
        };

        let result = s.sign_eip712(&omni, td).unwrap();
        assert_eq!(result.address, derived);
        assert!(result.signature.starts_with("0x"));
        assert_eq!(result.signature.len(), 2 + 130);
        assert!(result.digest.starts_with("0x"));
        assert_eq!(result.digest.len(), 2 + 64);

        // Cross-check signature recovers to derived addr via the spec digest.
        let raw = hex::decode(result.signature.trim_start_matches("0x")).unwrap();
        let recovery_id = RecoveryId::try_from(raw[64]).unwrap();
        let signature = Signature::from_slice(&raw[..64]).unwrap();
        let digest_bytes = hex::decode(result.digest.trim_start_matches("0x")).unwrap();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_bytes);
        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
        let encoded_point = vk.to_encoded_point(false);
        let pubkey_bytes = encoded_point.as_bytes();
        let mut h = Keccak256::new();
        h.update(&pubkey_bytes[1..]);
        let pubkey_hash = h.finalize();
        let recovered = format!("0x{}", hex::encode(&pubkey_hash[12..]));
        assert_eq!(recovered, derived);
    }

    #[test]
    fn sign_eip712_rejects_malformed_typed_data() {
        use agentkeys_core::clear_signing::TypedData;
        use std::collections::BTreeMap;

        let s = fixed_signer();
        // Missing EIP712Domain in types → invalid_typed_data.
        let td = TypedData {
            types: BTreeMap::new(),
            primary_type: "Permit".into(),
            domain: serde_json::json!({}),
            message: serde_json::json!({}),
        };
        let err = s.sign_eip712(&fixed_omni(), td).unwrap_err();
        assert!(matches!(err, SignerError::InvalidTypedData(_)));
    }
}

#[cfg(test)]
mod device_domain_tests {
    use super::*;
    use agentkeys_core::device_crypto::{agent_pop_payload, device_key_hash, ecrecover_eip191};

    fn signer() -> DevKeyService {
        DevKeyService::from_master_secret([0x42; 32])
    }

    #[test]
    fn device_domain_is_separated_from_the_wallet_domain() {
        // #552 — the SAME actor_omni yields DIFFERENT keys in the two
        // domains: a delegate K10 compromise can never sign wallet ops.
        let omni = "ab".repeat(32);
        let wallet = signer().derive_address(&omni).unwrap();
        let device = signer().derive_device_address(&omni).unwrap();
        assert_ne!(wallet, device);
        // Deterministic: same omni → same device address, every time.
        assert_eq!(device, signer().derive_device_address(&omni).unwrap());
        // Distinct omnis → distinct device keys.
        assert_ne!(
            device,
            signer().derive_device_address(&"cd".repeat(32)).unwrap()
        );
    }

    #[test]
    fn device_pop_sig_recovers_to_the_derived_address() {
        // End-to-end shape the #427 spawn-build consumes: the pop over the
        // canonical agent-pop payload must ecrecover to the derived address
        // (what `parse_register_and_grant` + the chain contract verify).
        let omni = "ab".repeat(32);
        let s = signer();
        let address = s.derive_device_address(&omni).unwrap();
        let dkh = device_key_hash(&address).unwrap();
        let (sig, sig_addr) = s
            .sign_device_eip191(&omni, &agent_pop_payload(&dkh))
            .unwrap();
        assert_eq!(sig_addr, address);
        let recovered = ecrecover_eip191(&agent_pop_payload(&dkh), &sig).unwrap();
        assert_eq!(recovered.to_lowercase(), address.to_lowercase());
    }
}
