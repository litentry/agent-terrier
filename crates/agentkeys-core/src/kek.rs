//! Signer-anchored per-actor KEK derivation — the ONE implementation
//! (#372 item 2 / #91 stage 2).
//!
//! The vault has always derived its AES-256 KEK by asking the signer to
//! EIP-191-sign a deterministic domain-tagged message and hashing the
//! signature (`s3_backend.rs::derive_kek`); the config data class now uses
//! the same construction client-side (daemon `ui_bridge`), so the derivation
//! lives here instead of being re-typed per caller:
//!
//!   msg = "agentkeys.kek.v1:<identity_lowercase>:<service>"
//!   sig = signer.sign_eip191(omni_account, msg)     // RFC 6979 → deterministic
//!   kek = SHA-256("agentkeys.kek-derive.v1" || sig)  // 32 bytes = AES-256 key
//!
//! The signer holds the K3 keys; neither the KEK nor the signing key ever
//! touches disk or the storage plane — an admin holding ciphertext + every
//! worker env still cannot decrypt (arch.md §17.5 / §22b.2).
//!
//! Identity segment per caller:
//! - vault (creds): the lowercase master WALLET address (`0x…`) — unchanged
//!   bytes vs the pre-refactor `derive_kek`, so every existing vault blob
//!   keeps its KEK.
//! - config (v3 envelopes): the lowercase `0x`-prefixed ACTOR omni — the
//!   same identity the S3 key + AAD bind.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::signer_client::{SignerClient, SignerClientError};

/// Domain tag prefixed to the signed message.
pub const KEK_DOMAIN_TAG: &str = "agentkeys.kek.v1";
/// Domain tag prefixed to the signature before hashing into the KEK.
pub const KEK_DERIVE_TAG: &[u8] = b"agentkeys.kek-derive.v1";

#[derive(Debug, Error)]
pub enum KekDeriveError {
    #[error("signer: {0}")]
    Signer(#[from] SignerClientError),
    #[error("signer returned invalid hex signature: {0}")]
    InvalidSignatureHex(String),
    #[error("signer returned {0}-byte signature, expected 65")]
    BadSignatureLength(usize),
}

/// Derive the 32-byte AES-256 KEK for `(identity, service)` via the signer.
///
/// `omni_account` selects the signer-held key; `identity` is the caller's
/// lowercase identity segment (see module docs). secp256k1 RFC 6979 makes the
/// signature — and therefore the KEK — deterministic across calls.
pub async fn derive_kek_via_signer(
    signer: &dyn SignerClient,
    omni_account: &str,
    identity: &str,
    service: &str,
) -> Result<[u8; 32], KekDeriveError> {
    let msg = format!("{KEK_DOMAIN_TAG}:{identity}:{service}");
    let signed = signer.sign_eip191(omni_account, msg.as_bytes()).await?;

    // signed.signature is "0x" + 130 hex chars (65 bytes: r || s || v).
    let sig_hex = signed.signature.trim_start_matches("0x");
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| KekDeriveError::InvalidSignatureHex(e.to_string()))?;
    if sig_bytes.len() != 65 {
        return Err(KekDeriveError::BadSignatureLength(sig_bytes.len()));
    }

    let mut hasher = Sha256::new();
    hasher.update(KEK_DERIVE_TAG);
    hasher.update(&sig_bytes);
    let out = hasher.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&out);
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clear_signing::TypedData;
    use crate::signer_client::{DerivedAddress, SignedMessage, SignedTypedData, SignerClient};
    use async_trait::async_trait;

    /// Mock signer producing a 65-byte "signature" deterministically from
    /// (omni, message) — mirrors RFC 6979 determinism without secp256k1.
    /// `sig` overrides the signature when set (malformed-signature tests).
    struct MockSigner {
        sig: Option<String>,
    }

    #[async_trait]
    impl SignerClient for MockSigner {
        async fn derive_address(
            &self,
            _omni_account: &str,
        ) -> Result<DerivedAddress, SignerClientError> {
            unimplemented!("not used by KEK derivation")
        }

        async fn sign_eip191(
            &self,
            omni_account: &str,
            message_bytes: &[u8],
        ) -> Result<SignedMessage, SignerClientError> {
            if let Some(s) = &self.sig {
                return Ok(SignedMessage {
                    signature: s.clone(),
                    address: "0x0".into(),
                    key_version: 1,
                });
            }
            let mut h = Sha256::new();
            h.update(omni_account.as_bytes());
            h.update(message_bytes);
            let d = h.finalize();
            let mut sig = Vec::with_capacity(65);
            sig.extend_from_slice(&d);
            sig.extend_from_slice(&d);
            sig.push(0x1b);
            Ok(SignedMessage {
                signature: format!("0x{}", hex::encode(sig)),
                address: "0x0".into(),
                key_version: 1,
            })
        }

        async fn sign_eip712(
            &self,
            _omni_account: &str,
            _typed_data: &TypedData,
        ) -> Result<SignedTypedData, SignerClientError> {
            unimplemented!("not used by KEK derivation")
        }
    }

    #[tokio::test]
    async fn derivation_is_deterministic_per_identity_and_service() {
        let s = MockSigner { sig: None };
        let a = derive_kek_via_signer(&s, "aa", "0xabc", "svc")
            .await
            .unwrap();
        let b = derive_kek_via_signer(&s, "aa", "0xabc", "svc")
            .await
            .unwrap();
        assert_eq!(a, b, "same inputs must derive the same KEK (RFC 6979)");
        let c = derive_kek_via_signer(&s, "aa", "0xabc", "other")
            .await
            .unwrap();
        assert_ne!(a, c, "different service must derive a different KEK");
        let d = derive_kek_via_signer(&s, "aa", "0xdef", "svc")
            .await
            .unwrap();
        assert_ne!(a, d, "different identity must derive a different KEK");
    }

    #[tokio::test]
    async fn rejects_malformed_signature() {
        let s = MockSigner {
            sig: Some("0xdeadbeef".into()),
        };
        let res = derive_kek_via_signer(&s, "a", "b", "c").await;
        assert!(matches!(res, Err(KekDeriveError::BadSignatureLength(4))));
    }
}
