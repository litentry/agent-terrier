//! AES-256-GCM envelope v2 — **byte-for-byte identical to the CLI's
//! existing `agentkeys-core/src/s3_backend.rs` envelope**.
//!
//! Envelope layout (binary):
//!   version (1 byte = 0x02)
//!   nonce   (12 bytes)
//!   ciphertext || auth_tag (16 bytes appended by AES-GCM)
//!
//! AAD = `agentkeys.cred.aad.v2|<actor_omni_hex>|<service>` (NO trailing
//! NUL, NO hash). This matches `aad_for_v2` in s3_backend.rs so a blob
//! the CLI wrote can be read by the worker and vice versa.
//!
//! The stage-1 codex review (finding #5) flagged a prior mismatch
//! (worker was hashing AAD, CLI was using raw); this module is the
//! canonical reference and is now covered by a cross-crate test vector
//! (`tests/envelope_cross_compat.rs`).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use thiserror::Error;

pub const ENVELOPE_VERSION_V2: u8 = 0x02;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// v3 (#372 item 2 / #91): CLIENT-encrypted under the signer-derived
/// per-actor KEK. The worker stores/returns v3 envelopes VERBATIM — it holds
/// no key that can open them. ONE owner (`agentkeys_core::envelope_v3`, also
/// used by the daemon's encrypt/decrypt side); re-exported here so worker
/// code keeps a single `envelope::` surface.
pub use agentkeys_core::envelope_v3::{
    aad_v3, decrypt_v3, encrypt_v3, version, EnvelopeV3Error, ENVELOPE_VERSION_V3, MIN_ENVELOPE_LEN,
};

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("invalid KEK hex: {0}")]
    InvalidKekHex(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("envelope too short ({0} bytes)")]
    Truncated(usize),
    #[error("unsupported envelope version 0x{0:02x}")]
    UnsupportedVersion(u8),
    #[error(
        "v3 envelope requires the signer-derived per-actor KEK (client-side, #372) — \
         the static worker KEK cannot open it"
    )]
    V3RequiresDerivedKek,
}

/// AAD for v2 envelopes. MUST match `agentkeys-core::s3_backend::aad_for_v2`
/// byte-for-byte. Format:
///   `agentkeys.cred.aad.v2|<lowercase_actor_omni_hex>|<service>`
///
/// `actor_omni` is the 64-char hex without `0x` (lowercase); `service` is
/// passed through as-is (the CLI does not lowercase it before AAD; we
/// match that exactly for round-trip compatibility).
pub fn aad(_operator_omni: &str, actor_omni: &str, service: &str, _k3_epoch: u64) -> Vec<u8> {
    let actor = actor_omni
        .strip_prefix("0x")
        .unwrap_or(actor_omni)
        .to_lowercase();
    let mut out = Vec::with_capacity(32 + actor.len() + service.len());
    out.extend_from_slice(b"agentkeys.cred.aad.v2|");
    out.extend_from_slice(actor.as_bytes());
    out.push(b'|');
    out.extend_from_slice(service.as_bytes());
    out
}

pub fn encrypt(
    kek_hex: &str,
    plaintext: &[u8],
    aad_bytes: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let kek = decode_kek(kek_hex)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad_bytes,
            },
        )
        .map_err(|e| EnvelopeError::Encrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(ENVELOPE_VERSION_V2);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(kek_hex: &str, envelope: &[u8], aad_bytes: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(EnvelopeError::Truncated(envelope.len()));
    }
    if envelope[0] == ENVELOPE_VERSION_V3 {
        // Fail loud + specific: a v3 blob reaching a static-KEK decrypt call
        // site is a wiring bug (the worker must return v3 envelopes verbatim
        // for CLIENT-side decrypt), not a generic "unsupported version".
        return Err(EnvelopeError::V3RequiresDerivedKek);
    }
    if envelope[0] != ENVELOPE_VERSION_V2 {
        return Err(EnvelopeError::UnsupportedVersion(envelope[0]));
    }
    let kek = decode_kek(kek_hex)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let nonce = Nonce::from_slice(&envelope[1..1 + NONCE_LEN]);
    let ct = &envelope[1 + NONCE_LEN..];
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: aad_bytes,
            },
        )
        .map_err(|e| EnvelopeError::Decrypt(e.to_string()))
}

fn decode_kek(kek_hex: &str) -> Result<[u8; KEY_LEN], EnvelopeError> {
    let bytes = hex::decode(kek_hex.trim_start_matches("0x"))
        .map_err(|e| EnvelopeError::InvalidKekHex(e.to_string()))?;
    if bytes.len() != KEY_LEN {
        return Err(EnvelopeError::InvalidKekHex(format!(
            "expected {KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_matches_cli_format() {
        // CLI's s3_backend.rs aad_for_v2: "agentkeys.cred.aad.v2|" + actor + "|" + service
        // (no hash, no trailing NUL, no k3_epoch).
        let actor = "0xABCDEF12".to_string() + &"0".repeat(56);
        let a = aad("ignored", &actor, "openrouter", 999);
        assert_eq!(
            a,
            format!(
                "agentkeys.cred.aad.v2|{}|openrouter",
                "abcdef12".to_string() + &"0".repeat(56)
            )
            .as_bytes()
        );
    }

    #[test]
    fn aad_strips_0x_and_lowercases_actor() {
        let a1 = aad("x", "0xABCDEF", "s", 1);
        let a2 = aad("x", "abcdef", "s", 1);
        assert_eq!(a1, a2);
    }

    #[test]
    fn aad_preserves_service_casing_for_cli_compat() {
        // CLI's aad_for_v2 inlines service.0.as_bytes() with no
        // lowercase. We match that for round-trip compatibility.
        // Test would FAIL if we accidentally lowercased here.
        let upper = aad("x", "0xabc", "OpenRouter", 1);
        let lower = aad("x", "0xabc", "openrouter", 1);
        assert_ne!(
            upper, lower,
            "AAD must preserve service casing (CLI compat)"
        );
    }

    #[test]
    fn roundtrips_under_known_kek() {
        let kek = "a".repeat(64);
        let aad = aad("0x1", "0xdef", "openrouter", 1);
        let pt = b"sk-or-v1-EXAMPLE-SECRET";
        let env = encrypt(&kek, pt, &aad).unwrap();
        let recovered = decrypt(&kek, &env, &aad).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn detects_aad_tamper() {
        let kek = "b".repeat(64);
        let aad1 = aad("x", "0xab", "svc-a", 1);
        let aad2 = aad("x", "0xab", "svc-b", 1);
        let env = encrypt(&kek, b"x", &aad1).unwrap();
        assert!(
            decrypt(&kek, &env, &aad2).is_err(),
            "AAD tamper must fail decrypt"
        );
    }

    #[test]
    fn detects_version_drift() {
        let kek = "c".repeat(64);
        let aad = aad("x", "0xab", "s", 1);
        let mut env = encrypt(&kek, b"x", &aad).unwrap();
        env[0] = 0x01;
        let res = decrypt(&kek, &env, &aad);
        assert!(matches!(res, Err(EnvelopeError::UnsupportedVersion(0x01))));
    }

    #[test]
    fn rejects_short_envelope() {
        let res = decrypt(&"d".repeat(64), &[0x02, 0x01, 0x02], &[]);
        assert!(matches!(res, Err(EnvelopeError::Truncated(_))));
    }

    #[test]
    fn invalid_kek_length_errors() {
        let res = encrypt("aa", b"x", &[]);
        assert!(matches!(res, Err(EnvelopeError::InvalidKekHex(_))));
    }

    // ── v3 (#372 item 2 / #91) — the WORKER-side interplay only. The v3
    // crypto itself is owned + tested in `agentkeys_core::envelope_v3`.

    #[test]
    fn static_kek_decrypt_of_v3_fails_loud_and_specific() {
        // The worker must never try (and silently mangle) a v3 blob with its
        // static env KEK — the error names the wiring bug.
        let kek = [1u8; KEY_LEN];
        let env = encrypt_v3(&kek, b"x", &aad_v3("0xab", "s")).unwrap();
        let res = decrypt(&"e".repeat(64), &env, &aad_v3("0xab", "s"));
        assert!(matches!(res, Err(EnvelopeError::V3RequiresDerivedKek)));
    }

    #[test]
    fn derived_kek_decrypt_of_v2_is_rejected() {
        // v2 blobs stay on the static-KEK path; decrypt_v3 refuses them
        // instead of failing with a confusing GCM error under the wrong key.
        let static_kek = "f".repeat(64);
        let aad2 = aad("x", "0xab", "s", 1);
        let env = encrypt(&static_kek, b"x", &aad2).unwrap();
        let res = decrypt_v3(&[0u8; KEY_LEN], &env, &aad2);
        assert!(matches!(
            res,
            Err(EnvelopeV3Error::UnsupportedVersion(ENVELOPE_VERSION_V2))
        ));
    }

    #[test]
    fn aad_v3_differs_from_v2_aad() {
        // Distinct domain prefix: a version-byte flip can never validate
        // against the other version's AAD even if the KEKs coincided.
        assert_ne!(aad_v3("0xab", "s"), aad("x", "0xab", "s", 1));
    }
}
