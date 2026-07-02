//! v3 AES-256-GCM envelope — CLIENT-encrypted under the signer-derived
//! per-actor KEK (#372 item 2 / #91). ONE owner for both sides of the wire:
//! the daemon (encrypt before `/v1/config/put`, decrypt after
//! `/v1/config/get`) and the config worker (version-sniff + store verbatim —
//! it re-exports these symbols via `agentkeys_worker_creds::envelope`).
//!
//! Wire layout (identical to v1/v2): `1B version(0x03) | 12B nonce |
//! ciphertext | 16B tag`. AAD carries its own domain prefix
//! (`agentkeys.cred.aad.v3|<actor>|<service>`) so a version-byte flip can
//! never validate against another version's AAD. The KEK comes from
//! [`crate::kek::derive_kek_via_signer`] — the vault's construction; the
//! storage plane and every worker env hold nothing that opens a v3 blob.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use thiserror::Error;

pub const ENVELOPE_VERSION_V3: u8 = 0x03;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
/// Smallest well-formed envelope: version + nonce + empty ct + GCM tag.
pub const MIN_ENVELOPE_LEN: usize = 1 + NONCE_LEN + 16;

#[derive(Debug, Error)]
pub enum EnvelopeV3Error {
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("envelope too short ({0} bytes)")]
    Truncated(usize),
    #[error("unsupported envelope version 0x{0:02x} (v3 expected)")]
    UnsupportedVersion(u8),
}

/// Version byte of a well-formed envelope; `None` when too short to be one.
pub fn version(envelope: &[u8]) -> Option<u8> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return None;
    }
    Some(envelope[0])
}

/// AAD for v3 envelopes. Same normalization as the v2 AAD (lowercase
/// `0x`-stripped actor, service casing preserved), distinct domain prefix:
///   `agentkeys.cred.aad.v3|<lowercase_actor_omni_hex>|<service>`
pub fn aad_v3(actor_omni: &str, service: &str) -> Vec<u8> {
    let actor = actor_omni
        .strip_prefix("0x")
        .unwrap_or(actor_omni)
        .to_lowercase();
    let mut out = Vec::with_capacity(32 + actor.len() + service.len());
    out.extend_from_slice(b"agentkeys.cred.aad.v3|");
    out.extend_from_slice(actor.as_bytes());
    out.push(b'|');
    out.extend_from_slice(service.as_bytes());
    out
}

/// Encrypt a v3 envelope under a RAW 32-byte KEK (signer-derived,
/// [`crate::kek::derive_kek_via_signer`]). Client-side only — the worker
/// never holds this key.
pub fn encrypt_v3(
    kek: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad_bytes: &[u8],
) -> Result<Vec<u8>, EnvelopeV3Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad_bytes,
            },
        )
        .map_err(|e| EnvelopeV3Error::Encrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(ENVELOPE_VERSION_V3);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a v3 envelope under a RAW 32-byte KEK. Rejects any other version —
/// v2 blobs stay on the worker's static-KEK path.
pub fn decrypt_v3(
    kek: &[u8; KEY_LEN],
    envelope: &[u8],
    aad_bytes: &[u8],
) -> Result<Vec<u8>, EnvelopeV3Error> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(EnvelopeV3Error::Truncated(envelope.len()));
    }
    if envelope[0] != ENVELOPE_VERSION_V3 {
        return Err(EnvelopeV3Error::UnsupportedVersion(envelope[0]));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
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
        .map_err(|e| EnvelopeV3Error::Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_roundtrips_under_raw_kek() {
        let kek = [7u8; KEY_LEN];
        let aad = aad_v3("0xABCdef", "memory-taxonomy");
        let env = encrypt_v3(&kek, b"taxonomy-json", &aad).unwrap();
        assert_eq!(env[0], ENVELOPE_VERSION_V3);
        let out = decrypt_v3(&kek, &env, &aad).unwrap();
        assert_eq!(out, b"taxonomy-json");
    }

    #[test]
    fn v3_detects_aad_tamper() {
        let kek = [9u8; KEY_LEN];
        let env = encrypt_v3(&kek, b"x", &aad_v3("0xab", "svc-a")).unwrap();
        assert!(decrypt_v3(&kek, &env, &aad_v3("0xab", "svc-b")).is_err());
    }

    #[test]
    fn v3_detects_wrong_kek() {
        let env = encrypt_v3(&[1u8; KEY_LEN], b"x", &aad_v3("0xab", "s")).unwrap();
        assert!(decrypt_v3(&[2u8; KEY_LEN], &env, &aad_v3("0xab", "s")).is_err());
    }

    #[test]
    fn decrypt_v3_rejects_other_versions() {
        let mut env = encrypt_v3(&[3u8; KEY_LEN], b"x", &aad_v3("0xab", "s")).unwrap();
        env[0] = 0x02;
        let res = decrypt_v3(&[3u8; KEY_LEN], &env, &aad_v3("0xab", "s"));
        assert!(matches!(
            res,
            Err(EnvelopeV3Error::UnsupportedVersion(0x02))
        ));
    }

    #[test]
    fn aad_v3_normalizes_actor_and_carries_v3_prefix() {
        assert_eq!(aad_v3("0xABCdef", "s"), aad_v3("abcdef", "s"));
        assert_eq!(
            aad_v3("0xABC", "MyService"),
            b"agentkeys.cred.aad.v3|abc|MyService".to_vec()
        );
    }

    #[test]
    fn version_reads_the_byte_or_none_when_short() {
        let env = encrypt_v3(&[2u8; KEY_LEN], b"x", &aad_v3("0xab", "s")).unwrap();
        assert_eq!(version(&env), Some(ENVELOPE_VERSION_V3));
        assert_eq!(version(&[0x03, 0x00]), None);
    }
}
