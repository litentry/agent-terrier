//! Decode browser WebAuthn assertions for account UserOp signatures.
//! The caller resolves the signer hash against the authenticated operator's account.

use agentkeys_core::erc4337::encode_webauthn_signature;
pub use agentkeys_protocol::hosted_signer::BrowserAssertion;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::Signature;

fn b64u(field: &str, s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| format!("{field} base64url: {e}"))
}

/// The decoded pieces of a [`BrowserAssertion`] — raw bytes + DER-extracted
/// `(r, s)` + the challenge byte-offset in `clientDataJSON`. Shared by the
/// accept path (ABI-encoded into the UserOp signature) and the #242 passkey
/// re-auth verb (fed to the on-chain `K11Verifier.verifyAssertion` view call).
pub struct AssertionParts {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// Byte offset of the challenge VALUE in `clientDataJSON` (right after the
    /// literal `"challenge":"`).
    pub challenge_location: usize,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Decode a browser assertion into its verification parts:
///   - base64url-decode the three blobs;
///   - `(r, s) = DER-decode(signature)` → 32-byte big-endian each (p256;
///     mirrors the mainnet-proven `extract_chain_assertion` — no low-s renorm,
///     the authenticator already emits low-s for P-256/WebAuthn);
///   - `challenge_location` via the `"challenge":"` needle.
pub fn decode_assertion_parts(a: &BrowserAssertion) -> Result<AssertionParts, String> {
    let authenticator_data = b64u("authenticator_data", &a.authenticator_data)?;
    let client_data_json = b64u("client_data_json", &a.client_data_json)?;
    let signature_der = b64u("signature", &a.signature)?;

    // DER → (r, s). p256 `Signature::to_bytes()` = r(32) ‖ s(32), big-endian.
    let sig =
        Signature::from_der(&signature_der).map_err(|e| format!("signature DER → (r,s): {e}"))?;
    let rs = sig.to_bytes();
    if rs.len() != 64 {
        return Err(format!("sig.to_bytes() = {} bytes, expected 64", rs.len()));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&rs[0..32]);
    s.copy_from_slice(&rs[32..64]);

    let cdj =
        std::str::from_utf8(&client_data_json).map_err(|e| format!("clientDataJSON utf-8: {e}"))?;
    const NEEDLE: &str = "\"challenge\":\"";
    let challenge_location = cdj
        .find(NEEDLE)
        .map(|p| p + NEEDLE.len())
        .ok_or_else(|| format!("clientDataJSON missing {NEEDLE:?}"))?;

    Ok(AssertionParts {
        authenticator_data,
        client_data_json,
        challenge_location,
        r,
        s,
    })
}

/// Encode an assertion for the signer hash verified against the session-bound account.
pub fn encode_browser_assertion_signature(
    a: &BrowserAssertion,
    cred_id_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let parts = decode_assertion_parts(a)?;

    Ok(encode_webauthn_signature(
        cred_id_hash,
        &parts.authenticator_data,
        &parts.client_data_json,
        parts.challenge_location as u128,
        &parts.r,
        &parts.s,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::erc4337::master_cred_id_hash;
    use p256::ecdsa::{signature::Signer, SigningKey};

    fn b64(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    /// Round-trip: a real P-256 DER signature + a real clientDataJSON decode into
    /// the exact `encode_webauthn_signature` layout. Asserts the six head words:
    /// [credIdHash][offAuth][offCdj][challengeLoc][r][s].
    #[test]
    fn decodes_a_real_p256_assertion_into_the_userop_signature() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        // The decoder does NOT verify the sig (the chain does) — it only extracts
        // (r, s) from DER — so signing arbitrary bytes is a faithful unit test.
        let sig: Signature = sk.sign(b"any-message");
        let der = sig.to_der();
        let rs = sig.to_bytes();

        let auth_data = vec![0xABu8; 37]; // ≥ 37 bytes (rpIdHash + flags + signCount)
        let cdj = br#"{"type":"webauthn.get","challenge":"abc123","origin":"https://x"}"#;
        let challenge_loc = std::str::from_utf8(cdj)
            .unwrap()
            .find("\"challenge\":\"")
            .unwrap()
            + "\"challenge\":\"".len();

        let omni = [0x42u8; 32];
        let a = BrowserAssertion {
            authenticator_data: b64(&auth_data),
            client_data_json: b64(cdj),
            signature: b64(der.as_bytes()),
            credential_id: b64(b"raw-credential-id"),
        };
        let hash = agentkeys_core::erc4337::credential_id_hash(b"raw-credential-id");
        let out = encode_browser_assertion_signature(&a, &hash).unwrap();

        assert_eq!(
            &out[0..32],
            &agentkeys_core::device_crypto::keccak256(b"raw-credential-id")
        );
        // Head layout (each 32-byte word): credIdHash | offAuth | offCdj | loc | r | s.
        assert_eq!(&out[0..32], &hash);
        let original = encode_browser_assertion_signature(&a, &master_cred_id_hash(&omni)).unwrap();
        assert_eq!(&original[0..32], &master_cred_id_hash(&omni));
        let word_u128 = |n: u128| {
            let mut w = [0u8; 32];
            w[16..].copy_from_slice(&n.to_be_bytes());
            w
        };
        assert_eq!(&out[32..64], &word_u128(6 * 32)); // off_auth = head = 6 words
        assert_eq!(&out[96..128], &word_u128(challenge_loc as u128));
        assert_eq!(&out[128..160], &rs[0..32]); // r
        assert_eq!(&out[160..192], &rs[32..64]); // s
                                                 // The tail carries the authenticatorData + clientDataJSON (length-prefixed).
        assert!(out.len() > 6 * 32 + auth_data.len() + cdj.len());
    }

    #[test]
    fn rejects_bad_base64_and_missing_challenge() {
        let omni = [0u8; 32];
        let mut a = BrowserAssertion {
            authenticator_data: "!!notb64".into(),
            client_data_json: "e30".into(),
            signature: "AA".into(),
            credential_id: "AA".into(),
        };
        assert!(encode_browser_assertion_signature(&a, &omni).is_err());

        // valid b64 but clientDataJSON has no challenge field, and signature isn't DER.
        a.authenticator_data = URL_SAFE_NO_PAD.encode([0u8; 37]);
        a.client_data_json = URL_SAFE_NO_PAD.encode(br#"{"type":"webauthn.get"}"#);
        a.signature = URL_SAFE_NO_PAD.encode([0u8; 8]); // not a valid DER sig
        assert!(encode_browser_assertion_signature(&a, &omni).is_err());
    }
}
