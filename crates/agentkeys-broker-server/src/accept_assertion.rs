pub use agentkeys_core::webauthn_assertion::{
    decode_assertion_parts, encode_browser_assertion_signature, AssertionParts, BrowserAssertion,
};

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::erc4337::master_cred_id_hash;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::Signature;
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
