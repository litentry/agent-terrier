//! Decode browser WebAuthn assertions for account UserOp signatures.
//! The caller resolves the signer hash against the authenticated operator's account.

use crate::erc4337::encode_webauthn_signature;
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
