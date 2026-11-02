use agentkeys_protocol::hosted_signer::{
    BrowserAssertion, HostedSignerIntent, MAX_BROWSER_APPROVAL_BYTES,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::device_crypto::{device_key_hash, ecrecover_eip191};
use crate::webauthn_assertion::decode_assertion_parts;

#[derive(Debug, thiserror::Error)]
pub enum EnrollmentProofError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Denied(String),
}

fn word(value: &str) -> Result<[u8; 32], EnrollmentProofError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|_| EnrollmentProofError::Invalid("expected hexadecimal enrollment value".into()))?
        .try_into()
        .map_err(|_| EnrollmentProofError::Invalid("expected 32-byte enrollment value".into()))
}

pub fn challenge(intent: &HostedSignerIntent) -> Result<[u8; 32], serde_json::Error> {
    let mut digest = Sha256::new();
    digest.update(b"agentkeys:hosted-signer-enrollment:v1:");
    digest.update(serde_json::to_vec(intent)?);
    Ok(digest.finalize().into())
}

pub fn verify_public_proofs(
    intent: &HostedSignerIntent,
    proof: &BrowserAssertion,
    device_proof: &str,
) -> Result<[u8; 32], EnrollmentProofError> {
    use EnrollmentProofError::{Denied, Invalid};
    if proof.authenticator_data.len()
        + proof.client_data_json.len()
        + proof.signature.len()
        + device_proof.len()
        > MAX_BROWSER_APPROVAL_BYTES
    {
        return Err(Invalid("browser proof is too large".into()));
    }
    if proof.credential_id != intent.credential_id {
        return Err(Denied("proof credential does not match enrollment".into()));
    }
    let parts = decode_assertion_parts(proof).map_err(Invalid)?;
    let client_data: serde_json::Value = serde_json::from_slice(&parts.client_data_json)
        .map_err(|error| Invalid(format!("client data: {error}")))?;
    let expected_challenge = challenge(intent).map_err(|error| Invalid(error.to_string()))?;
    if client_data.get("origin").and_then(|value| value.as_str()) != Some(&intent.origin)
        || client_data.get("type").and_then(|value| value.as_str()) != Some("webauthn.get")
        || client_data
            .get("challenge")
            .and_then(|value| value.as_str())
            != Some(&URL_SAFE_NO_PAD.encode(expected_challenge))
        || client_data
            .get("crossOrigin")
            .and_then(|value| value.as_bool())
            == Some(true)
    {
        return Err(Denied(
            "new credential proof has the wrong origin, challenge, or context".into(),
        ));
    }
    let expected_rp: [u8; 32] = Sha256::digest(intent.rp_id.as_bytes()).into();
    if parts.authenticator_data.len() < 37
        || parts.authenticator_data[..32] != expected_rp
        || parts.authenticator_data[32] & 5 != 5
    {
        return Err(Denied(
            "new credential proof requires the matching relying party and user verification".into(),
        ));
    }
    let mut public_key = vec![4];
    public_key.extend_from_slice(&word(&intent.public_key_x)?);
    public_key.extend_from_slice(&word(&intent.public_key_y)?);
    let key = VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| Invalid("invalid P-256 public key".into()))?;
    let signature = Signature::from_scalars(parts.r, parts.s)
        .map_err(|_| Invalid("invalid P-256 signature".into()))?;
    let mut signed_message = parts.authenticator_data;
    signed_message.extend_from_slice(&Sha256::digest(&parts.client_data_json));
    key.verify(&signed_message, &signature)
        .map_err(|_| Denied("new credential proof signature rejected".into()))?;
    let address = ecrecover_eip191(&expected_challenge, device_proof)
        .map_err(|_| Denied("new device proof rejected".into()))?;
    let derived_hash = device_key_hash(&address).map_err(|error| Invalid(error.to_string()))?;
    if word(&derived_hash)? != word(&intent.device_key_hash)? {
        return Err(Denied(
            "device proof does not own the requested K10 binding".into(),
        ));
    }
    Ok(expected_challenge)
}
