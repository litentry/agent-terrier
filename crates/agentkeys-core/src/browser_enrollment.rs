use agentkeys_protocol::hosted_signer::{
    BrowserAssertion, HostedSignerIntent, HOSTED_SIGNER_TTL_SECONDS, MAX_BROWSER_APPROVAL_BYTES,
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

pub struct EnrollmentSigner {
    pub credential_hash: [u8; 32],
    pub pub_x: [u8; 32],
    pub pub_y: [u8; 32],
    pub rp_id_hash: [u8; 32],
}

fn address(value: &str) -> Result<[u8; 20], EnrollmentProofError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|_| EnrollmentProofError::Invalid("invalid account address".into()))?
        .try_into()
        .map_err(|_| EnrollmentProofError::Invalid("expected a 20-byte account address".into()))
}

pub fn credential_hash(credential_id: &str) -> Result<[u8; 32], EnrollmentProofError> {
    let raw = URL_SAFE_NO_PAD
        .decode(credential_id)
        .map_err(|_| EnrollmentProofError::Invalid("invalid credential_id base64url".into()))?;
    if raw.is_empty() || raw.len() > 1024 {
        return Err(EnrollmentProofError::Invalid(
            "credential_id must contain 1 to 1024 bytes".into(),
        ));
    }
    Ok(crate::erc4337::credential_id_hash(&raw))
}
pub fn validate_origin(
    origin: &str,
    rp_id: &str,
    allowed_origins: &[String],
) -> Result<(), EnrollmentProofError> {
    let url = reqwest::Url::parse(origin)
        .map_err(|error| EnrollmentProofError::Invalid(format!("origin: {error}")))?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.origin().ascii_serialization() != origin
        || url.host_str() != Some(rp_id)
        || !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || !allowed_origins.iter().any(|allowed| allowed == origin)
    {
        return Err(EnrollmentProofError::Denied(
            "origin must be an allowed browser origin and rp_id must equal its host".into(),
        ));
    }
    Ok(())
}
pub fn validate_intent(
    intent: &HostedSignerIntent,
    omni: &[u8; 32],
    account: &[u8; 20],
    chain_id: u64,
    nonce: &[u8; 32],
    current_time: u64,
    origins: &[String],
) -> Result<EnrollmentSigner, EnrollmentProofError> {
    if word(&intent.operator_omni)? != *omni
        || address(&intent.account)? != *account
        || intent.chain_id != chain_id
        || word(&intent.operator_nonce)? != *nonce
    {
        return Err(EnrollmentProofError::Denied(
            "enrollment belongs to another operator, account, chain, or stale operator nonce"
                .into(),
        ));
    }
    if intent.expires_at <= current_time
        || intent.expires_at > current_time.saturating_add(HOSTED_SIGNER_TTL_SECONDS)
    {
        return Err(EnrollmentProofError::Invalid(
            "enrollment expired or has an invalid lifetime; restart on the new browser".into(),
        ));
    }
    validate_origin(&intent.origin, &intent.rp_id, origins)?;
    word(&intent.device_key_hash)?;
    let public_key_x = word(&intent.public_key_x)?;
    let public_key_y = word(&intent.public_key_y)?;
    let mut encoded = vec![4];
    encoded.extend_from_slice(&public_key_x);
    encoded.extend_from_slice(&public_key_y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|_| EnrollmentProofError::Invalid("invalid P-256 public key".into()))?;
    Ok(EnrollmentSigner {
        credential_hash: credential_hash(&intent.credential_id)?,
        pub_x: public_key_x,
        pub_y: public_key_y,
        rp_id_hash: Sha256::digest(intent.rp_id.as_bytes()).into(),
    })
}
