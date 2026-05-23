//! `SessionKeypair` — broker-internal ES256 keypair for `/v1/mint-*` session JWTs.
//!
//! Mirrors `crate::oidc::OidcKeypair` in shape (ES256 P-256, base64url-encoded
//! affine X/Y, kid + PEM persisted at mode 0600). The crucial difference is
//! the on-disk `"purpose"` field set to `"session"` and validated at load.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};

use crate::error::{BrokerError, BrokerResult};
use crate::jwt::{KeypairPurpose, KeypairPurposeError};

/// On-disk shape. The `purpose` field defaults to `Session` only if absent
/// and the load path was called with `allow_untagged = true` (legacy
/// migration). New keypairs always include it.
#[derive(Serialize, Deserialize)]
struct PersistedSessionKeypair {
    kid: String,
    private_key_pem: String,
    purpose: KeypairPurpose,
}

/// In-memory ES256 signing keypair for broker-internal session JWTs.
pub struct SessionKeypair {
    pub kid: String,
    pub private_key_pem: String,
    /// base64url(no-pad) X coordinate. Kept for symmetry with OidcKeypair
    /// even though we never serve a JWKS for the session keypair.
    pub public_x_b64: String,
    pub public_y_b64: String,
}

impl SessionKeypair {
    /// Generate a fresh ES256 keypair, tag it with `purpose=session`, and
    /// persist at `path` (mode 0600 on Unix).
    pub fn generate_and_persist(path: &Path) -> BrokerResult<Self> {
        let signing_key = SigningKey::random(&mut crate::oidc::rand_compat::OsRngWrapper);
        let verifying_key = signing_key.verifying_key();

        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| BrokerError::Internal(format!("encode pkcs8 pem: {e}")))?
            .to_string();

        let kid = format!(
            "{}-{}",
            KeypairPurpose::Session.kid_prefix(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );

        let encoded_point = verifying_key.to_encoded_point(false);
        let x_bytes = encoded_point
            .x()
            .ok_or_else(|| BrokerError::Internal("verifying key missing X".into()))?;
        let y_bytes = encoded_point
            .y()
            .ok_or_else(|| BrokerError::Internal("verifying key missing Y".into()))?;

        let public_x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
        let public_y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

        let persisted = PersistedSessionKeypair {
            kid: kid.clone(),
            private_key_pem: private_key_pem.clone(),
            purpose: KeypairPurpose::Session,
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrokerError::Internal(format!("create dir {parent:?}: {e}")))?;
        }
        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| BrokerError::Internal(format!("serialize keypair: {e}")))?;
        std::fs::write(path, json)
            .map_err(|e| BrokerError::Internal(format!("write keypair {path:?}: {e}")))?;
        crate::oidc::set_owner_only_inner(path)?;

        Ok(Self {
            kid,
            private_key_pem,
            public_x_b64,
            public_y_b64,
        })
    }

    /// Load a session keypair from `path`. **Refuses to load any keypair
    /// whose persisted `purpose` is not `Session`** — this is the codex /
    /// eng-review #7 footgun mitigation: an operator accidentally pointing
    /// BROKER_SESSION_KEYPAIR_PATH at the OIDC keypair file will get a
    /// load-time error, not a same-key signing accident.
    pub fn load(path: &Path) -> BrokerResult<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| BrokerError::Internal(format!("read keypair {path:?}: {e}")))?;
        let persisted: PersistedSessionKeypair = serde_json::from_str(&raw).map_err(|e| {
            BrokerError::Internal(format!(
                "parse session keypair {path:?}: {e} (the file may be missing the \"purpose\" field — session keypairs must be tagged purpose=session)"
            ))
        })?;

        if persisted.purpose != KeypairPurpose::Session {
            return Err(BrokerError::Internal(
                KeypairPurposeError::PurposeMismatch {
                    path: path.display().to_string(),
                    expected: KeypairPurpose::Session,
                    actual: persisted.purpose,
                }
                .to_string(),
            ));
        }

        let signing_key = SigningKey::from_pkcs8_pem(&persisted.private_key_pem)
            .map_err(|e| BrokerError::Internal(format!("decode pkcs8 pem: {e}")))?;
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let x_bytes = encoded_point
            .x()
            .ok_or_else(|| BrokerError::Internal("verifying key missing X".into()))?;
        let y_bytes = encoded_point
            .y()
            .ok_or_else(|| BrokerError::Internal("verifying key missing Y".into()))?;

        Ok(Self {
            kid: persisted.kid,
            private_key_pem: persisted.private_key_pem,
            public_x_b64: URL_SAFE_NO_PAD.encode(x_bytes),
            public_y_b64: URL_SAFE_NO_PAD.encode(y_bytes),
        })
    }

    /// Default on-disk location: `~/.agentkeys/broker/session-keypair.json`.
    /// Distinct filename from the OIDC keypair to make accidental mis-pointing
    /// easier to spot.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".agentkeys")
            .join("broker")
            .join("session-keypair.json")
    }

    /// Sign `claims` (a JSON object) into a compact JWS (ES256, with our kid).
    pub fn sign_jwt(&self, claims: &serde_json::Value) -> BrokerResult<String> {
        let key = EncodingKey::from_ec_pem(self.private_key_pem.as_bytes())
            .map_err(|e| BrokerError::Internal(format!("load signing key: {e}")))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &key)
            .map_err(|e| BrokerError::Internal(format!("sign session jwt: {e}")))
    }

    /// Export the public component of this session keypair as a PEM-encoded
    /// SubjectPublicKeyInfo (SPKI) string. The signer service reads this at
    /// boot to verify broker session JWTs without holding the private key.
    pub fn public_key_pem(&self) -> BrokerResult<String> {
        let signing_key = SigningKey::from_pkcs8_pem(&self.private_key_pem).map_err(|e| {
            BrokerError::Internal(format!("decode pkcs8 pem for pubkey export: {e}"))
        })?;
        let verifying_key = signing_key.verifying_key();
        verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| BrokerError::Internal(format!("encode public key pem: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_persists_with_purpose_tag() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kp.json");
        SessionKeypair::generate_and_persist(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"purpose\""));
        assert!(raw.contains("\"session\""));
    }

    #[test]
    fn generate_and_load_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kp.json");
        let kp1 = SessionKeypair::generate_and_persist(&path).unwrap();
        let kp2 = SessionKeypair::load(&path).unwrap();
        assert_eq!(kp1.kid, kp2.kid);
        assert!(kp1.kid.starts_with("ak-session-"));
        assert_eq!(kp1.public_x_b64, kp2.public_x_b64);
    }

    #[test]
    fn load_refuses_oidc_purpose_keypair() {
        // Write a JSON with purpose=oidc to the path, then attempt to load
        // as a session keypair — must fail with PurposeMismatch.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wrong-purpose.json");
        // Generate a real OIDC keypair (with purpose tag) at this path.
        // We synthesize the JSON manually because OidcKeypair doesn't yet
        // emit the purpose field — that lands in the same story below.
        let raw = r#"{
          "kid": "ak-oidc-1",
          "private_key_pem": "-----BEGIN PRIVATE KEY-----\nbm9uc2Vuc2U=\n-----END PRIVATE KEY-----\n",
          "purpose": "oidc"
        }"#;
        std::fs::write(&path, raw).unwrap();

        let err = SessionKeypair::load(&path)
            .err()
            .expect("must reject oidc-purpose keypair");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("oidc") && msg.contains("session"),
            "error must mention both purposes, got: {}",
            err
        );
    }

    #[test]
    fn load_refuses_untagged_keypair() {
        // Legacy / unspecified-purpose JSON: load must fail because the
        // session-keypair load path is strict (no migration window).
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("untagged.json");
        let raw = r#"{
          "kid": "untagged-1",
          "private_key_pem": "-----BEGIN PRIVATE KEY-----\nbm9uc2Vuc2U=\n-----END PRIVATE KEY-----\n"
        }"#;
        std::fs::write(&path, raw).unwrap();
        assert!(SessionKeypair::load(&path).is_err());
    }
}
