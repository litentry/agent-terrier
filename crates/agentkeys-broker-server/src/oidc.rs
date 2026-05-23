use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};

use crate::error::{BrokerError, BrokerResult};
use crate::jwt::KeypairPurpose;

/// Persisted on-disk shape (mode 0600). Keeping the kid + PEM lets us add
/// rotation later (multiple kids in JWKS) without changing the file format.
///
/// Stage 7 adds an optional `purpose` field — see plan §3.5.6. Pre-Stage-7
/// keypair files have no `purpose` field and are loaded with the default
/// `KeypairPurpose::Oidc` (legacy migration). New keypairs always include
/// the field. After one minor version, missing-purpose load becomes a hard
/// error matching the strict `SessionKeypair::load` semantics.
#[derive(Serialize, Deserialize)]
struct PersistedKeypair {
    kid: String,
    private_key_pem: String,
    #[serde(default = "default_purpose_oidc")]
    purpose: KeypairPurpose,
}

fn default_purpose_oidc() -> KeypairPurpose {
    KeypairPurpose::Oidc
}

/// In-memory ES256 signing keypair plus the public-key components needed to
/// emit a JWK and a `kid` for JWT headers.
pub struct OidcKeypair {
    pub kid: String,
    pub private_key_pem: String,
    /// base64url(no-pad)-encoded affine X coordinate (P-256, 32 bytes raw).
    pub public_x_b64: String,
    /// base64url(no-pad)-encoded affine Y coordinate.
    pub public_y_b64: String,
}

impl OidcKeypair {
    /// Generate a fresh ES256 keypair and persist it at `path` (mode 0600 on Unix).
    pub fn generate_and_persist(path: &Path) -> BrokerResult<Self> {
        let signing_key = SigningKey::random(&mut rand_compat::OsRngWrapper);
        let verifying_key = signing_key.verifying_key();

        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| BrokerError::Internal(format!("encode pkcs8 pem: {e}")))?
            .to_string();

        let kid = format!(
            "v1-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );

        let encoded_point = verifying_key.to_encoded_point(false);
        let x_bytes = encoded_point
            .x()
            .ok_or_else(|| BrokerError::Internal("verifying key missing X coordinate".into()))?;
        let y_bytes = encoded_point
            .y()
            .ok_or_else(|| BrokerError::Internal("verifying key missing Y coordinate".into()))?;

        let public_x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
        let public_y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

        let persisted = PersistedKeypair {
            kid: kid.clone(),
            private_key_pem: private_key_pem.clone(),
            purpose: KeypairPurpose::Oidc,
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrokerError::Internal(format!("create dir {parent:?}: {e}")))?;
        }
        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| BrokerError::Internal(format!("serialize keypair: {e}")))?;
        std::fs::write(path, json)
            .map_err(|e| BrokerError::Internal(format!("write keypair {path:?}: {e}")))?;
        set_owner_only_inner(path)?;

        Ok(Self {
            kid,
            private_key_pem,
            public_x_b64,
            public_y_b64,
        })
    }

    /// Load an already-persisted keypair from `path`. Refuses to load any
    /// keypair tagged `purpose=session` — that file belongs in the slot
    /// managed by `crate::jwt::SessionKeypair::load`. Pre-Stage-7 keypair
    /// files have no `purpose` field and are accepted as `oidc`.
    pub fn load(path: &Path) -> BrokerResult<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| BrokerError::Internal(format!("read keypair {path:?}: {e}")))?;
        let persisted: PersistedKeypair = serde_json::from_str(&raw)
            .map_err(|e| BrokerError::Internal(format!("parse keypair {path:?}: {e}")))?;

        if persisted.purpose != KeypairPurpose::Oidc {
            return Err(BrokerError::Internal(format!(
                "keypair at {} has purpose {:?} but OIDC slot expects oidc",
                path.display(),
                persisted.purpose
            )));
        }

        let signing_key = SigningKey::from_pkcs8_pem(&persisted.private_key_pem)
            .map_err(|e| BrokerError::Internal(format!("decode pkcs8 pem: {e}")))?;
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let x_bytes = encoded_point
            .x()
            .ok_or_else(|| BrokerError::Internal("verifying key missing X coordinate".into()))?;
        let y_bytes = encoded_point
            .y()
            .ok_or_else(|| BrokerError::Internal("verifying key missing Y coordinate".into()))?;

        Ok(Self {
            kid: persisted.kid,
            private_key_pem: persisted.private_key_pem,
            public_x_b64: URL_SAFE_NO_PAD.encode(x_bytes),
            public_y_b64: URL_SAFE_NO_PAD.encode(y_bytes),
        })
    }

    /// Load if the file exists, otherwise generate and persist. The dev-only
    /// path the broker uses at startup before a TEE-derived key is wired in.
    pub fn load_or_generate(path: &Path) -> BrokerResult<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Self::generate_and_persist(path)
        }
    }

    /// Default on-disk location: `~/.agentkeys/broker/oidc-keypair.json`.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".agentkeys")
            .join("broker")
            .join("oidc-keypair.json")
    }

    /// Return the JWK Set body that `/.well-known/jwks.json` serves.
    pub fn jwks_json(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": self.public_x_b64,
                "y": self.public_y_b64,
                "kid": self.kid,
                "alg": "ES256",
                "use": "sig",
            }]
        })
    }

    /// Sign `claims` (a JSON object) into a compact JWS (ES256, with our kid).
    pub fn sign_jwt(&self, claims: &serde_json::Value) -> BrokerResult<String> {
        let key = EncodingKey::from_ec_pem(self.private_key_pem.as_bytes())
            .map_err(|e| BrokerError::Internal(format!("load signing key: {e}")))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &key).map_err(|e| BrokerError::Internal(format!("sign jwt: {e}")))
    }
}

/// Internal chmod-0600 helper. `pub(crate)` so the parallel
/// `crate::jwt::SessionKeypair` can reuse it without duplicating the
/// platform-conditional code.
#[cfg(unix)]
pub(crate) fn set_owner_only_inner(path: &Path) -> BrokerResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| BrokerError::Internal(format!("metadata {path:?}: {e}")))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| BrokerError::Internal(format!("chmod {path:?}: {e}")))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_owner_only_inner(_path: &Path) -> BrokerResult<()> {
    // On non-Unix, file ACLs aren't 0600-shaped. The README warns operators
    // to run the broker on Linux; we don't fail startup on Windows just to
    // make CI green.
    Ok(())
}

/// Bridges `rand_core 0.6` (what `p256` 0.13 expects) to the system OS RNG.
/// `pub` so the parallel `SessionKeypair` can reuse it AND so integration
/// tests can construct fresh signing keys without pulling in their own
/// rand_core wrapper.
pub mod rand_compat {
    pub struct OsRngWrapper;

    impl rand_core::CryptoRng for OsRngWrapper {}

    impl rand_core::RngCore for OsRngWrapper {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            getrandom::getrandom(dest).expect("OS RNG failed");
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            getrandom::getrandom(dest)
                .map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use tempfile::TempDir;

    #[test]
    fn generate_and_load_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kp.json");

        let kp1 = OidcKeypair::generate_and_persist(&path).unwrap();
        assert!(path.exists());
        assert!(!kp1.kid.is_empty());
        assert_eq!(URL_SAFE_NO_PAD.decode(&kp1.public_x_b64).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(&kp1.public_y_b64).unwrap().len(), 32);

        let kp2 = OidcKeypair::load(&path).unwrap();
        assert_eq!(kp1.kid, kp2.kid);
        assert_eq!(kp1.public_x_b64, kp2.public_x_b64);
        assert_eq!(kp1.public_y_b64, kp2.public_y_b64);
    }

    #[test]
    fn load_or_generate_creates_then_reuses() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kp.json");

        let kp1 = OidcKeypair::load_or_generate(&path).unwrap();
        let kp2 = OidcKeypair::load_or_generate(&path).unwrap();
        assert_eq!(
            kp1.kid, kp2.kid,
            "second call must reuse the persisted keypair"
        );
    }

    #[test]
    fn jwks_shape_matches_aws_oidc_expectations() {
        let tmp = TempDir::new().unwrap();
        let kp = OidcKeypair::generate_and_persist(&tmp.path().join("kp.json")).unwrap();
        let jwks = kp.jwks_json();
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], kp.kid);
        assert!(key["x"].is_string());
        assert!(key["y"].is_string());
    }

    #[test]
    fn sign_jwt_round_trips_via_public_key() {
        let tmp = TempDir::new().unwrap();
        let kp = OidcKeypair::generate_and_persist(&tmp.path().join("kp.json")).unwrap();

        let claims = serde_json::json!({
            "iss": "https://oidc.agentkeys.dev",
            "sub": "agentkeys:agent:0xabc",
            "aud": "sts.amazonaws.com",
            "exp": 9_999_999_999_u64,
            "iat": 1_000_000_000_u64,
            "agentkeys_user_wallet": "0xabc",
        });
        let jwt = kp.sign_jwt(&claims).unwrap();
        assert_eq!(jwt.matches('.').count(), 2);

        // Verify with the public components we'd serve over the wire.
        let decoding_key =
            DecodingKey::from_ec_components(&kp.public_x_b64, &kp.public_y_b64).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["sts.amazonaws.com"]);
        validation.set_issuer(&["https://oidc.agentkeys.dev"]);

        let token_data: jsonwebtoken::TokenData<serde_json::Value> =
            decode(&jwt, &decoding_key, &validation).expect("public-key verify");
        assert_eq!(token_data.header.alg, Algorithm::ES256);
        assert_eq!(token_data.header.kid.as_deref(), Some(kp.kid.as_str()));
        assert_eq!(token_data.claims["agentkeys_user_wallet"], "0xabc");
    }

    #[cfg(unix)]
    #[test]
    fn persisted_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kp.json");
        OidcKeypair::generate_and_persist(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }
}
