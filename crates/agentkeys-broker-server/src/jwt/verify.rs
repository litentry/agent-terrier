//! Session JWT verification.
//!
//! Used by `/v1/mint-*` and any other broker-internal endpoint that
//! requires an authenticated user identity. The OIDC issuer keypair
//! is NEVER used to verify session JWTs and vice versa — the kid prefix
//! difference and the keypair-purpose tagging in `jwt/mod.rs` ensure this
//! by construction.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{BrokerError, BrokerResult};
use crate::jwt::SessionKeypair;

/// Claims the broker reads back from a verified session JWT.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub agentkeys: AgentKeysClaims,
}

/// The custom `agentkeys` namespace inside the session JWT.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentKeysClaims {
    pub omni_account: String,
    pub wallet_address: String,
    pub identity_type: String,
    pub identity_value: String,
}

/// Verify a session JWT against the broker's session keypair. Validates
/// signature, expiration, audience (`agentkeys:broker`), and issuer.
pub fn verify_session_jwt(
    keypair: &SessionKeypair,
    issuer: &str,
    token: &str,
) -> BrokerResult<SessionClaims> {
    let decoding_key = DecodingKey::from_ec_components(&keypair.public_x_b64, &keypair.public_y_b64)
        .map_err(|e| BrokerError::Unauthorized(format!("decoding key construction: {e}")))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["agentkeys:broker"]);
    validation.set_issuer(&[issuer]);

    let token_data = decode::<SessionClaims>(token, &decoding_key, &validation)
        .map_err(|e| BrokerError::Unauthorized(format!("session jwt verify: {e}")))?;

    // Defense-in-depth: also assert the kid header matches our session
    // keypair. Closes the (theoretical) attack where a forged token claims
    // a different kid that nonetheless verifies under our key — the
    // jsonwebtoken validator already checks the signature, but pinning the
    // kid keeps audits clean and makes accidental key-mix-ups crash loud.
    if token_data.header.kid.as_deref() != Some(keypair.kid.as_str()) {
        return Err(BrokerError::Unauthorized(format!(
            "session jwt kid mismatch: token kid={:?}, expected {}",
            token_data.header.kid, keypair.kid
        )));
    }

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::issue::mint_session_jwt;
    use tempfile::TempDir;

    fn keypair() -> (TempDir, SessionKeypair) {
        let tmp = TempDir::new().unwrap();
        let kp = SessionKeypair::generate_and_persist(&tmp.path().join("kp.json")).unwrap();
        (tmp, kp)
    }

    #[test]
    fn round_trip_mint_then_verify() {
        let (_tmp, kp) = keypair();
        let issuer = "https://broker.example.com";
        let token =
            mint_session_jwt(&kp, issuer, "0x7f", "0xabc", "evm", "0xabc", 300).unwrap();
        let claims = verify_session_jwt(&kp, issuer, &token).unwrap();
        assert_eq!(claims.aud, "agentkeys:broker");
        assert_eq!(claims.iss, issuer);
        assert_eq!(claims.agentkeys.omni_account, "0x7f");
        assert_eq!(claims.agentkeys.identity_type, "evm");
    }

    #[test]
    fn verify_rejects_wrong_audience() {
        let (_tmp, kp) = keypair();
        let claims = serde_json::json!({
            "iss": "https://broker.example.com",
            "sub": "agentkeys:user:0x7f",
            "aud": "wrong-aud",
            "exp": 9_999_999_999_u64,
            "iat": 1_000_000_000_u64,
            "jti": "test",
            "agentkeys": {
                "omni_account": "0x7f",
                "wallet_address": "0xabc",
                "identity_type": "evm",
                "identity_value": "0xabc",
            }
        });
        let token = kp.sign_jwt(&claims).unwrap();
        let err = verify_session_jwt(&kp, "https://broker.example.com", &token);
        assert!(err.is_err(), "must reject wrong audience");
    }

    #[test]
    fn verify_rejects_expired_token() {
        let (_tmp, kp) = keypair();
        let claims = serde_json::json!({
            "iss": "https://broker.example.com",
            "sub": "agentkeys:user:0x7f",
            "aud": "agentkeys:broker",
            "exp": 1_000_000_001_u64,  // 2001
            "iat": 1_000_000_000_u64,
            "jti": "test",
            "agentkeys": {
                "omni_account": "0x7f",
                "wallet_address": "0xabc",
                "identity_type": "evm",
                "identity_value": "0xabc",
            }
        });
        let token = kp.sign_jwt(&claims).unwrap();
        let err = verify_session_jwt(&kp, "https://broker.example.com", &token);
        assert!(err.is_err(), "must reject expired");
    }

    #[test]
    fn verify_rejects_wrong_issuer() {
        let (_tmp, kp) = keypair();
        let token =
            mint_session_jwt(&kp, "https://broker.example.com", "0x7f", "0xabc", "evm", "0xabc", 300)
                .unwrap();
        let err = verify_session_jwt(&kp, "https://different-broker.example.com", &token);
        assert!(err.is_err(), "must reject wrong issuer");
    }
}
