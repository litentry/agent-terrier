//! Session JWT issuance helpers.
//!
//! Per plan §3.5.5 — session JWTs are minted by `/v1/auth/*/verify` and
//! consumed by `/v1/mint-*` endpoints. The claim shape:
//!
//! ```json
//! {
//!   "iss":  "<broker oidc issuer URL>",
//!   "kid":  "ak-session-<unix>",  (in header)
//!   "sub":  "agentkeys:user:<omni_account>",
//!   "aud":  "agentkeys:broker",
//!   "exp":  <iat + ttl>,
//!   "iat":  <unix>,
//!   "jti":  "<ulid>",
//!   "agentkeys": {
//!     "omni_account":   "<hex>",
//!     "wallet_address": "0x…",
//!     "identity_type":  "evm" | "email" | "oauth2_google" | …,
//!     "identity_value": "<original identity value>"
//!   }
//! }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::error::{BrokerError, BrokerResult};
use crate::jwt::SessionKeypair;

/// Build the canonical session-JWT claims object and sign it with `keypair`.
pub fn mint_session_jwt(
    keypair: &SessionKeypair,
    issuer: &str,
    omni_account: &str,
    wallet_address: &str,
    identity_type: &str,
    identity_value: &str,
    ttl_seconds: u64,
) -> BrokerResult<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| BrokerError::Internal(format!("clock before unix epoch: {e}")))?
        .as_secs();
    let exp = now + ttl_seconds;

    let claims = json!({
        "iss": issuer,
        "sub": format!("agentkeys:user:{}", omni_account),
        "aud": "agentkeys:broker",
        "exp": exp,
        "iat": now,
        "jti": ulid_like(),
        "agentkeys": {
            "omni_account":   omni_account,
            "wallet_address": wallet_address,
            "identity_type":  identity_type,
            "identity_value": identity_value,
        }
    });

    keypair.sign_jwt(&claims)
}

/// Mint an `audit_proof` JWT for a capability grant (Phase B, US-025).
///
/// Per plan §3.5.5: the audit_proof is the broker's ES256 signature
/// over canonical grant content. Tampering with the SQLite row breaks
/// JWT verification — DB exfiltration cannot produce a verified-but-
/// tampered grant.
///
/// Phase E will swap the canonical-JSON-via-jsonwebtoken approach for
/// canonical CBOR per V0.1-FOLLOWUPS R1-F3. The compact-JWS wire shape
/// stays the same.
#[allow(clippy::too_many_arguments)]
pub fn mint_grant_audit_proof(
    keypair: &SessionKeypair,
    issuer: &str,
    grant_id: &str,
    master_omni_account: &str,
    daemon_address: &str,
    service: &str,
    scope_path: &str,
    granted_at: i64,
    expires_at: i64,
    max_uses: i64,
) -> BrokerResult<String> {
    let claims = json!({
        "iss":  issuer,
        "sub":  format!("agentkeys:grant:{}", grant_id),
        "aud":  "agentkeys:audit-proof",
        "iat":  granted_at,
        // exp is the grant's own expiration so the JWT becomes invalid
        // exactly when the grant does — the verifier doesn't need to
        // separately fetch the SQLite row's expires_at to know the
        // grant is dead.
        "exp":  expires_at,
        "agentkeys": {
            "kind":                 "grant",
            "grant_id":             grant_id,
            "master_omni_account":  master_omni_account,
            "daemon_address":       daemon_address,
            "service":              service,
            "scope_path":           scope_path,
            "granted_at":           granted_at,
            "expires_at":           expires_at,
            "max_uses":             max_uses,
        }
    });
    keypair.sign_jwt(&claims)
}

/// Cheap monotonic-ish identifier; not a real ULID but unique enough for
/// short-lived JWTs and small enough that we don't pull in a crate just
/// for this. Format: `<unix_micros>-<rand_hex>`.
fn ulid_like() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    let mut rand_bytes = [0u8; 8];
    getrandom::getrandom(&mut rand_bytes).expect("OS RNG failed");
    format!("{:x}-{}", micros, hex::encode(rand_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn mint_produces_three_part_jwt() {
        let tmp = TempDir::new().unwrap();
        let kp = SessionKeypair::generate_and_persist(&tmp.path().join("kp.json")).unwrap();
        let jwt = mint_session_jwt(
            &kp,
            "https://broker.example.com",
            "abc123",
            "0xabc",
            "evm",
            "0xabc",
            300,
        )
        .unwrap();
        assert_eq!(jwt.matches('.').count(), 2);
    }

    #[test]
    fn ulid_like_is_distinct_across_calls() {
        let a = ulid_like();
        let b = ulid_like();
        assert_ne!(a, b);
    }
}
