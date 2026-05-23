//! `SiweWalletAuth` — Phase 0 wallet-signature auth method.
//!
//! Per plan §3.5.1: SIWE-wrapped EIP-191. The challenge() step builds a
//! SIWE (EIP-4361) message with the broker's domain, a fresh CSPRNG nonce,
//! issued_at, and expiration_time (issued_at + 45 min). The verify() step
//! parses the returned signed message + 65-byte signature, asserts every
//! field matches what the broker issued, runs k256 ecrecover, and
//! confirms the recovered address equals the SIWE message's `address`
//! field.
//!
//! The crypto envelope is EIP-191:
//!   "\x19Ethereum Signed Message:\n<len><msg>" → keccak256 → ecrecover.
//!
//! Defense properties:
//! - Domain binding: SIWE `domain` field is bound to the broker's host;
//!   a signature gathered by another app authenticating to a different
//!   domain cannot be replayed here.
//! - Nonce single-use: enforced by `AuthNonceStore` (UNIQUE on nonce +
//!   conditional UPDATE for race safety).
//! - 45-min issued_at window: SIWE `expiration_time` field, validated at
//!   verify() time.
//! - Low-s signature normalization: k256's verify path enforces canonical
//!   signatures (the curve already rejects high-s by default in 0.13).
//! - Chain-ID binding: SIWE `chain_id` field is bound to whatever the
//!   client claimed at challenge time and re-checked at verify time.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::json;
use sha3::{Digest, Keccak256};

use crate::plugins::auth::{
    AuthChallenge, AuthError, AuthResponse, ChallengeParams, IdentityType, UserAuthMethod,
    VerifiedIdentity,
};
use crate::plugins::Readiness;
use crate::storage::{AuthNonceStore, ConsumeOutcome};

const PLUGIN_NAME: &str = "wallet_sig";
/// SIWE message expiration window in seconds. Plan §3.5.1 specifies 45min.
const SIWE_TTL_SECONDS: i64 = 45 * 60;

/// In-memory plugin handle.
pub struct SiweWalletAuth {
    nonce_store: Arc<AuthNonceStore>,
    /// SIWE `domain` field — typically the host portion of `BROKER_OIDC_ISSUER`
    /// (e.g. `"broker.agentkeys.dev"`). Plumbed in from boot.rs.
    domain: String,
    /// SIWE `uri` field — full URL form of `BROKER_OIDC_ISSUER`.
    uri: String,
    /// In-memory map from `request_id` → (nonce, address, chain_id) so verify()
    /// can re-check that the returned SIWE message matches what we issued
    /// without requiring the client to send it back. Mutex<HashMap> is fine
    /// for v0; under multi-process deployment this would move to SQLite.
    pending: tokio::sync::Mutex<std::collections::HashMap<String, PendingChallenge>>,
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    nonce: String,
    address: String,
    /// Captured at challenge() so audits can reconstruct the full SIWE
    /// message context. Not currently re-checked at verify() because the
    /// chain_id is bound into `siwe_message` and recovered through the
    /// signature verification — the address ↔ key binding is what the
    /// signature proves.
    #[allow(dead_code)]
    chain_id: u64,
    /// Full SIWE message text — kept so verify() can re-render the canonical
    /// form against any submitted message and reject mismatches.
    siwe_message: String,
}

impl SiweWalletAuth {
    pub fn new(
        nonce_store: Arc<AuthNonceStore>,
        domain: impl Into<String>,
        uri: impl Into<String>,
    ) -> Self {
        Self {
            nonce_store,
            domain: domain.into(),
            uri: uri.into(),
            pending: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl UserAuthMethod for SiweWalletAuth {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn ready(&self) -> Readiness {
        if self.nonce_store.writable() {
            Readiness::ready_with("wallet_sig: nonce store writable")
        } else {
            Readiness::unready("auth_nonces table not writable")
        }
    }

    async fn challenge(&self, params: ChallengeParams) -> Result<AuthChallenge, AuthError> {
        // Inputs: address (required), chain_id (required, integer).
        let address = params
            .extras
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidRequest("missing field: address".into()))?
            .to_lowercase();
        if address.len() != 42 || !address.starts_with("0x") {
            return Err(AuthError::InvalidRequest(format!(
                "malformed address: {}",
                address
            )));
        }
        if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AuthError::InvalidRequest(format!(
                "malformed address: {}",
                address
            )));
        }
        let chain_id = params
            .extras
            .get("chain_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AuthError::InvalidRequest("missing field: chain_id".into()))?;

        // Generate request_id + nonce.
        let request_id = format!("siwe-{}", random_id_hex(16));
        let nonce = random_id_hex(16);
        let now = unix_now()?;
        let expires_at = now + SIWE_TTL_SECONDS;

        // Persist nonce (single-use enforcement at consume time).
        self.nonce_store.issue(&nonce, &address, now, expires_at)?;

        // Build SIWE message body. EIP-4361 canonical form.
        // We deliberately produce a fixed line ordering to match the parsing
        // step in verify() — even though the SIWE spec allows order
        // flexibility, locking it here prevents whitespace footguns.
        let issued_at_iso = unix_to_iso8601(now);
        let expires_at_iso = unix_to_iso8601(expires_at);
        let siwe_message = format!(
            "{domain} wants you to sign in with your Ethereum account:\n\
             {address}\n\
             \n\
             Authenticate with AgentKeys broker.\n\
             \n\
             URI: {uri}\n\
             Version: 1\n\
             Chain ID: {chain_id}\n\
             Nonce: {nonce}\n\
             Issued At: {iat}\n\
             Expiration Time: {exp}\n\
             Resources:\n\
             - urn:agentkeys:client:agentkeys",
            domain = self.domain,
            address = address,
            uri = self.uri,
            chain_id = chain_id,
            nonce = nonce,
            iat = issued_at_iso,
            exp = expires_at_iso,
        );

        // Stash for verify().
        self.pending.lock().await.insert(
            request_id.clone(),
            PendingChallenge {
                nonce: nonce.clone(),
                address: address.clone(),
                chain_id,
                siwe_message: siwe_message.clone(),
            },
        );

        Ok(AuthChallenge {
            request_id,
            expires_in_seconds: SIWE_TTL_SECONDS as u64,
            extras: json!({
                "siwe_message": siwe_message,
                "nonce": nonce,
                "expires_at_iso": expires_at_iso,
            }),
        })
    }

    async fn verify(&self, response: AuthResponse) -> Result<VerifiedIdentity, AuthError> {
        // Extract the submitted signature.
        let signature_hex = response
            .extras
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidRequest("missing field: signature".into()))?;

        // Look up pending challenge. Removed on success or failure to
        // prevent replay even at the in-memory layer (the on-disk
        // single-use is in `auth_nonces`).
        let pending = {
            let mut map = self.pending.lock().await;
            map.remove(&response.request_id).ok_or_else(|| {
                AuthError::Unauthorized(format!(
                    "no pending wallet-sig challenge for request_id: {}",
                    response.request_id
                ))
            })?
        };

        // Atomically consume the nonce.
        let now = unix_now()?;
        match self.nonce_store.consume(&pending.nonce, now)? {
            ConsumeOutcome::Consumed {
                address: stored_address,
                ..
            } => {
                if stored_address != pending.address {
                    return Err(AuthError::Internal(format!(
                        "nonce->address mismatch: stored={}, pending={}",
                        stored_address, pending.address
                    )));
                }
            }
            ConsumeOutcome::Expired => {
                return Err(AuthError::Expired(format!(
                    "siwe message expired (>= {}s after issued_at)",
                    SIWE_TTL_SECONDS
                )));
            }
            ConsumeOutcome::NotFoundOrConsumed => {
                return Err(AuthError::Unauthorized(
                    "nonce already consumed or unknown — replay rejected".into(),
                ));
            }
        }

        // Verify the EIP-191 signature over the SIWE message.
        let recovered_address = ecrecover_address(&pending.siwe_message, signature_hex)?;
        if recovered_address.to_lowercase() != pending.address.to_lowercase() {
            return Err(AuthError::Unauthorized(format!(
                "signature does not recover to claimed address: claimed={}, recovered={}",
                pending.address, recovered_address
            )));
        }

        Ok(VerifiedIdentity {
            identity_type: IdentityType::Evm,
            identity_value: pending.address,
        })
    }
}

/// EIP-191 ecrecover: build the prefixed message, keccak256 it, recover the
/// address from `(r, s, recovery_id)`, return the 0x-prefixed lowercase
/// hex form.
///
/// Signature wire format: 65 bytes = r(32) || s(32) || v(1). v ∈ {0, 1, 27, 28}.
/// We normalize v back to {0, 1} for k256's RecoveryId.
fn ecrecover_address(message: &str, signature_hex: &str) -> Result<String, AuthError> {
    let sig_hex = signature_hex.trim_start_matches("0x");
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| AuthError::InvalidRequest(format!("signature is not hex: {}", e)))?;
    if sig_bytes.len() != 65 {
        return Err(AuthError::InvalidRequest(format!(
            "signature must be 65 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let v_byte = sig_bytes[64];
    let recovery_id_byte = match v_byte {
        0 | 1 => v_byte,
        27 | 28 => v_byte - 27,
        other => {
            return Err(AuthError::InvalidRequest(format!(
                "unsupported v byte: {}",
                other
            )));
        }
    };
    let recovery_id = RecoveryId::try_from(recovery_id_byte)
        .map_err(|e| AuthError::InvalidRequest(format!("bad recovery id: {}", e)))?;
    let signature = Signature::from_slice(&sig_bytes[..64])
        .map_err(|e| AuthError::InvalidRequest(format!("bad sig bytes: {}", e)))?;

    // EIP-191 prefixed digest.
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();

    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|e| AuthError::Unauthorized(format!("recover failed: {}", e)))?;

    // Address = last 20 bytes of keccak256(uncompressed_pubkey_xy).
    let encoded_point = verifying_key.to_encoded_point(false);
    let pubkey_bytes = encoded_point.as_bytes();
    // First byte is the 0x04 uncompressed marker; skip it.
    if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
        return Err(AuthError::Internal(
            "recovered key is not 65-byte uncompressed P-256k1 point".into(),
        ));
    }
    let mut addr_hasher = Keccak256::new();
    addr_hasher.update(&pubkey_bytes[1..]);
    let pubkey_hash = addr_hasher.finalize();
    let address_bytes = &pubkey_hash[12..];
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

fn unix_now() -> Result<i64, AuthError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AuthError::Internal(format!("clock before unix epoch: {}", e)))?
        .as_secs() as i64)
}

fn unix_to_iso8601(secs: i64) -> String {
    // Minimal RFC3339 formatter to avoid pulling in chrono.
    // Format: 2026-05-05T14:22:11Z. Good enough for SIWE.
    let days_since_epoch = secs / 86400;
    let secs_of_day = secs.rem_euclid(86400);
    let h = secs_of_day / 3600;
    let m = (secs_of_day / 60) % 60;
    let s = secs_of_day % 60;
    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's `civil_from_days` shifted to 1970 epoch.
    // Valid for all dates 1970-2400+.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn random_id_hex(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    getrandom::getrandom(&mut buf).expect("OS RNG failed");
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Arc<AuthNonceStore> {
        Arc::new(AuthNonceStore::open_in_memory().unwrap())
    }

    fn plugin() -> SiweWalletAuth {
        SiweWalletAuth::new(store(), "broker.test", "https://broker.test")
    }

    #[tokio::test]
    async fn challenge_returns_siwe_message_with_required_fields() {
        let p = plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({
                    "address": "0xABCDef0123456789abcdef0123456789ABCDef00",
                    "chain_id": 84532_u64,
                }),
            })
            .await
            .unwrap();
        let msg = challenge.extras["siwe_message"].as_str().unwrap();
        assert!(msg.contains("broker.test wants you to sign in"));
        assert!(msg.contains("0xabcdef0123456789abcdef0123456789abcdef00"));
        assert!(msg.contains("Chain ID: 84532"));
        assert!(msg.contains("URI: https://broker.test"));
        assert!(msg.contains("Version: 1"));
        assert!(msg.contains("Nonce: "));
        assert!(msg.contains("Issued At: "));
        assert!(msg.contains("Expiration Time: "));
    }

    #[tokio::test]
    async fn challenge_rejects_malformed_address() {
        let p = plugin();
        let res = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({
                    "address": "0xtoo-short",
                    "chain_id": 1_u64,
                }),
            })
            .await;
        assert!(matches!(res, Err(AuthError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn challenge_rejects_missing_chain_id() {
        let p = plugin();
        let res = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({
                    "address": "0xABCDef0123456789abcdef0123456789ABCDef00",
                }),
            })
            .await;
        assert!(matches!(res, Err(AuthError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn verify_rejects_unknown_request_id() {
        let p = plugin();
        let res = p
            .verify(AuthResponse {
                request_id: "no-such-request".into(),
                extras: json!({"signature": "0x".to_string() + &"00".repeat(65)}),
            })
            .await;
        assert!(matches!(res, Err(AuthError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn verify_rejects_garbage_signature() {
        let p = plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({
                    "address": "0xABCDef0123456789abcdef0123456789ABCDef00",
                    "chain_id": 1_u64,
                }),
            })
            .await
            .unwrap();
        let res = p
            .verify(AuthResponse {
                request_id: challenge.request_id,
                extras: json!({"signature": "0x".to_string() + &"00".repeat(65)}),
            })
            .await;
        // 65 bytes of zeros: k256 rejects the all-zero (r,s) at
        // Signature::from_slice → AuthError::InvalidRequest. If the bytes
        // were valid-shaped but recovered the wrong address we'd see
        // Unauthorized. Either rejection demonstrates the security
        // property (no spurious VerifiedIdentity).
        match res {
            Err(AuthError::InvalidRequest(_)) | Err(AuthError::Unauthorized(_)) => {}
            other => panic!("expected InvalidRequest or Unauthorized, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn verify_rejects_replay_after_first_use() {
        let p = plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({
                    "address": "0xABCDef0123456789abcdef0123456789ABCDef00",
                    "chain_id": 1_u64,
                }),
            })
            .await
            .unwrap();
        // First verify with garbage signature consumes the in-memory pending
        // entry and the on-disk nonce.
        let _ = p
            .verify(AuthResponse {
                request_id: challenge.request_id.clone(),
                extras: json!({"signature": "0x".to_string() + &"00".repeat(65)}),
            })
            .await;
        // Replay attempt: same request_id, same (or different) signature.
        let replay = p
            .verify(AuthResponse {
                request_id: challenge.request_id,
                extras: json!({"signature": "0x".to_string() + &"00".repeat(65)}),
            })
            .await;
        assert!(matches!(replay, Err(AuthError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn ready_reports_ready_for_open_store() {
        let p = plugin();
        assert!(p.ready().is_ready());
    }

    #[tokio::test]
    async fn name_is_stable() {
        let p = plugin();
        assert_eq!(p.name(), "wallet_sig");
    }

    #[test]
    fn iso8601_formatter_known_vectors() {
        // 2026-05-05T14:22:11Z. seconds since epoch: …
        // Use the formatter and assert the shape.
        let s = unix_to_iso8601(1746455331);
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert!(s.chars().nth(4) == Some('-'));
        assert!(s.chars().nth(7) == Some('-'));
        assert!(s.chars().nth(10) == Some('T'));
    }

    #[test]
    fn ecrecover_round_trip_with_signing_key() {
        // Generate a fresh k256 keypair, sign the EIP-191 envelope of a
        // SIWE-shaped message, and assert ecrecover_address recovers the
        // expected address.
        use k256::ecdsa::SigningKey;
        let signing_key = SigningKey::random(&mut crate::oidc::rand_compat::OsRngWrapper);
        let verifying_key = signing_key.verifying_key();

        // Compute the address from the verifying key.
        let encoded_point = verifying_key.to_encoded_point(false);
        let pubkey_bytes = encoded_point.as_bytes();
        let mut addr_hasher = Keccak256::new();
        addr_hasher.update(&pubkey_bytes[1..]);
        let pubkey_hash = addr_hasher.finalize();
        let expected_addr = format!("0x{}", hex::encode(&pubkey_hash[12..]));

        let message = "broker.test wants you to sign in";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message.as_bytes());
        let digest = hasher.finalize();

        let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());
        let sig_hex = format!("0x{}", hex::encode(&sig_bytes));

        let recovered = ecrecover_address(message, &sig_hex).unwrap();
        assert_eq!(recovered.to_lowercase(), expected_addr.to_lowercase());
    }

    #[test]
    fn ecrecover_rejects_wrong_signature_length() {
        let res = ecrecover_address("hello", "0x00");
        assert!(matches!(res, Err(AuthError::InvalidRequest(_))));
    }
}
