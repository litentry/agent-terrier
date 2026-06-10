//! `POST /v1/auth/passkey/start` — passkey re-auth challenge (issue #242).
//!
//! The master re-login verb: after a logout (or an expired J1) the operator's
//! BOUND K11 passkey signs a fresh broker challenge, and the CHAIN — the
//! `SidecarRegistry.operatorMasterWallet[omni]` P256Account + its live signer
//! set — is the credential registry the broker verifies against in
//! `/v1/auth/passkey/verify`. No email round-trip: the session JWT this flow
//! mints is scoped to the chain-verified omni and to nothing else, so the verb
//! can never escalate across identities (you only get a J1 for an omni whose
//! on-chain master passkey you control).
//!
//! Body: `{ "omni_account": "0x<64 hex>" }`.
//! Returns `{ "challenge": "0x<64 hex>", "expires_in_seconds", "account" }`.
//!
//! The challenge doubles as the verify-time lookup key: it lands in
//! [`AuthNonceStore`](crate::storage::AuthNonceStore) (single-use, TTL'd — the
//! SIWE-nonce posture) with the omni bound in the `address` column under a
//! `passkey:` prefix so a SIWE nonce can never be consumed through
//! passkey/verify or vice versa.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::BrokerError;
use crate::handlers::accept::{
    call_operator_master_wallet, eth_address_has_code, load_chain_read_config,
};
use crate::state::SharedState;

/// Challenge lifetime: long enough for one Touch ID prompt, short enough that
/// a leaked challenge goes stale fast.
pub(crate) const PASSKEY_CHALLENGE_TTL_SECS: i64 = 120;

/// `address`-column prefix binding a nonce row to this flow (cross-protocol
/// nonce-reuse guard vs the SIWE rows sharing the table).
pub(crate) const PASSKEY_NONCE_PREFIX: &str = "passkey:";

#[derive(Debug, Deserialize)]
pub struct PasskeyStartRequest {
    pub omni_account: String,
}

/// Normalize + validate a `0x<64 hex>` omni → lowercase `0x`-prefixed form.
pub(crate) fn parse_omni_0x64(s: &str) -> Result<String, BrokerError> {
    let h = s.trim().trim_start_matches("0x").to_lowercase();
    if h.len() != 64 || hex::decode(&h).is_err() {
        return Err(BrokerError::BadRequest(
            "omni_account must be 0x + 64 hex".into(),
        ));
    }
    Ok(format!("0x{h}"))
}

pub(crate) fn now_unix_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn passkey_start(
    State(state): State<SharedState>,
    Json(body): Json<PasskeyStartRequest>,
) -> Result<impl IntoResponse, BrokerError> {
    let omni = parse_omni_0x64(&body.omni_account)?;

    // Chain probe: the omni must have a DEPLOYED P256Account master (mirrors
    // accept_build's guard — an EOA master predates the passkey model and has
    // no signer set to re-auth against).
    let (rpc_url, registry) = load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    let account = call_operator_master_wallet(&state.http, &rpc_url, &registry, &omni)
        .await
        .map_err(BrokerError::BackendUnreachable)?;
    if account == [0u8; 20] {
        return Err(BrokerError::BadRequest(
            "no master account on chain for this omni — onboard via email first".into(),
        ));
    }
    if !eth_address_has_code(&state.http, &rpc_url, &account)
        .await
        .map_err(BrokerError::BackendUnreachable)?
    {
        return Err(BrokerError::BadRequest(
            "operator master is a legacy EOA, not a passkey P256Account — passkey re-auth \
             requires the smart-account master; re-onboard via email"
                .into(),
        ));
    }

    // Mint + store the single-use challenge.
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge)
        .map_err(|e| BrokerError::Internal(format!("challenge rng: {e}")))?;
    let challenge_hex = format!("0x{}", hex::encode(challenge));
    let now = now_unix_i64();
    state
        .nonce_store
        .issue(
            &challenge_hex,
            &format!("{PASSKEY_NONCE_PREFIX}{omni}"),
            now,
            now + PASSKEY_CHALLENGE_TTL_SECS,
        )
        .map_err(|e| BrokerError::Internal(format!("store passkey challenge: {e:?}")))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "challenge":          challenge_hex,
            "expires_in_seconds": PASSKEY_CHALLENGE_TTL_SECS,
            "account":            format!("0x{}", hex::encode(account)),
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_omni_normalizes_and_rejects_garbage() {
        let ok = parse_omni_0x64(&format!("0x{}", "AB".repeat(32))).unwrap();
        assert_eq!(ok, format!("0x{}", "ab".repeat(32)));
        // bare (no 0x) is accepted + normalized
        assert_eq!(
            parse_omni_0x64(&"cd".repeat(32)).unwrap(),
            format!("0x{}", "cd".repeat(32))
        );
        assert!(parse_omni_0x64("0x1234").is_err(), "too short");
        assert!(
            parse_omni_0x64(&format!("0x{}zz", "ab".repeat(31))).is_err(),
            "non-hex"
        );
        assert!(parse_omni_0x64("").is_err());
    }
}
