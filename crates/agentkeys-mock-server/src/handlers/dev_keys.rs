//! HTTP handlers for the dev_key_service signer.
//!
//! See `docs/spec/signer-protocol.md` for the wire contract. Both endpoints
//! return 503 `signer_disabled` when `state.dev_signer` is `None`
//! (i.e. `DEV_KEY_SERVICE_MASTER_SECRET` was unset at boot). When enabled,
//! they delegate to `DevKeyService` for derivation/signing.
//!
//! JWT bearer auth: when `state.broker_session_pubkey` is `Some`, every request
//! MUST carry `Authorization: Bearer <jwt>` signed by the broker's session keypair.
//! The JWT's `agentkeys.omni_account` claim MUST match the request body's
//! `omni_account` field. When the pubkey is `None` (legacy/test mode), auth
//! is skipped.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{decode, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dev_key_service::{SignerError, KEY_VERSION};
use crate::state::SharedState;

#[derive(Deserialize)]
pub struct DeriveAddressRequest {
    pub omni_account: String,
}

#[derive(Deserialize)]
pub struct SignMessageRequest {
    pub omni_account: String,
    pub message_hex: String,
}

/// Issue #82 — typed-data sign request. `typed_data` carries the canonical
/// EIP-712 v4 JSON shape (matches MetaMask `eth_signTypedData_v4`).
#[derive(Deserialize)]
pub struct SignTypedDataRequest {
    pub omni_account: String,
    pub typed_data: agentkeys_core::clear_signing::TypedData,
}

/// Minimal JWT claims we care about for verification.
#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    exp: u64,
    agentkeys: AgentKeysClaims,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentKeysClaims {
    omni_account: String,
    /// Agent J1 only (#144): the master omni this child was HDKD-derived from.
    #[serde(default)]
    parent_omni: Option<String>,
    /// Agent J1 only: the K10 device address whose pop_sig redeemed the link
    /// code. #513's chain gate re-checks this binding on chain.
    #[serde(default)]
    device_pubkey: Option<String>,
}

/// Claims the signer trusts after JWT verification (#512/#513): the actor, and
/// — agent sessions only — the lineage fields the chain gate re-verifies.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSession {
    pub omni_account: String,
    pub parent_omni: Option<String>,
    pub device_pubkey: Option<String>,
}

/// Verify the bearer JWT (ES256 signature + expiry + `agentkeys:broker`
/// audience) and return its verified `agentkeys` claims. `Ok(None)` = auth
/// disabled (no broker pubkey loaded — legacy/test mode). #512's `sign-sts`
/// reads the actor FROM these claims; the body-omni cross-check wrapper below
/// keeps the historical `/dev/*` contract byte-identical.
pub(crate) fn verify_session_jwt_claims(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<Option<VerifiedSession>, (StatusCode, Json<Value>)> {
    let Some(decoding_key) = state.broker_session_pubkey.as_ref() else {
        return Ok(None);
    };

    let token = extract_bearer(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error":   "unauthorized",
                "message": "missing Authorization: Bearer <jwt> header",
            })),
        )
    })?;

    // The signer doesn't know the broker's issuer URL — validate sig + exp +
    // audience only; the broker already validated iss when it minted the token.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["agentkeys:broker"]);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "aud"]);

    let token_data = decode::<SessionClaims>(token, decoding_key, &validation).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error":   "unauthorized",
                "message": format!("invalid session JWT: {e}"),
            })),
        )
    })?;

    let c = token_data.claims.agentkeys;
    Ok(Some(VerifiedSession {
        omni_account: c.omni_account,
        parent_omni: c.parent_omni,
        device_pubkey: c.device_pubkey,
    }))
}

/// Verify the bearer JWT and assert `claims.agentkeys.omni_account == body_omni`.
/// Returns `Ok(())` on success.
/// Returns `Err((StatusCode::UNAUTHORIZED, Json(...)))` on any failure.
///
/// Skipped entirely when `state.broker_session_pubkey` is `None`.
fn verify_session_jwt(
    state: &SharedState,
    headers: &HeaderMap,
    body_omni: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    match verify_session_jwt_claims(state, headers)? {
        None => Ok(()),
        Some(sess) if sess.omni_account == body_omni => Ok(()),
        Some(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error":   "unauthorized",
                "message": "JWT omni_account claim does not match request body",
            })),
        )),
    }
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(str::trim)
}

pub async fn derive_address(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<DeriveAddressRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_session_jwt(&state, &headers, &body.omni_account) {
        return e.into_response();
    }
    let Some(signer) = state.dev_signer.as_ref() else {
        return signer_disabled().into_response();
    };
    match signer.derive_address(&body.omni_account) {
        Ok(address) => (
            StatusCode::OK,
            Json(json!({
                "address":     address,
                "key_version": KEY_VERSION,
            })),
        )
            .into_response(),
        Err(e) => signer_error(e).into_response(),
    }
}

pub async fn sign_message(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SignMessageRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_session_jwt(&state, &headers, &body.omni_account) {
        return e.into_response();
    }
    let Some(signer) = state.dev_signer.as_ref() else {
        return signer_disabled().into_response();
    };

    let message_bytes = match hex::decode(body.message_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(e) => {
            return signer_error(SignerError::InvalidMessageHex(format!(
                "not valid hex: {e}"
            )))
            .into_response();
        }
    };

    match signer.sign_eip191(&body.omni_account, &message_bytes) {
        Ok((signature, address)) => (
            StatusCode::OK,
            Json(json!({
                "signature":   signature,
                "address":     address,
                "key_version": KEY_VERSION,
            })),
        )
            .into_response(),
        Err(e) => signer_error(e).into_response(),
    }
}

/// Issue #82 — typed-data sign handler. Mirrors `sign_message` for the JWT
/// auth + signer-disabled paths; on success returns the signature + every
/// digest the signer computed internally (so the caller can cross-reference
/// against an ERC-7730 metadata file for audit).
pub async fn sign_typed_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SignTypedDataRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_session_jwt(&state, &headers, &body.omni_account) {
        return e.into_response();
    }
    let Some(signer) = state.dev_signer.as_ref() else {
        return signer_disabled().into_response();
    };

    match signer.sign_eip712(&body.omni_account, body.typed_data) {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "signature":         result.signature,
                "address":           result.address,
                "primary_type_hash": result.primary_type_hash,
                "domain_separator":  result.domain_separator,
                "digest":            result.digest,
                "key_version":       KEY_VERSION,
            })),
        )
            .into_response(),
        Err(e) => signer_error(e).into_response(),
    }
}

pub(crate) fn signer_disabled() -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error":   "signer_disabled",
            "message": "dev_key_service disabled — set DEV_KEY_SERVICE_MASTER_SECRET to enable",
        })),
    )
}

pub(crate) fn signer_error(e: SignerError) -> (StatusCode, Json<Value>) {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(json!({
            "error":   e.code(),
            "message": e.to_string(),
        })),
    )
}
