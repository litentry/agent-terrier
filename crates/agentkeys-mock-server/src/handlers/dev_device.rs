//! #552 — DELEGATE K10 device-domain signer endpoints.
//!
//! The delegate's K10 is DERIVED (never stored) from its `actor_omni` under
//! the `agentkeys-k10-device` HKDF domain (`dev_key_service`), so the signer
//! custodies every delegate key with zero per-key state. Two endpoints:
//!
//! - `POST /dev/derive-device` — address + `device_key_hash` + a fresh
//!   `pop_sig` over the canonical agent-pop payload (the signer computes the
//!   payload ITSELF — no caller-supplied message exists on this route).
//!   Two authorization arms: the ACTOR's own J1 (`jwt.omni == actor_omni`),
//!   or the MASTER's J1 plus the delegate `label` proving HDKD parentage
//!   (`child_omni_hex(jwt.omni, label) == actor_omni`) — the arm the #427
//!   spawn-build uses, since the master IS the authority over its children.
//! - `POST /dev/sign-device-cap-pop` — the #76 cap-mint proof-of-possession.
//!   ACTOR arm only. The caller sends the STRUCTURED fields and the signer
//!   recomputes `cap_pop_payload(...)` itself — never a caller prehash (the
//!   same rule the EIP-712 route follows), so this key can only ever sign
//!   the two domain-restricted payload shapes, never arbitrary messages.
//!
//! **Fail-closed auth (unlike the legacy `/dev/*` routes):** when no broker
//! session pubkey is loaded these endpoints refuse with 503
//! `signer_auth_not_configured` — device signatures mint on-chain-bindable
//! identity, so a "skip auth in legacy mode" arm is unacceptable here.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use agentkeys_core::device_crypto::{agent_pop_payload, cap_pop_payload, device_key_hash};

use crate::dev_key_service::KEY_VERSION;
use crate::handlers::dev_keys::{
    signer_disabled, signer_error, verify_session_jwt_claims, VerifiedSession,
};
use crate::state::SharedState;

#[derive(Deserialize)]
pub struct DeriveDeviceRequest {
    /// The delegate's HDKD child omni (64 hex, `0x` optional).
    pub actor_omni: String,
    /// The delegate's label — REQUIRED for the master arm (it is the HDKD
    /// parentage proof); ignored when the bearer IS the actor.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Deserialize)]
pub struct SignDeviceCapPopRequest {
    pub actor_omni: String,
    pub operator_omni: String,
    pub service: String,
    pub op: String,
    pub data_class: String,
    pub client_nonce: String,
    pub client_ts: u64,
}

fn norm(omni: &str) -> String {
    omni.trim().trim_start_matches("0x").to_lowercase()
}

/// Pure authorization over VERIFIED claims (unit-testable without JWTs):
/// the bearer is the actor itself, or the actor's HDKD parent proving
/// parentage via the label.
pub(crate) fn actor_authorized(
    claims: &VerifiedSession,
    actor_omni: &str,
    label: Option<&str>,
) -> bool {
    let actor = norm(actor_omni);
    let jwt_omni = norm(&claims.omni_account);
    if !jwt_omni.is_empty() && jwt_omni == actor {
        return true;
    }
    if let Some(label) = label {
        if let Ok(child) = agentkeys_core::actor_omni::child_omni_hex(&jwt_omni, label) {
            return norm(&child) == actor;
        }
    }
    false
}

/// The fail-closed gate shared by both device endpoints.
fn authorize(
    state: &SharedState,
    headers: &HeaderMap,
    actor_omni: &str,
    label: Option<&str>,
) -> Result<(), (StatusCode, Json<Value>)> {
    match verify_session_jwt_claims(state, headers)? {
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error":   "signer_auth_not_configured",
                "message": "device-domain endpoints refuse without a broker session pubkey \
                            (fail-closed — start the signer with --broker-session-pubkey-path)",
            })),
        )),
        Some(claims) if actor_authorized(&claims, actor_omni, label) => Ok(()),
        Some(_) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error":   "actor_not_authorized",
                "message": "bearer JWT is neither the actor nor (with `label`) its HDKD parent",
            })),
        )),
    }
}

/// `POST /dev/derive-device` (#552).
pub async fn derive_device(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<DeriveDeviceRequest>,
) -> impl IntoResponse {
    if let Err(e) = authorize(&state, &headers, &body.actor_omni, body.label.as_deref()) {
        return e.into_response();
    }
    let Some(signer) = state.dev_signer.as_ref() else {
        return signer_disabled().into_response();
    };
    let actor = norm(&body.actor_omni);
    let address = match signer.derive_device_address(&actor) {
        Ok(a) => a,
        Err(e) => return signer_error(e).into_response(),
    };
    let dkh = match device_key_hash(&address) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal", "message": format!("device_key_hash: {e}") })),
            )
                .into_response();
        }
    };
    // The pop payload is computed HERE from the derived address — this route
    // never signs caller-supplied bytes.
    let pop = match signer.sign_device_eip191(&actor, &agent_pop_payload(&dkh)) {
        Ok((sig, _)) => sig,
        Err(e) => return signer_error(e).into_response(),
    };
    (
        StatusCode::OK,
        Json(json!({
            "address":         address,
            "device_key_hash": dkh,
            "pop_sig":         pop,
            "key_version":     KEY_VERSION,
        })),
    )
        .into_response()
}

/// `POST /dev/sign-device-cap-pop` (#552 — the #76 PoP, actor-J1-gated).
pub async fn sign_device_cap_pop(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SignDeviceCapPopRequest>,
) -> impl IntoResponse {
    if let Err(e) = authorize(&state, &headers, &body.actor_omni, None) {
        return e.into_response();
    }
    let Some(signer) = state.dev_signer.as_ref() else {
        return signer_disabled().into_response();
    };
    let actor = norm(&body.actor_omni);
    // Recompute the digest from the structured fields — never trust a
    // caller-supplied prehash (spec rule shared with /dev/sign-typed-data).
    let digest = cap_pop_payload(
        &body.operator_omni,
        &actor,
        &body.service,
        &body.op,
        &body.data_class,
        &body.client_nonce,
        body.client_ts,
    );
    let (signature, address) = match signer.sign_device_eip191(&actor, &digest) {
        Ok(r) => r,
        Err(e) => return signer_error(e).into_response(),
    };
    let dkh = device_key_hash(&address).unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "signature":       signature,
            "address":         address,
            "device_key_hash": dkh,
            "key_version":     KEY_VERSION,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(omni: &str) -> VerifiedSession {
        VerifiedSession {
            omni_account: omni.to_string(),
            parent_omni: None,
            device_pubkey: None,
        }
    }

    #[test]
    fn actor_arm_matches_normalized_omni() {
        let actor = "AB".repeat(32);
        assert!(actor_authorized(
            &claims(&actor.to_lowercase()),
            &format!("0x{actor}"),
            None
        ));
        assert!(!actor_authorized(&claims(&"cd".repeat(32)), &actor, None));
    }

    #[test]
    fn master_arm_requires_the_parentage_proving_label() {
        let master = "22".repeat(32);
        let child = agentkeys_core::actor_omni::child_omni_hex(&master, "cook").unwrap();
        // Master J1 + the right label → authorized for the CHILD's device key.
        assert!(actor_authorized(&claims(&master), &child, Some("cook")));
        // Wrong label derives a different child → refused.
        assert!(!actor_authorized(&claims(&master), &child, Some("clean")));
        // No label → the master arm never fires (no ambient parent authority).
        assert!(!actor_authorized(&claims(&master), &child, None));
        // A NON-parent with the same label derives elsewhere → refused.
        assert!(!actor_authorized(
            &claims(&"33".repeat(32)),
            &child,
            Some("cook")
        ));
    }
}
