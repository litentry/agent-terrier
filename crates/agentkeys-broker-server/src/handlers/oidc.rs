use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use serde_json::json;

use crate::audit::{MintOutcome, MintRecord};
use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::jwt::verify::verify_session_jwt;
use crate::state::SharedState;

/// `GET /.well-known/openid-configuration` — OIDC discovery doc.
///
pub async fn discovery(State(state): State<SharedState>) -> impl IntoResponse {
    let issuer = &state.config.oidc_issuer;
    Json(json!({
        "issuer": issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["openid"],
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_supported": [
            "iss",
            "sub",
            "aud",
            "iat",
            "exp",
            "nbf",
            "agentkeys_attested_at",
            "agentkeys_enclave_tier",
            "agentkeys_child_wallet",
            "agentkeys_grant_id",
            "agentkeys_operation",
            "agentkeys_user_wallet",
            "agentkeys_actor_omni",
        ],
    }))
}

/// `GET /.well-known/jwks.json` — JWK Set with our ES256 public key.
pub async fn jwks(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.oidc.jwks_json())
}

pub use agentkeys_protocol::auth::OidcJwtResponse as MintOidcJwtResponse;

/// `POST /v1/mint-oidc-jwt` — session-JWT in, short-lived ES256 OIDC JWT out,
/// for the explicitly configured audience.
///
/// The bearer is a broker-signed session JWT (kid `ak-session-…`) minted by
/// `/v1/auth/wallet/verify`, `/v1/auth/email/verify`, or
/// `/v1/auth/oauth2/callback`. Verified locally against the broker's session
/// keypair — no backend round-trip.
///
/// Audited via the existing mint-audit log with a `oidc_jwt` outcome marker so
/// identity-token issuance remains observable.
#[tracing::instrument(skip_all, fields(wallet = tracing::field::Empty, outcome = tracing::field::Empty))]
pub async fn mint_oidc_jwt(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> BrokerResult<Json<MintOidcJwtResponse>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;

    let session_claims =
        match verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, token) {
            Ok(c) => c,
            Err(e) => {
                let _ = state.audit.record_mint(
                    MintRecord {
                        requester_token: token,
                        requester_wallet: "unknown",
                        requested_role: "oidc_jwt",
                        session_duration_seconds: state.config.oidc_jwt_ttl_seconds as i32,
                        sts_session_name: "(unauthenticated)",
                        outcome: MintOutcome::AuthFailed,
                    },
                    Some(&e.to_string()),
                );
                return Err(e);
            }
        };

    // Identity comes from the verified session, not a caller-supplied wallet.
    let wallet = session_claims.agentkeys.wallet_address;
    let actor_omni = session_claims.agentkeys.omni_account;
    let report_id = if wallet.is_empty() {
        actor_omni.clone()
    } else {
        wallet.clone()
    };
    tracing::Span::current().record("wallet", report_id.as_str());

    // Pre-binding agent sessions cannot issue usable identity tokens.
    if let Some(device_pubkey) = session_claims.agentkeys.device_pubkey.as_deref() {
        use crate::handlers::cap::{call_get_device, ChainContracts, ROLE_CAP_MINT};
        // Mirror the FULL cap-mint invariant (cap.rs verify_chain): the device must
        // be active AND bound to BOTH the session's operator (parent_omni) and actor
        // (omni_account), with the CAP_MINT role. Checking only actor would let any
        // OTHER registered operator bind (this device hash, this actor) and pass the
        // gate, bypassing the master that issued the link code.
        let parent_omni = session_claims
            .agentkeys
            .parent_omni
            .as_deref()
            .unwrap_or("");
        let chain = ChainContracts::from_state(&state)
            .map_err(|e| BrokerError::Internal(format!("chain config for agent gate: {e:?}")))?;
        let dkh = agentkeys_core::device_crypto::device_key_hash(device_pubkey).map_err(|e| {
            BrokerError::BadRequest(format!("bad device_pubkey in session claim: {e}"))
        })?;
        let device = call_get_device(&state.http, &chain.rpc_url, &chain.registry, &dkh)
            .await
            .map_err(|e| BrokerError::Internal(format!("on-chain device read: {e:?}")))?;
        let norm = |s: &str| s.trim_start_matches("0x").to_lowercase();
        let denied: Option<&str> = if parent_omni.is_empty() {
            Some("agent session missing parent_omni lineage — cannot verify operator binding")
        } else if device.registered_at == 0 || device.revoked {
            Some("agent device not active on-chain — the master must registerAgentDevice (bind) before this agent can mint identity tokens")
        } else if norm(&device.operator_omni) != norm(parent_omni) {
            Some("on-chain device operator_omni does not match the agent session's parent_omni")
        } else if norm(&device.actor_omni) != norm(&actor_omni) {
            Some("on-chain device actor_omni does not match the session omni")
        } else if (device.roles & ROLE_CAP_MINT) == 0 {
            Some("on-chain device lacks the CAP_MINT role")
        } else {
            None
        };
        if let Some(reason) = denied {
            let _ = state.audit.record_mint(
                MintRecord {
                    requester_token: token,
                    requester_wallet: &report_id,
                    requested_role: "oidc_jwt",
                    session_duration_seconds: state.config.oidc_jwt_ttl_seconds as i32,
                    sts_session_name: "(agent-not-active)",
                    outcome: MintOutcome::AuthFailed,
                },
                Some(reason),
            );
            tracing::Span::current().record("outcome", "agent_not_active");
            return Err(BrokerError::Forbidden(reason.into()));
        }
    }

    let (claims, _now, exp) = build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &actor_omni,
        &wallet,
        state.config.oidc_jwt_ttl_seconds,
        &state.config.oidc_audience,
    );

    let jwt = state.oidc.sign_jwt(&claims)?;

    state.audit.record_mint(
        MintRecord {
            requester_token: token,
            requester_wallet: &report_id,
            requested_role: "oidc_jwt",
            session_duration_seconds: state.config.oidc_jwt_ttl_seconds as i32,
            sts_session_name: &state.oidc.kid,
            outcome: MintOutcome::Ok,
        },
        None,
    )?;
    tracing::Span::current().record("outcome", "ok");

    Ok(Json(MintOidcJwtResponse {
        jwt,
        wallet: report_id,
        expiration: exp,
    }))
}

/// Build identity claims from a verified session for one configured audience.
pub(crate) fn build_oidc_jwt_claims(
    issuer: &str,
    actor_omni: &str,
    wallet: &str,
    ttl_seconds: u64,
    oidc_audience: &str,
) -> (serde_json::Value, i64, i64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let exp = now + ttl_seconds as i64;
    let wallet_lc = wallet.to_lowercase();
    let actor_omni = actor_omni.trim().trim_start_matches("0x").to_lowercase();
    let actor_omni = actor_omni.as_str();
    let user_wallet = if wallet_lc.is_empty() {
        actor_omni
    } else {
        wallet_lc.as_str()
    };

    let claims = json!({
        "iss": issuer,
        "sub": format!("agentkeys:agent:{}", user_wallet),
        "aud": oidc_audience,
        "iat": now,
        "exp": exp,
        "agentkeys_user_wallet": user_wallet,
        "agentkeys_actor_omni": actor_omni,
    });

    (claims, now, exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_claims_are_normalized_and_bound_to_the_configured_audience() {
        let actor = "ab".repeat(32);
        for wallet in ["", "synthetic-wallet"] {
            let (claims, issued, expires) = build_oidc_jwt_claims(
                "https://issuer.example",
                &format!("0x{}", actor.to_uppercase()),
                wallet,
                300,
                "https://relying-party.example",
            );
            assert_eq!(claims["iss"], "https://issuer.example");
            assert_eq!(claims["aud"], "https://relying-party.example");
            assert_eq!(claims["agentkeys_actor_omni"], actor);
            let reported = if wallet.is_empty() {
                actor.as_str()
            } else {
                wallet
            };
            assert_eq!(claims["agentkeys_user_wallet"], reported);
            assert_eq!(claims["sub"], format!("agentkeys:agent:{reported}"));
            assert_eq!(expires - issued, 300);
            let mut keys = claims
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "agentkeys_actor_omni",
                    "agentkeys_user_wallet",
                    "aud",
                    "exp",
                    "iat",
                    "iss",
                    "sub"
                ]
            );
        }
    }
}
