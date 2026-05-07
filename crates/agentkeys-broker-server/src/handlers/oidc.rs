use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::audit::{MintOutcome, MintRecord};
use crate::auth::{extract_bearer_token, validate_bearer_token};
use crate::error::{BrokerError, BrokerResult};
use crate::state::SharedState;

/// `GET /.well-known/openid-configuration` — OIDC discovery doc.
///
/// Shaped to satisfy AWS IAM `create-open-id-connect-provider` and the
/// `sts:AssumeRoleWithWebIdentity` exchange. Mirrors the TS oidc-stub the
/// broker is replacing so existing test recipes keep working.
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
            "https://aws.amazon.com/tags",
        ],
    }))
}

/// `GET /.well-known/jwks.json` — JWK Set with our ES256 public key.
pub async fn jwks(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.oidc.jwks_json())
}

#[derive(serde::Serialize)]
pub struct MintOidcJwtResponse {
    pub jwt: String,
    pub wallet: String,
    pub expiration: i64,
}

/// `POST /v1/mint-oidc-jwt` — bearer-token in (validated against the session
/// backend), short-lived ES256 JWT out, suitable for `sts:AssumeRoleWithWebIdentity`.
///
/// Audited via the existing mint-audit log with a `oidc_jwt` outcome marker so
/// operators see one ledger for AWS-cred mints and OIDC-JWT mints.
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

    let session = match validate_bearer_token(&state.http, &state.config.backend_url, token).await {
        Ok(s) => s,
        Err(e) => {
            let outcome = match &e {
                BrokerError::Unauthorized(_) => MintOutcome::AuthFailed,
                _ => MintOutcome::BackendError,
            };
            let _ = state.audit.record_mint(
                MintRecord {
                    requester_token: token,
                    requester_wallet: "unknown",
                    requested_role: "oidc_jwt",
                    session_duration_seconds: state.config.oidc_jwt_ttl_seconds as i32,
                    sts_session_name: "(unauthenticated)",
                    outcome,
                },
                Some(&e.to_string()),
            );
            return Err(e);
        }
    };

    tracing::Span::current().record("wallet", session.wallet.as_str());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let exp = now + state.config.oidc_jwt_ttl_seconds as i64;

    // The `https://aws.amazon.com/tags` claim is what AWS STS reads to populate
    // session tags from the JWT. AWS does NOT auto-promote arbitrary OIDC claims
    // — the bare `agentkeys_user_wallet` claim alone produces an untagged session,
    // and `${aws:PrincipalTag/agentkeys_user_wallet}` in bucket policies expands
    // to empty. `transitive_tag_keys` ensures the tag persists across role chains
    // (e.g. assumed-role → assume-role).
    // Spec: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html#oidc-session-tags
    let claims = json!({
        "iss": state.config.oidc_issuer,
        "sub": format!("agentkeys:agent:{}", session.wallet),
        "aud": "sts.amazonaws.com",
        "iat": now,
        "exp": exp,
        "agentkeys_user_wallet": session.wallet,
        "https://aws.amazon.com/tags": {
            "principal_tags": {
                "agentkeys_user_wallet": [session.wallet],
            },
            "transitive_tag_keys": ["agentkeys_user_wallet"],
        },
    });

    let jwt = state.oidc.sign_jwt(&claims)?;

    state.audit.record_mint(
        MintRecord {
            requester_token: token,
            requester_wallet: &session.wallet,
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
        wallet: session.wallet,
        expiration: exp,
    }))
}
