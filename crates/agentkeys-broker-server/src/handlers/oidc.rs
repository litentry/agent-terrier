use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::audit::{MintOutcome, MintRecord};
use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::jwt::verify::verify_session_jwt;
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
            "agentkeys_actor_omni",
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

/// `POST /v1/mint-oidc-jwt` — session-JWT in, short-lived ES256 OIDC JWT out,
/// suitable for `sts:AssumeRoleWithWebIdentity`.
///
/// The bearer is a broker-signed session JWT (kid `ak-session-…`) minted by
/// `/v1/auth/wallet/verify`, `/v1/auth/email/verify`, `/v1/auth/oauth2/callback`,
/// or `/v1/auth/exchange`. Verified locally against the broker's session
/// keypair — no backend round-trip — matching the path `/v1/mint-aws-creds`
/// already takes (`handlers::mint::mint_v2`).
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

    let session_claims = match verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        token,
    ) {
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

    let wallet = session_claims.agentkeys.wallet_address;
    tracing::Span::current().record("wallet", wallet.as_str());

    let (claims, _now, exp) =
        build_oidc_jwt_claims(&state.config.oidc_issuer, &wallet, state.config.oidc_jwt_ttl_seconds);

    let jwt = state.oidc.sign_jwt(&claims)?;

    state.audit.record_mint(
        MintRecord {
            requester_token: token,
            requester_wallet: &wallet,
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
        wallet,
        expiration: exp,
    }))
}

/// Build the OIDC JWT claim set the broker signs for AWS STS
/// `AssumeRoleWithWebIdentity`. Returns `(claims, iat_unix, exp_unix)` so
/// callers can also use the timestamps for audit rows / response shaping.
///
/// Used by:
/// - `mint_oidc_jwt` (handler above) — public `/v1/mint-oidc-jwt` endpoint.
/// - `crate::handlers::mint::mint_v2` — internal JWT minted
///   per-call so the broker can do `AssumeRoleWithWebIdentity` itself
///   (issue #71 Option B).
///
/// The wallet is lowercased before being placed in the `principal_tags`
/// claim so it matches the lowercase prefixes the bucket policy uses
/// (`bots/${aws:PrincipalTag/agentkeys_user_wallet}/`); checksummed-mixed-
/// case wallets going in here would never match a lowercase resource ARN.
///
/// The `https://aws.amazon.com/tags` claim is what AWS STS reads to
/// populate session tags from the JWT. AWS does NOT auto-promote
/// arbitrary OIDC claims — the bare `agentkeys_user_wallet` claim alone
/// produces an untagged session, and
/// `${aws:PrincipalTag/agentkeys_user_wallet}` in bucket policies expands
/// to empty. `transitive_tag_keys` ensures the tag persists across role
/// chains. Spec:
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html#oidc-session-tags>
///
/// **v2 stage-1 (arch.md §14):** the JWT also carries
/// `agentkeys_actor_omni` — the wallet-independent stable anchor
/// `SHA256("agentkeys" || "evm" || wallet_lc)`. Both keys appear under
/// `principal_tags` and `transitive_tag_keys` during the migration
/// window so v1 bucket policies (keyed on `agentkeys_user_wallet`) and
/// v2 bucket policies (keyed on `agentkeys_actor_omni`) both work. Once
/// every cloud is migrated to v2 (per `bucket-policy-v2-migrate.sh`),
/// v1 can be retired from the claim set.
pub(crate) fn build_oidc_jwt_claims(
    issuer: &str,
    wallet: &str,
    ttl_seconds: u64,
) -> (serde_json::Value, i64, i64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let exp = now + ttl_seconds as i64;
    let wallet_lc = wallet.to_lowercase();
    // v2 actor_omni = SHA256("agentkeys" || "evm" || wallet_lc). Lives in
    // `crate::identity::omni_account::derive_omni_account` so the broker
    // never reimplements the hash — same function the storage layer uses
    // when keying identity-link rows on omni.
    let actor_omni =
        crate::identity::omni_account::derive_omni_account("evm", &wallet_lc).to_string();

    let claims = json!({
        "iss": issuer,
        "sub": format!("agentkeys:agent:{}", wallet_lc),
        "aud": "sts.amazonaws.com",
        "iat": now,
        "exp": exp,
        "agentkeys_user_wallet": wallet_lc,
        "agentkeys_actor_omni": actor_omni,
        "https://aws.amazon.com/tags": {
            "principal_tags": {
                "agentkeys_user_wallet": [wallet_lc],
                "agentkeys_actor_omni": [actor_omni],
            },
            "transitive_tag_keys": [
                "agentkeys_user_wallet",
                "agentkeys_actor_omni",
            ],
        },
    });

    (claims, now, exp)
}
