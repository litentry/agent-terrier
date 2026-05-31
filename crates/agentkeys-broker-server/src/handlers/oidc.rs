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
/// `/v1/auth/wallet/verify`, `/v1/auth/email/verify`, or
/// `/v1/auth/oauth2/callback`. Verified locally against the broker's session
/// keypair — no backend round-trip.
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

    // The actor_omni is read VERBATIM from the verified (broker-signed) session
    // claim — never re-derived from a wallet (issue #144). A J1_agent has no
    // wallet, so re-deriving would yield an empty/garbage tag → STS creds scoped
    // to the wrong prefix → worker 403. For wallet/master sessions the claim
    // equals the old re-derived value, so this is byte-identical for them.
    let wallet = session_claims.agentkeys.wallet_address;
    let actor_omni = session_claims.agentkeys.omni_account;
    // Report id for audit/span/response: the wallet for master sessions, the
    // actor_omni for agents (no wallet). Drives the STS session name downstream.
    let report_id = if wallet.is_empty() {
        actor_omni.clone()
    } else {
        wallet.clone()
    };
    tracing::Span::current().record("wallet", report_id.as_str());

    // Finding 1 (adversarial review of #149): an agent_hdkd session (device_pubkey
    // present, wallet empty) must NOT mint STS-capable OIDC JWTs until its device is
    // bound on-chain. J1_agent is minted at link-code redeem (PRE-binding), so
    // without this gate a redeemed-but-unapproved agent could AssumeRoleWithWebIdentity
    // to its own actor prefix BEFORE the master's registerAgentDevice + scope grant.
    // Wallet/master sessions (no device_pubkey) are the operator's own and unaffected.
    // Same on-chain check the cap-mint path uses (SidecarRegistry.getDevice).
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
            Some("agent device not active on-chain — the master must registerAgentDevice (bind) before this agent can mint OIDC/STS credentials")
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

/// Build the OIDC JWT claim set the broker signs for AWS STS
/// `AssumeRoleWithWebIdentity`. Returns `(claims, iat_unix, exp_unix)` so
/// callers can also use the timestamps for audit rows / response shaping.
///
/// Used by `mint_oidc_jwt` (handler above) — public `/v1/mint-oidc-jwt` endpoint.
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
    actor_omni: &str,
    wallet: &str,
    ttl_seconds: u64,
) -> (serde_json::Value, i64, i64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let exp = now + ttl_seconds as i64;
    let wallet_lc = wallet.to_lowercase();
    // `actor_omni` is supplied VERBATIM from the verified session claim (issue
    // #144) — the broker signed it at session-mint time, so it's trusted and is
    // NOT re-derived here. For a wallet/master session it equals
    // SHA256("agentkeys"||"evm"||wallet_lc) (what the old code computed); for an
    // agent J1 it is the HDKD child omni. The v1 `agentkeys_user_wallet` tag
    // falls back to the actor_omni when there's no wallet so it's never empty
    // (a v1 policy keyed on it then resolves to the same `bots/<actor>/` prefix).
    let user_wallet = if wallet_lc.is_empty() {
        actor_omni
    } else {
        wallet_lc.as_str()
    };

    let claims = json!({
        "iss": issuer,
        "sub": format!("agentkeys:agent:{}", user_wallet),
        "aud": "sts.amazonaws.com",
        "iat": now,
        "exp": exp,
        "agentkeys_user_wallet": user_wallet,
        "agentkeys_actor_omni": actor_omni,
        "https://aws.amazon.com/tags": {
            "principal_tags": {
                "agentkeys_user_wallet": [user_wallet],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::omni_account::derive_omni_account;

    #[test]
    fn wallet_session_oidc_tags_unchanged_after_144() {
        // Regression: for a wallet/master session the actor_omni read from the
        // claim EQUALS the value the old code re-derived from the wallet, so the
        // OIDC tag set is byte-identical to pre-#144.
        let wallet = "0xAbCdEf0123456789abcdef0123456789ABCDef00";
        let wallet_lc = wallet.to_lowercase();
        let actor_omni = derive_omni_account("evm", &wallet_lc).to_string();
        let (claims, _n, _e) = build_oidc_jwt_claims("https://issuer", &actor_omni, wallet, 300);
        assert_eq!(claims["agentkeys_actor_omni"], actor_omni);
        assert_eq!(claims["agentkeys_user_wallet"], wallet_lc);
        assert_eq!(claims["sub"], format!("agentkeys:agent:{wallet_lc}"));
        let tags = &claims["https://aws.amazon.com/tags"]["principal_tags"];
        assert_eq!(tags["agentkeys_actor_omni"][0], actor_omni);
        assert_eq!(tags["agentkeys_user_wallet"][0], wallet_lc);
    }

    #[test]
    fn agent_session_tags_carry_hdkd_omni_and_no_empty_wallet() {
        // Agent J1: HDKD child omni, empty wallet → the actor tag IS the HDKD
        // omni (so STS scopes creds to bots/<child>/...), and the v1 user_wallet
        // tag falls back to the omni rather than being empty.
        let child = "a".repeat(64);
        let (claims, _n, _e) = build_oidc_jwt_claims("https://issuer", &child, "", 300);
        assert_eq!(claims["agentkeys_actor_omni"], child);
        assert_eq!(claims["agentkeys_user_wallet"], child);
        assert_eq!(claims["sub"], format!("agentkeys:agent:{child}"));
        let tags = &claims["https://aws.amazon.com/tags"]["principal_tags"];
        assert_eq!(tags["agentkeys_actor_omni"][0], child);
    }
}
