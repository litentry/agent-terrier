//! `POST /v1/cap/canonical-sts` — broker-brokered scoped STS for a delegated
//! canonical-memory READ (#295 P1 §7a; the Codex-flagged critical fix).
//!
//! ## Why this exists
//! The earlier P1 path had the DELEGATE relay operator-tagged STS minted from the
//! *operator's session bearer*. That meant a delegate process holding the operator
//! bearer had FULL operator authority — the client-side read-only session policy
//! was only a convention it could bypass (re-mint unscoped operator STS). This
//! endpoint removes the operator bearer from the delegate entirely:
//!
//! 1. The delegate authenticates with its OWN session JWT (not the operator's).
//! 2. It presents the `CanonicalFetch` cap the broker already minted for it
//!    (operator=master, actor=delegate, service=`memory:<ns>`), which the broker
//!    only mints AFTER the on-chain `memory:<ns>` grant check.
//! 3. The broker re-verifies the cap (its own `broker_sig`, op, data class,
//!    freshness, and that the cap's `actor_omni` == the authenticated session —
//!    so a delegate can only redeem ITS OWN cap), mints an OPERATOR-tagged OIDC
//!    JWT **internally** (never handed out), and `AssumeRole`s the memory role
//!    with an inline session policy scoped to `s3:GetObject` on the EXACT object
//!    `bots/<operator>/memory/<ns>.enc` (read-only, single object).
//! 4. The delegate receives ONLY those narrow creds — it can read the one granted
//!    object and nothing else: no write/delete (closes finding 1), no other
//!    namespace of the master (closes finding 2), and no reusable operator bearer.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::handlers::cap::{verify_cap_payload_sig, CapOp, CapToken, DataClass};
use crate::handlers::oidc::build_oidc_jwt_claims;
use crate::jwt::verify::verify_session_jwt;
use crate::state::SharedState;

#[derive(Deserialize)]
pub struct CanonicalStsRequest {
    /// The broker-minted `CanonicalFetch`/`Memory` cap for this delegate.
    pub cap: CapToken,
}

#[derive(Serialize)]
pub struct CanonicalStsResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
}

pub async fn mint_canonical_sts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CanonicalStsRequest>,
) -> BrokerResult<Json<CanonicalStsResponse>> {
    // 1. Authenticate the DELEGATE via its OWN session (never the operator's).
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    let session = verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, token)?;
    let session_omni = session.agentkeys.omni_account;

    // 2. Config gate (back-compat: a broker without MEMORY_ROLE_ARN errors clearly
    //    rather than having failed to boot).
    let memory_role_arn = &state.config.memory_role_arn;
    if memory_role_arn.is_empty() {
        return Err(BrokerError::Internal(
            "canonical-sts not configured: set MEMORY_ROLE_ARN on the broker host".into(),
        ));
    }

    // 3. Verify the cap. A forged or foreign cap must NOT yield operator-prefix creds.
    let p = &req.cap.payload;
    let norm = |s: &str| s.trim_start_matches("0x").to_lowercase();
    if !matches!(p.op, CapOp::CanonicalFetch) || !matches!(p.data_class, DataClass::Memory) {
        return Err(BrokerError::Forbidden(
            "cap is not a CanonicalFetch/Memory cap".into(),
        ));
    }
    if norm(&p.actor_omni) != norm(&session_omni) {
        return Err(BrokerError::Forbidden(
            "cap actor_omni does not match the authenticated session — a delegate may only redeem its OWN canonical cap".into(),
        ));
    }
    if p.operator_omni.is_empty() {
        return Err(BrokerError::Forbidden("cap missing operator_omni".into()));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if p.expires_at != 0 && now > p.expires_at {
        return Err(BrokerError::Forbidden("cap expired".into()));
    }
    // The on-chain `memory:<ns>` grant was checked when the broker MINTED this cap
    // (cap.rs mint_cap), and `broker_sig` proves the broker minted it — so a valid
    // sig + short TTL is the authorization. The worker re-verifies independently
    // (incl. the on-chain scope) when the relayed creds hit /v1/memory/canonical-get.
    if !verify_cap_payload_sig(
        &state.session_keypair.private_key_pem,
        p,
        &req.cap.broker_sig,
    ) {
        return Err(BrokerError::Forbidden("cap broker_sig invalid".into()));
    }

    // 4. Mint an OPERATOR-tagged OIDC JWT INTERNALLY (consumed by the AssumeRole
    //    below; NEVER returned — that is what stops the delegate re-AssumeRole'ing
    //    unscoped). The tag is the OWNER omni so STS reads bots/<operator>/memory/.
    let (claims, _iat, _exp) = build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &p.operator_omni,
        "", // no wallet — agent/operator omni tag is what STS reads
        state.config.oidc_jwt_ttl_seconds,
    );
    let oidc_jwt = state.oidc.sign_jwt(&claims)?;

    // 4b. Defense-in-depth (#295 §7a finding 3): the cap's service is interpolated
    //     into the IAM Resource ARN below. cap-mint already rejects wildcard/path
    //     chars and `broker_sig` is verified above, so a valid cap is clean — but
    //     re-check so a future cap-mint bug can't turn `memory:*` into an IAM
    //     wildcard that widens this exact-object read into a prefix read.
    if p.service.contains(['*', '?', '/', '\\']) || p.service.contains("..") {
        return Err(BrokerError::Forbidden(
            "cap service contains wildcard or path characters".into(),
        ));
    }

    // 5. Inline session policy: GetObject on the EXACT object only. Bucket is
    //    wildcarded — the memory role's identity policy supplies the real bucket;
    //    the AWS intersection is GetObject on <real-bucket>/bots/<op>/memory/<ns>.enc.
    //    Read-only (no Put/Delete) + single object (no other namespace).
    let resource = format!(
        "arn:aws:s3:::*/bots/{}/memory/{}.enc",
        norm(&p.operator_omni),
        p.service.to_lowercase(),
    );
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CanonicalReadOneObject",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": resource,
        }]
    })
    .to_string();

    // 6. AssumeRole with the operator-tagged OIDC + the scoped policy. The delegate
    //    gets ONLY these narrow, read-only, single-object creds.
    let creds = agentkeys_provisioner::assume_role_with_jwt(
        &oidc_jwt,
        &p.operator_omni,
        memory_role_arn,
        &state.config.aws_region,
        900,
        None,
        Some(&policy),
    )
    .await
    .map_err(|e| BrokerError::Internal(format!("canonical-sts AssumeRole: {e}")))?;

    Ok(Json(CanonicalStsResponse {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration,
    }))
}
