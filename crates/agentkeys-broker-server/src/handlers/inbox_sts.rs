//! `POST /v1/cap/inbox-sts` — broker-brokered scoped STS for a delegated
//! absorption-inbox APPEND (#339 P2 §8; the write-side twin of
//! [`super::canonical_sts`]).
//!
//! ## Why this exists
//! Same A' rationale as the canonical READ: a delegate must NOT hold operator
//! authority. The cross-actor WRITE runs server-side in the memory worker, which
//! obtains its write creds HERE — never the delegate. The flow:
//!
//! 1. The delegate authenticates with its OWN session JWT (not the operator's).
//! 2. It presents the `Append` cap the broker already minted (operator=master,
//!    actor=delegate, service=`inbox:<ns>`), which the broker only mints AFTER the
//!    on-chain `inbox:<ns>` grant check (a DISTINCT service-id from the read grant).
//! 3. The broker re-verifies the cap (`broker_sig`, op, data class, freshness, and
//!    `actor_omni == session` — a delegate only redeems ITS OWN cap), mints an
//!    OPERATOR-tagged OIDC JWT **internally** (never handed out), and `AssumeRole`s
//!    the memory role with an inline session policy scoped to `s3:PutObject` on the
//!    single delegate's inbox sub-prefix `bots/<operator>/inbox/<delegate>/<service>/*`.
//! 4. The worker receives ONLY those narrow, write-only creds: it can PUT into one
//!    delegate's one-namespace inbox sub-prefix and nothing else — no read, no
//!    other delegate's prefix, no canonical memory, no reusable operator bearer.

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
pub struct InboxStsRequest {
    /// The broker-minted `Append`/`Memory` cap for this delegate.
    pub cap: CapToken,
}

#[derive(Serialize)]
pub struct InboxStsResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
}

pub async fn mint_inbox_sts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<InboxStsRequest>,
) -> BrokerResult<Json<InboxStsResponse>> {
    // 1. Authenticate the DELEGATE via its OWN session (never the operator's).
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    let session = verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, token)?;
    let session_omni = session.agentkeys.omni_account;

    // 2. Config gate (back-compat: a broker without MEMORY_ROLE_ARN errors clearly).
    let memory_role_arn = &state.config.memory_role_arn;
    if memory_role_arn.is_empty() {
        return Err(BrokerError::Internal(
            "inbox-sts not configured: set MEMORY_ROLE_ARN on the broker host".into(),
        ));
    }

    // 3. Verify the cap. A forged or foreign cap must NOT yield operator-prefix creds.
    let p = &req.cap.payload;
    let norm = |s: &str| s.trim_start_matches("0x").to_lowercase();
    if !matches!(p.op, CapOp::Append) || !matches!(p.data_class, DataClass::Memory) {
        return Err(BrokerError::Forbidden(
            "cap is not an Append/Memory cap".into(),
        ));
    }
    if norm(&p.actor_omni) != norm(&session_omni) {
        return Err(BrokerError::Forbidden(
            "cap actor_omni does not match the authenticated session — a delegate may only redeem its OWN inbox cap".into(),
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
    // The on-chain `inbox:<ns>` grant was checked when the broker MINTED this cap
    // (cap.rs mint_cap), and `broker_sig` proves the broker minted it. The worker
    // re-verifies independently (incl. the on-chain scope) when it writes.
    if !verify_cap_payload_sig(
        &state.session_keypair.private_key_pem,
        p,
        &req.cap.broker_sig,
    ) {
        return Err(BrokerError::Forbidden("cap broker_sig invalid".into()));
    }

    // 3b. Defense-in-depth (§8 / §7a finding 3): the cap service + omnis are
    //     interpolated into the IAM Resource ARN below. cap-mint already rejects
    //     wildcard/path chars; re-check so a future cap-mint bug can't widen the
    //     write into a prefix wildcard.
    if p.service.contains(['*', '?', '/', '\\']) || p.service.contains("..") {
        return Err(BrokerError::Forbidden(
            "cap service contains wildcard or path characters".into(),
        ));
    }

    // 4. Mint an OPERATOR-tagged OIDC JWT INTERNALLY (consumed by the AssumeRole
    //    below; NEVER returned). The tag is the OWNER omni so STS writes under
    //    bots/<operator>/inbox/.
    let (claims, _iat, _exp) = build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &p.operator_omni,
        "", // no wallet — operator omni tag is what STS keys on
        state.config.oidc_jwt_ttl_seconds,
        &state.config.sts_audience,
    );
    let oidc_jwt = state.oidc.sign_jwt(&claims)?;

    // 5. Inline session policy: PutObject on the delegate's inbox sub-prefix only.
    //    `bots/<operator>/inbox/<delegate>/<service>/*` — one operator, one delegate,
    //    one namespace. Write-only (no Get/Delete/List), so a compromised worker
    //    using these creds can only ADD inbox proposals for this one delegate+ns,
    //    never read/clobber the master's canonical memory or another delegate's inbox.
    //    Bucket is wildcarded; the memory role's identity policy supplies the real
    //    bucket — the AWS intersection is the exact sub-prefix in the real bucket.
    let resource = format!(
        "arn:aws:s3:::*/bots/{}/inbox/{}/{}/*",
        norm(&p.operator_omni),
        norm(&p.actor_omni),
        p.service.to_lowercase(),
    );
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "InboxAppendOneSubprefix",
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": resource,
        }]
    })
    .to_string();

    // 6. AssumeRole with the operator-tagged OIDC + the scoped policy. The worker
    //    gets ONLY these narrow, write-only, single-sub-prefix creds.
    let creds = state
        .sts
        .assume_role_scoped(
            memory_role_arn,
            &p.operator_omni,
            &oidc_jwt,
            900,
            Some(&policy),
        )
        .await
        .map_err(|e| BrokerError::Internal(format!("inbox-sts AssumeRole: {e}")))?;

    Ok(Json(InboxStsResponse {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration_unix,
    }))
}
