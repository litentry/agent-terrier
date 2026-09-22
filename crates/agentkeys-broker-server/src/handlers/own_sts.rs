//! `POST /v1/cap/own-sts` — broker-brokered scoped STS for a delegate's
//! OWN-namespace memory op (#716; the own-prefix sibling of
//! [`super::inbox_sts`] and [`super::canonical_sts`]).
//!
//! ## Why this exists
//! A delegate's two cross-actor data paths already run their credential
//! SERVER-SIDE: `memory_canonical_get` relays the delegate's session bearer +
//! cap to `/v1/cap/canonical-sts`, `memory_inbox_append` to `/v1/cap/inbox-sts`.
//! The delegate's OWN-namespace put/get was the outlier: it relied on the
//! CLIENT relaying `X-Aws-*` creds it minted through the AWS STS relay — which
//! needs a `memory_role_arn` the sandbox never holds — so on VE every #594/#694
//! checkpoint put reached the worker credential-less and died on the worker's
//! DEFAULT S3 client (`no providers in chain provided credentials`, measured
//! 2026-09-22 on VE prod: nothing a delegate remembered survived a re-create).
//! On AWS the same request silently rode the worker's EC2 instance profile —
//! the ambient-authority fallback arch.md §22e prohibits.
//!
//! The flow (A', same posture as the two siblings):
//! 1. The delegate authenticates with its OWN session JWT.
//! 2. It presents the `Store`/`Fetch` Memory cap the broker already minted for
//!    it (`actor == session`, service = its own `knowledge:<ns>`), which the
//!    broker only minted AFTER the on-chain `knowledge:<ns>` grant check (#642
//!    — a delegate mints own-store caps with its actor session).
//! 3. The broker re-verifies the cap (`broker_sig`, op, data class, freshness,
//!    `actor_omni == session`, and the #369 delegation path when present),
//!    mints an ACTOR-tagged OIDC JWT **internally** (never handed out), and
//!    `AssumeRole`s the memory role with an inline session policy scoped to the
//!    delegate's OWN objects for that ONE service — `bots/<actor>/memory/<service>.enc`
//!    and `bots/<actor>/memory/<service>.objects/*`. A `Store` cap yields
//!    PutObject and GetObject (the D-K5 compare-and-swap reads the current
//!    object before the put); a `Fetch` cap yields GetObject only.
//! 4. The worker receives ONLY those narrow creds and performs the op. On AWS
//!    the ACTOR PrincipalTag intersects with the same prefix (layer 3); on VE
//!    the provider-side per-actor scope-down does (no inline dialect, #510).
//!
//! Strictly narrower than what a delegate could already mint on AWS through
//! the client relay (its whole `bots/<actor>/{memory,inbox}/*`), so this is no
//! widening — it is the VE credential path that did not exist.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;

use agentkeys_protocol::OwnStsResult;

use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::handlers::cap::{verify_cap_payload_sig, CapOp, CapToken, DataClass};
use crate::handlers::oidc::build_oidc_jwt_claims;
use crate::jwt::verify::verify_session_jwt;
use crate::state::SharedState;

/// Credentials TTL — the worker uses them for exactly one op.
const OWN_STS_TTL_SECONDS: i32 = 900;

#[derive(Deserialize)]
pub struct OwnStsRequest {
    /// The broker-minted `Store`/`Fetch` Memory cap for the delegate's OWN
    /// namespace.
    pub cap: CapToken,
}

/// What the cap authorizes, decided from its SIGNED op (never the route).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnOp {
    /// `Store` — put (+ the compare-and-swap read of the current object).
    Write,
    /// `Fetch` — read only.
    Read,
}

impl OwnOp {
    /// The cap-op → grant mapping. `None` = not an own-store op (a canonical
    /// read, an inbox append, a channel op … must never redeem here).
    pub(crate) fn from_cap(op: CapOp, data_class: DataClass) -> Option<Self> {
        if !matches!(data_class, DataClass::Memory) {
            return None;
        }
        match op {
            CapOp::Store => Some(Self::Write),
            CapOp::Fetch => Some(Self::Read),
            _ => None,
        }
    }

    fn actions(self) -> Vec<&'static str> {
        match self {
            Self::Write => vec!["s3:PutObject", "s3:GetObject"],
            Self::Read => vec!["s3:GetObject"],
        }
    }
}

/// #369 defense-in-depth shared by the broker-brokered STS mints: when the cap
/// carries a device→sandbox delegation path, re-verify it here INDEPENDENTLY
/// of cap-mint (the worker only relays), so a cap-mint regression can never
/// widen a narrow or wrong-device delegation into a credential. Uses the SAME
/// shared crypto + scope matcher as cap-mint and the worker (#203).
pub(crate) fn reverify_delegation_path(cap: &CapToken, now: u64) -> BrokerResult<()> {
    let Some(deleg) = &cap.delegation_path else {
        return Ok(());
    };
    let p = &cap.payload;
    let (Some(client_sig), Some(client_nonce), Some(client_ts)) = (
        cap.client_sig.as_deref(),
        cap.client_nonce.as_deref(),
        cap.client_ts,
    ) else {
        return Err(BrokerError::Forbidden(
            "delegated cap missing client_sig/nonce/ts".into(),
        ));
    };
    let preimage = agentkeys_core::device_crypto::cap_pop_payload(
        &p.operator_omni,
        &p.actor_omni,
        &p.service,
        p.op.as_str(),
        p.data_class.as_str(),
        client_nonce,
        client_ts,
    );
    let recovered = agentkeys_core::device_crypto::ecrecover_eip191(&preimage, client_sig)
        .map_err(|e| BrokerError::Forbidden(format!("delegated cap-PoP recover: {e}")))?;
    if deleg.expires_at <= now {
        return Err(BrokerError::Forbidden("delegation expired".into()));
    }
    if !agentkeys_core::device_crypto::cap_in_scope(
        &deleg.scope,
        p.data_class.as_str(),
        p.op.as_str(),
        &p.service,
    ) {
        return Err(BrokerError::Forbidden(format!(
            "cap service {} outside delegation scope {:?}",
            p.service, deleg.scope
        )));
    }
    agentkeys_core::device_crypto::verify_delegation(
        &p.device_key_hash,
        &recovered,
        &deleg.scope,
        deleg.expires_at,
        &deleg.delegation_sig,
    )
    .map_err(|e| BrokerError::Forbidden(format!("delegation verify: {e}")))?;
    Ok(())
}

/// Inline session policy: the delegate's OWN objects for ONE service — the
/// legacy single slot and the #594 keyed objects under it — with the actions
/// the cap op earns. The bucket is wildcarded: the memory role's identity
/// policy supplies the real bucket, and the ACTOR PrincipalTag it interpolates
/// intersects to the same `bots/<actor>/` prefix (layer 3 stays the outer bound).
pub(crate) fn own_session_policy(actor_bare: &str, service_lc: &str, op: OwnOp) -> String {
    let slot = format!("arn:aws:s3:::*/bots/{actor_bare}/memory/{service_lc}.enc");
    let keyed = format!("arn:aws:s3:::*/bots/{actor_bare}/memory/{service_lc}.objects/*");
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OwnNamespaceOneService",
            "Effect": "Allow",
            "Action": op.actions(),
            "Resource": [slot, keyed],
        }]
    })
    .to_string()
}

pub async fn mint_own_sts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<OwnStsRequest>,
) -> BrokerResult<Json<OwnStsResult>> {
    // 1. Authenticate the DELEGATE via its OWN session.
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    let session = verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, token)?;
    let session_omni = session.agentkeys.omni_account;

    // 2. Config gate — same posture as canonical/inbox-sts.
    let memory_role_arn = &state.config.memory_role_arn;
    if memory_role_arn.is_empty() {
        return Err(BrokerError::Internal(
            "own-sts not configured: set MEMORY_ROLE_ARN on the broker host".into(),
        ));
    }

    // 3. Verify the cap. A forged, foreign or wrong-op cap must NOT yield creds.
    let p = &req.cap.payload;
    let norm = |s: &str| s.trim_start_matches("0x").to_lowercase();
    let Some(op) = OwnOp::from_cap(p.op, p.data_class) else {
        return Err(BrokerError::Forbidden(
            "cap is not a Store/Fetch Memory cap — own-sts serves a delegate's OWN namespace only"
                .into(),
        ));
    };
    if norm(&p.actor_omni) != norm(&session_omni) {
        return Err(BrokerError::Forbidden(
            "cap actor_omni does not match the authenticated session — a delegate may only redeem its OWN cap".into(),
        ));
    }
    if p.operator_omni.is_empty() || p.actor_omni.is_empty() {
        return Err(BrokerError::Forbidden(
            "cap missing operator_omni/actor_omni".into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if p.expires_at != 0 && now > p.expires_at {
        return Err(BrokerError::Forbidden("cap expired".into()));
    }
    // The on-chain `knowledge:<ns>` grant was checked when the broker MINTED the
    // cap (cap.rs mint_cap, the #642 actor-session path), and `broker_sig`
    // proves the broker minted it. The worker re-verifies independently
    // (incl. the on-chain scope) before it touches storage.
    if !verify_cap_payload_sig(
        &state.session_keypair.private_key_pem,
        p,
        &req.cap.broker_sig,
    ) {
        return Err(BrokerError::Forbidden("cap broker_sig invalid".into()));
    }
    reverify_delegation_path(&req.cap, now)?;

    // 3b. The service interpolates into the IAM Resource ARN below. cap-mint
    //     already rejects wildcard/path chars; re-check so a future cap-mint
    //     bug can't widen the grant into a prefix wildcard.
    if p.service.contains(['*', '?', '/', '\\']) || p.service.contains("..") {
        return Err(BrokerError::Forbidden(
            "cap service contains wildcard or path characters".into(),
        ));
    }

    // 4. Mint an ACTOR-tagged OIDC JWT INTERNALLY (consumed by the AssumeRole
    //    below; NEVER returned). The tag is the delegate's OWN omni: STS keys
    //    on it, so the creds reach `bots/<actor>/…` and nothing else.
    let (claims, _iat, _exp) = build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &p.actor_omni,
        "", // no wallet — the actor omni tag is what STS keys on
        state.config.oidc_jwt_ttl_seconds,
        &state.config.sts_audience,
    );
    let oidc_jwt = state.oidc.sign_jwt(&claims)?;

    // 5. AWS: narrow further to this ONE service's objects with an inline
    //    session policy. VE refuses the AWS dialect (#510) — the per-actor
    //    scope-down is rendered provider-side from the tag (the inbox-sts
    //    posture; the single-service narrowing is the #512 intent follow-up).
    let policy_string;
    let policy = if state.sts.supports_inline_session_policy() {
        policy_string = own_session_policy(&norm(&p.actor_omni), &p.service.to_lowercase(), op);
        Some(policy_string.as_str())
    } else {
        None
    };

    // 6. AssumeRole with the actor-tagged OIDC + the scoped policy.
    let creds = state
        .sts
        .assume_role_scoped(
            memory_role_arn,
            &p.actor_omni,
            &oidc_jwt,
            OWN_STS_TTL_SECONDS,
            policy,
        )
        .await
        .map_err(|e| BrokerError::Internal(format!("own-sts AssumeRole: {e}")))?;

    Ok(Json(OwnStsResult {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration_unix,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_own_store_and_fetch_memory_caps_redeem() {
        assert_eq!(
            OwnOp::from_cap(CapOp::Store, DataClass::Memory),
            Some(OwnOp::Write)
        );
        assert_eq!(
            OwnOp::from_cap(CapOp::Fetch, DataClass::Memory),
            Some(OwnOp::Read)
        );
        // The cross-actor ops have their own mints; compute/channel ops never
        // touch a memory prefix; a Store cap of another class is a class leak.
        for op in [
            CapOp::CanonicalFetch,
            CapOp::Append,
            CapOp::Teardown,
            CapOp::Classify,
            CapOp::ChannelPublish,
            CapOp::ChannelSubscribe,
            CapOp::SpeechUse,
        ] {
            assert_eq!(OwnOp::from_cap(op, DataClass::Memory), None, "{op:?}");
        }
        for class in [
            DataClass::Credentials,
            DataClass::Config,
            DataClass::Channel,
            DataClass::Speech,
        ] {
            assert_eq!(OwnOp::from_cap(CapOp::Store, class), None, "{class:?}");
            assert_eq!(OwnOp::from_cap(CapOp::Fetch, class), None, "{class:?}");
        }
    }

    #[test]
    fn session_policy_scopes_one_service_of_one_actor() {
        let policy = own_session_policy("abc123", "knowledge:chef", OwnOp::Write);
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmt = &v["Statement"][0];
        assert_eq!(
            stmt["Resource"],
            serde_json::json!([
                "arn:aws:s3:::*/bots/abc123/memory/knowledge:chef.enc",
                "arn:aws:s3:::*/bots/abc123/memory/knowledge:chef.objects/*"
            ])
        );
        // A Store cap earns the put + the compare-and-swap read; nothing wider
        // (no Delete, no List, no bucket-level op).
        assert_eq!(
            stmt["Action"],
            serde_json::json!(["s3:PutObject", "s3:GetObject"])
        );
        let read = own_session_policy("abc123", "knowledge:chef", OwnOp::Read);
        let r: serde_json::Value = serde_json::from_str(&read).unwrap();
        assert_eq!(
            r["Statement"][0]["Action"],
            serde_json::json!(["s3:GetObject"])
        );
        // The operator prefix is never named — only the actor's.
        assert!(!policy.contains("/inbox/"));
    }

    #[test]
    fn a_cap_without_a_delegation_path_needs_no_reverify() {
        let cap = CapToken {
            payload: crate::handlers::cap::CapPayload {
                operator_omni: format!("0x{}", "11".repeat(32)),
                actor_omni: format!("0x{}", "22".repeat(32)),
                service: "knowledge:chef".into(),
                op: CapOp::Store,
                data_class: DataClass::Memory,
                device_key_hash: format!("0x{}", "33".repeat(32)),
                k3_epoch: 0,
                issued_at: 1,
                expires_at: 2,
                nonce: "n".into(),
            },
            broker_sig: String::new(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        };
        assert!(reverify_delegation_path(&cap, 1).is_ok());
    }
}
