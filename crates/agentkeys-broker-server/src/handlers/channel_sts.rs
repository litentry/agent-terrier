//! `POST /v1/cap/channel-sts` — the WORKER-redeemed, cap-derived storage
//! credential mint for the channel data class (#541).
//!
//! ## Why this exists (and why it is NOT the canonical/inbox relay shape)
//! memory/config are per-actor PRIVATE stores, so the CLIENT relays creds it
//! minted for its own prefix. A channel is a SHARED, owner-owned feed
//! (`bots/<owner>/channel/<id>/…`): a participant has nothing of its own to
//! relay and must never hold the OWNER's storage credential. So the CHANNEL
//! WORKER — after its independent layer-2 cap verify — exchanges the cap for
//! short-lived, owner-scoped creds here and touches storage with those. This
//! retires the ambient-credential path entirely (arch §22e): on AWS the worker
//! previously rode the EC2 instance profile (defeating §17.5 layers 3/4); on
//! VE it had nothing and every storage call failed.
//!
//! ## Authorization
//! 1. **Worker bearer** — `AGENTKEYS_CHANNEL_STS_TOKEN`, a host-minted shared
//!    secret written by `setup-broker-host.sh` into BOTH the broker unit env
//!    and the channel worker env (same generate-once posture as the worker
//!    KEKs; never in the repo env files). Devices/delegates hold caps but not
//!    this bearer, so a cap alone can never be redeemed for raw storage creds
//!    — participants stay behind the worker's mediation (L2 policy, size caps,
//!    envelope encryption, audit).
//! 2. **The cap itself** — must be a broker-signed, unexpired Channel-class
//!    `ChannelPublish`/`ChannelSubscribe` cap; its `operator_omni` names the
//!    feed OWNER the creds are scoped to.
//!
//! ## Scoping
//! AWS: an inline session policy narrows to Get/Put/Delete/List on
//! `bots/<owner>/channel/<channel_id>/*` — intersected with the channel role's
//! identity policy (`provision-channel-role.sh`, PrincipalTag-interpolated) and
//! the bucket policy (`apply-channel-bucket-policy.sh`). VE: the provider
//! refuses AWS-dialect inline policies (#510); the per-owner scope-down is
//! rendered VE-side from the OIDC tag, so we pass `None` and rely on it (the
//! #512 intent renderer is the follow-up that narrows to the single channel).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;

use agentkeys_protocol::ChannelStsCreds;

use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::handlers::cap::{verify_cap_payload_sig, CapOp, CapToken, DataClass};
use crate::handlers::oidc::build_oidc_jwt_claims;
use crate::state::SharedState;

/// Credentials TTL. Short — the worker caches until ~60 s before expiry.
const CHANNEL_STS_TTL_SECONDS: i32 = 900;

#[derive(Deserialize)]
pub struct ChannelStsRequest {
    /// The broker-minted Channel-class cap the worker just verified.
    pub cap: CapToken,
}

pub async fn mint_channel_sts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ChannelStsRequest>,
) -> BrokerResult<Json<ChannelStsCreds>> {
    // 1. Config gate — both halves must be provisioned or the endpoint refuses
    //    with a clear pointer (same posture as canonical-sts / MEMORY_ROLE_ARN).
    let role = &state.config.channel_role_arn;
    let expected_bearer = &state.config.channel_sts_token;
    if role.is_empty() || expected_bearer.is_empty() {
        return Err(BrokerError::Internal(
            "channel-sts not configured: set CHANNEL_ROLE_ARN + AGENTKEYS_CHANNEL_STS_TOKEN \
             on the broker host (setup-broker-host.sh writes both)"
                .into(),
        ));
    }

    // 2. Worker bearer (constant-time compare). Only the co-located channel
    //    worker holds this — a cap alone is deliberately NOT redeemable.
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    if !constant_time_str_eq(got, expected_bearer) {
        return Err(BrokerError::Unauthorized(
            "channel-sts bearer invalid".into(),
        ));
    }

    // 3. Verify the cap: channel class, channel op, unexpired, broker-signed.
    let p = &req.cap.payload;
    if !matches!(p.data_class, DataClass::Channel) {
        return Err(BrokerError::Forbidden(
            "cap is not a Channel-class cap".into(),
        ));
    }
    if !matches!(p.op, CapOp::ChannelPublish | CapOp::ChannelSubscribe) {
        return Err(BrokerError::Forbidden(
            "cap op is not ChannelPublish/ChannelSubscribe".into(),
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
    if !verify_cap_payload_sig(
        &state.session_keypair.private_key_pem,
        p,
        &req.cap.broker_sig,
    ) {
        return Err(BrokerError::Forbidden("cap broker_sig invalid".into()));
    }

    // 4. The channel id comes from the SIGNED service field; its charset rule
    //    ([a-z0-9-], no edge dash) is re-checked here because it interpolates
    //    into the IAM Resource ARN below (canonical-sts §4b defense-in-depth —
    //    a future cap-mint bug must not turn a service into an IAM wildcard).
    let channel_id = channel_id_from_service(&p.service)?;

    // 5. Mint an OWNER-tagged OIDC JWT internally (never returned). The claim
    //    builder normalizes the omni to the bare lowercase form the
    //    PrincipalTag-interpolated policies expect.
    let (claims, _iat, _exp) = build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &p.operator_omni,
        "",
        state.config.oidc_jwt_ttl_seconds,
        &state.config.sts_audience,
    );
    let oidc_jwt = state.oidc.sign_jwt(&claims)?;

    // 6. AWS: narrow further to THIS channel's prefix with an inline session
    //    policy (objects + prefix-conditioned list — teardown needs Delete).
    //    VE: the provider refuses the AWS dialect; per-owner scope-down is
    //    rendered provider-side from the tag (see module docs).
    let policy_string;
    let policy = if state.sts.supports_inline_session_policy() {
        let owner = p.operator_omni.trim_start_matches("0x").to_lowercase();
        policy_string = channel_session_policy(&owner, &channel_id);
        Some(policy_string.as_str())
    } else {
        None
    };

    let creds = state
        .sts
        .assume_role_scoped(
            role,
            &p.operator_omni,
            &oidc_jwt,
            CHANNEL_STS_TTL_SECONDS,
            policy,
        )
        .await
        .map_err(|e| BrokerError::Internal(format!("channel-sts AssumeRole: {e}")))?;

    Ok(Json(ChannelStsCreds {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration_unix,
    }))
}

/// Strip `channel-pub:`/`channel-sub:` and enforce the daemon's channel-id rule
/// (1..=48 of `[a-z0-9-]`, no edge dash) — which inherently excludes every IAM
/// wildcard/path character.
fn channel_id_from_service(service: &str) -> BrokerResult<String> {
    let id = service
        .strip_prefix("channel-pub:")
        .or_else(|| service.strip_prefix("channel-sub:"))
        .ok_or_else(|| {
            BrokerError::Forbidden(format!(
                "cap service {service:?} is not channel-pub:<id>/channel-sub:<id>"
            ))
        })?;
    let valid = !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-');
    if !valid {
        return Err(BrokerError::Forbidden(format!(
            "cap channel id {id:?} violates the channel-id rule ([a-z0-9-], 1..=48, no edge dash)"
        )));
    }
    Ok(id.to_string())
}

/// Inline session policy: object ops + prefix-conditioned list, ONE channel of
/// ONE owner. Bucket is wildcarded — the channel role's identity policy
/// supplies the real bucket; AWS intersects the two.
fn channel_session_policy(owner_bare: &str, channel_id: &str) -> String {
    let objects = format!("arn:aws:s3:::*/bots/{owner_bare}/channel/{channel_id}/*");
    let prefix = format!("bots/{owner_bare}/channel/{channel_id}/*");
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ChannelObjects",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": objects,
            },
            {
                "Sid": "ChannelList",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::*",
                "Condition": { "StringLike": { "s3:prefix": prefix } },
            }
        ]
    })
    .to_string()
}

/// Constant-time string equality (length is not secret — the token is a fixed
/// 64-hex host secret; content comparison must not early-exit).
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_extraction_accepts_both_directions_and_rejects_iam_metachars() {
        assert_eq!(
            channel_id_from_service("channel-pub:opchat-test1").unwrap(),
            "opchat-test1"
        );
        assert_eq!(
            channel_id_from_service("channel-sub:cam-frontdoor").unwrap(),
            "cam-frontdoor"
        );
        // Not a channel service at all.
        assert!(channel_id_from_service("memory:family").is_err());
        // IAM metacharacters / path tricks / case / edge dash all refused.
        for bad in ["a*", "a?b", "a/b", "a\\b", "a..b", "A", "-a", "a-", ""] {
            assert!(
                channel_id_from_service(&format!("channel-pub:{bad}")).is_err(),
                "{bad:?} must be rejected"
            );
        }
        // Length rule: 48 ok, 49 refused.
        let ok48 = "a".repeat(48);
        assert!(channel_id_from_service(&format!("channel-pub:{ok48}")).is_ok());
        let bad49 = "a".repeat(49);
        assert!(channel_id_from_service(&format!("channel-pub:{bad49}")).is_err());
    }

    #[test]
    fn session_policy_scopes_one_channel_of_one_owner() {
        let policy = channel_session_policy("abc123", "opchat-test1");
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(
            v["Statement"][0]["Resource"],
            "arn:aws:s3:::*/bots/abc123/channel/opchat-test1/*"
        );
        // Teardown needs Delete; nothing wider (no s3:* / no bucket-level ops).
        assert_eq!(
            v["Statement"][0]["Action"],
            serde_json::json!(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"])
        );
        assert_eq!(
            v["Statement"][1]["Condition"]["StringLike"]["s3:prefix"],
            "bots/abc123/channel/opchat-test1/*"
        );
    }

    #[test]
    fn bearer_compare_is_exact() {
        assert!(constant_time_str_eq("deadbeef", "deadbeef"));
        assert!(!constant_time_str_eq("deadbeef", "deadbeee"));
        assert!(!constant_time_str_eq("deadbeef", "deadbee"));
        assert!(!constant_time_str_eq("", "x"));
    }
}
