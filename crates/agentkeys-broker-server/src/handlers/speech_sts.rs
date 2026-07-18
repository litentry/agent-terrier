//! `POST /v1/cap/speech-sts` — broker-brokered scoped STS for the speech
//! plane (#441, epic #439 stack ②: ASR/TTS through the SAME cap→STS relay
//! every other endpoint uses — no server-held speech token, no gate-custody
//! special case like the VE stack's #386 app-token posture).
//!
//! ## Shape (the canonical_sts.rs pattern, compute-plane edition)
//!
//! 1. The delegate authenticates with its OWN session JWT.
//! 2. It presents the `SpeechUse`/`Speech` cap the broker minted at
//!    `/v1/cap/speech` — which the broker only mints AFTER the on-chain
//!    `speech` grant check (master-self rides the #195 skip).
//! 3. The broker re-verifies the cap (broker_sig, op, data class, freshness,
//!    actor == session — a delegate can only redeem ITS OWN cap; #369
//!    delegation re-check when present), mints an ACTOR-tagged OIDC JWT
//!    internally (never handed out), and AssumeRoles the SPEECH role with an
//!    inline session policy pinning the exact speech actions.
//! 4. The delegate receives ONLY short-TTL creds whose effective permissions
//!    are `transcribe:StartStreamTranscription*` + `polly:SynthesizeSpeech` —
//!    the AWS intersection of the role's identity policy and the inline
//!    policy. No storage action, no re-AssumeRole, no operator bearer.
//!
//! ## Why no `${aws:PrincipalTag}` resource scoping here
//!
//! Transcribe streaming + Polly synthesis have no per-actor resources (the
//! calls are account-level compute, `Resource: *` by necessity), so the
//! layer-3 IAM pattern the storage roles use does not apply. The per-actor
//! gate is layers 1+2: the on-chain `speech` grant checked at cap-mint and
//! the actor==session check here. The session is still tagged with the
//! actor omni so CloudTrail attributes every speech call to the actor.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;

use agentkeys_protocol::SpeechStsResult;

use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::handlers::cap::{verify_cap_payload_sig, CapOp, CapToken, DataClass, SPEECH_SERVICE};
use crate::handlers::oidc::build_oidc_jwt_claims;
use crate::jwt::verify::verify_session_jwt;
use crate::state::SharedState;

/// Wire-identical to `agentkeys_protocol::SpeechStsBody` — local so the cap
/// deserializes into the broker's typed `CapToken` (the protocol crate's stays
/// transport-generic), the same split `canonical_sts.rs` uses.
#[derive(Deserialize)]
pub struct SpeechStsRequest {
    pub cap: CapToken,
}

pub async fn mint_speech_sts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SpeechStsRequest>,
) -> BrokerResult<Json<SpeechStsResult>> {
    // 1. Authenticate the caller via its OWN session.
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    let session = verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, token)?;
    let session_omni = session.agentkeys.omni_account;

    // 2. Config gate (back-compat: a broker without SPEECH_ROLE_ARN errors
    //    clearly rather than having failed to boot).
    let speech_role_arn = &state.config.speech_role_arn;
    if speech_role_arn.is_empty() {
        return Err(BrokerError::Internal(
            "speech-sts not configured: set SPEECH_ROLE_ARN on the broker host".into(),
        ));
    }

    // 3. Verify the cap. A forged, foreign, or wrong-plane cap yields nothing.
    let p = &req.cap.payload;
    let norm = |s: &str| s.trim_start_matches("0x").to_lowercase();
    if !matches!(p.op, CapOp::SpeechUse) || !matches!(p.data_class, DataClass::Speech) {
        return Err(BrokerError::Forbidden(
            "cap is not a SpeechUse/Speech cap".into(),
        ));
    }
    if p.service != SPEECH_SERVICE {
        return Err(BrokerError::Forbidden(format!(
            "speech cap carries service {:?} (want {SPEECH_SERVICE:?})",
            p.service
        )));
    }
    if norm(&p.actor_omni) != norm(&session_omni) {
        return Err(BrokerError::Forbidden(
            "cap actor_omni does not match the authenticated session — an actor may only redeem its OWN speech cap".into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if p.expires_at != 0 && now > p.expires_at {
        return Err(BrokerError::Forbidden("cap expired".into()));
    }
    // The on-chain `speech` grant was checked when the broker MINTED this cap
    // (cap.rs mint_cap) and broker_sig proves the broker minted it.
    if !verify_cap_payload_sig(
        &state.session_keypair.private_key_pem,
        p,
        &req.cap.broker_sig,
    ) {
        return Err(BrokerError::Forbidden("cap broker_sig invalid".into()));
    }

    // 3b. #369 defense-in-depth — re-verify the device→sandbox delegation
    //     independently of cap-mint, exactly as canonical-sts does, so a
    //     cap-mint regression cannot widen a narrow delegation into speech
    //     authority.
    if let Some(deleg) = &req.cap.delegation_path {
        let (Some(client_sig), Some(client_nonce), Some(client_ts)) = (
            req.cap.client_sig.as_deref(),
            req.cap.client_nonce.as_deref(),
            req.cap.client_ts,
        ) else {
            return Err(BrokerError::Forbidden(
                "delegated speech cap missing client_sig/nonce/ts".into(),
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
    }

    // 4. Mint an ACTOR-tagged OIDC JWT INTERNALLY (consumed by the AssumeRole
    //    below; never returned). Speech has no per-actor AWS resource, so the
    //    tag is attribution (CloudTrail), not scoping.
    let (claims, _iat, _exp) = build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &p.actor_omni,
        "",
        state.config.oidc_jwt_ttl_seconds,
        &state.config.sts_audience,
    );
    let oidc_jwt = state.oidc.sign_jwt(&claims)?;

    // 5. Inline session policy: EXACTLY the two speech surfaces, nothing else.
    //    The role's identity policy carries the same actions; the intersection
    //    is therefore these actions even if the role ever grows.
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "SpeechPlaneOnly",
            "Effect": "Allow",
            "Action": [
                "transcribe:StartStreamTranscription",
                "transcribe:StartStreamTranscriptionWebSocket",
                "polly:SynthesizeSpeech"
            ],
            "Resource": "*",
        }]
    })
    .to_string();

    // 6. AssumeRole → short-TTL, speech-only creds.
    let creds = state
        .sts
        .assume_role_scoped(
            speech_role_arn,
            &p.actor_omni,
            &oidc_jwt,
            900,
            Some(&policy),
        )
        .await
        .map_err(|e| BrokerError::Internal(format!("speech-sts AssumeRole: {e}")))?;

    Ok(Json(SpeechStsResult {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration_unix,
        region: state.config.aws_region.clone(),
    }))
}
