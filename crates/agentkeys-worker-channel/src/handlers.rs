//! Channel worker HTTP surface — #406 / `docs/spec/agent-channel-decoupling.md`.
//!
//! `/v1/channel/{publish,poll,teardown}` at the `channel/` S3 prefix per
//! arch.md §17.2 per-data-class buckets. The novel bit vs the config/memory
//! workers is the NRT worker-held long-poll (§14.12): a `poll` with no pending
//! event `await`s an in-process wakeup that a `publish` fires the instant the
//! event lands durably in S3.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use agentkeys_core::audit::{AuditOpKind, AuditResult, ChannelPublishBody, ChannelSubscribeBody};
use agentkeys_protocol::{ChannelDirection, ChannelEvent, ChannelEventKind, ChannelProducer};
use agentkeys_worker_creds::audit::{cap_hash, keccak_hex, zero_hash};
use agentkeys_worker_creds::aws_creds::{OptionalStsCreds, StsCreds};
use agentkeys_worker_creds::envelope;
use agentkeys_worker_creds::errors::{
    err_400, err_403, err_413, err_500, err_502, s3_error_summary, ApiError,
};
use agentkeys_worker_creds::verify::{self, CapOp, CapToken, DataClass};

use crate::state::SharedChannelWorkerState;

/// Process-local monotonic sequence — disambiguates two events published in the
/// same millisecond so feed keys stay strictly ordered within a worker run.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// #541 — resolve the S3 client for a request. Relayed `X-Aws-*` creds win
/// (back-compat with callers that mint their own); otherwise the worker redeems
/// the ALREADY-VERIFIED cap for owner-scoped creds at the broker's
/// `/v1/cap/channel-sts`. There is deliberately NO ambient fallback: the EC2
/// instance profile defeated §17.5 layers 3/4 on AWS, and VE (no ambient creds)
/// proved the path was never real — a request that can't resolve creds fails
/// LOUDLY here instead (arch §22e "cap-derived, never ambient").
async fn storage_s3(
    state: &SharedChannelWorkerState,
    creds: Option<&StsCreds>,
    cap: &CapToken,
    owner: &str,
    channel_id: &str,
) -> Result<aws_sdk_s3::Client, ApiError> {
    if let Some(relayed) = creds {
        return Ok(relayed.build_s3_client(&state.config.region).await);
    }
    let Some(minter) = &state.sts_minter else {
        return Err(err_500(
            "no storage credentials for this request: no X-Aws-* relay headers, and the cap→STS \
             minter is unconfigured (AGENTKEYS_BROKER_URL / AGENTKEYS_CHANNEL_STS_TOKEN — \
             setup-broker-host.sh writes both). Ambient instance-profile access is retired (#541).",
            "storage_creds_unconfigured",
        ));
    };
    let minted = minter.creds_for(cap, owner, channel_id).await?;
    Ok(minted.build_s3_client(&state.config.region).await)
}

pub fn build_router(state: SharedChannelWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/channel/publish", post(channel_publish))
        .route("/v1/channel/poll", post(channel_poll))
        .route("/v1/channel/teardown", post(channel_teardown))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub channel_bucket: String,
    pub chain_profile: String,
    pub max_poll_seconds: u64,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedChannelWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        channel_bucket: state.config.channel_bucket.clone(),
        chain_profile: state.config.chain_profile.clone(),
        max_poll_seconds: state.config.max_poll_seconds,
        version: env!("CARGO_PKG_VERSION"),
    })
}

// ── request/response bodies (mirror agentkeys_protocol::Channel*) ────────────

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub cap: CapToken,
    pub kind: ChannelEventKind,
    #[serde(default = "direction_in")]
    pub direction: ChannelDirection,
    #[serde(default)]
    pub body_b64: Option<String>,
    #[serde(default)]
    pub body_ref: Option<String>,
    #[serde(default)]
    pub correlation: Option<String>,
    /// #522 — producer-declared audio params (voice/rate/format), copied
    /// verbatim onto the event like `kind`/`correlation`.
    #[serde(default)]
    pub audio: Option<agentkeys_protocol::ChannelAudioParams>,
}

fn direction_in() -> ChannelDirection {
    ChannelDirection::In
}

#[derive(Debug, Serialize)]
pub struct PublishResponse {
    pub ok: bool,
    pub event_id: String,
    pub s3_key: String,
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PollRequest {
    pub cap: CapToken,
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub wait_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct PollResponse {
    pub ok: bool,
    pub events: Vec<ChannelEvent>,
    pub cursor: String,
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TeardownRequest {
    pub cap: CapToken,
    #[serde(default)]
    pub channel_id: String,
}

#[derive(Debug, Serialize)]
pub struct TeardownResponse {
    pub ok: bool,
    pub keys_deleted: usize,
    pub audit_envelope_hash: Option<String>,
}

// ── publish ─────────────────────────────────────────────────────────────────

async fn channel_publish(
    State(state): State<SharedChannelWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::ChannelPublish).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;

    let outcome = channel_publish_inner(&state, creds.as_ref(), &req, &channel_id).await;
    let audit_body = ChannelPublishBody {
        key: outcome
            .as_ref()
            .map(|(_, key, _)| key.clone())
            .unwrap_or_default(),
        channel_id: channel_id.clone(),
        event_id: outcome
            .as_ref()
            .map(|(id, _, _)| id.clone())
            .unwrap_or_default(),
        payload_hash: match &outcome {
            Ok((_, _, env_bytes)) => keccak_hex(env_bytes),
            Err(_) => zero_hash(),
        },
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(
            &req.cap,
            AuditOpKind::ChannelPublish,
            audit_body,
            audit_result,
        )
        .await;
    let (event_id, s3_key, _env) = outcome?;
    // NRT write-through wakeup (§14.12): the durable write is done; wake any
    // held consumer long-poll on this channel so it returns immediately.
    state.wakeup.signal(&channel_id);
    Ok(Json(PublishResponse {
        ok: true,
        event_id,
        s3_key,
        audit_envelope_hash: audited?,
    }))
}

/// Returns `(event_id, s3_key, envelope_bytes)` on success.
async fn channel_publish_inner(
    state: &SharedChannelWorkerState,
    creds: Option<&StsCreds>,
    req: &PublishRequest,
    channel_id: &str,
) -> Result<(String, String, Vec<u8>), ApiError> {
    // Exactly one of body_b64 / body_ref (small inline vs large-by-reference).
    let (body, body_ref) = match (&req.body_b64, &req.body_ref) {
        (Some(_), Some(_)) => {
            return Err(err_400(
                "exactly one of body_b64 / body_ref (both given)",
                "channel_publish_body_ambiguous",
            ))
        }
        (None, None) => {
            return Err(err_400(
                "exactly one of body_b64 / body_ref (neither given)",
                "channel_publish_body_empty",
            ))
        }
        (Some(b64), None) => {
            // Validate it is real base64 up front (fail-loud, #284 posture).
            let decoded = STANDARD
                .decode(b64)
                .map_err(|e| err_400(e.to_string(), "channel_body_b64_decode"))?;
            // #522 — explicit inline ceiling (there was NO size validation at
            // all before, only axum's implicit body limit). Larger payloads
            // belong in body_ref; the refusal names the escape hatch.
            let max = state.config.inline_max_bytes;
            if decoded.len() > max {
                return Err(err_413(
                    format!(
                        "inline body is {} bytes decoded (max {max}) — put large \
                         payloads in the feed and pass body_ref instead",
                        decoded.len()
                    ),
                    "channel_body_too_large",
                ));
            }
            (Some(b64.clone()), None)
        }
        (None, Some(r)) => (None, Some(r.clone())),
    };

    let now_millis = unix_millis();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let event_id = format!("{now_millis:013}-{seq:016x}");
    // D8 (#430): the feed is OPERATOR-owned — `bots/<operator>/channel/<id>/`
    // is the household bus every granted actor meets on (a delegate's reply
    // and the operator's send land in ONE feed). Master-self caps
    // (operator == actor) are byte-identical to the pre-#430 layout.
    let owner = normalize_omni(&req.cap.payload.operator_omni);

    // Provenance is WORKER-STAMPED from the cap-signed actor — never a body
    // field (§4.1). A delegate labels the event's `kind`, never its producer.
    let event = ChannelEvent {
        event_id: event_id.clone(),
        channel_id: channel_id.to_string(),
        direction: req.direction,
        producer: ChannelProducer::Actor {
            // Provenance stays the cap-signed ACTOR (who spoke), independent
            // of the operator-owned feed prefix (where it lives).
            actor_omni: format!("0x{}", normalize_omni(&req.cap.payload.actor_omni)),
        },
        kind: req.kind,
        body,
        body_ref,
        ts_millis: now_millis,
        correlation: req.correlation.clone(),
        audio: req.audio.clone(),
    };
    let plaintext =
        serde_json::to_vec(&event).map_err(|e| err_500(e.to_string(), "channel_event_encode"))?;

    // Envelope-encrypt under the worker KEK. AAD is DIRECTION-NEUTRAL (the bare
    // channel_id, not the channel-pub:/channel-sub: service) so a subscribe cap
    // decrypts what a publish cap encrypted (envelope::aad ignores operator +
    // k3_epoch, so pub/sub + epoch rotation don't break the AAD match).
    let aad = envelope::aad("", &owner, channel_id, 0);
    let env_bytes = envelope::encrypt(&state.config.kek_hex, &plaintext, &aad)
        .map_err(|e| err_500(e.to_string(), "channel_envelope_encrypt"))?;

    let key = feed_key(&owner, channel_id, &event_id);
    let s3 = storage_s3(state, creds, &req.cap, &owner, channel_id).await?;
    s3.put_object()
        .bucket(&state.config.channel_bucket)
        .key(&key)
        .body(env_bytes.clone().into())
        .send()
        .await
        .map_err(|e| err_502(format!("s3 PutObject: {}", s3_error_summary(&e)), "s3_put"))?;
    Ok((event_id, key, env_bytes))
}

// ── poll (the NRT long-poll) ─────────────────────────────────────────────────

async fn channel_poll(
    State(state): State<SharedChannelWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::ChannelSubscribe).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;
    // D8 (#430): read from the OPERATOR-owned feed (see channel_publish_inner).
    let owner = normalize_omni(&req.cap.payload.operator_omni);

    // Grab the wakeup handle BEFORE the first list so a publish landing during
    // the list still wakes us (§14.12 race note in wakeup.rs).
    let waiter = state.wakeup.waiter(&channel_id);

    let mut events = channel_list_after(
        &state,
        creds.as_ref(),
        &req.cap,
        &owner,
        &channel_id,
        &req.after,
    )
    .await?;

    // NRT long-poll: if nothing new and the caller wants to wait, hold the
    // request until a publish signals this channel (or the ceiling elapses),
    // then re-list once.
    if events.is_empty() && req.wait_seconds > 0 {
        let wait = req.wait_seconds.min(state.config.max_poll_seconds);
        let _ = tokio::time::timeout(Duration::from_secs(wait), waiter.notified()).await;
        events = channel_list_after(
            &state,
            creds.as_ref(),
            &req.cap,
            &owner,
            &channel_id,
            &req.after,
        )
        .await?;
    }

    let cursor = events
        .last()
        .map(|e| feed_key(&owner, &channel_id, &e.event_id))
        .unwrap_or_else(|| req.after.clone());

    let audit_body = ChannelSubscribeBody {
        channel_id: channel_id.clone(),
        cursor: req.after.clone(),
        event_count: events.len() as u64,
        cap_hash: cap_hash(&req.cap),
    };
    let audited = state
        .audit
        .emit(
            &req.cap,
            AuditOpKind::ChannelSubscribe,
            audit_body,
            AuditResult::Success,
        )
        .await;

    Ok(Json(PollResponse {
        ok: true,
        events,
        cursor,
        audit_envelope_hash: audited?,
    }))
}

/// List + decrypt every feed event whose key sorts strictly after `after`
/// (empty = from the feed start), oldest-first. S3 is the DURABLE record — this
/// is what makes an event survive a worker restart (§14.12).
async fn channel_list_after(
    state: &SharedChannelWorkerState,
    creds: Option<&StsCreds>,
    cap: &CapToken,
    owner: &str,
    channel_id: &str,
    after: &str,
) -> Result<Vec<ChannelEvent>, ApiError> {
    let prefix = feed_prefix(owner, channel_id);
    let s3 = storage_s3(state, creds, cap, owner, channel_id).await?;
    let mut list = s3
        .list_objects_v2()
        .bucket(&state.config.channel_bucket)
        .prefix(&prefix);
    if !after.is_empty() {
        list = list.start_after(after);
    }
    let resp = list.send().await.map_err(|e| {
        err_502(
            format!("s3 ListObjectsV2: {}", s3_error_summary(&e)),
            "s3_list",
        )
    })?;

    let aad = envelope::aad("", owner, channel_id, 0);
    let mut events = Vec::new();
    for obj in resp.contents() {
        let Some(key) = obj.key() else { continue };
        let got = s3
            .get_object()
            .bucket(&state.config.channel_bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| err_502(format!("s3 GetObject: {}", s3_error_summary(&e)), "s3_get"))?;
        let bytes = got
            .body
            .collect()
            .await
            .map_err(|e| err_502(e.to_string(), "s3_body"))?
            .into_bytes();
        let plaintext = envelope::decrypt(&state.config.kek_hex, &bytes, &aad)
            .map_err(|e| err_500(e.to_string(), "channel_envelope_decrypt"))?;
        let event: ChannelEvent = serde_json::from_slice(&plaintext)
            .map_err(|e| err_500(e.to_string(), "channel_event_decode"))?;
        events.push(event);
    }
    Ok(events)
}

// ── teardown (owner-scoped feed GC; admin, not route-minted in phase 1) ──────

async fn channel_teardown(
    State(state): State<SharedChannelWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;
    // D8 (#430): teardown sweeps the OPERATOR-owned feed prefix.
    let owner = normalize_omni(&req.cap.payload.operator_omni);

    let outcome =
        channel_teardown_inner(&state, creds.as_ref(), &req.cap, &owner, &channel_id).await;
    let audit_body = agentkeys_core::audit::ChannelTeardownBody {
        channel_id: channel_id.clone(),
        actor_target: req.cap.payload.actor_omni.clone(),
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(
            &req.cap,
            AuditOpKind::ChannelTeardown,
            audit_body,
            audit_result,
        )
        .await;
    let deleted = outcome?;
    Ok(Json(TeardownResponse {
        ok: true,
        keys_deleted: deleted,
        audit_envelope_hash: audited?,
    }))
}

async fn channel_teardown_inner(
    state: &SharedChannelWorkerState,
    creds: Option<&StsCreds>,
    cap: &CapToken,
    owner: &str,
    channel_id: &str,
) -> Result<usize, ApiError> {
    let prefix = feed_prefix(owner, channel_id);
    let s3 = storage_s3(state, creds, cap, owner, channel_id).await?;
    let list = s3
        .list_objects_v2()
        .bucket(&state.config.channel_bucket)
        .prefix(&prefix)
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_list"))?;
    let keys: Vec<String> = list
        .contents()
        .iter()
        .filter_map(|o| o.key().map(String::from))
        .collect();
    let mut deleted = 0usize;
    for k in &keys {
        if s3
            .delete_object()
            .bucket(&state.config.channel_bucket)
            .key(k)
            .send()
            .await
            .is_ok()
        {
            deleted += 1;
        }
    }
    Ok(deleted)
}

// ── shared cap-verify + key helpers ──────────────────────────────────────────

async fn verify_cap(
    state: &SharedChannelWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    verify::verify_signature(&state.config.broker_pubkey_pem, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    // K10 proof-of-possession (#76 — broker-SPOF defense); shared across classes.
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    // Direction isolation (D2): a ChannelPublish cap is honored only at
    // /publish, a ChannelSubscribe cap only at /poll.
    verify::check_op(cap, expected_op).map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    // Per-data-class isolation (#90/#201): a memory/cred/config cap MUST NOT be
    // honored here (and a Channel cap is rejected by every other worker).
    verify::check_data_class(cap, DataClass::Channel)
        .map_err(|e| err_403(e.to_string(), "cap_data_class_mismatch"))?;
    verify::check_freshness(cap).map_err(|e| err_403(e.to_string(), "cap_freshness_failed"))?;
    verify::check_chain_device(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.registry_contract,
        cap,
    )
    .await
    .map_err(err_403_or_502)?;
    // Scope: skipped when operator == actor (master-self channels — mirrors
    // every worker); consulted for a delegate/device (operator != actor)
    // against the on-chain channel-pub:<id> / channel-sub:<id> grant.
    verify::check_chain_scope(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.scope_contract,
        cap,
    )
    .await
    .map_err(err_403_or_502)?;
    verify::check_chain_k3_epoch(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.epoch_contract,
        cap,
    )
    .await
    .map_err(err_403_or_502)?;
    Ok(())
}

fn err_403_or_502(e: verify::VerifyError) -> ApiError {
    match e {
        verify::VerifyError::DeviceInactive
        | verify::VerifyError::DeviceMismatch { .. }
        | verify::VerifyError::DeviceRoleMissing { .. }
        | verify::VerifyError::NotInScope
        | verify::VerifyError::K3Mismatch { .. } => err_403(e.to_string(), "chain_check_failed"),
        _ => err_502(e.to_string(), "chain_rpc"),
    }
}

/// Extract the channel id from a SIGNED cap service (`channel-pub:<id>` or
/// `channel-sub:<id>`). Binding the feed to the signed service is what stops a
/// `channel-pub:cam` cap from writing into a different channel's feed.
fn channel_id_from_service(service: &str) -> Result<String, ApiError> {
    let id = service
        .strip_prefix("channel-pub:")
        .or_else(|| service.strip_prefix("channel-sub:"))
        .ok_or_else(|| {
            err_400(
                format!("cap service {service:?} is not a channel-pub:/channel-sub: service"),
                "channel_service_shape",
            )
        })?;
    if id.is_empty() || id.contains(['/', '\\', '*', '?']) || id.contains("..") {
        return Err(err_400(
            "channel id must be non-empty and free of path/wildcard characters",
            "channel_id_shape",
        ));
    }
    Ok(id.to_lowercase())
}

fn normalize_omni(omni: &str) -> String {
    omni.trim_start_matches("0x").to_lowercase()
}

/// Feed S3 key: `bots/<owner>/channel/<channel_id>/<event_id>.enc`. Distinct
/// `channel/` prefix from memory/config/credentials so a single audit pass
/// covers every data class and the per-actor STS tag bounds the blast radius.
fn feed_key(owner: &str, channel_id: &str, event_id: &str) -> String {
    format!("bots/{owner}/channel/{channel_id}/{event_id}.enc")
}

fn feed_prefix(owner: &str, channel_id: &str) -> String {
    format!("bots/{owner}/channel/{channel_id}/")
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_key_uses_channel_prefix_not_memory_or_config() {
        // arch.md §17.2 separation: the channel worker writes to
        // bots/<owner>/channel/..., never memory/ config/ credentials/.
        let key = feed_key("abcdef", "cam-frontdoor", "0000000001-0000000000000001");
        assert_eq!(
            key,
            "bots/abcdef/channel/cam-frontdoor/0000000001-0000000000000001.enc"
        );
        assert!(!key.contains("memory/"));
        assert!(!key.contains("config/"));
        assert!(!key.contains("credentials"));
    }

    #[test]
    fn channel_id_derives_from_signed_service_either_direction() {
        assert_eq!(
            channel_id_from_service("channel-pub:cam-frontdoor").unwrap(),
            "cam-frontdoor"
        );
        assert_eq!(
            channel_id_from_service("channel-sub:family-weixin").unwrap(),
            "family-weixin"
        );
        // A memory service is not a channel service.
        assert!(channel_id_from_service("memory:travel").is_err());
        // Path/wildcard injection into the feed key is rejected.
        assert!(channel_id_from_service("channel-pub:../escape").is_err());
        assert!(channel_id_from_service("channel-pub:a/b").is_err());
    }

    #[test]
    fn feed_keys_sort_by_time_then_seq() {
        // The cursor relies on lexicographic ordering matching event order.
        let a = feed_key("o", "c", "0000000001-0000000000000001");
        let b = feed_key("o", "c", "0000000001-0000000000000002");
        let c = feed_key("o", "c", "0000000002-0000000000000000");
        assert!(a < b, "same millis, later seq sorts after");
        assert!(b < c, "later millis sorts after");
    }
}
