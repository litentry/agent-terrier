use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;

use agentkeys_core::audit::{AuditOpKind, AuditResult, ChannelPublishBody, ChannelSubscribeBody};
use agentkeys_protocol::{ChannelDirection, ChannelEvent, ChannelProducer};
use agentkeys_worker_creds::audit::{cap_hash, keccak_hex, zero_hash};
use agentkeys_worker_creds::envelope;
use agentkeys_worker_creds::errors::{err_400, err_403, err_413, err_500, ApiError};
use agentkeys_worker_creds::storage_worker::{self, storage_error};
use agentkeys_worker_creds::verify::{CapOp, CapToken, DataClass};

use crate::state::SharedChannelWorkerState;

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn build_router(state: SharedChannelWorkerState) -> Router {
    let blob_body_limit = state.config.blob_max_bytes / 3 * 4 + (256 << 10);
    let browser_origins = state.worker.config.browser_origins.clone();
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/channel/publish", post(channel_publish))
        .route("/v1/channel/poll", post(channel_poll))
        .route("/v1/channel/teardown", post(channel_teardown))
        .route(
            "/v1/channel/blob-put",
            post(channel_blob_put).layer(axum::extract::DefaultBodyLimit::max(blob_body_limit)),
        )
        .route(
            "/v1/channel/blob-get",
            post(channel_blob_get).layer(axum::extract::DefaultBodyLimit::max(blob_body_limit)),
        );
    router
        .layer(agentkeys_worker_creds::cors::browser_cors_layer(
            &browser_origins,
        ))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub data_class: DataClass,
    pub chain_profile: String,
    pub max_poll_seconds: u64,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedChannelWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        data_class: DataClass::Channel,
        chain_profile: state.worker.config.chain_profile.clone(),
        max_poll_seconds: state.config.max_poll_seconds,
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub type PublishRequest = agentkeys_protocol::ChannelPublishBody<CapToken>;
pub type PollRequest = agentkeys_protocol::ChannelPollBody<CapToken>;
pub type TeardownRequest = agentkeys_protocol::ChannelTeardownBody<CapToken>;
pub use agentkeys_protocol::{
    ChannelPollResp as PollResponse, ChannelPublishResp as PublishResponse,
    ChannelTeardownResp as TeardownResponse,
};

async fn channel_publish(
    State(state): State<SharedChannelWorkerState>,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::ChannelPublish).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;

    let outcome = channel_publish_inner(&state, &req, &channel_id).await;
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
        .worker
        .audit
        .emit(
            &req.cap,
            AuditOpKind::ChannelPublish,
            audit_body,
            audit_result,
        )
        .await;
    let (event_id, s3_key, _env) = outcome?;
    state.wakeup.signal(&feed_prefix(
        &normalize_omni(&req.cap.payload.operator_omni),
        &channel_id,
    ));
    if matches!(req.direction, ChannelDirection::In) && state.wake.is_some() {
        let state = state.clone();
        let request = agentkeys_protocol::ChannelWakeRequest {
            owner_omni: format!("0x{}", normalize_omni(&req.cap.payload.operator_omni)),
            channel_id: channel_id.clone(),
            event_ts_ms: event_id
                .split('-')
                .next()
                .and_then(|value| value.parse().ok()),
        };
        tokio::spawn(async move {
            if let Some(wake) = &state.wake {
                if wake.wake(&request).await.is_err() {
                    tracing::warn!("channel message stored; configured application wake failed");
                }
            }
        });
    }
    Ok(Json(PublishResponse {
        ok: true,
        event_id,
        s3_key,
        audit_envelope_hash: audited?,
    }))
}

async fn channel_publish_inner(
    state: &SharedChannelWorkerState,
    req: &PublishRequest,
    channel_id: &str,
) -> Result<(String, String, Vec<u8>), ApiError> {
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
            let decoded = STANDARD
                .decode(b64)
                .map_err(|e| err_400(e.to_string(), "channel_body_b64_decode"))?;
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
    let owner = normalize_omni(&req.cap.payload.operator_omni);

    let event = ChannelEvent {
        event_id: event_id.clone(),
        channel_id: channel_id.to_string(),
        direction: req.direction,
        producer: ChannelProducer::Actor {
            actor_omni: format!("0x{}", normalize_omni(&req.cap.payload.actor_omni)),
        },
        kind: req.kind,
        body,
        body_ref,
        ts_millis: now_millis,
        correlation: req.correlation.clone(),
        audio: req.audio.clone(),
        partial: req.partial,
        seq: req.seq,
        stream: req.stream,
        contact: req.contact.clone(),
        content_type: req.content_type.clone(),
        relay_of: req.relay_of.clone(),
        addressee: req.addressee.clone(),
    };
    let plaintext =
        serde_json::to_vec(&event).map_err(|e| err_500(e.to_string(), "channel_event_encode"))?;

    let key = feed_key(&owner, channel_id, &event_id);
    let aad = object_aad(&owner, &key);
    let env_bytes = envelope::encrypt(development_key(state)?, &plaintext, &aad)
        .map_err(|e| err_500(e.to_string(), "channel_envelope_encrypt"))?;

    state
        .worker
        .storage
        .put(&req.cap, &key, &env_bytes, Some(""))
        .await
        .map_err(storage_error)?;
    Ok((event_id, key, env_bytes))
}

pub type BlobPutRequest = agentkeys_protocol::ChannelBlobPutBody<CapToken>;
pub type BlobGetRequest = agentkeys_protocol::ChannelBlobGetBody<CapToken>;

fn blob_key(owner: &str, channel_id: &str, blob_id: &str) -> String {
    format!("bots/{owner}/channel/{channel_id}.blob/{blob_id}.enc")
}

fn parse_blob_ref(body_ref: &str) -> Option<(String, String, String)> {
    let rest = body_ref.strip_prefix("bots/")?;
    let (owner, rest) = rest.split_once("/channel/")?;
    let (channel_with_blob, blob_file) = rest.rsplit_once('/')?;
    let channel_id = channel_with_blob.strip_suffix(".blob")?;
    let blob_id = blob_file.strip_suffix(".enc")?;
    if owner.is_empty()
        || channel_id.is_empty()
        || blob_id.is_empty()
        || channel_id.contains('/')
        || blob_id.contains('/')
    {
        return None;
    }
    Some((
        owner.to_string(),
        channel_id.to_string(),
        blob_id.to_string(),
    ))
}

fn encode_blob_plaintext(content_type: &str, bytes: &[u8]) -> Vec<u8> {
    let ct = content_type.as_bytes();
    let ct_len = ct.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(2 + ct_len + bytes.len());
    out.extend_from_slice(&(ct_len as u16).to_be_bytes());
    out.extend_from_slice(&ct[..ct_len]);
    out.extend_from_slice(bytes);
    out
}

fn decode_blob_plaintext(plaintext: &[u8]) -> Option<(String, &[u8])> {
    if plaintext.len() < 2 {
        return None;
    }
    let ct_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    let rest = &plaintext[2..];
    if rest.len() < ct_len {
        return None;
    }
    let content_type = String::from_utf8(rest[..ct_len].to_vec()).ok()?;
    Some((content_type, &rest[ct_len..]))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

async fn channel_blob_put(
    State(state): State<SharedChannelWorkerState>,
    Json(req): Json<BlobPutRequest>,
) -> Result<Json<agentkeys_protocol::ChannelBlobPutResp>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::ChannelPublish).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;
    let owner = normalize_omni(&req.cap.payload.operator_omni);
    let bytes = STANDARD
        .decode(&req.bytes_b64)
        .map_err(|e| err_400(e.to_string(), "channel_blob_b64_decode"))?;
    let max = state.config.blob_max_bytes;
    if bytes.is_empty() {
        return Err(err_400("blob is empty", "channel_blob_empty"));
    }
    if bytes.len() > max {
        return Err(err_413(
            format!(
                "blob is {} bytes decoded (max {max}, --blob-max-bytes)",
                bytes.len()
            ),
            "channel_blob_too_large",
        ));
    }
    let content_type = req.content_type.trim();
    if content_type.is_empty() || content_type.len() > 200 || content_type.contains('\n') {
        return Err(err_400(
            "content_type must be a non-empty media type",
            "channel_blob_content_type",
        ));
    }
    let sha256 = sha256_hex(&bytes);
    let now_millis = unix_millis();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let blob_id = format!("{now_millis:013}-{seq:016x}");
    let key = blob_key(&owner, &channel_id, &blob_id);
    let aad = object_aad(&owner, &key);
    let plaintext = encode_blob_plaintext(content_type, &bytes);
    let env_bytes = envelope::encrypt(development_key(&state)?, &plaintext, &aad)
        .map_err(|e| err_500(e.to_string(), "channel_envelope_encrypt"))?;
    let outcome: Result<(), ApiError> = async {
        state
            .worker
            .storage
            .put(&req.cap, &key, &env_bytes, Some(""))
            .await
            .map_err(storage_error)?;
        Ok(())
    }
    .await;
    let audit_body = ChannelPublishBody {
        key: key.clone(),
        channel_id: channel_id.clone(),
        event_id: blob_id.clone(),
        payload_hash: if outcome.is_ok() {
            keccak_hex(&env_bytes)
        } else {
            zero_hash()
        },
    };
    let audited = state
        .worker
        .audit
        .emit(
            &req.cap,
            AuditOpKind::ChannelPublish,
            audit_body,
            if outcome.is_ok() {
                AuditResult::Success
            } else {
                AuditResult::Failure
            },
        )
        .await;
    outcome?;
    audited?;
    Ok(Json(agentkeys_protocol::ChannelBlobPutResp {
        ok: true,
        body_ref: key,
        bytes: bytes.len() as u64,
        sha256,
    }))
}

async fn channel_blob_get(
    State(state): State<SharedChannelWorkerState>,
    Json(req): Json<BlobGetRequest>,
) -> Result<Json<agentkeys_protocol::ChannelBlobGetResp>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::ChannelSubscribe).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;
    let owner = normalize_omni(&req.cap.payload.operator_omni);
    let Some((ref_owner, ref_channel, _blob_id)) = parse_blob_ref(&req.body_ref) else {
        return Err(err_400(
            "body_ref is not a blob reference of this worker",
            "channel_blob_ref_shape",
        ));
    };
    if ref_owner != owner || ref_channel != channel_id {
        return Err(err_403(
            format!(
                "body_ref names feed {ref_channel} of {ref_owner}; the cap authorizes {channel_id}"
            ),
            "blob_ref_out_of_feed",
        ));
    }
    let aad = object_aad(&owner, &req.body_ref);
    let fetched: Result<(String, Vec<u8>), ApiError> = async {
        let bytes = state
            .worker
            .storage
            .get(&req.cap, &req.body_ref)
            .await
            .map_err(storage_error)?
            .bytes;
        let plaintext = envelope::decrypt(development_key(&state)?, &bytes, &aad)
            .map_err(|e| err_500(e.to_string(), "channel_envelope_decrypt"))?;
        let (content_type, raw) = decode_blob_plaintext(&plaintext)
            .ok_or_else(|| err_500("blob plaintext layout invalid", "channel_blob_decode"))?;
        Ok((content_type, raw.to_vec()))
    }
    .await;
    let audit_body = ChannelSubscribeBody {
        channel_id: channel_id.clone(),
        cursor: req.body_ref.clone(),
        event_count: u64::from(fetched.is_ok()),
        cap_hash: cap_hash(&req.cap),
    };
    let audited = state
        .worker
        .audit
        .emit(
            &req.cap,
            AuditOpKind::ChannelSubscribe,
            audit_body,
            if fetched.is_ok() {
                AuditResult::Success
            } else {
                AuditResult::Failure
            },
        )
        .await;
    let (content_type, raw) = fetched?;
    audited?;
    Ok(Json(agentkeys_protocol::ChannelBlobGetResp {
        ok: true,
        content_type,
        sha256: sha256_hex(&raw),
        bytes_b64: STANDARD.encode(raw),
    }))
}

async fn channel_poll(
    State(state): State<SharedChannelWorkerState>,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::ChannelSubscribe).await?;
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;
    let owner = normalize_omni(&req.cap.payload.operator_omni);

    let waiter = state.wakeup.waiter(&feed_prefix(&owner, &channel_id));

    let mut events =
        channel_list_after(&state, &req.cap, &owner, &channel_id, &req.after, req.tail).await?;

    if events.is_empty() && req.wait_seconds > 0 {
        let wait = req.wait_seconds.min(state.config.max_poll_seconds);
        let _ = tokio::time::timeout(Duration::from_secs(wait), waiter.notified()).await;
        events =
            channel_list_after(&state, &req.cap, &owner, &channel_id, &req.after, req.tail).await?;
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
        .worker
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

async fn channel_list_after(
    state: &SharedChannelWorkerState,
    cap: &CapToken,
    owner: &str,
    channel_id: &str,
    after: &str,
    tail: Option<u32>,
) -> Result<Vec<ChannelEvent>, ApiError> {
    let prefix = feed_prefix(owner, channel_id);
    if !after.is_empty() && !after.starts_with(&prefix) {
        return Err(err_400(
            "cursor belongs to another channel",
            "channel_cursor_out_of_scope",
        ));
    }
    let tail_n = tail.map(|count| count as usize).filter(|count| *count > 0);
    let mut keys = Vec::new();
    let mut continuation = (!after.is_empty()).then(|| after.to_string());
    loop {
        let page = state
            .worker
            .storage
            .list(cap, &prefix, continuation.as_deref())
            .await
            .map_err(storage_error)?;
        keys.extend(page.keys);
        if let Some(count) = tail_n {
            keep_tail(&mut keys, count);
        }
        continuation = page.next;
        if tail_n.is_none() || continuation.is_none() {
            break;
        }
    }

    let mut events = Vec::new();
    for key in keys {
        let aad = object_aad(owner, &key);
        let bytes = state
            .worker
            .storage
            .get(cap, &key)
            .await
            .map_err(storage_error)?
            .bytes;
        let plaintext = envelope::decrypt(development_key(state)?, &bytes, &aad)
            .map_err(|e| err_500(e.to_string(), "channel_envelope_decrypt"))?;
        let event: ChannelEvent = serde_json::from_slice(&plaintext)
            .map_err(|e| err_500(e.to_string(), "channel_event_decode"))?;
        events.push(event);
    }
    Ok(events)
}

async fn channel_teardown(
    State(state): State<SharedChannelWorkerState>,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;
    if normalize_omni(&req.cap.payload.operator_omni) != normalize_omni(&req.cap.payload.actor_omni)
    {
        return Err(err_403(
            "channel deletion requires owner-self authority",
            "channel_not_owner",
        ));
    }
    let channel_id = channel_id_from_service(&req.cap.payload.service)?;
    let owner = normalize_omni(&req.cap.payload.operator_omni);

    let outcome = channel_teardown_inner(&state, &req.cap, &owner, &channel_id).await;
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
        .worker
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
    cap: &CapToken,
    owner: &str,
    channel_id: &str,
) -> Result<usize, ApiError> {
    let mut deleted = 0;
    for prefix in [
        feed_prefix(owner, channel_id),
        format!("bots/{owner}/channel/{channel_id}.blob/"),
    ] {
        deleted += storage_worker::delete_prefix(&state.worker, cap, &prefix).await?;
    }
    Ok(deleted)
}

async fn verify_cap(
    state: &SharedChannelWorkerState,
    cap: &CapToken,
    operation: CapOp,
) -> Result<(), ApiError> {
    storage_worker::verify_cap(&state.worker, cap, operation, DataClass::Channel).await
}

fn development_key(state: &SharedChannelWorkerState) -> Result<&str, ApiError> {
    state
        .worker
        .config
        .development_kek
        .as_deref()
        .map(String::as_str)
        .ok_or_else(|| {
            err_500(
                "channel encryption requires a protected development key",
                "development_kek_missing",
            )
        })
}

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
    if !agentkeys_protocol::console::valid_channel_id(id) {
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

fn object_aad(owner: &str, key: &str) -> Vec<u8> {
    envelope::aad("", owner, key, 0)
}

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
        assert!(channel_id_from_service("knowledge:travel").is_err());
        assert!(channel_id_from_service("channel-pub:../escape").is_err());
        assert!(channel_id_from_service("channel-pub:a/b").is_err());
    }

    #[test]
    fn blob_key_is_a_sibling_of_the_feed_prefix_and_refs_parse_back() {
        let key = blob_key("abcdef", "weixin-chef", "0000000001-0000000000000001");
        assert_eq!(
            key,
            "bots/abcdef/channel/weixin-chef.blob/0000000001-0000000000000001.enc"
        );
        assert!(!key.starts_with(&feed_prefix("abcdef", "weixin-chef")));
        assert_eq!(
            parse_blob_ref(&key),
            Some((
                "abcdef".to_string(),
                "weixin-chef".to_string(),
                "0000000001-0000000000000001".to_string()
            ))
        );
        assert!(parse_blob_ref(&feed_key("abcdef", "weixin-chef", "x")).is_none());
        assert!(parse_blob_ref("bots/a/channel/c.blob/../x.enc").is_none());
        assert!(parse_blob_ref("memory/a/b.blob/c.enc").is_none());
    }

    #[test]
    fn blob_plaintext_layout_round_trips_the_original_bytes() {
        let raw = [0xffu8, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F'];
        let pt = encode_blob_plaintext("image/jpeg", &raw);
        let (ct, bytes) = decode_blob_plaintext(&pt).unwrap();
        assert_eq!(ct, "image/jpeg");
        assert_eq!(bytes, &raw);
        assert!(decode_blob_plaintext(&[0x00]).is_none());
        assert!(decode_blob_plaintext(&[0x00, 0x09, b'a']).is_none());
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn feed_keys_sort_by_time_then_seq() {
        let a = feed_key("o", "c", "0000000001-0000000000000001");
        let b = feed_key("o", "c", "0000000001-0000000000000002");
        let c = feed_key("o", "c", "0000000002-0000000000000000");
        assert!(a < b, "same millis, later seq sorts after");
        assert!(b < c, "later millis sorts after");
    }
}

fn keep_tail(keys: &mut Vec<String>, n: usize) {
    if keys.len() > n {
        keys.drain(..keys.len() - n);
    }
}

#[cfg(test)]
mod tail_tests {
    use super::keep_tail;

    #[test]
    fn the_tail_is_the_last_n_keys_across_pages() {
        let mut keys: Vec<String> = (1..=1000).map(|i| format!("k{i:05}")).collect();
        keep_tail(&mut keys, 3);
        assert_eq!(keys, vec!["k00998", "k00999", "k01000"]);
        keys.extend((1001..=1002).map(|i| format!("k{i:05}")));
        keep_tail(&mut keys, 3);
        assert_eq!(keys, vec!["k01000", "k01001", "k01002"]);
        let mut few = vec!["a".to_string()];
        keep_tail(&mut few, 3);
        assert_eq!(few, vec!["a"]);
    }
}
