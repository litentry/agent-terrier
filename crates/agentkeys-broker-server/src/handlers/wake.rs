//! #669 — `POST /v1/sandbox/wake`: the channel worker's write-through wake for
//! a hibernating application (plan §3.4 "app ≠ process", channel spec D9
//! "always-available without always-on"). When a publish lands on a feed, the
//! worker tells the broker; every durable spawn-context row whose
//! `bound_channels` names that feed AND whose `availability` allows sleep is
//! ensured (cold-created if dead) through the SAME #546 path the resolve /
//! sweeper use — nothing an app can observe changes.
//!
//! Creation runs separately from the request, once per delegate at a time
//! (`AppState::wake_creates_in_flight`), so a request timeout cannot cancel it
//! or trigger a competing creation. The runtime receives a replay window
//! (`AGENTKEYS_WAKE_SINCE_MS`) that includes the event which woke it.
//!
//! Authority: the caller is the co-located channel worker (the #541 host-minted
//! `AGENTKEYS_CHANNEL_STS_TOKEN` bearer — the same worker-only trust the
//! channel-sts mint uses); every create is still gated on a LIVE chain probe
//! (registered ∧ ¬revoked ∧ TIER_AGENT, omnis from the chain — D1), exactly
//! like the lease sweeper. The row is provisioning data; the wake cannot widen
//! anything: a delegate that was never granted the feed has no row naming it.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;

use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::handlers::accept::{eth_call, load_accept_config, selector};
use crate::handlers::channel_sts::constant_time_str_eq;
use crate::handlers::revoke::parse_device_probe;
use crate::state::SharedState;

pub use agentkeys_protocol::ChannelWakeRequest as WakeRequest;

/// How long a cold-create claim holds before a new wake may create again. A
/// create + adopt stays well under it; a crashed task must not pin the
/// delegate forever.
const CREATE_CLAIM_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Claim the cold-create for a delegate in `claims` (pure over the map):
/// `true` = ours to run; `false` = one is already in flight — join it.
pub(crate) fn claim_create_in(
    claims: &mut std::collections::HashMap<String, std::time::Instant>,
    device_key_hash: &str,
    now: std::time::Instant,
) -> bool {
    claims.retain(|_, started| now.duration_since(*started) < CREATE_CLAIM_TTL);
    if claims.contains_key(device_key_hash) {
        return false;
    }
    claims.insert(device_key_hash.to_string(), now);
    true
}

fn claim_create(state: &SharedState, device_key_hash: &str) -> bool {
    match state.wake_creates_in_flight.lock() {
        Ok(mut m) => claim_create_in(&mut m, device_key_hash, std::time::Instant::now()),
        Err(_) => true,
    }
}

fn release_create(state: &SharedState, device_key_hash: &str) {
    if let Ok(mut m) = state.wake_creates_in_flight.lock() {
        m.remove(device_key_hash);
    }
}

/// The unix-ms the woken sandbox replays its feeds from: the waking event
/// minus a margin (the feed hop's own latency, clock skew), or — when the
/// worker sent no timestamp — the last two minutes.
pub(crate) fn wake_replay_since(event_ts_ms: Option<u64>, now_ms: u64) -> u64 {
    const MARGIN_MS: u64 = 5_000;
    const FALLBACK_MS: u64 = 120_000;
    match event_ts_ms {
        Some(t) if t > 0 => t.saturating_sub(MARGIN_MS),
        _ => now_ms.saturating_sub(FALLBACK_MS),
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Serialize)]
pub struct WakeResponse {
    pub ok: bool,
    /// The device key hashes whose sandbox was ensured (empty = nothing sleeps
    /// on this feed — the common always-on case).
    pub woken: Vec<String>,
    pub skipped: usize,
}

/// The rows a publish on `channel_id` wakes: bound to the feed AND allowed to
/// hibernate. PURE (the handler supplies the rows).
pub(crate) fn rows_to_wake<'a>(
    rows: &'a [crate::storage::SpawnContext],
    channel_id: &str,
) -> Vec<&'a crate::storage::SpawnContext> {
    rows.iter()
        .filter(|r| r.availability().may_hibernate())
        .filter(|r| {
            r.bound_channels()
                .iter()
                .any(|b| b.channel_id == channel_id && b.direction.reads())
        })
        .collect()
}

pub async fn sandbox_wake(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<WakeRequest>,
) -> BrokerResult<Json<WakeResponse>> {
    let expected_bearer = &state.config.channel_sts_token;
    if expected_bearer.is_empty() {
        return Err(BrokerError::Internal(
            "sandbox wake not configured: AGENTKEYS_CHANNEL_STS_TOKEN is unset; \
             configure the same protected token for the broker and channel worker"
                .into(),
        ));
    }
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;
    if !constant_time_str_eq(got, expected_bearer) {
        return Err(BrokerError::Unauthorized("wake bearer invalid".into()));
    }
    let channel_id = req.channel_id.trim().to_string();
    if channel_id.is_empty() {
        return Err(BrokerError::BadRequest("channel_id is empty".into()));
    }
    let Some(backend) = state.sandbox.clone() else {
        return Ok(Json(WakeResponse {
            ok: true,
            woken: Vec::new(),
            skipped: 0,
        }));
    };
    let rows = state.spawn_context_store.list()?;
    let candidates = rows_to_wake(&rows, &channel_id);
    if candidates.is_empty() {
        return Ok(Json(WakeResponse {
            ok: true,
            woken: Vec::new(),
            skipped: 0,
        }));
    }
    let (chain_cfg, _) = load_accept_config().map_err(BrokerError::Internal)?;
    let owner = crate::handlers::accept::norm_omni(&req.owner_omni);
    let mut woken = Vec::new();
    let mut skipped = 0usize;
    for row in candidates {
        // D1 gate — identical to the sweeper's: act only on a positive chain
        // read of an active TIER_AGENT binding owned by the feed's owner.
        let hash = match hex::decode(&row.device_key_hash) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                skipped += 1;
                continue;
            }
        };
        let data = format!("0x{}{}", selector("getDevice(bytes32)"), hex::encode(hash));
        let probe = match eth_call(&state.http, &chain_cfg.rpc_url, &chain_cfg.registry, &data)
            .await
            .and_then(|raw| parse_device_probe(&raw))
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    device_key_hash = %row.device_key_hash,
                    error = %e,
                    "#669 sandbox wake: chain probe failed — row skipped"
                );
                skipped += 1;
                continue;
            }
        };
        let operator_omni_hex = hex::encode(probe.operator_omni);
        if !probe.is_registered() || probe.revoked || probe.tier != 2 || operator_omni_hex != owner
        {
            skipped += 1;
            continue;
        }
        let live = backend
            .live_for_device(&row.device_key_hash)
            .await
            .unwrap_or_default();
        if !live.is_empty() {
            // Already running — the feed's NRT poll delivers; nothing to do.
            continue;
        }
        let actor_omni = format!("0x{}", hex::encode(probe.actor_omni));
        let operator_omni = format!("0x{operator_omni_hex}");
        if !claim_create(&state, &row.device_key_hash) {
            tracing::info!(
                device_key_hash = %row.device_key_hash,
                label = %row.label,
                channel = %channel_id,
                "#669 sandbox wake: a cold-create is already in flight for this app — joining it (its replay window covers this event too)"
            );
            woken.push(row.device_key_hash.clone());
            continue;
        }
        let since_ms = wake_replay_since(req.event_ts_ms, now_unix_ms());
        tracing::info!(
            device_key_hash = %row.device_key_hash,
            label = %row.label,
            channel = %channel_id,
            replay_since_ms = since_ms,
            "#669 sandbox wake: feed event for a hibernating app — cold-creating (detached from this request)"
        );
        let st = state.clone();
        let dkh = row.device_key_hash.clone();
        let label = row.label.clone();
        let channel = channel_id.clone();
        tokio::spawn(async move {
            let extra = vec![(
                agentkeys_protocol::sandbox_env::WAKE_SINCE_MS.to_string(),
                since_ms.to_string(),
            )];
            let provision = crate::handlers::sandbox::ensure_for_delegate_extra(
                &st,
                &dkh,
                &actor_omni,
                &operator_omni,
                &extra,
            )
            .await;
            release_create(&st, &dkh);
            match provision {
                Some(p) if p.error.is_none() => tracing::info!(
                    device_key_hash = %dkh,
                    label = %label,
                    channel = %channel,
                    sandbox_id = p.sandbox_id.as_deref().unwrap_or("-"),
                    "#669 sandbox wake: cold-create done — the app replays the feed from the wake window"
                ),
                Some(p) => tracing::warn!(
                    device_key_hash = %dkh,
                    label = %label,
                    error = ?p.error,
                    "#669 sandbox wake: create failed — the sweeper / next event retries"
                ),
                None => tracing::warn!(
                    device_key_hash = %dkh,
                    "#669 sandbox wake: no sandbox backend — nothing created"
                ),
            }
        });
        woken.push(row.device_key_hash.clone());
    }
    Ok(Json(WakeResponse {
        ok: true,
        woken,
        skipped,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SpawnContext;

    /// The second wake within the claim window joins the first create; a
    /// stale claim (the task died) expires; a released claim frees the slot.
    #[test]
    fn one_cold_create_per_delegate_at_a_time() {
        let mut claims = std::collections::HashMap::new();
        let t0 = std::time::Instant::now();
        assert!(claim_create_in(&mut claims, "dkh-a", t0));
        assert!(!claim_create_in(
            &mut claims,
            "dkh-a",
            t0 + std::time::Duration::from_secs(7)
        ));
        assert!(claim_create_in(&mut claims, "dkh-b", t0));
        assert!(claim_create_in(
            &mut claims,
            "dkh-a",
            t0 + CREATE_CLAIM_TTL + std::time::Duration::from_secs(1)
        ));
        claims.remove("dkh-b");
        assert!(claim_create_in(
            &mut claims,
            "dkh-b",
            t0 + std::time::Duration::from_secs(1)
        ));
    }

    /// The replay window starts a margin before the waking event; an older
    /// worker that sent no timestamp gets the last two minutes.
    #[test]
    fn the_replay_window_starts_at_the_waking_event() {
        assert_eq!(
            wake_replay_since(Some(1_790_485_817_236), 1_790_485_900_000),
            1_790_485_812_236
        );
        assert_eq!(
            wake_replay_since(None, 1_790_485_900_000),
            1_790_485_780_000
        );
        assert_eq!(
            wake_replay_since(Some(0), 1_790_485_900_000),
            1_790_485_780_000
        );
        assert_eq!(wake_replay_since(Some(1_000), 5_000), 0);
    }

    fn row(label: &str, availability: &str, feeds: &[(&str, &str)]) -> SpawnContext {
        let bound: Vec<agentkeys_protocol::BoundChannel> = feeds
            .iter()
            .map(|(id, dir)| agentkeys_protocol::BoundChannel {
                slot: "s".into(),
                kind: agentkeys_protocol::ChannelEndpointKind::Messaging,
                direction: match *dir {
                    "pub" => agentkeys_protocol::SlotDirection::Pub,
                    "duplex" => agentkeys_protocol::SlotDirection::Duplex,
                    _ => agentkeys_protocol::SlotDirection::Sub,
                },
                channel_id: (*id).to_string(),
                event_kinds: vec![],
                endpoint_actor_omni: None,
                default_app: None,
            })
            .collect();
        SpawnContext {
            device_key_hash: format!("{:0>64}", label.len()),
            label: label.into(),
            chat_channel_id: format!("opchat-{label}"),
            k10_address: "0xabc".into(),
            memory_ns: format!("app-{label}"),
            created_at: 1,
            preset_id: label.into(),
            bound_channels_json: serde_json::to_string(&bound).unwrap(),
            availability: availability.into(),
            memory_namespaces: String::new(),
            tz_offset_minutes: 0,
            context_version: 0,
            context_hash: String::new(),
        }
    }

    #[test]
    fn only_hibernating_rows_bound_to_the_feed_as_readers_wake() {
        let rows = vec![
            row("chef", "always-on", &[("weixin-chef", "sub")]),
            row(
                "dog",
                "wake-on-event",
                &[("entry-cam", "sub"), ("weixin-dog", "pub")],
            ),
            row("report", "scheduled", &[("entry-cam", "duplex")]),
            row("legacy", "", &[]),
        ];
        let woke: Vec<&str> = rows_to_wake(&rows, "entry-cam")
            .iter()
            .map(|r| r.label.as_str())
            .collect();
        assert_eq!(woke, vec!["dog", "report"]);
        // An always-on app never needs a wake (it is running).
        assert!(rows_to_wake(&rows, "weixin-chef").is_empty());
        // A pub-only binding is not a reason to wake (nothing arrives for it).
        assert!(rows_to_wake(&rows, "weixin-dog").is_empty());
        assert!(rows_to_wake(&rows, "unknown").is_empty());
    }
}
