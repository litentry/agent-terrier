//! #594 — the delegate-sandbox LEASE SWEEPER: the "do it automatically" half
//! of expiry relaunch (plan `docs/plan/issue-594-sandbox-checkpoint-relaunch.md`).
//!
//! A veFaaS instance hard-expires at `create_time + Timeout` (extensions are
//! rejected at the cap by construction — #589), and nothing re-creates it
//! until a resolve/pairing-poll happens — i.e. until the owner opens
//! parent-control. Until then the delegate is chat-silent while every health
//! surface stays green (the classic silent-chat failure class). This sweeper
//! closes that gap: on a cadence it walks the durable #546 spawn-context rows
//! (the set of delegates the broker can re-create at all) and
//!
//! - **dead** (no live runtime — the lease already expired, or the instance
//!   died): cold-create through `ensure_for_delegate`; the replacement
//!   restores its state in-sandbox from the #594 checkpoint;
//! - **expiring soon** (lease inside the rotate margin): warm-rotate through
//!   the SAME #577 core the one-click update uses (fresh export → kill →
//!   re-create → import), so the hand-off carries a fresher snapshot than any
//!   periodic checkpoint. #340 background jobs defer the rotate until the
//!   force margin — at that point rotation kills them, but the lease was
//!   about to anyway.
//!
//! Authority: acting on a spawn-context row alone would resurrect delegates
//! revoked outside the broker (the row is provisioning data, never authority
//! — D1). Every action is therefore gated on a LIVE chain probe: registered ∧
//! ¬revoked ∧ TIER_AGENT, with the actor/operator omnis taken from the chain
//! read, exactly like the #577 handler. A probe failure (RPC down) SKIPS the
//! row — the sweeper never acts without a positive chain read.
//!
//! Default ON when a sandbox backend is configured; `AGENTKEYS_SANDBOX_AUTORELAUNCH=0`
//! opts a stack out (then parent-control's lease label + the #577 update
//! button remain the manual "ask the user" path). Note the steady-state
//! consequence: an ACTIVE binding now means a continuously-running sandbox —
//! archiving the delegate stays the way to stop running it (the #589
//! shorter-initial-lease / idle-cost decision is unchanged and open).

use std::time::Duration;

use crate::handlers::accept::{eth_call, load_accept_config, selector};
use crate::handlers::revoke::parse_device_probe;
use crate::handlers::update::{rotate_delegate_runtime, RotateError};
use crate::state::SharedState;

pub struct SweeperConfig {
    pub enabled: bool,
    pub interval: Duration,
    /// Rotate when the lease ends within this window.
    pub rotate_margin: Duration,
    /// Inside this window, rotate even over running #340 jobs.
    pub force_margin: Duration,
}

impl SweeperConfig {
    /// Pure construction from a lookup fn (the no-env-mutation-in-tests seam).
    pub fn from_lookup(read: &dyn Fn(&str) -> Option<String>) -> Self {
        let secs = |k: &str, lo: u64, hi: u64, default: u64| {
            read(k)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|s| (lo..=hi).contains(s))
                .unwrap_or(default)
        };
        let mins = |k: &str, lo: u64, hi: u64, default: u64| secs(k, lo, hi, default) * 60;
        Self {
            enabled: read("AGENTKEYS_SANDBOX_AUTORELAUNCH").as_deref() != Some("0"),
            interval: Duration::from_secs(secs(
                "AGENTKEYS_SANDBOX_SWEEP_INTERVAL_SECS",
                60,
                3_600,
                300,
            )),
            rotate_margin: Duration::from_secs(mins(
                "AGENTKEYS_SANDBOX_ROTATE_MARGIN_MINS",
                1,
                720,
                30,
            )),
            force_margin: Duration::from_secs(mins(
                "AGENTKEYS_SANDBOX_ROTATE_FORCE_MARGIN_MINS",
                1,
                720,
                10,
            )),
        }
    }

    pub fn from_env() -> Self {
        let read = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self::from_lookup(&read)
    }
}

/// Parse an `ExpireAt` into unix seconds. Input is RFC3339, because
/// [`ve_faas::normalize_expire_at`](crate::ve_faas::normalize_expire_at) has
/// already converted the vendor's shape at the boundary; empty / `?` means no
/// expiry (ECS, or a row without one).
///
/// This stays STRICT on purpose. The vendor's real layout is Go's `time.Time`
/// (`2026-08-15 15:50:54 +0800 CST`), whose trailing zone abbreviation is
/// ambiguous — teaching this parser to read it would put the format knowledge
/// in two places, and the earlier revision that assumed RFC3339 here is
/// exactly why no VE instance was ever warm-rotated (every sweep logged
/// `unparseable ExpireAt`). One owner, at the boundary; anything that still
/// arrives unrecognized is UNKNOWN and the caller does NOT rotate on a guess
/// (evidence policy: never invent the vendor's format).
pub(crate) fn parse_expire_at(raw: &str) -> Option<i64> {
    let t = raw.trim();
    if t.is_empty() || t == "?" {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(t)
        .map(|d| d.timestamp())
        .ok()
}

/// #669 — whether the `scheduled` policy has a tick due within `window`
/// seconds of `now` (UTC seconds; `tz_offset_minutes` shifts the wall clock
/// the cron is written against). Walks the window minute by minute — the
/// sweep interval is ≤ 3600 s, so at most ~60 `cron_matches` per entry.
pub(crate) fn schedule_tick_due_within(
    schedule: &[agentkeys_protocol::PresetSchedule],
    tz_offset_minutes: i64,
    now_unix: i64,
    window_secs: i64,
) -> bool {
    if schedule.is_empty() || window_secs <= 0 {
        return false;
    }
    let start_min = now_unix.div_euclid(60);
    let end_min = (now_unix + window_secs).div_euclid(60);
    for m in start_min..=end_min {
        let local = m * 60 + tz_offset_minutes * 60;
        let Some(dt) = chrono::DateTime::from_timestamp(local, 0) else {
            continue;
        };
        use chrono::{Datelike, Timelike};
        let (minute, hour, dom, month, dow) = (
            dt.minute(),
            dt.hour(),
            dt.day(),
            dt.month(),
            dt.weekday().num_days_from_sunday(),
        );
        if schedule
            .iter()
            .any(|s| agentkeys_protocol::cron_matches(&s.cron, minute, hour, dom, month, dow))
        {
            return true;
        }
    }
    false
}

/// #669 — the `availability` policy applied to a sweep decision: an
/// `always-on` app keeps today's behavior; a `wake-on-event` app is left
/// asleep (a feed event wakes it via `/v1/sandbox/wake`, its checkpoint
/// restores in-sandbox); a `scheduled` app is created / rotated only when a
/// schedule tick is due within the lookahead, else left asleep.
pub(crate) fn apply_availability(
    action: SweepAction,
    availability: agentkeys_protocol::Availability,
    tick_due: bool,
) -> SweepAction {
    use agentkeys_protocol::Availability;
    match availability {
        Availability::AlwaysOn => action,
        Availability::WakeOnEvent => SweepAction::None,
        Availability::Scheduled => {
            if tick_due {
                action
            } else {
                SweepAction::None
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SweepAction {
    /// Live and not near its lease end (or lease unknowable) — leave it.
    None,
    /// No live runtime — re-create cold (checkpoint restores in-sandbox).
    ColdCreate,
    /// Lease ends within the rotate margin — warm-rotate now; `force` = the
    /// force margin is also breached (rotate even over running jobs).
    Rotate { force: bool },
}

/// The per-delegate decision, pure: `live_expiries` is one entry per live
/// runtime (`None` = no/unparseable expiry — never rotated on).
pub(crate) fn decide(
    now_unix: i64,
    live_expiries: &[Option<i64>],
    rotate_margin: Duration,
    force_margin: Duration,
) -> SweepAction {
    if live_expiries.is_empty() {
        return SweepAction::ColdCreate;
    }
    let Some(earliest) = live_expiries.iter().flatten().min().copied() else {
        return SweepAction::None;
    };
    if earliest - now_unix <= rotate_margin.as_secs() as i64 {
        SweepAction::Rotate {
            force: earliest - now_unix <= force_margin.as_secs() as i64,
        }
    } else {
        SweepAction::None
    }
}

/// Spawn the sweeper task at boot (no-op without a sandbox backend or when
/// opted out).
pub fn spawn_if_enabled(state: SharedState) {
    let cfg = SweeperConfig::from_env();
    if state.sandbox.is_none() {
        return;
    }
    if !cfg.enabled {
        tracing::info!(
            "#594 lease sweeper: disabled via AGENTKEYS_SANDBOX_AUTORELAUNCH=0 — expired \
             delegates relaunch only on resolve or the parent-control update button"
        );
        return;
    }
    tracing::info!(
        interval_secs = cfg.interval.as_secs(),
        rotate_margin_secs = cfg.rotate_margin.as_secs(),
        force_margin_secs = cfg.force_margin.as_secs(),
        "#594 lease sweeper: starting (auto-relaunch of expired/expiring delegate sandboxes)"
    );
    tokio::spawn(async move {
        // Clear of the boot burst (precache registration, tier-2 probes).
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            sweep_once(&state, &cfg).await;
            tokio::time::sleep(cfg.interval).await;
        }
    });
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One pass over every durable spawn-context row. Per-row failures are logged
/// and never abort the sweep.
async fn sweep_once(state: &SharedState, cfg: &SweeperConfig) {
    let Some(backend) = state.sandbox.clone() else {
        return;
    };
    let rows = match state.spawn_context_store.list() {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "#594 lease sweeper: spawn-context list failed — sweep skipped");
            return;
        }
    };
    if rows.is_empty() {
        return;
    }
    let (chain_cfg, _broker_sk) = match load_accept_config() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "#594 lease sweeper: chain config unavailable — sweep skipped");
            return;
        }
    };
    for row in rows {
        // A row with no credential (pre-#546-era write) would re-create
        // chat-silent — same pre-flight as the #577 handler.
        if row.k10_address.is_empty() && row.k10_secret_hex.is_empty() {
            continue;
        }
        // D1 gate: act only on a POSITIVE chain read of an active TIER_AGENT
        // binding; the omnis come from the chain, never from the row.
        let hash = match hex::decode(&row.device_key_hash) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
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
                    "#594 lease sweeper: chain probe failed — row skipped this sweep"
                );
                continue;
            }
        };
        if !probe.registered || probe.revoked || probe.tier != 2 {
            // Revoked outside the broker → the row is stale; the confirmed-
            // revoke hook normally deletes it, so just leave it alone here.
            continue;
        }
        let actor_omni = format!("0x{}", hex::encode(probe.actor_omni));
        let operator_omni = format!("0x{}", hex::encode(probe.operator_omni));

        let live = match backend.live_for_device(&row.device_key_hash).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    device_key_hash = %row.device_key_hash,
                    error = %format!("{e:#}"),
                    "#594 lease sweeper: live-instance list failed — row skipped this sweep"
                );
                continue;
            }
        };
        let expiries: Vec<Option<i64>> = live
            .iter()
            .map(|i| {
                let parsed = parse_expire_at(&i.expire_at);
                if parsed.is_none() && !i.expire_at.trim().is_empty() && i.expire_at.trim() != "?" {
                    tracing::warn!(
                        sandbox_id = %i.id,
                        expire_at = %i.expire_at,
                        "#594 lease sweeper: unparseable ExpireAt — treating as no-expiry \
                         (never rotating on a guessed format)"
                    );
                }
                parsed
            })
            .collect();

        // #669 — the app's availability policy gates the action.
        let availability = row.availability();
        let tick_due = if availability == agentkeys_protocol::Availability::Scheduled {
            schedule_tick_due_within(
                &crate::handlers::presets::template_schedule(&row.preset_id),
                row.tz_offset_minutes,
                now_unix(),
                (cfg.interval + cfg.rotate_margin).as_secs() as i64,
            )
        } else {
            false
        };
        let action = apply_availability(
            decide(now_unix(), &expiries, cfg.rotate_margin, cfg.force_margin),
            availability,
            tick_due,
        );
        if action != SweepAction::None && availability.may_hibernate() {
            tracing::info!(
                device_key_hash = %row.device_key_hash,
                label = %row.label,
                availability = %availability.as_str(),
                "#669 lease sweeper: schedule tick due — waking a scheduled app"
            );
        }
        match action {
            SweepAction::None => {}
            SweepAction::ColdCreate => {
                tracing::info!(
                    device_key_hash = %row.device_key_hash,
                    label = %row.label,
                    "#594 lease sweeper: no live runtime — re-creating (checkpoint restores in-sandbox)"
                );
                let provision = crate::handlers::sandbox::ensure_for_delegate(
                    state,
                    &row.device_key_hash,
                    &actor_omni,
                    &operator_omni,
                )
                .await;
                if let Some(p) = provision {
                    if let Some(e) = p.error {
                        tracing::warn!(
                            device_key_hash = %row.device_key_hash,
                            error = %e,
                            "#594 lease sweeper: re-create failed — retrying next sweep"
                        );
                    }
                }
            }
            SweepAction::Rotate { force } => {
                tracing::info!(
                    device_key_hash = %row.device_key_hash,
                    label = %row.label,
                    force,
                    "#594 lease sweeper: lease ends within the margin — warm-rotating"
                );
                match rotate_delegate_runtime(
                    state,
                    &backend,
                    &row.device_key_hash,
                    &actor_omni,
                    &operator_omni,
                    probe.operator_omni,
                    force,
                    "lease-expiry",
                )
                .await
                {
                    Ok(outcome) => tracing::info!(
                        device_key_hash = %row.device_key_hash,
                        old = ?outcome.old_sandbox_ids,
                        migrated = outcome.session.migrated,
                        detail = %outcome.session.detail,
                        "#594 lease sweeper: rotated"
                    ),
                    Err(RotateError::JobsRunning(n)) => tracing::info!(
                        device_key_hash = %row.device_key_hash,
                        jobs = n,
                        "#594 lease sweeper: {n} job(s) running — deferring until the force margin"
                    ),
                    Err(RotateError::Failed(e)) => tracing::warn!(
                        device_key_hash = %row.device_key_hash,
                        error = %e,
                        "#594 lease sweeper: rotate failed — retrying next sweep"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_expire_at_reads_the_measured_vefaas_shape() {
        // The pinned probe fixture shape (ve_faas.rs parse_instances test).
        // Offset handling: +08:00 must land on the same instant as its UTC twin.
        let t = parse_expire_at("2026-07-06T00:00:00+08:00").expect("rfc3339 with offset");
        assert_eq!(Some(t), parse_expire_at("2026-07-05T16:00:00Z"));
        assert_eq!(parse_expire_at(""), None);
        assert_eq!(parse_expire_at("?"), None);
        assert_eq!(parse_expire_at("not-a-date"), None);
        // Unix-epoch digits are NOT a documented VE shape — refuse to guess.
        assert_eq!(parse_expire_at("1783353600"), None);
    }

    #[test]
    fn decide_covers_dead_expiring_and_healthy() {
        let m30 = Duration::from_secs(30 * 60);
        let m10 = Duration::from_secs(10 * 60);
        let now = 1_000_000;
        // Dead → cold create.
        assert_eq!(decide(now, &[], m30, m10), SweepAction::ColdCreate);
        // Healthy (lease far out) → nothing.
        assert_eq!(
            decide(now, &[Some(now + 7200)], m30, m10),
            SweepAction::None
        );
        // Inside the rotate margin, outside force → gentle rotate.
        assert_eq!(
            decide(now, &[Some(now + 20 * 60)], m30, m10),
            SweepAction::Rotate { force: false }
        );
        // Inside the force margin (or already past) → forced rotate.
        assert_eq!(
            decide(now, &[Some(now + 5 * 60)], m30, m10),
            SweepAction::Rotate { force: true }
        );
        assert_eq!(
            decide(now, &[Some(now - 60)], m30, m10),
            SweepAction::Rotate { force: true }
        );
        // Live but unknowable expiry (ECS / unparseable) → never rotate.
        assert_eq!(decide(now, &[None], m30, m10), SweepAction::None);
        // Multiple runtimes: the earliest lease drives.
        assert_eq!(
            decide(now, &[Some(now + 7200), Some(now + 60)], m30, m10),
            SweepAction::Rotate { force: true }
        );
    }

    /// #669 — the availability policy over the sweep decision.
    #[test]
    fn availability_policy_gates_the_sweep_action() {
        use agentkeys_protocol::Availability;
        let rot = SweepAction::Rotate { force: false };
        assert_eq!(
            apply_availability(SweepAction::ColdCreate, Availability::AlwaysOn, false),
            SweepAction::ColdCreate
        );
        assert_eq!(
            apply_availability(SweepAction::ColdCreate, Availability::WakeOnEvent, true),
            SweepAction::None
        );
        assert_eq!(
            apply_availability(
                SweepAction::Rotate { force: false },
                Availability::Scheduled,
                false
            ),
            SweepAction::None
        );
        assert_eq!(
            apply_availability(
                SweepAction::Rotate { force: false },
                Availability::Scheduled,
                true
            ),
            rot
        );
    }

    /// #669 — a schedule tick inside the lookahead (in the household's tz).
    #[test]
    fn schedule_tick_lookahead_honors_the_tz_offset() {
        let sched = vec![agentkeys_protocol::PresetSchedule {
            cron: "0 7 * * *".into(),
            label: "morning".into(),
            label_zh: String::new(),
            prompt: "plan".into(),
            session: None,
        }];
        // 2026-09-09 06:50 UTC+8 = 2026-09-08 22:50 UTC.
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-08T22:50:00Z")
            .unwrap()
            .timestamp();
        assert!(schedule_tick_due_within(&sched, 480, now, 15 * 60));
        assert!(!schedule_tick_due_within(&sched, 480, now, 5 * 60));
        // In UTC the same instant is 22:50 — the 07:00 tick is 8 h away.
        assert!(!schedule_tick_due_within(&sched, 0, now, 15 * 60));
        assert!(!schedule_tick_due_within(&[], 480, now, 3600));
    }

    #[test]
    fn config_defaults_bounds_and_kill_switch() {
        let none = |_: &str| None;
        let cfg = SweeperConfig::from_lookup(&none);
        assert!(cfg.enabled);
        assert_eq!(cfg.interval.as_secs(), 300);
        assert_eq!(cfg.rotate_margin.as_secs(), 30 * 60);
        assert_eq!(cfg.force_margin.as_secs(), 10 * 60);

        let custom = |k: &str| match k {
            "AGENTKEYS_SANDBOX_AUTORELAUNCH" => Some("0".to_string()),
            "AGENTKEYS_SANDBOX_SWEEP_INTERVAL_SECS" => Some("60".to_string()),
            "AGENTKEYS_SANDBOX_ROTATE_MARGIN_MINS" => Some("5".to_string()),
            "AGENTKEYS_SANDBOX_ROTATE_FORCE_MARGIN_MINS" => Some("2".to_string()),
            _ => None,
        };
        let cfg = SweeperConfig::from_lookup(&custom);
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval.as_secs(), 60);
        assert_eq!(cfg.rotate_margin.as_secs(), 300);
        assert_eq!(cfg.force_margin.as_secs(), 120);

        // Out-of-bounds tuning falls back to defaults (never a 1s hot loop).
        let wild = |k: &str| match k {
            "AGENTKEYS_SANDBOX_SWEEP_INTERVAL_SECS" => Some("1".to_string()),
            "AGENTKEYS_SANDBOX_ROTATE_MARGIN_MINS" => Some("100000".to_string()),
            _ => None,
        };
        let cfg = SweeperConfig::from_lookup(&wild);
        assert_eq!(cfg.interval.as_secs(), 300);
        assert_eq!(cfg.rotate_margin.as_secs(), 30 * 60);
    }
}
