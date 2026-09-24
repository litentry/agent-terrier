//! #669 — R4 SCHEDULES as clock events (plan §3.3 / §4.4 R4): the app
//! template's `schedule[]` entries fire as agent turns, guard-gated on the
//! delegate's `tool:schedule` grant.
//!
//! Under the four verbs a schedule tick is an EVENT with provenance — the
//! clock as a `session`-kind channel — not a separate API: at each matching
//! minute (in the household's tz) the entry's prompt runs through the bridge
//! `/v1/chat` tagged `[clock · <label> · <local time>]`, and the reply is
//! published to the app's opchat feed as a `text` event with
//! `correlation = clock:<label>:<unix-minute>` (the owner sees the timed turn
//! in the transcript; a device on the feed sees it too). The armed entries
//! are also registered at the bridge `POST /v1/jobs` (best-effort) so the
//! device `jobs` command lists them. The cron matcher is the protocol's
//! (`cron_matches`, one owner); the tick loop is minute-deduped.
//!
//! The guard (rule R7): the tick loop arms ONLY when the delegate's own grant
//! view (`/v1/sandbox/self/grants`, a chain read-through) carries
//! `tool:schedule`; otherwise the entries are recorded as DENIED — loud in the
//! log and in the `jobs` doc — and never run. The grant view is re-read every
//! hour so a later grant ceremony arms them without a restart.

use std::sync::Arc;

use agentkeys_backend_client::protocol::{cron_matches, PresetSchedule};
use serde::Serialize;

/// The armed-vs-denied state of one entry, for the `jobs` doc.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScheduleJob {
    pub id: String,
    pub cron: String,
    pub label: String,
    /// `armed` · `denied` (no `tool:schedule` grant)
    pub status: String,
    pub last_fired_minute: Option<i64>,
}

/// Local wall-clock fields for a UTC instant shifted by `tz_offset_minutes`.
pub fn local_fields(now_unix: i64, tz_offset_minutes: i64) -> Option<(u32, u32, u32, u32, u32)> {
    use chrono::{Datelike, Timelike};
    let dt = chrono::DateTime::from_timestamp(now_unix + tz_offset_minutes * 60, 0)?;
    Some((
        dt.minute(),
        dt.hour(),
        dt.day(),
        dt.month(),
        dt.weekday().num_days_from_sunday(),
    ))
}

/// The entries whose cron matches this minute (PURE — the tick loop's core).
pub fn due_entries(
    schedule: &[PresetSchedule],
    now_unix: i64,
    tz_offset_minutes: i64,
) -> Vec<&PresetSchedule> {
    let Some((minute, hour, dom, month, dow)) = local_fields(now_unix, tz_offset_minutes) else {
        return Vec::new();
    };
    schedule
        .iter()
        .filter(|s| cron_matches(&s.cron, minute, hour, dom, month, dow))
        .collect()
}

/// A stable id for an entry (its index + label slug).
pub fn job_id(index: usize, entry: &PresetSchedule) -> String {
    let slug: String = entry
        .label
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("schedule-{index}-{}", slug.trim_matches('-'))
}

/// The turn text a tick hands to the bridge — the clock's provenance tag +
/// the entry's prompt (template content, never framework code).
pub fn clock_turn_text(entry: &PresetSchedule, now_unix: i64, tz_offset_minutes: i64) -> String {
    let stamp = local_fields(now_unix, tz_offset_minutes)
        .map(|(mi, h, d, mo, _)| format!("{mo:02}-{d:02} {h:02}:{mi:02}"))
        .unwrap_or_else(|| now_unix.to_string());
    format!(
        "[clock · {} · {stamp} · scheduled turn, not a person]\n{}",
        entry.label.trim(),
        entry.prompt.trim()
    )
}

/// The correlation id of a tick's published reply (one per entry per minute).
pub fn clock_correlation(index: usize, entry: &PresetSchedule, now_unix: i64) -> String {
    format!("clock:{}:{}", job_id(index, entry), now_unix.div_euclid(60))
}

/// The bridge `POST /v1/jobs` registration body for the armed entries
/// (best-effort; a pre-#669 bridge 404s and the daemon keeps ticking).
pub fn jobs_registration_body(jobs: &[ScheduleJob]) -> serde_json::Value {
    serde_json::json!({
        "jobs": jobs.iter().map(|j| serde_json::json!({
            "id": j.id, "cron": j.cron, "label": j.label, "status": j.status,
        })).collect::<Vec<_>>()
    })
}

/// What the scheduler needs from the loop to fire a tick.
pub struct ScheduleRuntime {
    pub schedule: Vec<PresetSchedule>,
    pub tz_offset_minutes: i64,
    pub bridge_url: String,
    pub bridge_token: Option<String>,
    pub self_grants_url: String,
    pub chat_channel_id: String,
    pub http: reqwest::Client,
    pub publisher: Arc<crate::chat_loop::Publisher>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Register the armed entries at the bridge (best-effort, loud).
async fn register_jobs(rt: &ScheduleRuntime, jobs: &[ScheduleJob]) {
    let mut req = rt
        .http
        .post(format!("{}/v1/jobs", rt.bridge_url.trim_end_matches('/')))
        .timeout(std::time::Duration::from_secs(20))
        .json(&jobs_registration_body(jobs));
    if let Some(t) = &rt.bridge_token {
        req = req.bearer_auth(t);
    }
    match req.send().await {
        Ok(r) if r.status().is_success() => {
            tracing::info!(
                jobs = jobs.len(),
                "#669 schedule: entries registered at the bridge"
            )
        }
        Ok(r) => tracing::info!(
            status = %r.status(),
            "#669 schedule: bridge did not accept the jobs registration (pre-#669 image?) — ticking anyway"
        ),
        Err(e) => {
            tracing::info!(error = %e, "#669 schedule: bridge unreachable for jobs registration — ticking anyway")
        }
    }
}

/// The tick loop. Re-reads the grant view hourly; fires each due entry once
/// per minute; publishes the reply to opchat.
pub async fn run(rt: ScheduleRuntime) {
    if rt.schedule.is_empty() {
        return;
    }
    let mut jobs: Vec<ScheduleJob> = rt
        .schedule
        .iter()
        .enumerate()
        .map(|(i, s)| ScheduleJob {
            id: job_id(i, s),
            cron: s.cron.clone(),
            label: s.label.clone(),
            status: "denied".into(),
            last_fired_minute: None,
        })
        .collect();
    let mut granted = false;
    let mut last_grant_check: i64 = 0;
    let mut announced_denied = false;
    loop {
        let now = now_unix();
        if now - last_grant_check >= 3600 || last_grant_check == 0 {
            let view = crate::app_runtime::fetch_self_grants(
                &rt.http,
                &rt.self_grants_url,
                rt.bridge_token.as_deref(),
            )
            .await;
            granted = view
                .as_deref()
                .map(|v| crate::app_runtime::tool_granted(v, "schedule"))
                .unwrap_or(false);
            last_grant_check = now;
            let status = if granted { "armed" } else { "denied" };
            for j in &mut jobs {
                j.status = status.to_string();
            }
            if granted {
                register_jobs(&rt, &jobs).await;
                announced_denied = false;
            } else if !announced_denied {
                tracing::warn!(
                    entries = jobs.len(),
                    "#669 schedule: `tool:schedule` is NOT granted — the template's schedule \
                     entries are guard-denied (grant it in the permission editor to arm them)"
                );
                let notice = format!(
                    "⏰ This app's {} scheduled turn(s) are switched off: the `Scheduled reports` \
                     capability (tool:schedule) is not granted. Enable it in the permissions \
                     page to arm them. · 此应用的定时任务未开启：请在权限页授予“定时报告”能力。",
                    jobs.len()
                );
                let _ = rt
                    .publisher
                    .publish_text_out(&rt.chat_channel_id, &notice, "clock:denied")
                    .await;
                announced_denied = true;
            }
        }
        if granted {
            let minute = now.div_euclid(60);
            for (i, entry) in rt.schedule.iter().enumerate() {
                if jobs[i].last_fired_minute == Some(minute) {
                    continue;
                }
                let due =
                    !due_entries(std::slice::from_ref(entry), now, rt.tz_offset_minutes).is_empty();
                if !due {
                    continue;
                }
                jobs[i].last_fired_minute = Some(minute);
                let text = clock_turn_text(entry, now, rt.tz_offset_minutes);
                let correlation = clock_correlation(i, entry, now);
                tracing::info!(label = %entry.label, "#669 schedule: tick — running the scheduled turn");
                let session = crate::session_scope::schedule_session(&entry.label, entry.session);
                let reply = match crate::chat_loop::bridge_chat_at(
                    &rt.http,
                    &rt.bridge_url,
                    rt.bridge_token.as_deref(),
                    &text,
                    Some(&session),
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, label = %entry.label, "#669 schedule: scheduled turn failed");
                        format!("(scheduled turn `{}` failed: {e})", entry.label)
                    }
                };
                if let Err(e) = rt
                    .publisher
                    .publish_text_out(&rt.chat_channel_id, &reply, &correlation)
                    .await
                {
                    tracing::warn!(error = %e, "#669 schedule: reply publish failed");
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cron: &str, label: &str) -> PresetSchedule {
        PresetSchedule {
            cron: cron.into(),
            label: label.into(),
            label_zh: String::new(),
            prompt: "Publish the plan.".into(),
            session: None,
        }
    }

    #[test]
    fn due_entries_follow_the_household_tz() {
        let sched = vec![
            entry("0 7 * * *", "morning plan"),
            entry("0 16 * * *", "dinner"),
        ];
        // 2026-09-08 23:00 UTC = 2026-09-09 07:00 UTC+8.
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-08T23:00:00Z")
            .unwrap()
            .timestamp();
        let due: Vec<&str> = due_entries(&sched, now, 480)
            .iter()
            .map(|s| s.label.as_str())
            .collect();
        assert_eq!(due, vec!["morning plan"]);
        assert!(due_entries(&sched, now, 0).is_empty());
        assert!(due_entries(&sched, now + 60, 480).is_empty());
    }

    #[test]
    fn ids_turn_text_and_correlation_are_stable() {
        let e = entry("0 7 * * *", "Morning Plan!");
        assert_eq!(job_id(0, &e), "schedule-0-morning-plan");
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-08T23:00:00Z")
            .unwrap()
            .timestamp();
        let t = clock_turn_text(&e, now, 480);
        assert!(
            t.starts_with("[clock · Morning Plan! · 09-09 07:00 · scheduled turn, not a person]\n")
        );
        assert!(t.ends_with("Publish the plan."));
        assert_eq!(
            clock_correlation(0, &e, now),
            format!("clock:schedule-0-morning-plan:{}", now / 60)
        );
        let body = jobs_registration_body(&[ScheduleJob {
            id: "schedule-0-x".into(),
            cron: "* * * * *".into(),
            label: "x".into(),
            status: "armed".into(),
            last_fired_minute: None,
        }]);
        assert_eq!(body["jobs"][0]["status"], "armed");
    }
}
