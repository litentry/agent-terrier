//! #693 — the delegate's LAUNCH / PULL LIFECYCLE (`docs/plan/knowledge-repository.md`
//! §8): `booting` → `restoring` (checkpoint) → `syncing` (k of n namespaces)
//! → `ready`; `degraded` when the engine is down or a pull failed (chat still
//! answers — the mirror stays never-load-bearing); `pulling` while a periodic
//! pass runs.
//!
//! The stage lives in a watch channel every loop reads; each change is also
//! published as a `lifecycle` event on every CONVERSATIONAL feed this delegate
//! writes — its opchat and messaging slots (D2 — no broker state: the console
//! and the contact gate read the stage there). Device feeds (display, camera,
//! …) carry the app's content only: a lifecycle row there is noise a renderer
//! skips, and it pushes the content out of a bounded read (measured
//! 2026-09-19: the kitchen display feed held 984 lifecycle rows against 13
//! cards and the console's "latest card" read found none). And a
//! turn waits for `ready` up to a bound (`AGENTKEYS_KNOWLEDGE_READY_WAIT_SECS`,
//! default 60) before answering in `degraded` and saying so. "sync now" is a
//! `command` event on the same feed; the mirror answers with an immediate pass.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentkeys_backend_client::protocol::{ChannelEndpointKind, DelegateLifecycle, LifecycleStage};
use tokio::sync::{mpsc, watch, Notify};

use crate::app_runtime::FeedSpec;
use crate::chat_loop::Publisher;

/// `AGENTKEYS_KNOWLEDGE_READY_WAIT_SECS` — how long a turn waits for `ready`
/// before answering degraded (default 60, clamped to 0..=600).
pub fn ready_wait_from(read: impl Fn(&str) -> Option<String>) -> Duration {
    let secs = read("AGENTKEYS_KNOWLEDGE_READY_WAIT_SECS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(60)
        .min(600);
    Duration::from_secs(secs)
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What a turn found when it asked for the knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    /// The engine is down or the last pull failed — answer from what is there.
    Degraded,
    /// Still booting / restoring / syncing after the whole bound.
    Waiting,
}

pub struct LifecycleHub {
    state: watch::Sender<DelegateLifecycle>,
    events: mpsc::Sender<DelegateLifecycle>,
    events_rx: std::sync::Mutex<Option<mpsc::Receiver<DelegateLifecycle>>>,
    /// "sync now" — the mirror runs a pass at once.
    pub sync_now: Notify,
    ready_wait: Duration,
    /// Without a mirror, the end of the restore phase IS `ready`.
    mirror_enabled: AtomicBool,
    restore_done: AtomicBool,
    first_pass_done: AtomicBool,
    /// #594 — a checkpoint restore that has not concluded
    /// ([`LifecycleHub::set_checkpoint_note`]).
    checkpoint_note: std::sync::Mutex<Option<String>>,
    /// #694 — when the checkpoint last let the engine go
    /// ([`LifecycleHub::engine_released`]).
    engine_released_at: std::sync::Mutex<Option<std::time::Instant>>,
    /// Wakes the mirror's inter-pass wait when the engine is let go after the
    /// boot restore phase.
    pub engine_wake: Notify,
}

fn report(stage: LifecycleStage, detail: impl Into<String>) -> DelegateLifecycle {
    DelegateLifecycle {
        stage,
        detail: detail.into(),
        done: 0,
        total: 0,
        mirrored: 0,
        deleted: 0,
        ms: 0,
        errors: Vec::new(),
        ts_millis: now_millis(),
        audit_envelope_hash: None,
    }
}

/// The report that ENDS a pull pass ([`LifecycleHub::pass_finished`] with the
/// engine up) — the one a reader turns into the pass's audit row. Every other
/// report (a stage change, the engine-down notice, `syncing k/n`) carries no
/// pass duration.
pub fn is_pass_report(ev: &DelegateLifecycle) -> bool {
    matches!(ev.stage, LifecycleStage::Ready | LifecycleStage::Degraded) && ev.ms > 0
}

impl LifecycleHub {
    pub fn new(ready_wait: Duration) -> Arc<Self> {
        let (state, _rx) = watch::channel(report(LifecycleStage::Booting, "daemon up"));
        let (events, rx) = mpsc::channel(64);
        Arc::new(Self {
            state,
            events,
            events_rx: std::sync::Mutex::new(Some(rx)),
            sync_now: Notify::new(),
            ready_wait,
            mirror_enabled: AtomicBool::new(true),
            restore_done: AtomicBool::new(false),
            first_pass_done: AtomicBool::new(false),
            checkpoint_note: std::sync::Mutex::new(None),
            engine_released_at: std::sync::Mutex::new(None),
            engine_wake: Notify::new(),
        })
    }

    pub fn current(&self) -> DelegateLifecycle {
        self.state.borrow().clone()
    }

    /// Publish one report: the watch (every loop) + the feed publisher.
    pub fn set(&self, mut ev: DelegateLifecycle) {
        if ev.ts_millis == 0 {
            ev.ts_millis = now_millis();
        }
        self.state.send_replace(ev.clone());
        // a full queue drops the oldest-in-flight report, never blocks a loop
        let _ = self.events.try_send(ev);
    }

    pub fn stage(&self, stage: LifecycleStage, detail: impl Into<String>) {
        self.set(report(stage, detail));
    }

    /// The mirror is off (no namespaces / kill switch): readiness comes from
    /// the restore phase alone.
    pub fn set_mirror_enabled(&self, on: bool) {
        self.mirror_enabled.store(on, Ordering::Release);
        if !on && self.restore_done.load(Ordering::Acquire) {
            self.stage(
                LifecycleStage::Ready,
                "no knowledge mirror on this delegate",
            );
        }
    }

    pub fn restore_pending(&self) -> bool {
        !self.restore_done.load(Ordering::Acquire)
    }

    /// The checkpoint's boot restore phase ended — restored, nothing to
    /// restore, or still pending (the checkpoint loop keeps retrying and
    /// [`Self::set_checkpoint_note`] says so) — the mirror may now judge the
    /// engine, or, without one, we are ready.
    pub fn restore_finished(&self, detail: &str) {
        self.restore_done.store(true, Ordering::Release);
        if !self.mirror_enabled.load(Ordering::Acquire) {
            self.stage(LifecycleStage::Ready, detail);
        } else {
            self.stage(LifecycleStage::Syncing, detail);
        }
    }

    /// #594 — mark (or, with `None`, clear) a checkpoint restore that has not
    /// concluded. The note rides the detail of EVERY published report until
    /// cleared, so a later pull pass's report cannot hide it; a change
    /// republishes the current stage at once.
    pub fn set_checkpoint_note(&self, note: Option<String>) {
        {
            let mut current = self
                .checkpoint_note
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if *current == note {
                return;
            }
            *current = note;
        }
        let mut ev = self.current();
        ev.ts_millis = now_millis();
        let _ = self.events.try_send(ev);
    }

    /// #694 — the checkpoint let the engine go (its workspace restore left
    /// pending, or the hold reached its bound): the engine starts now, so the
    /// mirror waits out its `/health` like a first pass instead of reporting
    /// it down until the next interval — woken at once after the boot phase.
    pub fn engine_released(&self) {
        *self
            .engine_released_at
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(std::time::Instant::now());
        if !self.restore_pending() {
            self.engine_wake.notify_one();
        }
    }

    pub fn engine_released_at(&self) -> Option<std::time::Instant> {
        *self
            .engine_released_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// A report as it leaves the daemon: the checkpoint note after the detail.
    fn published(&self, mut ev: DelegateLifecycle) -> DelegateLifecycle {
        let note = self
            .checkpoint_note
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(note) = note {
            ev.detail = if ev.detail.is_empty() {
                note
            } else {
                format!("{} · {note}", ev.detail)
            };
        }
        ev
    }

    pub fn first_pass_pending(&self) -> bool {
        !self.first_pass_done.load(Ordering::Acquire)
    }

    /// The end of a pull pass decides the stage: `ready`, or `degraded` when
    /// the engine was down or any namespace failed to fetch. The watch flips
    /// NOW (a waiting turn answers at once); the caller publishes the returned
    /// report with [`Self::publish_pass`] once the pass's audit row has its
    /// receipt, so a pass stays ONE feed event.
    #[allow(clippy::too_many_arguments)]
    pub fn pass_finished(
        &self,
        total: u32,
        mirrored: u64,
        deleted: u64,
        ms: u64,
        errors: Vec<String>,
        engine_down: bool,
    ) -> DelegateLifecycle {
        self.first_pass_done.store(true, Ordering::Release);
        let (stage, detail) = if engine_down {
            (
                LifecycleStage::Degraded,
                "engine unreachable — answering without knowledge".to_string(),
            )
        } else if !errors.is_empty() {
            (
                LifecycleStage::Degraded,
                format!("pull failed: {}", errors[0]),
            )
        } else {
            (
                LifecycleStage::Ready,
                format!("{total} namespace(s) · {mirrored} line(s) mirrored · {ms} ms"),
            )
        };
        let ev = DelegateLifecycle {
            stage,
            detail,
            done: total,
            total,
            mirrored,
            deleted,
            ms,
            errors,
            ts_millis: now_millis(),
            audit_envelope_hash: None,
        };
        self.state.send_replace(ev.clone());
        ev
    }

    /// Publish a [`Self::pass_finished`] report — with the receipt of the
    /// pass's audit row when it landed. The watch takes the receipt too unless
    /// a newer report replaced the pass meanwhile.
    pub fn publish_pass(&self, ev: DelegateLifecycle) {
        self.state.send_if_modified(|cur| {
            let same_pass = cur.ts_millis == ev.ts_millis && cur.stage == ev.stage;
            if same_pass {
                *cur = ev.clone();
            }
            same_pass
        });
        let _ = self.events.try_send(ev);
    }

    /// Wait for the knowledge up to the bound; a turn NEVER waits forever.
    pub async fn wait_ready(&self) -> Readiness {
        let mut rx = self.state.subscribe();
        let deadline = tokio::time::Instant::now() + self.ready_wait;
        loop {
            match rx.borrow().stage {
                s if s.answers() => return Readiness::Ready,
                LifecycleStage::Degraded => return Readiness::Degraded,
                _ => {}
            }
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {}
                // the bound elapsed, or the hub is gone (nothing will change)
                _ => return Readiness::Waiting,
            }
        }
    }

    pub fn take_events(&self) -> Option<mpsc::Receiver<DelegateLifecycle>> {
        self.events_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }
}

/// The note a reply carries when it was answered before `ready` — bilingual,
/// one line, in front of the answer.
pub fn degraded_note(r: Readiness) -> Option<&'static str> {
    match r {
        Readiness::Ready => None,
        Readiness::Degraded => {
            Some("⚠ knowledge unavailable · 知识暂不可用 — answering from what I have")
        }
        Readiness::Waiting => {
            Some("⏳ knowledge still loading · 知识加载中 — answering from what I have")
        }
    }
}

/// The feeds a lifecycle report belongs on: the conversational feeds this
/// delegate WRITES — its opchat (`chat`) and its messaging slots. A display or
/// any other device feed carries content only (see the module doc).
pub fn lifecycle_feeds(feeds: &[FeedSpec]) -> Vec<FeedSpec> {
    feeds
        .iter()
        .filter(|f| {
            f.direction.writes()
                && matches!(
                    f.kind,
                    ChannelEndpointKind::Chat | ChannelEndpointKind::Messaging
                )
        })
        .cloned()
        .collect()
}

/// Forward every stage change to the delegate's conversational feeds (see
/// [`lifecycle_feeds`]), the current stage first (a console that missed the
/// boot still sees where we are). `feeds` is the chat loop's LIVE set — a
/// #717 rebind swaps it and the next report goes to the new feeds.
pub fn spawn_publisher(
    hub: Arc<LifecycleHub>,
    publisher: Arc<Publisher>,
    feeds: Arc<std::sync::RwLock<Vec<FeedSpec>>>,
) {
    let Some(mut rx) = hub.take_events() else {
        return;
    };
    let current = |feeds: &std::sync::RwLock<Vec<FeedSpec>>| -> Vec<FeedSpec> {
        lifecycle_feeds(&feeds.read().expect("feeds lock"))
    };
    tokio::spawn(async move {
        let now = current(&feeds);
        publish_all(&publisher, &now, &hub.published(hub.current())).await;
        while let Some(ev) = rx.recv().await {
            let now = current(&feeds);
            publish_all(&publisher, &now, &hub.published(ev)).await;
        }
    });
}

async fn publish_all(publisher: &Publisher, feeds: &[FeedSpec], ev: &DelegateLifecycle) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let body = match serde_json::to_vec(ev) {
        Ok(b) => STANDARD.encode(b),
        Err(e) => {
            tracing::warn!(error = %e, "#693 lifecycle: report serialize failed");
            return;
        }
    };
    for f in feeds {
        if let Err(e) = publisher
            .publish(
                &f.channel_id,
                "lifecycle",
                body.clone(),
                "lifecycle",
                None,
                Some("application/json"),
            )
            .await
        {
            tracing::debug!(error = %e, channel = %f.channel_id, stage = ev.stage.as_str(), "#693 lifecycle: publish failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_wait_defaults_and_clamps() {
        assert_eq!(ready_wait_from(|_| None), Duration::from_secs(60));
        assert_eq!(
            ready_wait_from(|_| Some("5".into())),
            Duration::from_secs(5)
        );
        assert_eq!(
            ready_wait_from(|_| Some("9999".into())),
            Duration::from_secs(600)
        );
        assert_eq!(
            ready_wait_from(|_| Some("nope".into())),
            Duration::from_secs(60)
        );
    }

    #[tokio::test]
    async fn a_turn_waits_for_ready_then_answers_degraded_at_the_bound() {
        let hub = LifecycleHub::new(Duration::from_millis(50));
        assert_eq!(
            hub.wait_ready().await,
            Readiness::Waiting,
            "booting past the bound"
        );
        hub.stage(LifecycleStage::Degraded, "engine unreachable");
        assert_eq!(hub.wait_ready().await, Readiness::Degraded);
        hub.stage(LifecycleStage::Pulling, "periodic pass");
        assert_eq!(
            hub.wait_ready().await,
            Readiness::Ready,
            "a periodic pass never blocks"
        );
        let h2 = hub.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            h2.stage(LifecycleStage::Ready, "3 namespaces");
        });
        hub.stage(LifecycleStage::Syncing, "1 of 3");
        assert_eq!(
            hub.wait_ready().await,
            Readiness::Ready,
            "woken by the change"
        );
    }

    #[test]
    fn readiness_without_a_mirror_comes_from_the_restore_phase() {
        let hub = LifecycleHub::new(Duration::from_secs(1));
        hub.set_mirror_enabled(false);
        assert_eq!(hub.current().stage, LifecycleStage::Booting);
        hub.restore_finished("no checkpoint");
        assert_eq!(hub.current().stage, LifecycleStage::Ready);
        let hub = LifecycleHub::new(Duration::from_secs(1));
        hub.restore_finished("restored");
        assert_eq!(
            hub.current().stage,
            LifecycleStage::Syncing,
            "a mirror decides"
        );
        hub.pass_finished(2, 10, 0, 300, vec![], false);
        assert_eq!(hub.current().stage, LifecycleStage::Ready);
        assert!(!hub.first_pass_pending());
        hub.pass_finished(2, 0, 0, 30, vec!["fetch travel: 502".into()], false);
        assert_eq!(hub.current().stage, LifecycleStage::Degraded);
        assert_eq!(hub.current().errors.len(), 1);
    }

    /// #594 — a checkpoint restore still pending past the boot window must stay
    /// visible: the next pull pass's report would otherwise replace the detail.
    #[test]
    fn a_pending_restore_rides_every_published_report_until_it_concludes() {
        let hub = LifecycleHub::new(Duration::from_secs(1));
        let mut rx = hub.take_events().expect("events");
        let pending = "checkpoint restore pending (no delegate session) — saves paused";
        hub.set_checkpoint_note(Some(pending.into()));
        let republished = rx.try_recv().expect("a note change republishes the stage");
        assert_eq!(republished.stage, LifecycleStage::Booting);
        assert_eq!(
            hub.published(republished).detail,
            format!("daemon up · {pending}")
        );
        hub.set_checkpoint_note(Some(pending.into()));
        assert!(
            rx.try_recv().is_err(),
            "an unchanged note republishes nothing"
        );

        hub.restore_finished("");
        assert_eq!(hub.published(hub.current()).detail, pending);
        hub.pass_finished(2, 10, 0, 300, vec![], false);
        let ready = hub.published(hub.current());
        assert_eq!(ready.stage, LifecycleStage::Ready, "chat never waits on it");
        assert_eq!(
            ready.detail,
            format!("2 namespace(s) · 10 line(s) mirrored · 300 ms · {pending}")
        );

        hub.set_checkpoint_note(None);
        assert_eq!(
            hub.published(hub.current()).detail,
            "2 namespace(s) · 10 line(s) mirrored · 300 ms"
        );
        assert_eq!(
            hub.current().detail,
            "2 namespace(s) · 10 line(s) mirrored · 300 ms"
        );
    }

    /// #694 — the engine let go by the checkpoint's hold is waited out by the
    /// mirror; after the boot phase the mirror is also woken from its
    /// inter-pass wait (during it, the mirror is not sleeping there).
    #[tokio::test]
    async fn a_released_engine_wakes_the_mirror_only_after_the_boot_phase() {
        let hub = LifecycleHub::new(Duration::from_secs(1));
        assert!(hub.engine_released_at().is_none());
        hub.engine_released();
        assert!(hub.engine_released_at().is_some());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), hub.engine_wake.notified())
                .await
                .is_err(),
            "no wake during the boot restore phase"
        );
        hub.restore_finished("");
        hub.engine_released();
        tokio::time::timeout(Duration::from_millis(200), hub.engine_wake.notified())
            .await
            .expect("woken after the boot phase");
    }

    #[test]
    fn a_pass_is_one_feed_event_that_carries_its_audit_receipt() {
        let hub = LifecycleHub::new(Duration::from_secs(1));
        let mut rx = hub.take_events().expect("receiver");
        let mut ev = hub.pass_finished(2, 3, 1, 420, vec![], false);
        assert_eq!(
            hub.current().stage,
            LifecycleStage::Ready,
            "the watch flips before the receipt"
        );
        assert!(
            rx.try_recv().is_err(),
            "nothing reaches the feed before publish_pass"
        );
        ev.audit_envelope_hash = Some("0xabc".into());
        hub.publish_pass(ev);
        let sent = rx.try_recv().expect("the pass report");
        assert_eq!(sent.audit_envelope_hash.as_deref(), Some("0xabc"));
        assert!(rx.try_recv().is_err(), "exactly one event per pass");
        assert_eq!(hub.current().audit_envelope_hash.as_deref(), Some("0xabc"));
    }

    #[test]
    fn only_the_report_that_ends_a_pull_pass_is_a_pass_report() {
        let hub = LifecycleHub::new(Duration::from_secs(1));
        let pulled = hub.pass_finished(2, 3, 0, 420, vec![], false);
        assert!(is_pass_report(&pulled));
        let failed = hub.pass_finished(2, 0, 0, 90, vec!["fetch travel: 502".into()], false);
        assert!(is_pass_report(&failed));
        let engine_down = hub.pass_finished(2, 0, 0, 0, vec![], true);
        assert!(!is_pass_report(&engine_down));
        hub.stage(LifecycleStage::Pulling, "periodic pull");
        assert!(!is_pass_report(&hub.current()));
        hub.restore_finished("restored");
        assert!(!is_pass_report(&hub.current()));
        hub.set_mirror_enabled(false);
        assert!(!is_pass_report(&hub.current()));
    }

    #[test]
    fn the_note_names_the_state() {
        assert!(degraded_note(Readiness::Ready).is_none());
        assert!(degraded_note(Readiness::Waiting)
            .unwrap()
            .contains("loading"));
        assert!(degraded_note(Readiness::Degraded)
            .unwrap()
            .contains("unavailable"));
    }
}

#[cfg(test)]
mod lifecycle_feed_tests {
    use super::lifecycle_feeds;
    use crate::app_runtime::FeedSpec;
    use agentkeys_backend_client::protocol::{ChannelEndpointKind, SlotDirection};

    fn feed(
        slot: &str,
        kind: ChannelEndpointKind,
        direction: SlotDirection,
        channel: &str,
    ) -> FeedSpec {
        FeedSpec {
            slot: slot.into(),
            kind,
            direction,
            channel_id: channel.into(),
            endpoint_actor_omni: None,
            default_app: None,
        }
    }

    #[test]
    fn only_the_conversational_feeds_carry_lifecycle() {
        let feeds = vec![
            feed(
                "opchat",
                ChannelEndpointKind::Chat,
                SlotDirection::Duplex,
                "opchat-chef",
            ),
            feed(
                "kitchen_screen",
                ChannelEndpointKind::Display,
                SlotDirection::Pub,
                "kitchen-screen",
            ),
            feed(
                "family_chat",
                ChannelEndpointKind::Messaging,
                SlotDirection::Duplex,
                "weixin-chef",
            ),
            feed(
                "inbox",
                ChannelEndpointKind::Messaging,
                SlotDirection::Sub,
                "weixin-inbox",
            ),
            feed(
                "cam",
                ChannelEndpointKind::Camera,
                SlotDirection::Pub,
                "fridge-cam",
            ),
        ];
        let out: Vec<String> = lifecycle_feeds(&feeds)
            .into_iter()
            .map(|f| f.channel_id)
            .collect();
        assert_eq!(
            out,
            vec!["opchat-chef".to_string(), "weixin-chef".to_string()]
        );
    }
}
