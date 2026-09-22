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
    }
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

    /// The checkpoint's restore phase ended (restored, nothing to restore, or
    /// gave up) — the mirror may now judge the engine, or, without one, we are
    /// ready.
    pub fn restore_finished(&self, detail: &str) {
        self.restore_done.store(true, Ordering::Release);
        if !self.mirror_enabled.load(Ordering::Acquire) {
            self.stage(LifecycleStage::Ready, detail);
        } else {
            self.stage(LifecycleStage::Syncing, detail);
        }
    }

    pub fn first_pass_pending(&self) -> bool {
        !self.first_pass_done.load(Ordering::Acquire)
    }

    /// The end of a pull pass decides the stage: `ready`, or `degraded` when
    /// the engine was down or any namespace failed to fetch.
    #[allow(clippy::too_many_arguments)]
    pub fn pass_finished(
        &self,
        total: u32,
        mirrored: u64,
        deleted: u64,
        ms: u64,
        errors: Vec<String>,
        engine_down: bool,
    ) {
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
        self.set(DelegateLifecycle {
            stage,
            detail,
            done: total,
            total,
            mirrored,
            deleted,
            ms,
            errors,
            ts_millis: now_millis(),
        });
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
        publish_all(&publisher, &now, &hub.current()).await;
        while let Some(ev) = rx.recv().await {
            let now = current(&feeds);
            publish_all(&publisher, &now, &ev).await;
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
