//! Near-real-time (NRT) write-through wakeup registry (§14.12).
//!
//! The channel worker is the ONLY write path for a feed, so it can complete a
//! held consumer long-poll the instant a matching publish lands — without S3
//! ever being the notification path (S3 stays the DURABLE record). This is an
//! in-process `channel_id → Notify` map: a poll with no immediately-available
//! event `await`s the channel's `Notify` (with a timeout); a publish
//! `notify_waiters()` after the durable write wakes every held poll on that
//! channel, which then re-lists S3 and returns the fresh event.
//!
//! Scale-out caveat (recorded, not built — §14.12): with multiple worker
//! replicas this wakeup needs a notify hop (Redis/SNS-class). Today's
//! one-worker-per-class deployment needs none; a held poll on a different
//! replica simply falls back to its poll-timeout re-list.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// A concurrency-safe `channel_id → Notify` registry. Cheap to clone (an
/// `Arc`), one instance lives in the worker state.
#[derive(Clone, Default)]
pub struct WakeupRegistry {
    inner: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
}

impl WakeupRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get (or create) the `Notify` for a channel. A subscriber grabs this
    /// BEFORE its S3 re-list so a publish that lands during the list still
    /// wakes it (`Notify` remembers a permit for a not-yet-waiting waiter only
    /// via `notify_one`; we use `notify_waiters`, so the grab-then-list-then-
    /// await order below is what closes the race).
    fn notify_for(&self, channel_id: &str) -> Arc<Notify> {
        let mut map = self.inner.lock().expect("wakeup registry poisoned");
        map.entry(channel_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Called by a publish AFTER the durable S3 write — wakes every held poll
    /// on this channel so they re-list and return the fresh event.
    pub fn signal(&self, channel_id: &str) {
        // Only signal if someone registered interest; avoid creating map churn
        // for fire-and-forget publishes with no live subscriber.
        let existing = {
            let map = self.inner.lock().expect("wakeup registry poisoned");
            map.get(channel_id).cloned()
        };
        if let Some(n) = existing {
            n.notify_waiters();
        }
    }

    /// A subscriber's handle: grab the channel's notifier, then the caller
    /// lists S3; if empty it `await`s [`Waiter::notified`] with a timeout.
    pub fn waiter(&self, channel_id: &str) -> Waiter {
        Waiter {
            notify: self.notify_for(channel_id),
        }
    }
}

/// A held long-poll's wakeup handle. The `notified()` future resolves when a
/// publish signals the channel (or the caller's timeout fires around it).
pub struct Waiter {
    notify: Arc<Notify>,
}

impl Waiter {
    /// Await the next publish signal on this channel. The CALLER wraps this in
    /// `tokio::time::timeout(..)` so a quiet channel returns empty after the
    /// long-poll ceiling instead of hanging.
    pub async fn notified(&self) {
        self.notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::{timeout, Instant};

    #[tokio::test]
    async fn signal_wakes_a_held_waiter_well_under_the_nrt_target() {
        // §14.12 NRT: an awake long-poll must observe a fresh publish in < 2 s
        // (p50 sub-second). Prove the write-through wakeup delivers in ~ms, not
        // via a poll-timeout. The waiter is grabbed BEFORE the signal fires
        // (the real publish→S3→signal order), and a background task signals
        // after a short delay while the waiter is parked with a 2 s ceiling.
        let reg = WakeupRegistry::new();
        let waiter = reg.waiter("cam-frontdoor");
        let reg2 = reg.clone();
        let start = Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            reg2.signal("cam-frontdoor");
        });
        // A 2 s ceiling stands in for the long-poll timeout; the signal must
        // resolve `notified()` far sooner.
        timeout(Duration::from_secs(2), waiter.notified())
            .await
            .expect("wakeup must fire before the 2 s NRT ceiling");
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "write-through wakeup should deliver sub-500ms, took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn signal_on_a_quiet_channel_is_a_noop() {
        // A publish to a channel with no live subscriber must not panic or
        // allocate a permanent waiter — fire-and-forget stays cheap.
        let reg = WakeupRegistry::new();
        reg.signal("no-subscribers-here");
        // A subsequent waiter still works.
        let waiter = reg.waiter("no-subscribers-here");
        let reg2 = reg.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            reg2.signal("no-subscribers-here");
        });
        timeout(Duration::from_secs(1), waiter.notified())
            .await
            .expect("waiter registered after an earlier no-op signal still wakes");
    }
}
