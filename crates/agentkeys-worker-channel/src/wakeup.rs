use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
};

use tokio::sync::{futures::OwnedNotified, Notify};

#[derive(Clone, Default)]
pub struct WakeupRegistry {
    inner: Arc<Mutex<HashMap<String, Weak<Notify>>>>,
}

impl WakeupRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn notify_for(&self, feed: &str) -> Arc<Notify> {
        let mut entries = self.inner.lock().expect("wakeup registry poisoned");
        entries.retain(|_, notifier| notifier.strong_count() > 0);
        if let Some(notifier) = entries.get(feed).and_then(Weak::upgrade) {
            return notifier;
        }
        let notifier = Arc::new(Notify::new());
        entries.insert(feed.to_string(), Arc::downgrade(&notifier));
        notifier
    }

    pub fn signal(&self, feed: &str) {
        let notifier = self
            .inner
            .lock()
            .expect("wakeup registry poisoned")
            .get(feed)
            .and_then(Weak::upgrade);
        if let Some(notifier) = notifier {
            notifier.notify_waiters();
        }
    }

    pub fn waiter(&self, feed: &str) -> Waiter {
        let mut notified = Box::pin(self.notify_for(feed).notified_owned());
        notified.as_mut().enable();
        Waiter { notified }
    }
}

pub struct Waiter {
    notified: Pin<Box<OwnedNotified>>,
}

impl Waiter {
    pub async fn notified(self) {
        self.notified.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::{timeout, Instant};

    #[tokio::test]
    async fn a_publish_between_listing_and_waiting_is_not_lost() {
        let registry = WakeupRegistry::new();
        let waiter = registry.waiter("owner/channel");
        registry.signal("owner/channel");
        timeout(Duration::from_millis(100), waiter.notified())
            .await
            .expect("a publish after registration must not wait for the poll timeout");
    }

    #[tokio::test]
    async fn notifications_are_owner_scoped_and_idle_entries_are_reclaimed() {
        let registry = WakeupRegistry::new();
        let first = registry.waiter("owner-one/chat");
        let second = registry.waiter("owner-one/chat");
        let unrelated = registry.waiter("owner-two/chat");
        registry.signal("owner-one/chat");
        timeout(Duration::from_millis(100), first.notified())
            .await
            .unwrap();
        timeout(Duration::from_millis(100), second.notified())
            .await
            .unwrap();
        assert!(timeout(Duration::from_millis(20), unrelated.notified())
            .await
            .is_err());
        let _active = registry.waiter("owner-three/chat");
        assert_eq!(registry.inner.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn signal_wakes_a_held_waiter_well_under_the_nrt_target() {
        let reg = WakeupRegistry::new();
        let waiter = reg.waiter("cam-frontdoor");
        let reg2 = reg.clone();
        let start = Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            reg2.signal("cam-frontdoor");
        });
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
        let reg = WakeupRegistry::new();
        reg.signal("no-subscribers-here");
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
