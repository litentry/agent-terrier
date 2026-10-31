use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

#[derive(Default)]
pub struct DelegateLocks {
    locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl DelegateLocks {
    pub async fn lock(&self, device_key_hash: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let key = device_key_hash
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_ascii_lowercase();
        let delegate_lock = {
            let mut locks = self
                .locks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // An entry only the map still references has no holder and no
            // waiter — drop it so the map stays one row per active delegate.
            locks.retain(|_, held| Arc::strong_count(held) > 1);
            locks.entry(key).or_default().clone()
        };
        delegate_lock.lock_owned().await
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.locks
            .lock()
            .map(|locks| locks.len())
            .unwrap_or_default()
    }
}

pub(crate) async fn run_detached<T: Send + 'static>(
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T> {
    tokio::spawn(work)
        .await
        .map_err(|e| anyhow::anyhow!("sandbox task ended abnormally: {e}"))
}

#[derive(Debug, Clone)]
pub struct EnsureOutcome {
    pub sandbox_id: String,
    pub created: bool,
    pub status: String,
    pub agent_url: Option<String>,
}

pub type CreateEnvProvider = Box<
    dyn FnOnce()
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<(String, String)>> + Send>>
        + Send,
>;

pub fn no_create_envs() -> CreateEnvProvider {
    Box::new(|| Box::pin(async { Vec::new() }))
}

#[derive(Debug, Clone)]
pub struct LiveRuntime {
    pub id: String,
    pub status: String,
    pub expire_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeImage {
    pub image_id: String,
    pub image_url: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceImageInfo {
    pub image_id: String,
    pub image_ref: String,
}

pub fn image_stale(booted: Option<&InstanceImageInfo>, current: &[RuntimeImage]) -> Option<bool> {
    let booted = booted?;
    if current.is_empty() || booted.image_id.is_empty() {
        return None;
    }
    Some(
        !current
            .iter()
            .any(|image| image.image_id == booted.image_id),
    )
}

/// Implementations enforce device ownership, serialize creates and call on_create only for a new runtime.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    fn kind(&self) -> &'static str;
    fn runtime_ref(&self) -> String;
    fn static_agent_url(&self) -> Option<String> {
        None
    }
    async fn ensure_for_delegate_with_envs(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        base_envs: &[(String, String)],
        on_create: CreateEnvProvider,
    ) -> Result<EnsureOutcome>;
    async fn kill_for_device(&self, device_key_hash: &str) -> Result<Vec<String>>;
    async fn live_for_device(&self, device_key_hash: &str) -> Result<Vec<LiveRuntime>>;
    fn current_image_tag(&self) -> Option<String>;
    async fn current_images(&self) -> Result<Vec<RuntimeImage>>;
    async fn booted_image_info(&self, sandbox_id: &str) -> Result<Option<InstanceImageInfo>>;
    fn instance_endpoint(
        &self,
        sandbox_id: &str,
        port: u16,
    ) -> Option<(String, Vec<(String, String)>)>;
    fn instance_mgmt_endpoint(&self, sandbox_id: &str) -> Option<(String, Vec<(String, String)>)> {
        self.instance_endpoint(
            sandbox_id,
            agentkeys_protocol::sandbox_env::SANDBOX_BRIDGE_PORT,
        )
    }
    fn instance_daemon_endpoint(
        &self,
        sandbox_id: &str,
    ) -> Option<(String, Vec<(String, String)>)> {
        self.instance_endpoint(
            sandbox_id,
            agentkeys_protocol::sandbox_env::SANDBOX_DAEMON_PORT,
        )
    }
}

pub struct SandboxBackend(Arc<dyn SandboxRuntime>);

impl SandboxBackend {
    pub fn new(runtime: Arc<dyn SandboxRuntime>) -> Self {
        Self(runtime)
    }

    pub async fn from_env() -> Result<Option<Self>> {
        let Some(config) =
            crate::docker_runtime::DockerConfig::from_lookup(|key| std::env::var(key).ok())?
        else {
            return Ok(None);
        };
        let runtime = crate::docker_runtime::DockerRuntime::connect(config).await?;
        Ok(Some(Self::new(Arc::new(runtime))))
    }
}

impl std::ops::Deref for SandboxBackend {
    type Target = dyn SandboxRuntime;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn one_delegate_serializes_whatever_the_hash_spelling() {
        let locks = DelegateLocks::default();
        let held = locks.lock("0xAB12").await;
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(50), locks.lock("ab12")).await;
        assert!(
            second.is_err(),
            "the bare-hex spelling must wait on the 0x holder"
        );
        drop(held);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), locks.lock("ab12"))
            .await
            .expect("a released lock is free");
    }

    #[tokio::test]
    async fn a_slow_delegate_never_blocks_another() {
        let locks = DelegateLocks::default();
        let _chef = locks.lock("0xaaaa").await;
        tokio::time::timeout(std::time::Duration::from_millis(50), locks.lock("0xbbbb"))
            .await
            .expect("a different delegate must not queue behind a held create");
    }

    #[tokio::test]
    async fn idle_delegates_leave_no_lock_behind() {
        let locks = DelegateLocks::default();
        drop(locks.lock("0xaaaa").await);
        drop(locks.lock("0xbbbb").await);
        let _held = locks.lock("0xcccc").await;
        assert_eq!(locks.tracked(), 1, "only the held delegate stays tracked");
    }

    #[tokio::test]
    async fn a_caller_that_goes_away_does_not_cancel_the_work() {
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = finished.clone();
        let caller = tokio::spawn(run_detached(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        caller.abort();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            finished.load(std::sync::atomic::Ordering::SeqCst),
            "the create must run to completion after its caller is dropped"
        );
    }

    #[test]
    fn image_comparison_requires_known_immutable_identity() {
        let current = vec![RuntimeImage {
            image_id: "digest-new".into(),
            image_url: "local:dev".into(),
            status: "available".into(),
        }];
        let old = InstanceImageInfo {
            image_id: "digest-old".into(),
            image_ref: "local:dev".into(),
        };
        assert_eq!(image_stale(Some(&old), &current), Some(true));
        assert_eq!(image_stale(None, &current), None);
        assert_eq!(image_stale(Some(&old), &[]), None);
        let same = InstanceImageInfo {
            image_id: "digest-new".into(),
            image_ref: "another-tag".into(),
        };
        assert_eq!(image_stale(Some(&same), &current), Some(false));
    }
}
