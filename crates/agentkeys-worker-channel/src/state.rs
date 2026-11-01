use std::sync::Arc;

use agentkeys_worker_creds::state::SharedWorkerState;
use clap::Args;

use crate::{wake::WakeClient, wakeup::WakeupRegistry};

const DEFAULT_MAX_POLL_SECONDS: u64 = 25;
const DEFAULT_INLINE_MAX_BYTES: usize = 1 << 20;
const DEFAULT_BLOB_MAX_BYTES: usize = 16 << 20;

#[derive(Args)]
pub struct ChannelWorkerConfig {
    #[arg(long, default_value_t = DEFAULT_MAX_POLL_SECONDS)]
    pub max_poll_seconds: u64,
    #[arg(long, default_value_t = DEFAULT_INLINE_MAX_BYTES)]
    pub inline_max_bytes: usize,
    #[arg(long, default_value_t = DEFAULT_BLOB_MAX_BYTES)]
    pub blob_max_bytes: usize,
}

impl Default for ChannelWorkerConfig {
    fn default() -> Self {
        Self {
            max_poll_seconds: DEFAULT_MAX_POLL_SECONDS,
            inline_max_bytes: DEFAULT_INLINE_MAX_BYTES,
            blob_max_bytes: DEFAULT_BLOB_MAX_BYTES,
        }
    }
}

impl ChannelWorkerConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.inline_max_bytes > 0 && self.inline_max_bytes <= DEFAULT_INLINE_MAX_BYTES,
            "inline limit must be within the supported 1 MiB request envelope"
        );
        anyhow::ensure!(
            self.blob_max_bytes > 0 && self.blob_max_bytes <= DEFAULT_BLOB_MAX_BYTES,
            "blob limit must be within the supported 16 MiB storage envelope"
        );
        anyhow::ensure!(
            self.max_poll_seconds <= DEFAULT_MAX_POLL_SECONDS,
            "poll duration exceeds the supported maximum"
        );
        Ok(())
    }
}

pub struct ChannelWorkerState {
    pub worker: SharedWorkerState,
    pub config: ChannelWorkerConfig,
    pub wake: Option<WakeClient>,
    pub wakeup: WakeupRegistry,
}

pub type SharedChannelWorkerState = Arc<ChannelWorkerState>;

impl ChannelWorkerState {
    pub fn new(
        worker: SharedWorkerState,
        config: ChannelWorkerConfig,
        wake: Option<WakeClient>,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        anyhow::ensure!(
            worker.config.development_kek.is_some(),
            "channel encryption requires a protected development key"
        );
        Ok(Self {
            worker,
            config,
            wake,
            wakeup: WakeupRegistry::new(),
        })
    }
}
