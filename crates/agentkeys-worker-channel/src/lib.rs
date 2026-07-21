//! Channel-service worker — #406 / `docs/spec/agent-channel-decoupling.md` (D7).
//!
//! Mirrors the memory/config workers' cap-verify + AES-256-GCM + S3 semantics,
//! but uses a separate S3 prefix (`channel/...`), a separate bucket
//! (`$CHANNEL_BUCKET`), accepts only `DataClass::Channel` caps, and adds the
//! near-real-time (NRT) decision (§14.12): the channel worker is the ONLY write
//! path, so it completes held consumer long-polls **in-process** the instant a
//! matching event lands (write-through wakeup). S3/TOS is the durable record —
//! never the notification path.
//!
//! Direction is the SIGNED cap op: a `ChannelPublish` cap is honored only at
//! `/v1/channel/publish`, a `ChannelSubscribe` cap only at `/v1/channel/poll`
//! (`verify::check_op`), so a publish grant can never consume and a subscribe
//! grant can never produce (D2 direction isolation). A non-Channel cap is
//! rejected by `verify::check_data_class`, symmetric with the other workers.
//!
//! Shares all cryptographic + chain-verification code with the credentials
//! worker via `agentkeys_worker_creds`.

pub mod handlers;
pub mod state;
pub mod sts_mint;
pub mod wakeup;

pub use state::{ChannelWorkerConfig, ChannelWorkerState};
