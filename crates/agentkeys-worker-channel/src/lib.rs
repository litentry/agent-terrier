//! Encrypted capability-scoped channel feeds with local long-poll notifications.

pub mod handlers;
pub mod state;
pub mod wake;
pub mod wakeup;

pub use state::{ChannelWorkerConfig, ChannelWorkerState};
