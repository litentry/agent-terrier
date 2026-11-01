pub use agentkeys_backend_client::protocol::knowledge_history::*;

/// The ring size for this process (read once per write — the knob is read-only).
pub fn history_keep() -> u32 {
    keep_from(std::env::var(KEEP_ENV).ok().as_deref())
}
