//! #573 — the ABSORPTION BRIDGE (arch §17.6 context flows, the `context-pub`
//! leg): an agent-INVOKED "propose to my owner" verb that pushes ONE
//! working-memory learning into the master's staging inbox for curated merge.
//! In the sandbox the agent runs `propose-to-owner "<text>" [namespace]`
//! (a thin wrapper over `agentkeys-daemon --propose-once`); the daemon signs
//! as the delegate and rides the EXISTING inbox-append path — cap-mint against
//! the on-chain `inbox:<ns>` grant, worker-stamped provenance, master
//! curation. The inbox stays the ONLY write path toward canonical.
//!
//! Deliberately NOT a mirror reverse-leg scan (#573's design choice):
//! mirrored canonical content and the agent's own `viking_remember` files
//! share one engine namespace, and the only "what the mirror wrote" record
//! (the ingest manifest) is sandbox-local and wiped on respawn — a scanner
//! would re-propose the agent's whole working memory after every respawn AND
//! echo canonical-derived content back into the inbox. The agent's INTENT is
//! the filter: it decides what is durable enough to propose.
//!
//! Bounded by construction: explicit invocation, a sliding-window rate gate
//! (`AGENTKEYS_PROPOSE_MAX_PER_HOUR`), a size cap
//! (`AGENTKEYS_PROPOSE_MAX_BYTES`), content-hash-keyed storage (re-proposing
//! identical text overwrites the same inbox object), and the master's
//! curation gate on the way into canonical (never a fast-forward — the
//! injection-vector defense holds).

use std::path::{Path, PathBuf};

use agentkeys_backend_client::protocol::ContextKind;
use agentkeys_backend_client::BackendClient;
use anyhow::{bail, Context};

use crate::chat_loop::{ChatLoopConfig, DelegateCredential};

/// Defaults for the two bounds — env-overridable, never load-bearing limits.
pub const DEFAULT_MAX_PER_HOUR: u32 = 20;
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024;
const RATE_WINDOW_SECS: u64 = 3600;

pub struct ProposeConfig {
    pub chat: ChatLoopConfig,
    pub memory_worker_url: String,
    /// Fallback namespace when the invocation names none — the FIRST entry of
    /// `AGENTKEYS_MEMORY_NAMESPACES` (the same candidate list the #566 mirror
    /// probes), so the propose default follows the granted-context wiring.
    pub default_namespace: String,
    pub max_per_hour: u32,
    pub max_bytes: usize,
    /// Sliding-window ledger (unix-seconds lines). Sandbox-local, dies with
    /// the sandbox — like the mirror's ingest manifest.
    pub stamp_file: PathBuf,
}

impl ProposeConfig {
    /// Build from the chat env. `None` = bridge disabled: the kill switch is
    /// set, or the memory worker URL cannot be derived from the broker host.
    pub fn from_chat_env(chat: ChatLoopConfig) -> Option<Self> {
        let read = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        if read("AGENTKEYS_PROPOSE").as_deref() == Some("0") {
            tracing::info!("#573 propose: disabled via AGENTKEYS_PROPOSE=0");
            return None;
        }
        let memory_worker_url = match read("AGENTKEYS_WORKER_MEMORY_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .or_else(|| crate::ui_bridge::derive_worker_url(&chat.broker_url, "memory"))
        {
            Some(u) => u,
            None => {
                tracing::warn!(
                    broker = %chat.broker_url,
                    "#573 propose: cannot derive the memory worker URL — bridge disabled"
                );
                return None;
            }
        };
        let default_namespace = read("AGENTKEYS_MEMORY_NAMESPACES")
            .unwrap_or_else(|| crate::memory_mirror::DEFAULT_NAMESPACES.to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .find(|s| !s.is_empty())?;
        let max_per_hour = read("AGENTKEYS_PROPOSE_MAX_PER_HOUR")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&n| (1..=1000).contains(&n))
            .unwrap_or(DEFAULT_MAX_PER_HOUR);
        let max_bytes = read("AGENTKEYS_PROPOSE_MAX_BYTES")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| (1..=1024 * 1024).contains(&n))
            .unwrap_or(DEFAULT_MAX_BYTES);
        let stamp_file = read("AGENTKEYS_PROPOSE_STAMP_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                Path::new(&home).join(".agentkeys").join("propose-stamps")
            });
        Some(Self {
            chat,
            memory_worker_url,
            default_namespace,
            max_per_hour,
            max_bytes,
            stamp_file,
        })
    }
}

/// One proposal as invoked (flags + stdin text); `None`s take the config
/// defaults at push time.
pub struct ProposalInput {
    pub namespace: Option<String>,
    pub key: Option<String>,
    pub kind: String,
    pub text: String,
}

/// Sliding-window rate gate over the stamp file. Reads the surviving stamps,
/// refuses when the window is full, records `now` otherwise. Plain-code and
/// injected-clock so tests never touch process env or real time.
pub fn rate_gate(stamp_file: &Path, now: u64, max_per_hour: u32) -> anyhow::Result<()> {
    let floor = now.saturating_sub(RATE_WINDOW_SECS);
    let mut stamps: Vec<u64> = std::fs::read_to_string(stamp_file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .filter(|&t| t >= floor)
        .collect();
    if stamps.len() >= max_per_hour as usize {
        bail!(
            "proposal rate limit reached: {} proposals in the last hour (max {}). \
             The limit resets as older proposals age out; batch related learnings \
             into one proposal instead of many small ones.",
            stamps.len(),
            max_per_hour
        );
    }
    stamps.push(now);
    if let Some(dir) = stamp_file.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let body = stamps
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(stamp_file, body + "\n")
        .with_context(|| format!("write {}", stamp_file.display()))
}

/// Validate + push ONE proposal through the shared inbox-append core
/// (`cred_admin::memory_inbox_push_with` — the #203 one-owner rule; the
/// client carries this credential's cap PoP, so #552 signer custody signs
/// remotely). Returns the machine-readable receipt the one-shot prints.
pub async fn propose_once(
    cfg: &ProposeConfig,
    credential: &DelegateCredential,
    bearer: &str,
    input: ProposalInput,
    now_unix: u64,
) -> anyhow::Result<serde_json::Value> {
    let text = input.text.trim();
    if text.is_empty() {
        bail!("nothing to propose: the proposal text (stdin) is empty");
    }
    if text.len() > cfg.max_bytes {
        bail!(
            "proposal too large: {} bytes (max {}). Propose the distilled learning, \
             not raw transcripts.",
            text.len(),
            cfg.max_bytes
        );
    }
    let kind = ContextKind::parse(&input.kind).with_context(|| {
        format!(
            "--propose-kind must be knowledge|skill (got `{}`)",
            input.kind
        )
    })?;
    if matches!(kind, ContextKind::Persona) {
        // The master's curation gate refuses persona adoption outright
        // (403 persona_not_inbox_adoptable) — pushing one only wastes an
        // inbox slot the owner can never accept. Refuse with the reason.
        bail!(
            "persona proposals are never inbox-adoptable (the master's curation gate \
             refuses them) — propose knowledge or skill"
        );
    }
    let namespace = input
        .namespace
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| cfg.default_namespace.clone());
    let key = input
        .key
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("proposal-{now_unix}"));
    rate_gate(&cfg.stamp_file, now_unix, cfg.max_per_hour)?;

    let client = BackendClient::new(
        Some(cfg.chat.broker_url.clone()),
        Some(cfg.memory_worker_url.clone()),
        None,
        None,
        Some(bearer.to_string()),
        None,
        None,
        std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
    );
    let client = credential.configure_client(client);
    let resp = agentkeys_cli::cred_admin::memory_inbox_push_with(
        &client,
        &namespace,
        &key,
        text,
        kind,
        &cfg.chat.operator_omni,
        &cfg.chat.actor_omni,
        &credential.device_key_hash(),
        bearer,
    )
    .await?;
    Ok(serde_json::json!({
        "outcome": "proposed",
        "namespace": namespace,
        "key": key,
        "kind": kind.as_str(),
        "content_hash": resp.content_hash,
        "s3_key": resp.s3_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_stamp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("agentkeys-propose-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("stamps")
    }

    #[test]
    fn rate_gate_fills_then_refuses_then_ages_out() {
        let stamps = scratch_stamp_file("window");
        let now = 1_000_000;
        for i in 0..3 {
            rate_gate(&stamps, now + i, 3).expect("under the limit");
        }
        let err = rate_gate(&stamps, now + 10, 3).expect_err("window full");
        assert!(err.to_string().contains("rate limit"), "{err}");
        // One hour later the old stamps age out and proposing resumes.
        rate_gate(&stamps, now + RATE_WINDOW_SECS + 11, 3).expect("window aged out");
    }

    #[test]
    fn rate_gate_ignores_garbage_lines_and_creates_parents() {
        let stamps = scratch_stamp_file("garbage");
        std::fs::create_dir_all(stamps.parent().unwrap()).unwrap();
        std::fs::write(&stamps, "not-a-number\n\n42\n").unwrap();
        // The stale 42 is far outside the window; only the fresh stamp counts.
        rate_gate(&stamps, 1_000_000, 1).expect("garbage + stale lines ignored");
        let err = rate_gate(&stamps, 1_000_001, 1).expect_err("now full");
        assert!(err.to_string().contains("max 1"), "{err}");
    }
}
