//! #594 — the delegate-side runtime CHECKPOINT loop + restore-on-boot
//! (plan `docs/plan/issue-594-sandbox-checkpoint-relaunch.md`).
//!
//! A veFaaS instance hard-expires at its lease deadline, and the #577
//! Hermes-home hand-off only works between two LIVE instances (broker-RAM
//! relay) — at expiry there is nothing left to export. This loop makes the
//! delegate's exportable runtime context DURABLE: periodically ask the local
//! bridge for its runtime-home snapshot (`/v1/sandbox/mgmt/session/export`,
//! the same #577 surface the broker relay uses) and persist it into the
//! delegate's OWN `memory:<ns>` grant under the reserved keyed-object slot
//! `agentkeys_protocol::CHECKPOINT_OBJECT_KEY`. At boot, the replacement
//! instance runs the mirror image: fetch the checkpoint and import it BEFORE
//! the first periodic save can overwrite it with a fresh (empty) home.
//!
//! Authority is the delegate's own: the sandbox mints its own `MemoryPut`/
//! `MemoryGet` caps (#552 signer PoP) over its own granted service — the
//! broker cannot write a checkpoint and never holds one at rest (D2/D4), and
//! the content lives in the per-actor encrypted memory plane (D6). Freshness
//! races with the #577 relay import are settled bridge-side by the newer-wins
//! `snapshot_at` guard, not by arrival order.
//!
//! Never load-bearing: every failure is a warn + retry next tick; chat and
//! the sandbox's jobs are unaffected.

use std::sync::Arc;
use std::time::Duration;

use agentkeys_backend_client::protocol::{
    service_memory, CapMintOp, CapMintRequest, CheckpointEnvelope, MemoryGetInput, MemoryPutInput,
    CHECKPOINT_OBJECT_KEY,
};
use agentkeys_backend_client::{normalize_omni_0x, BackendClient, BackendError};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::chat_loop::{ChatLoopConfig, DelegateCredential};

/// How long the boot restore keeps retrying while the bridge / broker come up
/// (the daemon often starts before the bridge finishes its ACP handshake).
const RESTORE_RETRY_WINDOW_SECS: u64 = 180;
const RESTORE_RETRY_INTERVAL_SECS: u64 = 5;
/// First periodic save runs this soon after the restore phase — early enough
/// that a freshly-migrated home becomes durable quickly, late enough to stay
/// clear of the boot burst.
const FIRST_TICK_DELAY_SECS: u64 = 120;

pub struct CheckpointConfig {
    pub chat: ChatLoopConfig,
    pub memory_worker_url: String,
    /// The delegate's own namespace (bare, e.g. `watchdog`) — the cap service
    /// is `service_memory(namespace)`.
    pub namespace: String,
    /// The #577 management bearer — the bridge requires it on the export
    /// surface; both processes read the same instance env, so it never skews.
    pub mgmt_token: String,
    pub interval: Duration,
    /// Refuse-loudly ceiling for one export body (raw bridge JSON bytes).
    pub max_bytes: usize,
    /// #616 — the reserved memory object key this delegate's checkpoints live
    /// under, selected by runtime (`AGENTKEYS_AGENT_RUNTIME=dsh` →
    /// `checkpoint/dsh-home` (#621 — one runtime, one slot). The restore path
    /// reads ONLY this key; hermes-era `checkpoint/hermes-home` objects are
    /// orphaned data, never restored cross-runtime.
    pub object_key: String,
}

impl CheckpointConfig {
    /// Build from the chat env. `None` = checkpoint disabled: kill switch,
    /// no #577 mgmt token (pre-#577 image / non-broker spawn), underivable
    /// namespace, or no memory-worker URL.
    pub fn from_chat_env(chat: ChatLoopConfig) -> Option<Self> {
        let read = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self::from_lookup(&read, chat)
    }

    /// Pure construction from a lookup fn — the testable seam (the repo's
    /// no-env-mutation-in-tests rule: tests pass a closure, never set_var).
    pub fn from_lookup(
        read: &dyn Fn(&str) -> Option<String>,
        chat: ChatLoopConfig,
    ) -> Option<Self> {
        use agentkeys_backend_client::protocol::sandbox_env as env_names;
        if read("AGENTKEYS_CHECKPOINT").as_deref() == Some("0") {
            tracing::info!("#594 checkpoint: disabled via AGENTKEYS_CHECKPOINT=0");
            return None;
        }
        let Some(mgmt_token) = read(env_names::MGMT_TOKEN) else {
            tracing::info!(
                "#594 checkpoint: no {} in the instance env (pre-#577 image or a spawn \
                 outside the broker lifecycle) — checkpoint disabled",
                env_names::MGMT_TOKEN
            );
            return None;
        };
        // Namespace: explicit injection (#425 O2 inherited namespaces differ
        // from the label) → else the ceremony's ns-defaults-to-label rule via
        // the `opchat-<label>` channel id.
        let namespace = match read(env_names::MEMORY_NS) {
            Some(ns) => ns,
            None => match chat.chat_channel_id.strip_prefix("opchat-") {
                Some(label) if !label.is_empty() => label.to_string(),
                _ => {
                    tracing::warn!(
                        channel = %chat.chat_channel_id,
                        "#594 checkpoint: no AGENTKEYS_MEMORY_NS and the channel id is not \
                         `opchat-<label>` — cannot address the delegate's memory grant; \
                         checkpoint disabled"
                    );
                    return None;
                }
            },
        };
        let memory_worker_url = match read("AGENTKEYS_WORKER_MEMORY_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .or_else(|| crate::ui_bridge::derive_worker_url(&chat.broker_url, "memory"))
        {
            Some(u) => u,
            None => {
                tracing::warn!(
                    broker = %chat.broker_url,
                    "#594 checkpoint: cannot derive the memory worker URL — checkpoint disabled"
                );
                return None;
            }
        };
        let interval = read("AGENTKEYS_CHECKPOINT_INTERVAL_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| (60..=86_400).contains(&s))
            .unwrap_or(900);
        let max_bytes = read("AGENTKEYS_CHECKPOINT_MAX_BYTES")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&b| (64 * 1024..=32 * 1024 * 1024).contains(&b))
            .unwrap_or(8 * 1024 * 1024);
        // #621 — one runtime, one slot: the dsh home key is THE checkpoint key.
        let object_key = CHECKPOINT_OBJECT_KEY.to_string();
        Some(Self {
            chat,
            memory_worker_url,
            namespace,
            mgmt_token,
            interval: Duration::from_secs(interval),
            max_bytes,
            object_key,
        })
    }

    fn backend_client(&self, bearer: &str, credential: &DelegateCredential) -> BackendClient {
        let client = BackendClient::new(
            Some(self.chat.broker_url.clone()),
            Some(self.memory_worker_url.clone()),
            None,
            None,
            Some(bearer.to_string()),
            None,
            None,
            std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
        );
        credential.configure_client(client)
    }
}

/// Spawn the checkpoint task alongside the chat loop (own session + cadence,
/// shared `DelegateCredential` — the #566 mirror pattern).
pub fn spawn(cfg: CheckpointConfig, credential: Arc<DelegateCredential>) {
    tokio::spawn(async move {
        run_loop(cfg, credential).await;
    });
}

async fn run_loop(cfg: CheckpointConfig, credential: Arc<DelegateCredential>) {
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "#594 checkpoint: http client build failed");
            return;
        }
    };
    tracing::info!(
        namespace = %cfg.namespace,
        interval_secs = cfg.interval.as_secs(),
        max_bytes = cfg.max_bytes,
        "#594 checkpoint: starting (restore, then periodic save)"
    );

    let mut session: Option<String> = None;

    // Phase 1 — restore. MUST complete (or conclusively give up) before the
    // first save: a fresh instance's near-empty home saved first would
    // overwrite the very checkpoint we came to restore.
    let deadline = std::time::Instant::now() + Duration::from_secs(RESTORE_RETRY_WINDOW_SECS);
    loop {
        let bearer = match ensure_session(&http, &cfg, &credential, &mut session).await {
            Some(b) => b,
            None => {
                if past(deadline, "restore gave up: no delegate session") {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(RESTORE_RETRY_INTERVAL_SECS)).await;
                continue;
            }
        };
        match restore_once(&http, &cfg, &credential, &bearer).await {
            Ok(outcome) => {
                tracing::info!(outcome = %outcome, "#594 checkpoint: restore phase done");
                break;
            }
            Err(RestoreError::SessionExpired) => session = None,
            Err(RestoreError::Retryable(e)) => {
                if past(deadline, &format!("restore gave up: {e}")) {
                    break;
                }
            }
            Err(RestoreError::Fatal(e)) => {
                tracing::warn!(error = %e, "#594 checkpoint: restore skipped (not retryable)");
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(RESTORE_RETRY_INTERVAL_SECS)).await;
    }

    // Phase 2 — periodic save.
    let mut last_saved_hash: Option<[u8; 32]> = None;
    tokio::time::sleep(Duration::from_secs(FIRST_TICK_DELAY_SECS)).await;
    loop {
        if let Some(bearer) = ensure_session(&http, &cfg, &credential, &mut session).await {
            match save_once(&http, &cfg, &credential, &bearer, &mut last_saved_hash).await {
                Ok(SaveOutcome::Saved { bytes }) => {
                    tracing::info!(bytes, namespace = %cfg.namespace, "#594 checkpoint: saved")
                }
                Ok(SaveOutcome::Unchanged) => {
                    tracing::debug!("#594 checkpoint: home unchanged — nothing to save")
                }
                Ok(SaveOutcome::TooLarge { bytes }) => tracing::warn!(
                    bytes,
                    cap = cfg.max_bytes,
                    "#594 checkpoint: export exceeds the size cap — NOT saved (trim \
                     the runtime home or raise AGENTKEYS_CHECKPOINT_MAX_BYTES)"
                ),
                Err(SaveError::SessionExpired) => session = None,
                Err(SaveError::Failed(e)) => {
                    tracing::warn!(error = %e, "#594 checkpoint: save failed — retrying next tick")
                }
            }
        }
        tokio::time::sleep(cfg.interval).await;
    }
}

fn past(deadline: std::time::Instant, reason: &str) -> bool {
    if std::time::Instant::now() >= deadline {
        tracing::warn!(
            reason = %reason,
            "#594 checkpoint: restore window elapsed — continuing with a fresh home \
             (periodic saves start anyway)"
        );
        return true;
    }
    false
}

/// Resolve (or reuse) the delegate session; `None` = resolve failed (logged).
async fn ensure_session(
    http: &reqwest::Client,
    cfg: &CheckpointConfig,
    credential: &DelegateCredential,
    session: &mut Option<String>,
) -> Option<String> {
    if session.is_none() {
        match crate::chat_loop::resolve_session(http, &cfg.chat, credential).await {
            Ok(jwt) => {
                credential.on_new_session(&jwt).await;
                *session = Some(jwt);
            }
            Err(e) => {
                tracing::warn!(error = %e, "#594 checkpoint: resolve failed");
                return None;
            }
        }
    }
    session.clone()
}

enum SaveOutcome {
    Saved { bytes: usize },
    Unchanged,
    TooLarge { bytes: usize },
}

enum SaveError {
    SessionExpired,
    Failed(String),
}

/// One save pass: bridge export → wrap → cap-mint → memory put (keyed).
async fn save_once(
    http: &reqwest::Client,
    cfg: &CheckpointConfig,
    credential: &DelegateCredential,
    bearer: &str,
    last_saved_hash: &mut Option<[u8; 32]>,
) -> Result<SaveOutcome, SaveError> {
    let export = bridge_export(http, cfg).await.map_err(SaveError::Failed)?;
    let raw_len = export.raw_len;
    if raw_len > cfg.max_bytes {
        return Ok(SaveOutcome::TooLarge { bytes: raw_len });
    }
    if Some(export.content_hash) == *last_saved_hash {
        return Ok(SaveOutcome::Unchanged);
    }
    let envelope = CheckpointEnvelope {
        version: 1,
        saved_at: export.snapshot_at,
        runtime: Some("dsh".to_string()),
        snapshot: export.snapshot,
    };
    let plaintext =
        serde_json::to_vec(&envelope).map_err(|e| SaveError::Failed(format!("wrap: {e}")))?;

    let client = cfg.backend_client(bearer, credential);
    let service = service_memory(&cfg.namespace);
    let cap = client
        .cap_mint(
            CapMintOp::MemoryPut,
            CapMintRequest {
                operator_omni: normalize_omni_0x(&cfg.chat.operator_omni),
                actor_omni: normalize_omni_0x(&cfg.chat.actor_omni),
                service: service.clone(),
                device_key_hash: credential.device_key_hash(),
                ttl_seconds: 300,
            },
            bearer,
        )
        .await
        .map_err(|e| classify_save(e, "cap-mint"))?;
    let put = client
        .memory_put(MemoryPutInput {
            cap,
            namespace: service,
            plaintext_b64: STANDARD.encode(&plaintext),
            object_key: Some(cfg.object_key.clone()),
        })
        .await
        .map_err(|e| classify_save(e, "memory-put"))?;
    if !put.ok {
        return Err(SaveError::Failed("memory-put answered ok=false".into()));
    }
    *last_saved_hash = Some(export.content_hash);
    Ok(SaveOutcome::Saved {
        bytes: plaintext.len(),
    })
}

fn classify_save(e: BackendError, stage: &str) -> SaveError {
    match e {
        BackendError::Http { status: 401, .. } => SaveError::SessionExpired,
        other => SaveError::Failed(format!("{stage}: {other}")),
    }
}

struct BridgeExport {
    snapshot: serde_json::Value,
    snapshot_at: u64,
    raw_len: usize,
    /// keccak over the export WITHOUT its `snapshot_at` (which changes every
    /// call) — the change detector for skip-unchanged.
    content_hash: [u8; 32],
}

async fn bridge_export(
    http: &reqwest::Client,
    cfg: &CheckpointConfig,
) -> Result<BridgeExport, String> {
    let url = format!(
        "{}/v1/sandbox/mgmt/session/export",
        cfg.chat.bridge_url.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .bearer_auth(&cfg.mgmt_token)
        .send()
        .await
        .map_err(|e| format!("bridge export: {e}"))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("bridge export body: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "bridge export HTTP {status}: {}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    let raw_len = body.len();
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("bridge export parse: {e}"))?;
    let snapshot_at = snapshot
        .get("snapshot_at")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(now_unix);
    let content_hash = {
        let mut stable = snapshot.clone();
        if let Some(o) = stable.as_object_mut() {
            o.remove("snapshot_at");
        }
        agentkeys_core::device_crypto::keccak256(stable.to_string().as_bytes())
    };
    // Normalize: the stored snapshot always carries ITS OWN export time, so a
    // pre-#594 bridge (no snapshot_at in the export) still produces a
    // checkpoint the newer-wins guard can order.
    if let Some(o) = snapshot.as_object_mut() {
        o.entry("snapshot_at")
            .or_insert(serde_json::json!(snapshot_at));
    }
    Ok(BridgeExport {
        snapshot,
        snapshot_at,
        raw_len,
        content_hash,
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum RestoreError {
    SessionExpired,
    /// Transport-ish — worth retrying inside the boot window.
    Retryable(String),
    /// Definitive — retrying cannot help (bad envelope, bridge refused).
    Fatal(String),
}

/// One restore pass: memory get (keyed) → unwrap → bridge import.
/// Returns a human outcome string for the single boot log line.
async fn restore_once(
    http: &reqwest::Client,
    cfg: &CheckpointConfig,
    credential: &DelegateCredential,
    bearer: &str,
) -> Result<String, RestoreError> {
    let client = cfg.backend_client(bearer, credential);
    let service = service_memory(&cfg.namespace);
    let cap = client
        .cap_mint(
            CapMintOp::MemoryGet,
            CapMintRequest {
                operator_omni: normalize_omni_0x(&cfg.chat.operator_omni),
                actor_omni: normalize_omni_0x(&cfg.chat.actor_omni),
                service: service.clone(),
                device_key_hash: credential.device_key_hash(),
                ttl_seconds: 300,
            },
            bearer,
        )
        .await
        .map_err(|e| classify_restore(e, "cap-mint"))?;
    let got = match client
        .memory_get(MemoryGetInput {
            cap,
            namespace: service,
            object_key: Some(cfg.object_key.clone()),
        })
        .await
    {
        Ok(g) => g,
        // No checkpoint yet (first spawn of this delegate) — a clean outcome.
        Err(BackendError::Http { status: 404, .. }) => {
            return Ok("no checkpoint stored (first spawn?)".into())
        }
        Err(e) => return Err(classify_restore(e, "memory-get")),
    };
    let bytes = STANDARD
        .decode(&got.plaintext_b64)
        .map_err(|e| RestoreError::Fatal(format!("checkpoint b64: {e}")))?;
    let envelope: CheckpointEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| RestoreError::Fatal(format!("checkpoint parse: {e}")))?;
    if envelope.version != 1 {
        return Err(RestoreError::Fatal(format!(
            "checkpoint version {} unsupported (this daemon speaks 1) — NOT restored",
            envelope.version
        )));
    }
    let mut body = envelope.snapshot;
    if let Some(o) = body.as_object_mut() {
        o.insert("snapshot_at".into(), serde_json::json!(envelope.saved_at));
        o.insert("restart".into(), serde_json::json!(true));
    }
    let url = format!(
        "{}/v1/sandbox/mgmt/session/import",
        cfg.chat.bridge_url.trim_end_matches('/')
    );
    let resp = http
        .post(&url)
        .bearer_auth(&cfg.mgmt_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| RestoreError::Retryable(format!("bridge import: {e}")))?;
    let status = resp.status();
    let v: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        // 404 = mgmt surface not armed on the bridge — definitive here, since
        // both processes read the same instance env.
        return Err(RestoreError::Fatal(format!(
            "bridge import HTTP {status}: {v}"
        )));
    }
    if v.get("applied").and_then(|a| a.as_bool()) == Some(false) {
        return Ok(format!(
            "skipped as stale (a fresher import already applied — #577 relay?): {v}"
        ));
    }
    Ok(format!(
        "restored {} file(s) from the checkpoint saved at {} (agent re-sourced: {})",
        v.get("restored_files")
            .and_then(|n| n.as_u64())
            .unwrap_or(0),
        envelope.saved_at,
        v.get("agent_restarted")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
    ))
}

fn classify_restore(e: BackendError, stage: &str) -> RestoreError {
    match e {
        BackendError::Http { status: 401, .. } => RestoreError::SessionExpired,
        BackendError::Http { status, body } if (400..500).contains(&status) => {
            RestoreError::Fatal(format!("{stage}: HTTP {status}: {body}"))
        }
        other => RestoreError::Retryable(format!("{stage}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat(channel: &str) -> ChatLoopConfig {
        ChatLoopConfig {
            broker_url: "https://broker.agentterrier.cn".into(),
            channel_worker_url: "https://channel.agentterrier.cn".into(),
            chat_channel_id: channel.into(),
            actor_omni: format!("0x{}", "ab".repeat(32)),
            operator_omni: format!("0x{}", "cd".repeat(32)),
            device_key_hex: None,
            session_jwt: Some("jwt".into()),
            signer_url: Some("https://signer.agentterrier.cn".into()),
            bridge_url: "http://127.0.0.1:8090".into(),
            bridge_token: None,
            speech_url: None,
            speech_bearer: None,
            stream_flush_ms: 1000,
        }
    }

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            pairs
                .iter()
                .find(|(pk, _)| *pk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn config_derives_namespace_from_opchat_channel() {
        let read = lookup(&[("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x")]);
        let cfg = CheckpointConfig::from_lookup(&read, chat("opchat-watchdog")).expect("enabled");
        assert_eq!(cfg.namespace, "watchdog");
        // The worker URL is DERIVED from the broker host (never pre-composed).
        assert_eq!(cfg.memory_worker_url, "https://memory.agentterrier.cn");
        assert_eq!(cfg.interval.as_secs(), 900);
        assert_eq!(cfg.max_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn config_prefers_injected_memory_ns_over_label_derive() {
        // #425 O2 — an INHERITED namespace differs from the label; the
        // broker-injected env wins over the channel-id derivation.
        let read = lookup(&[
            ("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x"),
            ("AGENTKEYS_MEMORY_NS", "inherited-ns"),
            ("AGENTKEYS_CHECKPOINT_INTERVAL_SECS", "60"),
            ("AGENTKEYS_CHECKPOINT_MAX_BYTES", "65536"),
        ]);
        let cfg = CheckpointConfig::from_lookup(&read, chat("opchat-newlabel")).expect("enabled");
        assert_eq!(cfg.namespace, "inherited-ns");
        assert_eq!(cfg.interval.as_secs(), 60);
        assert_eq!(cfg.max_bytes, 65536);
    }

    #[test]
    fn config_disabled_without_mgmt_token_kill_switch_or_derivable_ns() {
        // Pre-#577 image: no mgmt token → no export surface → disabled.
        let read = lookup(&[]);
        assert!(CheckpointConfig::from_lookup(&read, chat("opchat-w")).is_none());
        // Kill switch.
        let read = lookup(&[
            ("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x"),
            ("AGENTKEYS_CHECKPOINT", "0"),
        ]);
        assert!(CheckpointConfig::from_lookup(&read, chat("opchat-w")).is_none());
        // Non-opchat channel id and no injected ns → underivable → disabled.
        let read = lookup(&[("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x")]);
        assert!(CheckpointConfig::from_lookup(&read, chat("custom-feed")).is_none());
    }

    #[test]
    fn config_clamps_out_of_bounds_tuning_to_defaults() {
        let read = lookup(&[
            ("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x"),
            ("AGENTKEYS_CHECKPOINT_INTERVAL_SECS", "5"),
            ("AGENTKEYS_CHECKPOINT_MAX_BYTES", "999999999999"),
        ]);
        let cfg = CheckpointConfig::from_lookup(&read, chat("opchat-w")).expect("enabled");
        assert_eq!(cfg.interval.as_secs(), 900);
        assert_eq!(cfg.max_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn checkpoint_key_is_the_single_dsh_slot() {
        // #621: one runtime, one slot — no env selects a key anymore.
        let base = |k: &str| -> Option<String> {
            match k {
                "AGENTKEYS_SANDBOX_MGMT_TOKEN" => Some("smt1_x".into()),
                "AGENTKEYS_MEMORY_NS" => Some("watchdog".into()),
                _ => None,
            }
        };
        let cfg = CheckpointConfig::from_lookup(&base, chat("opchat-watchdog")).expect("cfg");
        assert_eq!(cfg.object_key, CHECKPOINT_OBJECT_KEY);
        assert_eq!(cfg.object_key, "checkpoint/dsh-home");
    }
}
