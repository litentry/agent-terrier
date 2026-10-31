//! Periodically persist actor runtime state and restore it before a new save.
//! Pending restores protect the stored snapshot from replacement by an empty runtime.

use std::sync::Arc;
use std::time::Duration;

use agentkeys_backend_client::protocol::{
    service_knowledge, CapMintOp, CapMintRequest, CheckpointEnvelope, MemoryGetInput,
    MemoryPutInput, CHECKPOINT_OBJECT_KEY, OV_WORKSPACE_OBJECT_KEY,
};
use agentkeys_backend_client::{normalize_omni_0x, BackendClient, BackendError};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::chat_loop::{ChatLoopConfig, DelegateCredential};
use crate::lifecycle::LifecycleHub;

/// How long the boot restore keeps retrying while the bridge / broker come up
/// (the daemon often starts before the bridge finishes its ACP handshake).
/// Past it the lifecycle moves on (chat never waits on a restore) and a
/// restore still pending is retried every tick — the saves wait for it.
const RESTORE_RETRY_WINDOW_SECS: u64 = 180;
const RESTORE_RETRY_INTERVAL_SECS: u64 = 5;
/// How many times one workspace restore attempt fetches the engine-workspace
/// object before it answers pending (a transient body-stream failure, never
/// a 4xx) — the next tick retries it.
const WORKSPACE_GET_ATTEMPTS: u8 = 4;
/// The first tick (a save, or a retry of a restore still pending) runs this
/// soon after the restore phase — early enough that a freshly-migrated home
/// becomes durable quickly, late enough to stay clear of the boot burst.
const FIRST_TICK_DELAY_SECS: u64 = 120;
/// While the engine is held for its workspace restore, a tick comes this often
/// (the engine and the knowledge wait on every attempt).
const ENGINE_HOLD_RETRY_SECS: u64 = 30;
/// The engine hold's bound (`AGENTKEYS_OV_RESTORE_PENDING_MAX_SECS` — the
/// start script reads the same knob with the same default).
const DEFAULT_ENGINE_HOLD_MAX_SECS: u64 = 1800;

pub struct CheckpointConfig {
    pub chat: ChatLoopConfig,
    pub memory_worker_url: String,
    /// The delegate's own namespace (bare, e.g. `watchdog`) — the cap service
    /// is `service_knowledge(namespace)`.
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
    /// #694 — the engine workspace to checkpoint beside the home
    /// (`OPENVIKING_WORKSPACE`); `None` when its parent dir does not exist
    /// (no engine on this box).
    pub workspace: Option<std::path::PathBuf>,
    /// The mirror's ingest manifest — it travels inside the workspace object
    /// so a restored index is also a restored "already mirrored" set.
    pub manifest: std::path::PathBuf,
    /// Touched once the workspace restore CONCLUDED (restored, nothing stored,
    /// or refused for good) — never on a timeout: the engine's start script
    /// waits for it (`AGENTKEYS_OV_RESTORE_MARKER`), and a restarted daemon
    /// that finds it knows the live workspace descends from that conclusion.
    pub marker: std::path::PathBuf,
    /// How long the engine may be held for a workspace restore in flight
    /// (`<marker>.pending`, `AGENTKEYS_OV_RESTORE_PENDING_MAX_SECS`, default
    /// 1800, 0 = never held). The start script stops waiting at the same bound,
    /// so a crashed daemon cannot keep the engine down.
    pub engine_hold_max: Duration,
    /// When the engine hold went up ([`CheckpointConfig::hold_engine_now`]);
    /// `None` = the engine is not held.
    pub engine_held_since: Option<std::time::Instant>,
    /// #693 — the lifecycle hub (`restoring` → the restore outcome).
    pub hub: Option<Arc<LifecycleHub>>,
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
        let workspace_path = std::path::PathBuf::from(
            read("OPENVIKING_WORKSPACE")
                .unwrap_or_else(|| "/opt/agentkeys/openviking/workspace".to_string()),
        );
        let workspace = workspace_path
            .parent()
            .filter(|p| p.is_dir())
            .map(|_| workspace_path.clone());
        let marker =
            std::path::PathBuf::from(read("AGENTKEYS_OV_RESTORE_MARKER").unwrap_or_else(|| {
                workspace_path
                    .parent()
                    .unwrap_or(std::path::Path::new("/tmp"))
                    .join(".workspace-restored")
                    .to_string_lossy()
                    .into_owned()
            }));
        let engine_hold_max = read("AGENTKEYS_OV_RESTORE_PENDING_MAX_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&s| s <= 86_400)
            .unwrap_or(DEFAULT_ENGINE_HOLD_MAX_SECS);
        Some(Self {
            chat,
            memory_worker_url,
            namespace,
            mgmt_token,
            interval: Duration::from_secs(interval),
            max_bytes,
            object_key,
            workspace,
            manifest: agentkeys_memory_openviking::ingest_manifest_from_env(),
            marker,
            engine_hold_max: Duration::from_secs(engine_hold_max),
            engine_held_since: None,
            hub: None,
        })
    }

    /// #694 — put the engine hold up now. The chat loop calls this BEFORE its
    /// credential bootstrap, which can stall on the signer while the engine's
    /// start script only waits its own bound for a hold to appear.
    pub fn hold_engine_now(&mut self) {
        self.engine_held_since = hold_engine(self).then(std::time::Instant::now);
    }

    /// Nothing will restore the workspace (the chat loop could not start): let
    /// the engine go at once.
    pub fn release_engine_now(&self) {
        release_engine(&self.marker);
    }

    fn backend_client(&self, credential: &DelegateCredential) -> BackendClient {
        let client = BackendClient::new(
            Some(self.chat.broker_url.clone()),
            Some(self.memory_worker_url.clone()),
            None,
            None,
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
    if let Some(h) = &cfg.hub {
        h.stage(
            agentkeys_backend_client::protocol::LifecycleStage::Restoring,
            "restoring the checkpoint",
        );
    }

    // #694 — the engine workspace (index + manifest) restores BEFORE the engine
    // starts, so the first pull is a delta: the start script waits for the
    // marker a conclusion touches, and past its own bound too while the engine
    // is held (`<marker>.pending`, up to `engine_hold_max`, put up by the chat
    // loop before its credential bootstrap) — so a restore that lands late
    // still lands into an empty workspace.
    let mut engine_hold = cfg.engine_held_since;

    // Phase 1 — restore both objects inside the boot window. Nothing is saved
    // over an object until its restore CONCLUDES: a fresh instance's near-empty
    // home saved first would overwrite the very checkpoint we came to restore.
    let deadline = std::time::Instant::now() + Duration::from_secs(RESTORE_RETRY_WINDOW_SECS);
    let mut home = RestoreState::Pending("not attempted yet".into());
    let mut workspace = RestoreState::Pending("not attempted yet".into());
    loop {
        attempt_pending(
            &http,
            &cfg,
            &credential,
            &mut session,
            &mut home,
            &mut workspace,
        )
        .await;
        engine_hold = keep_engine_hold(engine_hold, &workspace, &cfg);
        if !home.retries() && !workspace.retries() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                home = ?home,
                workspace = ?workspace,
                engine_held = engine_hold.is_some(),
                "#594 checkpoint: restore window elapsed with a restore still PENDING — \
                 retried every tick; nothing is saved over a stored object until its \
                 restore concludes"
            );
            break;
        }
        tokio::time::sleep(Duration::from_secs(RESTORE_RETRY_INTERVAL_SECS)).await;
    }
    if let Some(h) = &cfg.hub {
        h.set_checkpoint_note(restore_note(&home, &workspace, engine_hold.is_some()));
        h.restore_finished(&concluded_summary(&home, &workspace));
    }

    // Phase 2 — each tick retries a restore still pending, else saves.
    let mut last_saved_hash: Option<[u8; 32]> = None;
    let mut last_workspace_fp: Option<[u8; 32]> = None;
    let mut first_tick = true;
    loop {
        tokio::time::sleep(next_tick_delay(
            engine_hold.is_some(),
            first_tick,
            cfg.interval,
        ))
        .await;
        first_tick = false;
        if home.retries() || workspace.retries() {
            attempt_pending(
                &http,
                &cfg,
                &credential,
                &mut session,
                &mut home,
                &mut workspace,
            )
            .await;
            engine_hold = keep_engine_hold(engine_hold, &workspace, &cfg);
            for (restore, state) in [("runtime home", &home), ("engine workspace", &workspace)] {
                if let RestoreState::Pending(why) = state {
                    tracing::warn!(
                        restore,
                        reason = %why,
                        "#594 checkpoint: restore still pending — retrying next tick; \
                         nothing is saved over the stored object meanwhile"
                    );
                }
            }
            if let Some(h) = &cfg.hub {
                h.set_checkpoint_note(restore_note(&home, &workspace, engine_hold.is_some()));
            }
        }
        if workspace.saves() {
            if let Some(bearer) = ensure_session(&http, &cfg, &credential, &mut session).await {
                match workspace_save(&cfg, &credential, &bearer, &mut last_workspace_fp).await {
                    Ok(SaveOutcome::Saved { bytes }) => {
                        tracing::info!(bytes, "#694 checkpoint: engine workspace saved")
                    }
                    Ok(SaveOutcome::Unchanged) => {}
                    Ok(SaveOutcome::TooLarge { bytes }) => tracing::warn!(
                        bytes,
                        cap = cfg.max_bytes,
                        "#694 checkpoint: engine workspace exceeds the size cap — NOT saved"
                    ),
                    Err(SaveError::SessionExpired) => session = None,
                    Err(SaveError::Failed(e)) => {
                        tracing::warn!(error = %e, "#694 checkpoint: engine workspace save failed — retrying next tick")
                    }
                }
            }
        }
        if home.saves() {
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
        }
    }
}

/// The wait before the next tick: short while the engine is held (it waits on
/// every restore attempt), the first-tick delay once, then the save cadence.
fn next_tick_delay(engine_held: bool, first_tick: bool, interval: Duration) -> Duration {
    if engine_held {
        Duration::from_secs(ENGINE_HOLD_RETRY_SECS).min(interval)
    } else if first_tick {
        Duration::from_secs(FIRST_TICK_DELAY_SECS)
    } else {
        interval
    }
}

/// `<marker>.pending` — the engine hold (the start script derives the same
/// name from `AGENTKEYS_OV_RESTORE_MARKER`).
fn pending_marker(marker: &std::path::Path) -> std::path::PathBuf {
    let mut name = marker.as_os_str().to_owned();
    name.push(".pending");
    name.into()
}

/// The workspace restore would unpack into an empty workspace: an engine
/// workspace on this box, empty (or absent), and no restore concluded yet.
fn workspace_awaits_restore(workspace: Option<&std::path::Path>, marker: &std::path::Path) -> bool {
    workspace.is_some_and(|ws| !marker.exists() && !dir_has_entries(ws))
}

/// #694 — hold the engine while its workspace restore is in flight: write
/// `<marker>.pending` when the restore would unpack into an empty workspace,
/// else clear a stale one (a crashed run's). Returns whether the engine is held.
fn hold_engine(cfg: &CheckpointConfig) -> bool {
    if cfg.engine_hold_max.is_zero()
        || !workspace_awaits_restore(cfg.workspace.as_deref(), &cfg.marker)
    {
        release_engine(&cfg.marker);
        return false;
    }
    let pending = pending_marker(&cfg.marker);
    if let Some(parent) = pending.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&pending, now_unix().to_string()) {
        Ok(()) => {
            tracing::info!(
                pending = ?pending,
                hold_max_secs = cfg.engine_hold_max.as_secs(),
                "#694 checkpoint: engine held until its workspace restore concludes"
            );
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, pending = ?pending, "#694 checkpoint: engine hold not declared — the engine starts after its own wait");
            false
        }
    }
}

/// The engine stays held while its workspace restore is still pending, up to
/// the bound the start script also stops at.
fn engine_stays_held(workspace: &RestoreState, held_for: Duration, hold_max: Duration) -> bool {
    workspace.retries() && held_for < hold_max
}

/// Keep the engine hold, or let the engine go — the hold file removed after
/// any marker a conclusion touched, and the mirror told to wait out the start.
fn keep_engine_hold(
    hold: Option<std::time::Instant>,
    workspace: &RestoreState,
    cfg: &CheckpointConfig,
) -> Option<std::time::Instant> {
    let since = hold?;
    if engine_stays_held(workspace, since.elapsed(), cfg.engine_hold_max) {
        return Some(since);
    }
    release_engine(&cfg.marker);
    if let Some(h) = &cfg.hub {
        h.engine_released();
    }
    None
}

fn release_engine(marker: &std::path::Path) {
    let pending = pending_marker(marker);
    match std::fs::remove_file(&pending) {
        Ok(()) => tracing::info!(pending = ?pending, "#694 checkpoint: engine hold released"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            error = %e,
            pending = ?pending,
            "#694 checkpoint: engine hold file not removed — the start script stops waiting at its own bound"
        ),
    }
}

/// Where one restore (the runtime home, or the engine workspace) stands. Only
/// a CONCLUDED restore lets the periodic save write its object.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RestoreState {
    /// Not concluded — no session, a transport error, a 5xx, a throttle, a
    /// failed unpack, or the boot window ran out: retried every tick, never
    /// saved over.
    Pending(String),
    /// Restored, nothing stored (404), skipped as stale, or refused for good:
    /// the periodic save owns the object from here.
    Concluded(String),
    /// Engine workspace only: the engine filled its workspace before the
    /// restore could land while a stored one exists. Kept for the next
    /// respawn — never unpacked over a live engine, never saved over, not
    /// retried (it cannot land in this sandbox).
    Held,
}

impl RestoreState {
    /// The periodic save may write this restore's object.
    fn saves(&self) -> bool {
        matches!(self, RestoreState::Concluded(_))
    }

    /// The next tick retries this restore.
    fn retries(&self) -> bool {
        matches!(self, RestoreState::Pending(_))
    }
}

/// A restore attempt's definitive answer.
enum Restored {
    Done(String),
    /// See [`RestoreState::Held`].
    Held,
}

/// The decision over one restore attempt: only a definitive answer concludes.
fn decide(attempt: Result<Restored, RestoreError>) -> RestoreState {
    match attempt {
        Ok(Restored::Done(outcome)) => RestoreState::Concluded(outcome),
        Ok(Restored::Held) => RestoreState::Held,
        Err(RestoreError::Fatal(e)) => RestoreState::Concluded(format!("not restored: {e}")),
        Err(RestoreError::NoSession) => RestoreState::Pending("no delegate session".into()),
        Err(RestoreError::SessionExpired) => {
            RestoreState::Pending("delegate session expired".into())
        }
        Err(RestoreError::Retryable(e)) => RestoreState::Pending(e),
    }
}

/// Attempt whichever restores are still pending; a workspace restore that
/// concludes touches the engine's marker. A resolve that just failed is not
/// repeated within the same pass (a stalled broker is not asked twice).
async fn attempt_pending(
    http: &reqwest::Client,
    cfg: &CheckpointConfig,
    credential: &DelegateCredential,
    session: &mut Option<String>,
    home: &mut RestoreState,
    workspace: &mut RestoreState,
) {
    let mut resolve_failed = false;
    if home.retries() {
        let attempt = match ensure_session(http, cfg, credential, session).await {
            Some(bearer) => restore_once(http, cfg, credential, &bearer)
                .await
                .map(Restored::Done),
            None => {
                resolve_failed = true;
                Err(RestoreError::NoSession)
            }
        };
        *home = settle("runtime home", attempt, session);
    }
    if workspace.retries() {
        let attempt = match workspace_settled_locally(cfg.workspace.as_deref(), &cfg.marker) {
            Some(outcome) => Ok(Restored::Done(outcome)),
            None if resolve_failed => Err(RestoreError::NoSession),
            None => match ensure_session(http, cfg, credential, session).await {
                Some(bearer) => workspace_restore(cfg, credential, &bearer).await,
                None => Err(RestoreError::NoSession),
            },
        };
        *workspace = settle("engine workspace", attempt, session);
        if workspace.saves() {
            touch_marker(&cfg.marker);
        }
    }
}

/// Log one attempt's definitive answer, drop an expired session, decide.
fn settle(
    restore: &str,
    attempt: Result<Restored, RestoreError>,
    session: &mut Option<String>,
) -> RestoreState {
    match &attempt {
        Ok(Restored::Done(outcome)) => {
            tracing::info!(restore, outcome = %outcome, "#594 checkpoint: restore concluded")
        }
        Ok(Restored::Held) => tracing::warn!(
            restore,
            "#694 checkpoint: the engine filled its workspace before the restore could \
             land — the stored workspace is KEPT for the next respawn; this sandbox's \
             workspace is not checkpointed"
        ),
        Err(RestoreError::Fatal(e)) => tracing::warn!(
            restore,
            error = %e,
            "#594 checkpoint: not restored (definitive) — periodic saves own the object"
        ),
        Err(RestoreError::SessionExpired) => *session = None,
        Err(RestoreError::NoSession) | Err(RestoreError::Retryable(_)) => {}
    }
    decide(attempt)
}

/// The boot restore's concluded outcomes, one line (a pending or held one
/// rides the checkpoint note instead).
fn concluded_summary(home: &RestoreState, workspace: &RestoreState) -> String {
    [home, workspace]
        .into_iter()
        .filter_map(|state| match state {
            RestoreState::Concluded(outcome) => Some(outcome.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The console's line for a restore that has not concluded — it rides every
/// lifecycle report's detail until the restore concludes
/// ([`LifecycleHub::set_checkpoint_note`]). `None` = nothing outstanding.
fn restore_note(
    home: &RestoreState,
    workspace: &RestoreState,
    engine_held: bool,
) -> Option<String> {
    let mut parts = Vec::new();
    if let RestoreState::Pending(why) = home {
        parts.push(format!(
            "checkpoint restore pending ({}) — saves paused",
            brief(why)
        ));
    }
    match workspace {
        RestoreState::Pending(why) if engine_held => parts.push(format!(
            "engine workspace restore pending ({}) — the engine waits for it, saves paused",
            brief(why)
        )),
        RestoreState::Pending(why) => parts.push(format!(
            "engine workspace restore pending ({}) — saves paused",
            brief(why)
        )),
        RestoreState::Held => parts.push(
            "engine workspace restore held (the engine started first) — the stored one \
             returns at the next respawn"
                .to_string(),
        ),
        RestoreState::Concluded(_) => {}
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// A reason short enough for one console line (the log keeps the full one).
fn brief(reason: &str) -> String {
    const MAX_CHARS: usize = 96;
    if reason.chars().count() <= MAX_CHARS {
        return reason.to_string();
    }
    let head: String = reason.chars().take(MAX_CHARS).collect();
    format!("{head}…")
}

fn touch_marker(marker: &std::path::Path) {
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(marker, now_unix().to_string()) {
        tracing::warn!(error = %e, marker = ?marker, "#694 checkpoint: restore marker not written — the engine starts after its own wait");
    }
}

/// The manifest's snapshot name inside the workspace archive.
const MANIFEST_SNAPSHOT: &str = ".agentkeys-ov-ingested.txt";

/// Refresh the manifest's snapshot in the workspace only when its content
/// changed: a copy stamps a fresh mtime, and [`dir_fingerprint`] (path, size,
/// mtime) would call every tick a change and re-upload an unchanged
/// workspace. A snapshot that cannot be written is logged once — the restore
/// then re-mirrors once, nothing worse.
fn snapshot_manifest(manifest: &std::path::Path, ws: &std::path::Path) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let Ok(current) = std::fs::read(manifest) else {
        return;
    };
    let snap = ws.join(MANIFEST_SNAPSHOT);
    if std::fs::read(&snap).is_ok_and(|held| held == current) {
        return;
    }
    if let Err(e) = std::fs::write(&snap, &current) {
        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(error = %e, snapshot = ?snap, "#694 checkpoint: manifest snapshot not written — a restore re-mirrors once");
        }
    }
}

fn dir_has_entries(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}

/// A cheap change detector over the workspace: every (path, size, mtime).
fn dir_fingerprint(dir: &std::path::Path) -> [u8; 32] {
    fn walk(dir: &std::path::Path, out: &mut String) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if let Ok(m) = e.metadata() {
                let mtime = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                out.push_str(&format!("{}\x1f{}\x1f{}\n", p.display(), m.len(), mtime));
            }
        }
    }
    let mut s = String::new();
    walk(dir, &mut s);
    agentkeys_core::device_crypto::keccak256(s.as_bytes())
}

async fn tar_gz(dir: &std::path::Path) -> Result<Vec<u8>, String> {
    let out = tokio::process::Command::new("tar")
        .arg("-C")
        .arg(dir)
        .args(["-czf", "-", "."])
        .output()
        .await
        .map_err(|e| format!("tar unavailable: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tar exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(out.stdout)
}

async fn untar_gz(dir: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("tar")
        .arg("-C")
        .arg(dir)
        .args(["-xzf", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("tar unavailable: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(bytes)
            .await
            .map_err(|e| format!("tar stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("tar wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tar exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(())
}

/// #694 — unpack a stored workspace archive into the empty (or absent)
/// workspace ATOMICALLY: extract into a sibling staging dir, then swap it in
/// with one rename. A failed extract leaves nothing behind; a workspace that
/// filled meanwhile (a live engine) is never replaced — `Ok(false)`.
async fn unpack_workspace(ws: &std::path::Path, archive: &[u8]) -> Result<bool, String> {
    let (Some(parent), Some(name)) = (ws.parent(), ws.file_name()) else {
        return Err(format!("workspace path {} has no parent", ws.display()));
    };
    let mut staging_name = name.to_owned();
    staging_name.push(".restoring");
    let staging = parent.join(staging_name);
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("mkdir {}: {e}", staging.display()))?;
    if let Err(e) = untar_gz(&staging, archive).await {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!("unpack: {e}"));
    }
    if dir_has_entries(ws) {
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(false);
    }
    if let Err(e) = std::fs::rename(&staging, ws) {
        let _ = std::fs::remove_dir_all(&staging);
        if dir_has_entries(ws) {
            return Ok(false);
        }
        return Err(format!("swap into {}: {e}", ws.display()));
    }
    Ok(true)
}

/// #694 — the workspace restore's answers that need no stored object: no
/// engine on this box, or a restore that already concluded in this sandbox
/// (a restarted daemon finds the marker its conclusion touched). A populated
/// workspace WITHOUT the marker is not one of them: the engine starts on its
/// own after a bounded wait, so its workspace says nothing about the stored one.
fn workspace_settled_locally(
    workspace: Option<&std::path::Path>,
    marker: &std::path::Path,
) -> Option<String> {
    match workspace {
        None => Some("no engine workspace on this box".into()),
        Some(_) if marker.exists() => {
            Some("engine workspace restore already concluded in this sandbox".into())
        }
        Some(_) => None,
    }
}

/// #694 — fetch the engine workspace object and unpack it into an EMPTY
/// workspace. A populated one (a live engine) is never unpacked over — and
/// with a stored object present it is HELD: never saved over it either.
async fn workspace_restore(
    cfg: &CheckpointConfig,
    credential: &DelegateCredential,
    bearer: &str,
) -> Result<Restored, RestoreError> {
    let Some(ws) = &cfg.workspace else {
        return Ok(Restored::Done("no engine workspace on this box".into()));
    };
    let client = cfg.backend_client(credential);
    let service = service_knowledge(&cfg.namespace);
    // The workspace object is the biggest thing the restore reads; a dropped
    // body stream on the worker's side (`502 s3_body`, measured once on
    // 2026-09-27) is transient — retry it a few times, a fresh cap each time,
    // before this attempt answers pending (the next tick retries it). A 4xx
    // is definitive.
    let mut attempt = 0u8;
    let got = loop {
        attempt += 1;
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
        match client
            .memory_get(MemoryGetInput {
                cap,
                namespace: service.clone(),
                object_key: Some(OV_WORKSPACE_OBJECT_KEY.to_string()),
            })
            .await
        {
            Ok(g) => break g,
            Err(BackendError::Http { status: 404, .. }) => {
                return Ok(Restored::Done(
                    "no engine workspace checkpoint (first spawn?)".into(),
                ))
            }
            Err(e) => match classify_restore(e, "memory-get") {
                RestoreError::Retryable(why) if attempt < WORKSPACE_GET_ATTEMPTS => {
                    tracing::warn!(
                        error = %why,
                        attempt,
                        "#694 checkpoint: engine workspace get failed on a transient error — retrying"
                    );
                    tokio::time::sleep(Duration::from_secs(RESTORE_RETRY_INTERVAL_SECS)).await;
                }
                refusal => return Err(refusal),
            },
        }
    };
    if dir_has_entries(ws) {
        return Ok(Restored::Held);
    }
    let bytes = STANDARD
        .decode(&got.plaintext_b64)
        .map_err(|e| RestoreError::Fatal(format!("workspace b64: {e}")))?;
    // A failed unpack is local (permissions, disk) and leaves nothing behind —
    // the next attempt retries it.
    if !unpack_workspace(ws, &bytes)
        .await
        .map_err(RestoreError::Retryable)?
    {
        return Ok(Restored::Held);
    }
    let snap = ws.join(MANIFEST_SNAPSHOT);
    let mut manifest_restored = false;
    if snap.is_file() {
        if let Some(parent) = cfg.manifest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::copy(&snap, &cfg.manifest) {
            Ok(_) => manifest_restored = true,
            Err(e) => {
                tracing::warn!(error = %e, "#694 checkpoint: manifest snapshot not restored — the first pull re-mirrors")
            }
        }
    }
    // An archive without the manifest (saved while it could not persist) is
    // an index the mirror cannot see: its first pull rewrites every item.
    Ok(Restored::Done(if manifest_restored {
        format!(
            "engine workspace restored ({} bytes) — the first pull is a delta",
            bytes.len()
        )
    } else {
        format!(
            "engine workspace restored ({} bytes) without a manifest snapshot — the first pull re-mirrors every item once",
            bytes.len()
        )
    }))
}

/// #694 — archive the engine workspace (with a snapshot of the manifest) into
/// its keyed object when it changed since the last save.
async fn workspace_save(
    cfg: &CheckpointConfig,
    credential: &DelegateCredential,
    bearer: &str,
    last_fp: &mut Option<[u8; 32]>,
) -> Result<SaveOutcome, SaveError> {
    let Some(ws) = &cfg.workspace else {
        return Ok(SaveOutcome::Unchanged);
    };
    if !dir_has_entries(ws) {
        return Ok(SaveOutcome::Unchanged);
    }
    snapshot_manifest(&cfg.manifest, ws);
    let fp = dir_fingerprint(ws);
    if Some(fp) == *last_fp {
        return Ok(SaveOutcome::Unchanged);
    }
    let bytes = tar_gz(ws).await.map_err(SaveError::Failed)?;
    if bytes.len() > cfg.max_bytes {
        return Ok(SaveOutcome::TooLarge { bytes: bytes.len() });
    }
    let client = cfg.backend_client(credential);
    let service = service_knowledge(&cfg.namespace);
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
            plaintext_b64: STANDARD.encode(&bytes),
            object_key: Some(OV_WORKSPACE_OBJECT_KEY.to_string()),
            expected_content_hash: None,
        })
        .await
        .map_err(|e| classify_save(e, "memory-put"))?;
    if !put.ok {
        return Err(SaveError::Failed("memory-put answered ok=false".into()));
    }
    *last_fp = Some(fp);
    Ok(SaveOutcome::Saved { bytes: bytes.len() })
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

    let client = cfg.backend_client(credential);
    let service = service_knowledge(&cfg.namespace);
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
            expected_content_hash: None,
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
    /// No delegate session could be resolved — nothing was read.
    NoSession,
    SessionExpired,
    /// Transport, a 5xx, a throttle, a failed unpack — the stored object may
    /// exist unread, so this never concludes the restore.
    Retryable(String),
    /// Definitive — retrying cannot help (bad envelope, a 4xx refusal).
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
    let client = cfg.backend_client(credential);
    let service = service_knowledge(&cfg.namespace);
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
        return Err(import_refusal(status.as_u16(), &v));
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

/// Transient by HTTP semantics — a server error, a request timeout (408) or
/// throttling (429): never a conclusion.
fn transient_status(status: u16) -> bool {
    status >= 500 || status == 408 || status == 429
}

fn classify_restore(e: BackendError, stage: &str) -> RestoreError {
    match e {
        BackendError::Http { status: 401, .. } => RestoreError::SessionExpired,
        BackendError::Http { status, body }
            if (400..500).contains(&status) && !transient_status(status) =>
        {
            RestoreError::Fatal(format!("{stage}: HTTP {status}: {body}"))
        }
        other => RestoreError::Retryable(format!("{stage}: {other}")),
    }
}

/// The bridge refused the import. A 4xx is definitive — 404 = the mgmt
/// surface not armed, 403 = a bearer skew, 400 = a snapshot it rejects (both
/// processes read the same instance env). A 5xx is not: a write may have
/// half-landed, and a save now would put that half-restored home over the
/// checkpoint.
fn import_refusal(status: u16, body: &serde_json::Value) -> RestoreError {
    let refusal = format!("bridge import HTTP {status}: {body}");
    if transient_status(status) {
        RestoreError::Retryable(refusal)
    } else {
        RestoreError::Fatal(refusal)
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
            wake_since_ms: None,
            tz_offset_minutes: 0,
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

    /// The decision: only a definitive answer concludes a restore. A missing
    /// session, an expired one or a transient failure never does — the stored
    /// object may exist unread, and a save would overwrite it.
    #[test]
    fn only_a_definitive_answer_concludes_a_restore() {
        for definitive in [
            Ok(Restored::Done(
                "restored 12 file(s) from the checkpoint saved at 1759000000".into(),
            )),
            Ok(Restored::Done("no checkpoint stored (first spawn?)".into())),
            Ok(Restored::Done(
                "skipped as stale (a fresher import already applied)".into(),
            )),
            Err(RestoreError::Fatal(
                "checkpoint version 2 unsupported".into(),
            )),
        ] {
            let state = decide(definitive);
            assert!(state.saves() && !state.retries(), "{state:?}");
        }
        for not_yet in [
            Err(RestoreError::NoSession),
            Err(RestoreError::SessionExpired),
            Err(RestoreError::Retryable(
                "memory-get: backend HTTP error (502): s3_get".into(),
            )),
        ] {
            let state = decide(not_yet);
            assert!(!state.saves() && state.retries(), "{state:?}");
        }
        let held = decide(Ok(Restored::Held));
        assert_eq!(held, RestoreState::Held);
        assert!(
            !held.saves() && !held.retries(),
            "kept: never saved over, never retried"
        );
    }

    /// The 2026-09-28 shape: no session for the whole boot window. The loop's
    /// order per tick — retry while pending, save once concluded — writes
    /// nothing until a later tick's restore lands.
    #[test]
    fn a_timed_out_restore_saves_only_after_a_later_tick_concludes_it() {
        let mut attempts = vec![
            Err(RestoreError::NoSession),
            Err(RestoreError::Retryable(
                "cap-mint: backend transport error: timed out".into(),
            )),
            Ok(Restored::Done(
                "restored 12 file(s) from the checkpoint saved at 1759000000".into(),
            )),
        ]
        .into_iter();
        let mut home = RestoreState::Pending("not attempted yet".into());
        let mut saved_on_tick = Vec::new();
        for tick in 0..5 {
            if home.retries() {
                home = decide(attempts.next().expect("one attempt per pending tick"));
            }
            if home.saves() {
                saved_on_tick.push(tick);
            }
        }
        assert_eq!(saved_on_tick, vec![2, 3, 4]);
        assert!(
            attempts.next().is_none(),
            "a concluded restore is never retried"
        );
    }

    #[test]
    fn a_server_error_or_throttle_never_concludes_a_restore() {
        let http = |status: u16| BackendError::Http {
            status,
            body: "{}".into(),
        };
        for status in [500, 502, 503, 504, 408, 429] {
            assert!(
                matches!(
                    classify_restore(http(status), "memory-get"),
                    RestoreError::Retryable(_)
                ),
                "worker {status}"
            );
            assert!(
                matches!(
                    import_refusal(status, &serde_json::Value::Null),
                    RestoreError::Retryable(_)
                ),
                "bridge {status}: a write may have half-landed"
            );
        }
        assert!(matches!(
            classify_restore(BackendError::Transport("timed out".into()), "cap-mint"),
            RestoreError::Retryable(_)
        ));
        assert!(matches!(
            classify_restore(http(401), "cap-mint"),
            RestoreError::SessionExpired
        ));
        for status in [400, 403] {
            assert!(
                matches!(
                    classify_restore(http(status), "cap-mint"),
                    RestoreError::Fatal(_)
                ),
                "worker {status}"
            );
        }
        for status in [400, 403, 404, 413] {
            assert!(
                matches!(
                    import_refusal(status, &serde_json::Value::Null),
                    RestoreError::Fatal(_)
                ),
                "bridge {status}"
            );
        }
    }

    #[test]
    fn the_console_sees_every_restore_that_has_not_concluded() {
        let done = RestoreState::Concluded("restored".into());
        assert_eq!(restore_note(&done, &done, false), None);
        assert_eq!(concluded_summary(&done, &done), "restored; restored");

        let no_session = RestoreState::Pending("no delegate session".into());
        let note = restore_note(&no_session, &done, false).expect("pending → note");
        assert_eq!(
            note,
            "checkpoint restore pending (no delegate session) — saves paused"
        );
        assert_eq!(concluded_summary(&no_session, &done), "restored");

        let note = restore_note(&done, &RestoreState::Held, false).expect("held → note");
        assert!(note.starts_with("engine workspace restore held"), "{note}");

        assert_eq!(
            restore_note(&done, &no_session, true).as_deref(),
            Some(
                "engine workspace restore pending (no delegate session) — the engine waits \
                 for it, saves paused"
            ),
            "a held engine says why it is down"
        );

        let long = RestoreState::Pending(format!("memory-get: {}", "x".repeat(400)));
        let note = restore_note(&long, &no_session, false).expect("both pending");
        assert!(
            note.contains("checkpoint restore pending (memory-get: "),
            "{note}"
        );
        assert!(
            note.contains("…) — saves paused; engine workspace restore pending"),
            "{note}"
        );
        assert!(note.chars().count() < 250, "one console line: {note}");
    }

    /// A populated workspace WITHOUT the marker is not a conclusion: the engine
    /// starts on its own after its bounded wait, so only a stored-object read
    /// can settle it. The marker (touched only by a conclusion) can.
    #[test]
    fn a_workspace_settles_locally_only_without_an_engine_or_after_a_conclusion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ws = dir.path().join("workspace");
        let marker = dir.path().join(".workspace-restored");
        assert_eq!(
            workspace_settled_locally(None, &marker).as_deref(),
            Some("no engine workspace on this box")
        );
        assert_eq!(workspace_settled_locally(Some(&ws), &marker), None);
        std::fs::create_dir_all(&ws).expect("mkdir");
        std::fs::write(ws.join("vectordb.bin"), b"a fresh engine's index").expect("write");
        assert_eq!(
            workspace_settled_locally(Some(&ws), &marker),
            None,
            "the engine may have started on its own — read the stored object first"
        );
        touch_marker(&marker);
        assert!(
            workspace_settled_locally(Some(&ws), &marker).is_some(),
            "a restarted daemon finds its own conclusion"
        );
    }

    /// #694 — the manifest snapshot moves only when the manifest's CONTENT
    /// changed: a copy every tick stamped a fresh mtime, the fingerprint called
    /// it a change, and an unchanged workspace was re-uploaded every tick.
    #[test]
    fn the_manifest_snapshot_moves_only_when_the_manifest_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).expect("mkdir");
        std::fs::write(ws.join("vectordb.bin"), b"index").expect("write");
        let manifest = dir.path().join("ov-ingested.txt");
        let snap = ws.join(MANIFEST_SNAPSHOT);
        snapshot_manifest(&manifest, &ws);
        assert!(!snap.exists(), "no manifest yet, no snapshot");
        std::fs::write(&manifest, "household\tfood-preferences\tabcd\n").expect("write");
        snapshot_manifest(&manifest, &ws);
        assert_eq!(
            std::fs::read_to_string(&snap).expect("snapshot"),
            "household\tfood-preferences\tabcd\n"
        );
        let pinned = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        std::fs::File::options()
            .write(true)
            .open(&snap)
            .and_then(|f| f.set_modified(pinned))
            .expect("pin mtime");
        let fp = dir_fingerprint(&ws);
        snapshot_manifest(&manifest, &ws);
        assert_eq!(
            std::fs::metadata(&snap).and_then(|m| m.modified()).ok(),
            Some(pinned),
            "an unchanged manifest leaves the snapshot alone"
        );
        assert_eq!(dir_fingerprint(&ws), fp);
        std::fs::write(&manifest, "household\tfood-preferences\tef01\n").expect("write");
        snapshot_manifest(&manifest, &ws);
        assert!(std::fs::read_to_string(&snap)
            .expect("snapshot")
            .ends_with("ef01\n"));
        assert_ne!(dir_fingerprint(&ws), fp);
    }

    /// #694 — the engine hold: one name shared with the start script, declared
    /// only while the restore would unpack into an empty workspace, and a stale
    /// hold file (a crashed run's) cleared otherwise.
    #[test]
    fn the_engine_is_held_only_while_its_restore_would_unpack_into_an_empty_workspace() {
        assert_eq!(
            pending_marker(std::path::Path::new(
                "/opt/agentkeys/openviking/.workspace-restored"
            )),
            std::path::PathBuf::from("/opt/agentkeys/openviking/.workspace-restored.pending"),
            "the start script's \"${{AGENTKEYS_OV_RESTORE_MARKER}}.pending\""
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let ws = dir.path().join("workspace");
        let marker = dir.path().join(".workspace-restored");
        let pending = pending_marker(&marker);
        let (ws_env, marker_env) = (
            ws.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        );
        let pairs = [
            ("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x"),
            ("OPENVIKING_WORKSPACE", ws_env.as_str()),
            ("AGENTKEYS_OV_RESTORE_MARKER", marker_env.as_str()),
        ];
        let mut cfg =
            CheckpointConfig::from_lookup(&lookup(&pairs), chat("opchat-chef")).expect("cfg");
        assert_eq!(cfg.engine_hold_max, Duration::from_secs(1800));
        assert!(cfg.engine_held_since.is_none());

        cfg.hold_engine_now();
        assert!(
            cfg.engine_held_since.is_some(),
            "no workspace yet, no marker → held"
        );
        assert!(pending.is_file());
        cfg.release_engine_now();
        assert!(!pending.exists(), "a chat loop that cannot start lets go");

        assert!(hold_engine(&cfg), "no workspace yet, no marker → held");
        assert!(pending.is_file());

        std::fs::create_dir_all(&ws).expect("mkdir");
        std::fs::write(ws.join("vectordb.bin"), b"a live engine").expect("write");
        assert!(
            !hold_engine(&cfg),
            "a populated workspace is never unpacked over"
        );
        assert!(!pending.exists(), "the stale hold is cleared");

        std::fs::remove_file(ws.join("vectordb.bin")).expect("rm");
        touch_marker(&marker);
        std::fs::write(&pending, b"a crashed run's").expect("write");
        assert!(!hold_engine(&cfg), "a concluded restore holds nothing");
        assert!(!pending.exists());

        std::fs::remove_file(&marker).expect("rm");
        let off = [
            ("AGENTKEYS_SANDBOX_MGMT_TOKEN", "smt1_x"),
            ("OPENVIKING_WORKSPACE", ws_env.as_str()),
            ("AGENTKEYS_OV_RESTORE_MARKER", marker_env.as_str()),
            ("AGENTKEYS_OV_RESTORE_PENDING_MAX_SECS", "0"),
        ];
        let cfg = CheckpointConfig::from_lookup(&lookup(&off), chat("opchat-chef")).expect("cfg");
        assert!(!hold_engine(&cfg), "0 turns the hold off");
        assert!(!pending.exists());
    }

    #[test]
    fn a_held_engine_is_let_go_once_its_restore_leaves_pending_or_the_bound_passes() {
        let max = Duration::from_secs(1800);
        let pending = RestoreState::Pending("no delegate session".into());
        assert!(engine_stays_held(&pending, Duration::from_secs(1799), max));
        assert!(
            !engine_stays_held(&pending, max, max),
            "the start script stops waiting at the same bound"
        );
        assert!(!engine_stays_held(
            &RestoreState::Concluded("engine workspace restored (10 bytes)".into()),
            Duration::ZERO,
            max
        ));
        assert!(!engine_stays_held(&RestoreState::Held, Duration::ZERO, max));

        let interval = Duration::from_secs(900);
        assert_eq!(
            next_tick_delay(true, true, interval),
            Duration::from_secs(ENGINE_HOLD_RETRY_SECS),
            "the engine waits on every attempt"
        );
        assert_eq!(
            next_tick_delay(true, false, interval),
            Duration::from_secs(ENGINE_HOLD_RETRY_SECS)
        );
        assert_eq!(
            next_tick_delay(false, true, interval),
            Duration::from_secs(FIRST_TICK_DELAY_SECS)
        );
        assert_eq!(next_tick_delay(false, false, interval), interval);
    }

    /// A late restore lands whole or not at all: a failed extract leaves the
    /// workspace as it was (retryable, never half-restored — the engine would
    /// start on it), and a workspace that filled meanwhile is never replaced.
    #[tokio::test]
    async fn a_workspace_unpack_swaps_in_whole_or_not_at_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stored = dir.path().join("stored");
        std::fs::create_dir_all(stored.join("memories")).expect("mkdir");
        std::fs::write(stored.join("memories/diary.md"), b"hotpot on Jinli").expect("write");
        let archive = tar_gz(&stored).await.expect("tar");
        let ws = dir.path().join("workspace");
        let staging = dir.path().join("workspace.restoring");

        assert!(unpack_workspace(&ws, b"not a gzip").await.is_err());
        assert!(
            !dir_has_entries(&ws),
            "a failed extract leaves nothing behind"
        );
        assert!(!staging.exists());

        std::fs::create_dir_all(&ws).expect("mkdir");
        assert_eq!(unpack_workspace(&ws, &archive).await, Ok(true));
        assert_eq!(
            std::fs::read(ws.join("memories/diary.md")).expect("restored"),
            b"hotpot on Jinli"
        );
        assert!(!staging.exists());

        assert_eq!(
            unpack_workspace(&ws, &archive).await,
            Ok(false),
            "a populated workspace is never replaced"
        );
    }
}
