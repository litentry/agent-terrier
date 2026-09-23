//! #566 — the delegate-side DISTRIBUTION MIRROR (arch §17.6 `context flows`,
//! plan `docs/plan/issue-566-openviking-native-memory-provider.md`).
//!
//! The delegate runtime consumes OpenViking as its first-class native memory provider
//! (`memory.provider: openviking`, in-sandbox engine on :1933). The AgentKeys
//! bound is enforced at INGEST-time: this mirror is the only writer of
//! canonical-derived content into the engine, and it can only write what
//! `canonical-get` returns — the memory worker re-verifies the cap + namespace
//! on every fetch, so the engine's corpus is always ⊆ (the delegate's own
//! working memory ∪ gate-authorized canonical slices).
//!
//! Namespace discovery is PROBE-based (no broker involvement, D2-stateless):
//! each pass attempts `canonical-get` for every candidate namespace; the
//! worker's verdict is the authz truth —
//!   200  -> reconcile the namespace onto the returned lines,
//!   403  -> the grant is absent/revoked -> reconcile onto EMPTY
//!           (delete-through: mirrored content leaves the index this pass),
//!   401  -> the delegate session expired -> re-resolve and retry next pass,
//!   else -> transient -> leave the index untouched (durable truth is never
//!           here; a fresh sandbox rebuilds from canonical).
//!
//! Never load-bearing: engine down ⇒ log-once + retry next interval; the agent
//! falls back to its built-in memory and chat is unaffected.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agentkeys_backend_client::protocol::{
    service_knowledge, CapMintOp, CapMintRequest, LifecycleStage, MemoryGetInput,
};
use agentkeys_backend_client::{normalize_omni_0x, BackendClient, BackendError};
use agentkeys_memory_openviking::{
    ingest_manifest_from_env, MirrorItem, OpenVikingClient, ReconcileStats, DEFAULT_ENDPOINT,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::chat_loop::{ChatLoopConfig, DelegateCredential};
use crate::lifecycle::LifecycleHub;

/// The #108 v0 namespace defaults — the candidate set the mirror probes when
/// `AGENTKEYS_MEMORY_NAMESPACES` is not injected. Probing an ungranted
/// namespace is cheap and safe: the worker answers 403 and the mirror treats
/// it as "nothing authorized here".
pub const DEFAULT_NAMESPACES: &str = "personal,family,work,travel";

/// Default bound for the first pass's engine wait (see
/// [`MirrorConfig::first_pass_engine_wait`]).
pub const DEFAULT_FIRST_PASS_ENGINE_WAIT_SECS: u64 = 90;

/// Whether an unanswered engine `/health` should be waited out rather than
/// judged: only on the first pass, and only within the bound.
pub(crate) fn first_pass_waits_for_engine(
    first_pass: bool,
    waited: Duration,
    bound: Duration,
) -> bool {
    first_pass && waited < bound
}

#[cfg(test)]
#[test]
fn default_namespaces_match_the_protocol_owner() {
    // #666 — ONE owner (agentkeys-protocol::DEFAULT_MIRROR_NAMESPACES); the
    // broker composes an app install's `AGENTKEYS_MEMORY_NAMESPACES` from the
    // same list, so the two can never disagree.
    assert_eq!(
        DEFAULT_NAMESPACES,
        agentkeys_backend_client::protocol::DEFAULT_MIRROR_NAMESPACES.join(",")
    );
}

#[derive(Clone)]
pub struct MirrorConfig {
    /// The engine base URL, captured at construction — logged, never re-read
    /// from env (the client already holds the value it actually dials).
    pub engine_endpoint: String,
    pub chat: ChatLoopConfig,
    pub memory_worker_url: String,
    pub namespaces: Vec<String>,
    pub interval: Duration,
    /// How long the FIRST pass waits for the engine's `/health` before judging
    /// it (`AGENTKEYS_MEMORY_MIRROR_ENGINE_WAIT_SECS`, default 90, 0..=600).
    /// The engine boots after the daemon (supervisord priority), so a first
    /// pass that judged it before it listened stamped `degraded` for a whole
    /// interval — measured 2026-09-18: 12 s after boot, `ready` 5 min later.
    pub first_pass_engine_wait: Duration,
    pub engine: OpenVikingClient,
    pub manifest: std::path::PathBuf,
    /// #694 — namespaces of one pass reconcile concurrently, this many at a time
    /// (`AGENTKEYS_MIRROR_FANOUT`, default 4, 1..=16).
    pub fanout: usize,
    /// #693 — the lifecycle hub (stage + "sync now"); `None` for the one-shot.
    pub hub: Option<Arc<LifecycleHub>>,
}

/// One namespace's outcome in a pass, with how long it took.
pub struct NamespaceReport {
    pub ns: String,
    pub outcome: NamespaceOutcome,
    pub ms: u64,
}

impl MirrorConfig {
    /// Build from the chat env + the `OPENVIKING_*`/`AGENTKEYS_MEMORY_*` env.
    /// `None` = mirror disabled: the kill switch is set, or the memory worker
    /// URL cannot be derived from the broker host.
    pub fn from_chat_env(chat: ChatLoopConfig) -> Option<Self> {
        let read = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        if read("AGENTKEYS_MEMORY_MIRROR").as_deref() == Some("0") {
            tracing::info!("#566 memory mirror: disabled via AGENTKEYS_MEMORY_MIRROR=0");
            return None;
        }
        // Override → else derive `memory.<zone>` from the broker host (the
        // derive_worker_url convention — never a pre-composed host env).
        let memory_worker_url = match read("AGENTKEYS_WORKER_MEMORY_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .or_else(|| crate::ui_bridge::derive_worker_url(&chat.broker_url, "memory"))
        {
            Some(u) => u,
            None => {
                tracing::warn!(
                    broker = %chat.broker_url,
                    "#566 memory mirror: cannot derive the memory worker URL — mirror disabled"
                );
                return None;
            }
        };
        let namespaces: Vec<String> = read("AGENTKEYS_MEMORY_NAMESPACES")
            .unwrap_or_else(|| DEFAULT_NAMESPACES.to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if namespaces.is_empty() {
            tracing::info!("#566 memory mirror: empty namespace set — mirror disabled");
            return None;
        }
        let interval = read("AGENTKEYS_MEMORY_MIRROR_INTERVAL_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| (30..=3600).contains(&s))
            .unwrap_or(300);
        let first_pass_engine_wait = read("AGENTKEYS_MEMORY_MIRROR_ENGINE_WAIT_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s <= 600)
            .unwrap_or(DEFAULT_FIRST_PASS_ENGINE_WAIT_SECS);
        // In-sandbox the engine is co-located; the env identity defaults match
        // the engine tree's historical coordinates (`default`/`default`/`hermes`,
        // the hermes-era plugin default — kept for tree continuity, override via
        // OPENVIKING_AGENT) so the mirror's
        // `viking://user/<user>/…` URIs live in the tree `viking_search`
        // queries. Tenancy is structural — one engine per sandbox (§17.6).
        let engine_endpoint =
            read("OPENVIKING_ENDPOINT").unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let engine = OpenVikingClient::new(
            engine_endpoint.clone(),
            read("OPENVIKING_API_KEY").unwrap_or_default(),
            read("OPENVIKING_ACCOUNT").unwrap_or_else(|| "default".to_string()),
            read("OPENVIKING_USER").unwrap_or_else(|| "default".to_string()),
            read("OPENVIKING_AGENT").unwrap_or_else(|| "hermes".to_string()),
        );
        let fanout = read("AGENTKEYS_MIRROR_FANOUT")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| (1..=16).contains(&n))
            .unwrap_or(4);
        Some(Self {
            engine_endpoint,
            chat,
            memory_worker_url,
            namespaces,
            interval: Duration::from_secs(interval),
            first_pass_engine_wait: Duration::from_secs(first_pass_engine_wait),
            engine,
            manifest: ingest_manifest_from_env(),
            fanout,
            hub: None,
        })
    }
}

/// Per-namespace outcome of one mirror pass.
#[derive(Debug)]
pub enum NamespaceOutcome {
    /// Authorized: reconciled onto the returned lines.
    Reconciled(ReconcileStats),
    /// The backend refused the namespace (no/revoked grant): reconciled onto
    /// empty — mirrored content delete-throughed. `denied_at` names the
    /// refusing stage (`cap-mint` vs `canonical-get`) and `detail` carries the
    /// refusal body — a denial without its reason is undebuggable (learned in
    /// the first CI run of suite-7).
    Denied {
        stats: ReconcileStats,
        denied_at: &'static str,
        detail: String,
    },
    /// The canonical blob no longer exists (404) — reconciled onto empty, same
    /// delete-through as a revocation.
    Absent(ReconcileStats),
    /// Session expired (401) — re-resolve, namespace retried next pass.
    SessionExpired,
    /// Transient fetch failure — index untouched.
    FetchError(String),
}

/// One full pass over every candidate namespace. Public for the
/// `--memory-mirror-once` daemon flag and the e2e harness.
/// One pass over every candidate namespace — concurrently, `fanout` at a time
/// (#694), each timed (#693). Reports come back in the configured order.
pub async fn mirror_once(
    cfg: &MirrorConfig,
    credential: &Arc<DelegateCredential>,
    bearer: &str,
) -> Vec<NamespaceReport> {
    let cfg = Arc::new(cfg.clone());
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.fanout.max(1)));
    let total = cfg.namespaces.len() as u32;
    let mut set: tokio::task::JoinSet<(usize, NamespaceReport)> = tokio::task::JoinSet::new();
    for (i, ns) in cfg.namespaces.iter().cloned().enumerate() {
        let (cfg, credential, bearer, sem) = (
            cfg.clone(),
            credential.clone(),
            bearer.to_string(),
            sem.clone(),
        );
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let started = Instant::now();
            let outcome = mirror_namespace(&cfg, &credential, &bearer, &ns).await;
            (
                i,
                NamespaceReport {
                    ns,
                    outcome,
                    ms: started.elapsed().as_millis() as u64,
                },
            )
        });
    }
    let mut out: Vec<(usize, NamespaceReport)> = Vec::with_capacity(total as usize);
    let mut done = 0u32;
    while let Some(res) = set.join_next().await {
        match res {
            Ok(r) => {
                done += 1;
                if let Some(hub) = &cfg.hub {
                    if hub.first_pass_pending() {
                        let mut ev = hub.current();
                        ev.stage = LifecycleStage::Syncing;
                        ev.detail = format!("{done} of {total} namespaces");
                        ev.done = done;
                        ev.total = total;
                        ev.ts_millis = 0;
                        hub.set(ev);
                    }
                }
                out.push(r);
            }
            Err(e) => tracing::warn!(error = %e, "#566 memory mirror: namespace task failed"),
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

async fn mirror_namespace(
    cfg: &MirrorConfig,
    credential: &DelegateCredential,
    bearer: &str,
    ns: &str,
) -> NamespaceOutcome {
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
    let dkh = credential.device_key_hash();
    match fetch_canonical(&client, cfg, ns, &dkh, bearer).await {
        Ok(content) => {
            let items = mirror_units(&content);
            NamespaceOutcome::Reconciled(
                cfg.engine.reconcile_items(ns, &items, &cfg.manifest).await,
            )
        }
        Err((stage, BackendError::Http { status: 403, body })) => NamespaceOutcome::Denied {
            stats: cfg.engine.reconcile_items(ns, &[], &cfg.manifest).await,
            denied_at: stage,
            detail: truncate(&body, 300),
        },
        // 404 = the canonical blob is GONE (master deleted the namespace).
        // Treat it like a revocation: the engine mirrors canonical, so
        // content whose source no longer exists must not linger until the
        // next respawn. Distinct label keeps "not authorized" (403)
        // diagnosable from "no longer exists" (404).
        Err((_, BackendError::Http { status: 404, .. })) => {
            NamespaceOutcome::Absent(cfg.engine.reconcile_items(ns, &[], &cfg.manifest).await)
        }
        Err((_, BackendError::Http { status: 401, .. })) => NamespaceOutcome::SessionExpired,
        Err((stage, e)) => NamespaceOutcome::FetchError(format!("{stage}: {e}")),
    }
}

/// The counts a pass adds up to (the lifecycle report + the audit row).
pub struct PassSummary {
    pub namespaces: u32,
    pub mirrored: u64,
    pub deleted: u64,
    pub errors: Vec<String>,
    pub session_expired: bool,
}

pub fn summarize(reports: &[NamespaceReport]) -> PassSummary {
    let mut s = PassSummary {
        namespaces: reports.len() as u32,
        mirrored: 0,
        deleted: 0,
        errors: Vec::new(),
        session_expired: false,
    };
    for r in reports {
        match &r.outcome {
            NamespaceOutcome::Reconciled(st) => {
                s.mirrored += st.mirrored as u64;
                s.deleted += st.deleted as u64;
                if st.write_failed > 0 || st.delete_failed > 0 {
                    s.errors.push(format!(
                        "engine {}: {} write(s) / {} delete(s) failed{}",
                        r.ns,
                        st.write_failed,
                        st.delete_failed,
                        st.first_error
                            .as_deref()
                            .map(|e| format!(" — first: {e}"))
                            .unwrap_or_default()
                    ));
                }
            }
            NamespaceOutcome::Denied { stats, .. } | NamespaceOutcome::Absent(stats) => {
                s.deleted += stats.deleted as u64;
            }
            NamespaceOutcome::SessionExpired => s.session_expired = true,
            NamespaceOutcome::FetchError(e) => s.errors.push(format!("fetch {}: {e}", r.ns)),
        }
    }
    s
}

/// #693 — the ONE durable row per pass (op_kind 105), on the delegate's own
/// authority, best effort: a missing audit plane is a warn, never a stall.
pub async fn audit_pass(
    cfg: &MirrorConfig,
    reports: &[NamespaceReport],
    pass_ms: u64,
    boot: bool,
) -> Result<(), String> {
    let s = summarize(reports);
    let stage = if s.errors.is_empty() {
        "ready"
    } else {
        "degraded"
    };
    let body = agentkeys_core::audit::DelegateLifecycleBody {
        stage: stage.to_string(),
        namespaces: s.namespaces,
        mirrored: s.mirrored,
        deleted: s.deleted,
        ms: pass_ms,
        boot,
        errors: s.errors.len() as u32,
        first_error: s.errors.first().cloned().unwrap_or_default(),
    };
    let result = if s.errors.is_empty() {
        agentkeys_core::audit::AuditResult::Success as u8
    } else {
        agentkeys_core::audit::AuditResult::Failure as u8
    };
    let _ = cfg; // the self backend re-reads the same chat env contract
    let backend = crate::self_backend::acquire().await?;
    backend
        .audit_append(
            agentkeys_core::audit::AuditOpKind::DelegateLifecycle as u8,
            serde_json::to_value(body).map_err(|e| e.to_string())?,
            result,
            None,
        )
        .await
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Errors carry the STAGE that produced them — a bare 403 is ambiguous between
/// the broker's cap-mint (session/device/scope) and the worker's independent
/// re-verify, and the two have different fixes.
async fn fetch_canonical(
    client: &BackendClient,
    cfg: &MirrorConfig,
    namespace: &str,
    device_key_hash: &str,
    bearer: &str,
) -> Result<String, (&'static str, BackendError)> {
    // The cap `service` AND the worker `namespace` are the FULL `knowledge:<ns>`
    // wire id (the on-chain grant hashes that string — the protocol
    // `service_knowledge` builder is the one composition site). A bare namespace
    // 403s at cap-mint with `service_not_in_scope` (the first CI runs of
    // suite-7); the delegation demo passes the full id for both fields.
    let service = service_knowledge(namespace);
    let cap = client
        .cap_mint(
            CapMintOp::MemoryCanonicalGet,
            CapMintRequest {
                operator_omni: normalize_omni_0x(&cfg.chat.operator_omni),
                actor_omni: normalize_omni_0x(&cfg.chat.actor_omni),
                service: service.clone(),
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            bearer,
        )
        .await
        .map_err(|e| ("cap-mint", e))?;
    let got = client
        .memory_canonical_get(MemoryGetInput {
            cap,
            namespace: service,
            object_key: None,
        })
        .await
        .map_err(|e| ("canonical-get", e))?;
    let bytes = STANDARD.decode(&got.plaintext_b64).map_err(|e| {
        (
            "decode",
            BackendError::Parse(format!("memory plaintext_b64: {e}")),
        )
    })?;
    String::from_utf8(bytes)
        .map_err(|e| ("decode", BackendError::Parse(format!("memory utf8: {e}"))))
}

/// Split a canonical blob into the ITEMS the engine should hold — ONE resource
/// directory per knowledge entry (`viking://resources/<ns>/<key>/`, the L0/L1
/// sidecars from the entry's title and preview, the body as L2).
///
/// Canonical namespaces are #201 JSON ARRAYS of `ApiMemoryEntry`-shaped objects
/// (`agentkeys_protocol::web_api::ApiMemoryEntry` is the producer/owner type;
/// read permissively here by its canonical field names, because harness and
/// pre-#201 blobs carry only a subset of them). Line-splitting such a blob —
/// what this did long ago — mirrored the pretty-printed JSON's individual
/// lines as if each were a memory, so the engine filled up with fragments
/// like `}` and `"bytes": 51` (caught by suite-7 step 7 reading back
/// `"bytes": 51`).
///
/// A plain-TEXT blob keeps a line-per-item fallback (keyed `line-<n>`), and an
/// array we cannot interpret falls back to it too — never fail closed on an
/// unexpected shape, the durable truth is elsewhere.
fn mirror_units(blob: &str) -> Vec<MirrorItem> {
    if let Ok(serde_json::Value::Array(entries)) = serde_json::from_str::<serde_json::Value>(blob) {
        let mut out: Vec<MirrorItem> = Vec::new();
        for entry in &entries {
            match entry {
                serde_json::Value::String(text) if !text.trim().is_empty() => {
                    out.push(MirrorItem {
                        key: format!("item-{}", out.len()),
                        title: String::new(),
                        preview: String::new(),
                        body: text.trim().to_string(),
                    });
                }
                serde_json::Value::Object(obj) => {
                    let field = |k: &str| {
                        obj.get(k)
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    };
                    // The sealed context document (the anchor) lives in the
                    // app's own namespace as `kind: context` — runtime facts
                    // for the daemon, never a knowledge item for the engine.
                    if field("kind") == "context" {
                        continue;
                    }
                    let body = field("body");
                    let preview = field("preview");
                    if body.is_empty() && preview.is_empty() {
                        continue; // nothing searchable in this entry
                    }
                    let key = match field("key") {
                        k if !k.is_empty() => k,
                        _ => format!("item-{}", out.len()),
                    };
                    out.push(MirrorItem {
                        key,
                        title: field("title"),
                        preview,
                        body,
                    });
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    blob.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
        .map(|(seq, line)| MirrorItem {
            key: format!("line-{seq}"),
            title: String::new(),
            preview: String::new(),
            body: line.to_string(),
        })
        .collect()
}

/// Machine-readable report for `--memory-mirror-once` (and the e2e steps that
/// assert on it): per-namespace outcome + `ms` (#693), the pass wall time, and
/// whether the lifecycle audit row landed.
pub fn report_json(
    reports: &[NamespaceReport],
    pass_ms: u64,
    audit: Option<Result<(), String>>,
) -> serde_json::Value {
    let namespaces: Vec<serde_json::Value> = reports
        .iter()
        .map(|r| {
            let ns = &r.ns;
            let mut v = match &r.outcome {
                NamespaceOutcome::Reconciled(s) => serde_json::json!({
                    "namespace": ns, "outcome": "reconciled",
                    "mirrored": s.mirrored, "deleted": s.deleted,
                    "write_failed": s.write_failed, "delete_failed": s.delete_failed,
                }),
                NamespaceOutcome::Denied {
                    stats,
                    denied_at,
                    detail,
                } => serde_json::json!({
                    "namespace": ns, "outcome": "denied",
                    "denied_at": denied_at, "detail": detail,
                    "deleted": stats.deleted, "delete_failed": stats.delete_failed,
                }),
                NamespaceOutcome::Absent(s) => serde_json::json!({
                    "namespace": ns, "outcome": "absent",
                    "deleted": s.deleted, "delete_failed": s.delete_failed,
                }),
                NamespaceOutcome::SessionExpired => serde_json::json!({
                    "namespace": ns, "outcome": "session_expired",
                }),
                NamespaceOutcome::FetchError(e) => serde_json::json!({
                    "namespace": ns, "outcome": "fetch_error", "error": e,
                }),
            };
            v["ms"] = serde_json::json!(r.ms);
            v
        })
        .collect();
    let summary = summarize(reports);
    serde_json::json!({
        "namespaces": namespaces,
        "pass_ms": pass_ms,
        "mirrored": summary.mirrored,
        "deleted": summary.deleted,
        "errors": summary.errors,
        "audit": audit.map(|a| match a {
            Ok(()) => serde_json::json!({ "appended": true }),
            Err(e) => serde_json::json!({ "appended": false, "error": e }),
        }),
    })
}

pub fn spawn(cfg: MirrorConfig, credential: Arc<DelegateCredential>) {
    tokio::spawn(async move {
        run_loop(cfg, credential).await;
    });
}

async fn run_loop(cfg: MirrorConfig, credential: Arc<DelegateCredential>) {
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "#566 memory mirror: http client build failed");
            return;
        }
    };
    tracing::info!(
        namespaces = %cfg.namespaces.join(","),
        interval_secs = cfg.interval.as_secs(),
        engine = %cfg.engine_endpoint,
        "#566 memory mirror: starting (ingest-time gate bound)"
    );
    let mut session: Option<String> = None;
    let mut engine_down_logged = false;
    let mut first_pass = true;
    let first_pass_started = Instant::now();
    loop {
        if !cfg.engine.health().await {
            // #694 — the engine waits for the workspace restore before its first
            // start; while that phase runs, an unanswered /health is expected.
            if cfg.hub.as_ref().is_some_and(|h| h.restore_pending()) {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            // The engine starts after this daemon (supervisord priority): give
            // its first `/health` a bounded wait before judging it, so the
            // first report is `ready`, not a `degraded` that stands for a
            // whole interval.
            if first_pass_waits_for_engine(
                first_pass,
                first_pass_started.elapsed(),
                cfg.first_pass_engine_wait,
            ) {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            if !engine_down_logged {
                tracing::info!(
                    "#566 memory mirror: engine unreachable — idle until it answers /health \
                     (the agent falls back to built-in memory; chat unaffected)"
                );
                engine_down_logged = true;
            }
            if let Some(h) = &cfg.hub {
                h.pass_finished(cfg.namespaces.len() as u32, 0, 0, 0, Vec::new(), true);
            }
            wait_interval_or_sync(&cfg).await;
            continue;
        }
        engine_down_logged = false;
        if session.is_none() {
            match crate::chat_loop::resolve_session(&http, &cfg.chat, &credential).await {
                Ok(jwt) => {
                    credential.on_new_session(&jwt).await;
                    session = Some(jwt);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "#566 memory mirror: resolve failed — retrying");
                    tokio::time::sleep(cfg.interval).await;
                    continue;
                }
            }
        }
        let bearer = session.clone().unwrap_or_default();
        if let Some(h) = &cfg.hub {
            if !first_pass {
                h.stage(LifecycleStage::Pulling, "periodic pull");
            }
        }
        let started = Instant::now();
        let reports = mirror_once(&cfg, &credential, &bearer).await;
        let pass_ms = started.elapsed().as_millis() as u64;
        let mut expired = false;
        for NamespaceReport { ns, outcome, .. } in &reports {
            match outcome {
                NamespaceOutcome::Reconciled(s) if s.is_noop() => {}
                NamespaceOutcome::Denied { stats, .. } if stats.is_noop() => {}
                NamespaceOutcome::Absent(s) if s.is_noop() => {}
                NamespaceOutcome::Absent(s) => tracing::info!(
                    ns = %ns, deleted = s.deleted, delete_failed = s.delete_failed,
                    "#566 memory mirror: canonical blob absent — delete-throughed"
                ),
                NamespaceOutcome::Reconciled(s) => tracing::info!(
                    ns = %ns, mirrored = s.mirrored, deleted = s.deleted,
                    write_failed = s.write_failed, delete_failed = s.delete_failed,
                    "#566 memory mirror: reconciled"
                ),
                NamespaceOutcome::Denied {
                    stats, denied_at, ..
                } => tracing::info!(
                    ns = %ns, deleted = stats.deleted, delete_failed = stats.delete_failed,
                    denied_at = %denied_at,
                    "#566 memory mirror: namespace not granted — delete-throughed"
                ),
                NamespaceOutcome::SessionExpired => expired = true,
                NamespaceOutcome::FetchError(e) => {
                    tracing::warn!(ns = %ns, error = %e, "#566 memory mirror: fetch failed")
                }
            }
        }
        if expired {
            session = None;
            continue; // re-resolve immediately, no interval wait
        }
        // #693 — the stage the pass ended in + the ONE durable row per pass.
        let summary = summarize(&reports);
        if let Some(h) = &cfg.hub {
            h.pass_finished(
                summary.namespaces,
                summary.mirrored,
                summary.deleted,
                pass_ms,
                summary.errors.clone(),
                false,
            );
        }
        if let Err(e) = audit_pass(&cfg, &reports, pass_ms, first_pass).await {
            tracing::warn!(error = %e, "#693 lifecycle: audit row not appended (best effort)");
        }
        first_pass = false;
        wait_interval_or_sync(&cfg).await;
    }
}

/// The inter-pass wait — cut short by "sync now" (#693).
async fn wait_interval_or_sync(cfg: &MirrorConfig) {
    match &cfg.hub {
        Some(h) => {
            tokio::select! {
                _ = tokio::time::sleep(cfg.interval) => {}
                _ = h.sync_now.notified() => {
                    tracing::info!("#693 lifecycle: sync now — pulling immediately");
                }
            }
        }
        None => tokio::time::sleep(cfg.interval).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The #201 canonical shape the master plant writes (pretty-printed by jq in
    // the harness, by serde in the daemon — both multi-line).
    const CANONICAL: &str = r#"[
  {
    "key": "ci-wire-proof",
    "title": "ci-wire-proof",
    "body": "mirror-proof: pandas at Dujiangyan; hotpot on Jinli",
    "updated": "2026-07-24",
    "bytes": 51
  }
]"#;

    #[test]
    fn json_array_mirrors_one_item_per_entry_not_per_line() {
        let units = mirror_units(CANONICAL);
        assert_eq!(
            units.len(),
            1,
            "one resource directory per ENTRY, not per JSON line"
        );
        assert_eq!(units[0].key, "ci-wire-proof");
        assert_eq!(units[0].title, "ci-wire-proof");
        assert!(units[0].body.contains("mirror-proof: pandas at Dujiangyan"));
        // the regression: JSON fragments must never become items
        for junk in ["\"bytes\": 51", "}", "]"] {
            assert!(
                !units.iter().any(|u| u.body.trim() == junk),
                "fragment {junk:?} leaked into the engine"
            );
        }
    }

    #[test]
    fn multi_entry_array_yields_one_item_each_keyed_by_the_entry() {
        let blob = r#"[{"key":"a","body":"first fact"},{"key":"b","body":"second fact"}]"#;
        let units = mirror_units(blob);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].key, "a");
        assert_eq!(units[1].key, "b");
        assert!(units[1].body.contains("second fact"));
    }

    #[test]
    fn entry_carries_its_preview_and_a_bodyless_previewless_entry_is_skipped() {
        let blob =
            r#"[{"key":"a","title":"A","preview":"only a preview"},{"key":"b","title":"t"}]"#;
        let units = mirror_units(blob);
        assert_eq!(
            units.len(),
            1,
            "the entry without body or preview contributes nothing"
        );
        assert_eq!(units[0].preview, "only a preview");
        assert_eq!(units[0].title, "A");
        assert!(units[0].body.is_empty());
    }

    #[test]
    fn plain_text_blob_keeps_one_item_per_line() {
        let units = mirror_units("first line\nsecond line\n");
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].body, "first line");
        assert_eq!(units[0].key, "line-0");
        assert_eq!(units[1].key, "line-1");
    }

    #[test]
    fn json_array_of_strings_mirrors_each_string() {
        let units = mirror_units(r#"["alpha","beta"]"#);
        assert_eq!(units.len(), 2);
        assert_eq!(units[1].body, "beta");
        assert_ne!(units[0].key, units[1].key);
    }

    #[test]
    fn uninterpretable_json_falls_back_to_lines() {
        // an array of numbers carries no memory text — line-split, never empty
        let units = mirror_units("[1, 2, 3]");
        assert!(!units.is_empty());
    }

    #[test]
    fn default_namespaces_are_the_108_set() {
        assert_eq!(
            DEFAULT_NAMESPACES.split(',').count(),
            4,
            "personal,family,work,travel"
        );
    }
}

#[cfg(test)]
mod first_pass_engine_wait_tests {
    use super::first_pass_waits_for_engine;
    use std::time::Duration;

    #[test]
    fn the_first_pass_waits_within_the_bound_and_never_after_it() {
        let bound = Duration::from_secs(90);
        assert!(first_pass_waits_for_engine(
            true,
            Duration::from_secs(0),
            bound
        ));
        assert!(first_pass_waits_for_engine(
            true,
            Duration::from_secs(89),
            bound
        ));
        assert!(!first_pass_waits_for_engine(
            true,
            Duration::from_secs(90),
            bound
        ));
        // A later pass judges the engine at once — the interval is the wait.
        assert!(!first_pass_waits_for_engine(
            false,
            Duration::from_secs(0),
            bound
        ));
        // The knob at 0 = the old behaviour.
        assert!(!first_pass_waits_for_engine(
            true,
            Duration::from_secs(0),
            Duration::ZERO
        ));
    }
}

/// The delegate's sealed context document from its OWN namespace on the
/// memory plane (the anchor — entry `context`, `kind: context`), read with
/// its own cap. `Ok(None)` = no such entry yet.
pub(crate) async fn fetch_own_context(
    cfg: &MirrorConfig,
    credential: &DelegateCredential,
    bearer: &str,
    own_ns: &str,
) -> Result<Option<agentkeys_backend_client::protocol::DelegateContextDoc>, String> {
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
    let dkh = credential.device_key_hash();
    let blob = match fetch_canonical(&client, cfg, own_ns, &dkh, bearer).await {
        Ok(b) => b,
        Err((_, BackendError::Http { status: 404, .. })) => return Ok(None),
        Err((stage, e)) => return Err(format!("{stage}: {e}")),
    };
    let key = agentkeys_backend_client::protocol::CONTEXT_ENTRY_KEY;
    let entries: serde_json::Value = serde_json::from_str(&blob).map_err(|e| e.to_string())?;
    let Some(body) = entries
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e.get("key").and_then(|k| k.as_str()) == Some(key))
        .and_then(|e| e.get("body").and_then(|b| b.as_str()))
    else {
        return Ok(None);
    };
    serde_json::from_str(body)
        .map(Some)
        .map_err(|e| format!("context document: {e}"))
}
