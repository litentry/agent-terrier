//! OpenViking engine adapter — plan `docs/plan/agentkeys-memory-design.md` §6a,
//! integration shape `docs/plan/issue-566-openviking-native-memory-provider.md`.
//!
//! OpenViking (`volcengine/OpenViking`) is a self-hosted context database. Since
//! #566 it is the AI runtime's FIRST-CLASS native memory provider (under dsh via
//! the official openviking memory plugin), and AgentKeys' gate bound moved to
//! INGEST-time: this crate's consumer is the daemon's distribution mirror,
//! which may only write what `canonical-get` returned (the memory worker
//! enforces per-namespace authorization on every fetch). AgentKeys still STORES
//! (K3-encrypted S3/TOS) + GATES (cap / scope / namespace / audit); the engine
//! holds a sandbox-local, rebuilt-on-respawn index of the authorized slice plus
//! the agent's own working memory.
//!
//! **Where the mirror files things (2026-09-18).** OpenViking's own vocabulary:
//! `resources/` is "knowledge and rules" (static, user-added), `memories/` is
//! "the agent's cognition" (extracted from its sessions into fixed category
//! folders). The runtime's per-step context recall draws ONLY from those
//! category folders plus resources and skills; the previous layout
//! (`memories/<ns>/mem_<hash>.md`) sat in an unowned folder the recall never
//! searched, so household knowledge was findable by a tool but never
//! auto-recalled (measured on the live image). Every canonical item is now a
//! resource directory:
//!
//!   viking://resources/<ns>/<item>/.abstract.md   L0 — the item's title + preview head (≤256 chars)
//!   viking://resources/<ns>/<item>/.overview.md   L1 — the item's preview (or body head) (≤4000 chars)
//!   viking://resources/<ns>/<item>/<item>.md      L2 — the body
//!
//! The sidecars matter because the sandbox engine runs WITHOUT the summarizing
//! model (`start-openviking.sh`: search/rank only), so nothing generates them —
//! the owner-curated title and preview of the git-style knowledge item are the
//! L0/L1 the recall shows (measured: overview text at detail `overview`, score
//! above the plugin's 0.35 threshold; an empty abstract gives a bare URI below it).
//!
//! Wire contract, verified against a live `openviking-server` 0.4.16:
//!
//!   base    http://127.0.0.1:1933  (OPENVIKING_ENDPOINT)
//!   headers X-OpenViking-Actor-Peer / -Account / -User, plus X-API-Key +
//!           `Authorization: Bearer <key>` when OPENVIKING_API_KEY is set
//!   GET    /health                                    -> 200 when up
//!   POST   /api/v1/content/write {uri, content, mode} -> mode create | replace
//!          (a plain write creates the item directory; an existing sidecar
//!          takes `replace`; the accepted modes are replace/append/create/upsert)
//!   DELETE /api/v1/fs?uri=<dir>&recursive=true        -> remove one item directory
//!   error envelope: HTTP >= 400, or {status:"error", error:{code,message}}
//!
//! The QUERY side is deliberately absent: reading is the AGENT's job through
//! its native provider (the memory plugin's recall + `mcp__openviking__*` tools).
//!
//! SAFETY — the gate bounds visibility at INGEST:
//! [`OpenVikingClient::reconcile_items`] only ever writes gate-authorized items
//! and delete-throughs items the gate no longer returns (revocation self-heals;
//! a fresh sandbox rebuilds from canonical). OpenViking can rank but can never
//! WIDEN visibility, and it is never load-bearing — engine down ⇒ the agent
//! falls back to its built-in memory; the mirror retries next pass.

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:1933";
/// OpenViking's home for knowledge (`viking://resources/`, account-global; the
/// recall's resources bucket searches it alongside the user's own `resources/`).
pub const RESOURCES_ROOT: &str = "viking://resources";
/// OpenViking's own L0 / L1 size defaults (docs: context layers).
pub const ABSTRACT_MAX_CHARS: usize = 256;
pub const OVERVIEW_MAX_CHARS: usize = 4000;
const SEGMENT_MAX_CHARS: usize = 80;
/// How long one item write waits for the engine to materialize a new
/// directory's sidecar placeholders (its semantic queue does that after the
/// body write; the public API refuses to CREATE a sidecar — "cannot create
/// generated semantic sidecar directly" — so `replace` needs the placeholder
/// first). Measured on 0.4.16: the placeholder appears within seconds.
const SIDECAR_WAIT_ATTEMPTS: u32 = 40;
const SIDECAR_WAIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// One canonical knowledge item as the mirror files it: the git-style store's
/// `key` / `title` / `preview` / `body` (the owner curates title + preview on
/// the Knowledge page — they become the recall's L0 / L1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorItem {
    pub key: String,
    pub title: String,
    pub preview: String,
    pub body: String,
}

impl MirrorItem {
    /// The item's directory name under its namespace.
    pub fn segment(&self) -> String {
        path_segment(&self.key)
    }

    /// Content hash over title + preview + body (first 16 hex of SHA-256): a
    /// changed item rewrites its files, an unchanged one costs nothing.
    pub fn content_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.title.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.preview.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.body.as_bytes());
        let digest = hasher.finalize();
        digest[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    fn heading(&self) -> &str {
        let title = self.title.trim();
        if title.is_empty() {
            self.key.trim()
        } else {
            title
        }
    }
}

/// A canonical key as a viking path segment: `[A-Za-z0-9._-]` kept, every other
/// run becomes one `-`; a leading `.` would name a hidden sidecar, so it is
/// trimmed. A key the sanitizer had to change gets a 4-hex tail of the original
/// so two keys can never share a directory; an empty result becomes `item-<hash>`.
pub fn path_segment(key: &str) -> String {
    let key = key.trim();
    let mut out = String::new();
    let mut last_dash = false;
    for c in key.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed: String = out
        .trim_matches(|c| c == '-' || c == '.')
        .chars()
        .take(SEGMENT_MAX_CHARS)
        .collect();
    let tail = short_hash(key);
    if trimmed.is_empty() {
        return format!("item-{tail}");
    }
    if trimmed == key {
        trimmed
    } else {
        format!("{trimmed}-{}", &tail[..4])
    }
}

/// L0: `<title>: <first paragraph of the preview, else of the body>`, ≤256 chars.
pub fn abstract_text(item: &MirrorItem) -> String {
    let source = if item.preview.trim().is_empty() {
        &item.body
    } else {
        &item.preview
    };
    let head = first_paragraph(source);
    let text = if head.is_empty() {
        item.heading().to_string()
    } else {
        format!("{}: {head}", item.heading())
    };
    truncate_chars(&text, ABSTRACT_MAX_CHARS)
}

/// L1: `# <title>` + the preview (else the body), ≤4000 chars.
pub fn overview_text(item: &MirrorItem) -> String {
    let source = if item.preview.trim().is_empty() {
        item.body.trim()
    } else {
        item.preview.trim()
    };
    truncate_chars(
        &format!("# {}\n\n{source}", item.heading()),
        OVERVIEW_MAX_CHARS,
    )
}

/// L2: `# <title>` + the body (the preview when the body is empty).
pub fn content_text(item: &MirrorItem) -> String {
    let source = if item.body.trim().is_empty() {
        item.preview.trim()
    } else {
        item.body.trim()
    };
    format!("# {}\n\n{source}", item.heading())
}

fn first_paragraph(text: &str) -> String {
    text.split("\n\n")
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .find(|p| !p.is_empty())
        .unwrap_or_default()
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn short_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone)]
pub struct OpenVikingClient {
    endpoint: String,
    api_key: String,
    account: String,
    user: String,
    agent: String,
    http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum OpenVikingError {
    #[error("openviking transport: {0}")]
    Transport(String),
    #[error("openviking http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("openviking parse: {0}")]
    Parse(String),
}

/// One manifest row: which item (by directory name) of which namespace is in
/// the engine, at which content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestRow {
    Item {
        namespace: String,
        segment: String,
        hash: String,
    },
    /// The pre-2026-09-18 layout (`<ns>\t<hash>`, one `memories/<ns>/mem_<hash>.md`
    /// per line): migrated away — deleted from the engine on the next pass.
    Legacy {
        namespace: String,
        hash: String,
    },
    Other(String),
}

fn parse_row(line: &str) -> ManifestRow {
    let parts: Vec<&str> = line.split('\t').collect();
    match parts.as_slice() {
        [namespace, segment, hash] if !namespace.is_empty() && !segment.is_empty() => {
            ManifestRow::Item {
                namespace: namespace.to_string(),
                segment: segment.to_string(),
                hash: hash.to_string(),
            }
        }
        [namespace, hash] if !namespace.is_empty() && !hash.is_empty() => ManifestRow::Legacy {
            namespace: namespace.to_string(),
            hash: hash.to_string(),
        },
        _ => ManifestRow::Other(line.to_string()),
    }
}

fn row_line(namespace: &str, segment: &str, hash: &str) -> String {
    format!("{namespace}\t{segment}\t{hash}")
}

impl OpenVikingClient {
    /// Build from the OpenViking env vars; `None` when `OPENVIKING_ENDPOINT` is
    /// unset/empty (so the caller cleanly falls back to a built-in engine).
    pub fn from_env() -> Option<Self> {
        let endpoint = std::env::var("OPENVIKING_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty())?;
        Some(Self::new(
            endpoint,
            std::env::var("OPENVIKING_API_KEY").unwrap_or_default(),
            std::env::var("OPENVIKING_ACCOUNT").unwrap_or_else(|_| "default".to_string()),
            std::env::var("OPENVIKING_USER").unwrap_or_else(|_| "default".to_string()),
            // The engine tree's agent coordinate — the historical hermes-era default,
            // kept for tree continuity (#621); override via OPENVIKING_AGENT.
            std::env::var("OPENVIKING_AGENT").unwrap_or_else(|_| "hermes".to_string()),
        ))
    }

    pub fn new(
        endpoint: String,
        api_key: String,
        account: String,
        user: String,
        agent: String,
    ) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_key,
            account,
            user,
            agent,
            http: reqwest::Client::new(),
        }
    }

    fn with_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        // `Actor-Peer` is the header the server's trusted mode reads (and what
        // the hermes-era plugin sent); the legacy `Agent` spelling rides along for
        // older servers that logged it.
        let mut req = req
            .header("X-OpenViking-Actor-Peer", &self.agent)
            .header("X-OpenViking-Agent", &self.agent);
        if !self.account.is_empty() {
            req = req.header("X-OpenViking-Account", &self.account);
        }
        if !self.user.is_empty() {
            req = req.header("X-OpenViking-User", &self.user);
        }
        if !self.api_key.is_empty() {
            req = req
                .header("X-API-Key", &self.api_key)
                .header("Authorization", format!("Bearer {}", self.api_key));
        }
        req
    }

    pub async fn health(&self) -> bool {
        let url = format!("{}/health", self.endpoint);
        self.with_headers(self.http.get(&url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// `POST /api/v1/content/write` with an explicit mode (`create` for a new
    /// file, `replace` for an existing one — sidecars included).
    pub async fn write_content(
        &self,
        uri: &str,
        content: &str,
        mode: &str,
    ) -> Result<(), OpenVikingError> {
        let url = format!("{}/api/v1/content/write", self.endpoint);
        let resp = self
            .with_headers(self.http.post(&url).json(&serde_json::json!({
                "uri": uri,
                "content": content,
                "mode": mode,
            })))
            .send()
            .await
            .map_err(|e| OpenVikingError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() || body_says_error(&body) {
            return Err(OpenVikingError::Http {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// Write a file so that it ends up with `content` whether or not it exists:
    /// `create` first, and `replace` when the engine answers that it exists.
    async fn write_upserting(&self, uri: &str, content: &str) -> Result<(), OpenVikingError> {
        match self.write_content(uri, content, "create").await {
            Ok(()) => Ok(()),
            Err(OpenVikingError::Http { body, .. })
                if body.to_ascii_lowercase().contains("exist") =>
            {
                self.write_content(uri, content, "replace").await
            }
            Err(e) => Err(e),
        }
    }

    /// A directory sidecar (`.abstract.md` / `.overview.md`): the engine
    /// materializes the placeholder itself after the body write (its semantic
    /// queue, asynchronously) and refuses a `create` through the public API,
    /// so this waits for the placeholder — `GET /api/v1/content/read` answers
    /// once it exists — then `replace`s it. Bounded: a placeholder that never
    /// appears is the item's write failure, retried next pass.
    async fn write_sidecar(&self, uri: &str, content: &str) -> Result<(), OpenVikingError> {
        let mut last = OpenVikingError::Transport(format!("{uri}: sidecar never materialized"));
        for attempt in 0..SIDECAR_WAIT_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(SIDECAR_WAIT_INTERVAL).await;
            }
            if !self.exists(uri).await {
                continue;
            }
            match self.write_content(uri, content, "replace").await {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            // `replace` raced the placeholder's own materialization: the read
            // succeeded a moment ago, so the next attempt normally lands.
        }
        Err(last)
    }

    /// `GET /api/v1/content/read?uri=…` answers 200 with `status: ok` once a
    /// file exists (sidecars included; `ls` hides them).
    async fn exists(&self, uri: &str) -> bool {
        let url = format!("{}/api/v1/content/read", self.endpoint);
        let resp = self
            .with_headers(self.http.get(&url).query(&[("uri", uri)]))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                !body_says_error(&body)
            }
            _ => false,
        }
    }

    /// `DELETE /api/v1/fs?uri=…` — one file; 404 counts as gone.
    pub async fn delete_content(&self, uri: &str) -> Result<(), OpenVikingError> {
        self.delete(uri, false).await
    }

    /// `DELETE /api/v1/fs?uri=…&recursive=true` — an item directory with its
    /// body and sidecars; 404 counts as gone.
    pub async fn delete_tree(&self, uri: &str) -> Result<(), OpenVikingError> {
        self.delete(uri, true).await
    }

    async fn delete(&self, uri: &str, recursive: bool) -> Result<(), OpenVikingError> {
        let url = format!("{}/api/v1/fs", self.endpoint);
        let mut query: Vec<(&str, String)> = vec![("uri", uri.to_string())];
        if recursive {
            query.push(("recursive", "true".to_string()));
        }
        let resp = self
            .with_headers(self.http.delete(&url).query(&query))
            .send()
            .await
            .map_err(|e| OpenVikingError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() || status.as_u16() == 404 {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(OpenVikingError::Http {
            status: status.as_u16(),
            body,
        })
    }

    /// The item's directory — the ONE composition site of the layout
    /// (`viking://resources/<ns>/<item>`; the e2e suite derives from here).
    pub fn resource_dir(&self, namespace: &str, segment: &str) -> String {
        format!("{RESOURCES_ROOT}/{namespace}/{segment}")
    }

    /// The pre-2026-09-18 file URI, kept only to migrate old sandboxes away.
    pub fn legacy_memory_uri(&self, namespace: &str, hash: &str) -> String {
        format!(
            "viking://user/{}/memories/{namespace}/mem_{hash}.md",
            if self.user.is_empty() {
                "default"
            } else {
                &self.user
            }
        )
    }

    /// Write one item's three files (body first, so the directory exists for
    /// the sidecars).
    async fn write_item(&self, namespace: &str, item: &MirrorItem) -> Result<(), OpenVikingError> {
        let segment = item.segment();
        let dir = self.resource_dir(namespace, &segment);
        self.write_upserting(&format!("{dir}/{segment}.md"), &content_text(item))
            .await?;
        self.write_sidecar(&format!("{dir}/.abstract.md"), &abstract_text(item))
            .await?;
        self.write_sidecar(&format!("{dir}/.overview.md"), &overview_text(item))
            .await
    }

    /// The #566 distribution-mirror pass for ONE namespace: converge the engine
    /// on exactly the gate-authorized `items`.
    ///
    /// - a new or changed item (by content hash) gets its three files written
    ///   and its manifest row recorded; a failed write is counted and retried
    ///   next pass (the row is not recorded);
    /// - a recorded item the gate no longer returns (removed, or the whole
    ///   namespace revoked with `items = []`) has its directory DELETE-THROUGHed
    ///   and its row dropped; a failed delete keeps the row and retries;
    /// - a legacy row (the old `memories/<ns>/mem_<hash>.md` layout) has its
    ///   file deleted and the row dropped — old sandboxes migrate themselves.
    ///
    /// The manifest is one file shared by the concurrent namespace tasks (#694):
    /// the network work runs unlocked, then this namespace's rows are swapped
    /// in under the manifest lock in one read-modify-write.
    pub async fn reconcile_items(
        &self,
        namespace: &str,
        items: &[MirrorItem],
        manifest: &std::path::Path,
    ) -> ReconcileStats {
        let mut stats = ReconcileStats::default();
        let rows: Vec<ManifestRow> = read_manifest(manifest)
            .iter()
            .map(|l| parse_row(l))
            .collect();
        let mut recorded: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut legacy: Vec<String> = Vec::new();
        for row in &rows {
            match row {
                ManifestRow::Item {
                    namespace: ns,
                    segment,
                    hash,
                } if ns == namespace => {
                    recorded.insert(segment.clone(), hash.clone());
                }
                ManifestRow::Legacy {
                    namespace: ns,
                    hash,
                } if ns == namespace => {
                    legacy.push(hash.clone());
                }
                _ => {}
            }
        }
        // Desired state: one row per distinct directory (a duplicate key in the
        // canonical array keeps its first occurrence).
        let mut desired: Vec<(String, String, &MirrorItem)> = Vec::new();
        for item in items {
            let segment = item.segment();
            if desired.iter().any(|(s, _, _)| *s == segment) {
                continue;
            }
            desired.push((segment, item.content_hash(), item));
        }
        let mut next_rows: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        // Deletions: recorded directories the gate no longer returns.
        for (segment, hash) in &recorded {
            if desired.iter().any(|(s, _, _)| s == segment) {
                continue;
            }
            let dir = self.resource_dir(namespace, segment);
            match self.delete_tree(&dir).await {
                Ok(()) => stats.deleted += 1,
                Err(e) => {
                    stats.note_error("delete", &dir, &e);
                    stats.delete_failed += 1;
                    next_rows.insert(segment.clone(), hash.clone());
                }
            }
        }
        // Migration: the old per-line files leave the engine.
        let mut legacy_kept: Vec<String> = Vec::new();
        for hash in &legacy {
            let legacy_uri = self.legacy_memory_uri(namespace, hash);
            match self.delete_content(&legacy_uri).await {
                Ok(()) => stats.deleted += 1,
                Err(e) => {
                    stats.note_error("delete", &legacy_uri, &e);
                    stats.delete_failed += 1;
                    legacy_kept.push(hash.clone());
                }
            }
        }
        // Writes: new or changed items.
        for (segment, hash, item) in &desired {
            if recorded.get(segment) == Some(hash) {
                next_rows.insert(segment.clone(), hash.clone());
                continue;
            }
            match self.write_item(namespace, item).await {
                Ok(()) => {
                    stats.mirrored += 1;
                    next_rows.insert(segment.clone(), hash.clone());
                }
                Err(e) => {
                    stats.note_error("write", &self.resource_dir(namespace, segment), &e);
                    stats.write_failed += 1;
                    if let Some(old) = recorded.get(segment) {
                        next_rows.insert(segment.clone(), old.clone());
                    }
                }
            }
        }
        // Swap this namespace's rows in, keeping every other namespace's.
        let mut lines: Vec<String> = Vec::new();
        for row in &rows {
            match row {
                ManifestRow::Item { namespace: ns, .. }
                | ManifestRow::Legacy { namespace: ns, .. }
                    if ns == namespace =>
                {
                    continue
                }
                ManifestRow::Item {
                    namespace: ns,
                    segment,
                    hash,
                } => lines.push(row_line(ns, segment, hash)),
                ManifestRow::Legacy {
                    namespace: ns,
                    hash,
                } => lines.push(format!("{ns}\t{hash}")),
                ManifestRow::Other(line) => {
                    if !line.trim().is_empty() {
                        lines.push(line.clone());
                    }
                }
            }
        }
        let mut own: Vec<(String, String)> = next_rows.into_iter().collect();
        own.sort();
        for (segment, hash) in own {
            lines.push(row_line(namespace, &segment, &hash));
        }
        for hash in legacy_kept {
            lines.push(format!("{namespace}\t{hash}"));
        }
        rewrite_manifest(manifest, &lines);
        stats
    }
}

/// The engine answers 200 with `{status:"error"}` for some refusals.
fn body_says_error(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s == "error")
        })
        .unwrap_or(false)
}

/// Outcome of one [`OpenVikingClient::reconcile_items`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileStats {
    /// Items newly written or rewritten this pass.
    pub mirrored: usize,
    /// Items whose write errored (retried next pass).
    pub write_failed: usize,
    /// Stale item directories (and legacy files) removed from the engine.
    pub deleted: usize,
    /// Stale entries whose delete errored (kept in the manifest, retried).
    pub delete_failed: usize,
    /// The first failure's reason (uri + engine answer) — a count without its
    /// reason is undebuggable (suite-7 once died on "1 write(s) failed" alone).
    pub first_error: Option<String>,
}

impl ReconcileStats {
    pub fn is_noop(&self) -> bool {
        self.mirrored == 0 && self.write_failed == 0 && self.deleted == 0 && self.delete_failed == 0
    }

    fn note_error(&mut self, what: &str, uri: &str, err: &OpenVikingError) {
        tracing::warn!(uri, error = %err, "openviking mirror: {what} failed — retried next pass");
        if self.first_error.is_none() {
            self.first_error = Some(format!("{what} {uri}: {err}"));
        }
    }
}

/// Manifest path for [`OpenVikingClient::reconcile_items`]:
/// `AGENTKEYS_OV_INGEST_MANIFEST`, else `$HOME/.agentkeys/ov-ingested.txt`.
/// Lives in the SANDBOX filesystem on purpose — a respawn wipes it (or the
/// #694 workspace checkpoint restores it beside the engine index), and the
/// next pass rebuilds from canonical.
pub fn ingest_manifest_from_env() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("AGENTKEYS_OV_INGEST_MANIFEST") {
        if !p.trim().is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::Path::new(&home)
        .join(".agentkeys")
        .join("ov-ingested.txt")
}

/// #694 — namespaces of one pass reconcile concurrently; the manifest is ONE
/// file, so each read / rewrite holds this lock (short, filesystem-only).
static MANIFEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn manifest_guard() -> std::sync::MutexGuard<'static, ()> {
    MANIFEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn read_manifest(path: &std::path::Path) -> Vec<String> {
    let _guard = manifest_guard();
    std::fs::read_to_string(path)
        .map(|s| s.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default()
}

fn rewrite_manifest(path: &std::path::Path, entries: &[String]) {
    let _guard = manifest_guard();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut body = entries.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    if let Err(err) = std::fs::write(path, &body) {
        // Non-fatal: the engine already holds the new state, so the next pass
        // re-issues writes that answer "exists" / deletes that 404 (both counted
        // as done). Surfacing the I/O error is what matters — a silent failure
        // looks like a stuck mirror.
        tracing::warn!(error = %err, path = ?path, "openviking manifest rewrite failed — this namespace is re-reconciled next pass");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};

    fn client(endpoint: String) -> OpenVikingClient {
        OpenVikingClient::new(
            endpoint,
            String::new(),
            "default".into(),
            "default".into(),
            "hermes".into(),
        )
    }

    fn item(key: &str, title: &str, preview: &str, body: &str) -> MirrorItem {
        MirrorItem {
            key: key.into(),
            title: title.into(),
            preview: preview.into(),
            body: body.into(),
        }
    }

    fn items() -> Vec<MirrorItem> {
        vec![
            item(
                "food-preferences",
                "Food preferences",
                "Avoid gluten and cilantro; favourites are steamed fish and tomato egg stir-fry.",
                "# Food preferences\n\nThe family avoids gluten: no wheat noodles, bread or seitan.\n\nNobody likes cilantro.",
            ),
            item("chengdu-trip", "", "", "Chengdu trip — Apr 12 to 16."),
        ]
    }

    // ── pure pieces ──────────────────────────────────────────────────────────

    #[test]
    fn a_key_becomes_a_safe_directory_name() {
        assert_eq!(path_segment("food-preferences"), "food-preferences");
        assert_eq!(path_segment("Gene_Report.v2"), "Gene_Report.v2");
        // a changed key carries a tail so `a/b` and `a-b` never collide
        let slashed = path_segment("diary/2026-09-17/lunch");
        assert!(slashed.starts_with("diary-2026-09-17-lunch-"), "{slashed}");
        assert_eq!(slashed.len(), "diary-2026-09-17-lunch-".len() + 4);
        assert_ne!(path_segment("a/b"), path_segment("a-b"));
        // a leading dot would name a hidden sidecar
        assert!(!path_segment(".hidden").starts_with('.'));
        // nothing usable → a hashed name, never empty
        assert!(path_segment("///").starts_with("item-"));
        assert!(path_segment("").starts_with("item-"));
        // bounded
        assert!(path_segment(&"k".repeat(500)).len() <= SEGMENT_MAX_CHARS + 5);
    }

    #[test]
    fn layers_come_from_title_preview_and_body() {
        let it = &items()[0];
        assert_eq!(
            abstract_text(it),
            "Food preferences: Avoid gluten and cilantro; favourites are steamed fish and tomato egg stir-fry."
        );
        assert!(overview_text(it).starts_with("# Food preferences\n\nAvoid gluten"));
        assert!(content_text(it)
            .starts_with("# Food preferences\n\n# Food preferences\n\nThe family avoids"));
        // no title → the key heads every layer; no preview → the body's first paragraph
        let bare = &items()[1];
        assert_eq!(
            abstract_text(bare),
            "chengdu-trip: Chengdu trip — Apr 12 to 16."
        );
        assert_eq!(
            overview_text(bare),
            "# chengdu-trip\n\nChengdu trip — Apr 12 to 16."
        );
        assert_eq!(
            content_text(bare),
            "# chengdu-trip\n\nChengdu trip — Apr 12 to 16."
        );
        // an empty item still has a heading
        let empty = item("k", "", "", "");
        assert_eq!(abstract_text(&empty), "k");
    }

    #[test]
    fn layers_respect_openvikings_size_limits() {
        let long = item("k", "T", "", &"word ".repeat(3000));
        assert!(abstract_text(&long).chars().count() <= ABSTRACT_MAX_CHARS);
        assert!(abstract_text(&long).ends_with('…'));
        assert!(overview_text(&long).chars().count() <= OVERVIEW_MAX_CHARS);
        assert!(
            content_text(&long).len() > OVERVIEW_MAX_CHARS,
            "the body is never cut"
        );
        // multi-byte safe
        let cjk = item("k", "偏好", "", &"家庭饮食偏好。".repeat(200));
        assert!(abstract_text(&cjk).chars().count() <= ABSTRACT_MAX_CHARS);
    }

    #[test]
    fn content_hash_tracks_every_layer() {
        let base = items()[0].clone();
        let mut changed = base.clone();
        changed.preview.push('!');
        assert_ne!(base.content_hash(), changed.content_hash());
        assert_eq!(base.content_hash(), items()[0].content_hash());
        assert_eq!(base.content_hash().len(), 16);
    }

    #[test]
    fn manifest_rows_parse_both_layouts() {
        assert_eq!(
            parse_row("family\tfood-preferences\tabcd"),
            ManifestRow::Item {
                namespace: "family".into(),
                segment: "food-preferences".into(),
                hash: "abcd".into()
            }
        );
        assert_eq!(
            parse_row("family\t0123456789abcdef"),
            ManifestRow::Legacy {
                namespace: "family".into(),
                hash: "0123456789abcdef".into()
            }
        );
        assert!(matches!(parse_row("garbage"), ManifestRow::Other(_)));
    }

    // ── the engine stub ──────────────────────────────────────────────────────

    /// What the stub records: `(method, uri, mode-or-recursive)`.
    type Log = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>;

    /// Records writes and deletes; `write_status`/`write_body` answer every
    /// write, `delete_status` every delete. `exists_on_create` makes a `create`
    /// on an already-written URI answer 409 like the real engine.
    async fn spawn_stub(
        write_status: u16,
        write_body: &'static str,
        delete_status: u16,
        exists_on_create: bool,
    ) -> (String, Log) {
        use axum::extract::Query;
        use axum::http::StatusCode;
        let log: Log = Default::default();
        let (lw, ld, lr) = (log.clone(), log.clone(), log.clone());
        let app = Router::new()
            .route(
                "/api/v1/content/write",
                post(move |Json(body): Json<serde_json::Value>| {
                    let log = lw.clone();
                    async move {
                        let uri = body["uri"].as_str().unwrap_or_default().to_string();
                        let mode = body["mode"].as_str().unwrap_or_default().to_string();
                        let seen_before = log
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|(m, u, _)| m == "write" && *u == uri);
                        log.lock().unwrap().push(("write".into(), uri, mode.clone()));
                        if exists_on_create && mode == "create" && seen_before {
                            return (
                                StatusCode::CONFLICT,
                                r#"{"status":"error","error":{"code":"ALREADY_EXISTS","message":"already exists"}}"#.to_string(),
                            );
                        }
                        (
                            StatusCode::from_u16(write_status).unwrap(),
                            write_body.to_string(),
                        )
                    }
                }),
            )
            .route(
                "/api/v1/fs",
                axum::routing::delete(
                    move |Query(q): Query<std::collections::HashMap<String, String>>| {
                        let log = ld.clone();
                        async move {
                            log.lock().unwrap().push((
                                "delete".into(),
                                q.get("uri").cloned().unwrap_or_default(),
                                q.get("recursive").cloned().unwrap_or_default(),
                            ));
                            (
                                StatusCode::from_u16(delete_status).unwrap(),
                                "{}".to_string(),
                            )
                        }
                    },
                ),
            )
            .route(
                "/api/v1/content/read",
                axum::routing::get(
                    move |Query(q): Query<std::collections::HashMap<String, String>>| {
                        let log = lr.clone();
                        async move {
                            // The placeholder race: a sidecar reads back only
                            // once its directory's body was written (the real
                            // engine materializes it a moment after).
                            let uri = q.get("uri").cloned().unwrap_or_default();
                            let dir = uri
                                .rsplit_once('/')
                                .map(|(d, _)| d.to_string())
                                .unwrap_or_default();
                            let body_written = log.lock().unwrap().iter().any(|(m, u, _)| {
                                m == "write"
                                    && u.starts_with(&format!("{dir}/"))
                                    && !u.rsplit('/').next().unwrap_or("").starts_with('.')
                            });
                            log.lock().unwrap().push(("read".into(), uri, String::new()));
                            if body_written {
                                (
                                    StatusCode::OK,
                                    r#"{"status":"ok","result":"placeholder"}"#.to_string(),
                                )
                            } else {
                                (
                                    StatusCode::NOT_FOUND,
                                    r#"{"status":"error","error":{"code":"NOT_FOUND","message":"no such file"}}"#.to_string(),
                                )
                            }
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), log)
    }

    fn writes(log: &Log) -> Vec<(String, String)> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m == "write")
            .map(|(_, u, mode)| (u.clone(), mode.clone()))
            .collect()
    }

    fn deletes(log: &Log) -> Vec<(String, String)> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m == "delete")
            .map(|(_, u, r)| (u.clone(), r.clone()))
            .collect()
    }

    fn manifest_lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn a_sidecar_is_written_only_after_its_placeholder_reads_back() {
        let (endpoint, log) = spawn_stub(200, "{}", 200, false).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);
        let stats = c.reconcile_items("family", &items()[..1], &manifest).await;
        assert_eq!((stats.mirrored, stats.write_failed), (1, 0));
        let ops: Vec<(String, String)> = log
            .lock()
            .unwrap()
            .iter()
            .map(|(m, u, _)| (m.clone(), u.clone()))
            .collect();
        // body write, then a successful read of each sidecar BEFORE its replace
        let body_at = ops
            .iter()
            .position(|(m, u)| m == "write" && u.ends_with("/food-preferences.md"))
            .unwrap();
        for name in [".abstract.md", ".overview.md"] {
            let read_at = ops
                .iter()
                .position(|(m, u)| m == "read" && u.ends_with(name))
                .unwrap();
            let write_at = ops
                .iter()
                .position(|(m, u)| m == "write" && u.ends_with(name))
                .unwrap();
            assert!(body_at < read_at && read_at < write_at, "{name}: {ops:?}");
        }
    }

    #[tokio::test]
    async fn an_item_is_three_files_under_its_resource_directory_then_a_noop() {
        let (endpoint, log) = spawn_stub(200, "{}", 200, false).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);
        let stats = c.reconcile_items("family", &items(), &manifest).await;
        assert_eq!(
            (stats.mirrored, stats.write_failed, stats.deleted),
            (2, 0, 0)
        );
        let w = writes(&log);
        assert_eq!(w.len(), 6, "body + two sidecars per item");
        assert_eq!(
            w[0],
            (
                "viking://resources/family/food-preferences/food-preferences.md".to_string(),
                "create".to_string()
            )
        );
        assert_eq!(
            w[1],
            (
                "viking://resources/family/food-preferences/.abstract.md".to_string(),
                "replace".to_string()
            )
        );
        assert_eq!(
            w[2],
            (
                "viking://resources/family/food-preferences/.overview.md".to_string(),
                "replace".to_string()
            )
        );
        assert!(w[3]
            .0
            .starts_with("viking://resources/family/chengdu-trip/"));
        let rows = manifest_lines(&manifest);
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .any(|r| r.starts_with("family\tfood-preferences\t")),
            "{rows:?}"
        );
        // second pass: nothing to do, nothing sent
        let again = c.reconcile_items("family", &items(), &manifest).await;
        assert!(again.is_noop());
        assert_eq!(writes(&log).len(), 6);
        assert!(deletes(&log).is_empty());
    }

    #[tokio::test]
    async fn a_changed_item_is_rewritten_and_a_removed_one_is_deleted_recursively() {
        let (endpoint, log) = spawn_stub(200, "{}", 200, false).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);
        c.reconcile_items("family", &items(), &manifest).await;
        let mut next = items();
        next[0].body.push_str("\n\nGrandma cannot have shellfish.");
        next.truncate(1);
        let stats = c.reconcile_items("family", &next, &manifest).await;
        assert_eq!(
            (stats.mirrored, stats.deleted, stats.delete_failed),
            (1, 1, 0)
        );
        let d = deletes(&log);
        assert_eq!(
            d,
            vec![(
                "viking://resources/family/chengdu-trip".to_string(),
                "true".to_string()
            )]
        );
        assert_eq!(
            writes(&log).len(),
            9,
            "the changed item rewrote its three files"
        );
        let rows = manifest_lines(&manifest);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].starts_with("family\tfood-preferences\t"));
        assert!(rows[0].ends_with(&next[0].content_hash()));
    }

    #[tokio::test]
    async fn a_revoked_namespace_reconciles_onto_empty_and_keeps_other_namespaces() {
        let (endpoint, log) = spawn_stub(200, "{}", 200, false).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);
        c.reconcile_items("family", &items(), &manifest).await;
        c.reconcile_items("health", &items()[..1], &manifest).await;
        let stats = c.reconcile_items("family", &[], &manifest).await;
        assert_eq!((stats.mirrored, stats.deleted), (0, 2));
        let d = deletes(&log);
        assert_eq!(d.len(), 2);
        assert!(d
            .iter()
            .all(|(u, r)| u.starts_with("viking://resources/family/") && r == "true"));
        let rows = manifest_lines(&manifest);
        assert_eq!(
            rows.len(),
            1,
            "health's row survives family's revocation: {rows:?}"
        );
        assert!(rows[0].starts_with("health\t"));
    }

    #[tokio::test]
    async fn legacy_memory_files_are_migrated_away() {
        let (endpoint, log) = spawn_stub(200, "{}", 200, false).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        std::fs::write(
            &manifest,
            "family\t0123456789abcdef\nwork\tfedcba9876543210\n",
        )
        .unwrap();
        let c = client(endpoint);
        let stats = c.reconcile_items("family", &items()[..1], &manifest).await;
        assert_eq!((stats.mirrored, stats.deleted), (1, 1));
        let d = deletes(&log);
        assert_eq!(
            d,
            vec![(
                "viking://user/default/memories/family/mem_0123456789abcdef.md".to_string(),
                String::new()
            )]
        );
        let rows = manifest_lines(&manifest);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(
            rows.contains(&"work\tfedcba9876543210".to_string()),
            "another namespace's legacy row waits for its own pass"
        );
        assert!(rows
            .iter()
            .any(|r| r.starts_with("family\tfood-preferences\t")));
    }

    #[tokio::test]
    async fn write_failures_are_counted_and_retried_next_pass() {
        let (endpoint, log) = spawn_stub(500, "boom", 200, false).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);
        let stats = c.reconcile_items("family", &items(), &manifest).await;
        assert_eq!((stats.mirrored, stats.write_failed), (0, 2));
        let reason = stats
            .first_error
            .clone()
            .expect("the failure names its reason");
        assert!(
            reason.contains("write viking://resources/family/food-preferences")
                && reason.contains("boom"),
            "{reason}"
        );
        assert!(
            manifest_lines(&manifest).is_empty(),
            "nothing recorded for a failed item"
        );
        let again = c.reconcile_items("family", &items(), &manifest).await;
        assert_eq!(again.write_failed, 2);
        assert_eq!(
            writes(&log).len(),
            4,
            "the body write fails first each time, so one write per item per pass"
        );
    }

    #[tokio::test]
    async fn an_existing_body_takes_replace_and_a_failed_delete_keeps_the_row() {
        let (endpoint, log) = spawn_stub(200, "{}", 500, true).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);
        c.reconcile_items("family", &items()[..1], &manifest).await;
        // manifest lost (a fresh sandbox restored without it): the body exists
        // engine-side, `create` answers 409, `replace` completes the item
        std::fs::remove_file(&manifest).unwrap();
        let stats = c.reconcile_items("family", &items()[..1], &manifest).await;
        assert_eq!((stats.mirrored, stats.write_failed), (1, 0));
        let w = writes(&log);
        let modes: Vec<&str> = w
            .iter()
            .filter(|(u, _)| u.ends_with("/food-preferences.md"))
            .map(|(_, m)| m.as_str())
            .collect();
        assert_eq!(modes, vec!["create", "create", "replace"]);
        // a delete the engine refuses keeps the row for the next pass
        let stats = c.reconcile_items("family", &[], &manifest).await;
        assert_eq!((stats.deleted, stats.delete_failed), (0, 1));
        assert_eq!(manifest_lines(&manifest).len(), 1);
    }

    #[tokio::test]
    async fn an_error_envelope_on_200_is_an_error() {
        let (endpoint, _log) = spawn_stub(200, r#"{"status":"error","error":{"code":"INVALID_ARGUMENT","message":"unsupported write mode"}}"#, 200, false).await;
        let c = client(endpoint);
        let err = c
            .write_content("viking://resources/x/y/y.md", "t", "overwrite")
            .await
            .unwrap_err();
        assert!(matches!(err, OpenVikingError::Http { status: 200, .. }));
    }
}
