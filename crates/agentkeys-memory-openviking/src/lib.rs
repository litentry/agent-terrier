//! OpenViking engine adapter — plan `docs/plan/agentkeys-memory-design.md` §6a,
//! integration shape `docs/plan/issue-566-openviking-native-memory-provider.md`.
//!
//! OpenViking (`volcengine/OpenViking`) is a self-hosted context database. Since
//! #566 it is Hermes' FIRST-CLASS native memory provider (`memory.provider:
//! openviking` — the agent reads/writes it directly via `viking_search` /
//! `viking_remember`), and AgentKeys' gate bound moved to INGEST-time: this
//! crate's consumer is the daemon's distribution mirror, which may only write
//! what `canonical-get` returned (the memory worker enforces per-namespace
//! authorization on every fetch). AgentKeys still STORES (K3-encrypted S3) +
//! GATES (cap / scope / namespace / audit); the engine holds a sandbox-local,
//! rebuilt-on-respawn index of the authorized slice plus the agent's own
//! working memory.
//!
//! This crate is now WRITE-SIDE ONLY — the mirror's half of the contract,
//! verified against a live `openviking-server` 0.4.11:
//!
//!   base    http://127.0.0.1:1933  (OPENVIKING_ENDPOINT)
//!   headers X-OpenViking-Actor-Peer / -Account / -User, plus X-API-Key +
//!           `Authorization: Bearer <key>` when OPENVIKING_API_KEY is set
//!   GET    /health                        -> 200 when up
//!   POST   /api/v1/content/write {uri, content, mode:"create"}
//!   DELETE /api/v1/fs?uri=<viking://…>    -> remove one mirrored file
//!   error envelope: HTTP >= 400, or {status:"error", error:{code,message}}
//!
//! The QUERY side is deliberately absent. Reading is the AGENT's job through
//! its native provider (`viking_search`/`viking_read`), so the pre-#566
//! `search_find` + `rank_gate_bounded` pair had zero consumers once the wire
//! hook was retired — AND it parsed `{result:{results:[…]}}`, a shape the real
//! server never emits (0.4.11 answers `{result:{memories:[…],resources:[…]}}`
//! with URIs + scores, no verbatim content). Its unit tests passed only because
//! the stub echoed the crate's own invented shape. Rather than ship a broken,
//! unused API, it is removed; a future ranking client (#183's config-driven
//! adapter) should be written against the measured shape and proven end-to-end
//! by `e2e/suite-7-memory-mirror.sh`.
//!
//! SAFETY — the gate bounds visibility at INGEST:
//! [`OpenVikingClient::reconcile_ingested`] only ever writes gate-authorized
//! lines and delete-throughs lines the gate no longer returns (revocation
//! self-heals; a fresh sandbox rebuilds from canonical). OpenViking can rank
//! but can never WIDEN visibility, and it is never load-bearing — engine down
//! ⇒ Hermes falls back to its built-in memory; the mirror retries next pass.

use agentkeys_memory_engine::MemoryLine;

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:1933";

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
        // the Hermes plugin sends); the legacy `Agent` spelling rides along for
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

    /// `POST /api/v1/content/write` — mirror one gate-authorized line into
    /// OpenViking so `search/find` can rank it. The durable copy stays in
    /// AgentKeys' encrypted S3; this is OpenViking's (operator-self-hosted)
    /// ranking index only.
    pub async fn write_content(&self, uri: &str, content: &str) -> Result<(), OpenVikingError> {
        let url = format!("{}/api/v1/content/write", self.endpoint);
        let resp = self
            .with_headers(self.http.post(&url).json(&serde_json::json!({
                "uri": uri,
                "content": content,
                "mode": "create",
            })))
            .send()
            .await
            .map_err(|e| OpenVikingError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OpenVikingError::Http {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// `DELETE /api/v1/fs?uri=<viking://…>` — remove one mirrored file from the
    /// index (the delete-through half of [`Self::reconcile_ingested`]). A 404
    /// counts as deleted (the goal state — absent — already holds).
    pub async fn delete_content(&self, uri: &str) -> Result<(), OpenVikingError> {
        let url = format!("{}/api/v1/fs", self.endpoint);
        let resp = self
            .with_headers(self.http.delete(&url).query(&[("uri", uri)]))
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

    /// The mirror URI for one gate-authorized line — the ONE composition site
    /// (ensure/reconcile/delete and the e2e all derive from here). Content-hash
    /// names make the mirror idempotent regardless of namespace order or churn.
    pub fn memory_uri(&self, namespace: &str, hash: &str) -> String {
        format!(
            "viking://user/{}/memories/{namespace}/mem_{hash}.md",
            if self.user.is_empty() {
                "default"
            } else {
                &self.user
            }
        )
    }

    /// The production ingest leg (#399): make sure every gate-authorized line
    /// is present in OpenViking's ranking index BEFORE the rank call, tracked
    /// by a manifest file in the sandbox filesystem so warm turns cost zero
    /// writes. Content-hash URIs make the mirror idempotent regardless of
    /// namespace order or churn.
    ///
    /// Rebuild-on-respawn IS this function: a fresh sandbox has no manifest and
    /// an empty index, so the first ranked turn re-mirrors everything from the
    /// gate-authorized canonical lines (the durable truth never lives here).
    /// Best-effort by design — a failed write is counted, logged by the caller,
    /// and retried on the next turn; ranking then falls back deterministically.
    ///
    /// Returns `(mirrored, failed)` — lines newly written (or already present
    /// server-side) vs lines whose write errored.
    pub async fn ensure_ingested(
        &self,
        namespace: &str,
        lines: &[MemoryLine],
        manifest: &std::path::Path,
    ) -> (usize, usize) {
        if lines.is_empty() {
            return (0, 0);
        }
        let seen = read_manifest(manifest);
        let mut mirrored = 0usize;
        let mut failed = 0usize;
        let mut new_entries: Vec<String> = Vec::new();
        for line in lines {
            let hash = line_hash(&line.text);
            let key = format!("{namespace}\t{hash}");
            if seen.contains(&key) {
                continue;
            }
            let uri = self.memory_uri(namespace, &hash);
            match self.write_content(&uri, &line.text).await {
                Ok(()) => {
                    mirrored += 1;
                    new_entries.push(key);
                }
                // mode:"create" on an already-present URI — the index HAS the
                // line (e.g. manifest lost but index warm); record + move on.
                Err(OpenVikingError::Http { body, .. })
                    if body.to_ascii_lowercase().contains("exist") =>
                {
                    mirrored += 1;
                    new_entries.push(key);
                }
                Err(_) => failed += 1,
            }
        }
        if !new_entries.is_empty() {
            append_manifest(manifest, &new_entries);
        }
        (mirrored, failed)
    }

    /// The #566 distribution-mirror pass for ONE namespace: converge the index
    /// on exactly the gate-authorized `lines`.
    ///
    /// - additions ride [`Self::ensure_ingested`] (manifest-tracked, idempotent);
    /// - manifest entries of this namespace whose line no longer appears in
    ///   `lines` are DELETE-THROUGHed (`DELETE /api/v1/fs`) and dropped from the
    ///   manifest — so a line the master removed, or a namespace whose grant was
    ///   revoked (`lines = []`), leaves the index at the next pass, not only at
    ///   respawn. A failed delete stays in the manifest and retries next pass.
    ///
    /// Best-effort like everything here: the durable truth never lives in the
    /// engine, and a fresh sandbox rebuilds from canonical.
    pub async fn reconcile_ingested(
        &self,
        namespace: &str,
        lines: &[MemoryLine],
        manifest: &std::path::Path,
    ) -> ReconcileStats {
        let current: std::collections::HashSet<String> =
            lines.iter().map(|l| line_hash(&l.text)).collect();
        let ns_prefix = format!("{namespace}\t");
        let stale: Vec<String> = read_manifest(manifest)
            .into_iter()
            .filter(|key| {
                key.strip_prefix(&ns_prefix)
                    .is_some_and(|hash| !current.contains(hash))
            })
            .collect();
        let mut deleted = 0usize;
        let mut delete_failed = 0usize;
        let mut dropped: Vec<String> = Vec::new();
        for key in &stale {
            let hash = key.strip_prefix(&ns_prefix).unwrap_or_default();
            match self.delete_content(&self.memory_uri(namespace, hash)).await {
                Ok(()) => {
                    deleted += 1;
                    dropped.push(key.clone());
                }
                Err(_) => delete_failed += 1,
            }
        }
        let (mirrored, write_failed) = self.ensure_ingested(namespace, lines, manifest).await;
        if !dropped.is_empty() {
            let keep: Vec<String> = read_manifest(manifest)
                .into_iter()
                .filter(|k| !dropped.contains(k))
                .collect();
            rewrite_manifest(manifest, &keep);
        }
        ReconcileStats {
            mirrored,
            write_failed,
            deleted,
            delete_failed,
        }
    }
}

/// Outcome of one [`OpenVikingClient::reconcile_ingested`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileStats {
    /// Lines newly written (or confirmed present) this pass.
    pub mirrored: usize,
    /// Lines whose write errored (retried next pass).
    pub write_failed: usize,
    /// Stale mirrored lines removed from the index.
    pub deleted: usize,
    /// Stale lines whose delete errored (kept in the manifest, retried).
    pub delete_failed: usize,
}

impl ReconcileStats {
    pub fn is_noop(&self) -> bool {
        *self == Self::default()
    }
}

/// Manifest path for [`OpenVikingClient::ensure_ingested`]:
/// `AGENTKEYS_OV_INGEST_MANIFEST`, else `$HOME/.agentkeys/ov-ingested.txt`.
/// Lives in the SANDBOX filesystem on purpose — respawn wipes it, and the next
/// ranked turn rebuilds the index from canonical (#399 persistence decision).
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

/// First 8 bytes of SHA-256 over the line text, hex — stable across turns and
/// namespace reorderings, so the same line never mirrors twice.
fn line_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn read_manifest(path: &std::path::Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(path)
        .map(|s| s.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default()
}

fn append_manifest(path: &std::path::Path, entries: &[String]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        for e in entries {
            if let Err(err) = writeln!(f, "{e}") {
                tracing::warn!(error = %err, path = ?path, "openviking manifest append failed — the next pass re-mirrors this line");
            }
        }
    }
}

fn rewrite_manifest(path: &std::path::Path, entries: &[String]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut body = entries.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    if let Err(err) = std::fs::write(path, &body) {
        // Non-fatal: the entries were already deleted server-side, so the next
        // pass re-issues deletes that 404 (counted as done). Surfacing the I/O
        // error is what matters — a silent failure looks like a stuck mirror.
        tracing::warn!(error = %err, path = ?path, "openviking manifest rewrite failed — stale entries retried next pass");
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

    fn lines() -> Vec<MemoryLine> {
        vec![
            MemoryLine {
                text: "Chengdu trip — Apr 12 to 16.".into(),
                seq: 0,
            },
            MemoryLine {
                text: "Allergic to peanuts.".into(),
                seq: 1,
            },
        ]
    }

    // ── #399 ingest leg ──────────────────────────────────────────────────────

    type WriteLog = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// Stub serving BOTH write (records URIs; `status` controls the reply) and
    /// find, for the ingest tests.
    async fn spawn_ingest_stub(write_status: u16, write_body: &'static str) -> (String, WriteLog) {
        use axum::http::StatusCode;
        let log: WriteLog = Default::default();
        let log_c = log.clone();
        let app = Router::new()
            .route(
                "/api/v1/content/write",
                post(move |Json(body): Json<serde_json::Value>| {
                    let log = log_c.clone();
                    async move {
                        log.lock()
                            .unwrap()
                            .push(body["uri"].as_str().unwrap_or_default().to_string());
                        (
                            StatusCode::from_u16(write_status).unwrap(),
                            write_body.to_string(),
                        )
                    }
                }),
            )
            .route(
                "/api/v1/search/find",
                post(|| async { Json(serde_json::json!({ "result": {"results": []} })) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), log)
    }

    #[tokio::test]
    async fn ingest_mirrors_once_then_manifest_skips() {
        let (endpoint, log) = spawn_ingest_stub(200, "{}").await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);

        let (mirrored, failed) = c.ensure_ingested("home", &lines(), &manifest).await;
        assert_eq!((mirrored, failed), (2, 0));
        let wrote = log.lock().unwrap().clone();
        assert_eq!(wrote.len(), 2);
        // content-hash URIs under the client's user + the namespace
        assert!(wrote[0].starts_with("viking://user/default/memories/home/mem_"));
        assert!(wrote[0].ends_with(".md"));

        // second call: manifest short-circuits — ZERO new writes
        let (mirrored2, failed2) = c.ensure_ingested("home", &lines(), &manifest).await;
        assert_eq!((mirrored2, failed2), (0, 0));
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn ingest_treats_already_exists_as_mirrored() {
        // index warm but manifest lost (e.g. hand-wiped): server says exists →
        // counted mirrored + recorded, so the NEXT call skips the write.
        let (endpoint, log) = spawn_ingest_stub(
            409,
            r#"{"status":"error","error":{"message":"uri already exists"}}"#,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);

        let (mirrored, failed) = c.ensure_ingested("home", &lines(), &manifest).await;
        assert_eq!((mirrored, failed), (2, 0));
        let (m2, f2) = c.ensure_ingested("home", &lines(), &manifest).await;
        assert_eq!((m2, f2), (0, 0));
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn ingest_counts_failures_and_retries_next_turn() {
        let (endpoint, log) = spawn_ingest_stub(500, "boom").await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);

        let (mirrored, failed) = c.ensure_ingested("home", &lines(), &manifest).await;
        assert_eq!((mirrored, failed), (0, 2));
        // nothing recorded → the next turn retries every line
        let (m2, f2) = c.ensure_ingested("home", &lines(), &manifest).await;
        assert_eq!((m2, f2), (0, 2));
        assert_eq!(log.lock().unwrap().len(), 4);
    }

    /// Stub for the #566 reconcile tests: records writes AND `DELETE
    /// /api/v1/fs?uri=…` (the delete-through half); `delete_status` controls
    /// the delete reply.
    async fn spawn_reconcile_stub(delete_status: u16) -> (String, WriteLog, WriteLog) {
        use axum::extract::Query;
        use axum::http::StatusCode;
        let writes: WriteLog = Default::default();
        let deletes: WriteLog = Default::default();
        let (w, d) = (writes.clone(), deletes.clone());
        let app = Router::new()
            .route(
                "/api/v1/content/write",
                post(move |Json(body): Json<serde_json::Value>| {
                    let w = w.clone();
                    async move {
                        w.lock()
                            .unwrap()
                            .push(body["uri"].as_str().unwrap_or_default().to_string());
                        (StatusCode::OK, "{}".to_string())
                    }
                }),
            )
            .route(
                "/api/v1/fs",
                axum::routing::delete(
                    move |Query(q): Query<std::collections::HashMap<String, String>>| {
                        let d = d.clone();
                        async move {
                            d.lock()
                                .unwrap()
                                .push(q.get("uri").cloned().unwrap_or_default());
                            (
                                StatusCode::from_u16(delete_status).unwrap(),
                                "{}".to_string(),
                            )
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), writes, deletes)
    }

    #[tokio::test]
    async fn reconcile_adds_new_and_delete_throughs_stale() {
        let (endpoint, writes, deletes) = spawn_reconcile_stub(200).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);

        let s1 = c.reconcile_ingested("home", &lines(), &manifest).await;
        assert_eq!((s1.mirrored, s1.deleted), (2, 0));

        // Line 0 dropped from canonical; a new line appears → 1 write + 1 delete
        let next = vec![
            lines()[1].clone(),
            MemoryLine {
                text: "Prefers window seats.".into(),
                seq: 1,
            },
        ];
        let s2 = c.reconcile_ingested("home", &next, &manifest).await;
        assert_eq!((s2.mirrored, s2.deleted, s2.delete_failed), (1, 1, 0));
        let deleted = deletes.lock().unwrap().clone();
        assert_eq!(deleted.len(), 1);
        assert!(deleted[0].starts_with("viking://user/default/memories/home/mem_"));
        assert_eq!(writes.lock().unwrap().len(), 3);

        // Converged: a third pass is a full no-op.
        let s3 = c.reconcile_ingested("home", &next, &manifest).await;
        assert!(s3.is_noop());
    }

    #[tokio::test]
    async fn reconcile_empty_is_revocation_delete_through() {
        let (endpoint, _writes, deletes) = spawn_reconcile_stub(200).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);

        c.reconcile_ingested("home", &lines(), &manifest).await;
        // Grant revoked → the worker 403s → the mirror reconciles onto EMPTY.
        let s = c.reconcile_ingested("home", &[], &manifest).await;
        assert_eq!((s.deleted, s.mirrored), (2, 0));
        assert_eq!(deletes.lock().unwrap().len(), 2);
        // Manifest drained → a re-grant re-mirrors from scratch.
        assert!(read_manifest(&manifest).is_empty());
    }

    #[tokio::test]
    async fn reconcile_failed_delete_stays_in_manifest_for_retry() {
        let (endpoint, _writes, deletes) = spawn_reconcile_stub(500).await;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("ov-ingested.txt");
        let c = client(endpoint);

        c.reconcile_ingested("home", &lines(), &manifest).await;
        let s = c.reconcile_ingested("home", &[], &manifest).await;
        assert_eq!((s.deleted, s.delete_failed), (0, 2));
        assert_eq!(deletes.lock().unwrap().len(), 2);
        // Entries survive the failed delete → the NEXT pass retries them.
        assert_eq!(read_manifest(&manifest).len(), 2);
    }

    #[test]
    fn line_hash_is_stable_and_short() {
        let a = line_hash("Allergic to peanuts.");
        assert_eq!(a.len(), 16);
        assert_eq!(a, line_hash("Allergic to peanuts."));
        assert_ne!(a, line_hash("Chengdu trip — Apr 12 to 16."));
    }
}
