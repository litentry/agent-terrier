//! OpenViking engine adapter — plan `docs/plan/agentkeys-memory-design.md` §6a.
//!
//! OpenViking (`volcengine/OpenViking`) is a self-hosted context database. In
//! AgentKeys' Model-B integration it is the pluggable RANKING engine *behind*
//! our gate: AgentKeys still STORES (K3-encrypted S3) + GATES (cap / scope /
//! namespace / audit) + DELIVERS (the `pre_llm_call` hook). OpenViking only
//! reorders. The HTTP contract below is taken verbatim from the Hermes
//! `plugins/memory/openviking` client — not guessed:
//!
//!   base    http://127.0.0.1:1933  (OPENVIKING_ENDPOINT)
//!   headers X-OpenViking-Agent / -Account / -User, plus X-API-Key +
//!           `Authorization: Bearer <key>` when OPENVIKING_API_KEY is set
//!   GET  /health                       -> 200 when up
//!   POST /api/v1/search/find {query, top_k}
//!        -> {result:{results:[{score, content|text, uri}]}}
//!   POST /api/v1/content/write {uri, content, mode:"create"}
//!   error envelope: HTTP >= 400, or {status:"error", error:{code,message}}
//!
//! SAFETY — the gate bounds visibility: [`rank_gate_bounded`] only ever returns
//! lines that were in the gate-authorized input set. OpenViking can change the
//! ORDER but can never WIDEN what is injectable; a compromised/over-broad
//! OpenViking cannot leak content the gate did not authorize. On any error or
//! empty result it returns `None`, so the caller falls back to a deterministic
//! engine (recency) — OpenViking is never load-bearing for availability.

use serde::Deserialize;

use agentkeys_memory_engine::{MemoryLine, SelectionBudget};

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

#[derive(Debug, Deserialize)]
struct FindEnvelope {
    #[serde(default)]
    result: Option<FindResult>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FindResult {
    #[serde(default)]
    results: Vec<FindHit>,
}

#[derive(Debug, Deserialize)]
struct FindHit {
    #[serde(default)]
    score: f64,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

impl FindHit {
    fn body(&self) -> Option<&str> {
        self.content.as_deref().or(self.text.as_deref())
    }
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
        let mut req = req.header("X-OpenViking-Agent", &self.agent);
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

    /// `POST /api/v1/search/find` — semantic ranking. Returns `(score, text)`
    /// hits in OpenViking's ranked order.
    pub async fn search_find(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<(f64, String)>, OpenVikingError> {
        let url = format!("{}/api/v1/search/find", self.endpoint);
        let resp = self
            .with_headers(
                self.http
                    .post(&url)
                    .json(&serde_json::json!({ "query": query, "top_k": top_k })),
            )
            .send()
            .await
            .map_err(|e| OpenVikingError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| OpenVikingError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(OpenVikingError::Http {
                status: status.as_u16(),
                body,
            });
        }
        let envelope: FindEnvelope =
            serde_json::from_str(&body).map_err(|e| OpenVikingError::Parse(e.to_string()))?;
        if envelope.status.as_deref() == Some("error") {
            return Err(OpenVikingError::Http {
                status: status.as_u16(),
                body,
            });
        }
        Ok(envelope
            .result
            .map(|r| r.results)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|hit| hit.body().map(|b| (hit.score, b.to_string())))
            .collect())
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
            let uri = format!(
                "viking://user/{}/memories/{namespace}/mem_{hash}.md",
                if self.user.is_empty() {
                    "default"
                } else {
                    &self.user
                }
            );
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
            let _ = writeln!(f, "{e}");
        }
    }
}

fn normalize(text: &str) -> String {
    text.trim().to_lowercase()
}

/// Rank gate-authorized `lines` via OpenViking, bounded by the gate.
///
/// Returns `Some(reordered subset of `lines`)` on success, or `None` on any
/// error / empty / no-match so the caller falls back to a deterministic engine.
/// A hit maps to a line when their normalized text is equal or one contains the
/// other (OpenViking may return a tiered abstract rather than the verbatim
/// line). Only `lines` entries are ever returned — never a raw OpenViking hit.
pub async fn rank_gate_bounded(
    client: &OpenVikingClient,
    query: &str,
    lines: &[MemoryLine],
    budget: &SelectionBudget,
) -> Option<Vec<MemoryLine>> {
    if lines.is_empty() {
        return None;
    }
    let top_k = budget.max_lines.unwrap_or(lines.len()).max(1);
    let hits = client.search_find(query, top_k).await.ok()?;
    if hits.is_empty() {
        return None;
    }
    let mut out: Vec<MemoryLine> = Vec::new();
    let mut taken = std::collections::HashSet::new();
    for (_score, hit_text) in hits {
        let hit_norm = normalize(&hit_text);
        if let Some(line) = lines.iter().find(|l| {
            let line_norm = normalize(&l.text);
            line_norm == hit_norm || hit_norm.contains(&line_norm) || line_norm.contains(&hit_norm)
        }) {
            if taken.insert(line.seq) {
                out.push(line.clone());
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    if let Some(max) = budget.max_lines {
        out.truncate(max);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};

    async fn spawn_stub(response: serde_json::Value) -> String {
        let app = Router::new()
            .route(
                "/api/v1/search/find",
                post(|State(body): State<serde_json::Value>| async move { Json(body) }),
            )
            .with_state(response);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

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

    #[tokio::test]
    async fn search_find_parses_score_ordered_hits() {
        let endpoint = spawn_stub(serde_json::json!({
            "result": {"results": [
                {"score": 0.9, "content": "Allergic to peanuts."},
                {"score": 0.7, "text": "Chengdu trip — Apr 12 to 16."}
            ]}
        }))
        .await;
        let hits = client(endpoint).search_find("peanut", 5).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].1, "Allergic to peanuts.");
    }

    #[tokio::test]
    async fn rank_is_gate_bounded_and_reordered() {
        // OpenViking ranks peanuts top, then chengdu, AND returns an
        // unauthorized line that is NOT in the gate set — it must be dropped.
        let endpoint = spawn_stub(serde_json::json!({
            "result": {"results": [
                {"score": 0.9, "content": "Allergic to peanuts."},
                {"score": 0.8, "content": "SECRET not in the authorized set"},
                {"score": 0.7, "content": "Chengdu trip — Apr 12 to 16."}
            ]}
        }))
        .await;
        let budget = SelectionBudget {
            max_lines: Some(5),
            max_bytes: None,
        };
        let out = rank_gate_bounded(&client(endpoint), "peanut", &lines(), &budget)
            .await
            .unwrap();
        let texts: Vec<&str> = out.iter().map(|l| l.text.as_str()).collect();
        // gate-bound: only the two authorized lines, in OpenViking's order
        assert_eq!(
            texts,
            vec!["Allergic to peanuts.", "Chengdu trip — Apr 12 to 16."]
        );
    }

    #[tokio::test]
    async fn empty_results_falls_back_to_none() {
        let endpoint = spawn_stub(serde_json::json!({ "result": {"results": []} })).await;
        let budget = SelectionBudget::default();
        assert!(rank_gate_bounded(&client(endpoint), "q", &lines(), &budget)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn budget_caps_results() {
        let endpoint = spawn_stub(serde_json::json!({
            "result": {"results": [
                {"score": 0.9, "content": "Allergic to peanuts."},
                {"score": 0.7, "content": "Chengdu trip — Apr 12 to 16."}
            ]}
        }))
        .await;
        let budget = SelectionBudget {
            max_lines: Some(1),
            max_bytes: None,
        };
        let out = rank_gate_bounded(&client(endpoint), "q", &lines(), &budget)
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "Allergic to peanuts.");
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

    #[test]
    fn line_hash_is_stable_and_short() {
        let a = line_hash("Allergic to peanuts.");
        assert_eq!(a.len(), 16);
        assert_eq!(a, line_hash("Allergic to peanuts."));
        assert_ne!(a, line_hash("Chengdu trip — Apr 12 to 16."));
    }
}
