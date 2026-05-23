//! Localhost cap-token proxy — v2 stage-1 sidecar daemon role.
//!
//! Per arch.md §6 + §15.1: the daemon is the operator's local trust
//! anchor for agents. It serves a minimal HTTP surface on a Unix
//! socket (`$XDG_RUNTIME_DIR/agentkeys-proxy.sock` or `/tmp/agentkeys-…`)
//! that:
//!
//!   - mints cap-tokens by calling the broker's `/v1/cap/cred-*`
//!     endpoints with the operator's session JWT;
//!   - caches successful cap responses for up to 5 min (TTL the broker
//!     embeds in `expires_at`);
//!   - fails closed when the broker has been silent for > 60 s
//!     (`last_broker_contact` is updated on every successful call);
//!   - emits a one-line JSON audit row per request to stdout for the
//!     operator's local audit log + the eventual chain-batch relay.
//!
//! Stage-1 simplification per arch.md §22b (codex audit follow-up):
//!   - **No SO_PEERCRED enforcement**. Socket access is gated only by
//!     the 0600 perm bit + parent-dir 0700 (operator-uid owned). On a
//!     multi-user box where another local user can read the operator's
//!     `$XDG_RUNTIME_DIR`, that user can connect and the proxy will
//!     accept the request. Stage 2 (#90) adds peer-credential reading
//!     via tokio's `UnixStream::peer_cred()` + per-(uid, binary_path)
//!     policy match before any cap-mint.
//!   - **Per-caller scope policies stubbed** — allow-all when no
//!     policy file is loaded. Stage 2 (#90) adds policy file loading +
//!     deny-by-default + per-caller spend quotas.
//!
//! Both gaps are tracked in #90's "Daemon hardening" task list.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// In-memory cap-token cache. Key = `(operator_omni, actor_omni, service, op)`.
/// Value = (cached_response_json, fetched_at, expires_at).
#[derive(Debug, Default)]
pub struct CapCache {
    entries: HashMap<String, CachedCap>,
}

#[derive(Debug, Clone)]
pub struct CachedCap {
    body: serde_json::Value,
    fetched_at: Instant,
    expires_at_unix: u64,
}

#[derive(Debug)]
pub struct ProxyState {
    pub broker_url: String,
    pub session_jwt: String,
    pub cache: RwLock<CapCache>,
    /// Wall-clock of the most recent successful broker call. Daemon
    /// fails closed when (now - last_broker_contact) > BROKER_STALE_TTL.
    pub last_broker_contact: RwLock<Instant>,
    pub http: reqwest::Client,
}

pub type SharedProxyState = Arc<ProxyState>;

/// Hard fail-closed threshold per arch.md §6.
const BROKER_STALE_TTL: Duration = Duration::from_secs(60);
/// Cache hit TTL — capped by both the broker's `expires_at` (authoritative)
/// AND this client-side ceiling (defense in depth).
const CACHE_HIT_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CapRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    reason: &'static str,
}

/// Build the proxy router. The caller binds it to a unix socket or
/// TCP listener; `main` wires the listener.
pub fn build_router(state: SharedProxyState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/cap/cred-store", post(cap_cred_store))
        .route("/v1/cap/cred-fetch", post(cap_cred_fetch))
        .with_state(state)
}

/// Build a fresh ProxyState. Tests instantiate this directly; the CLI
/// `agentkeys-daemon proxy` subcommand pulls broker_url + JWT from env.
pub fn build_state(broker_url: String, session_jwt: String) -> SharedProxyState {
    Arc::new(ProxyState {
        broker_url,
        session_jwt,
        cache: RwLock::new(CapCache::default()),
        // Pre-seeded with now() so the first request doesn't fail-closed
        // before any broker call has happened.
        last_broker_contact: RwLock::new(Instant::now()),
        http: reqwest::Client::new(),
    })
}

// ─── handlers ──────────────────────────────────────────────────────────

async fn healthz(State(state): State<SharedProxyState>) -> Json<serde_json::Value> {
    let last = *state.last_broker_contact.read().await;
    let stale = last.elapsed() > BROKER_STALE_TTL;
    Json(serde_json::json!({
        "ok": !stale,
        "broker_stale": stale,
        "last_broker_contact_seconds_ago": last.elapsed().as_secs(),
    }))
}

async fn cap_cred_store(
    State(state): State<SharedProxyState>,
    Json(req): Json<CapRequest>,
) -> impl IntoResponse {
    handle_cap(state, req, "cred-store", "store").await
}

async fn cap_cred_fetch(
    State(state): State<SharedProxyState>,
    Json(req): Json<CapRequest>,
) -> impl IntoResponse {
    handle_cap(state, req, "cred-fetch", "fetch").await
}

async fn handle_cap(
    state: SharedProxyState,
    req: CapRequest,
    upstream_path: &'static str,
    op_label: &'static str,
) -> axum::response::Response {
    // 1. fail-closed check.
    let last = *state.last_broker_contact.read().await;
    if last.elapsed() > BROKER_STALE_TTL {
        emit_audit_line(&req, op_label, "fail_closed_stale_broker", false);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: format!("broker silent for {}s", last.elapsed().as_secs()),
                reason: "broker_stale",
            }),
        )
            .into_response();
    }

    // 2. cache hit?
    let cache_key = format!(
        "{}:{}:{}:{}",
        req.operator_omni, req.actor_omni, req.service, op_label
    );
    {
        let cache = state.cache.read().await;
        if let Some(hit) = cache.entries.get(&cache_key) {
            let now_unix = unix_now();
            let still_fresh =
                hit.fetched_at.elapsed() < CACHE_HIT_TTL && now_unix < hit.expires_at_unix;
            if still_fresh {
                emit_audit_line(&req, op_label, "cache_hit", true);
                return (StatusCode::OK, Json(hit.body.clone())).into_response();
            }
        }
    }

    // 3. upstream broker call.
    let upstream = format!(
        "{}/v1/cap/{}",
        state.broker_url.trim_end_matches('/'),
        upstream_path
    );
    let resp = state
        .http
        .post(&upstream)
        .bearer_auth(&state.session_jwt)
        .json(&req)
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            emit_audit_line(&req, op_label, "broker_unreachable", false);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: e.to_string(),
                    reason: "broker_unreachable",
                }),
            )
                .into_response();
        }
    };
    let status = resp.status();
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            emit_audit_line(&req, op_label, "broker_invalid_json", false);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: e.to_string(),
                    reason: "broker_invalid_json",
                }),
            )
                .into_response();
        }
    };

    if !status.is_success() {
        emit_audit_line(&req, op_label, "broker_error", false);
        return (status, Json(body)).into_response();
    }

    // 4. update last_broker_contact + cache.
    {
        let mut last = state.last_broker_contact.write().await;
        *last = Instant::now();
    }
    let expires_at_unix = body
        .get("payload")
        .and_then(|p| p.get("expires_at"))
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| unix_now() + 300);
    {
        let mut cache = state.cache.write().await;
        cache.entries.insert(
            cache_key,
            CachedCap {
                body: body.clone(),
                fetched_at: Instant::now(),
                expires_at_unix,
            },
        );
    }

    emit_audit_line(&req, op_label, "broker_ok", true);
    (StatusCode::OK, Json(body)).into_response()
}

fn emit_audit_line(req: &CapRequest, op: &str, outcome: &str, ok: bool) {
    let line = serde_json::json!({
        "ts": unix_now(),
        "op": op,
        "outcome": outcome,
        "ok": ok,
        "service": req.service,
        "actor_omni": req.actor_omni,
        "operator_omni": req.operator_omni,
    });
    println!("{}", line);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve where to put the unix socket. Order:
///   1. `AGENTKEYS_PROXY_SOCKET` env var (operator override)
///   2. `$XDG_RUNTIME_DIR/agentkeys-proxy.sock` (Linux convention)
///   3. `~/.agentkeys/agentkeys-proxy.sock` (macOS + fallback)
pub fn resolve_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTKEYS_PROXY_SOCKET") {
        return PathBuf::from(p);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return Path::new(&xdg).join("agentkeys-proxy.sock");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    Path::new(&home)
        .join(".agentkeys")
        .join("agentkeys-proxy.sock")
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_socket_respects_env_override() {
        let _g = EnvGuard::set("AGENTKEYS_PROXY_SOCKET", "/tmp/test-proxy.sock");
        assert_eq!(resolve_socket_path(), PathBuf::from("/tmp/test-proxy.sock"));
    }

    #[test]
    fn unix_now_returns_recent_timestamp() {
        let t = unix_now();
        // Must be after 2026-01-01 (1767225600) — sanity-check the clock
        // is sensible, not a 0 from a botched conversion.
        assert!(t > 1_767_225_600, "got suspicious timestamp {t}");
    }

    #[test]
    fn cap_request_roundtrips_json() {
        let r = CapRequest {
            operator_omni: format!("0x{}", "a".repeat(64)),
            actor_omni: format!("0x{}", "b".repeat(64)),
            service: "openrouter".into(),
            device_key_hash: format!("0x{}", "c".repeat(64)),
            ttl_seconds: Some(180),
        };
        let j = serde_json::to_string(&r).unwrap();
        let r2: CapRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(r.service, r2.service);
        assert_eq!(r.ttl_seconds, r2.ttl_seconds);
    }

    #[tokio::test]
    async fn healthz_reports_fresh_broker() {
        let state = build_state("http://localhost:1".into(), "fake-jwt".into());
        let body = healthz(State(state)).await;
        let v = body.0;
        assert_eq!(v["ok"], serde_json::Value::Bool(true));
        assert_eq!(v["broker_stale"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn handle_cap_fails_closed_when_broker_stale() {
        let state = build_state("http://localhost:1".into(), "fake-jwt".into());
        // Force last_broker_contact to be old.
        {
            let mut last = state.last_broker_contact.write().await;
            *last = Instant::now()
                .checked_sub(BROKER_STALE_TTL + Duration::from_secs(5))
                .unwrap_or(*last);
        }
        let req = CapRequest {
            operator_omni: format!("0x{}", "a".repeat(64)),
            actor_omni: format!("0x{}", "b".repeat(64)),
            service: "openrouter".into(),
            device_key_hash: format!("0x{}", "c".repeat(64)),
            ttl_seconds: None,
        };
        let resp = handle_cap(state, req, "cred-fetch", "fetch").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // Lightweight env-guard so tests don't pollute each other.
    struct EnvGuard {
        key: &'static str,
        prior: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::set_var(key, val);
            Self { key, prior }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
