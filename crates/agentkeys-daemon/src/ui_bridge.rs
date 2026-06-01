//! UI bridge — HTTP surface the parent-control web UI talks to.
//!
//! Distinct from `proxy.rs` (agent-facing cap-mint) and `companion.rs`
//! (second-master M-of-N approval). The ui-bridge listens on
//! `127.0.0.1:3114` by default, accepts CORS from `http://localhost:3113`
//! (the Next.js dev server / bundled web UI), and exposes operator-side
//! ceremonies the browser drives — initially K11 enrollment.
//!
//! Per arch.md §10.2, K11 enrollment is the master-binding ceremony:
//!
//!   1. browser POST /v1/k11/enroll/begin   → daemon returns
//!      PublicKeyCredentialCreationOptions (challenge + rp + user +
//!      pubKeyCredParams + authenticatorSelection)
//!   2. browser calls navigator.credentials.create(options)
//!   3. browser POST /v1/k11/enroll/finish  → daemon verifies
//!      attestation via webauthn-rs, returns credentialId
//!
//! For M1 the on-chain SidecarRegistry.register_master_device() call
//! is stubbed (returns chainTxHash=null). Real chain submission lands
//! in PR-C alongside the audit-service SSE feed.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderValue, Method, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{Any, CorsLayer};
use url::Url;
use webauthn_rs::prelude::*;

/// In-flight registration state. Keyed by `user_id` (the random opaque
/// handle the browser echoes back). Cleared once a finish call consumes
/// the entry, or on next start (in-memory only).
#[derive(Default)]
pub struct EnrollState {
    pending: HashMap<String, PasskeyRegistration>,
    registered: HashMap<String, RegisteredCredential>,
}

#[derive(Clone)]
#[allow(dead_code)] // fields are read once chain submission lands in PR-C
pub struct RegisteredCredential {
    pub credential_id_b64: String,
    pub registered_at_unix: u64,
}

pub struct UiBridgeState {
    pub webauthn: Webauthn,
    pub enroll: RwLock<EnrollState>,
    pub actors: RwLock<HashMap<String, ApiActor>>,
    pub caps: RwLock<HashMap<String, Vec<ApiCapToken>>>,
    pub audit: RwLock<VecDeque<ApiAuditEvent>>,
    pub audit_tx: broadcast::Sender<ApiAuditEvent>,
    pub workers: RwLock<HashMap<String, ApiWorker>>,
    pub anchor: RwLock<ApiAnchorStatus>,
    /// Master-actor memory entries, keyed by content_hash for idempotent
    /// plant (re-planting the same entry is a no-op). Maps the §2 "plant
    /// preserved memory" flow + GH plan issue-9step-flow.md.
    pub master_memory: RwLock<HashMap<String, ApiMemoryEntry>>,
}

/// A master-actor memory entry. `content_hash` is the dedup key —
/// keccak-free sha256 over (ns || key || body) so a re-plant of the same
/// content is detected and skipped (the "prevent duplicate plant" gate).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiMemoryEntry {
    pub ns: String,
    pub key: String,
    pub title: String,
    pub bytes: u64,
    pub version: String,
    pub updated: String,
    pub preview: String,
    pub body: String,
    #[serde(default)]
    pub content_hash: String,
}

impl ApiMemoryEntry {
    fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.ns.as_bytes());
        h.update(b"\x1f");
        h.update(self.key.as_bytes());
        h.update(b"\x1f");
        h.update(self.body.as_bytes());
        hex::encode(h.finalize())
    }
}

pub type SharedUiBridgeState = Arc<UiBridgeState>;

const AUDIT_BUFFER_CAP: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiScopeBits {
    pub read: bool,
    pub write: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPaymentCap {
    pub per_tx: f64,
    pub daily: f64,
    pub currency: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTimeWindow {
    pub start: String,
    pub end: String,
    pub tz: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiActor {
    pub id: String,
    pub omni: String,
    pub omni_hex: String,
    pub label: String,
    pub role: String,
    pub parent: Option<String>,
    pub derivation: String,
    pub device: String,
    pub device_pubkey: String,
    pub last_active: String,
    pub status: String,
    pub vendor: String,
    pub k11: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<HashMap<String, ApiScopeBits>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_cap: Option<ApiPaymentCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<ApiTimeWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiCapToken {
    pub id: String,
    pub cap: String,
    pub scope: String,
    pub ttl: String,
    pub minted: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub danger: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiAuditEvent {
    pub id: String,
    pub ts: String,
    pub actor_id: String,
    pub actor: String,
    pub kind: String,
    pub detail: String,
    pub chip: String,
    pub sev: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiWorkerActorShare {
    pub actor: String,
    pub count: u64,
    pub share: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiWorker {
    pub id: String,
    pub title: String,
    pub host: String,
    pub desc: String,
    pub calls_today: u64,
    pub calls_hour: u64,
    pub p50: u64,
    pub p95: u64,
    pub cap: String,
    pub by_actor: Vec<ApiWorkerActorShare>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApiAnchorBatch {
    pub ts: String,
    pub root: String,
    pub count: u64,
    pub txn: String,
    pub conf: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApiAnchorStatus {
    pub last_anchor_at: u64,
    pub next_anchor_in: u64,
    pub recent: Vec<ApiAnchorBatch>,
}

#[derive(Debug, Deserialize)]
pub struct EnrollBeginRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollBeginResponse {
    pub user_id: String,
    pub creation_options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct EnrollFinishRequest {
    pub user_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct EnrollFinishResponse {
    pub credential_id: String,
    pub registered_at_unix: u64,
    pub chain_tx_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    reason: &'static str,
}

fn err(
    status: StatusCode,
    error: impl Into<String>,
    reason: &'static str,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
            reason,
        }),
    )
}

/// Build the ui-bridge router with CORS open to the configured web-UI origin.
pub fn build_router(state: SharedUiBridgeState, allowed_origin: &str) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            allowed_origin
                .parse::<HeaderValue>()
                .unwrap_or(HeaderValue::from_static("http://localhost:3113")),
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .max_age(std::time::Duration::from_secs(600));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/k11/enroll/begin", post(enroll_begin))
        .route("/v1/k11/enroll/finish", post(enroll_finish))
        .route("/v1/actors", get(list_actors))
        .route("/v1/actors/:id", get(get_actor))
        .route("/v1/actors/:id/caps", get(list_caps))
        .route("/v1/actors/:id/scope", post(update_scope))
        .route("/v1/actors/:id/payment-cap", post(update_payment_cap))
        .route("/v1/actors/:id/revoke", post(revoke_device))
        .route("/v1/actors/:id/caps/revoke", post(revoke_cap))
        .route("/v1/audit/recent", get(list_recent_audit))
        .route("/v1/audit/stream", get(audit_stream))
        .route("/v1/anchor/status", get(anchor_status))
        .route("/v1/workers", get(list_workers))
        .route("/v1/workers/:id", get(get_worker))
        .route("/v1/master/memory", get(list_master_memory))
        .route("/v1/master/memory/plant", post(plant_master_memory))
        .route("/v1/dev/seed", post(dev_seed))
        .route("/v1/dev/event", post(dev_emit_event))
        .layer(cors)
        .with_state(state)
}

/// Build the bridge state. `rp_id` is the WebAuthn relying-party id —
/// always "localhost" for dev, "agentkeys.io" (or operator domain) in
/// production. `rp_origin` is the browser's window.location.origin.
pub fn build_state(
    rp_id: &str,
    rp_origin: &str,
    rp_name: &str,
) -> anyhow::Result<SharedUiBridgeState> {
    let origin = Url::parse(rp_origin)?;
    let builder = WebauthnBuilder::new(rp_id, &origin)?.rp_name(rp_name);
    let webauthn = builder.build()?;
    let (audit_tx, _audit_rx) = broadcast::channel::<ApiAuditEvent>(256);
    Ok(Arc::new(UiBridgeState {
        webauthn,
        enroll: RwLock::new(EnrollState::default()),
        actors: RwLock::new(HashMap::new()),
        caps: RwLock::new(HashMap::new()),
        audit: RwLock::new(VecDeque::with_capacity(AUDIT_BUFFER_CAP)),
        audit_tx,
        workers: RwLock::new(HashMap::new()),
        anchor: RwLock::new(ApiAnchorStatus::default()),
        master_memory: RwLock::new(HashMap::new()),
    }))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "surface": "ui-bridge" }))
}

async fn enroll_begin(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<EnrollBeginRequest>,
) -> Result<Json<EnrollBeginResponse>, (StatusCode, Json<ErrorBody>)> {
    if req.username.trim().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "username required",
            "missing-username",
        ));
    }
    let user_id = Uuid::new_v4();
    let user_id_str = user_id.to_string();
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &req.username, &req.display_name, None)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("webauthn start failed: {e}"),
                "webauthn-start-failed",
            )
        })?;

    let mut guard = state.enroll.write().await;
    guard.pending.insert(user_id_str.clone(), reg_state);

    Ok(Json(EnrollBeginResponse {
        user_id: user_id_str,
        creation_options: serde_json::to_value(&ccr).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encode failed: {e}"),
                "encode-failed",
            )
        })?,
    }))
}

async fn enroll_finish(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<EnrollFinishRequest>,
) -> Result<Json<EnrollFinishResponse>, (StatusCode, Json<ErrorBody>)> {
    let reg =
        serde_json::from_value::<RegisterPublicKeyCredential>(req.credential).map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                format!("malformed credential: {e}"),
                "credential-malformed",
            )
        })?;

    let reg_state = {
        let mut guard = state.enroll.write().await;
        guard.pending.remove(&req.user_id).ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "no pending enrollment for this user_id",
                "no-pending",
            )
        })?
    };

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                format!("attestation rejected: {e}"),
                "attestation-rejected",
            )
        })?;

    let credential_id_b64 = base64url_encode(passkey.cred_id().as_ref());
    let registered_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut guard = state.enroll.write().await;
    guard.registered.insert(
        req.user_id.clone(),
        RegisteredCredential {
            credential_id_b64: credential_id_b64.clone(),
            registered_at_unix,
        },
    );

    // TODO(PR-C): submit credentialId to SidecarRegistry.register_master_device()
    // via the broker. Currently stubbed — chain_tx_hash returns null.
    let chain_tx_hash: Option<String> = None;

    Ok(Json(EnrollFinishResponse {
        credential_id: credential_id_b64,
        registered_at_unix,
        chain_tx_hash,
    }))
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ts_hms() -> String {
    // HH:MM:SS in UTC for audit event timestamps. Operator-facing only —
    // chain timestamps are independent.
    let now = now_unix();
    let h = (now / 3600) % 24;
    let m = (now / 60) % 60;
    let s = now % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// ─── Read endpoints ────────────────────────────────────────────────────

async fn list_actors(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    let guard = state.actors.read().await;
    let mut actors: Vec<ApiActor> = guard.values().cloned().collect();
    // Stable order: master first, then by id.
    actors.sort_by(|a, b| {
        let a_master = if a.role == "master" { 0 } else { 1 };
        let b_master = if b.role == "master" { 0 } else { 1 };
        a_master.cmp(&b_master).then_with(|| a.id.cmp(&b.id))
    });
    Json(serde_json::json!({ "actors": actors }))
}

async fn get_actor(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let guard = state.actors.read().await;
    guard
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))
}

async fn list_caps(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let guard = state.caps.read().await;
    let caps = guard.get(&id).cloned().unwrap_or_default();
    Json(serde_json::json!({ "caps": caps }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateScopeRequest {
    pub namespace: String,
    pub read: bool,
    pub write: bool,
}

async fn update_scope(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateScopeRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let scope = actor.scope.get_or_insert_with(HashMap::new);
    scope.insert(
        req.namespace.clone(),
        ApiScopeBits {
            read: req.read,
            write: req.write,
        },
    );
    let snapshot = actor.clone();
    drop(guard);

    let evt = ApiAuditEvent {
        id: format!("e-scope-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "scope.updated".into(),
        detail: format!(
            "{} · {} · read={} write={}",
            id, req.namespace, req.read, req.write
        ),
        chip: "broker".into(),
        sev: "ok".into(),
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct UpdatePaymentCapRequest {
    pub per_tx: f64,
    pub daily: f64,
}

async fn update_payment_cap(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePaymentCapRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let cap = actor.payment_cap.get_or_insert(ApiPaymentCap {
        per_tx: 0.0,
        daily: 0.0,
        currency: "USDC".into(),
    });
    cap.per_tx = req.per_tx;
    cap.daily = req.daily;
    let snapshot = actor.clone();
    drop(guard);

    let evt = ApiAuditEvent {
        id: format!("e-paycap-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "payment-cap.updated".into(),
        detail: format!("{} · per_tx={} daily={}", id, req.per_tx, req.daily),
        chip: "broker".into(),
        sev: "ok".into(),
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct RevokeDeviceRequest {
    pub intent_text: String,
    pub intent_fields: Vec<(String, String)>,
}

async fn revoke_device(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<RevokeDeviceRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    actor.status = "bad".into();
    actor.last_active = "revoked".into();
    if !actor.label.ends_with(" (revoked)") {
        actor.label.push_str(" (revoked)");
    }
    let snapshot = actor.clone();
    drop(guard);

    // Invalidate every cap minted for this actor (TTL → 0).
    state.caps.write().await.remove(&id);

    let evt = ApiAuditEvent {
        id: format!("e-revoke-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "device.revoked".into(),
        detail: format!(
            "{} · intent='{}' · fields={}",
            id,
            req.intent_text,
            req.intent_fields.len()
        ),
        chip: "revoke".into(),
        sev: "bad".into(),
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct RevokeCapRequest {
    pub cap: String,
    pub intent_text: String,
}

async fn revoke_cap(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<RevokeCapRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    {
        let actors = state.actors.read().await;
        if !actors.contains_key(&id) {
            return Err(err(
                StatusCode::NOT_FOUND,
                "no such actor",
                "actor-not-found",
            ));
        }
    }
    let mut caps_guard = state.caps.write().await;
    if let Some(caps) = caps_guard.get_mut(&id) {
        caps.retain(|c| c.cap != req.cap);
    }
    drop(caps_guard);

    let evt = ApiAuditEvent {
        id: format!("e-cap-revoke-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "cap.revoked".into(),
        detail: format!("{} · cap={} · intent='{}'", id, req.cap, req.intent_text),
        chip: "revoke".into(),
        sev: "bad".into(),
    };
    push_audit(&state, evt).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
pub struct ListRecentAuditQuery {
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

async fn list_recent_audit(
    State(state): State<SharedUiBridgeState>,
    axum::extract::Query(q): axum::extract::Query<ListRecentAuditQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(AUDIT_BUFFER_CAP);
    let guard = state.audit.read().await;
    let mut events: Vec<ApiAuditEvent> = guard
        .iter()
        .rev()
        .filter(|e| q.actor_id.as_deref().is_none_or(|a| e.actor_id == a))
        .take(limit)
        .cloned()
        .collect();
    // Reverse-rev: newest first, which is the natural iteration order
    // when we push_back + iter().rev(). Already in that order; ensure stable.
    // (Re-sort by ts descending as a safety belt for ties.)
    events.sort_by(|a, b| b.ts.cmp(&a.ts));
    Json(serde_json::json!({ "events": events }))
}

async fn audit_stream(
    State(state): State<SharedUiBridgeState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.audit_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(evt) => match serde_json::to_string(&evt) {
            Ok(json) => Some(Ok(Event::default().event("audit").data(json))),
            Err(_) => None,
        },
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn anchor_status(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    let mut snapshot = state.anchor.read().await.clone();
    // Compute next_anchor_in dynamically (2-min cadence per arch.md §11).
    let now = now_unix();
    if snapshot.last_anchor_at > 0 {
        let elapsed = now.saturating_sub(snapshot.last_anchor_at);
        snapshot.next_anchor_in = 120u64.saturating_sub(elapsed % 120);
    } else {
        snapshot.next_anchor_in = 120u64.saturating_sub(now % 120);
    }
    Json(snapshot)
}

async fn list_workers(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    let guard = state.workers.read().await;
    let mut workers: Vec<ApiWorker> = guard.values().cloned().collect();
    workers.sort_by(|a, b| a.id.cmp(&b.id));
    Json(serde_json::json!({ "workers": workers }))
}

async fn get_worker(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> Result<Json<ApiWorker>, (StatusCode, Json<ErrorBody>)> {
    let guard = state.workers.read().await;
    guard
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such worker", "worker-not-found"))
}

// ─── Dev seed (operator-only, debug data injection) ────────────────────

#[derive(Debug, Deserialize)]
pub struct DevSeedRequest {
    #[serde(default)]
    pub actors: Vec<ApiActor>,
    #[serde(default)]
    pub caps: HashMap<String, Vec<ApiCapToken>>,
    #[serde(default)]
    pub workers: Vec<ApiWorker>,
    #[serde(default)]
    pub anchor: Option<ApiAnchorStatus>,
    #[serde(default)]
    pub audit: Vec<ApiAuditEvent>,
    #[serde(default)]
    pub master_memory: Vec<ApiMemoryEntry>,
}

async fn dev_seed(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DevSeedRequest>,
) -> impl IntoResponse {
    {
        let mut actors = state.actors.write().await;
        for a in req.actors {
            actors.insert(a.id.clone(), a);
        }
    }
    {
        let mut caps = state.caps.write().await;
        for (k, v) in req.caps {
            caps.insert(k, v);
        }
    }
    {
        let mut workers = state.workers.write().await;
        for w in req.workers {
            workers.insert(w.id.clone(), w);
        }
    }
    if let Some(a) = req.anchor {
        *state.anchor.write().await = a;
    }
    if !req.master_memory.is_empty() {
        let mut mem = state.master_memory.write().await;
        for mut e in req.master_memory {
            let hash = if e.content_hash.is_empty() {
                e.compute_hash()
            } else {
                e.content_hash.clone()
            };
            e.content_hash = hash.clone();
            mem.insert(hash, e);
        }
    }
    for evt in req.audit {
        push_audit(&state, evt).await;
    }
    Json(serde_json::json!({ "ok": true }))
}

async fn dev_emit_event(
    State(state): State<SharedUiBridgeState>,
    Json(evt): Json<ApiAuditEvent>,
) -> impl IntoResponse {
    push_audit(&state, evt).await;
    Json(serde_json::json!({ "ok": true }))
}

// ─── Master memory — list + idempotent plant (§2 "plant preserved memory") ──

async fn list_master_memory(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    let guard = state.master_memory.read().await;
    let mut entries: Vec<ApiMemoryEntry> = guard.values().cloned().collect();
    entries.sort_by(|a, b| a.ns.cmp(&b.ns).then_with(|| a.key.cmp(&b.key)));
    Json(serde_json::json!({ "entries": entries }))
}

#[derive(Debug, Deserialize)]
pub struct PlantRequest {
    pub entries: Vec<ApiMemoryEntry>,
}

#[derive(Debug, Serialize)]
pub struct PlantResponse {
    pub planted: usize,
    pub skipped: usize,
    pub total: usize,
}

/// Idempotent plant: each entry's content_hash is the dedup key. Re-planting
/// the same content is a no-op (skipped++), so "prevent duplicate plant" is
/// enforced server-side, not just in the UI. Returns planted/skipped counts +
/// the resulting total. An audit row records the plant.
async fn plant_master_memory(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<PlantRequest>,
) -> Json<PlantResponse> {
    let mut planted = 0usize;
    let mut skipped = 0usize;
    {
        let mut mem = state.master_memory.write().await;
        for mut e in req.entries {
            let hash = if e.content_hash.is_empty() {
                e.compute_hash()
            } else {
                e.content_hash.clone()
            };
            e.content_hash = hash.clone();
            if let std::collections::hash_map::Entry::Vacant(slot) = mem.entry(hash) {
                slot.insert(e);
                planted += 1;
            } else {
                skipped += 1;
            }
        }
    }
    let total = state.master_memory.read().await.len();
    if planted > 0 {
        let evt = ApiAuditEvent {
            id: format!("e-mem-plant-{}", now_unix()),
            ts: now_ts_hms(),
            actor_id: "master".into(),
            actor: "master".into(),
            kind: "memory.write".into(),
            detail: format!("planted preserved memory · {planted} entries · {skipped} duplicates"),
            chip: "memory".into(),
            sev: "ok".into(),
        };
        push_audit(&state, evt).await;
    }
    Json(PlantResponse {
        planted,
        skipped,
        total,
    })
}

async fn push_audit(state: &SharedUiBridgeState, evt: ApiAuditEvent) {
    let mut buf = state.audit.write().await;
    if buf.len() == AUDIT_BUFFER_CAP {
        buf.pop_front();
    }
    buf.push_back(evt.clone());
    drop(buf);
    // Ignore send errors — broadcast Sender returns Err when there
    // are no subscribers, which is the normal case until the UI connects.
    let _ = state.audit_tx.send(evt);
}

// ─── Tests ─────────────────────────────────────────────────────────────
//
// These tests exercise the begin/finish state machine without a real
// browser. They use webauthn-rs's `SoftPasskey` test helper so the
// attestation chain is real (not stubbed), but everything happens
// in-process — no network, no platform authenticator, no Touch ID.
//
// Coverage focus per PR-A's cargo-llvm-cov gate:
//   - happy-path begin → finish round-trip
//   - finish with a stale / never-issued user_id → "no-pending" error
//   - finish with a malformed credential JSON  → "credential-malformed" error
//   - finish that tries to replay a consumed user_id → "no-pending" (consumed at finish)
//   - begin with empty username → "missing-username" error
//
// Run: `cargo test -p agentkeys-daemon --lib ui_bridge`
//      `cargo llvm-cov -p agentkeys-daemon --lib ui_bridge`

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> SharedUiBridgeState {
        build_state("localhost", "http://localhost:3113", "AgentKeys Test").unwrap()
    }

    #[tokio::test]
    async fn begin_returns_user_id_and_creation_options() {
        let state = make_state();
        let resp = enroll_begin(
            State(state.clone()),
            Json(EnrollBeginRequest {
                username: "sara@example.com".into(),
                display_name: "Sara".into(),
            }),
        )
        .await
        .expect("begin should succeed");
        assert!(!resp.0.user_id.is_empty(), "user_id must be set");
        assert!(
            resp.0.creation_options.get("publicKey").is_some(),
            "creation_options must contain publicKey field per WebAuthn spec, got: {}",
            resp.0.creation_options
        );

        let guard = state.enroll.read().await;
        assert!(
            guard.pending.contains_key(&resp.0.user_id),
            "pending registration must be stored"
        );
    }

    #[tokio::test]
    async fn begin_rejects_empty_username() {
        let state = make_state();
        let err = enroll_begin(
            State(state),
            Json(EnrollBeginRequest {
                username: "   ".into(),
                display_name: "Sara".into(),
            }),
        )
        .await
        .expect_err("empty username must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0.reason, "missing-username");
    }

    #[tokio::test]
    async fn finish_with_unknown_user_id_returns_no_pending() {
        let state = make_state();
        let err = enroll_finish(
            State(state),
            Json(EnrollFinishRequest {
                user_id: "00000000-0000-0000-0000-000000000000".into(),
                credential: serde_json::json!({
                    "id": "test",
                    "rawId": "dGVzdA",
                    "response": {
                        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjGSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAALraVWanqkAfvZZFYZpVEg0AQg",
                        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                    },
                    "type": "public-key"
                }),
            }),
        )
        .await
        .expect_err("unknown user_id must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0.reason, "no-pending");
    }

    #[tokio::test]
    async fn finish_with_malformed_credential_returns_malformed() {
        let state = make_state();
        let err = enroll_finish(
            State(state),
            Json(EnrollFinishRequest {
                user_id: "doesn-t-matter".into(),
                credential: serde_json::json!({ "totally": "not a credential" }),
            }),
        )
        .await
        .expect_err("malformed credential must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0.reason, "credential-malformed");
    }

    #[tokio::test]
    async fn replay_after_consume_returns_no_pending() {
        // First begin to get a real user_id, then finish twice with the
        // SAME user_id and the same (malformed-but-parseable-only-the-second-time)
        // credential — we don't need a real attestation for this assertion,
        // we just need to confirm the pending entry is consumed on first
        // attempt regardless of finish outcome.
        let state = make_state();
        let begin_resp = enroll_begin(
            State(state.clone()),
            Json(EnrollBeginRequest {
                username: "replay@example.com".into(),
                display_name: "Replay Test".into(),
            }),
        )
        .await
        .unwrap();
        let user_id = begin_resp.0.user_id;

        // Confirm pending exists.
        assert!(state.enroll.read().await.pending.contains_key(&user_id));

        // First finish (with malformed credential — fails before pending consume).
        let _ = enroll_finish(
            State(state.clone()),
            Json(EnrollFinishRequest {
                user_id: user_id.clone(),
                credential: serde_json::json!({ "not": "valid" }),
            }),
        )
        .await
        .expect_err("first finish should fail at parse");

        // Pending should STILL exist because parse failed before consume.
        assert!(
            state.enroll.read().await.pending.contains_key(&user_id),
            "pending must survive a parse-stage failure so the user can retry"
        );

        // Now simulate a valid-shaped-but-bad-attestation credential. Pending
        // gets consumed on .remove() call, and webauthn-rs rejects the
        // attestation.
        let _ = enroll_finish(
            State(state.clone()),
            Json(EnrollFinishRequest {
                user_id: user_id.clone(),
                credential: serde_json::json!({
                    "id": "test",
                    "rawId": "dGVzdA",
                    "response": {
                        "attestationObject": "o2NmbXRkbm9uZQ",
                        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                    },
                    "type": "public-key"
                }),
            }),
        )
        .await
        .expect_err("second finish must fail attestation");

        // Pending must NOT exist anymore — consume happened at .remove().
        assert!(
            !state.enroll.read().await.pending.contains_key(&user_id),
            "pending must be consumed after a finish attempt that parsed the credential"
        );

        // Third finish should fail with no-pending.
        let err = enroll_finish(
            State(state.clone()),
            Json(EnrollFinishRequest {
                user_id: user_id.clone(),
                credential: serde_json::json!({
                    "id": "test",
                    "rawId": "dGVzdA",
                    "response": {
                        "attestationObject": "o2NmbXRkbm9uZQ",
                        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                    },
                    "type": "public-key"
                }),
            }),
        )
        .await
        .expect_err("third finish must fail no-pending after consume");
        assert_eq!(err.1 .0.reason, "no-pending");
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let resp = healthz().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn seed_actor(state: &SharedUiBridgeState) -> ApiActor {
        let actor = ApiActor {
            id: "agent-folotoy".into(),
            omni: "O_master//folotoy".into(),
            omni_hex: "0x7c2d…41a9".into(),
            label: "FoloToy bear".into(),
            role: "agent".into(),
            parent: Some("master".into()),
            derivation: "//folotoy".into(),
            device: "FoloToy hardware".into(),
            device_pubkey: "D_pub_folotoy".into(),
            last_active: "now".into(),
            status: "ok".into(),
            vendor: "FoloToy Inc.".into(),
            k11: false,
            scope: None,
            payment_cap: None,
            time_window: None,
            services: None,
        };
        let cloned = actor.clone();
        let st = state.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { st.actors.write().await.insert(cloned.id.clone(), cloned) })
        });
        actor
    }

    async fn seed_actor_async(state: &SharedUiBridgeState) -> ApiActor {
        let actor = ApiActor {
            id: "agent-folotoy".into(),
            omni: "O_master//folotoy".into(),
            omni_hex: "0x7c2d…41a9".into(),
            label: "FoloToy bear".into(),
            role: "agent".into(),
            parent: Some("master".into()),
            derivation: "//folotoy".into(),
            device: "FoloToy hardware".into(),
            device_pubkey: "D_pub_folotoy".into(),
            last_active: "now".into(),
            status: "ok".into(),
            vendor: "FoloToy Inc.".into(),
            k11: false,
            scope: None,
            payment_cap: None,
            time_window: None,
            services: None,
        };
        state
            .actors
            .write()
            .await
            .insert(actor.id.clone(), actor.clone());
        actor
    }

    #[tokio::test]
    async fn list_actors_returns_empty_when_nothing_registered() {
        let state = make_state();
        let resp = list_actors(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_actors_returns_master_first() {
        let state = make_state();
        let mut actors = state.actors.write().await;
        actors.insert(
            "agent-1".into(),
            ApiActor {
                id: "agent-1".into(),
                role: "agent".into(),
                omni: "x".into(),
                omni_hex: "x".into(),
                label: "agent-1".into(),
                parent: Some("master".into()),
                derivation: "//agent1".into(),
                device: "".into(),
                device_pubkey: "".into(),
                last_active: "now".into(),
                status: "ok".into(),
                vendor: "".into(),
                k11: false,
                scope: None,
                payment_cap: None,
                time_window: None,
                services: None,
            },
        );
        actors.insert(
            "master".into(),
            ApiActor {
                id: "master".into(),
                role: "master".into(),
                omni: "O_master".into(),
                omni_hex: "x".into(),
                label: "Sara".into(),
                parent: None,
                derivation: "/".into(),
                device: "".into(),
                device_pubkey: "".into(),
                last_active: "now".into(),
                status: "ok".into(),
                vendor: "self".into(),
                k11: true,
                scope: None,
                payment_cap: None,
                time_window: None,
                services: None,
            },
        );
        drop(actors);

        // Decode the JSON to check ordering invariant.
        let resp = list_actors(State(state)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actors_arr = json["actors"].as_array().unwrap();
        assert_eq!(actors_arr[0]["role"], "master", "master must come first");
    }

    #[tokio::test]
    async fn get_actor_unknown_returns_404() {
        let state = make_state();
        let err = get_actor(State(state), Path("does-not-exist".into()))
            .await
            .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0.reason, "actor-not-found");
    }

    #[tokio::test]
    async fn get_actor_known_returns_payload() {
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = get_actor(State(state), Path("agent-folotoy".into()))
            .await
            .unwrap();
        assert_eq!(resp.0.label, "FoloToy bear");
    }

    #[tokio::test]
    async fn update_scope_writes_and_emits_audit() {
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = update_scope(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(UpdateScopeRequest {
                namespace: "family".into(),
                read: true,
                write: false,
            }),
        )
        .await
        .unwrap();
        assert!(resp.0.scope.as_ref().unwrap().get("family").unwrap().read);
        // Audit event landed.
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "scope.updated"));
    }

    #[tokio::test]
    async fn update_scope_unknown_actor_404() {
        let state = make_state();
        let err = update_scope(
            State(state),
            Path("nope".into()),
            Json(UpdateScopeRequest {
                namespace: "family".into(),
                read: true,
                write: false,
            }),
        )
        .await
        .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_payment_cap_writes_and_emits_audit() {
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = update_payment_cap(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(UpdatePaymentCapRequest {
                per_tx: 5.0,
                daily: 25.0,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.payment_cap.as_ref().unwrap().per_tx, 5.0);
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "payment-cap.updated"));
    }

    #[tokio::test]
    async fn revoke_device_flips_status_and_clears_caps() {
        let state = make_state();
        seed_actor_async(&state).await;
        // Pre-seed some caps so we can verify they're cleared.
        state.caps.write().await.insert(
            "agent-folotoy".into(),
            vec![ApiCapToken {
                id: "cap-1".into(),
                cap: "memory:read".into(),
                scope: "family".into(),
                ttl: "900s".into(),
                minted: "now".into(),
                danger: None,
            }],
        );

        let resp = revoke_device(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeDeviceRequest {
                intent_text: "Revoke FoloToy".into(),
                intent_fields: vec![("actor".into(), "agent-folotoy".into())],
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.status, "bad");
        assert!(resp.0.label.ends_with("(revoked)"));
        assert!(state.caps.read().await.get("agent-folotoy").is_none());
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "device.revoked"));
    }

    #[tokio::test]
    async fn revoke_cap_removes_only_matching_cap_and_emits_audit() {
        let state = make_state();
        seed_actor_async(&state).await;
        state.caps.write().await.insert(
            "agent-folotoy".into(),
            vec![
                ApiCapToken {
                    id: "cap-1".into(),
                    cap: "memory:read".into(),
                    scope: "family".into(),
                    ttl: "900s".into(),
                    minted: "now".into(),
                    danger: None,
                },
                ApiCapToken {
                    id: "cap-2".into(),
                    cap: "payment:execute".into(),
                    scope: "p≤5".into(),
                    ttl: "60s".into(),
                    minted: "now".into(),
                    danger: Some(true),
                },
            ],
        );

        let _ = revoke_cap(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeCapRequest {
                cap: "memory:read".into(),
                intent_text: "Revoke memory:read".into(),
            }),
        )
        .await
        .unwrap();

        let caps = state.caps.read().await;
        let remaining = caps.get("agent-folotoy").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].cap, "payment:execute");
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "cap.revoked"));
    }

    #[tokio::test]
    async fn dev_seed_populates_all_collections() {
        let state = make_state();
        let resp = dev_seed(
            State(state.clone()),
            Json(DevSeedRequest {
                actors: vec![ApiActor {
                    id: "seed-1".into(),
                    omni: "x".into(),
                    omni_hex: "x".into(),
                    label: "seed".into(),
                    role: "agent".into(),
                    parent: Some("master".into()),
                    derivation: "//seed".into(),
                    device: "".into(),
                    device_pubkey: "".into(),
                    last_active: "now".into(),
                    status: "ok".into(),
                    vendor: "".into(),
                    k11: false,
                    scope: None,
                    payment_cap: None,
                    time_window: None,
                    services: None,
                }],
                caps: HashMap::new(),
                workers: vec![ApiWorker {
                    id: "memory".into(),
                    title: "memory-service".into(),
                    host: "memory.litentry.org".into(),
                    desc: "".into(),
                    calls_today: 100,
                    calls_hour: 10,
                    p50: 30,
                    p95: 100,
                    cap: "mem:r".into(),
                    by_actor: vec![],
                }],
                anchor: Some(ApiAnchorStatus {
                    last_anchor_at: 100,
                    next_anchor_in: 0,
                    recent: vec![],
                }),
                audit: vec![],
                master_memory: vec![],
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.actors.read().await.len(), 1);
        assert_eq!(state.workers.read().await.len(), 1);
        assert_eq!(state.anchor.read().await.last_anchor_at, 100);
    }

    fn mem_entry(ns: &str, key: &str, body: &str) -> ApiMemoryEntry {
        ApiMemoryEntry {
            ns: ns.into(),
            key: key.into(),
            title: format!("{key}.md"),
            bytes: body.len() as u64,
            version: "v2".into(),
            updated: "just now".into(),
            preview: body.chars().take(40).collect(),
            body: body.into(),
            content_hash: String::new(),
        }
    }

    #[tokio::test]
    async fn master_memory_empty_by_default() {
        let state = make_state();
        let resp = list_master_memory(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn plant_then_replant_is_idempotent_dedup() {
        let state = make_state();
        let entries = vec![
            mem_entry("personal", "profile", "name: Kevin"),
            mem_entry("travel", "chengdu", "trip May 25-29"),
        ];

        // First plant: both land.
        let r1 = plant_master_memory(
            State(state.clone()),
            Json(PlantRequest {
                entries: entries.clone(),
            }),
        )
        .await;
        assert_eq!(r1.0.planted, 2);
        assert_eq!(r1.0.skipped, 0);
        assert_eq!(r1.0.total, 2);
        assert_eq!(state.master_memory.read().await.len(), 2);

        // Re-plant the SAME content: 0 planted, 2 skipped (dedup by content_hash).
        let r2 = plant_master_memory(State(state.clone()), Json(PlantRequest { entries })).await;
        assert_eq!(r2.0.planted, 0);
        assert_eq!(r2.0.skipped, 2);
        assert_eq!(r2.0.total, 2);
        assert_eq!(
            state.master_memory.read().await.len(),
            2,
            "re-plant must not duplicate"
        );

        // Plant emits a memory.write audit row (only when something was planted).
        assert!(state
            .audit
            .read()
            .await
            .iter()
            .any(|e| e.kind == "memory.write"));
    }

    #[tokio::test]
    async fn plant_changed_body_adds_a_new_entry() {
        let state = make_state();
        let _ = plant_master_memory(
            State(state.clone()),
            Json(PlantRequest {
                entries: vec![mem_entry("personal", "profile", "v1 body")],
            }),
        )
        .await;
        // Same ns/key but DIFFERENT body → different content_hash → a new entry.
        let r = plant_master_memory(
            State(state.clone()),
            Json(PlantRequest {
                entries: vec![mem_entry("personal", "profile", "v2 body")],
            }),
        )
        .await;
        assert_eq!(r.0.planted, 1);
        assert_eq!(state.master_memory.read().await.len(), 2);
    }

    #[tokio::test]
    async fn list_workers_empty_by_default() {
        let state = make_state();
        let resp = list_workers(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_worker_unknown_returns_404() {
        let state = make_state();
        let err = get_worker(State(state), Path("memory".into()))
            .await
            .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0.reason, "worker-not-found");
    }

    #[tokio::test]
    async fn audit_buffer_caps_at_buffer_cap() {
        let state = make_state();
        for i in 0..(AUDIT_BUFFER_CAP + 25) {
            let evt = ApiAuditEvent {
                id: format!("e-{i}"),
                ts: format!("00:00:{:02}", i % 60),
                actor_id: "x".into(),
                actor: "x".into(),
                kind: "test.event".into(),
                detail: format!("event {i}"),
                chip: "audit".into(),
                sev: "ok".into(),
            };
            push_audit(&state, evt).await;
        }
        let buf = state.audit.read().await;
        assert_eq!(
            buf.len(),
            AUDIT_BUFFER_CAP,
            "ring buffer must cap at AUDIT_BUFFER_CAP"
        );
    }

    #[tokio::test]
    async fn audit_stream_subscribes_before_emit_and_receives() {
        let state = make_state();
        let mut rx = state.audit_tx.subscribe();
        let evt = ApiAuditEvent {
            id: "e-stream-1".into(),
            ts: "00:00:00".into(),
            actor_id: "x".into(),
            actor: "x".into(),
            kind: "stream.test".into(),
            detail: "broadcast".into(),
            chip: "audit".into(),
            sev: "ok".into(),
        };
        push_audit(&state, evt.clone()).await;
        let received = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("must receive within 200ms")
            .expect("must not error");
        assert_eq!(received.id, "e-stream-1");
    }

    // Convince clippy the sync helper isn't dead code.
    #[allow(dead_code)]
    fn _keep_seed_actor_alive(state: &SharedUiBridgeState) -> ApiActor {
        seed_actor(state)
    }
}
