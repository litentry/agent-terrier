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
//! The on-chain register (registerFirstMasterDevice) is WIRED (issue #196):
//! K11-finish shells out to `--register-master-script` and returns the real
//! `chain_tx_hash` + `chain` status (+ `chain_error` on failure). It is skipped
//! (`chain: none`) ONLY when no register script is configured (dev/no-infra) —
//! the web app launcher (`dev.sh`) always passes one, so the onboarding
//! ceremony is NOT deferred.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
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

use agentkeys_core::init_flow;

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
    /// Broker base URL for the W1 onboarding email→verify flow. `None` ⇒ email
    /// onboarding is disabled (the daemon was started without `--broker-url`)
    /// and the email endpoints fail closed with `broker-not-configured`.
    pub broker_url: Option<String>,
    /// Allowed browser origin (= the CORS origin, e.g. `http://localhost:3113`).
    /// Server-side defense-in-depth: the onboarding email endpoints reject a
    /// mismatched `Origin` header even though browser CORS already would, so a
    /// cross-origin page can't trigger magic-link emails.
    pub allowed_origin: String,
    /// W1 onboarding: request_id → email, recorded at email/start so email/status
    /// knows which identity verified. Cleared on logout.
    pub pending_email: RwLock<HashMap<String, String>>,
    /// The verified operator identity, held in the daemon once the magic link is
    /// clicked (never handed to the browser — the daemon is the authenticated
    /// proxy). `None` until verified / after logout; this is the real "logged in"
    /// signal that replaces the browser's `ak_onboarded` localStorage flag.
    pub onboarding_session: RwLock<Option<OnboardingSession>>,
    /// Signer (dev_key_service) base URL for the SIWE→J1 step — the signer
    /// *attests* the managed wallet it derives (no user wallet / MetaMask).
    /// `None` ⇒ email verify holds an identity-only session (no EVM J1 / actor omni).
    pub signer_url: Option<String>,
    /// Chain id for the managed-wallet attestation (mirrors `--init-chain-id`).
    pub chain_id: u64,
    /// W3 real-memory chain — the memory worker base URL (e.g. `https://memory.litentry.org`).
    /// `None` ⇒ master-memory plant/list fall back to the in-memory store (dev/no-infra).
    pub memory_url: Option<String>,
    /// Per-actor memory IAM role ARN for the STS relay (`MEMORY_ROLE_ARN`). Required
    /// alongside `memory_url` for the real chain; a partial config fails loud (issue #90 discipline).
    pub memory_role_arn: Option<String>,
    /// AWS region for the STS relay (`REGION`).
    pub region: String,
    /// The on-chain-registered master device key hash, sent as `device_key_hash` in
    /// memory cap-mint. Must match the device registered via the W3 bootstrap
    /// (`docs/plan/web-flow/w3-real-memory.md` §4). `None` ⇒ real chain disabled.
    /// Issue #196 makes this a FALLBACK: once the K11-finish register shell-out
    /// runs, `registered_master` holds the freshly-registered hash and takes
    /// precedence, so the operator no longer has to pass `--master-device-key-hash`.
    pub master_device_key_hash: Option<String>,
    /// Issue #196: the on-chain master-device registration result, populated by
    /// the K11-finish handler's register shell-out. `Some` ⇒ the master device is
    /// on chain with CAP_MINT; its `device_key_hash` is what real cap-mint sends
    /// (takes precedence over `master_device_key_hash`).
    pub registered_master: RwLock<Option<RegisteredMaster>>,
    /// Issue #196: path to `harness/scripts/heima-register-first-master.sh` (the
    /// §4.2 sanctioned shell-out). `None` ⇒ K11-finish does NOT submit the
    /// on-chain register (chain stays "none"); set via `--register-master-script`
    /// to enable the real web onboarding chain write.
    pub register_master_script: Option<String>,
}

/// Issue #196: outcome of the on-chain master-device registration shell-out.
#[derive(Clone, Debug)]
pub struct RegisteredMaster {
    /// `device_key_hash` the broker resolves on cap-mint — what `real_memory_ctx`
    /// sends. Derived + returned by `heima-register-first-master.sh`.
    pub device_key_hash: String,
    /// The session (managed-wallet) omni the device was registered under
    /// (operator == actor for master-self). `cap.rs` requires
    /// `device.actor_omni == req.actor_omni`, so this must equal the cap-mint omni.
    pub operator_omni: String,
    /// `registerFirstMasterDevice` tx hash. `None` on idempotent skip (the device
    /// was already on chain from a prior login).
    pub tx_hash: Option<String>,
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
    /// Issue #196: real `registerFirstMasterDevice` tx hash once the on-chain
    /// register shell-out succeeds. `None` on idempotent skip (already on chain),
    /// when no register script is configured, or when chain registration failed
    /// (see `chain` / `chain_error`). No longer a hard-coded stub.
    pub chain_tx_hash: Option<String>,
    /// "master-registered" once the master device is on chain with CAP_MINT (new
    /// tx OR idempotent-skip), else "none". Mirrors `GET /v1/onboarding/state`.
    pub chain: String,
    /// Populated only when the register shell-out FAILED — the passkey is still
    /// enrolled (the `credential_id` above is valid), but the chain write didn't
    /// land. The web UI surfaces this so the operator funds + retries instead of
    /// hitting a confusing cap-mint failure at plant time (issue #90 fail-loud).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_error: Option<String>,
}

// ── W1 onboarding: real email magic-link verify (broker-backed) ──

#[derive(Debug, Deserialize)]
pub struct EmailStartRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct EmailStartResponse {
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EmailStatusQuery {
    pub request_id: String,
}

#[derive(Debug, Serialize)]
pub struct EmailStatusResponse {
    /// "pending" | "verified" | "failed:<reason>"
    pub status: String,
    /// Set when verified: the operator's identity omni (shown after login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omni_account: Option<String>,
}

/// The verified operator identity held in the daemon after the magic link is
/// clicked. Held server-side; never serialized to the browser.
#[derive(Clone, Debug)]
pub struct OnboardingSession {
    pub email: String,
    /// The EVM `actor_omni` after the managed-wallet attestation (SIWE→J1), or
    /// the identity omni if that step was skipped / unavailable.
    pub omni: String,
    /// The J1 (EVM-omni) session JWT — the daemon's authenticated bearer; held
    /// here, never handed to the browser. Read once cap-mint over the EVM session
    /// lands (next W-phase); held now so onboarding establishes the real session.
    #[allow(dead_code)]
    pub j1: String,
}

#[derive(Debug, Serialize)]
pub struct OnboardingStateResponse {
    /// "verified" once the magic link is clicked + held; else "none".
    pub identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omni: Option<String>,
    /// "enrolled" if a K11 passkey was registered this session, else "none".
    pub k11: String,
    /// Issue #196: "master-registered" once the master device is on chain with
    /// CAP_MINT (the K11-finish register shell-out landed or was idempotent-skip),
    /// else "none". This is the last onboarding gate before the memory plant
    /// button works end-to-end (real cap-mint resolves the on-chain device).
    pub chain: String,
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
        .route("/v1/auth/email/start", post(auth_email_start))
        .route("/v1/auth/email/status", get(auth_email_status))
        .route("/v1/onboarding/state", get(onboarding_state))
        .route("/v1/auth/logout", post(logout))
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
// Runtime-config constructor: the params ARE the daemon's config surface (RP +
// broker/signer + chain + W3 memory). Bundling into a config struct is deferred
// (W2 adds more chain config here); clippy's documented escape for constructors.
#[allow(clippy::too_many_arguments)]
pub fn build_state(
    rp_id: &str,
    rp_origin: &str,
    rp_name: &str,
    broker_url: Option<String>,
    signer_url: Option<String>,
    chain_id: u64,
    memory_url: Option<String>,
    memory_role_arn: Option<String>,
    region: String,
    master_device_key_hash: Option<String>,
    register_master_script: Option<String>,
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
        broker_url,
        allowed_origin: rp_origin.to_string(),
        pending_email: RwLock::new(HashMap::new()),
        onboarding_session: RwLock::new(None),
        signer_url,
        chain_id,
        memory_url,
        memory_role_arn,
        region,
        master_device_key_hash,
        registered_master: RwLock::new(None),
        register_master_script,
    }))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "surface": "ui-bridge" }))
}

/// W1: request a magic-link email. Proxies the broker's `email/request` so the
/// browser never holds broker URLs; returns the `request_id` the browser polls.
/// Server-side origin gate for the onboarding email endpoints (defense-in-depth
/// on top of CORS): a present `Origin` that doesn't match the configured app
/// origin is rejected, so a cross-origin page can't trigger magic-link emails.
/// A missing Origin (non-browser / CLI) is allowed.
fn reject_cross_origin(
    state: &SharedUiBridgeState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if origin != state.allowed_origin {
            return Err(err(
                StatusCode::FORBIDDEN,
                format!("cross-origin onboarding request from {origin} rejected"),
                "bad-origin",
            ));
        }
    }
    Ok(())
}

async fn auth_email_start(
    State(state): State<SharedUiBridgeState>,
    headers: HeaderMap,
    Json(req): Json<EmailStartRequest>,
) -> Result<Json<EmailStartResponse>, (StatusCode, Json<ErrorBody>)> {
    reject_cross_origin(&state, &headers)?;
    let broker = state.broker_url.as_deref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "email onboarding disabled (daemon started without --broker-url)",
            "broker-not-configured",
        )
    })?;
    if req.email.trim().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "email required",
            "missing-email",
        ));
    }
    let request_id = init_flow::email_request(broker, req.email.trim())
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("broker email/request failed: {e}"),
                "broker-email-failed",
            )
        })?;
    state
        .pending_email
        .write()
        .await
        .insert(request_id.clone(), req.email.trim().to_string());
    Ok(Json(EmailStartResponse { request_id }))
}

/// W1: poll the magic-link status (the browser calls this on a timer until the
/// status is no longer `pending` — i.e. the operator clicked the link).
async fn auth_email_status(
    State(state): State<SharedUiBridgeState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<EmailStatusQuery>,
) -> Result<Json<EmailStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    reject_cross_origin(&state, &headers)?;
    let broker = state.broker_url.as_deref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "email onboarding disabled (daemon started without --broker-url)",
            "broker-not-configured",
        )
    })?;
    let status = init_flow::auth_status_once(broker, "email", &q.request_id)
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("broker email/status failed: {e}"),
                "broker-status-failed",
            )
        })?;
    let resp = match status {
        init_flow::AuthStatus::Pending => EmailStatusResponse {
            status: "pending".into(),
            omni_account: None,
        },
        init_flow::AuthStatus::Verified {
            session_jwt,
            identity_omni,
        } => {
            let email = state
                .pending_email
                .read()
                .await
                .get(&q.request_id)
                .cloned()
                .unwrap_or_default();
            // Managed-wallet attestation (SIWE→J1): the signer derives + attests
            // the managed wallet for this email identity (no user wallet) and the
            // broker mints J1. On success we hold the EVM `actor_omni` + J1; if the
            // signer is unconfigured/unreachable we fall back to the identity-only
            // session so onboarding still completes (the EVM session can retry).
            let held = match state.signer_url.as_deref() {
                Some(signer) => match init_flow::finish_email_session(
                    broker,
                    signer,
                    &session_jwt,
                    &identity_omni,
                    state.chain_id,
                    &email,
                )
                .await
                {
                    Ok(init) => OnboardingSession {
                        email,
                        omni: init.evm_omni,
                        j1: init.session.token,
                    },
                    Err(e) => {
                        tracing::warn!(
                            "ui-bridge: SIWE->J1 attestation failed, holding identity-only: {e}"
                        );
                        OnboardingSession {
                            email,
                            omni: identity_omni,
                            j1: String::new(),
                        }
                    }
                },
                None => OnboardingSession {
                    email,
                    omni: identity_omni,
                    j1: String::new(),
                },
            };
            let omni = held.omni.clone();
            *state.onboarding_session.write().await = Some(held);
            EmailStatusResponse {
                status: "verified".into(),
                omni_account: Some(omni),
            }
        }
        init_flow::AuthStatus::Failed(reason) => EmailStatusResponse {
            status: format!("failed:{reason}"),
            omni_account: None,
        },
    };
    Ok(Json(resp))
}

/// W1: aggregate onboarding state — the real "are we logged in" signal that
/// replaces the browser's `ak_onboarded` localStorage flag. Identity is held in
/// the daemon (never the browser); `k11` reflects the in-memory enroll store.
async fn onboarding_state(
    State(state): State<SharedUiBridgeState>,
) -> Json<OnboardingStateResponse> {
    let session = state.onboarding_session.read().await.clone();
    let k11 = if state.enroll.read().await.registered.is_empty() {
        "none"
    } else {
        "enrolled"
    };
    let chain = if state.registered_master.read().await.is_some() {
        "master-registered"
    } else {
        "none"
    };
    let (identity, email, omni) = match session {
        Some(s) => ("verified".to_string(), Some(s.email), Some(s.omni)),
        None => ("none".to_string(), None, None),
    };
    Json(OnboardingStateResponse {
        identity,
        email,
        omni,
        k11: k11.to_string(),
        chain: chain.to_string(),
    })
}

/// W1: clear the held onboarding session (logout / reset) so re-onboarding
/// starts clean. Re-testability per arch.md §6: the same email re-verifies to the
/// same `actor_omni`, and the device key + encryption are untouched — only the
/// session is dropped.
async fn logout(State(state): State<SharedUiBridgeState>) -> Json<serde_json::Value> {
    *state.onboarding_session.write().await = None;
    state.pending_email.write().await.clear();
    Json(serde_json::json!({ "ok": true }))
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
    // Issue #196: pull the raw attestationObject (b64url) out of the credential
    // JSON BEFORE `from_value` consumes it — the on-chain register shell-out
    // forwards the K11 pubkey + rpIdHash extracted from it (the web path has no
    // disk K11 file). Always present in a real registration response.
    let attestation_object_b64 = req
        .credential
        .get("response")
        .and_then(|r| r.get("attestationObject"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

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

    drop(guard);

    // Issue #196: submit registerFirstMasterDevice on chain (un-stub
    // chain_tx_hash). The device is registered under the daemon's SESSION omni —
    // cap.rs forces device.operator_omni == J1.omni_account == the cap-mint
    // operator_omni, so a master-self memory cap resolves exactly this device.
    // The deployer key signs the tx (msg.sender); the K11 pubkey is the browser
    // passkey just enrolled. Best-effort: a chain failure does NOT void the
    // passkey enrollment — it surfaces in `chain_error` so the operator funds +
    // retries instead of hitting a confusing cap-mint failure at plant time.
    let (chain_tx_hash, chain, chain_error) = finish_chain_register(
        &state,
        &credential_id_b64,
        attestation_object_b64.as_deref(),
    )
    .await;

    Ok(Json(EnrollFinishResponse {
        credential_id: credential_id_b64,
        registered_at_unix,
        chain_tx_hash,
        chain,
        chain_error,
    }))
}

/// K11-finish → on-chain register glue (issue #196). Returns
/// `(chain_tx_hash, chain_status, chain_error)` and never errors out the
/// enrollment (the passkey is already persisted). Chain registration is skipped
/// — `("none", None)` with no error — when no register script is configured
/// (dev / no-infra). A missing session or a shell-out failure returns a
/// `chain_error` so the web UI can surface "fund + retry".
async fn finish_chain_register(
    state: &SharedUiBridgeState,
    credential_id_b64url: &str,
    attestation_object_b64: Option<&str>,
) -> (Option<String>, String, Option<String>) {
    let Some(script) = state.register_master_script.clone() else {
        return (None, "none".to_string(), None);
    };
    let session = state.onboarding_session.read().await.clone();
    let Some(session) = session else {
        let msg = "K11 enrolled but no onboarding session — verify email first, \
                   then re-enroll to register the master device on chain"
            .to_string();
        tracing::warn!("ui-bridge register-master: {msg}");
        return (None, "none".to_string(), Some(msg));
    };
    if session.omni.is_empty() {
        return (
            None,
            "none".to_string(),
            Some("onboarding session has no EVM omni (managed-wallet attestation skipped)".into()),
        );
    }
    let Some(att_b64) = attestation_object_b64 else {
        return (
            None,
            "none".to_string(),
            Some("credential missing response.attestationObject — cannot derive K11 pubkey".into()),
        );
    };
    let k11 = match decode_web_k11(att_b64) {
        Ok(k) => k,
        Err(e) => {
            return (
                None,
                "none".to_string(),
                Some(format!("K11 pubkey extract: {e}")),
            )
        }
    };

    match register_master_device(&script, &session.omni, &k11, credential_id_b64url).await {
        Ok(rm) => {
            tracing::info!(
                target: "agentkeys.daemon.ui_bridge",
                operator_omni = %rm.operator_omni,
                device_key_hash = %rm.device_key_hash,
                tx = rm.tx_hash.as_deref().unwrap_or("(already-registered)"),
                "issue #196: master device registered on chain (CAP_MINT) — cap-mint will resolve this device"
            );
            let tx = rm.tx_hash.clone();
            *state.registered_master.write().await = Some(rm);
            (tx, "master-registered".to_string(), None)
        }
        Err(e) => {
            tracing::error!("ui-bridge register-master shell-out failed: {e}");
            (None, "none".to_string(), Some(e))
        }
    }
}

/// Decode the attestationObject (b64url) → the on-chain K11 material (pubkey +
/// rpIdHash). Reuses the CLI's tested CBOR/COSE parser.
fn decode_web_k11(
    att_obj_b64url: &str,
) -> Result<agentkeys_cli::k11_webauthn::WebK11Material, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD
        .decode(att_obj_b64url)
        .map_err(|e| format!("attestationObject not valid b64url: {e}"))?;
    agentkeys_cli::k11_webauthn::parse_web_k11(&bytes).map_err(|e| e.to_string())
}

/// Shell out to `heima-register-first-master.sh` (wire-real-paths.md §4.2) to
/// submit `registerFirstMasterDevice` under the session omni, signed by the
/// local deployer key (msg.sender). Parses the trailing JSON line for the
/// device_key_hash (what cap-mint sends) + tx_hash (None on idempotent skip).
async fn register_master_device(
    script: &str,
    session_omni: &str,
    k11: &agentkeys_cli::k11_webauthn::WebK11Material,
    credential_id_b64url: &str,
) -> Result<RegisteredMaster, String> {
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .arg("--operator-omni")
        .arg(session_omni)
        .arg("--actor-omni")
        .arg(session_omni)
        .arg("--k11-cose-hex")
        .arg(&k11.cose_pubkey_hex)
        .arg("--k11-cred-id")
        .arg(credential_id_b64url)
        .arg("--rp-id-hash")
        .arg(&k11.rp_id_hash_hex)
        .output()
        .await
        .map_err(|e| format!("spawn {script}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Surface the last few stderr lines (the script logs `fail <reason>`).
        let tail: String = stderr
            .lines()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!("register script exited {}: {tail}", output.status));
    }

    // The script prints human logs on stderr and a single JSON line on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("register script produced no JSON on stdout: {stdout}"))?;
    let parsed: serde_json::Value =
        serde_json::from_str(json_line.trim()).map_err(|e| format!("register JSON parse: {e}"))?;

    let device_key_hash = parsed
        .get("device_key_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("register JSON missing device_key_hash: {json_line}"))?
        .to_string();
    let operator_omni = parsed
        .get("operator_omni")
        .and_then(|v| v.as_str())
        .unwrap_or(session_omni)
        .to_string();
    let tx_hash = parsed
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(RegisteredMaster {
        device_key_hash,
        operator_omni,
        tx_hash,
    })
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

// ─── W3: real memory chain (cap-mint → STS relay → worker → S3) ─────────────
//
// When the daemon has --memory-url + --memory-role-arn + --master-device-key-hash
// AND a master onboarding session, the master plants its OWN memory under its
// actor_omni (operator == actor == O_master) via the same chain the MCP
// http_backend + phase1-wire-demo use. Otherwise plant falls back to the
// in-memory store. Per-actor by construction (cap-mint binds device.actor_omni
// == req.actor_omni); see docs/plan/web-flow/w3-real-memory.md §1.

struct RealMemoryCtx {
    broker: String,
    memory_url: String,
    role_arn: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// `Ok(None)` → real chain not configured (in-memory fallback). `Ok(Some)` →
/// fully configured + a master session present. `Err` → configured but a
/// required piece is missing (partial config / not logged in) — fail loud
/// rather than silently degrade per-actor isolation (issue #90 discipline).
async fn real_memory_ctx(state: &UiBridgeState) -> Result<Option<RealMemoryCtx>, String> {
    let Some(memory_url) = state.memory_url.clone() else {
        return Ok(None);
    };
    let broker = state
        .broker_url
        .clone()
        .ok_or("real memory: --memory-url set but --broker-url missing")?;
    let role_arn = state
        .memory_role_arn
        .clone()
        .ok_or("real memory: --memory-url set but MEMORY_ROLE_ARN missing")?;
    // Prefer the device hash from the K11-finish register shell-out (issue #196)
    // — it's the device actually on chain under this session omni. Fall back to
    // the --master-device-key-hash CLI flag (pre-registered device / tests).
    let device_key_hash = match state.registered_master.read().await.as_ref() {
        Some(rm) => rm.device_key_hash.clone(),
        None => state.master_device_key_hash.clone().ok_or(
            "real memory: master device not registered on chain yet (finish K11 \
             enrollment to register) and no --master-device-key-hash fallback set",
        )?,
    };
    let session = state
        .onboarding_session
        .read()
        .await
        .clone()
        .ok_or("real memory: no master session — complete onboarding first")?;
    if session.omni.is_empty() || session.j1.is_empty() {
        return Err("real memory: master session is identity-only (no EVM omni/J1)".into());
    }
    Ok(Some(RealMemoryCtx {
        broker,
        memory_url,
        role_arn,
        region: state.region.clone(),
        j1: session.j1,
        // The broker cap-mint input-validates that operator_omni/actor_omni start with
        // 0x, but the onboarding session stores the omni bare. Normalize ONCE here so
        // both memory_put_real + memory_get_real send a 0x-prefixed omni (the broker
        // normalize_hex32's it for the device-binding match either way).
        omni: if session.omni.starts_with("0x") {
            session.omni
        } else {
            format!("0x{}", session.omni)
        },
        device_key_hash,
    }))
}

/// One real memory-put: cap-mint(`memory:<ns>`) → STS relay → worker
/// `/v1/memory/put`. Returns the worker's S3 key. Mirrors
/// `agentkeys-mcp-server::backend::http_backend::memory_put`.
async fn memory_put_real(
    client: &reqwest::Client,
    ctx: &RealMemoryCtx,
    entry: &ApiMemoryEntry,
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // 1. cap-mint for the master's own actor (operator == actor == O_master).
    let cap_resp = client
        .post(format!("{}/v1/cap/memory-put", ctx.broker))
        .bearer_auth(&ctx.j1)
        .json(&serde_json::json!({
            "operator_omni": ctx.omni,
            "actor_omni": ctx.omni,
            "service": format!("memory:{}", entry.ns),
            "device_key_hash": ctx.device_key_hash,
            "ttl_seconds": 300,
        }))
        .send()
        .await
        .map_err(|e| format!("cap-mint transport: {e}"))?;
    if !cap_resp.status().is_success() {
        let status = cap_resp.status();
        let body = cap_resp.text().await.unwrap_or_default();
        return Err(format!("cap-mint {status}: {body}"));
    }
    let cap: serde_json::Value = cap_resp
        .json()
        .await
        .map_err(|e| format!("cap-mint parse: {e}"))?;

    // 2. STS relay — per-actor creds tagged agentkeys_actor_omni == O_master.
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| format!("STS relay: {e}"))?;

    // 3. worker put → S3 bots/<O_master>/memory/memory:<ns>.enc.
    let put_resp = client
        .post(format!("{}/v1/memory/put", ctx.memory_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        .json(&serde_json::json!({
            "cap": cap,
            "plaintext_b64": STANDARD.encode(entry.body.as_bytes()),
            "namespace": entry.ns,
        }))
        .send()
        .await
        .map_err(|e| format!("worker put transport: {e}"))?;
    if !put_resp.status().is_success() {
        let status = put_resp.status();
        let body = put_resp.text().await.unwrap_or_default();
        return Err(format!("worker put {status}: {body}"));
    }
    let parsed: serde_json::Value = put_resp
        .json()
        .await
        .map_err(|e| format!("worker put parse: {e}"))?;
    Ok(parsed
        .get("s3_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string())
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
) -> axum::response::Response {
    match plant_master_memory_inner(&state, req).await {
        Ok(resp) => (axum::http::StatusCode::OK, Json(resp)).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// Core plant logic. Returns the typed `PlantResponse` (real chain or in-memory
/// fallback) or an `(HTTP status, reason)` for partial-config / not-logged-in
/// (409) and real-worker-failure (502). The handler maps it to a response; tests
/// call this directly to assert the typed counts.
async fn plant_master_memory_inner(
    state: &SharedUiBridgeState,
    req: PlantRequest,
) -> Result<PlantResponse, (axum::http::StatusCode, String)> {
    let ctx = real_memory_ctx(state).await.map_err(|reason| {
        tracing::warn!("plant_master_memory: {reason}");
        (axum::http::StatusCode::CONFLICT, reason)
    })?;

    let mut planted = 0usize;
    let mut skipped = 0usize;

    if let Some(ctx) = ctx {
        // REAL chain — the master plants its own memory to the worker/S3.
        let client = reqwest::Client::new();
        let mut errors: Vec<String> = Vec::new();
        for mut e in req.entries {
            let hash = if e.content_hash.is_empty() {
                e.compute_hash()
            } else {
                e.content_hash.clone()
            };
            e.content_hash = hash.clone();
            if state.master_memory.read().await.contains_key(&hash) {
                skipped += 1;
                continue;
            }
            match memory_put_real(&client, &ctx, &e).await {
                Ok(_s3_key) => {
                    state.master_memory.write().await.insert(hash, e);
                    planted += 1;
                }
                Err(err) => {
                    tracing::warn!("plant_master_memory: real put failed: {err}");
                    errors.push(err);
                }
            }
        }
        // Any durable-write failure fails the whole plant — a partial plant must NOT
        // read as success (the prepared archive would be partially persisted while the
        // caller proceeds with missing memory). The successfully-written entries stay in
        // `master_memory` so a re-plant is idempotent and resumes the failed namespaces.
        // We early-return BEFORE the success audit + Ok response below.
        if !errors.is_empty() {
            return Err((
                axum::http::StatusCode::BAD_GATEWAY,
                format!(
                    "plant incomplete: {} of {} write(s) failed (planted {planted}, skipped {skipped}): {}",
                    errors.len(),
                    planted + skipped + errors.len(),
                    errors.join("; ")
                ),
            ));
        }
    } else {
        // In-memory fallback (dev / no infra) — content-hash dedup.
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
        push_audit(state, evt).await;
    }
    Ok(PlantResponse {
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
        build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            "us-east-1".into(),
            None,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn real_memory_ctx_none_when_unconfigured() {
        // No --memory-url ⇒ in-memory fallback (Ok(None)), not an error.
        let state = make_state();
        assert!(real_memory_ctx(&state).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn real_memory_ctx_errs_on_partial_config() {
        // --memory-url set but MEMORY_ROLE_ARN missing ⇒ fail loud (issue #90),
        // never a silent per-actor-isolation downgrade.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some("https://broker.example".into()),
            None,
            84532,
            Some("https://memory.example".into()),
            None,
            "us-east-1".into(),
            Some("0xdkh".into()),
            None,
        )
        .unwrap();
        let err = match real_memory_ctx(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected real_memory_ctx to return Err"),
        };
        assert!(err.contains("MEMORY_ROLE_ARN"), "got: {err}");
    }

    #[tokio::test]
    async fn real_memory_ctx_errs_when_not_logged_in() {
        // Fully configured but no onboarding session ⇒ Err (onboard first),
        // not a silent no-op.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some("https://broker.example".into()),
            None,
            84532,
            Some("https://memory.example".into()),
            Some("arn:aws:iam::1:role/memory".into()),
            "us-east-1".into(),
            Some("0xdkh".into()),
            None,
        )
        .unwrap();
        let err = match real_memory_ctx(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected real_memory_ctx to return Err"),
        };
        assert!(err.contains("session"), "got: {err}");
    }

    #[tokio::test]
    async fn auth_email_start_without_broker_is_unavailable() {
        // make_state() builds with broker_url = None ⇒ email onboarding is
        // disabled, so the endpoint fails closed (503 broker-not-configured)
        // rather than silently no-op'ing.
        let state = make_state();
        let e = auth_email_start(
            State(state),
            axum::http::HeaderMap::new(),
            Json(EmailStartRequest {
                email: "sara@example.com".into(),
            }),
        )
        .await
        .expect_err("no broker configured should error");
        assert_eq!(e.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.1 .0.reason, "broker-not-configured");
    }

    #[tokio::test]
    async fn auth_email_start_rejects_cross_origin() {
        // make_state()'s allowed origin is http://localhost:3113; a request
        // carrying a different Origin is rejected before any broker call —
        // the server-side gate on top of CORS.
        let state = make_state();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("origin", "http://evil.example".parse().unwrap());
        let e = auth_email_start(
            State(state),
            headers,
            Json(EmailStartRequest {
                email: "sara@example.com".into(),
            }),
        )
        .await
        .expect_err("cross-origin should be rejected");
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert_eq!(e.1 .0.reason, "bad-origin");
    }

    #[tokio::test]
    async fn onboarding_state_reflects_session_and_logout() {
        let state = make_state();
        // No session held yet → identity "none".
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.identity,
            "none"
        );
        // Simulate a verified magic-link click.
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "sara@example.com".into(),
            omni: "0xabc123".into(),
            j1: String::new(),
        });
        let s = onboarding_state(State(state.clone())).await;
        assert_eq!(s.0.identity, "verified");
        assert_eq!(s.0.email.as_deref(), Some("sara@example.com"));
        assert_eq!(s.0.omni.as_deref(), Some("0xabc123"));
        // Logout clears it → re-testable.
        let _ = logout(State(state.clone())).await;
        assert_eq!(onboarding_state(State(state)).await.0.identity, "none");
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
        let r1 = plant_master_memory_inner(
            &state,
            PlantRequest {
                entries: entries.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(r1.planted, 2);
        assert_eq!(r1.skipped, 0);
        assert_eq!(r1.total, 2);
        assert_eq!(state.master_memory.read().await.len(), 2);

        // Re-plant the SAME content: 0 planted, 2 skipped (dedup by content_hash).
        let r2 = plant_master_memory_inner(&state, PlantRequest { entries })
            .await
            .unwrap();
        assert_eq!(r2.planted, 0);
        assert_eq!(r2.skipped, 2);
        assert_eq!(r2.total, 2);
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
        let _ = plant_master_memory_inner(
            &state,
            PlantRequest {
                entries: vec![mem_entry("personal", "profile", "v1 body")],
            },
        )
        .await
        .unwrap();
        // Same ns/key but DIFFERENT body → different content_hash → a new entry.
        let r = plant_master_memory_inner(
            &state,
            PlantRequest {
                entries: vec![mem_entry("personal", "profile", "v2 body")],
            },
        )
        .await
        .unwrap();
        assert_eq!(r.planted, 1);
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

    // ─── Issue #196: on-chain master-device registration (K11-finish glue) ───

    fn write_temp_script(name: &str, body: &str) -> String {
        let path = std::env::temp_dir().join(format!("ak196-{name}.sh"));
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn dummy_k11() -> agentkeys_cli::k11_webauthn::WebK11Material {
        // Values are opaque to register_master_device (it just forwards them as
        // args; the fake scripts ignore them).
        agentkeys_cli::k11_webauthn::WebK11Material {
            cose_pubkey_hex: format!("04{}", "ab".repeat(64)),
            rp_id_hash_hex: "cd".repeat(32),
        }
    }

    #[tokio::test]
    async fn register_master_device_parses_success() {
        let script = write_temp_script(
            "ok",
            "#!/usr/bin/env bash\necho 'human log' >&2\n\
             echo '{\"ok\":true,\"device_key_hash\":\"0xdeadbeef\",\"operator_omni\":\"0xfeed\",\"actor_omni\":\"0xfeed\",\"tx_hash\":\"0xTX\",\"block_number\":\"42\"}'\n",
        );
        let rm = register_master_device(&script, "0xfeed", &dummy_k11(), "credid")
            .await
            .expect("parse success JSON");
        assert_eq!(rm.device_key_hash, "0xdeadbeef");
        assert_eq!(rm.operator_omni, "0xfeed");
        assert_eq!(rm.tx_hash.as_deref(), Some("0xTX"));
    }

    #[tokio::test]
    async fn register_master_device_parses_idempotent_skip() {
        // Already-registered skip: device_key_hash present, NO tx_hash.
        let script = write_temp_script(
            "skip",
            "#!/usr/bin/env bash\n\
             echo '{\"ok\":true,\"skipped\":\"already-registered\",\"device_key_hash\":\"0xabc\",\"operator_omni\":\"0xfeed\",\"actor_omni\":\"0xfeed\"}'\n",
        );
        let rm = register_master_device(&script, "0xfeed", &dummy_k11(), "credid")
            .await
            .expect("parse skip JSON");
        assert_eq!(rm.device_key_hash, "0xabc");
        assert!(rm.tx_hash.is_none(), "idempotent skip carries no tx_hash");
    }

    #[tokio::test]
    async fn register_master_device_errors_on_nonzero_exit() {
        let script = write_temp_script(
            "fail",
            "#!/usr/bin/env bash\necho '    fail cast send failed' >&2\nexit 1\n",
        );
        let err = register_master_device(&script, "0xfeed", &dummy_k11(), "credid")
            .await
            .expect_err("non-zero exit must be an Err");
        assert!(
            err.contains("exited") || err.contains("cast send failed"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn onboarding_state_reports_chain_status() {
        let state = make_state();
        let before = onboarding_state(State(state.clone())).await;
        assert_eq!(before.0.chain, "none");
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: "0xabc".into(),
            operator_omni: "0xfeed".into(),
            tx_hash: Some("0xTX".into()),
        });
        let after = onboarding_state(State(state.clone())).await;
        assert_eq!(after.0.chain, "master-registered");
    }

    #[tokio::test]
    async fn finish_chain_register_skips_when_no_script() {
        // No --register-master-script ⇒ on-chain register disabled (dev/no-infra),
        // a CLEAN skip (chain "none", no error), not a failure.
        let state = make_state();
        let (tx, chain, err) = finish_chain_register(&state, "credid", Some("ignored")).await;
        assert!(tx.is_none());
        assert_eq!(chain, "none");
        assert!(err.is_none(), "no-script is a clean skip: {err:?}");
    }

    #[tokio::test]
    async fn finish_chain_register_errors_when_no_session() {
        // Script configured but no onboarding session ⇒ can't determine the omni
        // to register under; surfaces a chain_error (passkey still enrolled).
        let script = write_temp_script("nosession", "#!/usr/bin/env bash\necho '{}'\n");
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            "us-east-1".into(),
            None,
            Some(script),
        )
        .unwrap();
        let (tx, chain, err) = finish_chain_register(&state, "credid", Some("ignored")).await;
        assert!(tx.is_none());
        assert_eq!(chain, "none");
        assert!(
            err.as_deref().unwrap_or("").contains("session"),
            "should explain the missing session: {err:?}"
        );
    }
}
