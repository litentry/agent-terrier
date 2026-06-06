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
    /// Serializes real-chain plants (#201 Phase 4, codex finding 1). The plant is
    /// a read-modify-write of each `memory:<ns>` blob; two concurrent plants for
    /// the same namespace would otherwise race (both read, both write → last wins,
    /// dropping the other's entries). Held for the whole real-chain plant body.
    pub plant_lock: tokio::sync::Mutex<()>,
    /// In-memory mirror of the authored memory-types taxonomy (#207 item 1A,
    /// config-init entry point A). On the REAL chain the durable
    /// `config/memory-taxonomy.enc` is the source of truth and this is just a
    /// write-through cache; with Config UNCONFIGURED (dev / no-infra) it is the
    /// only home, so `init` still authors a taxonomy and the master-memory list
    /// can show its categories before any memory is planted. `None` until the
    /// master picks a preset (or NL→COMPILE, #207 item 1B, lands).
    pub authored_taxonomy: RwLock<Option<MemoryTaxonomy>>,
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
    /// #201 config data class — the config worker base URL (e.g. `https://config.litentry.org`).
    /// `None` ⇒ the memory-types taxonomy is read/written from the in-memory fallback (dev/no-infra),
    /// and the master-memory list derives categories from the cache instead of the durable,
    /// master-only Config-class taxonomy object (`config/memory-taxonomy.enc`).
    pub config_url: Option<String>,
    /// #201 config data class — per-actor config IAM role ARN for the STS relay (`CONFIG_ROLE_ARN`).
    /// Required alongside `config_url`; a partial config fails loud (issue #90 discipline).
    pub config_role_arn: Option<String>,
    /// #207 classifier-service — the classify worker base URL. `Some` ⇒ the
    /// cap-gated, audited worker TAG path (mint a `Classify` cap → `/v1/classify/tag`);
    /// `None` ⇒ the daemon classifies against the bundled `agentkeys-catalog` tier-0
    /// locally (deterministic, dev/no-infra). Drives cred auto-categorize (#207 item 7)
    /// + connect-time auto-distribute (#207 item 5).
    pub classify_url: Option<String>,
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
    /// Resolved chain profile (deployed contract registry + explorer + RPC) the
    /// chain-info + audit-decode endpoints serve to the web UI (#153). Resolved
    /// from `$AGENTKEYS_CHAIN` (default `heima`) at `build_state`.
    pub chain_profile: agentkeys_core::chain_profile::ChainProfile,
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

/// Content hash over (ns ‖ key ‖ body) — the dedup key for plant idempotency
/// AND the durable-merge identity (codex finding 1). A free function so the
/// merge can recompute it for durable `StoredMemoryEntry`s (which don't carry
/// the hash) using the same scheme as `ApiMemoryEntry::compute_hash`.
fn content_hash_for(ns: &str, key: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ns.as_bytes());
    h.update(b"\x1f");
    h.update(key.as_bytes());
    h.update(b"\x1f");
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

impl ApiMemoryEntry {
    fn compute_hash(&self) -> String {
        content_hash_for(&self.ns, &self.key, &self.body)
    }

    /// The on-disk form stored inside the per-namespace JSON array (#201 Phase 4).
    fn to_stored(&self) -> StoredMemoryEntry {
        StoredMemoryEntry {
            key: self.key.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            updated: self.updated.clone(),
            bytes: self.bytes,
        }
    }

    /// Rehydrate a UI entry from a stored array element decrypted out of
    /// `memory:<ns>.enc`. `version`/`preview` are derived (not stored) and
    /// `content_hash` is left empty (the read path doesn't dedup).
    fn from_stored(ns: &str, s: StoredMemoryEntry) -> Self {
        let preview = s.body.chars().take(80).collect();
        ApiMemoryEntry {
            ns: ns.to_string(),
            key: s.key,
            title: s.title,
            bytes: s.bytes,
            version: "v1".to_string(),
            updated: s.updated,
            preview,
            body: s.body,
            content_hash: String::new(),
        }
    }
}

/// One element of the per-namespace JSON array `memory:<ns>.enc` (#201 Phase 4).
/// Fixes the lossy single-body overwrite: a namespace with several memories
/// round-trips as one array. The agent reads the same blobs (W4 inheritance
/// defers the agent WRITE path; the inject already renders this shape).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredMemoryEntry {
    key: String,
    title: String,
    body: String,
    updated: String,
    bytes: u64,
}

/// The `config/memory-taxonomy.enc` object (#178 §7 / #201): the master-only
/// category set the web list resolves WITHOUT decrypting any memory blob. The
/// categories are the namespaces the operator has planted; labels are derived.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemoryTaxonomy {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    categories: Vec<MemoryCategory>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryCategory {
    pub ns: String,
    pub label: String,
}

/// The signed `service` of the Config-class taxonomy object (→ S3 key
/// `bots/<O_master>/config/memory-taxonomy.enc`). Config is master-only, so the
/// broker + worker skip the on-chain scope check for `operator == actor` (#195).
const TAXONOMY_SERVICE: &str = "memory-taxonomy";

/// Title-case a namespace for its display label (`travel` → `Travel`). The
/// taxonomy object is the durable label home; this is the derivation used when
/// minting a fresh taxonomy from planted namespaces.
fn label_for_ns(ns: &str) -> String {
    let mut chars = ns.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Union `incoming` categories INTO `existing`, keyed by namespace, preserving
/// every existing entry (its label is kept — an authored label or a user edit is
/// never clobbered) and appending only namespaces not already present. Sorted by
/// ns for a stable on-disk blob.
///
/// This is what makes an **authored** taxonomy (#207 item 1A) durable against the
/// test-only `plant`: re-running `init` is an idempotent no-op, and a later plant
/// (cache-derived categories) ADDS its namespaces but can never drop the authored
/// ones — the same read-modify-write discipline already applied to memory blobs
/// (#201 codex finding 1), now applied to the category index.
fn merge_categories(
    existing: Vec<MemoryCategory>,
    incoming: &[MemoryCategory],
) -> Vec<MemoryCategory> {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut out: Vec<MemoryCategory> = Vec::new();
    for c in existing {
        if seen.insert(c.ns.clone()) {
            out.push(c);
        }
    }
    for c in incoming {
        if seen.insert(c.ns.clone()) {
            out.push(c.clone());
        }
    }
    out.sort_by(|a, b| a.ns.cmp(&b.ns));
    out
}

/// Parse a decrypted `memory:<ns>` blob into its entries, tolerating BOTH the
/// new per-namespace JSON array (#201 Phase 4) and a legacy single-body blob
/// (pre-#201 / agent-written) — the latter becomes a one-element array keyed by
/// the namespace, so the read path never breaks on an old blob.
fn parse_stored_blob(plaintext: &str, ns: &str) -> Vec<StoredMemoryEntry> {
    let trimmed = plaintext.trim_start();
    if trimmed.starts_with('[') {
        if let Ok(entries) = serde_json::from_str::<Vec<StoredMemoryEntry>>(plaintext) {
            return entries;
        }
    }
    vec![StoredMemoryEntry {
        key: ns.to_string(),
        title: ns.to_string(),
        body: plaintext.to_string(),
        updated: String::new(),
        bytes: plaintext.len() as u64,
    }]
}

/// Merge the DURABLE entries already stored in a namespace with the newly
/// planted entries, deduped by content hash (ns‖key‖body). Durable entries are
/// ALWAYS preserved (codex finding 1 — a plant must never drop already-stored
/// memory); a new entry whose content matches an existing one is a no-op,
/// otherwise it is appended. Sorted by key for a stable on-disk blob. Returns
/// the merged array plus the count of entries that were genuinely new to the
/// durable set (for the plant's `planted`/`skipped` accounting).
fn merge_stored_entries(
    ns: &str,
    durable: Vec<StoredMemoryEntry>,
    incoming: &[ApiMemoryEntry],
) -> (Vec<StoredMemoryEntry>, usize) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<StoredMemoryEntry> = Vec::new();
    for d in durable {
        if seen.insert(content_hash_for(ns, &d.key, &d.body)) {
            out.push(d);
        }
    }
    let mut newly_added = 0usize;
    for e in incoming {
        if seen.insert(content_hash_for(ns, &e.key, &e.body)) {
            out.push(e.to_stored());
            newly_added += 1;
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    (out, newly_added)
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

/// Canonical master-memory web-API routes — the SINGLE source of truth for the
/// path the React frontend (`apps/parent-control/lib/client/daemon.ts`) and the
/// harness web-parity demo (`harness/web-parity-demo.sh`) both hit. They used to
/// hardcode `/v1/master/memory/plant` independently → a rename here left phase 6
/// green on the old path (false-green, issue #203 / the #206 parity ladder). The
/// route + the `ApiMemoryEntry` body shape are now pinned to
/// `harness/fixtures/web-api/master_memory_plant.json` (see the test below) and
/// the two consumers are gated against it by `scripts/check-web-api-drift.sh`.
pub const MASTER_MEMORY_ROUTE: &str = "/v1/master/memory";
pub const MASTER_MEMORY_PLANT_ROUTE: &str = "/v1/master/memory/plant";

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
        .route("/v1/actors/:id/scope/grant", post(grant_service_scope))
        .route("/v1/actors/:id/payment-cap", post(update_payment_cap))
        .route("/v1/actors/:id/revoke", post(revoke_device))
        .route("/v1/actors/:id/caps/revoke", post(revoke_cap))
        .route("/v1/audit/recent", get(list_recent_audit))
        .route("/v1/audit/stream", get(audit_stream))
        .route("/v1/audit/:id/decode", get(decode_audit_event))
        .route("/v1/chain/info", get(chain_info))
        .route("/v1/anchor/status", get(anchor_status))
        .route("/v1/workers", get(list_workers))
        .route("/v1/workers/:id", get(get_worker))
        .route(MASTER_MEMORY_ROUTE, get(list_master_memory))
        .route("/v1/master/memory/entry", get(get_master_memory_entry))
        .route(MASTER_MEMORY_PLANT_ROUTE, post(plant_master_memory))
        .route("/v1/master/config/presets", get(list_config_presets))
        .route("/v1/master/config/init", post(init_config_default))
        .route("/v1/master/classify/tag", post(classify_tag))
        .route("/v1/master/classify/propose", post(classify_propose))
        .route("/v1/master/credentials", get(list_master_credentials))
        .route(
            "/v1/master/credentials/store",
            post(store_master_credential),
        )
        // Agent pairing — the web-app half of the §10.2 agent-initiated ceremony
        // (issue #214). The master pulls the broker's pending agent bindings
        // (agents it claimed, awaiting on-chain register) for the pairing screen.
        .route("/v1/agent/pairing/pending", get(list_pairing_requests))
        .route("/v1/agent/pairing/claim", post(claim_pairing))
        .route("/v1/agent/pairing/register", post(register_pairing))
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
    config_url: Option<String>,
    config_role_arn: Option<String>,
    classify_url: Option<String>,
    region: String,
    master_device_key_hash: Option<String>,
    register_master_script: Option<String>,
) -> anyhow::Result<SharedUiBridgeState> {
    let origin = Url::parse(rp_origin)?;
    let builder = WebauthnBuilder::new(rp_id, &origin)?.rp_name(rp_name);
    let webauthn = builder.build()?;
    let (audit_tx, _audit_rx) = broadcast::channel::<ApiAuditEvent>(256);
    // Resolve the chain profile (deployed contract registry + explorer) from
    // $AGENTKEYS_CHAIN, defaulting to heima mainnet. Drives /v1/chain/info +
    // /v1/audit/:id/decode (#153). Never hard-fails: an unknown chain name
    // falls back to the embedded heima profile.
    let chain_profile = match agentkeys_core::chain_profile::ChainProfile::resolve(
        None,
        std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
        std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
            .ok()
            .as_deref(),
    ) {
        Ok((p, _)) => p,
        Err(e) => {
            // codex review #153: don't silently serve heima addresses when the
            // operator set a bad $AGENTKEYS_CHAIN / profile file — warn loudly so
            // /v1/chain/info isn't trusted as the wrong chain.
            tracing::warn!(
                error = %e,
                "ui-bridge: chain profile resolution failed; falling back to heima — \
                 /v1/chain/info will show heima addresses regardless of the requested chain"
            );
            agentkeys_core::chain_profile::ChainProfile::load_builtin("heima")?
        }
    };
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
        plant_lock: tokio::sync::Mutex::new(()),
        authored_taxonomy: RwLock::new(None),
        broker_url,
        allowed_origin: rp_origin.to_string(),
        pending_email: RwLock::new(HashMap::new()),
        onboarding_session: RwLock::new(None),
        signer_url,
        chain_id,
        memory_url,
        memory_role_arn,
        config_url,
        config_role_arn,
        classify_url,
        region,
        master_device_key_hash,
        registered_master: RwLock::new(None),
        register_master_script,
        chain_profile,
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
pub struct GrantScopeRequest {
    pub data_class: String,
    /// The namespace (memory) or service id (credentials) being granted.
    pub entity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub gating: String,
}

/// `POST /v1/actors/:id/scope/grant` (#207 items 5/7/8) — record a CONFIRMED
/// auto-distribute grant: a memory namespace the agent inherits (read) or a
/// credential service it may use. Same daemon-state + audit posture as
/// `update_scope` — the ui-bridge owns the scope VIEW; the on-chain `setScope`
/// is the operator's `heima-scope-set.sh` (a master `SCOPE_MGMT` + K11 mutation),
/// which the web surface deliberately does NOT drive (mirrors `update_scope`).
///
/// A `Sensitive` grant only reaches this endpoint after an explicit per-grant K11
/// confirm in the UI; a `Safe` one after the reviewed-set confirm. `propose` never
/// calls this — so an unconfirmed sensitive category is never granted (the §3.2
/// invariant, enforced end to end).
async fn grant_service_scope(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<GrantScopeRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let (chip, label) = if req.data_class == "memory" {
        // Memory inheritance (#207 item 8): granting a namespace = read access.
        let scope = actor.scope.get_or_insert_with(HashMap::new);
        scope.insert(
            req.entity.clone(),
            ApiScopeBits {
                read: true,
                write: false,
            },
        );
        ("memory", format!("memory:{}", req.entity))
    } else {
        // Credential grant (#207 item 7): the service joins the agent's services.
        let services = actor.services.get_or_insert_with(Vec::new);
        if !services.contains(&req.entity) {
            services.push(req.entity.clone());
        }
        ("creds", req.entity.clone())
    };
    let snapshot = actor.clone();
    drop(guard);

    let how = if req.gating == "k11" {
        "K11-confirmed"
    } else {
        "auto-confirmed"
    };
    let detail = if req.category.is_empty() {
        format!("granted {label} · {how} · chain commit via master K11")
    } else {
        format!(
            "granted {label} · {} · {how} · chain commit via master K11",
            req.category
        )
    };
    let evt = ApiAuditEvent {
        id: format!("e-grant-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: id.clone(),
        actor: id.clone(),
        kind: "scope.granted".into(),
        detail,
        chip: chip.into(),
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

/// `GET /v1/chain/info` — the chain the daemon targets + its deployed contract
/// registry, for the parent-control chain page (#153). Real addresses from the
/// resolved chain profile, each with an explorer link.
async fn chain_info(State(state): State<SharedUiBridgeState>) -> Json<serde_json::Value> {
    let p = &state.chain_profile;
    let contracts: Vec<serde_json::Value> = p
        .contracts
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "address": c.address,
                "purpose": c.purpose,
                "deployedAt": c.deployed_at,
                "explorerUrl": p.explorer.contract_url(&c.address),
            })
        })
        .collect();
    Json(serde_json::json!({
        "name": p.name,
        "display": p.display_name,
        "chainId": p.chain_id,
        "rpc": p.rpc.http,
        "wss": p.rpc.wss,
        "explorer": p.explorer.url,
        "tokenSymbol": p.token.symbol,
        "tokenDecimals": p.token.decimals,
        "finality": p.finality.default_block_tag,
        "contracts": contracts,
    }))
}

/// `GET /v1/audit/:id/decode` — decode one audit event's CBOR `AuditEnvelope`
/// and the on-chain calldata it commits, against the verified ABIs (#153). The
/// real replacement for the web UI's `decodeCalldata` mock.
async fn decode_audit_event(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let event = {
        let guard = state.audit.read().await;
        guard.iter().find(|e| e.id == id).cloned()
    }
    .ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "audit event not found",
            "no-such-event",
        )
    })?;

    // Resolve the real omnis: the event's actor, and the master (operator).
    let (actor_omni, operator_omni) = {
        let actors = state.actors.read().await;
        let actor_omni = actors.get(&event.actor_id).map(|a| a.omni_hex.clone());
        let operator_omni = actors
            .values()
            .find(|a| a.role.eq_ignore_ascii_case("master"))
            .map(|a| a.omni_hex.clone());
        (actor_omni, operator_omni)
    };

    Ok(Json(crate::audit_decode::decode_event(
        &event,
        actor_omni.as_deref(),
        operator_omni.as_deref(),
        &state.chain_profile,
    )))
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

/// `GET /v1/master/memory` → the memory CATEGORIES, resolved from the durable,
/// master-only Config-class taxonomy (#178 §7 / #201) with **zero memory
/// decryption**. Falls back to cache-derived categories ONLY when Config is
/// unconfigured or the taxonomy is confirmed missing; a configured-but-failing
/// Config surfaces as 502 (codex finding 2 — never hide a broken Config behind a
/// stale "looks empty" view). Per-entry detail is lazy via `.../memory/entry`.
/// GET /v1/agent/pairing/pending — the web-app half of §10.2 agent pairing
/// (issue #214). The master pulls the broker's pending agent bindings (agents it
/// claimed that await on-chain register) via its J1 session, mapped to the web
/// UI's `PairingRequest` shape. REAL data — broker `/v1/agent/pending-bindings`
/// (reuses `agentkeys_cli::agent_admin`, the CLI master-side pairing client).
async fn list_pairing_requests(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "no broker configured (--broker-url) — cannot pull pending agent pairings"
            })),
        )
            .into_response();
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "no master session — verify email + register the master first"
                })),
            )
                .into_response()
        }
    };
    match agentkeys_cli::agent_admin::agent_pending_value(broker, &j1).await {
        Ok(v) => {
            let requests: Vec<serde_json::Value> = v
                .get("pending")
                .and_then(|p| p.as_array())
                .map(|rows| rows.iter().map(pending_binding_to_request).collect())
                .unwrap_or_default();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "requests": requests })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("broker pending-bindings: {e:#}") })),
        )
            .into_response(),
    }
}

/// Map one broker `PendingBinding` row → the web UI's `PairingRequest` JSON
/// (`apps/parent-control/app/_components/types.ts`). These rows are POST-claim
/// (the one-time code was consumed at claim), so `pairCode` carries the real
/// request handle and the UI presents them as "awaiting your on-chain approval".
fn pending_binding_to_request(b: &serde_json::Value) -> serde_json::Value {
    let field = |k: &str| {
        b.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let request_id = field("request_id");
    let label = field("label");
    let device_pubkey = field("device_pubkey");
    let pop_sig = field("pop_sig");
    let requested_scope = field("requested_scope");
    // char-safe head…tail elision for long hex handles.
    let short = |v: &str| -> String {
        let n = v.chars().count();
        if n > 18 {
            let head: String = v.chars().take(10).collect();
            let tail: String = v.chars().skip(n - 6).collect();
            format!("{head}…{tail}")
        } else {
            v.to_string()
        }
    };
    // requested_scope: comma-separated "<service>:<ns>" tokens → RequestedPerm[].
    let requested: Vec<serde_json::Value> = requested_scope
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|tok| {
            let (cap, ns) = match tok.split_once(':') {
                Some((c, n)) => (
                    c.to_string(),
                    vec![serde_json::Value::String(n.to_string())],
                ),
                None => (tok.to_string(), Vec::new()),
            };
            serde_json::json!({ "cap": cap, "ns": ns, "reason": "requested at pairing" })
        })
        .collect();
    serde_json::json!({
        "id": request_id,
        "agent": label,
        "vendor": "agent",
        "device": "sandbox device (K10)",
        "machine": "aiosandbox",
        "runtime": "hermes",
        "dpub": short(&device_pubkey),
        "dpubFull": device_pubkey,
        "pairCode": short(&request_id),
        "derivation": format!("//{label}"),
        "requested": requested,
        "requestedAt": "awaiting on-chain approval",
        "attestation": format!("PoP verified · {}", short(&pop_sig)),
    })
}

#[derive(Debug, Deserialize)]
struct ClaimPairingRequest {
    pairing_code: String,
    label: String,
    #[serde(default)]
    requested_scope: String,
}

/// POST /v1/agent/pairing/claim — the master claims an agent's one-time pairing
/// code (#214, §10.2 P.1). Binds the agent under the HDKD child omni for `label`
/// and declares its requested scope, via the broker, using the master's J1
/// session. The agent then surfaces in pending-bindings (GET …/pending) awaiting
/// the master's on-chain register. Reuses `agentkeys_cli::agent_admin::agent_claim`.
async fn claim_pairing(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ClaimPairingRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "no broker configured (--broker-url)" })),
        )
            .into_response();
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "no master session — verify email + register the master first"
                })),
            )
                .into_response()
        }
    };
    let code = req.pairing_code.trim();
    let label = req.label.trim();
    if code.is_empty() || label.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "pairing_code and label are required" })),
        )
            .into_response();
    }
    match agentkeys_cli::agent_admin::agent_claim(broker, code, label, &req.requested_scope, &j1)
        .await
    {
        Ok(body) => {
            let claim: serde_json::Value =
                serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({ "ok": true }));
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "claim": claim })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("agent claim: {e:#}") })),
        )
            .into_response(),
    }
}

fn pairing_err(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

#[derive(Debug, Deserialize)]
struct RegisterPairingRequest {
    request_id: String,
}

/// POST /v1/agent/pairing/register — the master approves a claimed agent: submit
/// `registerAgentDevice` on chain for its sandbox-generated device key, then ack
/// the broker so it clears from pending (#214, §10.2 P.2). The device fields come
/// from the broker's AUTHORITATIVE pending binding (never the browser). Shells out
/// to `heima-agent-create.sh --from-pubkey` (the sibling of the master register
/// script), mirroring `register_master_device`. The Touch-ID scope grant is the
/// separate `/v1/actors/:id/scope/grant` step (P.3).
async fn register_pairing(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<RegisterPairingRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.as_deref() else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no broker configured (--broker-url)",
        );
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => {
            return pairing_err(
                StatusCode::FORBIDDEN,
                "no master session — verify email + register the master first",
            )
        }
    };
    // The agent-create script is the sibling of the master register script (both
    // live in scripts/); reuse that config rather than a second flag.
    let Some(master_script) = state.register_master_script.clone() else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "on-chain register not configured (--register-master-script) — cannot register the agent device",
        );
    };
    let agent_script = match std::path::Path::new(&master_script).parent() {
        Some(dir) => dir.join("heima-agent-create.sh"),
        None => {
            return pairing_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot derive heima-agent-create.sh path",
            )
        }
    };
    // Pull the authoritative binding from the broker (device fields, never the UI).
    let bindings = match agentkeys_cli::agent_admin::agent_pending_value(broker, &j1).await {
        Ok(v) => v,
        Err(e) => {
            return pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("broker pending-bindings: {e:#}"),
            )
        }
    };
    let row = bindings
        .get("pending")
        .and_then(|p| p.as_array())
        .and_then(|rows| {
            rows.iter()
                .find(|r| {
                    r.get("request_id").and_then(|v| v.as_str()) == Some(req.request_id.as_str())
                })
                .cloned()
        });
    let Some(row) = row else {
        return pairing_err(
            StatusCode::NOT_FOUND,
            "no pending binding for that request_id (claim it first, or it was already registered)",
        );
    };
    let field = |k: &str| {
        row.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let label = field("label");
    // The binding's `device_pubkey` holds the agent's EVM address (§10.2).
    let agent_address = field("device_pubkey");
    let actor_omni = field("child_omni");
    let device_key_hash = field("device_key_hash");
    let pop_sig = field("pop_sig");
    if label.is_empty()
        || agent_address.is_empty()
        || actor_omni.is_empty()
        || device_key_hash.is_empty()
        || pop_sig.is_empty()
    {
        return pairing_err(
            StatusCode::BAD_GATEWAY,
            "pending binding is missing device fields (label/address/omni/key-hash/pop-sig)",
        );
    }
    let tx = match register_agent_device(
        &agent_script.to_string_lossy(),
        &label,
        &agent_address,
        &actor_omni,
        &device_key_hash,
        &pop_sig,
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            return pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("registerAgentDevice: {e}"),
            )
        }
    };
    // Clear it from the broker's pending list (best-effort — the chain write is
    // the binding act; a failed ack just leaves a stale pending row).
    if let Err(e) = agentkeys_cli::agent_admin::agent_ack(broker, &req.request_id, &j1).await {
        tracing::warn!("ui-bridge: registered agent but broker ack failed: {e:#}");
    }
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        label = %label,
        actor_omni = %actor_omni,
        tx = tx.as_deref().unwrap_or("(already-registered)"),
        "#214: agent device registered on chain (web pairing)"
    );
    // Surface the freshly-registered agent in the web UI (state.actors) so it
    // appears in the devices view + becomes targetable by the existing scope-grant
    // flow (P.3, /v1/actors/:id/scope/grant). Keyed by `agent-<label>`, mirroring
    // the master actor's in-memory model (chain-backed reload is a separate concern).
    let omni_hex = if actor_omni.starts_with("0x") {
        actor_omni.clone()
    } else {
        format!("0x{actor_omni}")
    };
    let agent_actor = ApiActor {
        id: format!("agent-{label}"),
        omni: omni_hex.clone(),
        omni_hex,
        label: label.clone(),
        role: "agent".into(),
        parent: Some("master".into()),
        derivation: format!("//{label}"),
        device: "sandbox device (§10.2)".into(),
        device_pubkey: agent_address.clone(),
        last_active: "just paired".into(),
        status: "ok".into(),
        vendor: String::new(),
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
        .insert(agent_actor.id.clone(), agent_actor);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "label": label, "actor_omni": actor_omni, "tx_hash": tx })),
    )
        .into_response()
}

/// Shell out to `heima-agent-create.sh --from-pubkey` to submit `registerAgentDevice`
/// for a SANDBOX-generated device key (the master never holds the agent key).
/// Mirrors `register_master_device`. Returns the tx hash (None on idempotent skip).
async fn register_agent_device(
    script: &str,
    label: &str,
    agent_address: &str,
    actor_omni: &str,
    device_key_hash: &str,
    pop_sig: &str,
) -> Result<Option<String>, String> {
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .arg("--label")
        .arg(label)
        .arg("--agent-address")
        .arg(agent_address)
        .arg("--actor-omni")
        .arg(actor_omni)
        .arg("--device-key-hash")
        .arg(device_key_hash)
        .arg("--pop-sig")
        .arg(pop_sig)
        .output()
        .await
        .map_err(|e| format!("spawn {script}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines: Vec<&str> = stderr.lines().rev().take(6).collect();
        lines.reverse();
        return Err(format!(
            "heima-agent-create.sh exited {}: {}",
            output.status,
            lines.join("\n")
        ));
    }
    // The script logs to stderr + prints a final JSON line to stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let tx = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v.get("tx_hash").and_then(|t| t.as_str()).map(String::from));
    Ok(tx)
}

async fn list_master_memory(State(state): State<SharedUiBridgeState>) -> axum::response::Response {
    match resolve_categories(&state).await {
        Ok(categories) => (
            StatusCode::OK,
            Json(serde_json::json!({ "categories": categories })),
        )
            .into_response(),
        Err(reason) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": reason })),
        )
            .into_response(),
    }
}

/// Resolve the category set. Cache fallback is returned ONLY for the two benign
/// cases — Config unconfigured, or the taxonomy object confirmed missing (404 /
/// never planted). Every OTHER Config failure (partial config, cap-mint/STS,
/// worker 5xx, decrypt/parse) is propagated as `Err` so the list 502s instead of
/// silently masking it as an empty store (codex finding 2).
async fn resolve_categories(state: &SharedUiBridgeState) -> Result<Vec<MemoryCategory>, String> {
    match real_config_ctx(state).await {
        Ok(Some(ctx)) => {
            let client = reqwest::Client::new();
            match config_fetch_taxonomy(&client, &ctx).await {
                Ok(Some(tax)) if !tax.categories.is_empty() => Ok(tax.categories),
                // Present-but-empty (unusual) or confirmed-missing taxonomy →
                // fallback is legitimate (nothing durable to list).
                Ok(_) => Ok(fallback_categories(state).await),
                // A configured-but-broken Config store is a HARD error (502), never
                // masked behind in-memory data or an empty list (#201 finding-2):
                // the operator must see + fix it. Real data or a loud failure.
                Err(e) => Err(format!("config taxonomy unavailable: {e}")),
            }
        }
        Ok(None) => Ok(fallback_categories(state).await), // Config not configured
        Err(e) => Err(format!("config not ready: {e}")),  // partial config / no session
    }
}

/// Categories to show when no durable taxonomy is available — the union of the
/// authored in-memory taxonomy (`init`, #207 item 1A) and the cache-derived
/// namespaces (planted memory). Used as the dev/no-infra path and as the
/// real-path fallback when the durable object is missing/empty, so an authored
/// preset is visible even before any memory is planted.
async fn fallback_categories(state: &SharedUiBridgeState) -> Vec<MemoryCategory> {
    let cache_cats = categories_from_cache(state).await;
    match state.authored_taxonomy.read().await.clone() {
        Some(tax) => merge_categories(tax.categories, &cache_cats),
        None => cache_cats,
    }
}

/// Derive categories from the distinct namespaces present in the in-memory
/// cache (the dev/no-infra path + the post-restart fallback before the durable
/// taxonomy is re-read). Labels are title-cased from the namespace.
async fn categories_from_cache(state: &SharedUiBridgeState) -> Vec<MemoryCategory> {
    let guard = state.master_memory.read().await;
    let mut seen = std::collections::BTreeSet::new();
    for e in guard.values() {
        seen.insert(e.ns.clone());
    }
    seen.into_iter()
        .map(|ns| MemoryCategory {
            label: label_for_ns(&ns),
            ns,
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct MemoryEntryQuery {
    pub ns: String,
    #[serde(default)]
    pub key: Option<String>,
}

/// `GET /v1/master/memory/entry?ns=<ns>[&key=<key>]` → the entries in one
/// namespace, decrypted ON DEMAND (#201 Phase 4 lazy detail). Real chain:
/// memory-get(`memory:<ns>`) → decrypt → parse the JSON array. Fallback:
/// filter the in-memory cache. `&key=` narrows to a single entry.
async fn get_master_memory_entry(
    State(state): State<SharedUiBridgeState>,
    axum::extract::Query(q): axum::extract::Query<MemoryEntryQuery>,
) -> axum::response::Response {
    match get_master_memory_entry_inner(&state, &q).await {
        Ok(entries) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ns": q.ns, "entries": entries })),
        )
            .into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn get_master_memory_entry_inner(
    state: &SharedUiBridgeState,
    q: &MemoryEntryQuery,
) -> Result<Vec<ApiMemoryEntry>, (StatusCode, String)> {
    let ctx = real_memory_ctx(state)
        .await
        .map_err(|reason| (StatusCode::CONFLICT, reason))?;
    if let Some(ctx) = ctx {
        let client = reqwest::Client::new();
        let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
            &ctx.broker,
            &ctx.j1,
            &ctx.role_arn,
            &ctx.region,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("STS relay: {e}")))?;
        // Ok(None) → the namespace has no durable blob (nothing to show); a real
        // worker error surfaces as 502 (not an empty list masking a failure).
        let stored = memory_get_ns_real(&client, &ctx, &creds, &q.ns)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?
            .unwrap_or_default();
        Ok(stored
            .into_iter()
            .filter(|s| q.key.as_deref().is_none_or(|k| k == s.key))
            .map(|s| ApiMemoryEntry::from_stored(&q.ns, s))
            .collect())
    } else {
        let guard = state.master_memory.read().await;
        let mut entries: Vec<ApiMemoryEntry> = guard
            .values()
            .filter(|e| e.ns == q.ns && q.key.as_deref().is_none_or(|k| k == e.key))
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(entries)
    }
}

// ─── W3: real memory chain (cap-mint → STS relay → worker → S3) ─────────────
//
// When the daemon has --memory-url + --memory-role-arn + --master-device-key-hash
// AND a master onboarding session, the master plants its OWN memory under its
// actor_omni (operator == actor == O_master) via the same chain the MCP
// http_backend + phase1-wire-demo use. Otherwise plant falls back to the
// in-memory store. Per-actor by construction (cap-mint binds device.actor_omni
// == req.actor_omni); see docs/plan/web-flow/w3-real-memory.md §1.

/// The session-scoped coordinates shared by every real-chain worker call
/// (memory + config): the broker, the master J1, the (normalized) master omni,
/// the on-chain device hash, and the region. Resolved once; the per-data-class
/// contexts add the worker URL + IAM role on top.
struct SessionCoords {
    broker: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// Resolve the master session coordinates or fail loud (issue #90 discipline):
/// a missing broker / unregistered device / absent session is an `Err`, never a
/// silent degrade. Shared by `real_memory_ctx` + `real_config_ctx`.
async fn resolve_session_coords(state: &UiBridgeState) -> Result<SessionCoords, String> {
    let broker = state
        .broker_url
        .clone()
        .ok_or("real chain: worker URL set but --broker-url missing")?;
    // Prefer the device hash from the K11-finish register shell-out (issue #196)
    // — it's the device actually on chain under this session omni. Fall back to
    // the --master-device-key-hash CLI flag (pre-registered device / tests).
    let device_key_hash = match state.registered_master.read().await.as_ref() {
        Some(rm) => rm.device_key_hash.clone(),
        None => state.master_device_key_hash.clone().ok_or(
            "real chain: master device not registered on chain yet (finish K11 \
             enrollment to register) and no --master-device-key-hash fallback set",
        )?,
    };
    let session = state
        .onboarding_session
        .read()
        .await
        .clone()
        .ok_or("real chain: no master session — complete onboarding first")?;
    if session.omni.is_empty() || session.j1.is_empty() {
        return Err("real chain: master session is identity-only (no EVM omni/J1)".into());
    }
    Ok(SessionCoords {
        broker,
        region: state.region.clone(),
        j1: session.j1,
        // The broker cap-mint input-validates that operator_omni/actor_omni start with
        // 0x, but the onboarding session stores the omni bare. Normalize via the ONE
        // shared normalizer (issue #203) so every worker call (memory + config) sends
        // a 0x-prefixed omni and this can't drift from the cap-mint body the
        // MCP/harness paths send (the broker normalize_hex32's it either way).
        omni: agentkeys_backend_client::normalize_omni_0x(&session.omni),
        device_key_hash,
    })
}

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
    let role_arn = state
        .memory_role_arn
        .clone()
        .ok_or("real memory: --memory-url set but MEMORY_ROLE_ARN missing")?;
    let c = resolve_session_coords(state).await?;
    Ok(Some(RealMemoryCtx {
        broker: c.broker,
        memory_url,
        role_arn,
        region: c.region,
        j1: c.j1,
        omni: c.omni,
        device_key_hash: c.device_key_hash,
    }))
}

struct RealConfigCtx {
    broker: String,
    config_url: String,
    role_arn: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// Same `Ok(None)`/`Ok(Some)`/`Err` contract as `real_memory_ctx`, gated on
/// `config_url` (#201 Config data class). When `None`, the taxonomy lives only
/// in the in-memory fallback and the list derives categories from the cache.
async fn real_config_ctx(state: &UiBridgeState) -> Result<Option<RealConfigCtx>, String> {
    let Some(config_url) = state.config_url.clone() else {
        return Ok(None);
    };
    let role_arn = state
        .config_role_arn
        .clone()
        .ok_or("real config: --config-url set but CONFIG_ROLE_ARN missing")?;
    let c = resolve_session_coords(state).await?;
    Ok(Some(RealConfigCtx {
        broker: c.broker,
        config_url,
        role_arn,
        region: c.region,
        j1: c.j1,
        omni: c.omni,
        device_key_hash: c.device_key_hash,
    }))
}

/// Mint a master-self cap for the given broker route (`memory-put` /
/// `memory-get` / `config-store` / `config-fetch`) and `service` string.
/// operator == actor == O_master, so the broker skips the on-chain scope check
/// (#195). Returns the raw cap JSON the worker re-verifies.
///
/// Routes through the shared `agentkeys-backend-client` (issue #203): the
/// cap-mint body IS the crate's `BrokerCapRequest`, so the daemon's cap-mint —
/// for memory AND the #201 config data class — can't drift its shape or omni
/// from the agent/MCP path (the #200 bug locus). Worker put/get bodies use the
/// crate's body types too (see callers); the raw worker POST stays here to reuse
/// the once-minted STS creds across namespaces.
async fn mint_master_cap(
    broker: &str,
    j1: &str,
    omni: &str,
    device_key_hash: &str,
    route: &str,
    service: &str,
) -> Result<agentkeys_backend_client::CapToken, String> {
    use agentkeys_backend_client::{BackendClient, CapMintOp, CapMintRequest};
    let op = match route {
        "memory-put" => CapMintOp::MemoryPut,
        "memory-get" => CapMintOp::MemoryGet,
        "config-store" => CapMintOp::ConfigStore,
        "config-fetch" => CapMintOp::ConfigFetch,
        "cred-store" => CapMintOp::CredStore,
        "cred-fetch" => CapMintOp::CredFetch,
        other => return Err(format!("mint_master_cap: unknown cap route {other}")),
    };
    let client = BackendClient::new(
        Some(broker.to_string()),
        None,
        None,
        None,
        None,
        None,
        None,
        String::new(),
    );
    client
        .cap_mint(
            op,
            CapMintRequest {
                operator_omni: omni.to_string(),
                actor_omni: omni.to_string(),
                service: service.to_string(),
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            j1,
        )
        .await
        .map_err(|e| format!("cap-mint({route}): {e}"))
}

/// Per-namespace memory-put (#201 Phase 4): cap-mint(`memory:<ns>`) → worker
/// `/v1/memory/put` with the JSON array as plaintext. STS creds are minted once
/// by the caller and reused across namespaces. Returns the worker's S3 key.
async fn memory_put_ns_real(
    client: &reqwest::Client,
    ctx: &RealMemoryCtx,
    creds: &agentkeys_provisioner::AwsTempCreds,
    ns: &str,
    entries: &[StoredMemoryEntry],
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "memory-put",
        &format!("memory:{ns}"),
    )
    .await?;
    let plaintext = serde_json::to_vec(entries).map_err(|e| format!("ns array serialize: {e}"))?;
    let put_resp = client
        .post(format!("{}/v1/memory/put", ctx.memory_url))
        .header("x-aws-access-key-id", &creds.access_key_id)
        .header("x-aws-secret-access-key", &creds.secret_access_key)
        .header("x-aws-session-token", &creds.session_token)
        // Crate-owned body shape (issue #203) — a drifted field is a compile error.
        .json(&agentkeys_backend_client::MemoryPutBody {
            cap,
            plaintext_b64: STANDARD.encode(&plaintext),
            namespace: ns.to_string(),
        })
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

/// Per-namespace memory-get (#201 Phase 4 lazy detail): cap-mint(`memory:<ns>`)
/// → worker `/v1/memory/get` → decrypt → parse the JSON array (tolerant of a
/// legacy single-body blob). The whole namespace decrypts in one round-trip.
/// `Ok(Some(entries))` when the namespace blob exists, `Ok(None)` when the
/// worker reports it MISSING (HTTP 404 / `NoSuchKey` — never written), and `Err`
/// on a real worker/transport/decrypt failure. The `Option` is what lets the
/// read-modify-write plant tell "new namespace" (write fresh) from "transient
/// error" (abort — never overwrite durable data) per codex finding 1.
async fn memory_get_ns_real(
    client: &reqwest::Client,
    ctx: &RealMemoryCtx,
    creds: &agentkeys_provisioner::AwsTempCreds,
    ns: &str,
) -> Result<Option<Vec<StoredMemoryEntry>>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "memory-get",
        &format!("memory:{ns}"),
    )
    .await?;
    let get_resp = client
        .post(format!("{}/v1/memory/get", ctx.memory_url))
        .header("x-aws-access-key-id", &creds.access_key_id)
        .header("x-aws-secret-access-key", &creds.secret_access_key)
        .header("x-aws-session-token", &creds.session_token)
        // Crate-owned body shape (issue #203).
        .json(&agentkeys_backend_client::MemoryGetBody {
            cap,
            namespace: ns.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("worker get transport: {e}"))?;
    if get_resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None); // namespace never written
    }
    if !get_resp.status().is_success() {
        let status = get_resp.status();
        let body = get_resp.text().await.unwrap_or_default();
        return Err(format!("worker get {status}: {body}"));
    }
    let parsed: serde_json::Value = get_resp
        .json()
        .await
        .map_err(|e| format!("worker get parse: {e}"))?;
    let b64 = parsed
        .get("plaintext_b64")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| format!("plaintext_b64 decode: {e}"))?;
    let plaintext = String::from_utf8(bytes).map_err(|e| format!("plaintext utf8: {e}"))?;
    Ok(Some(parse_stored_blob(&plaintext, ns)))
}

/// Config-store the master-only memory-types taxonomy (#201): cap-mint
/// (`config-store`, service `memory-taxonomy`) → config worker `/v1/config/put`.
/// Mints its own STS creds under the CONFIG role (distinct from the memory role
/// per arch.md §17.2 per-data-class bucket separation).
async fn config_store_taxonomy(
    client: &reqwest::Client,
    ctx: &RealConfigCtx,
    taxonomy: &MemoryTaxonomy,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "config-store",
        TAXONOMY_SERVICE,
    )
    .await?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| format!("STS relay (config): {e}"))?;
    let plaintext = serde_json::to_vec(taxonomy).map_err(|e| format!("taxonomy serialize: {e}"))?;
    let resp = client
        .post(format!("{}/v1/config/put", ctx.config_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        // Crate-owned body shape (issue #203) — config worker put body.
        .json(&agentkeys_backend_client::ConfigPutBody {
            cap,
            plaintext_b64: STANDARD.encode(&plaintext),
        })
        .send()
        .await
        .map_err(|e| format!("config put transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("config put {status}: {body}"));
    }
    Ok(())
}

/// Config-fetch the taxonomy (#201). `Ok(None)` ONLY when the object is
/// confirmed MISSING (HTTP 404 / `NoSuchKey` — never planted), so the list may
/// legitimately fall back to cache-derived categories. Any OTHER failure
/// (cap-mint, STS, config worker 5xx, decrypt/parse) is an `Err` that the caller
/// MUST surface — never silently downgrade to the cache, which would hide a
/// configured-but-broken Config behind a stale "looks empty" view (codex
/// finding 2).
async fn config_fetch_taxonomy(
    client: &reqwest::Client,
    ctx: &RealConfigCtx,
) -> Result<Option<MemoryTaxonomy>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "config-fetch",
        TAXONOMY_SERVICE,
    )
    .await?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| format!("STS relay (config): {e}"))?;
    let resp = client
        .post(format!("{}/v1/config/get", ctx.config_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        // Crate-owned body shape (issue #203) — config worker get body.
        .json(&agentkeys_backend_client::ConfigGetBody { cap })
        .send()
        .await
        .map_err(|e| format!("config get transport: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Confirmed missing — nothing planted yet. The ONLY legitimate fallback.
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("config get {status}: {body}"));
    }
    let parsed: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("config get parse: {e}"))?;
    let b64 = parsed
        .get("plaintext_b64")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| format!("taxonomy plaintext decode: {e}"))?;
    let taxonomy: MemoryTaxonomy =
        serde_json::from_slice(&bytes).map_err(|e| format!("taxonomy parse: {e}"))?;
    Ok(Some(taxonomy))
}

/// Read-modify-write the durable taxonomy: config-fetch the current
/// `config/memory-taxonomy.enc`, MERGE `new_categories` in (preserving every
/// existing entry, [`merge_categories`]), and config-store the union. Returns the
/// merged categories now durable.
///
/// A fetch ERROR aborts WITHOUT storing — never overwrite a taxonomy we failed to
/// read (the #201 finding-1 footgun, now guarding the category index too). A
/// confirmed-missing object (`Ok(None)`) is a fresh start, not an error. Shared by
/// the test-only `plant` (cache-derived categories) and the authored `init`
/// (preset categories, #207 item 1A) so both compose without clobbering.
async fn reconcile_taxonomy(
    client: &reqwest::Client,
    cfg: &RealConfigCtx,
    new_categories: &[MemoryCategory],
) -> Result<Vec<MemoryCategory>, String> {
    let existing = match config_fetch_taxonomy(client, cfg).await {
        Ok(Some(tax)) => tax.categories,
        Ok(None) => Vec::new(),
        Err(e) => return Err(e),
    };
    let merged = merge_categories(existing, new_categories);
    let taxonomy = MemoryTaxonomy {
        version: 1,
        categories: merged.clone(),
    };
    config_store_taxonomy(client, cfg, &taxonomy).await?;
    Ok(merged)
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
    /// Durable category-index (taxonomy) outcome, surfaced so a configured-Config
    /// store failure is NOT hidden behind an otherwise-successful memory plant
    /// (codex finding 2): `"ok"` (written), `"unconfigured"` (Config not set up,
    /// cache-only), `"failed: <reason>"` (memory IS durable but the category index
    /// is stale → retry), or `"skipped: <reason>"` (config-context unavailable).
    pub taxonomy_status: String,
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
    let mut taxonomy_status = String::from("unconfigured");

    if let Some(ctx) = ctx {
        // REAL chain — read-modify-write per namespace under a plant lock so a
        // restart-stale cache or a concurrent plant can NEVER drop durable
        // entries (codex finding 1). Each namespace write MERGES the current
        // durable blob with the request, so the per-namespace JSON array grows
        // monotonically instead of last-writer-wins overwriting.
        let _plant_guard = state.plant_lock.lock().await;
        let client = reqwest::Client::new();

        // Hash every request entry once, then group by namespace.
        let mut by_ns: std::collections::BTreeMap<String, Vec<ApiMemoryEntry>> =
            std::collections::BTreeMap::new();
        for mut e in req.entries {
            if e.content_hash.is_empty() {
                e.content_hash = e.compute_hash();
            }
            by_ns.entry(e.ns.clone()).or_default().push(e);
        }

        // STS creds (memory role) minted once, reused across namespaces.
        let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
            &ctx.broker,
            &ctx.j1,
            &ctx.role_arn,
            &ctx.region,
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                format!("STS relay: {e}"),
            )
        })?;

        let mut committed: Vec<ApiMemoryEntry> = Vec::new();
        for (ns, entries) in &by_ns {
            // Read the durable blob FIRST. Ok(None) = brand-new namespace;
            // Err = a real worker/transport error → ABORT this plant rather than
            // overwrite durable data we failed to read (the finding-1 footgun).
            let durable = match memory_get_ns_real(&client, &ctx, &creds, ns).await {
                Ok(opt) => opt.unwrap_or_default(),
                Err(e) => {
                    return Err((
                        axum::http::StatusCode::BAD_GATEWAY,
                        format!(
                            "plant aborted: durable read of memory:{ns} failed ({e}) — not overwriting"
                        ),
                    ));
                }
            };
            let (merged, newly) = merge_stored_entries(ns, durable, entries);
            if let Err(e) = memory_put_ns_real(&client, &ctx, &creds, ns, &merged).await {
                return Err((
                    axum::http::StatusCode::BAD_GATEWAY,
                    format!("plant aborted: write of memory:{ns} failed: {e}"),
                ));
            }
            planted += newly;
            skipped += entries.len().saturating_sub(newly);
            committed.extend(entries.iter().cloned());
        }

        // Mirror the committed entries into the in-memory cache (a secondary
        // index for the list/detail fallback + same-session dedup); durable S3
        // remains the source of truth.
        {
            let mut cache = state.master_memory.write().await;
            for e in committed {
                cache.insert(e.content_hash.clone(), e);
            }
        }

        // Reconcile the durable taxonomy LAST, as a read-modify-write MERGE so a
        // plant ADDS its namespaces without ever dropping an authored taxonomy
        // (#207 item 1A) — categories_from_cache only knows planted namespaces.
        // A configured store FAILURE is surfaced as an explicit partial-success
        // status (codex finding 2) — the memory blobs ARE durable, but the
        // category index would be stale, so the operator must know to retry
        // rather than see a silent success.
        taxonomy_status = match real_config_ctx(state).await {
            Ok(Some(cfg)) => {
                let cache_cats = categories_from_cache(state).await;
                match reconcile_taxonomy(&client, &cfg, &cache_cats).await {
                    Ok(_) => "ok".to_string(),
                    Err(e) => {
                        tracing::error!(
                            "plant_master_memory: taxonomy reconcile FAILED (memory durable; \
                             category index stale — retry the plant): {e}"
                        );
                        format!("failed: {e}")
                    }
                }
            }
            Ok(None) => "unconfigured".to_string(),
            Err(e) => {
                tracing::warn!(
                    "plant_master_memory: config-context unavailable (taxonomy skipped): {e}"
                );
                format!("skipped: {e}")
            }
        };
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
        taxonomy_status,
    })
}

// ─── #207 item 1A: config-init entry point A (default-preset bootstrap) ──────

/// One bundled preset, flattened for the wire (the daemon's `MemoryCategory`
/// shape so the UI reuses its category renderer).
#[derive(Serialize)]
struct PresetView {
    id: String,
    label: String,
    description: String,
    categories: Vec<MemoryCategory>,
}

fn preset_categories(p: &crate::presets::ConfigPreset) -> Vec<MemoryCategory> {
    p.categories
        .iter()
        .map(|(ns, label)| MemoryCategory {
            ns: (*ns).to_string(),
            label: (*label).to_string(),
        })
        .collect()
}

/// `GET /v1/master/config/presets` → the bundled default taxonomy presets + the
/// shipped default id (#207 item 1A). Read-only, no session required — these are
/// public bundled defaults (catalog ≠ policy: the presets carry categories, never
/// a tenant's grants).
async fn list_config_presets() -> axum::response::Response {
    let presets: Vec<PresetView> = crate::presets::bundled_presets()
        .iter()
        .map(|p| PresetView {
            id: p.id.to_string(),
            label: p.label.to_string(),
            description: p.description.to_string(),
            categories: preset_categories(p),
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "default_id": crate::presets::DEFAULT_PRESET_ID,
            "presets": presets,
        })),
    )
        .into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct InitConfigRequest {
    /// Preset id to author; empty ⇒ the shipped default (rich adult-household).
    #[serde(default)]
    pub preset_id: String,
}

#[derive(Debug, Serialize)]
pub struct InitConfigResponse {
    /// The preset actually authored (echoes the resolved default for an empty id).
    pub preset_id: String,
    /// `"ok"` (durable `config/memory-taxonomy.enc` written) or `"cached"` (Config
    /// unconfigured — authored into the in-memory mirror only, dev/no-infra).
    pub taxonomy_status: String,
    /// The merged category set now in effect (authored ∪ any pre-existing).
    pub categories: Vec<MemoryCategory>,
}

/// `POST /v1/master/config/init` → author the memory-types taxonomy from a
/// bundled default preset (#207 item 1A, config-init entry point A). This writes
/// the category INDEX, not scope grants — it is master-self (operator == actor;
/// the broker skips the on-chain scope check, #195), the same posture as the
/// plant's taxonomy reconcile. Scope grants are K11-gated and land with
/// auto-distribute (#207 item 5); entry point B (NL → COMPILE) is #207 item 1B.
///
/// Idempotent: re-running merges (never clobbers) so a second init or a later
/// plant only adds namespaces.
async fn init_config_default(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<InitConfigRequest>,
) -> axum::response::Response {
    match init_config_default_inner(&state, &req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn init_config_default_inner(
    state: &SharedUiBridgeState,
    req: &InitConfigRequest,
) -> Result<InitConfigResponse, (StatusCode, String)> {
    let preset = crate::presets::resolve_preset(&req.preset_id).ok_or((
        StatusCode::BAD_REQUEST,
        format!("unknown preset_id: {}", req.preset_id),
    ))?;
    let authored = preset_categories(preset);

    let (taxonomy_status, categories) = match real_config_ctx(state).await {
        Ok(Some(cfg)) => {
            // REAL chain: read-modify-write MERGE into the durable, encrypted Config
            // store. A config worker failure (unreachable / S3 error) is a HARD error
            // — we author REAL durable data or fail loud. NO in-memory fallback that
            // masks a broken store (#201 finding-2): the operator must fix the Config
            // data class (provision the bucket + role, deploy/repair the worker).
            let client = reqwest::Client::new();
            let merged = reconcile_taxonomy(&client, &cfg, &authored)
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!(
                            "taxonomy authoring failed — the Config data class must be healthy \
                             (config worker reachable + its bucket/role provisioned with S3 \
                             Get/Put/List on bots/<actor>/config/*): {e}"
                        ),
                    )
                })?;
            ("ok".to_string(), merged)
        }
        // No `--config-url` configured AT ALL: the explicit dev/no-infra mode —
        // author into the in-memory mirror so the local UI works WITHOUT a config
        // worker. This is NOT a degrade of a configured store (that fails loud
        // above); it is the honest absence of one.
        Ok(None) => {
            let existing = state
                .authored_taxonomy
                .read()
                .await
                .clone()
                .map(|t| t.categories)
                .unwrap_or_default();
            ("cached".to_string(), merge_categories(existing, &authored))
        }
        // Partial config (config-url set but role missing) / no session — a real
        // misconfiguration the operator must fix; fail loud.
        Err(e) => return Err((StatusCode::CONFLICT, format!("config not ready: {e}"))),
    };

    // Write-through the in-memory mirror in both paths (the unconfigured home,
    // and a cache aligned with durable Config for the real path).
    *state.authored_taxonomy.write().await = Some(MemoryTaxonomy {
        version: 1,
        categories: categories.clone(),
    });

    // Audit the authoring action. The taxonomy is the Config data class; the
    // closest existing audit chip is `memory` (it IS the memory-types taxonomy).
    let evt = ApiAuditEvent {
        id: format!("e-cfg-init-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "config.taxonomy".into(),
        detail: format!(
            "authored taxonomy · preset {} · {} categories",
            preset.id,
            categories.len()
        ),
        chip: "memory".into(),
        sev: "ok".into(),
    };
    push_audit(state, evt).await;

    Ok(InitConfigResponse {
        preset_id: preset.id.to_string(),
        taxonomy_status,
        categories,
    })
}

// ─── #207 items 5 + 7: classification (cred-categorize + auto-distribute) ────
//
// The CLASSIFY BRIDGE. Two paths, same deterministic catalog data:
//   • worker (audited) — when `--classify-url` + a real session: mint a master-self
//     `Classify` cap → `POST /v1/classify/tag`. Picks up signed vendor overlays + audit.
//   • local tier-0 — otherwise: the bundled `agentkeys-catalog` in-process
//     (deterministic, free, no infra). This IS the intended tier-0 (#178 §8.1).
//
// Determinism guardrail (#178 §5): TAG returns a category + sensitivity, NEVER
// allow/deny. The sensitivity comes from the CATALOG floor (not a vendor/telemetry
// prior, #207 §3 invariant 2). `propose` proposes scopes; it NEVER writes one —
// the confirm/grant path (the existing K11-gated `update_scope`) is the only writer,
// so an unconfirmed sensitive category produces NO scope grant by construction.

/// Process-wide bundled catalog (tier-0). Built once.
fn bundled_catalog() -> &'static agentkeys_catalog::Catalog {
    static CATALOG: std::sync::OnceLock<agentkeys_catalog::Catalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(agentkeys_catalog::Catalog::bundled)
}

/// Normalize/validate a data-class string to the cap's snake_case set. Defaults
/// to `credentials` (the common cred-categorize case) for an empty value.
fn normalize_data_class(s: &str) -> Result<&'static str, String> {
    match s.trim().to_lowercase().as_str() {
        "" | "credentials" | "cred" => Ok("credentials"),
        "memory" => Ok("memory"),
        "config" => Ok("config"),
        other => Err(format!("unknown data_class: {other}")),
    }
}

/// The auto-distribute gating tier for a category's sensitivity (#207 §3 inv. 2):
/// Safe → `auto` (auto-confirm + daily review); Sensitive → `k11` (explicit confirm).
/// The tier comes from the CATALOG floor, so a vendor/telemetry prior can't downgrade it.
fn gating_for(s: agentkeys_catalog::Sensitivity) -> &'static str {
    match s {
        agentkeys_catalog::Sensitivity::Safe => "auto",
        agentkeys_catalog::Sensitivity::Sensitive => "k11",
    }
}

/// The signed `service` string a scope grant would be over: memory → `memory:<ns>`,
/// credentials/other → the lowercased entity (service id). Matches the cap layer.
fn service_for(data_class: &str, entity: &str) -> String {
    match data_class {
        "memory" => format!("memory:{}", entity.trim().to_lowercase()),
        _ => entity.trim().to_lowercase(),
    }
}

/// Mint a master-self `Classify` cap for `(data_class, entity)` via the broker.
async fn mint_master_classify_cap(
    client: &reqwest::Client,
    broker: &str,
    j1: &str,
    omni: &str,
    device_key_hash: &str,
    data_class: &str,
) -> Result<serde_json::Value, String> {
    let service = format!("classify:{data_class}");
    let resp = client
        .post(format!("{broker}/v1/cap/classify"))
        .bearer_auth(j1)
        .json(&serde_json::json!({
            "operator_omni": omni,
            "actor_omni": omni,
            "service": service,
            "device_key_hash": device_key_hash,
            "data_class": data_class,
            "ttl_seconds": 300,
        }))
        .send()
        .await
        .map_err(|e| format!("classify cap-mint transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "classify cap-mint {status}: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("classify cap json: {e}"))
}

/// The audited worker TAG path. `Ok(None)` when `--classify-url` is unset (caller
/// falls back to the local tier-0); `Err` on a real failure (session/cap/worker).
async fn classify_via_worker(
    state: &SharedUiBridgeState,
    data_class: &str,
    entity: &str,
) -> Result<Option<agentkeys_catalog::Classification>, String> {
    let Some(classify_url) = state.classify_url.clone() else {
        return Ok(None);
    };
    let coords = resolve_session_coords(state).await?;
    let client = reqwest::Client::new();
    let cap = mint_master_classify_cap(
        &client,
        &coords.broker,
        &coords.j1,
        &coords.omni,
        &coords.device_key_hash,
        data_class,
    )
    .await?;
    let resp = client
        .post(format!("{classify_url}/v1/classify/tag"))
        .json(&serde_json::json!({ "cap": cap, "data_class": data_class, "entity": entity }))
        .send()
        .await
        .map_err(|e| format!("classify tag transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "classify tag {status}: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("classify tag json: {e}"))?;
    let classification = serde_json::from_value(body["classification"].clone())
        .map_err(|e| format!("classification parse: {e}"))?;
    Ok(Some(classification))
}

/// Classify an entity → category + sensitivity. For MEMORY the entity is a
/// namespace = a category, so its sensitivity is the catalog FLOOR (#207 item 8,
/// agent memory inheritance) — a deterministic local lookup. For credentials/config
/// the entity is a service: worker (audited) when configured + reachable, else the
/// bundled catalog tier-0 (same data, deterministic).
async fn classify_entity(
    state: &SharedUiBridgeState,
    data_class: &str,
    entity: &str,
) -> agentkeys_catalog::Classification {
    if data_class == "memory" {
        return bundled_catalog().classify_namespace(entity);
    }
    if state.classify_url.is_some() {
        match classify_via_worker(state, data_class, entity).await {
            Ok(Some(c)) => return c,
            Ok(None) => {}
            Err(e) => tracing::warn!("classify worker path failed, using local tier-0: {e}"),
        }
    }
    bundled_catalog().tag(entity)
}

#[derive(Debug, Deserialize)]
pub struct ClassifyTagRequest {
    #[serde(default)]
    pub data_class: String,
    pub entity: String,
}

/// `POST /v1/master/classify/tag` (#207 item 7 — cred auto-categorize). Classify a
/// minted credential's service (or any entity) → its category + sensitivity, so the
/// master can confirm a `cred:<service>` grant. Read-only; never writes scope.
async fn classify_tag(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ClassifyTagRequest>,
) -> axum::response::Response {
    let data_class = match normalize_data_class(&req.data_class) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if req.entity.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "entity required" })),
        )
            .into_response();
    }
    let c = classify_entity(&state, data_class, &req.entity).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data_class": data_class,
            "entity": req.entity.trim().to_lowercase(),
            "service": service_for(data_class, &req.entity),
            "classification": c,
            "audited": state.classify_url.is_some(),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct SurfaceItem {
    #[serde(default)]
    pub data_class: String,
    pub entity: String,
}

#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    #[serde(default)]
    pub actor_id: String,
    pub surface: Vec<SurfaceItem>,
}

/// One proposed scope grant. `gating` is the sensitivity tier from the CATALOG:
/// `auto` (Safe → auto-confirm + surface in the daily review) | `k11` (Sensitive →
/// explicit per-grant K11 confirm). NEVER granted here — `propose` only proposes.
#[derive(Debug, Serialize)]
pub struct ProposedScope {
    pub data_class: String,
    pub entity: String,
    pub service: String,
    pub category: String,
    pub sensitivity: agentkeys_catalog::Sensitivity,
    pub gating: &'static str,
    pub confidence: f32,
}

/// `POST /v1/master/classify/propose` (#207 item 5 — connect-time auto-distribute).
/// Classify an agent's surface (the memory namespaces it reads + the cred services
/// it uses) and PROPOSE scopes, sensitivity-tiered. This writes NOTHING: safe
/// proposals are `auto` (the UI can confirm a reviewed set in one gesture); sensitive
/// ones are `k11` (explicit per-grant confirm). The grant itself is the existing
/// K11-gated `update_scope` path — so an unconfirmed sensitive category produces NO
/// scope grant (the load-bearing #207 §3 invariant 2, true by construction).
async fn classify_propose(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ProposeRequest>,
) -> axum::response::Response {
    let mut proposals: Vec<ProposedScope> = Vec::new();
    for item in &req.surface {
        let data_class = match normalize_data_class(&item.data_class) {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e })),
                )
                    .into_response()
            }
        };
        if item.entity.trim().is_empty() {
            continue;
        }
        let c = classify_entity(&state, data_class, &item.entity).await;
        let gating = gating_for(c.sensitivity);
        proposals.push(ProposedScope {
            data_class: data_class.to_string(),
            entity: item.entity.trim().to_lowercase(),
            service: service_for(data_class, &item.entity),
            category: c.category,
            sensitivity: c.sensitivity,
            gating,
            confidence: c.confidence,
        });
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "actor_id": req.actor_id, "proposals": proposals })),
    )
        .into_response()
}

// ─── #207: master CREDENTIALS surface (same abstraction as memory) ───────────
//
// Credentials are a first-class data class in the app, mirroring memory: the
// memory list resolves namespaces → categories (the taxonomy); the credentials
// list resolves stored services → categories (the catalog). Both are
// list-then-categorize over the master's own real data. Real data or a loud
// failure — no in-memory stand-in (the unconfigured dev case is an honest empty).

struct RealCredCtx {
    broker: String,
    cred_url: String,
    role_arn: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// Resolve the cred-worker context from env (`AGENTKEYS_WORKER_CRED_URL` +
/// `VAULT_ROLE_ARN`, which the daemon's launcher sources from
/// operator-workstation.env) + the master session. `Ok(None)` when the cred
/// worker isn't configured (dev/no-infra). A partial config (URL set but role
/// missing) fails loud (issue #90 discipline).
async fn real_cred_ctx(state: &UiBridgeState) -> Result<Option<RealCredCtx>, String> {
    let cred_url = match std::env::var("AGENTKEYS_WORKER_CRED_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return Ok(None),
    };
    let role_arn = std::env::var("VAULT_ROLE_ARN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("real cred: AGENTKEYS_WORKER_CRED_URL set but VAULT_ROLE_ARN missing")?;
    let c = resolve_session_coords(state).await?;
    Ok(Some(RealCredCtx {
        broker: c.broker,
        cred_url,
        role_arn,
        region: c.region,
        j1: c.j1,
        omni: c.omni,
        device_key_hash: c.device_key_hash,
    }))
}

/// A categorized credential service — the cred parallel to `MemoryCategory`:
/// the service id + its catalog category + sensitivity (so the UI groups creds
/// by category exactly like memory namespaces).
#[derive(Debug, Serialize)]
pub struct CredService {
    pub service: String,
    pub category: String,
    pub sensitivity: agentkeys_catalog::Sensitivity,
}

/// `GET /v1/master/credentials` — list the master's stored credential services
/// (cred worker `/v1/cred/list`), each categorized via the catalog. The
/// per-data-class parallel to `GET /v1/master/memory`. Unconfigured (no cred
/// worker) → empty (honest dev); a configured-but-broken worker → 502.
async fn list_master_credentials(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    match list_master_credentials_inner(&state).await {
        Ok(creds) => (
            StatusCode::OK,
            Json(serde_json::json!({ "credentials": creds })),
        )
            .into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn list_master_credentials_inner(
    state: &SharedUiBridgeState,
) -> Result<Vec<CredService>, (StatusCode, String)> {
    let ctx = match real_cred_ctx(state).await {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(Vec::new()), // no cred worker configured (dev) → empty
        Err(e) => return Err((StatusCode::CONFLICT, format!("cred not ready: {e}"))),
    };
    let client = reqwest::Client::new();
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "cred-fetch",
        "credentials",
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred cap-mint: {e}")))?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("STS relay (cred): {e}")))?;
    let resp = client
        .post(format!("{}/v1/cred/list", ctx.cred_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        .json(&serde_json::json!({ "cap": cap }))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred list transport: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "cred list {status}: {}",
                resp.text().await.unwrap_or_default()
            ),
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred list json: {e}")))?;
    let services: Vec<String> = body["services"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::with_capacity(services.len());
    for svc in services {
        let c = classify_entity(state, "credentials", &svc).await;
        out.push(CredService {
            service: svc,
            category: c.category,
            sensitivity: c.sensitivity,
        });
    }
    out.sort_by(|a, b| {
        (a.category.clone(), a.service.clone()).cmp(&(b.category.clone(), b.service.clone()))
    });
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct StoreCredRequest {
    pub service: String,
    pub secret: String,
}

/// `POST /v1/master/credentials/store` — vault a master credential (mint a
/// master-self `cred-store` cap → STS → cred worker `/v1/cred/store`). The
/// credential parallel to the memory plant. Real durable write or a loud failure.
async fn store_master_credential(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<StoreCredRequest>,
) -> axum::response::Response {
    let service = req.service.trim().to_lowercase();
    if service.is_empty() || service.len() > 64 || req.secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "service (1..=64) and secret are required" })),
        )
            .into_response();
    }
    let ctx = match real_cred_ctx(&state).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "no cred worker configured (set AGENTKEYS_WORKER_CRED_URL + VAULT_ROLE_ARN)" })),
            )
                .into_response()
        }
        Err(e) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": format!("cred not ready: {e}") }))).into_response()
        }
    };
    match store_master_credential_inner(&ctx, &service, &req.secret).await {
        Ok(category) => {
            let evt = ApiAuditEvent {
                id: format!("e-cred-store-{}", now_unix()),
                ts: now_ts_hms(),
                actor_id: "master".into(),
                actor: "master".into(),
                kind: "credential.store".into(),
                detail: format!("vaulted credential · {service} · {category}"),
                chip: "creds".into(),
                sev: "ok".into(),
            };
            push_audit(&state, evt).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "service": service, "category": category })),
            )
                .into_response()
        }
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn store_master_credential_inner(
    ctx: &RealCredCtx,
    service: &str,
    secret: &str,
) -> Result<String, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let client = reqwest::Client::new();
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "cred-store",
        service,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred cap-mint: {e}")))?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("STS relay (cred): {e}")))?;
    let resp = client
        .post(format!("{}/v1/cred/store", ctx.cred_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        .json(
            &serde_json::json!({ "cap": cap, "plaintext_b64": STANDARD.encode(secret.as_bytes()) }),
        )
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("cred store transport: {e}"),
            )
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "cred store {status}: {}",
                resp.text().await.unwrap_or_default()
            ),
        ));
    }
    Ok(bundled_catalog().tag(service).category)
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

    /// #214: a broker PendingBinding row (post-claim, §10.2) maps to the web UI's
    /// PairingRequest shape — label→agent, requested_scope→RequestedPerm[],
    /// device_pubkey→dpub. The device key is surfaced for display only, never as
    /// a secret, and the HDKD derivation path is reconstructed from the label.
    #[test]
    fn pending_binding_maps_to_pairing_request() {
        let row = serde_json::json!({
            "request_id": "req-abc123def456",
            "child_omni": "0xchildomni",
            "operator_omni": "0xmasteromni",
            "label": "demo-agent",
            "requested_scope": "memory:travel,memory:family",
            "device_pubkey": "0x04aabbccddeeff00112233445566778899aabbcc",
            "pop_sig": "0xsignaturedeadbeef0011223344556677",
        });
        let pr = pending_binding_to_request(&row);
        assert_eq!(pr["id"], "req-abc123def456");
        assert_eq!(pr["agent"], "demo-agent");
        assert_eq!(pr["derivation"], "//demo-agent");
        assert_eq!(pr["dpubFull"], "0x04aabbccddeeff00112233445566778899aabbcc");
        let requested = pr["requested"].as_array().expect("requested is an array");
        assert_eq!(requested.len(), 2, "two scope tokens");
        assert_eq!(requested[0]["cap"], "memory");
        assert_eq!(requested[0]["ns"][0], "travel");
        assert_eq!(requested[1]["ns"][0], "family");
    }

    /// #214: the pairing routes (poll / claim / register) require a configured
    /// broker — `make_state` has none, so every one fails closed with 503 rather
    /// than reaching the network. (Live broker behavior is the harness e2e.)
    #[tokio::test]
    async fn pairing_routes_fail_closed_without_a_broker() {
        let state = make_state();
        assert_eq!(
            list_pairing_requests(State(state.clone())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            claim_pairing(
                State(state.clone()),
                Json(ClaimPairingRequest {
                    pairing_code: "PAIR-1234".into(),
                    label: "demo-agent".into(),
                    requested_scope: String::new(),
                }),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            register_pairing(
                State(state),
                Json(RegisterPairingRequest {
                    request_id: "req-1".into(),
                }),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Pin the master-memory plant CONTRACT (the daemon's web API) to the
    /// committed fixture that `daemon.ts` + `web-parity-demo.sh` are gated
    /// against (issue #203 / the #206 parity ladder, rung 2). The Rust struct +
    /// route const are the source of truth; this test fails the moment they
    /// drift from the fixture, so a field rename or route change can't silently
    /// leave phase 6 green on the old path. If you change `ApiMemoryEntry` or the
    /// route on purpose, update `harness/fixtures/web-api/master_memory_plant.json`
    /// to match (and the two consumers will be re-gated by the bash check).
    #[test]
    fn master_memory_plant_contract_matches_fixture() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../harness/fixtures/web-api/master_memory_plant.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");

        assert_eq!(
            fixture["route"].as_str().expect("fixture.route"),
            MASTER_MEMORY_PLANT_ROUTE,
            "route const drifted from the web-api fixture"
        );

        let sample = ApiMemoryEntry {
            ns: "travel".into(),
            key: "probe".into(),
            title: "t".into(),
            bytes: 1,
            version: "v1".into(),
            updated: "2026-06-05".into(),
            preview: "p".into(),
            body: "b".into(),
            content_hash: String::new(),
        };
        let mut got: Vec<String> = serde_json::to_value(&sample)
            .expect("entry serializes")
            .as_object()
            .expect("entry is an object")
            .keys()
            .cloned()
            .collect();
        got.sort();
        let want: Vec<String> = fixture["entry_keys"]
            .as_array()
            .expect("fixture.entry_keys")
            .iter()
            .map(|v| v.as_str().expect("entry_key is str").to_string())
            .collect();
        assert_eq!(
            got, want,
            "ApiMemoryEntry keys drifted from the web-api fixture — regenerate \
             harness/fixtures/web-api/master_memory_plant.json + re-gate daemon.ts/web-parity-demo.sh"
        );
    }

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
            None,
            None,
            None,
            "us-east-1".into(),
            None,
            None,
        )
        .unwrap()
    }

    fn cat(ns: &str, label: &str) -> MemoryCategory {
        MemoryCategory {
            ns: ns.into(),
            label: label.into(),
        }
    }

    // ─── #207 item 1A: authored-taxonomy bootstrap ──────────────────────────

    #[test]
    fn merge_categories_preserves_existing_and_adds_new() {
        // Existing labels win (an authored label / user edit is never clobbered);
        // a new ns is appended; output is ns-sorted for a stable blob.
        let existing = vec![cat("travel", "Travel"), cat("finance", "Finance")];
        let incoming = vec![
            cat("finance", "Finance & Investment"), // same ns → existing label kept
            cat("kids", "Kids"),                    // new ns → added
        ];
        let merged = merge_categories(existing, &incoming);
        let by_ns: std::collections::BTreeMap<_, _> = merged
            .iter()
            .map(|c| (c.ns.as_str(), c.label.as_str()))
            .collect();
        assert_eq!(by_ns.get("finance"), Some(&"Finance")); // existing wins
        assert_eq!(by_ns.get("kids"), Some(&"Kids"));
        assert_eq!(merged.len(), 3);
        // ns-sorted
        let ns: Vec<&str> = merged.iter().map(|c| c.ns.as_str()).collect();
        assert_eq!(ns, ["finance", "kids", "travel"]);
    }

    #[tokio::test]
    async fn init_default_authors_taxonomy_not_plant_derived() {
        // Acceptance (#207): the DEFAULT preset writes a REAL authored taxonomy
        // even with ZERO memory planted — the old path could only derive
        // categories from planted namespaces.
        let state = make_state();
        let resp = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init default");
        assert_eq!(resp.preset_id, crate::presets::DEFAULT_PRESET_ID);
        assert_eq!(resp.taxonomy_status, "cached"); // Config unconfigured in tests
        let ns: Vec<&str> = resp.categories.iter().map(|c| c.ns.as_str()).collect();
        for required in ["kids", "business", "smart-home", "finance", "family"] {
            assert!(
                ns.contains(&required),
                "authored taxonomy missing {required}"
            );
        }
        // And the master-memory list now resolves those authored categories with
        // NOTHING planted (proves "authored, not plant-derived").
        let listed = resolve_categories(&state).await.expect("resolve");
        assert_eq!(listed.len(), resp.categories.len());
    }

    #[tokio::test]
    async fn init_then_plant_preserves_authored_categories() {
        // Author a preset, then simulate a plant (a memory entry in the cache).
        // The list must be authored ∪ planted — the plant adds its namespace but
        // never drops an authored one (merge-not-clobber).
        let state = make_state();
        init_config_default_inner(
            &state,
            &InitConfigRequest {
                preset_id: "investor".into(),
            },
        )
        .await
        .expect("init investor");

        state.master_memory.write().await.insert(
            "h1".into(),
            ApiMemoryEntry {
                ns: "travel".into(),
                key: "chengdu".into(),
                title: "Chengdu".into(),
                bytes: 4,
                version: "v1".into(),
                updated: "2026-06-06".into(),
                preview: "trip".into(),
                body: "trip".into(),
                content_hash: "h1".into(),
            },
        );

        let listed = resolve_categories(&state).await.expect("resolve");
        let ns: std::collections::BTreeSet<&str> = listed.iter().map(|c| c.ns.as_str()).collect();
        // authored investor namespaces survive…
        assert!(ns.contains("investment") && ns.contains("markets"));
        // …and the planted namespace is added.
        assert!(ns.contains("travel"));
    }

    #[tokio::test]
    async fn init_is_idempotent() {
        let state = make_state();
        let first = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init 1")
            .categories
            .len();
        let second = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init 2")
            .categories
            .len();
        assert_eq!(first, second, "re-init must not grow the taxonomy");
    }

    #[tokio::test]
    async fn init_preserves_a_pre_existing_planted_namespace() {
        // Idempotency invariant (#207): init MERGES into the existing taxonomy —
        // it must NEVER clobber/delete a namespace a prior plant added. Seed a
        // "planted" namespace not in any preset, then init the default; the
        // planted namespace must survive alongside the newly-authored ones.
        let state = make_state();
        *state.authored_taxonomy.write().await = Some(MemoryTaxonomy {
            version: 1,
            categories: vec![cat("chengdu-trip", "Chengdu Trip")],
        });
        let resp = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init");
        let ns: Vec<&str> = resp.categories.iter().map(|c| c.ns.as_str()).collect();
        assert!(
            ns.contains(&"chengdu-trip"),
            "init DELETED the planted namespace — not idempotent/non-destructive"
        );
        assert!(
            ns.contains(&"kids"),
            "init did not add the preset categories"
        );
    }

    #[tokio::test]
    async fn init_unknown_preset_is_bad_request() {
        let state = make_state();
        let err = init_config_default_inner(
            &state,
            &InitConfigRequest {
                preset_id: "nope".into(),
            },
        )
        .await
        .expect_err("unknown preset must 400");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    // ─── #207 items 5 + 7: classify bridge + auto-distribute gating ─────────

    #[tokio::test]
    async fn classify_entity_local_categorizes_known_service() {
        // No --classify-url ⇒ local catalog tier-0. A known service resolves to
        // its category + the catalog floor sensitivity (cred auto-categorize, #207 7).
        let state = make_state();
        let stripe = classify_entity(&state, "credentials", "Stripe").await;
        assert_eq!(stripe.category, "payments");
        assert_eq!(
            stripe.sensitivity,
            agentkeys_catalog::Sensitivity::Sensitive
        );
        let notion = classify_entity(&state, "credentials", "notion").await;
        assert_eq!(notion.category, "productivity");
        assert_eq!(notion.sensitivity, agentkeys_catalog::Sensitivity::Safe);
    }

    #[tokio::test]
    async fn classify_entity_local_unknown_is_deny_by_default() {
        let state = make_state();
        let u = classify_entity(&state, "credentials", "totally-unknown-xyz").await;
        assert_eq!(u.category, "unknown");
        assert_eq!(u.sensitivity, agentkeys_catalog::Sensitivity::Sensitive);
    }

    #[test]
    fn gating_tiers_safe_auto_sensitive_k11() {
        // #207 §3 invariant 2: Safe → auto (auto-confirm + daily review),
        // Sensitive → k11 (explicit per-grant confirm). The tier is the CATALOG's.
        assert_eq!(gating_for(agentkeys_catalog::Sensitivity::Safe), "auto");
        assert_eq!(gating_for(agentkeys_catalog::Sensitivity::Sensitive), "k11");
    }

    #[tokio::test]
    async fn auto_distribute_sensitive_service_is_k11_gated() {
        // The load-bearing invariant surfaced: a sensitive cred (stripe→payments)
        // proposes as k11 (NOT auto) — it can never be silently granted; only the
        // explicit K11 confirm path writes scope. A safe one (notion) is auto.
        let state = make_state();
        let stripe = classify_entity(&state, "credentials", "stripe").await;
        assert_eq!(gating_for(stripe.sensitivity), "k11");
        let notion = classify_entity(&state, "credentials", "notion").await;
        assert_eq!(gating_for(notion.sensitivity), "auto");
    }

    #[test]
    fn service_for_builds_memory_and_cred_services() {
        assert_eq!(service_for("memory", "Travel"), "memory:travel");
        assert_eq!(service_for("credentials", "OpenRouter"), "openrouter");
    }

    #[tokio::test]
    async fn memory_namespace_inheritance_uses_category_floor() {
        // #207 item 8 — a memory namespace is classified as its CATEGORY (floor),
        // not a service lookup: travel → Safe (auto), health/finance → Sensitive
        // (explicit pick). A namespace the catalog doesn't vouch for → Sensitive.
        let state = make_state();
        let travel = classify_entity(&state, "memory", "travel").await;
        assert_eq!(travel.category, "travel");
        assert_eq!(gating_for(travel.sensitivity), "auto");
        let health = classify_entity(&state, "memory", "health").await;
        assert_eq!(gating_for(health.sensitivity), "k11");
        let finance = classify_entity(&state, "memory", "finance").await;
        assert_eq!(gating_for(finance.sensitivity), "k11");
        // unknown namespace → conservative Sensitive (explicit pick).
        let kids = classify_entity(&state, "memory", "kids").await;
        assert_eq!(gating_for(kids.sensitivity), "k11");
    }

    #[tokio::test]
    async fn list_credentials_empty_when_cred_worker_unconfigured() {
        // Credentials are the same abstraction as memory, with the same honesty:
        // no cred worker configured (AGENTKEYS_WORKER_CRED_URL unset in `cargo test`)
        // → empty (real-data-or-nothing, no in-memory stand-in). A configured-but-
        // broken worker would 502 instead (real_cred_ctx Ok(Some) → worker error).
        if std::env::var("AGENTKEYS_WORKER_CRED_URL")
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            return; // runner has a cred worker configured — skip the unconfigured assertion
        }
        let state = make_state();
        let creds = list_master_credentials_inner(&state).await.expect("list");
        assert!(creds.is_empty());
    }

    #[test]
    fn normalize_data_class_defaults_and_validates() {
        assert_eq!(normalize_data_class("").unwrap(), "credentials");
        assert_eq!(normalize_data_class("Memory").unwrap(), "memory");
        assert!(normalize_data_class("payments").is_err());
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
            None,
            None,
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
            None,
            None,
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
    async fn grant_service_scope_records_cred_and_memory() {
        // #207 items 7/8 — a CONFIRMED grant persists in actor state + audits.
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = grant_service_scope(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(GrantScopeRequest {
                data_class: "credentials".into(),
                entity: "openrouter".into(),
                category: "ai-services".into(),
                gating: "auto".into(),
            }),
        )
        .await
        .unwrap();
        assert!(resp
            .0
            .services
            .as_ref()
            .unwrap()
            .contains(&"openrouter".to_string()));

        let resp2 = grant_service_scope(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(GrantScopeRequest {
                data_class: "memory".into(),
                entity: "travel".into(),
                category: "travel".into(),
                gating: "k11".into(),
            }),
        )
        .await
        .unwrap();
        assert!(resp2.0.scope.as_ref().unwrap().get("travel").unwrap().read);
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "scope.granted"));
    }

    #[tokio::test]
    async fn grant_service_scope_unknown_actor_404() {
        let state = make_state();
        let err = grant_service_scope(
            State(state),
            Path("nope".into()),
            Json(GrantScopeRequest {
                data_class: "credentials".into(),
                entity: "x".into(),
                category: String::new(),
                gating: String::new(),
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

    // ─── #201 Phase 4: taxonomy categories + per-ns array + lazy detail ───

    #[test]
    fn label_for_ns_titlecases() {
        assert_eq!(label_for_ns("travel"), "Travel");
        assert_eq!(label_for_ns("personal"), "Personal");
        assert_eq!(label_for_ns(""), "");
    }

    #[test]
    fn parse_stored_blob_reads_json_array() {
        let blob = r#"[{"key":"chengdu-trip","title":"Chengdu trip","body":"Apr 12-16","updated":"2026-04-02","bytes":9}]"#;
        let entries = parse_stored_blob(blob, "travel");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "chengdu-trip");
        assert_eq!(entries[0].body, "Apr 12-16");
    }

    #[test]
    fn parse_stored_blob_tolerates_legacy_single_body() {
        // A pre-#201 single-body blob (or an agent-written one) becomes a
        // one-element array keyed by the namespace — the read path never breaks.
        let entries = parse_stored_blob("Chengdu trip — Apr 12 to 16", "travel");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "travel");
        assert!(entries[0].body.contains("Chengdu"));
    }

    #[test]
    fn to_stored_from_stored_round_trip() {
        let e = mem_entry("travel", "chengdu", "trip body");
        let s = e.to_stored();
        assert_eq!(s.key, "chengdu");
        assert_eq!(s.body, "trip body");
        let back = ApiMemoryEntry::from_stored("travel", s);
        assert_eq!(back.ns, "travel");
        assert_eq!(back.key, "chengdu");
        assert_eq!(back.body, "trip body");
    }

    #[tokio::test]
    async fn list_master_memory_returns_categories_from_cache_fallback() {
        // No config_url ⇒ categories derive from the planted namespaces (sorted,
        // deduped, title-cased), with ZERO memory decryption.
        let state = make_state();
        plant_master_memory_inner(
            &state,
            PlantRequest {
                entries: vec![
                    mem_entry("travel", "chengdu", "trip"),
                    mem_entry("personal", "profile", "name: Kevin"),
                    mem_entry("travel", "customs", "customs note"),
                ],
            },
        )
        .await
        .unwrap();
        let resp = list_master_memory(State(state)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let cats = json["categories"].as_array().unwrap();
        assert_eq!(cats.len(), 2, "two distinct namespaces");
        assert_eq!(cats[0]["ns"], "personal");
        assert_eq!(cats[0]["label"], "Personal");
        assert_eq!(cats[1]["ns"], "travel");
    }

    #[tokio::test]
    async fn get_master_memory_entry_filters_ns_and_key() {
        let state = make_state();
        plant_master_memory_inner(
            &state,
            PlantRequest {
                entries: vec![
                    mem_entry("travel", "chengdu", "trip body"),
                    mem_entry("travel", "customs", "customs body"),
                    mem_entry("personal", "profile", "profile body"),
                ],
            },
        )
        .await
        .unwrap();
        // ns only → both travel entries (lazy detail, in-memory fallback).
        let all = get_master_memory_entry_inner(
            &state,
            &MemoryEntryQuery {
                ns: "travel".into(),
                key: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|e| e.ns == "travel"));
        // ns + key → exactly one entry.
        let one = get_master_memory_entry_inner(
            &state,
            &MemoryEntryQuery {
                ns: "travel".into(),
                key: Some("chengdu".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].key, "chengdu");
        assert_eq!(one[0].body, "trip body");
    }

    // ─── #201 Phase 4 codex fixes: durable merge + configured-Config surfacing ──

    fn stored(key: &str, body: &str) -> StoredMemoryEntry {
        StoredMemoryEntry {
            key: key.into(),
            title: key.into(),
            body: body.into(),
            updated: "2026-04-02".into(),
            bytes: body.len() as u64,
        }
    }

    #[test]
    fn merge_preserves_durable_when_request_omits_them() {
        // codex finding 1: durable entries read back from S3 (e.g. after a daemon
        // restart, so they're ABSENT from the in-memory cache) MUST survive a
        // plant that only carries a new entry for the same namespace.
        let durable = vec![
            stored("chengdu-trip", "Apr 12-16"),
            stored("customs", "note"),
        ];
        let incoming = vec![mem_entry("travel", "anniversary", "dinner 2026-06-15")];
        let (merged, newly) = merge_stored_entries("travel", durable, &incoming);
        assert_eq!(newly, 1);
        assert_eq!(
            merged.len(),
            3,
            "durable entries preserved, new one appended"
        );
        let keys: Vec<&str> = merged.iter().map(|m| m.key.as_str()).collect();
        assert!(
            keys.contains(&"chengdu-trip")
                && keys.contains(&"customs")
                && keys.contains(&"anniversary")
        );
        assert!(
            keys.windows(2).all(|w| w[0] <= w[1]),
            "sorted by key for a stable blob"
        );
    }

    #[test]
    fn merge_dedups_identical_content() {
        // Re-planting content already in the durable blob is a no-op (newly == 0).
        let durable = vec![stored("profile", "name: Kevin")];
        let incoming = vec![mem_entry("personal", "profile", "name: Kevin")];
        let (merged, newly) = merge_stored_entries("personal", durable, &incoming);
        assert_eq!(newly, 0);
        assert_eq!(merged.len(), 1, "no duplicate appended");
    }

    #[test]
    fn merge_same_key_different_body_keeps_both() {
        // Content-hash identity: editing a key's body adds a 2nd entry (matches
        // the in-memory model) rather than dropping the original.
        let durable = vec![stored("profile", "v1")];
        let incoming = vec![mem_entry("personal", "profile", "v2")];
        let (merged, newly) = merge_stored_entries("personal", durable, &incoming);
        assert_eq!(newly, 1);
        assert_eq!(merged.len(), 2);
    }

    #[tokio::test]
    async fn list_master_memory_surfaces_configured_config_error() {
        // codex finding 2: a CONFIGURED-but-broken Config (--config-url set but
        // CONFIG_ROLE_ARN missing) must NOT silently fall back to the cache and
        // report an empty 200 — it surfaces as 502 so the operator sees it.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            Some("https://config.example".into()), // config_url set
            None,                                  // CONFIG_ROLE_ARN missing → partial config
            None,                                  // classify_url
            "us-east-1".into(),
            None,
            None,
        )
        .unwrap();
        let resp = list_master_memory(State(state)).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn plant_reports_taxonomy_status_unconfigured_in_fallback() {
        // No config_url ⇒ the plant's taxonomy_status is the honest "unconfigured"
        // (not a fake "ok"), so the caller knows the durable index wasn't touched.
        let state = make_state();
        let r = plant_master_memory_inner(
            &state,
            PlantRequest {
                entries: vec![mem_entry("travel", "chengdu", "trip")],
            },
        )
        .await
        .unwrap();
        assert_eq!(r.taxonomy_status, "unconfigured");
        assert_eq!(r.planted, 1);
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

    #[tokio::test]
    async fn decode_audit_event_returns_real_calldata_and_envelope() {
        // #153: GET /v1/audit/:id/decode wires the real decoder. Assert the
        // registry-derived fields (selector/function/op_kind label) which are
        // independent of which chain profile CI resolves.
        let state = make_state();
        let evt = ApiAuditEvent {
            id: "dec-1".into(),
            ts: "00:00:00".into(),
            actor_id: "agent-x".into(),
            actor: "X".into(),
            kind: "audit.append".into(),
            detail: "stored a credential".into(),
            chip: "credentials".into(),
            sev: "ok".into(),
        };
        push_audit(&state, evt).await;

        let resp = decode_audit_event(State(state.clone()), Path("dec-1".into()))
            .await
            .expect("decode must succeed");
        let v = resp.0;
        assert_eq!(v["tier"], serde_json::json!("tier-2"));
        assert_eq!(v["tx"]["to_contract"], serde_json::json!("CredentialAudit"));
        assert_eq!(
            v["tx"]["decoded"]["selector"],
            serde_json::json!("0xc1bf0e32")
        );
        assert_eq!(v["tx"]["decoded"]["function"], serde_json::json!("append"));
        assert_eq!(
            v["envelope"]["op_kind_label"],
            serde_json::json!("cred.store")
        );

        // unknown id → 404
        let err = decode_audit_event(State(state), Path("nope".into()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn chain_info_serves_resolved_profile_and_contract_array() {
        let state = make_state();
        let name = state.chain_profile.name.clone();
        let chain_id = state.chain_profile.chain_id;
        let resp = chain_info(State(state)).await;
        let v = resp.0;
        assert_eq!(v["name"], serde_json::json!(name));
        assert_eq!(v["chainId"], serde_json::json!(chain_id));
        assert!(v["contracts"].is_array(), "contracts must be an array");
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
            None,
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
