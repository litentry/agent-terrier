//! #577 — the ONE-CLICK delegate image update + the staleness surface.
//!
//! `POST /v1/agent/update` (J1_master-gated) replaces the archive+respawn
//! ceremony for image rollouts: it kills the delegate's live sandbox and
//! re-creates it against the CURRENT precached image **reusing the durable
//! #546 spawn context** — same actor/omni, same K10 derivation (a fresh #552
//! J1 is minted per create), same chat channel, no on-chain write, no Touch
//! ID, no slot movement. Between kill and re-create it performs a BEST-EFFORT
//! Hermes-home hand-off: export the old instance's on-disk `$HERMES_HOME`
//! state through the in-sandbox daemon's #577 management surface, import it
//! into the replacement, then re-source the agent. Every degradation
//! (pre-#577 image with no export endpoint, ECS backend with no
//! broker-routable management path, oversized home) is SURFACED in the
//! response — the update itself still lands.
//!
//! What the hand-off can and cannot preserve (measured, not assumed): Hermes
//! keeps its config / persona / skills / backups on disk under `$HERMES_HOME`
//! — those migrate. The live ACP conversation is held in the hermes bridge's
//! process MEMORY (`hermes_bridge.py` — "the session IS the memory") and dies
//! with the instance, exactly as it already does at every veFaaS expiry
//! (default lifetime 1440 min). Making the transcript itself durable is a
//! Hermes-config/persistence question tracked in #577's follow-ups, not
//! something this relay can conjure.
//!
//! `POST /v1/agent/image-status` (same auth) is the staleness signal: veFaaS
//! exposes no image digest, but an instance FREEZES the pre-cache
//! registration id it spawned from (`DescribeSandbox.ImageInfo.Id`) while a
//! #568 refresh mints a NEW registration id for the same tag — so
//! `frozen ≠ current` is exactly "this delegate runs old bits", now visible
//! in parent-control instead of via a shell probe.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use agentkeys_core::audit::{envelope_for, AuditOpKind, AuditResult, SandboxTeardownBody};

use crate::handlers::accept::{aerr, bearer, eth_call, load_accept_config, norm_omni, selector};
use crate::handlers::revoke::{parse_device_probe, DeviceProbe};
use crate::state::SharedState;

/// Ceiling for one exported Hermes home (the JSON snapshot body, bytes).
/// `$HERMES_HOME` is config + persona + skills docs (32 KiB/skill cap at the
/// bridge) + optional upstream backups — tens of KiB in practice; 32 MiB is
/// generous headroom, and anything larger is refused LOUDLY rather than
/// relayed through broker RAM unbounded (D2: the snapshot only ever lives in
/// this request's memory, never at rest).
const SESSION_SNAPSHOT_MAX_BYTES: usize = 32 * 1024 * 1024;

/// How long the import phase retries against the REPLACEMENT instance before
/// giving up (its daemon needs a few seconds after CreateSandbox returns).
const IMPORT_RETRY_WINDOW_SECS: u64 = 60;
const IMPORT_RETRY_INTERVAL_SECS: u64 = 5;

// ─── wire types ──────────────────────────────────────────────────────────────

/// `POST /v1/agent/update` body (J1_master-gated). One delegate per request —
/// parent-control's "Update all" iterates client-side, so a slow create never
/// holds N delegates' outcomes hostage to one HTTP response.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentUpdateRequest {
    pub operator_omni: String,
    pub device_key_hash: String,
    /// Update even while the delegate's background jobs (#340) are running
    /// (their output stream dies with the instance). Default: refuse loudly.
    #[serde(default)]
    pub force: bool,
}

/// One update outcome. `sandbox` mirrors the ceremony/resolve `"sandbox"`
/// object (`{sandbox_id,status,error}`) so the daemon can refresh the
/// manifest runtime the same way it does at spawn.
#[derive(Debug, Serialize)]
pub struct AgentUpdateResponse {
    pub device_key_hash: String,
    /// The instances this update tore down (normally exactly one).
    pub old_sandbox_ids: Vec<String>,
    pub sandbox: serde_json::Value,
    pub session: SessionHandoff,
}

/// The Hermes-home hand-off outcome — always present, never silent.
#[derive(Debug, Serialize)]
pub struct SessionHandoff {
    pub migrated: bool,
    pub detail: String,
}

/// `POST /v1/agent/image-status` body (J1_master-gated): the caller names the
/// delegates it can see (the broker keeps no per-operator delegate index —
/// chain is the registry, D1); each hash is chain-verified to belong to the
/// session operator before any instance detail is returned.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageStatusRequest {
    pub operator_omni: String,
    pub device_key_hashes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ImageStatusResponse {
    /// The broker's configured `CR_IMAGE` tag ref (`null` = app default /
    /// no registration-based backend).
    pub image: Option<String>,
    /// The CURRENT pre-cache registration id for `image` — what a create
    /// issued now would freeze.
    pub current_registration_id: Option<String>,
    /// The current registration's preheat state (`success` = 已预热).
    pub precache_status: Option<String>,
    pub delegates: Vec<DelegateImageStatus>,
}

#[derive(Debug, Serialize)]
pub struct DelegateImageStatus {
    pub device_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_status: Option<String>,
    /// The instance's veFaaS lease deadline as RFC3339 (normalized at the
    /// driver boundary — the vendor's own `2026-08-15 15:50:54 +0800 CST`
    /// form is NOT safe for a client's `Date.parse`). Absent on backends
    /// without a lease (ECS tasks have no expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_at: Option<String>,
    /// The registration id this instance froze at spawn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub booted_registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub booted_image_url: Option<String>,
    /// The LIVE agent identity the instance's bridge `/healthz` reports —
    /// what is actually RUNNING, not what the image tag claims. `agent_engine`
    /// is the ACP agent name (`hermes-agent`), `agent_version` its version
    /// (the #483 bump cadence's ground truth), `model` the LLM endpoint id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// `true` = running older bits than the current registration; `null` =
    /// unknowable (no live instance / default image / no registration).
    pub stale: Option<bool>,
    /// Per-delegate probe failure (chain probe, describe) — the row is still
    /// returned so one bad hash never hides the rest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── shared auth + chain probe ───────────────────────────────────────────────

/// J1 session auth + operator match (the spawn/archive rule, minus the
/// master-ACCOUNT resolution — an update performs no chain write, so a
/// legacy-EOA master may still update). Returns the normalized session omni.
fn auth_session(
    state: &SharedState,
    headers: &HeaderMap,
    operator_omni: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let token = bearer(headers)?;
    let claims = crate::jwt::verify::verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &token,
    )
    .map_err(|e| aerr(StatusCode::UNAUTHORIZED, format!("session jwt: {e}")))?;
    if norm_omni(&claims.agentkeys.omni_account) != norm_omni(operator_omni) {
        return Err(aerr(StatusCode::FORBIDDEN, "operator_mismatch"));
    }
    Ok(norm_omni(&claims.agentkeys.omni_account))
}

/// Chain-probe one delegate binding and require: registered, not revoked,
/// TIER_AGENT (2), owned by `session_omni`. Returns the probe (its
/// `actor_omni` is the chain-read identity the re-create is labeled with).
async fn probe_owned_delegate(
    state: &SharedState,
    rpc_url: &str,
    registry: &[u8; 20],
    session_omni: &str,
    device_key_hash: &str,
) -> Result<DeviceProbe, String> {
    let hash: [u8; 32] = hex::decode(norm_omni(device_key_hash))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("device_key_hash must be 32 bytes hex")?;
    let data = format!("0x{}{}", selector("getDevice(bytes32)"), hex::encode(hash));
    let raw = eth_call(&state.http, rpc_url, registry, &data).await?;
    let probe = parse_device_probe(&raw)?;
    if !probe.registered || probe.revoked {
        return Err("binding is revoked or was never registered".into());
    }
    let operator_bytes: [u8; 32] = hex::decode(session_omni)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("session omni must be 32 bytes")?;
    if probe.operator_omni != operator_bytes {
        return Err("the binding belongs to a different operator".into());
    }
    if probe.tier != 2 {
        return Err(format!(
            "update is for DELEGATES (TIER_AGENT) — this binding is tier {}",
            probe.tier
        ));
    }
    Ok(probe)
}

// ─── the in-sandbox management client (#577 hand-off) ────────────────────────

/// One bearer-gated call to an instance's in-sandbox management surface,
/// through the backend's routing headers.
#[allow(clippy::too_many_arguments)] // thin HTTP shim — a param per wire fact
async fn mgmt_request(
    http: &reqwest::Client,
    base: &str,
    headers: &[(String, String)],
    token: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Vec<u8>>,
    timeout_secs: u64,
) -> Result<Vec<u8>, String> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut req = http
        .request(method, &url)
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(timeout_secs));
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(b);
    }
    let resp = req.send().await.map_err(|e| format!("{path}: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("{path} body: {e}"))?
        .to_vec();
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&bytes);
        // char-boundary-safe truncation — byte slicing would panic mid-UTF-8.
        let detail: String = detail.trim().chars().take(300).collect();
        return Err(format!(
            "{path} HTTP {status}{}{detail}",
            if detail.is_empty() { "" } else { ": " },
        ));
    }
    Ok(bytes)
}

/// `jobs_running` per the OLD instance's management status (`null` inside the
/// JSON = the in-sandbox daemon couldn't reach its bridge — treated as "not
/// provably running", surfaced in the detail).
fn parse_jobs_running(status_body: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(status_body).ok()?;
    v.get("jobs").and_then(|j| j.as_u64())
}

/// The live agent identity one instance's bridge `/healthz` reports —
/// deliberately the RUNNING truth (the ACP handshake's agent name/version),
/// not the image tag's claim.
#[derive(Debug, Default, PartialEq, Eq)]
struct AgentHealth {
    engine: Option<String>,
    version: Option<String>,
    model: Option<String>,
}

/// Parse the bridge `/healthz` body. The bridge answers 200 when the ACP
/// agent is alive and 503 while it (re)starts — BOTH carry the same body
/// shape, so the caller parses regardless of status. Placeholder values the
/// bridge uses before the handshake (`"?"`) normalize to `None`.
fn parse_agent_health(body: &[u8]) -> AgentHealth {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return AgentHealth::default();
    };
    let field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "?" && *s != "(unset)")
            .map(str::to_string)
    };
    AgentHealth {
        engine: field("engine"),
        version: field("version"),
        model: field("model"),
    }
}

/// GET one instance's bridge `/healthz` through the gateway routing headers.
/// Unauthenticated by design (veFaaS health-checks it), short-fused, and
/// best-effort: any transport failure yields empty fields, never an error —
/// a stale/booting instance's row still renders.
async fn fetch_agent_health(
    http: &reqwest::Client,
    base: &str,
    headers: &[(String, String)],
) -> AgentHealth {
    let url = format!("{}/healthz", base.trim_end_matches('/'));
    let mut req = http.get(&url).timeout(std::time::Duration::from_secs(8));
    for (k, v) in headers {
        req = req.header(k, v);
    }
    match req.send().await {
        Ok(resp) => match resp.bytes().await {
            Ok(bytes) => parse_agent_health(&bytes),
            Err(_) => AgentHealth::default(),
        },
        Err(_) => AgentHealth::default(),
    }
}

// ─── POST /v1/agent/update ───────────────────────────────────────────────────

pub async fn agent_update(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<AgentUpdateRequest>,
) -> Result<Json<AgentUpdateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    let Some(backend) = state.sandbox.clone() else {
        return Err(aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "no sandbox lifecycle configured on this host (SANDBOX_FUNCTION_ID / \
             AGENTKEYS_SANDBOX_ECS_CLUSTER both unset) — nothing to update",
        ));
    };
    let (cfg, _broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let probe = probe_owned_delegate(
        &state,
        &cfg.rpc_url,
        &cfg.registry,
        &session_omni,
        &req.device_key_hash,
    )
    .await
    .map_err(|e| aerr(StatusCode::CONFLICT, e))?;
    let actor_omni = format!("0x{}", hex::encode(probe.actor_omni));
    let operator_omni_0x = format!("0x{session_omni}");

    // Pre-flight BEFORE any kill: a delegate without a durable spawn context
    // (#546) would re-create chat-silent — refuse up front, never mid-flight.
    match state.spawn_context_store.get(&req.device_key_hash) {
        Ok(Some(ctx)) if !ctx.k10_secret_hex.is_empty() || !ctx.k10_address.is_empty() => {}
        Ok(_) => {
            return Err(aerr(
                StatusCode::CONFLICT,
                "no durable spawn context for this delegate (pre-#546 spawn?) — an in-place \
                 update would re-create it chat-silent; archive + respawn instead",
            ));
        }
        Err(e) => {
            return Err(aerr(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn-context read failed: {e}"),
            ));
        }
    }

    let session_bytes32: [u8; 32] = hex::decode(&session_omni)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0u8; 32]);
    match rotate_delegate_runtime(
        &state,
        &backend,
        &req.device_key_hash,
        &actor_omni,
        &operator_omni_0x,
        session_bytes32,
        req.force,
        "update",
    )
    .await
    {
        Ok(outcome) => Ok(Json(AgentUpdateResponse {
            device_key_hash: req.device_key_hash,
            old_sandbox_ids: outcome.old_sandbox_ids,
            sandbox: outcome.sandbox_json,
            session: outcome.session,
        })),
        Err(RotateError::JobsRunning(n)) => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "jobs_running",
                "jobs": n,
                "message": format!(
                    "{n} background job(s) are running in this delegate's sandbox — \
                     updating now kills them and their output stream. Wait for them \
                     to finish, or pass force=true to update anyway."
                ),
            })),
        )),
        Err(RotateError::Failed(e)) => Err(aerr(StatusCode::BAD_GATEWAY, e)),
    }
}

// ─── the shared rotate core (#577 update · #594 lease sweeper) ───────────────

/// One completed rotate: what was killed, the ensure outcome, the hand-off.
pub(crate) struct RotateOutcome {
    pub old_sandbox_ids: Vec<String>,
    pub sandbox_json: serde_json::Value,
    pub session: SessionHandoff,
}

pub(crate) enum RotateError {
    /// #340 background jobs are live and `force` was not set — nothing was
    /// touched. The handler maps this to its 409; the sweeper retries next
    /// sweep (until its force margin).
    JobsRunning(u64),
    /// Failed before anything was re-created (list/kill) — nothing torn down
    /// beyond what the message says; safe to retry.
    Failed(String),
}

/// The rotate sequence both the #577 one-click update and the #594 lease
/// sweeper run: best-effort snapshot of the live instance → #340 jobs guard →
/// kill (+ one `SandboxTeardown` envelope per instance, with the caller's
/// reason) → re-create through the #546 `ensure_for_delegate` path → import
/// the snapshot into the replacement (retry while its bridge boots). ONE
/// owner, so the operator-clicked and lease-driven paths can never drift.
///
/// `audit_omni` labels the teardown envelopes: the verified session omni on
/// the handler path, the chain-probed operator omni on the sweeper path (the
/// authority the standing spawn-on-pair lifecycle acts under).
#[allow(clippy::too_many_arguments)] // the one rotate owner — a param per fact
pub(crate) async fn rotate_delegate_runtime(
    state: &SharedState,
    backend: &crate::sandbox_backend::SandboxBackend,
    device_key_hash: &str,
    actor_omni: &str,
    operator_omni_0x: &str,
    audit_omni: [u8; 32],
    force: bool,
    teardown_reason: &str,
) -> Result<RotateOutcome, RotateError> {
    let rotate_started = std::time::Instant::now();
    let live = backend
        .live_for_device(device_key_hash)
        .await
        .map_err(|e| RotateError::Failed(format!("list live instances: {e:#}")))?;
    tracing::info!(
        device_key_hash = %device_key_hash,
        reason = %teardown_reason,
        live_instances = live.len(),
        "#577 rotate: starting (snapshot → kill → re-create → import)"
    );

    // #640 — a session hand-off is only meaningful within ONE runtime family:
    // a snapshot is a runtime-home byte image (#616), so importing a hermes
    // home into DSH_HOME (or back, on a rollback) plants the wrong home
    // format. Skip the hand-off on POSITIVE evidence of a family switch (the
    // old instance's spawn-frozen tag vs what the #620 valve resolves now);
    // unknowns (ECS, console-default image) keep the hand-off, never guess.
    let runtime_switch: Option<(String, String)> = match (live.first(), backend.current_image_tag())
    {
        (Some(inst), Some(current)) => backend
            .booted_image_info(&inst.id)
            .await
            .ok()
            .flatten()
            .filter(|b| is_runtime_family_switch(&b.source_image_url, &current))
            .map(|b| (b.source_image_url, current)),
        _ => None,
    };

    // Snapshot + job guard against the OLD instance (best-effort, loud).
    let mgmt_token =
        crate::handlers::sandbox::sandbox_mgmt_token(&state.session_keypair, device_key_hash);
    let mut snapshot: Option<Vec<u8>> = None;
    let mut session_detail: String;
    if live.is_empty() {
        session_detail = "no live instance — cold start, nothing to migrate".to_string();
    } else if let Some((base, route_headers)) = backend.instance_mgmt_endpoint(&live[0].id) {
        match mgmt_request(
            &state.http,
            &base,
            &route_headers,
            &mgmt_token,
            reqwest::Method::GET,
            "/v1/sandbox/mgmt/status",
            None,
            15,
        )
        .await
        {
            Ok(body) => {
                let jobs = parse_jobs_running(&body);
                if let Some(n) = jobs.filter(|n| *n > 0) {
                    if !force {
                        return Err(RotateError::JobsRunning(n));
                    }
                    tracing::warn!(
                        device_key_hash = %device_key_hash,
                        jobs = n,
                        reason = %teardown_reason,
                        "#577 rotate FORCED over {n} running background job(s) — their output dies with the instance"
                    );
                }
            }
            // A status failure is not fatal: pre-#577 images have no mgmt
            // surface at all. The export attempt below reports the same cause.
            Err(e) => tracing::info!(
                device_key_hash = %device_key_hash,
                error = %e,
                "#577 rotate: old-instance status probe failed (pre-#577 image?) — proceeding"
            ),
        }
        if let Some((old_image, new_image)) = &runtime_switch {
            session_detail = format!(
                "session hand-off skipped: runtime family switch ({} → {}) — a home snapshot \
                 is runtime-keyed (#616); the replacement starts from canonical memory",
                image_repo(old_image),
                image_repo(new_image)
            );
            tracing::info!(
                device_key_hash = %device_key_hash,
                old_image = %old_image,
                new_image = %new_image,
                "#640 rotate: session hand-off skipped — runtime family switch"
            );
        } else {
            match mgmt_request(
                &state.http,
                &base,
                &route_headers,
                &mgmt_token,
                reqwest::Method::GET,
                "/v1/sandbox/mgmt/session/export",
                None,
                60,
            )
            .await
            {
                Ok(body) if body.len() > SESSION_SNAPSHOT_MAX_BYTES => {
                    session_detail = format!(
                        "session export skipped: snapshot {} bytes exceeds the {} byte cap",
                        body.len(),
                        SESSION_SNAPSHOT_MAX_BYTES
                    );
                }
                Ok(body) => {
                    session_detail = format!("exported {} bytes from the old instance", body.len());
                    snapshot = Some(body);
                }
                Err(e) => {
                    session_detail = format!(
                        "session export unavailable ({e}) — updated without the Hermes-home \
                         hand-off (a pre-#577 image has no export surface; this heals once the \
                         new image runs)"
                    );
                }
            }
        }
    } else {
        session_detail =
            "session hand-off unsupported on this backend (no broker-routable management path)"
                .to_string();
    }

    // Teardown — the same kill the unpair hook performs, with the caller's
    // reason ("update" / "lease-expiry").
    let killed = backend
        .kill_for_device(device_key_hash)
        .await
        .map_err(|e| {
            RotateError::Failed(format!("teardown failed (nothing re-created yet): {e:#}"))
        })?;
    for sandbox_id in &killed {
        let env = envelope_for(
            audit_omni,
            audit_omni,
            AuditOpKind::SandboxTeardown,
            SandboxTeardownBody {
                device_key_hash: device_key_hash.to_string(),
                sandbox_id: sandbox_id.clone(),
                reason: teardown_reason.into(),
            },
            AuditResult::Success,
            None,
            None,
        );
        crate::handlers::sandbox::append_best_effort(env).await;
    }

    // Re-create from the durable spawn context — the SAME path a veFaaS
    // expiry re-create takes (#546 reconstruction + fresh #552 J1 + lazily
    // re-provisioned metered gate key), so update can never drift from it.
    let provision = crate::handlers::sandbox::ensure_for_delegate(
        state,
        device_key_hash,
        actor_omni,
        operator_omni_0x,
    )
    .await;
    let sandbox_json = provision
        .as_ref()
        .map(|p| p.to_json())
        .unwrap_or(serde_json::Value::Null);
    let new_id = provision.as_ref().and_then(|p| p.sandbox_id.clone());

    // Restore into the replacement (retry while its daemon boots).
    let mut migrated = false;
    if let (Some(bytes), Some(new_id)) = (snapshot, new_id.as_deref()) {
        if let Some((base, route_headers)) = backend.instance_mgmt_endpoint(new_id) {
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_secs(IMPORT_RETRY_WINDOW_SECS);
            let mut last_err;
            loop {
                match mgmt_request(
                    &state.http,
                    &base,
                    &route_headers,
                    &mgmt_token,
                    reqwest::Method::POST,
                    "/v1/sandbox/mgmt/session/import",
                    Some(bytes.clone()),
                    60,
                )
                .await
                {
                    Ok(body) => {
                        let v: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                        // #594 — the bridge's newer-wins guard may skip a
                        // stale snapshot (applied:false); a pre-#594 bridge
                        // has no `applied` field and always applied.
                        if v.get("applied").and_then(|b| b.as_bool()).unwrap_or(true) {
                            migrated = true;
                            session_detail = format!(
                                "hermes home migrated ({} file(s); agent re-sourced: {})",
                                v.get("restored_files")
                                    .and_then(|n| n.as_u64())
                                    .unwrap_or(0),
                                v.get("agent_restarted")
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false),
                            );
                        } else {
                            session_detail = format!(
                                "import skipped by the bridge's newer-wins guard (a fresher \
                                 snapshot was already applied): {v}"
                            );
                        }
                        break;
                    }
                    Err(e) => last_err = e,
                }
                if std::time::Instant::now() >= deadline {
                    session_detail = format!(
                        "exported, but import into the replacement kept failing for \
                         {IMPORT_RETRY_WINDOW_SECS}s (last: {last_err}) — the new instance runs \
                         with a fresh Hermes home"
                    );
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(IMPORT_RETRY_INTERVAL_SECS))
                    .await;
            }
        }
    }

    tracing::info!(
        device_key_hash = %device_key_hash,
        reason = %teardown_reason,
        killed = killed.len(),
        new_sandbox = %new_id.as_deref().unwrap_or("(create failed)"),
        migrated,
        handoff = %session_detail,
        elapsed_ms = rotate_started.elapsed().as_millis() as u64,
        "#577 rotate: complete"
    );
    Ok(RotateOutcome {
        old_sandbox_ids: killed,
        sandbox_json,
        session: SessionHandoff {
            migrated,
            detail: session_detail,
        },
    })
}

// ─── POST /v1/agent/image-status ─────────────────────────────────────────────

pub async fn agent_image_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ImageStatusRequest>,
) -> Result<Json<ImageStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    let Some(backend) = state.sandbox.clone() else {
        // No lifecycle on this host: an empty, explicit answer — the UI shows
        // "no runtime" rather than a guessed staleness.
        return Ok(Json(ImageStatusResponse {
            image: None,
            current_registration_id: None,
            precache_status: None,
            delegates: req
                .device_key_hashes
                .iter()
                .map(|dkh| DelegateImageStatus {
                    device_key_hash: dkh.clone(),
                    sandbox_id: None,
                    sandbox_status: None,
                    expire_at: None,
                    booted_registration_id: None,
                    booted_image_url: None,
                    agent_engine: None,
                    agent_version: None,
                    model: None,
                    stale: None,
                    error: None,
                })
                .collect(),
        }));
    };
    let (cfg, _broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;

    let current = backend
        .current_image_registration()
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, format!("{e:#}")))?;

    let mut delegates = Vec::with_capacity(req.device_key_hashes.len());
    for dkh in &req.device_key_hashes {
        let mut row = DelegateImageStatus {
            device_key_hash: dkh.clone(),
            sandbox_id: None,
            sandbox_status: None,
            expire_at: None,
            booted_registration_id: None,
            booted_image_url: None,
            agent_engine: None,
            agent_version: None,
            model: None,
            stale: None,
            error: None,
        };
        if let Err(e) =
            probe_owned_delegate(&state, &cfg.rpc_url, &cfg.registry, &session_omni, dkh).await
        {
            row.error = Some(e);
            delegates.push(row);
            continue;
        }
        match backend.live_for_device(dkh).await {
            Ok(live) => {
                if let Some(first) = live.first() {
                    row.sandbox_id = Some(first.id.clone());
                    row.sandbox_status = Some(first.status.clone());
                    row.expire_at = Some(first.expire_at.clone()).filter(|s| !s.trim().is_empty());
                    match backend.booted_image_info(&first.id).await {
                        Ok(booted) => {
                            row.stale =
                                crate::ve_faas::image_stale(booted.as_ref(), current.as_ref());
                            if let Some(b) = booted {
                                row.booted_registration_id = Some(b.registration_id);
                                row.booted_image_url = Some(b.source_image_url);
                            }
                        }
                        Err(e) => row.error = Some(format!("describe: {e:#}")),
                    }
                    // The live agent identity, straight from the instance's
                    // bridge healthz — best-effort, never fails the row.
                    if let Some((base, route_headers)) = backend.instance_mgmt_endpoint(&first.id) {
                        let health = fetch_agent_health(&state.http, &base, &route_headers).await;
                        row.agent_engine = health.engine;
                        row.agent_version = health.version;
                        row.model = health.model;
                    }
                }
            }
            Err(e) => row.error = Some(format!("list: {e:#}")),
        }
        delegates.push(row);
    }

    Ok(Json(ImageStatusResponse {
        image: current
            .as_ref()
            .map(|c| c.image_url.clone())
            .or_else(|| backend.current_image_tag()),
        current_registration_id: current.as_ref().map(|c| c.image_id.clone()),
        precache_status: current.as_ref().map(|c| c.precache_status.clone()),
        delegates,
    }))
}

/// The repo path of an image ref — the ref minus a trailing `:tag` (a colon
/// followed by a slash-free suffix; a `host:port/...` ref keeps its port).
fn image_repo(image_ref: &str) -> &str {
    match image_ref.trim().rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo,
        _ => image_ref.trim(),
    }
}

/// #640 — pure verdict: does moving `old_ref` → `current_ref` cross a runtime
/// family (hermes-sandbox ⇄ dsh-sandbox)? Repo-path comparison: a tag bump
/// within one family is NOT a switch (the hand-off stays), a family change in
/// either direction is.
fn is_runtime_family_switch(old_ref: &str, current_ref: &str) -> bool {
    image_repo(old_ref) != image_repo(current_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_repo_strips_only_a_slash_free_tag() {
        assert_eq!(
            image_repo("cr.example.com/agentkeys/dsh-sandbox:v202608241032-gda35a18a"),
            "cr.example.com/agentkeys/dsh-sandbox"
        );
        // Untagged ref stays whole.
        assert_eq!(
            image_repo("cr.example.com/agentkeys/dsh-sandbox"),
            "cr.example.com/agentkeys/dsh-sandbox"
        );
        // A registry port is not a tag.
        assert_eq!(
            image_repo("registry:5000/agentkeys/dsh-sandbox"),
            "registry:5000/agentkeys/dsh-sandbox"
        );
        assert_eq!(
            image_repo("registry:5000/agentkeys/dsh-sandbox:v1"),
            "registry:5000/agentkeys/dsh-sandbox"
        );
    }

    #[test]
    fn runtime_family_switch_fires_on_family_change_only() {
        let hermes = "cr.example.com/agentkeys/hermes-sandbox:v20260813-053412-g753b5d51";
        let dsh = "cr.example.com/agentkeys/dsh-sandbox:v202608241032-gda35a18a";
        // The migration direction and the rollback direction both switch.
        assert!(is_runtime_family_switch(hermes, dsh));
        assert!(is_runtime_family_switch(dsh, hermes));
        // A tag bump within one family is NOT a switch — the hand-off stays.
        assert!(!is_runtime_family_switch(
            dsh,
            "cr.example.com/agentkeys/dsh-sandbox:v299901010101-gdeadbeef"
        ));
        assert!(!is_runtime_family_switch(hermes, hermes));
    }

    #[test]
    fn parse_agent_health_reads_the_bridge_healthz_shape() {
        // The live shape (hermes_bridge.py /healthz — same body on 200 and
        // the 503-while-restarting case, which is why status is ignored).
        let h = parse_agent_health(
            br#"{"ok":true,"engine":"hermes-agent","version":"0.19.0","model":"ep-2025-x"}"#,
        );
        assert_eq!(h.engine.as_deref(), Some("hermes-agent"));
        assert_eq!(h.version.as_deref(), Some("0.19.0"));
        assert_eq!(h.model.as_deref(), Some("ep-2025-x"));
        // Pre-handshake placeholders ("?" / "(unset)") normalize to None —
        // never rendered as a version.
        let h = parse_agent_health(
            br#"{"ok":false,"engine":"hermes-agent","version":"?","model":"(unset)"}"#,
        );
        assert_eq!(h.engine.as_deref(), Some("hermes-agent"));
        assert_eq!(h.version, None);
        assert_eq!(h.model, None);
        assert_eq!(parse_agent_health(b"not json"), AgentHealth::default());
    }

    #[test]
    fn parse_jobs_running_reads_the_mgmt_status_shape() {
        assert_eq!(parse_jobs_running(br#"{"jobs":2}"#), Some(2));
        assert_eq!(parse_jobs_running(br#"{"jobs":0}"#), Some(0));
        // Bridge-unreachable inside the sandbox → jobs null → not provably
        // running (the update proceeds; the status body said why).
        assert_eq!(parse_jobs_running(br#"{"jobs":null}"#), None);
        assert_eq!(parse_jobs_running(b"not json"), None);
    }
}
