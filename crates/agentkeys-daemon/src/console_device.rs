//! #541 / #670 / #682 — the CONSOLE'S OWN DEVICE ACTOR: every parent-control
//! install is a device (arch.md §6.4 — one machine ↔ one device actor) whose
//! channel participation rides its own K10 + child omni, while authority ops
//! keep needing the fresh master session on top. Until this enrollment lands
//! the console publishes through the transitional master-self channel cap
//! (`master_channel_cap`); once enrolled, a card-action tap on the console is
//! a `command` event attributed to THIS actor — the same event a kitchen
//! screen publishes, on the same feed, from a different actor.
//!
//! Enrollment = the ordinary §10.2 device pairing run against the daemon's own
//! K10 (`~/.agentkeys/console-device.key`, generated on this machine, never
//! leaves it — D3): pairing request → the master's claim (this same daemon,
//! its master J1) → `registerAgentDevice` → poll the device J1. Two ways it
//! lands: **folded into an app install** (the FIRST install that binds a
//! display slot registers the console in the SAME batch the app's ONE Touch
//! ID signs — `apps.rs`), or standalone from the endpoints tab (its own accept
//! ceremony). Persisted at `~/.agentkeys/console-device.json` (0600,
//! coordinates only — the key file stays separate); the device session J1 is
//! re-resolved from the key at need (`/v1/agent/resolve`, is_device).
//!
//! The halves are shared with the channel gateway's enrollment
//! (`gateway_device.rs`): [`console_pairing_start`] / [`finish_console_enrollment`]
//! (the device side, for the console) and [`device_accept_build`] /
//! [`device_accept_submit`] (the master's standalone accept).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use agentkeys_backend_client::normalize_omni_0x;
use agentkeys_core::device_crypto::DeviceKey;

use crate::ui_bridge::{
    invalidate_fleet_sync, master_channel_cap, now_unix, pairing_err,
    upsert_binding_manifest_entry, BindingManifestEntry, SharedUiBridgeState, UiBridgeState,
};

/// The persisted console-device coordinates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleDevice {
    /// The console's HDKD child omni (`0x`).
    pub actor_omni: String,
    pub device_key_hash: String,
    pub device_pubkey: String,
    pub label: String,
    pub key_file: String,
    pub broker_url: String,
    pub enrolled_at: u64,
}

/// What the daemon keeps between the claim and the on-chain confirm (the
/// standalone build → submit, or an install's build → submit).
#[derive(Debug, Clone)]
pub(crate) struct ConsoleEnrollPending {
    pub request_id: String,
    pub label: String,
    pub child_omni: String,
    pub device_key_hash: String,
    pub device_pubkey: String,
    pub key_file: String,
}

/// The device-side half of a §10.2 pairing for THIS console: the K10 + the
/// broker's pairing code (the master claims it next).
#[derive(Debug, Clone)]
pub(crate) struct ConsolePairingStart {
    pub request_id: String,
    pub pairing_code: String,
    pub device_pubkey: String,
    pub device_key_hash: String,
    pub pop_sig: String,
    pub key_file: String,
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
}

pub(crate) fn console_device_file() -> String {
    std::env::var("AGENTKEYS_CONSOLE_DEVICE_FILE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("{}/.agentkeys/console-device.json", home()))
}

pub(crate) fn console_key_file() -> String {
    std::env::var("AGENTKEYS_CONSOLE_DEVICE_KEY_FILE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("{}/.agentkeys/console-device.key", home()))
}

/// Load the persisted coordinates for THIS broker (a console enrolled on one
/// stack is not enrolled on another — the omni tree is per stack, #464).
pub(crate) fn load_persisted(broker_url: Option<&str>) -> Option<ConsoleDevice> {
    load_persisted_from(&console_device_file(), broker_url)
}

/// [`load_persisted`] against an explicit file. A record persisted with a BARE
/// actor omni (enrolled before the claim's answer was canonicalized — the bare
/// form failed every cap mint with `actor_omni must start with 0x`) is healed
/// to the `0x` form in memory AND rewritten, so its mints validate without a
/// re-enrollment.
pub(crate) fn load_persisted_from(path: &str, broker_url: Option<&str>) -> Option<ConsoleDevice> {
    // No broker known = no stack to be enrolled on (a persisted enrollment is
    // per stack, #464) — never adopt one blind.
    let broker = broker_url?.trim_end_matches('/');
    let raw = std::fs::read_to_string(path).ok()?;
    let mut dev: ConsoleDevice = serde_json::from_str(&raw).ok()?;
    if broker != dev.broker_url.trim_end_matches('/') {
        return None;
    }
    let canonical = normalize_omni_0x(dev.actor_omni.trim());
    if canonical != dev.actor_omni {
        tracing::info!(
            bare = %dev.actor_omni,
            canonical = %canonical,
            "#541 console device: healing the persisted actor omni to the canonical 0x form"
        );
        dev.actor_omni = canonical;
        if let Err(e) = persist_to(path, &dev) {
            tracing::warn!(
                error = %e,
                "#541 console device: the healed record could not be rewritten — healed in memory only"
            );
        }
    }
    Some(dev)
}

/// The child omni a claim answered with, in the canonical `0x` form every
/// cap-mint body carries ([`normalize_omni_0x`]). The broker's claim relays
/// `child_omni_hex`, which is BARE hex, and the cap-mint validator refuses a
/// bare `actor_omni` — the #200 drift class, re-introduced by the console +
/// gateway enrollments (persisted bare, minted bare: every card-action tap
/// answered 502 `actor_omni must start with 0x`, 2026-09-17).
pub(crate) fn claim_child_omni(claim: &serde_json::Value, label: &str) -> Result<String, String> {
    claim
        .get("child_omni")
        .and_then(|c| c.as_str())
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(normalize_omni_0x)
        .ok_or_else(|| format!("claim ({label}) returned no child_omni"))
}

fn persist(dev: &ConsoleDevice) -> Result<(), String> {
    persist_to(&console_device_file(), dev)
}

fn persist_to(path: &str, dev: &ConsoleDevice) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(dev).map_err(|e| format!("serialize: {e}"))?;
    agentkeys_core::device_crypto::write_key_0600(path, &json)
        .map_err(|e| format!("write {path}: {e}"))
}

/// A slug for the console's device label from the machine's hostname.
pub(crate) fn default_label() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .unwrap_or_else(|| "console".to_string());
    let slug: String = host
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-');
    let slug: String = slug.chars().take(20).collect();
    if slug.is_empty() {
        "console".to_string()
    } else {
        format!("console-{slug}")
    }
}

/// The `requested_scope` a DEVICE enrollment claims with. The broker's pairing
/// poll classifies a claim by its requested scope (`scope_is_device_only`):
/// channel-only ⇒ a device (channels attach, NOTHING spawns); anything else
/// ⇒ a delegate whose sandbox is provisioned at poll — which a console or a
/// gateway must never trigger. A standalone enrollment grants nothing yet, so
/// it names a nominal feed of its own label; an install's enrollment names
/// the app feeds the same batch grants.
pub(crate) fn nominal_device_scope(label: &str) -> String {
    format!("channel-sub:{label}")
}

/// The pairing request for THIS machine's K10: generate/load the key, ask the
/// broker for a pairing code. The master (this daemon) claims it next.
pub(crate) async fn console_pairing_start(
    state: &UiBridgeState,
) -> Result<ConsolePairingStart, String> {
    let broker = state
        .broker_url
        .clone()
        .ok_or_else(|| "no broker configured".to_string())?;
    let key_file = console_key_file();
    let dk =
        DeviceKey::load_or_generate(&key_file, false).map_err(|e| format!("console K10: {e}"))?;
    let device_pubkey = dk.address().to_string();
    let device_key_hash = dk
        .device_key_hash()
        .map_err(|e| format!("console K10 hash: {e}"))?;
    let pop_sig = dk.pop_sig().map_err(|e| format!("console K10 pop: {e}"))?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();
    let resp = http
        .post(format!(
            "{}/v1/agent/pairing/request",
            broker.trim_end_matches('/')
        ))
        .json(&serde_json::json!({ "device_pubkey": device_pubkey, "pop_sig": pop_sig }))
        .send()
        .await
        .map_err(|e| format!("pairing request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("pairing request HTTP {}", resp.status()));
    }
    let requested: serde_json::Value = resp.json().await.unwrap_or_default();
    let request_id = requested
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or("pairing request returned no request_id")?
        .to_string();
    let pairing_code = requested
        .get("pairing_code")
        .and_then(|v| v.as_str())
        .ok_or("pairing request returned no pairing_code")?
        .to_string();
    Ok(ConsolePairingStart {
        request_id,
        pairing_code,
        device_pubkey,
        device_key_hash,
        pop_sig,
        key_file,
    })
}

/// After the binding CONFIRMED on chain (standalone accept or an install
/// batch): prove it from the device side (one poll for the device J1),
/// persist the coordinates, write the manifest row, arm the console actor.
/// Returns the device + whether the poll proved the binding.
pub(crate) async fn finish_console_enrollment(
    state: &UiBridgeState,
    pending: &ConsoleEnrollPending,
) -> Result<(ConsoleDevice, bool), String> {
    let broker = state
        .broker_url
        .clone()
        .ok_or_else(|| "no broker configured".to_string())?;
    let dk = DeviceKey::load_or_generate(&pending.key_file, false)
        .map_err(|e| format!("console K10: {e}"))?;
    let pop_sig = dk.pop_sig().unwrap_or_default();
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();
    let base = broker.trim_end_matches('/');
    let mut proven = false;
    for _ in 0..6 {
        match http
            .post(format!("{base}/v1/agent/pairing/poll"))
            .json(&serde_json::json!({
                "request_id": pending.request_id,
                "device_pubkey": pending.device_pubkey,
                "pop_sig": pop_sig,
            }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                proven = true;
                break;
            }
            Ok(r) if r.status().as_u16() == 202 || r.status().as_u16() == 404 => {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            Ok(r) => {
                tracing::info!(status = %r.status(), "#541 console enroll: poll not ready — the resolve path covers it");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "#541 console enroll: poll transport failed");
                break;
            }
        }
    }
    let dev = ConsoleDevice {
        actor_omni: pending.child_omni.clone(),
        device_key_hash: pending.device_key_hash.clone(),
        device_pubkey: pending.device_pubkey.clone(),
        label: pending.label.clone(),
        key_file: pending.key_file.clone(),
        broker_url: broker.clone(),
        enrolled_at: now_unix(),
    };
    persist(&dev).map_err(|e| format!("persist console device: {e}"))?;
    upsert_binding_manifest_entry(
        state,
        BindingManifestEntry {
            actor_omni: dev.actor_omni.clone(),
            device_key_hash: dev.device_key_hash.clone(),
            label: dev.label.clone(),
            kind: "device".into(),
            granted_service_names: Vec::new(),
            updated_at: now_unix(),
            preset_id: None,
            agent_url: None,
            memory_ns: None,
            archived_at: None,
            resources_kept: None,
            runtime: None,
        },
    )
    .await;
    *state.console_device.write().await = Some(dev.clone());
    *state.console_enroll_pending.write().await = None;
    tracing::info!(actor = %dev.actor_omni, label = %dev.label, "#541 console ENROLLED as a device actor");
    Ok((dev, proven))
}

// ── the master's two halves of a STANDALONE device enrollment (shared) ──────

/// What the build half hands back: the broker's accept envelope (for the ONE
/// Touch ID) and the device's child omni from the claim.
pub(crate) struct DeviceAcceptBuilt {
    pub build: serde_json::Value,
    pub child_omni: String,
}

/// The master's claim of a device's §10.2 pairing code under `label`
/// (`requested_scope` must be channel-only — see [`nominal_device_scope`]),
/// then the accept build (`is_device`, ZERO grants — the §14.10 ≥1-channel
/// warn is expected; each app install adds the feeds this device serves).
pub(crate) async fn device_accept_build(
    state: &UiBridgeState,
    label: &str,
    pairing_code: &str,
    requested_scope: &str,
    device_key_hash: &str,
    pop_sig: &str,
    request_id: &str,
) -> Result<DeviceAcceptBuilt, axum::response::Response> {
    let Some(broker) = state.broker_url.clone() else {
        return Err(pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no broker configured",
        ));
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return Err(pairing_err(StatusCode::FORBIDDEN, "no master session")),
    };
    if !agentkeys_backend_client::protocol::is_valid_label(label) {
        return Err(pairing_err(
            StatusCode::BAD_REQUEST,
            "label must match ^[a-z0-9-]{1,32}$",
        ));
    }
    let claim = match agentkeys_cli::agent_admin::agent_claim(
        &broker,
        pairing_code,
        label,
        requested_scope,
        &j1,
    )
    .await
    {
        Ok(body) => serde_json::from_str::<serde_json::Value>(&body).unwrap_or_default(),
        Err(e) => {
            return Err(pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("device claim ({label}): {e:#}"),
            ))
        }
    };
    let child_omni = claim_child_omni(&claim, label)
        .map_err(|e| pairing_err(StatusCode::BAD_GATEWAY, &format!("device claim: {e}")))?;
    let body = serde_json::json!({
        "operator_omni": operator_omni,
        "actor_omni": child_omni,
        "device_key_hash": device_key_hash,
        "agent_pop_sig": pop_sig,
        "link_code_redemption": "0x",
        "services": [],
        "read_only": false,
        "max_per_call": "0",
        "max_per_period": "0",
        "max_total": "0",
        "period_seconds": 0,
        "is_device": true,
    });
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/accept/build", &j1, &body).await;
    if !resp.status().is_success() {
        return Err(resp);
    }
    state
        .accept_grants_by_request
        .write()
        .await
        .insert(request_id.to_string(), (Vec::new(), true));
    Ok(DeviceAcceptBuilt {
        build: parsed.unwrap_or_else(|| serde_json::json!({})),
        child_omni,
    })
}

/// Submit the K11-signed accept and ack the rendezvous (the device then polls
/// its session on its own side).
pub(crate) async fn device_accept_submit(
    state: &UiBridgeState,
    request_id: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, axum::response::Response> {
    let Some(broker) = state.broker_url.clone() else {
        return Err(pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no broker configured",
        ));
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return Err(pairing_err(StatusCode::FORBIDDEN, "no master session")),
    };
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/accept/submit", &j1, &body).await;
    if !resp.status().is_success() {
        return Err(resp);
    }
    invalidate_fleet_sync(state);
    ack_rendezvous(state, request_id).await;
    Ok(parsed.unwrap_or_else(|| serde_json::json!({ "ok": true })))
}

/// Ack a §10.2 rendezvous after its binding confirmed (best-effort, loud).
pub(crate) async fn ack_rendezvous(state: &UiBridgeState, request_id: &str) {
    let (Some(broker), Some(j1)) = (
        state.broker_url.clone(),
        state
            .onboarding_session
            .read()
            .await
            .as_ref()
            .map(|s| s.j1.clone())
            .filter(|j| !j.is_empty()),
    ) else {
        return;
    };
    if let Err(e) = agentkeys_cli::agent_admin::agent_ack(&broker, request_id, &j1).await {
        tracing::warn!(error = %format!("{e:#}"), request_id, "device enroll: ack failed (the binding is on chain)");
    }
}

// ── the console's own STANDALONE enrollment (endpoints tab) ─────────────────

#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleDeviceStatus {
    pub enrolled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub actor_omni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub device_key_hash: Option<String>,
    pub suggested_label: String,
}

/// GET /v1/master/console/device
pub async fn console_device_status(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    let dev = state.console_device.read().await.clone();
    (
        StatusCode::OK,
        Json(ConsoleDeviceStatus {
            enrolled: dev.is_some(),
            actor_omni: dev.as_ref().map(|d| d.actor_omni.clone()),
            label: dev.as_ref().map(|d| d.label.clone()),
            device_key_hash: dev.as_ref().map(|d| d.device_key_hash.clone()),
            suggested_label: default_label(),
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct ConsoleEnrollRequest {
    #[serde(default)]
    pub label: Option<String>,
}

/// POST /v1/master/console/device/enroll/build — the standalone ceremony
/// (an app install that binds a display slot enrolls the console in ITS
/// batch instead): pairing request → the master's claim → the accept build.
pub async fn console_enroll_build(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ConsoleEnrollRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    if state.console_device.read().await.is_some() {
        return pairing_err(
            StatusCode::CONFLICT,
            "this console is already enrolled as a device actor",
        );
    }
    let label = req
        .label
        .clone()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(default_label);
    let start = match console_pairing_start(&state).await {
        Ok(s) => s,
        Err(e) => return pairing_err(StatusCode::BAD_GATEWAY, &e),
    };
    let built = match device_accept_build(
        &state,
        &label,
        &start.pairing_code,
        &nominal_device_scope(&label),
        &start.device_key_hash,
        &start.pop_sig,
        &start.request_id,
    )
    .await
    {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    *state.console_enroll_pending.write().await = Some(ConsoleEnrollPending {
        request_id: start.request_id,
        label: label.clone(),
        child_omni: built.child_omni.clone(),
        device_key_hash: start.device_key_hash,
        device_pubkey: start.device_pubkey,
        key_file: start.key_file,
    });
    let mut out = built.build;
    out["label"] = serde_json::json!(label);
    out["actor_omni"] = serde_json::json!(built.child_omni);
    (StatusCode::OK, Json(out)).into_response()
}

/// POST /v1/master/console/device/enroll/submit — submit the K11-signed
/// accept, ack, prove the binding from the device side, persist.
pub async fn console_enroll_submit(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(pending) = state.console_enroll_pending.read().await.clone() else {
        return pairing_err(
            StatusCode::CONFLICT,
            "no console enrollment in flight — run build first",
        );
    };
    if let Err(resp) = device_accept_submit(&state, &pending.request_id, body).await {
        return resp;
    }
    match finish_console_enrollment(&state, &pending).await {
        Ok((dev, proven)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "actor_omni": dev.actor_omni,
                "label": dev.label,
                "device_key_hash": dev.device_key_hash,
                "device_session_proven": proven,
            })),
        )
            .into_response(),
        Err(e) => pairing_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// The console's device session (`J1_agent` for the console actor) — resolved
/// from its K10 via `/v1/agent/resolve` (is_device), cached until near expiry.
pub(crate) async fn console_session(
    state: &UiBridgeState,
    dev: &ConsoleDevice,
) -> Result<String, String> {
    let now = now_unix();
    if let Some((jwt, exp)) = state.console_session.read().await.clone() {
        if exp > now + 60 {
            return Ok(jwt);
        }
    }
    let dk = DeviceKey::load_or_generate(&dev.key_file, false)
        .map_err(|e| format!("console K10: {e}"))?;
    let pop_sig = dk.pop_sig().map_err(|e| format!("console pop: {e}"))?;
    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/agent/resolve",
            dev.broker_url.trim_end_matches('/')
        ))
        .timeout(std::time::Duration::from_secs(20))
        .json(&serde_json::json!({
            "device_pubkey": dk.address(),
            "pop_sig": pop_sig,
            "is_device": true,
        }))
        .send()
        .await
        .map_err(|e| format!("console resolve: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("console resolve HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("console resolve parse: {e}"))?;
    let jwt = v
        .get("session_jwt")
        .and_then(|s| s.as_str())
        .ok_or("console resolve returned no session_jwt")?
        .to_string();
    let exp = crate::master_session::jwt_exp_unix(&jwt).unwrap_or(now + 3600);
    *state.console_session.write().await = Some((jwt.clone(), exp));
    Ok(jwt)
}

/// Publish one `direction: in` event on `channel_id` as the console's device
/// actor when enrolled (attributed to it), else as the master (transitional,
/// `master_channel_cap`). Returns a receipt naming the attribution.
pub(crate) async fn publish_as_console_or_master(
    state: &UiBridgeState,
    channel_id: &str,
    kind: &str,
    body: &[u8],
) -> Result<serde_json::Value, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let dev = state.console_device.read().await.clone();
    let (cap, broker, attributed_to) = match dev {
        Some(dev) => {
            let jwt = console_session(state, &dev).await?;
            let coords = crate::ui_bridge::resolve_session_coords(state).await?;
            let dk = DeviceKey::load_or_generate(&dev.key_file, false)
                .map_err(|e| format!("console K10: {e}"))?;
            let client = agentkeys_backend_client::BackendClient::new(
                Some(dev.broker_url.clone()),
                None,
                None,
                None,
                Some(jwt.clone()),
                None,
                None,
                coords.region.clone(),
            )
            .with_device_key(std::sync::Arc::new(dk));
            let cap = client
                .cap_mint(
                    agentkeys_backend_client::protocol::CapMintOp::ChannelPublish,
                    agentkeys_backend_client::protocol::CapMintRequest {
                        operator_omni: coords.omni.clone(),
                        actor_omni: dev.actor_omni.clone(),
                        service: format!("channel-pub:{channel_id}"),
                        device_key_hash: dev.device_key_hash.clone(),
                        ttl_seconds: 120,
                    },
                    &jwt,
                )
                .await
                .map_err(|e| {
                    // The grant hint only when the broker DENIED (403); a
                    // malformed body or a broker outage is reported as it is.
                    let base = format!("console device cap mint on channel-pub:{channel_id}: {e}");
                    match e {
                        agentkeys_backend_client::BackendError::Http { status: 403, .. } => format!(
                            "{base} — the console holds no publish grant on this feed (an app install grants it)"
                        ),
                        _ => base,
                    }
                })?;
            (
                serde_json::to_value(&cap).map_err(|e| format!("cap serialize: {e}"))?,
                dev.broker_url.clone(),
                serde_json::json!({ "actor": "console-device", "actor_omni": dev.actor_omni }),
            )
        }
        None => {
            let (cap, coords) = master_channel_cap(
                state,
                format!("channel-pub:{channel_id}"),
                agentkeys_backend_client::protocol::CapMintOp::ChannelPublish,
            )
            .await?;
            (
                cap,
                coords.broker.clone(),
                serde_json::json!({ "actor": "master", "actor_omni": coords.omni }),
            )
        }
    };
    let worker = crate::ui_bridge::channel_worker_url(&broker)?;
    // @backend-fixture: channel_publish_body
    let publish = serde_json::json!({
        "cap": cap,
        "kind": kind,
        "direction": "in",
        "body_b64": STANDARD.encode(body),
    });
    let resp = reqwest::Client::new()
        .post(format!("{worker}/v1/channel/publish"))
        .timeout(std::time::Duration::from_secs(30))
        .json(&publish)
        .send()
        .await
        .map_err(|e| format!("channel worker publish: {e}"))?;
    let status = resp.status();
    let txt = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("channel worker publish HTTP {status}: {txt}"));
    }
    let mut receipt: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
    receipt["attributed_to"] = attributed_to;
    receipt["channel_id"] = serde_json::json!(channel_id);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_label_is_a_valid_device_label() {
        let l = default_label();
        assert!(
            agentkeys_backend_client::protocol::is_valid_label(&l),
            "{l}"
        );
        assert!(l.starts_with("console"));
    }

    #[test]
    fn nominal_device_scope_is_channel_only() {
        // The pairing poll must classify an endpoint claim as a DEVICE (never
        // provision a sandbox for a console / gateway).
        assert!(agentkeys_backend_client::protocol::scope_is_device_only(
            &nominal_device_scope("console-mac")
        ));
    }

    #[test]
    fn persisted_console_is_per_broker() {
        let dev = ConsoleDevice {
            actor_omni: "0xabc".into(),
            device_key_hash: "0xdef".into(),
            device_pubkey: "0x11".into(),
            label: "console-mac".into(),
            key_file: "/tmp/k".into(),
            broker_url: "https://broker.example".into(),
            enrolled_at: 1,
        };
        let json = serde_json::to_string(&dev).unwrap();
        let back: ConsoleDevice = serde_json::from_str(&json).unwrap();
        assert_eq!(back.actor_omni, "0xabc");
    }

    #[test]
    fn a_claim_child_omni_is_canonical_0x() {
        let bare = "d8".repeat(32);
        let prefixed = format!("0x{bare}");
        let v = serde_json::json!({ "child_omni": bare });
        assert_eq!(claim_child_omni(&v, "console-mac").unwrap(), prefixed);
        let v = serde_json::json!({ "child_omni": prefixed });
        assert_eq!(claim_child_omni(&v, "console-mac").unwrap(), prefixed);
        let e = claim_child_omni(&serde_json::json!({}), "console-mac").unwrap_err();
        assert!(
            e.contains("console-mac") && e.contains("no child_omni"),
            "{e}"
        );
        assert!(claim_child_omni(&serde_json::json!({ "child_omni": " " }), "x").is_err());
    }

    /// The owner's console (enrolled 2026-09-16) persisted the claim's bare
    /// omni and every card-action tap died at cap mint — a load heals it.
    #[test]
    fn a_bare_persisted_omni_is_healed_on_load_and_rewritten() {
        let dir = std::env::temp_dir().join(format!(
            "agentkeys-console-device-heal-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir
            .join("console-device.json")
            .to_string_lossy()
            .to_string();
        let bare = "d8".repeat(32);
        let dev = ConsoleDevice {
            actor_omni: bare.clone(),
            device_key_hash: "0xdef".into(),
            device_pubkey: "0x11".into(),
            label: "console-mac".into(),
            key_file: "/tmp/k".into(),
            broker_url: "https://broker.example".into(),
            enrolled_at: 1,
        };
        std::fs::write(&path, serde_json::to_string(&dev).unwrap()).unwrap();
        let loaded = load_persisted_from(&path, Some("https://broker.example/")).unwrap();
        assert_eq!(loaded.actor_omni, format!("0x{bare}"));
        let rewritten: ConsoleDevice =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(rewritten.actor_omni, format!("0x{bare}"));
        assert!(load_persisted_from(&path, Some("https://other.example")).is_none());
        assert!(load_persisted_from(&path, None).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The console's status read: a fresh daemon is not enrolled and suggests
    /// this machine's label; the enroll build refuses without a master session.
    #[tokio::test]
    async fn status_reports_unenrolled_and_enroll_needs_a_session() {
        use axum::extract::State;
        let state = crate::ui_bridge::build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "us-east-1".into(),
            None,
            None,
            None,
        )
        .unwrap();
        let resp = console_device_status(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["enrolled"], false);
        assert!(v["suggested_label"]
            .as_str()
            .unwrap()
            .starts_with("console"));
        assert!(v.get("actor_omni").is_none());
        let resp = console_enroll_build(State(state), Json(ConsoleEnrollRequest::default())).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
