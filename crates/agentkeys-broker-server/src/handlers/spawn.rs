//! #427 (epic #425 S1/S2 + decision 6) — the delegate SPAWN + ARCHIVE
//! ceremonies: `/v1/agent/spawn/build` and `/v1/agent/archive/build`, whose
//! signed ops relay through the SHARED submit path (`accept::accept_submit`,
//! aliased as `/v1/agent/{spawn,archive}/submit`) exactly like register /
//! scope / revoke do, plus [`finalize_for_confirmed_batch`] — the post-confirm
//! hook the shared relay calls (next to the #377 sandbox teardown hook).
//!
//! The spawn is the D9 headless in-band claim made a first-class endpoint:
//! NO pairing rendezvous (no QR, no request/approve), exactly ONE Touch ID —
//! the master's K11 signs ONE sponsored `executeBatch([registerDelegate,
//! setScope])` where `registerDelegate` consumes an agent slot ATOMICALLY
//! (the on-chain business quota; exhausted ⇒ the whole batch reverts, and
//! the build pre-checks `agentSlots` for a loud early 409).
//!
//! Build → submit context threading: the ceremony context the confirmed
//! calldata can't carry (the delegate K10 secret for sandbox injection, the
//! preset id, label, memory-namespace decision, keep-vs-delete choice) lives
//! in [`PendingCeremonyStore`] — **in-memory by design**, unlike the SQLite
//! pairing store: the pending-spawn row holds the delegate's PRIVATE KEY,
//! which must never sit at rest. A broker restart inside the build→submit
//! window (seconds, while the master Touch-IDs) drops the row; the finalize
//! hook then WARNs loudly and the recovery is archive + respawn.
//!
//! **K10 custody (#552 / §1a E1):** on a stack flipped to
//! `AGENTKEYS_DELEGATE_KEYS=signer` the delegate key is DERIVED in the
//! SIGNER's device HKDF domain at build time (master-bearer + label
//! parentage arm) — the broker sees only {address, device_key_hash,
//! pop_sig}, the pending row carries NO secret, and the sandbox boots on a
//! broker-minted J1. LEGACY (unflipped) stacks keep the phase-1 posture:
//! broker-side keygen, secret held ONLY in the pending row, injected at
//! confirm, dropped. A half-configured flip 503s loudly (never a silent
//! fallback).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use agentkeys_core::audit::{
    envelope_for, AuditClient, AuditOpKind, AuditResult, DelegateArchiveBody, DelegateSpawnBody,
};
use agentkeys_core::device_crypto::{agent_pop_payload, eip191_sign, evm_address, keccak256};
use agentkeys_core::erc4337::decode_execute_batch;
use agentkeys_core::erc4337::{ExtraScope, ScopeGrant};
use agentkeys_protocol::{
    compile_app, AppInstallBindings, Availability, BoundChannel, EndpointScope, ServiceAnnotation,
    SlotAudience,
};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::handlers::accept::{
    aerr, bearer, call_entrypoint_nonce, call_operator_master_wallet, eth_address_has_code,
    eth_call, load_accept_config, norm_omni, selector, AcceptConfig, BuildAcceptRequest,
    SPONSOR_WINDOW_SECS,
};
use crate::handlers::revoke::parse_device_probe;
use crate::sponsored_accept::{
    assemble_revoke_userop_with_scopes, assemble_spawn_userop_with_endpoints, AcceptUserOpParams,
    BuildAcceptResponse,
};
use crate::state::SharedState;
use agentkeys_core::erc4337::AgentRegister;
use agentkeys_protocol::EndpointEnrollment;

/// Build→Touch-ID→submit window. Past it the pending row is swept and the
/// submit's finalize hook degrades to the no-row WARN path.
const PENDING_CEREMONY_TTL: Duration = Duration::from_secs(900);

/// The template-grant caps: no spend caps on the operator-chat channel pair +
/// memory namespace (channel/memory grants don't meter spend; payment-class
/// grants — which DO — are never in the spawn template).
const TEMPLATE_CAP: &str = "0";

/// #552 — who custodies a NEW delegate's K10 at spawn-build.
#[derive(Debug)]
pub(crate) enum DelegateKeyCustody {
    /// Phase-1 broker-side keygen (§1a E1) — until the stack flips.
    Legacy,
    /// Signer-derived (device HKDF domain); the value is the signer base URL.
    Signer(String),
}

/// Resolve the custody mode from the broker env pair (PURE — env is read at
/// the call site so tests inject). `AGENTKEYS_DELEGATE_KEYS=signer` flips the
/// stack; it then REQUIRES `AGENTKEYS_SIGNER_URL` — a half-configured flip is
/// an Err (the caller 503s; never a silent legacy fallback).
pub(crate) fn delegate_key_custody(
    mode: Option<&str>,
    signer_url: Option<&str>,
) -> Result<DelegateKeyCustody, String> {
    match mode.map(str::trim) {
        Some("signer") => match signer_url
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
        {
            Some(url) => Ok(DelegateKeyCustody::Signer(url)),
            None => Err(
                "AGENTKEYS_DELEGATE_KEYS=signer but AGENTKEYS_SIGNER_URL is unset — refusing \
                 to fall back to broker-side keygen; fix the broker env (#552)"
                    .into(),
            ),
        },
        Some("") | None => Ok(DelegateKeyCustody::Legacy),
        Some(other) => Err(format!(
            "AGENTKEYS_DELEGATE_KEYS='{other}' is not a custody mode (expected 'signer' or unset)"
        )),
    }
}

// ─── pending-ceremony store (in-memory, deliberately — see module doc) ───────

pub struct PendingSpawn {
    pub operator_omni: String,
    pub actor_omni: String,
    pub device_key_hash: String,
    /// The delegate K10 EVM address — under #552 signer custody it is the
    /// SIGNER-derived address (no secret exists broker-side); legacy keygen
    /// fills it from the generated key. Rides into the J1 `device_pubkey`
    /// claim + the durable spawn context.
    pub k10_address: String,
    pub label: String,
    pub preset_id: String,
    pub memory_ns: String,
    pub memory_inherited: bool,
    pub chat_channel_id: String,
    pub services: Vec<String>,
    /// The delegate K10 secret (hex) — LEGACY custody only (§1a E1): RAM-only,
    /// injected into the sandbox at confirm, dropped with the row. EMPTY under
    /// #552 signer custody — no secret ever exists broker-side.
    pub k10_secret_hex: String,
    /// #660 — the app-runtime facts the durable spawn context persists at
    /// confirm (template, bound feeds, availability, mirror namespaces, tz).
    pub app: AppRuntimeFacts,
    created_at: Instant,
}

/// #660 stage 1 — what an app install carries from build to the durable spawn
/// context (and from there into every sandbox create). All-default for a
/// role-preset spawn.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppRuntimeFacts {
    pub template_version: String,
    pub bound_channels: Vec<BoundChannel>,
    pub availability: Availability,
    /// Comma-separated — the mirror's probe list (`""` = its defaults).
    pub memory_namespaces: String,
    pub tz_offset_minutes: i64,
}

impl AppRuntimeFacts {
    pub fn bound_channels_json(&self) -> String {
        if self.bound_channels.is_empty() {
            String::new()
        } else {
            serde_json::to_string(&self.bound_channels).unwrap_or_default()
        }
    }

    pub fn availability_str(&self) -> String {
        if self.availability == Availability::AlwaysOn {
            String::new()
        } else {
            self.availability.as_str().to_string()
        }
    }
}

pub struct PendingArchive {
    pub operator_omni: String,
    pub device_key_hash: String,
    pub resources_kept: bool,
    pub memory_ns: Option<String>,
    created_at: Instant,
}

#[derive(Default)]
pub struct PendingCeremonyStore {
    spawns: RwLock<HashMap<String, PendingSpawn>>,
    archives: RwLock<HashMap<String, PendingArchive>>,
}

impl PendingCeremonyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_spawn(&self, row: PendingSpawn) {
        let mut m = self.spawns.write().expect("pending-spawn lock");
        m.retain(|_, r| r.created_at.elapsed() < PENDING_CEREMONY_TTL);
        m.insert(norm_omni(&row.device_key_hash), row);
    }

    pub fn take_spawn(&self, device_key_hash: &str) -> Option<PendingSpawn> {
        let mut m = self.spawns.write().expect("pending-spawn lock");
        m.remove(&norm_omni(device_key_hash))
            .filter(|r| r.created_at.elapsed() < PENDING_CEREMONY_TTL)
    }

    pub fn put_archive(&self, row: PendingArchive) {
        let mut m = self.archives.write().expect("pending-archive lock");
        m.retain(|_, r| r.created_at.elapsed() < PENDING_CEREMONY_TTL);
        m.insert(norm_omni(&row.device_key_hash), row);
    }

    pub fn take_archive(&self, device_key_hash: &str) -> Option<PendingArchive> {
        let mut m = self.archives.write().expect("pending-archive lock");
        m.remove(&norm_omni(device_key_hash))
            .filter(|r| r.created_at.elapsed() < PENDING_CEREMONY_TTL)
    }
}

// ─── wire types ──────────────────────────────────────────────────────────────

/// `POST /v1/agent/spawn/build` body (J1_master-gated).
#[derive(Debug, Clone, Deserialize)]
pub struct SpawnBuildRequest {
    pub operator_omni: String,
    /// The delegate's name — also the HDKD child-omni derivation label
    /// (`^[a-z0-9-]{1,32}$`, `actor_omni::validate_label`).
    pub label: String,
    /// Repo preset slug (#428 catalog; applied by the daemon-side flow).
    /// `""` = blank spawn. Recorded in the DelegateSpawn anchor + manifest.
    #[serde(default)]
    pub preset_id: String,
    /// The template `knowledge:<ns>` namespace. Unset ⇒ fresh, named after the
    /// label. Set + `memory_inherited` ⇒ an archived delegate's KEPT namespace
    /// (#425 O2 — the caller (daemon) validates inheritability against the
    /// #424 manifest; the broker records the choice).
    #[serde(default)]
    pub memory_ns: Option<String>,
    #[serde(default)]
    pub memory_inherited: bool,
    /// #663 — the install wizard's choices (slots → channels, resources →
    /// items, audience). Present ⇒ `preset_id` names an app template the
    /// broker compiles into `services[]`; absent ⇒ a role-preset spawn.
    #[serde(default)]
    pub bindings: Option<AppInstallBindings>,
    /// #663 — the endpoint actors (gateway / console) whose FULL grant set the
    /// same Touch ID also (re)writes.
    #[serde(default)]
    pub endpoint_scopes: Vec<EndpointScope>,
    /// #663 — endpoint device actors to REGISTER in the same batch (not yet
    /// enrolled); verified for lineage + PoP before the batch is composed.
    #[serde(default)]
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
}

/// `POST /v1/agent/spawn/build` response: the sponsored-UserOp build envelope
/// plus everything the client needs to render + ack the ceremony.
#[derive(Debug, Serialize)]
pub struct SpawnBuildResponse {
    #[serde(flatten)]
    pub build: BuildAcceptResponse,
    pub actor_omni: String,
    pub device_key_hash: String,
    /// The duplex operator-chat channel id in the template grant (S4).
    pub chat_channel_id: String,
    pub memory_ns: String,
    pub memory_inherited: bool,
    /// The template grant NAMES (their keccak ids are what `setScope` signs).
    pub services: Vec<String>,
    /// Allowance state at build time (pre-consume) — for the UI quota meter.
    pub slots_used: u16,
    pub slots_total: u16,
    /// #663 — the sheet's per-line facts (empty on a role-preset spawn).
    pub annotations: Vec<ServiceAnnotation>,
    pub bound_channels: Vec<BoundChannel>,
    pub audience: Vec<SlotAudience>,
    pub availability: Availability,
    pub template_id: String,
    pub template_version: String,
    pub endpoint_scopes: Vec<EndpointScope>,
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
}

/// #663 — what ONE spawn mints, resolved before the UserOp is assembled: the
/// template compile (an app install) or today's fixed template (a blank /
/// role-preset spawn). PURE over the compiled-in catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpawnPlan {
    pub services: Vec<String>,
    pub memory_ns: String,
    pub chat_channel_id: String,
    pub annotations: Vec<ServiceAnnotation>,
    pub bound_channels: Vec<BoundChannel>,
    pub audience: Vec<SlotAudience>,
    pub availability: Availability,
    pub template_id: String,
    pub template_version: String,
    pub resource_namespaces: Vec<String>,
}

impl SpawnPlan {
    /// The mirror's probe list for this install: the bound resource
    /// namespaces + the household defaults (`""` = the mirror's own defaults,
    /// i.e. a role-preset delegate's posture today).
    pub fn memory_namespaces(&self) -> String {
        if self.resource_namespaces.is_empty() {
            return String::new();
        }
        let mut list: Vec<String> = self.resource_namespaces.clone();
        for d in agentkeys_protocol::DEFAULT_MIRROR_NAMESPACES {
            if !list.iter().any(|n| n == d) {
                list.push(d.to_string());
            }
        }
        list.join(",")
    }
}

fn template_refused(
    code: &str,
    template_id: &str,
    rows: Vec<agentkeys_protocol::TemplateError>,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": code,
            "template_id": template_id,
            "rows": rows,
            "message": format!(
                "template '{template_id}' refused: {}",
                rows.iter()
                    .map(|r| format!("{} — {}", r.row, r.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        })),
    )
}

/// Resolve the spawn plan for a build request (see [`SpawnPlan`]). Fail-closed
/// for an app install: an unknown template with bindings, a template that fails
/// the validator, or bindings that fail the compiler all refuse with the rows.
/// A blank spawn (`preset_id == ""`) or an unknown role-preset id without
/// bindings keeps today's fixed template (the preset is applied daemon-side).
pub(crate) fn plan_spawn(
    req: &SpawnBuildRequest,
) -> Result<SpawnPlan, (StatusCode, Json<serde_json::Value>)> {
    let chat_channel_id = agentkeys_protocol::opchat_channel_id(&req.label);
    let fixed = |memory_ns: String| SpawnPlan {
        services: spawn_template_services(&chat_channel_id, &memory_ns),
        memory_ns,
        chat_channel_id: chat_channel_id.clone(),
        annotations: Vec::new(),
        bound_channels: Vec::new(),
        audience: Vec::new(),
        availability: Availability::AlwaysOn,
        template_id: req.preset_id.clone(),
        template_version: String::new(),
        resource_namespaces: Vec::new(),
    };
    let label_ns = req.memory_ns.clone().unwrap_or_else(|| req.label.clone());
    if req.preset_id.trim().is_empty() {
        return Ok(fixed(label_ns));
    }
    let Some((summary, bundle)) = crate::handlers::presets::find_template(&req.preset_id) else {
        if req.bindings.is_some() {
            return Err(template_refused(
                "unknown_template",
                &req.preset_id,
                vec![agentkeys_protocol::TemplateError {
                    row: "preset_id".into(),
                    code: "unknown_template".into(),
                    message: format!(
                        "'{}' is not in the catalog — GET /v1/presets lists it",
                        req.preset_id
                    ),
                }],
            ));
        }
        tracing::warn!(
            preset_id = %req.preset_id,
            "#663 spawn-build: preset id not in the compiled-in catalog — spawning the fixed template (the daemon-side apply will report the unknown preset)"
        );
        return Ok(fixed(label_ns));
    };
    if let Err(rows) = crate::handlers::presets::validate_builtin(&bundle) {
        return Err(template_refused("template_invalid", &req.preset_id, rows));
    }
    let bindings = req.bindings.clone().unwrap_or_default();
    let compiled = compile_app(&summary, &req.label, req.memory_ns.as_deref(), &bindings)
        .map_err(|rows| template_refused("template_bindings_invalid", &req.preset_id, rows))?;
    Ok(SpawnPlan {
        services: compiled.services,
        memory_ns: compiled.memory_ns,
        chat_channel_id: compiled.chat_channel_id,
        annotations: compiled.annotations,
        bound_channels: compiled.bound_channels,
        audience: compiled.audience,
        availability: compiled.availability,
        template_id: summary.id.clone(),
        template_version: summary.version.clone(),
        resource_namespaces: compiled.resource_namespaces,
    })
}

/// #663 — the endpoint actors' `setScope` calls: names keccak'd exactly like
/// the delegate's (`service_ids`), preserved ids passed through, deduped;
/// template caps (channel grants meter no spend).
/// #663 — the endpoint enrollments an install batch registers: each must be
/// the session master's own HDKD child for its label (the claim's lineage)
/// and carry a PoP that recovers to the device key whose hash it names —
/// exactly what the accept ceremony checks, re-done here because the batch
/// never passes through `/v1/accept/build`.
pub(crate) fn parse_endpoint_enrollments(
    list: &[EndpointEnrollment],
    session_omni: &str,
) -> Result<Vec<AgentRegister>, String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(norm_omni(s)).map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    let operator = h32(session_omni, "session omni")?;
    let mut out = Vec::with_capacity(list.len());
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for (i, e) in list.iter().enumerate() {
        agentkeys_core::actor_omni::validate_label(&e.label)
            .map_err(|err| format!("endpoint_enrollments[{i}].label: {err}"))?;
        let expected = agentkeys_core::actor_omni::child_omni_hex(session_omni, &e.label)
            .map_err(|err| format!("endpoint_enrollments[{i}]: child omni: {err}"))?;
        if norm_omni(&expected) != norm_omni(&e.actor_omni) {
            return Err(format!(
                "endpoint_enrollments[{i}]: actor_omni is not this master's child for label `{}`",
                e.label
            ));
        }
        let dkh_hex = format!("0x{}", norm_omni(&e.device_key_hash));
        let payload = agent_pop_payload(&dkh_hex);
        let recovered = agentkeys_core::device_crypto::ecrecover_eip191(&payload, &e.pop_sig)
            .map_err(|err| format!("endpoint_enrollments[{i}].pop_sig: {err}"))?;
        let recomputed = agentkeys_core::device_crypto::device_key_hash(&recovered)
            .map_err(|err| format!("endpoint_enrollments[{i}]: device_key_hash: {err}"))?;
        if norm_omni(&recomputed) != norm_omni(&e.device_key_hash) {
            return Err(format!(
                "endpoint_enrollments[{i}]: pop_sig does not prove device_key_hash"
            ));
        }
        let actor = h32(
            &e.actor_omni,
            &format!("endpoint_enrollments[{i}].actor_omni"),
        )?;
        if seen.contains(&actor) {
            return Err(format!(
                "endpoint_enrollments[{i}]: actor {} listed twice",
                e.actor_omni
            ));
        }
        seen.push(actor);
        out.push(AgentRegister {
            device_key_hash: h32(&e.device_key_hash, "device_key_hash")?,
            operator_omni: operator,
            actor_omni: actor,
            link_code_redemption: Vec::new(),
            agent_pop_sig: hex::decode(e.pop_sig.trim_start_matches("0x"))
                .map_err(|err| format!("endpoint_enrollments[{i}].pop_sig hex: {err}"))?,
        });
    }
    Ok(out)
}

pub(crate) fn parse_endpoint_scopes(scopes: &[EndpointScope]) -> Result<Vec<ExtraScope>, String> {
    let h32 = |s: &str, name: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s.trim().trim_start_matches("0x"))
            .map_err(|e| format!("{name} hex: {e}"))?;
        b.try_into().map_err(|_| format!("{name} must be 32 bytes"))
    };
    let mut out = Vec::with_capacity(scopes.len());
    for (i, s) in scopes.iter().enumerate() {
        let actor_omni = h32(&s.actor_omni, &format!("endpoint_scopes[{i}].actor_omni"))?;
        if out.iter().any(|e: &ExtraScope| e.actor_omni == actor_omni) {
            return Err(format!(
                "endpoint_scopes[{i}]: actor {} listed twice",
                s.actor_omni
            ));
        }
        let mut services = crate::handlers::accept::service_ids(&s.services);
        for (j, id) in s.preserve_service_ids.iter().enumerate() {
            let h = h32(
                id,
                &format!("endpoint_scopes[{i}].preserve_service_ids[{j}]"),
            )?;
            if !services.contains(&h) {
                services.push(h);
            }
        }
        out.push(ExtraScope {
            actor_omni,
            grant: ScopeGrant {
                services,
                read_only: false,
                max_per_call: 0,
                max_per_period: 0,
                max_total: 0,
                period_seconds: 0,
            },
        });
    }
    Ok(out)
}

/// `POST /v1/agent/archive/build` body (J1_master-gated).
#[derive(Debug, Clone, Deserialize)]
pub struct ArchiveBuildRequest {
    pub operator_omni: String,
    /// The delegate binding to archive (must be an ACTIVE `TIER_AGENT` row of
    /// this operator — devices unbind via `/v1/revoke/build`, masters via the
    /// M-of-N recovery flow).
    pub device_key_hash: String,
    /// #425 O4 — keep (`true`, resources become inheritable) vs delete the
    /// delegate-specific resources. Recorded in the DelegateArchive anchor;
    /// the data-plane teardown of a deleted namespace is the caller's
    /// (daemon's) follow-through via the worker teardown flow.
    #[serde(default)]
    pub resources_kept: bool,
    /// The delegate's `knowledge:<ns>` namespace name, when the caller knows it
    /// (the broker only sees keccak'd grant ids on-chain) — recorded so the
    /// kept namespace is discoverable for #425 O2 inheritance.
    #[serde(default)]
    pub memory_ns: Option<String>,
    /// #663 — the endpoint actors' FULL sets after the app's feeds are dropped.
    #[serde(default)]
    pub endpoint_scopes: Vec<EndpointScope>,
}

#[derive(Debug, Serialize)]
pub struct ArchiveBuildResponse {
    #[serde(flatten)]
    pub build: BuildAcceptResponse,
    pub device_key_hash: String,
    pub resources_kept: bool,
}

// ─── chain reads ─────────────────────────────────────────────────────────────

/// `SidecarRegistry.agentSlots(bytes32) -> (uint16 used, uint16 total)` — the
/// #427 allowance view the build pre-check + UI quota meter read.
pub(crate) async fn call_agent_slots(
    http: &reqwest::Client,
    rpc: &str,
    registry: &[u8; 20],
    operator_omni: &str,
) -> Result<(u16, u16), String> {
    let arg = format!("{:0>64}", norm_omni(operator_omni));
    let data = format!("0x{}{}", selector("agentSlots(bytes32)"), arg);
    let raw = eth_call(http, rpc, registry, &data).await?;
    let hexs = raw.trim_start_matches("0x");
    if hexs.len() < 128 {
        return Err(format!("agentSlots short return: {raw}"));
    }
    let word_u16 = |i: usize| -> Result<u16, String> {
        u16::from_str_radix(&hexs[i * 64 + 60..(i + 1) * 64], 16)
            .map_err(|e| format!("agentSlots word {i}: {e}"))
    };
    Ok((word_u16(0)?, word_u16(1)?))
}

/// THE spawn template (#425 S2) — the ONLY grants a spawn ever mints: the
/// delegate's duplex operator-chat channel pair + its memory namespace +
/// (owner decision, 2026-09-01, #653 follow-up) `tool:web` — web search/fetch
/// is a product-default capability for new delegates; the owner unticks it in
/// the permission editor like any other grant. Presets are content, never
/// authority (#428): nothing a preset suggests is added here; suggestions
/// become grants only via a later explicit ceremony. The template pin test
/// below is the #428 nothing-auto-granted negative — widening this set is a
/// DELIBERATE policy edit, made loud by that test.
pub(crate) fn spawn_template_services(chat_channel_id: &str, memory_ns: &str) -> Vec<String> {
    vec![
        agentkeys_protocol::service_channel_pub(chat_channel_id),
        agentkeys_protocol::service_channel_sub(chat_channel_id),
        agentkeys_protocol::service_knowledge(memory_ns),
        agentkeys_protocol::service_tool("web"),
    ]
}

/// The loud, actionable business-gate error (#425 acceptance: "spawning beyond
/// the allowance fails loud and actionable — never silently").
pub(crate) fn allowance_exhausted_error(
    used: u16,
    total: u16,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "agent_slot_allowance_exhausted",
            "slots_used": used,
            "slots_total": total,
            "message": format!(
                "agent-slot allowance exhausted ({used}/{total} delegates in use) — archive a \
                 delegate to free a slot, or extend the allowance (platform action: \
                 SidecarRegistry.setAgentSlotAllowance, owner-gated)"
            ),
        })),
    )
}

// ─── /v1/agent/spawn/build ───────────────────────────────────────────────────

/// Shared J1 auth + master-account resolution for the two build handlers.
async fn auth_and_master(
    state: &SharedState,
    headers: &HeaderMap,
    operator_omni: &str,
) -> Result<
    (AcceptConfig, k256::ecdsa::SigningKey, String, [u8; 20]),
    (StatusCode, Json<serde_json::Value>),
> {
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
    let (cfg, broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let master_account =
        call_operator_master_wallet(&state.http, &cfg.rpc_url, &cfg.registry, operator_omni)
            .await
            .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    if master_account == [0u8; 20] {
        return Err(aerr(
            StatusCode::CONFLICT,
            "operator has no master account on chain (register the master first)",
        ));
    }
    if !eth_address_has_code(&state.http, &cfg.rpc_url, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?
    {
        return Err(aerr(
            StatusCode::CONFLICT,
            format!(
                "operator master 0x{} is a legacy EOA, not a passkey P256Account — the \
                 Touch-ID spawn/archive requires a P256Account master",
                hex::encode(master_account)
            ),
        ));
    }
    Ok((
        cfg,
        broker_sk,
        norm_omni(&claims.agentkeys.omni_account),
        master_account,
    ))
}

/// `POST /v1/agent/spawn/build` (J1_master) — the #427 spawn ceremony, build
/// half: allowance pre-check, HDKD child-omni derivation, broker-side K10
/// generation (custody caveat in the module doc), template grant assembly,
/// ONE sponsored `executeBatch([registerDelegate, setScope])` returned for
/// the master's single Touch ID.
pub async fn spawn_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SpawnBuildRequest>,
) -> Result<Json<SpawnBuildResponse>, (StatusCode, Json<serde_json::Value>)> {
    agentkeys_core::actor_omni::validate_label(&req.label)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, format!("label: {e}")))?;
    let (cfg, broker_sk, session_omni, master_account) =
        auth_and_master(&state, &headers, &req.operator_omni).await?;

    // The business gate, checked EARLY so the user never burns a Touch ID on a
    // doomed op (the contract still enforces atomically at registerDelegate).
    let (used, total) = call_agent_slots(&state.http, &cfg.rpc_url, &cfg.registry, &session_omni)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    if used >= total {
        return Err(allowance_exhausted_error(used, total));
    }

    // D9 in-band claim: the master IS the spawner, so the claim (label → HDKD
    // child omni) needs no rendezvous.
    let actor_omni = agentkeys_core::actor_omni::child_omni_hex(&session_omni, &req.label)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, format!("child omni: {e}")))?;

    // Delegate K10 custody (#552 endgame b): SIGNER-custodied once the stack
    // flips (AGENTKEYS_DELEGATE_KEYS=signer + AGENTKEYS_SIGNER_URL in the
    // broker env) — the key is DERIVED in the signer's device HKDF domain and
    // the broker fetches only {address, device_key_hash, pop_sig}, authorized
    // by the MASTER's own bearer + the HDKD parentage label. Until the flip:
    // the phase-1 broker-side keygen (§1a E1). A half-configured flip is a
    // LOUD 503, never a silent legacy fallback.
    let custody = delegate_key_custody(
        std::env::var("AGENTKEYS_DELEGATE_KEYS").ok().as_deref(),
        std::env::var("AGENTKEYS_SIGNER_URL").ok().as_deref(),
    )
    .map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let (k10_address, device_key_hash, pop_sig, k10_secret_hex) = match &custody {
        DelegateKeyCustody::Signer(signer_url) => {
            let master_bearer = bearer(&headers)?;
            let derived = agentkeys_core::signer_client::DeviceSignerClient::new(signer_url)
                .derive_device(&actor_omni, Some(&req.label), &master_bearer)
                .await
                .map_err(|e| {
                    aerr(
                        StatusCode::BAD_GATEWAY,
                        format!("signer derive-device (#552): {e}"),
                    )
                })?;
            tracing::info!(
                actor_omni = %actor_omni,
                address = %derived.address,
                "#552 spawn-build: delegate K10 signer-derived (no broker-side secret)"
            );
            (
                derived.address,
                derived.device_key_hash,
                derived.pop_sig,
                String::new(),
            )
        }
        DelegateKeyCustody::Legacy => {
            // Broker-side K10 (phase-1 custody posture — module doc + §1a E1):
            // fresh secp256k1, address → device_key_hash, pop_sig over the
            // standard agent-pop payload.
            let k10_sk = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
            let k10_address = evm_address(k10_sk.verifying_key());
            let device_key_hash = agentkeys_core::device_crypto::device_key_hash(&k10_address)
                .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, format!("k10: {e}")))?;
            let pop_sig = eip191_sign(&k10_sk, &agent_pop_payload(&device_key_hash))
                .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, format!("pop_sig: {e}")))?;
            (
                k10_address,
                device_key_hash,
                pop_sig,
                format!("0x{}", hex::encode(k10_sk.to_bytes())),
            )
        }
    };

    // The grant set: today's S2 template for a blank / role-preset spawn, or
    // the #663 manifest compile for an app install (fail-closed on any
    // refused row — the user never Touch-IDs a doomed or mis-bound install).
    let plan = plan_spawn(&req)?;
    let chat_channel_id = plan.chat_channel_id.clone();
    let memory_ns = plan.memory_ns.clone();
    let services = plan.services.clone();
    let extra_scopes = parse_endpoint_scopes(&req.endpoint_scopes)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let enrollments = parse_endpoint_enrollments(&req.endpoint_enrollments, &session_omni)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;

    let build_req = BuildAcceptRequest {
        operator_omni: req.operator_omni.clone(),
        actor_omni: actor_omni.clone(),
        device_key_hash: device_key_hash.clone(),
        agent_pop_sig: pop_sig,
        link_code_redemption: String::new(),
        services: services.clone(),
        is_device: false,
        read_only: false,
        max_per_call: TEMPLATE_CAP.into(),
        max_per_period: TEMPLATE_CAP.into(),
        max_total: TEMPLATE_CAP.into(),
        period_seconds: 0,
    };
    let (register, grant) = crate::handlers::accept::parse_register_and_grant(&build_req)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;

    let nonce = call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + SPONSOR_WINDOW_SECS;
    let params = AcceptUserOpParams {
        entry_point: cfg.entry_point,
        chain_id: cfg.chain_id,
        master_account,
        registry: cfg.registry,
        scope: cfg.scope,
        nonce,
        account_gas_limits: cfg.account_gas_limits,
        pre_verification_gas: cfg.pre_verification_gas,
        gas_fees: cfg.gas_fees,
        paymaster: cfg.paymaster,
        paymaster_verification_gas_limit: cfg.paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit: cfg.paymaster_post_op_gas_limit,
        valid_until,
        valid_after: 0,
        broker_signer: cfg.broker_signer,
        register: &register,
        grant: &grant,
    };
    let assembled =
        assemble_spawn_userop_with_endpoints(&params, &extra_scopes, &enrollments, &broker_sk)
            .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.pending_ceremonies.put_spawn(PendingSpawn {
        operator_omni: session_omni,
        actor_omni: actor_omni.clone(),
        device_key_hash: device_key_hash.clone(),
        label: req.label.clone(),
        preset_id: plan.template_id.clone(),
        memory_ns: memory_ns.clone(),
        memory_inherited: req.memory_inherited,
        chat_channel_id: chat_channel_id.clone(),
        services: services.clone(),
        k10_address: k10_address.clone(),
        k10_secret_hex,
        app: AppRuntimeFacts {
            template_version: plan.template_version.clone(),
            bound_channels: plan.bound_channels.clone(),
            availability: plan.availability,
            memory_namespaces: plan.memory_namespaces(),
            tz_offset_minutes: req
                .bindings
                .as_ref()
                .map(|b| b.tz_offset_minutes as i64)
                .unwrap_or(0),
        },
        created_at: Instant::now(),
    });

    Ok(Json(SpawnBuildResponse {
        build: assembled.into_build_response(&cfg.entry_point, cfg.chain_id),
        actor_omni,
        device_key_hash,
        chat_channel_id,
        memory_ns,
        memory_inherited: req.memory_inherited,
        services,
        slots_used: used,
        slots_total: total,
        annotations: plan.annotations,
        bound_channels: plan.bound_channels,
        audience: plan.audience,
        availability: plan.availability,
        template_id: plan.template_id,
        template_version: plan.template_version,
        endpoint_scopes: req.endpoint_scopes.clone(),
        endpoint_enrollments: req.endpoint_enrollments.clone(),
    }))
}

// ─── /v1/agent/archive/build ─────────────────────────────────────────────────

/// `POST /v1/agent/archive/build` (J1_master) — the archive ceremony, build
/// half: probe the binding (active `TIER_AGENT` of this operator), assemble
/// the ONE-Touch-ID revoke op (`revokeAgentDevice` frees the slot in-contract),
/// and record the keep-vs-delete choice for the finalize hook.
pub async fn archive_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ArchiveBuildRequest>,
) -> Result<Json<ArchiveBuildResponse>, (StatusCode, Json<serde_json::Value>)> {
    let (cfg, broker_sk, session_omni, master_account) =
        auth_and_master(&state, &headers, &req.operator_omni).await?;

    let hash: [u8; 32] = hex::decode(norm_omni(&req.device_key_hash))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            aerr(
                StatusCode::BAD_REQUEST,
                "device_key_hash must be 32 bytes hex",
            )
        })?;
    let data = format!("0x{}{}", selector("getDevice(bytes32)"), hex::encode(hash));
    let raw = eth_call(&state.http, &cfg.rpc_url, &cfg.registry, &data)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    let probe = parse_device_probe(&raw).map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    let operator_bytes: [u8; 32] = hex::decode(&session_omni)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| aerr(StatusCode::BAD_REQUEST, "session omni must be 32 bytes"))?;
    if !probe.registered || probe.revoked {
        return Err(aerr(
            StatusCode::CONFLICT,
            "nothing to archive — the binding is already revoked or was never registered",
        ));
    }
    if probe.operator_omni != operator_bytes {
        return Err(aerr(
            StatusCode::FORBIDDEN,
            "the binding belongs to a different operator",
        ));
    }
    if probe.tier != 2 {
        return Err(aerr(
            StatusCode::CONFLICT,
            format!(
                "archive is for DELEGATES (TIER_AGENT) — this binding is tier {} \
                 (devices unbind via /v1/revoke/build; masters via the recovery flow)",
                probe.tier
            ),
        ));
    }

    let nonce = call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + SPONSOR_WINDOW_SECS;
    // assemble_revoke_userop reads only registry + the hashes; register/grant
    // are structurally required by the params — pass inert zero values.
    let register = agentkeys_core::erc4337::AgentRegister {
        device_key_hash: hash,
        operator_omni: operator_bytes,
        actor_omni: [0u8; 32],
        link_code_redemption: Vec::new(),
        agent_pop_sig: Vec::new(),
    };
    let grant = agentkeys_core::erc4337::ScopeGrant {
        services: Vec::new(),
        read_only: false,
        max_per_call: 0,
        max_per_period: 0,
        max_total: 0,
        period_seconds: 0,
    };
    let params = AcceptUserOpParams {
        entry_point: cfg.entry_point,
        chain_id: cfg.chain_id,
        master_account,
        registry: cfg.registry,
        scope: cfg.scope,
        nonce,
        account_gas_limits: cfg.account_gas_limits,
        pre_verification_gas: cfg.pre_verification_gas,
        gas_fees: cfg.gas_fees,
        paymaster: cfg.paymaster,
        paymaster_verification_gas_limit: cfg.paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit: cfg.paymaster_post_op_gas_limit,
        valid_until,
        valid_after: 0,
        broker_signer: cfg.broker_signer,
        register: &register,
        grant: &grant,
    };
    // #663 — the endpoint actors' sets minus this app's feeds ride the same
    // Touch ID (the install's mirror).
    let extra_scopes = parse_endpoint_scopes(&req.endpoint_scopes)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let assembled = assemble_revoke_userop_with_scopes(&params, &[hash], &extra_scopes, &broker_sk)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.pending_ceremonies.put_archive(PendingArchive {
        operator_omni: session_omni,
        device_key_hash: req.device_key_hash.clone(),
        resources_kept: req.resources_kept,
        memory_ns: req.memory_ns.clone(),
        created_at: Instant::now(),
    });

    Ok(Json(ArchiveBuildResponse {
        build: assembled.into_build_response(&cfg.entry_point, cfg.chain_id),
        device_key_hash: req.device_key_hash,
        resources_kept: req.resources_kept,
    }))
}

// ─── the shared-relay finalize hook ──────────────────────────────────────────

/// Called by the shared submit relay after a CONFIRMED receipt (next to the
/// #377 sandbox-teardown hook). Decodes the batch; for each confirmed
/// `registerDelegate` runs the spawn finalization (gate provision → sandbox
/// spawn with identity + LLM envs → `DelegateSpawn` anchor), and for each
/// confirmed `revokeAgentDevice` with a pending ARCHIVE row runs the archive
/// finalization (gate deprovision → `DelegateArchive` anchor; the sandbox
/// kill is the existing teardown hook's job). Best-effort like its siblings:
/// the chain tx is final — failures are LOUD in the returned summary + WARN
/// logs, never swallowed, never able to fail the submit response.
pub async fn finalize_for_confirmed_batch(
    state: &SharedState,
    session_omni: [u8; 32],
    call_data: &[u8],
) -> Option<serde_json::Value> {
    let calls = decode_execute_batch(call_data).ok()?;
    let mut spawned = Vec::new();
    let mut archived = Vec::new();
    let mut enrolled = Vec::new();
    for call in &calls {
        let Ok(decoded) = agentkeys_core::audit::calldata::decode_calldata(&call.calldata) else {
            continue;
        };
        if decoded.contract != "SidecarRegistry" {
            continue;
        }
        match decoded.function.as_str() {
            "registerDelegate" => {
                let (Some(dkh), Some(actor)) = (
                    decoded.args.first().and_then(|a| a.value.as_str()),
                    decoded.args.get(2).and_then(|a| a.value.as_str()),
                ) else {
                    continue;
                };
                spawned.push(finalize_spawn(state, session_omni, dkh, actor).await);
            }
            // #663 — an endpoint device actor registered in the install batch
            // (the daemon completes its pairing + registry rows on this echo).
            "registerAgentDevice" => {
                let (Some(dkh), Some(actor)) = (
                    decoded.args.first().and_then(|a| a.value.as_str()),
                    decoded.args.get(2).and_then(|a| a.value.as_str()),
                ) else {
                    continue;
                };
                enrolled.push(serde_json::json!({ "device_key_hash": dkh, "actor_omni": actor }));
            }
            "revokeAgentDevice" => {
                let Some(dkh) = decoded.args.first().and_then(|a| a.value.as_str()) else {
                    continue;
                };
                if let Some(row) = state.pending_ceremonies.take_archive(dkh) {
                    archived.push(finalize_archive(state, session_omni, row).await);
                }
            }
            _ => {}
        }
    }
    if spawned.is_empty() && archived.is_empty() && enrolled.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "spawned": spawned, "archived": archived, "enrolled": enrolled }))
}

async fn finalize_spawn(
    state: &SharedState,
    session_omni: [u8; 32],
    device_key_hash: &str,
    actor_omni: &str,
) -> serde_json::Value {
    let row = state.pending_ceremonies.take_spawn(device_key_hash);
    #[allow(clippy::type_complexity)]
    let (label, preset_id, memory_ns, memory_inherited, chat_channel_id, k10_secret, k10_address) =
        match &row {
            Some(r) => (
                r.label.clone(),
                r.preset_id.clone(),
                r.memory_ns.clone(),
                r.memory_inherited,
                r.chat_channel_id.clone(),
                // Legacy custody carries the secret; #552 signer custody is "".
                Some(r.k10_secret_hex.clone()).filter(|s| !s.is_empty()),
                r.k10_address.clone(),
            ),
            None => {
                // Broker restarted (or TTL elapsed) between build and submit:
                // the chain row is FINAL but the ceremony context is gone —
                // Loud; recovery = archive (frees the slot) + respawn.
                tracing::warn!(
                    device_key_hash = %device_key_hash,
                    "#427 spawn finalize: NO pending row for a confirmed registerDelegate — \
                     ceremony context lost (broker restart between build and \
                     submit?). The delegate is registered but credential-less; archive + respawn."
                );
                (
                    String::new(),
                    String::new(),
                    String::new(),
                    false,
                    String::new(),
                    None,
                    String::new(),
                )
            }
        };

    // 0. #546 — persist the ceremony context DURABLY (device_key_hash →
    //    label/chat_channel_id/omnis/K10) BEFORE any create: the resolve/poll
    //    ensure path re-injects this exact set whenever the runtime is
    //    re-created (veFaaS expiry, backend desync, wake cold-start), so a
    //    re-created sandbox is never chat-silent. The row dies with the
    //    binding (deleted on confirmed revoke — custody note in
    //    `storage::spawn_contexts`). Best-effort + loud: a write failure
    //    costs future re-create chat, never the spawn itself.
    let ctx_row = row.as_ref().map(|r| {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        crate::storage::SpawnContext {
            device_key_hash: device_key_hash.to_string(),
            label: r.label.clone(),
            chat_channel_id: r.chat_channel_id.clone(),
            k10_address: r.k10_address.clone(),
            k10_secret_hex: r.k10_secret_hex.clone(),
            // #594 — the RESOLVED namespace (label-defaulted or #425 O2
            // inherited): what every re-create injects for the checkpoint.
            memory_ns: r.memory_ns.clone(),
            created_at,
            // #660 — the app-runtime facts every re-create re-injects.
            preset_id: r.preset_id.clone(),
            bound_channels_json: r.app.bound_channels_json(),
            availability: r.app.availability_str(),
            memory_namespaces: r.app.memory_namespaces.clone(),
            tz_offset_minutes: r.app.tz_offset_minutes,
        }
    });
    if let Some(ctx) = &ctx_row {
        let persist = state.spawn_context_store.upsert(ctx);
        if let Err(e) = persist {
            tracing::warn!(
                device_key_hash = %device_key_hash,
                error = %e,
                "#546 spawn-context persist FAILED — a future re-create of this delegate's \
                 sandbox will come up chat-silent"
            );
        }
    }

    // 1. Gate provisioning (epic decision 6): the usage plane. EAGER here — the
    //    ceremony always CREATES (a fresh delegate has no live instance) and must
    //    record the status for the audit anchor + the #543 runtime field. Same
    //    single-owner helper the resolve/poll cold-create path calls lazily.
    let gate = crate::handlers::sandbox::provision_delegate_envs(
        &state.http,
        &format!("0x{}", hex::encode(session_omni)),
        actor_omni,
        device_key_hash,
        &label,
    )
    .await;
    let gate_status = gate.status;
    let gate_error = gate.error;
    let mut extra_envs: Vec<(String, String)> = gate.envs;

    // 2. Sandbox spawn (#377 lifecycle) with the delegate identity + LLM envs.
    //    #430 — the in-sandbox chat loop's contract: its duplex feed id + where
    //    to resolve/mint (broker) and poll/publish (channel worker; DERIVED
    //    from the broker URL, override optional). The sandbox-resident daemon
    //    starts the loop only when the FULL set is present (partial = loud
    //    warn there, never silent). ONE owner (#546): the same assembly the
    //    resolve/poll re-create path injects from the durable spawn context.
    // #552 signer custody: there is no key to inject — the sandbox gets a
    // broker-minted J1 instead (its bearer toward the signer's device-domain
    // endpoints until the first resolve rotates it). Legacy rows keep the
    // key injection; the no-row WARN path injects neither.
    let session_jwt = if row.is_some() && k10_secret.is_none() && !k10_address.is_empty() {
        crate::handlers::sandbox::mint_delegate_session_jwt(
            state,
            actor_omni,
            &format!("0x{}", hex::encode(session_omni)),
            "//spawned",
            &k10_address,
        )
    } else {
        None
    };
    let (issuer, worker_override) = crate::handlers::sandbox::chat_link_env_sources();
    extra_envs.extend(crate::handlers::sandbox::delegate_identity_envs(
        actor_omni,
        &format!("0x{}", hex::encode(session_omni)),
        k10_secret.as_deref(),
        session_jwt.as_deref(),
        &chat_channel_id,
        issuer.as_deref(),
        worker_override.as_deref(),
        // #577 — arm the sandbox-management surface from the first boot so a
        // later one-click update can hand the Hermes home off.
        Some(&crate::handlers::sandbox::sandbox_mgmt_token(
            &state.session_keypair,
            device_key_hash,
        )),
        // #594 — the checkpoint loop's namespace (empty on the no-row path).
        Some(&memory_ns),
        // #715 — the in-pod bearer gating the bridge + daemon self surfaces.
        Some(&crate::handlers::sandbox::sandbox_bridge_token(
            &state.session_keypair,
            device_key_hash,
        )),
        // The stack's credential provider — the delegate's own-namespace
        // storage credential is minted the way this stack mints (VE: signer).
        Some(&state.config.sts_provider),
    ));
    // #660 — the app-runtime set (template, bound feeds, availability, mirror
    // namespaces, tz): the same values every re-create injects from the row.
    if let Some(ctx) = &ctx_row {
        extra_envs.extend(crate::handlers::sandbox::app_runtime_envs(ctx));
    }
    let sandbox = crate::handlers::sandbox::ensure_for_delegate_with_envs(
        state,
        device_key_hash,
        actor_omni,
        &format!("0x{}", hex::encode(session_omni)),
        &extra_envs,
        // The gate key is already in extra_envs (eager, above) — nothing extra to
        // mint at create time; the ceremony always creates so the no-op fires.
        crate::sandbox_backend::no_create_envs(),
    )
    .await;
    let sandbox_json = sandbox
        .as_ref()
        .map(|p| p.to_json())
        .unwrap_or(serde_json::Value::Null);

    // 3. The ceremony anchor (op_kind 55) — the label rides as a hash
    //    (household PII stays in the #424 manifest), preset + memory decision
    //    in the clear.
    let actor32 = omni32(actor_omni).unwrap_or([0u8; 32]);
    let env = envelope_for(
        actor32,
        session_omni,
        AuditOpKind::DelegateSpawn,
        DelegateSpawnBody {
            device_key_hash: device_key_hash.to_string(),
            preset_id: preset_id.clone(),
            label_hash: format!("0x{}", hex::encode(keccak256(label.as_bytes()))),
            memory_ns: memory_ns.clone(),
            memory_inherited,
        },
        AuditResult::Success,
        None,
        None,
    );
    let anchor = append_best_effort(env).await;

    serde_json::json!({
        "device_key_hash": device_key_hash,
        "actor_omni": actor_omni,
        "label": label,
        "preset_id": preset_id,
        "memory_ns": memory_ns,
        "memory_inherited": memory_inherited,
        "chat_channel_id": chat_channel_id,
        "context_recovered": row.is_some(),
        "gate": { "status": gate_status, "error": gate_error },
        "sandbox": sandbox_json,
        "audit_envelope_hash": anchor,
    })
}

async fn finalize_archive(
    state: &SharedState,
    session_omni: [u8; 32],
    row: PendingArchive,
) -> serde_json::Value {
    let mut gate_status = "not-configured".to_string();
    let mut gate_error: Option<String> = None;
    match crate::gate_admin::load_gate_admin_config() {
        None => {}
        Some(Err(e)) => {
            gate_status = "misconfigured".into();
            gate_error = Some(e);
        }
        Some(Ok(cfg)) => {
            match crate::gate_admin::deprovision_delegate(&state.http, &cfg, &row.device_key_hash)
                .await
            {
                Ok(disabled) => {
                    gate_status = if disabled {
                        "deprovisioned"
                    } else {
                        "not-provisioned"
                    }
                    .into();
                }
                Err(e) => {
                    tracing::error!(
                        device_key_hash = %row.device_key_hash,
                        error = %e,
                        "#427 archive: gate deprovisioning FAILED — the relay key stays \
                         LIVE until disabled (re-run the archive or disable at the gate)"
                    );
                    gate_status = "failed".into();
                    gate_error = Some(e);
                }
            }
        }
    }

    let env = envelope_for(
        session_omni,
        session_omni,
        AuditOpKind::DelegateArchive,
        DelegateArchiveBody {
            device_key_hash: row.device_key_hash.clone(),
            resources_kept: row.resources_kept,
        },
        AuditResult::Success,
        None,
        None,
    );
    let anchor = append_best_effort(env).await;

    serde_json::json!({
        "device_key_hash": row.device_key_hash,
        "resources_kept": row.resources_kept,
        "memory_ns": row.memory_ns,
        "gate": { "status": gate_status, "error": gate_error },
        "audit_envelope_hash": anchor,
    })
}

async fn append_best_effort(
    env: Result<agentkeys_core::audit::AuditEnvelope, agentkeys_core::audit::AuditError>,
) -> Option<String> {
    let env = match env {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "#427 ceremony audit envelope build failed — anchor NOT in the audit feed");
            return None;
        }
    };
    let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
        .unwrap_or_else(|_| crate::handlers::audit_emit::DEFAULT_AUDIT_WORKER_URL.to_string());
    match AuditClient::new(url).append(&env).await {
        Ok(resp) => Some(resp.envelope_hash),
        Err(e) => {
            tracing::warn!(
                op_kind = env.op_kind,
                error = %e,
                "#427 ceremony audit append FAILED (best-effort) — anchor NOT in the audit feed"
            );
            None
        }
    }
}

fn omni32(hex_str: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_str.trim().trim_start_matches("0x")).ok()?;
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_store_round_trips_and_is_one_shot() {
        let store = PendingCeremonyStore::new();
        store.put_spawn(PendingSpawn {
            operator_omni: "22".repeat(32),
            actor_omni: "33".repeat(32),
            device_key_hash: format!("0x{}", "11".repeat(32)),
            k10_address: "0xabcd".into(),
            label: "watchdog".into(),
            preset_id: "watchdog".into(),
            memory_ns: "watchdog".into(),
            memory_inherited: false,
            chat_channel_id: "opchat-watchdog".into(),
            services: vec!["knowledge:watchdog".into()],
            k10_secret_hex: "0xdead".into(),
            app: AppRuntimeFacts::default(),
            created_at: Instant::now(),
        });
        // 0x-prefix and case are normalized on both sides.
        let got = store.take_spawn(&"11".repeat(32)).expect("row");
        assert_eq!(got.label, "watchdog");
        assert!(store
            .take_spawn(&format!("0x{}", "11".repeat(32)))
            .is_none());
    }

    #[test]
    fn delegate_key_custody_flip_is_loud_never_silent() {
        // #552 — unset/empty = legacy; 'signer' + URL = signer custody; a
        // half-configured or unknown flip is an Err (503), never a fallback.
        assert!(matches!(
            delegate_key_custody(None, None),
            Ok(DelegateKeyCustody::Legacy)
        ));
        assert!(matches!(
            delegate_key_custody(Some(""), Some("https://signer.x")),
            Ok(DelegateKeyCustody::Legacy)
        ));
        match delegate_key_custody(Some("signer"), Some("https://signer.x/")) {
            Ok(DelegateKeyCustody::Signer(url)) => assert_eq!(url, "https://signer.x"),
            other => panic!("expected signer custody, got {:?}", other.is_ok()),
        }
        let err = delegate_key_custody(Some("signer"), None).unwrap_err();
        assert!(err.contains("AGENTKEYS_SIGNER_URL"), "{err}");
        let err = delegate_key_custody(Some("broker"), None).unwrap_err();
        assert!(err.contains("custody mode"), "{err}");
    }

    #[test]
    fn allowance_error_names_the_quota_and_the_actions() {
        let (status, body) = allowance_exhausted_error(3, 3);
        assert_eq!(status, StatusCode::CONFLICT);
        let v = body.0;
        assert_eq!(v["error"], "agent_slot_allowance_exhausted");
        assert_eq!(v["slots_used"], 3);
        assert_eq!(v["slots_total"], 3);
        let msg = v["message"].as_str().unwrap();
        assert!(msg.contains("archive a"), "{msg}");
        assert!(msg.contains("setAgentSlotAllowance"), "{msg}");
    }

    #[test]
    fn spawn_template_is_exactly_chat_pair_plus_memory_ns_plus_web() {
        // #428 nothing-auto-granted negative: the template is EXACTLY the
        // duplex opchat pair + the memory namespace + the default `tool:web`
        // capability (owner decision 2026-09-01) — a preset (or any other
        // input) can never widen it without changing this pinned set.
        assert_eq!(
            spawn_template_services("opchat-watchdog", "watchdog"),
            vec![
                "channel-pub:opchat-watchdog".to_string(),
                "channel-sub:opchat-watchdog".to_string(),
                "knowledge:watchdog".to_string(),
                "tool:web".to_string(),
            ]
        );
    }

    fn build_req(preset_id: &str, bindings: Option<AppInstallBindings>) -> SpawnBuildRequest {
        SpawnBuildRequest {
            operator_omni: format!("0x{}", "22".repeat(32)),
            label: "chef".into(),
            preset_id: preset_id.into(),
            memory_ns: None,
            memory_inherited: false,
            bindings,
            endpoint_scopes: Vec::new(),
            endpoint_enrollments: Vec::new(),
        }
    }

    /// #663 — an enrollment folded into the install batch is verified like
    /// an accept: lineage (the session master's child for the label) + the
    /// PoP over the device key hash; a wrong label or a tampered hash refuses.
    #[test]
    fn endpoint_enrollments_verify_lineage_and_pop() {
        let session = format!("0x{}", "22".repeat(32));
        let sk = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let addr = evm_address(sk.verifying_key());
        let dkh = agentkeys_core::device_crypto::device_key_hash(&addr).unwrap();
        let pop = eip191_sign(&sk, &agent_pop_payload(&dkh)).unwrap();
        let child = agentkeys_core::actor_omni::child_omni_hex(&session, "gateway-weixin").unwrap();
        let good = EndpointEnrollment {
            actor_omni: child.clone(),
            device_key_hash: dkh.clone(),
            pop_sig: pop.clone(),
            label: "gateway-weixin".into(),
            kind: "gateway".into(),
            transport: "weixin".into(),
        };
        let parsed = parse_endpoint_enrollments(std::slice::from_ref(&good), &session).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].agent_pop_sig,
            hex::decode(pop.trim_start_matches("0x")).unwrap()
        );
        assert!(parsed[0].link_code_redemption.is_empty());
        let wrong_label = EndpointEnrollment {
            label: "console-mac".into(),
            ..good.clone()
        };
        let err = parse_endpoint_enrollments(&[wrong_label], &session).unwrap_err();
        assert!(err.contains("not this master's child"), "{err}");
        let tampered = EndpointEnrollment {
            device_key_hash: format!("0x{}", "ab".repeat(32)),
            ..good.clone()
        };
        let err = parse_endpoint_enrollments(&[tampered], &session).unwrap_err();
        assert!(err.contains("pop_sig"), "{err}");
        let dup = parse_endpoint_enrollments(&[good.clone(), good], &session).unwrap_err();
        assert!(dup.contains("listed twice"), "{dup}");
    }

    /// #663 — a blank spawn and a role-preset spawn (bindings absent) plan
    /// EXACTLY today's fixed template; the template id rides through.
    #[test]
    fn plan_spawn_keeps_todays_template_for_blank_and_role_presets() {
        let blank = plan_spawn(&build_req("", None)).unwrap();
        assert_eq!(
            blank.services,
            spawn_template_services("opchat-chef", "chef")
        );
        assert_eq!(blank.memory_ns, "chef");
        assert!(blank.bound_channels.is_empty());
        assert_eq!(blank.memory_namespaces(), "");
        // A compiled-in role preset (zero slots) — byte-identical set, id kept.
        let role = plan_spawn(&build_req("watchdog", None)).unwrap();
        assert_eq!(role.services, blank.services);
        assert_eq!(role.template_id, "watchdog");
        assert_eq!(role.template_version, "1.0.0");
        // An unknown preset id WITHOUT bindings is tolerated (daemon-side
        // apply reports it); WITH bindings it is an install and refuses.
        assert!(plan_spawn(&build_req("nope", None)).is_ok());
        let err = plan_spawn(&build_req("nope", Some(AppInstallBindings::default()))).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0["error"], "unknown_template");
    }

    /// #663 — the endpoint actors' setScope inputs: names keccak'd like the
    /// delegate's, preserved ids passed through + deduped, a repeated actor
    /// refused.
    #[test]
    fn endpoint_scopes_parse_dedup_and_refuse_repeats() {
        let gw = format!("0x{}", "aa".repeat(32));
        let kept = format!("0x{}", "cc".repeat(32));
        let parsed = parse_endpoint_scopes(&[EndpointScope {
            actor_omni: gw.clone(),
            services: vec![
                "channel-pub:family-chat".into(),
                "channel-sub:family-chat".into(),
            ],
            preserve_service_ids: vec![kept.clone(), kept.clone()],
        }])
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].actor_omni, [0xaa; 32]);
        assert_eq!(parsed[0].grant.services.len(), 3);
        assert_eq!(
            parsed[0].grant.services[0],
            agentkeys_core::device_crypto::keccak256(b"channel-pub:family-chat")
        );
        assert_eq!(parsed[0].grant.services[2], [0xcc; 32]);
        assert_eq!(parsed[0].grant.max_total, 0);
        let dup = parse_endpoint_scopes(&[
            EndpointScope {
                actor_omni: gw.clone(),
                services: vec![],
                preserve_service_ids: vec![],
            },
            EndpointScope {
                actor_omni: gw,
                services: vec![],
                preserve_service_ids: vec![],
            },
        ]);
        assert!(dup.unwrap_err().contains("listed twice"));
        assert!(parse_endpoint_scopes(&[EndpointScope {
            actor_omni: "0x12".into(),
            services: vec![],
            preserve_service_ids: vec![],
        }])
        .is_err());
    }

    #[test]
    fn finalize_hook_ignores_non_ceremony_batches() {
        // Pure decode check: a scope-only batch has no registerDelegate /
        // revokeAgentDevice, so the hook returns None without touching state.
        let grant = agentkeys_core::erc4337::ScopeGrant {
            services: vec![[0xc1; 32]],
            read_only: true,
            max_per_call: 1,
            max_per_period: 1,
            max_total: 1,
            period_seconds: 60,
        };
        let batch = agentkeys_core::erc4337::scope_batch_calldata(
            &[0xa2; 20],
            &[0x22; 32],
            &[0x33; 32],
            &grant,
        );
        let calls = decode_execute_batch(&batch).unwrap();
        let ceremony = calls.iter().any(|c| {
            agentkeys_core::audit::calldata::decode_calldata(&c.calldata)
                .map(|d| d.function == "registerDelegate" || d.function == "revokeAgentDevice")
                .unwrap_or(false)
        });
        assert!(!ceremony);
    }

    /// #663 — a bound application manifest compiles into the sheet: the chef
    /// template with its family chat, kitchen screen and a food-preferences
    /// resource yields the documented services, annotations, bound channels
    /// and resource namespaces; a binding the manifest does not declare or a
    /// missing required slot is refused with `template_bindings_invalid`.
    #[test]
    fn plan_spawn_compiles_a_bound_application_manifest() {
        use agentkeys_protocol::{
            AppInstallBindings, ContactTier, ResourceBinding, ResourceKind, Sensitivity,
            SlotAudience, SlotBinding,
        };
        let bindings = AppInstallBindings {
            slots: vec![
                SlotBinding {
                    slot: "family_chat".into(),
                    channel_id: "family-chat".into(),
                    endpoint_actor_omni: None,
                },
                SlotBinding {
                    slot: "kitchen_screen".into(),
                    channel_id: "kitchen-display".into(),
                    endpoint_actor_omni: None,
                },
            ],
            resources: vec![ResourceBinding {
                name: "food-preferences".into(),
                item_id: "food-preferences-1".into(),
                ns: "food-prefs".into(),
                kind: ResourceKind::Profile,
                sensitivity: Sensitivity::Safe,
            }],
            audience: vec![SlotAudience {
                slot: "family_chat".into(),
                tiers: vec![ContactTier::Owner, ContactTier::Partner],
            }],
            tz_offset_minutes: 480,
        };
        let plan = plan_spawn(&build_req("chef", Some(bindings.clone()))).unwrap();
        assert_eq!(plan.template_id, "chef");
        assert!(!plan.template_version.is_empty());
        for s in [
            "channel-pub:opchat-chef",
            "channel-sub:opchat-chef",
            "knowledge:app-chef",
            "proposal:app-chef",
            "channel-sub:family-chat",
            "channel-pub:family-chat",
            "channel-pub:kitchen-display",
            "knowledge:food-prefs",
            "tool:schedule",
            "plugin:openviking",
        ] {
            assert!(
                plan.services.iter().any(|x| x == s),
                "missing {s}: {:?}",
                plan.services
            );
        }
        assert!(
            !plan.services.iter().any(|x| x == "proposal:food-prefs"),
            "a resource is read-only — never an inbox on its namespace"
        );
        assert_eq!(plan.bound_channels.len(), 2);
        assert!(!plan.annotations.is_empty());
        assert_eq!(plan.resource_namespaces, vec!["food-prefs".to_string()]);
        assert_eq!(plan.audience.len(), 1);
        assert_eq!(plan.chat_channel_id, "opchat-chef");

        // A slot the manifest does not declare is refused before any sheet.
        let mut bad = bindings.clone();
        bad.slots.push(SlotBinding {
            slot: "no_such_slot".into(),
            channel_id: "x".into(),
            endpoint_actor_omni: None,
        });
        let (status, body) = plan_spawn(&build_req("chef", Some(bad))).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], "template_bindings_invalid");

        // A required slot left unbound is refused too.
        let mut unbound = bindings;
        unbound.slots.retain(|b| b.slot != "family_chat");
        let (status, body) = plan_spawn(&build_req("chef", Some(unbound))).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], "template_bindings_invalid");
    }
}
