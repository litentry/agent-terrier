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
//! **K10 custody caveat (phase-1 posture, documented deviation):** the spec's
//! target is K10 generated IN the sandbox (`device_crypto::DeviceKey` doc).
//! Phase 1 generates it broker-side at build time (needed for the
//! `registerDelegate` calldata + pop_sig before any sandbox exists), holds it
//! ONLY in the pending row, injects it into the sandbox env at confirm, and
//! drops it. A compromised broker already controls veFaaS sandboxes (it
//! injects their LLM creds and images), so this adds little marginal risk;
//! moving keygen into the sandbox boot (build waits for the sandbox's in-band
//! pairing request) is the recorded hardening follow-up.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use agentkeys_core::audit::{
    envelope_for, AuditClient, AuditOpKind, AuditResult, DelegateArchiveBody, DelegateSpawnBody,
};
use agentkeys_core::device_crypto::{agent_pop_payload, eip191_sign, evm_address, keccak256};
use agentkeys_core::erc4337::decode_execute_batch;
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
    assemble_revoke_userop, assemble_spawn_userop, AcceptUserOpParams, BuildAcceptResponse,
};
use crate::state::SharedState;

/// Build→Touch-ID→submit window. Past it the pending row is swept and the
/// submit's finalize hook degrades to the no-row WARN path.
const PENDING_CEREMONY_TTL: Duration = Duration::from_secs(900);

/// The template-grant caps: no spend caps on the operator-chat channel pair +
/// memory namespace (channel/memory grants don't meter spend; payment-class
/// grants — which DO — are never in the spawn template).
const TEMPLATE_CAP: &str = "0";

// ─── pending-ceremony store (in-memory, deliberately — see module doc) ───────

pub struct PendingSpawn {
    pub operator_omni: String,
    pub actor_omni: String,
    pub device_key_hash: String,
    pub label: String,
    pub preset_id: String,
    pub memory_ns: String,
    pub memory_inherited: bool,
    pub chat_channel_id: String,
    pub services: Vec<String>,
    /// The delegate K10 secret (hex) — RAM-only, injected into the sandbox at
    /// confirm, dropped with the row. Never persisted.
    pub k10_secret_hex: String,
    created_at: Instant,
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
    /// The template `memory:<ns>` namespace. Unset ⇒ fresh, named after the
    /// label. Set + `memory_inherited` ⇒ an archived delegate's KEPT namespace
    /// (#425 O2 — the caller (daemon) validates inheritability against the
    /// #424 manifest; the broker records the choice).
    #[serde(default)]
    pub memory_ns: Option<String>,
    #[serde(default)]
    pub memory_inherited: bool,
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
    /// The delegate's `memory:<ns>` namespace name, when the caller knows it
    /// (the broker only sees keccak'd grant ids on-chain) — recorded so the
    /// kept namespace is discoverable for #425 O2 inheritance.
    #[serde(default)]
    pub memory_ns: Option<String>,
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
/// delegate's duplex operator-chat channel pair + its memory namespace.
/// Presets are content, never authority (#428): nothing a preset suggests is
/// added here; suggestions become grants only via a later explicit ceremony.
/// The template pin test below is the #428 nothing-auto-granted negative.
pub(crate) fn spawn_template_services(chat_channel_id: &str, memory_ns: &str) -> Vec<String> {
    vec![
        agentkeys_protocol::service_channel_pub(chat_channel_id),
        agentkeys_protocol::service_channel_sub(chat_channel_id),
        agentkeys_protocol::service_memory(memory_ns),
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

    // Broker-side K10 (phase-1 custody posture — module doc): fresh secp256k1,
    // address → device_key_hash, pop_sig over the standard agent-pop payload.
    let k10_sk = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let k10_address = evm_address(k10_sk.verifying_key());
    let device_key_hash = agentkeys_core::device_crypto::device_key_hash(&k10_address)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, format!("k10: {e}")))?;
    let pop_sig = eip191_sign(&k10_sk, &agent_pop_payload(&device_key_hash))
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, format!("pop_sig: {e}")))?;

    // The S2 template grants: the delegate's duplex operator-chat channel
    // (both directions) + its memory namespace (fresh or inherited, #425 O2).
    let chat_channel_id = format!("opchat-{}", req.label);
    let memory_ns = req.memory_ns.clone().unwrap_or_else(|| req.label.clone());
    let services = spawn_template_services(&chat_channel_id, &memory_ns);

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
    let assembled = assemble_spawn_userop(&params, &broker_sk)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.pending_ceremonies.put_spawn(PendingSpawn {
        operator_omni: session_omni,
        actor_omni: actor_omni.clone(),
        device_key_hash: device_key_hash.clone(),
        label: req.label.clone(),
        preset_id: req.preset_id.clone(),
        memory_ns: memory_ns.clone(),
        memory_inherited: req.memory_inherited,
        chat_channel_id: chat_channel_id.clone(),
        services: services.clone(),
        k10_secret_hex: format!("0x{}", hex::encode(k10_sk.to_bytes())),
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
    let assembled = assemble_revoke_userop(&params, &[hash], &broker_sk)
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
    if spawned.is_empty() && archived.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "spawned": spawned, "archived": archived }))
}

async fn finalize_spawn(
    state: &SharedState,
    session_omni: [u8; 32],
    device_key_hash: &str,
    actor_omni: &str,
) -> serde_json::Value {
    let row = state.pending_ceremonies.take_spawn(device_key_hash);
    let (label, preset_id, memory_ns, memory_inherited, chat_channel_id, k10_secret) = match &row {
        Some(r) => (
            r.label.clone(),
            r.preset_id.clone(),
            r.memory_ns.clone(),
            r.memory_inherited,
            r.chat_channel_id.clone(),
            Some(r.k10_secret_hex.clone()),
        ),
        None => {
            // Broker restarted (or TTL elapsed) between build and submit: the
            // chain row is FINAL but the ceremony context + K10 secret are
            // gone — the delegate cannot cap-mint. Loud; recovery = archive
            // (frees the slot) + respawn.
            tracing::warn!(
                device_key_hash = %device_key_hash,
                "#427 spawn finalize: NO pending row for a confirmed registerDelegate — \
                 ceremony context + K10 secret lost (broker restart between build and \
                 submit?). The delegate is registered but key-less; archive + respawn."
            );
            (
                String::new(),
                String::new(),
                String::new(),
                false,
                String::new(),
                None,
            )
        }
    };

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
    if let Some(secret) = &k10_secret {
        extra_envs.push(("AGENTKEYS_DEVICE_KEY_HEX".into(), secret.clone()));
    }
    extra_envs.push(("AGENTKEYS_ACTOR_OMNI".into(), actor_omni.to_string()));
    extra_envs.push((
        "AGENTKEYS_OPERATOR_OMNI".into(),
        format!("0x{}", hex::encode(session_omni)),
    ));
    // #430 — the in-sandbox chat loop's contract: its duplex feed id + where
    // to resolve/mint (broker) and poll/publish (channel worker). The
    // sandbox-resident daemon starts the loop only when the FULL set is
    // present (partial = loud warn there, never silent).
    if !chat_channel_id.is_empty() {
        extra_envs.push(("AGENTKEYS_CHAT_CHANNEL_ID".into(), chat_channel_id.clone()));
    }
    if let Ok(issuer) = std::env::var("BROKER_OIDC_ISSUER") {
        if !issuer.trim().is_empty() {
            extra_envs.push(("AGENTKEYS_BROKER_URL".into(), issuer.trim().to_string()));
        }
    }
    if let Ok(worker) = std::env::var("AGENTKEYS_WORKER_CHANNEL_URL") {
        if !worker.trim().is_empty() {
            extra_envs.push((
                "AGENTKEYS_CHANNEL_WORKER_URL".into(),
                worker.trim().to_string(),
            ));
        }
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
            label: "watchdog".into(),
            preset_id: "watchdog".into(),
            memory_ns: "watchdog".into(),
            memory_inherited: false,
            chat_channel_id: "opchat-watchdog".into(),
            services: vec!["memory:watchdog".into()],
            k10_secret_hex: "0xdead".into(),
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
    fn spawn_template_is_exactly_chat_pair_plus_memory_ns() {
        // #428 nothing-auto-granted negative: the template is EXACTLY the
        // duplex opchat pair + the memory namespace — a preset (or any other
        // input) can never widen it without changing this pinned set.
        assert_eq!(
            spawn_template_services("opchat-watchdog", "watchdog"),
            vec![
                "channel-pub:opchat-watchdog".to_string(),
                "channel-sub:opchat-watchdog".to_string(),
                "memory:watchdog".to_string(),
            ]
        );
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
}
