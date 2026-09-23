//! The ANCHOR (owner decision 2026-09-22): a delegate's bound channels live in
//! a context DOCUMENT on the memory plane (the app's own namespace) whose hash
//! is SEALED on chain — `appendRoot(operator, keccak(doc), version)` on the
//! audit contract, inside the same batch the owner signs for the install /
//! rebind. The broker's spawn-context row is a CACHE of it: any broker rebuilds
//! the row from the document once the chain confirms the seal (`rehydrate`).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use agentkeys_core::erc4337::TrailingCall;
use agentkeys_protocol::{BoundChannel, ContextSeal, DelegateContextDoc, CONTEXT_DOC_SCHEMA};

use crate::handlers::accept::{
    aerr, call_entrypoint_nonce, call_operator_master_wallet, env_profile, eth_call,
    load_accept_config, norm_omni, AcceptConfig, SPONSOR_WINDOW_SECS,
};
use crate::handlers::update::{auth_session, probe_owned_delegate};
use crate::sponsored_accept::{assemble_trailing_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;

/// The audit contract that takes the seal: the stack's env
/// (`CREDENTIAL_AUDIT_ADDRESS[_<CHAIN>]`, the test stacks carry their own
/// set), else the compiled chain profile — but ONLY when that profile's
/// registry is the one this broker accepts against (a test stack on an
/// overridden contract set must never seal into the prod audit contract).
pub fn audit_contract(cfg: &AcceptConfig) -> Option<[u8; 20]> {
    let parse = |s: &str| -> Option<[u8; 20]> {
        let b = hex::decode(s.trim().trim_start_matches("0x")).ok()?;
        b.try_into().ok()
    };
    if let Ok(v) = env_profile("CREDENTIAL_AUDIT_ADDRESS") {
        return parse(&v);
    }
    let (profile, _) = agentkeys_core::chain_profile::ChainProfile::resolve(
        None,
        std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
        std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
            .ok()
            .as_deref(),
    )
    .ok()?;
    let registry = profile
        .contract("SidecarRegistry")
        .and_then(|c| parse(&c.address))?;
    if registry != cfg.registry {
        return None;
    }
    profile
        .contract("CredentialAudit")
        .and_then(|c| parse(&c.address))
}

pub struct ContextDocFacts<'a> {
    pub version: u64,
    pub previous_hash: Option<String>,
    pub label: &'a str,
    pub device_key_hash: &'a str,
    pub actor_omni: &'a str,
    pub k10_address: &'a str,
    pub preset_id: &'a str,
    pub chat_channel_id: &'a str,
    pub memory_ns: &'a str,
    pub bound_channels: &'a [BoundChannel],
    pub availability: &'a str,
    pub memory_namespaces: &'a str,
    pub tz_offset_minutes: i64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The document a ceremony seals.
pub fn compose_context_doc(f: ContextDocFacts<'_>) -> DelegateContextDoc {
    DelegateContextDoc {
        schema: CONTEXT_DOC_SCHEMA,
        version: f.version,
        previous_hash: f.previous_hash,
        label: f.label.to_string(),
        device_key_hash: format!("0x{}", norm_omni(f.device_key_hash)),
        actor_omni: format!("0x{}", norm_omni(f.actor_omni)),
        k10_address: f.k10_address.to_string(),
        preset_id: f.preset_id.to_string(),
        chat_channel_id: f.chat_channel_id.to_string(),
        memory_ns: f.memory_ns.to_string(),
        bound_channels: f.bound_channels.to_vec(),
        availability: f.availability.to_string(),
        memory_namespaces: f.memory_namespaces.to_string(),
        tz_offset_minutes: f.tz_offset_minutes,
        updated_at: now_unix(),
    }
}

/// The document's bytes and their seal: keccak256 of the exact JSON stored
/// as the entry body.
pub fn doc_bytes_and_hash(doc: &DelegateContextDoc) -> (String, [u8; 32]) {
    let json = serde_json::to_string(doc).unwrap_or_default();
    let hash = agentkeys_core::device_crypto::keccak256(json.as_bytes());
    (json, hash)
}

/// The trailing seal call for a ceremony batch + the facts to return. `None`
/// seal when the stack names no audit contract (logged, never silent).
pub fn seal_for(
    cfg: &AcceptConfig,
    operator_omni: &[u8; 32],
    doc: &DelegateContextDoc,
) -> (Vec<TrailingCall>, Option<ContextSeal>) {
    let (json, hash) = doc_bytes_and_hash(doc);
    let Some(audit) = audit_contract(cfg) else {
        tracing::warn!(
            label = %doc.label,
            "anchor: no CredentialAudit address on this stack (CREDENTIAL_AUDIT_ADDRESS / the chain profile) — the ceremony carries NO seal"
        );
        return (Vec::new(), None);
    };
    (
        vec![(
            audit,
            agentkeys_core::erc4337::append_root_calldata(operator_omni, &hash, doc.version),
        )],
        Some(ContextSeal {
            context_doc: json,
            context_hash: format!("0x{}", hex::encode(hash)),
            context_version: doc.version,
        }),
    )
}

/// `rootCount(operator)` on the audit contract.
async fn root_count(
    http: &reqwest::Client,
    rpc: &str,
    audit: &[u8; 20],
    operator: &[u8; 32],
) -> Result<u64, String> {
    let data = format!(
        "0x{}",
        hex::encode(agentkeys_core::erc4337::root_count_calldata(operator))
    );
    let out = eth_call(http, rpc, audit, &data).await?;
    let bytes =
        hex::decode(out.trim_start_matches("0x")).map_err(|e| format!("rootCount hex: {e}"))?;
    if bytes.len() < 32 {
        return Err("rootCount: short answer".into());
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&bytes[24..32]);
    Ok(u64::from_be_bytes(n))
}

/// `getRoot(operator, idx).merkleRoot`.
async fn root_at(
    http: &reqwest::Client,
    rpc: &str,
    audit: &[u8; 20],
    operator: &[u8; 32],
    idx: u64,
) -> Result<[u8; 32], String> {
    let data = format!(
        "0x{}",
        hex::encode(agentkeys_core::erc4337::get_root_calldata(operator, idx))
    );
    let out = eth_call(http, rpc, audit, &data).await?;
    let bytes =
        hex::decode(out.trim_start_matches("0x")).map_err(|e| format!("getRoot hex: {e}"))?;
    if bytes.len() < 32 {
        return Err("getRoot: short answer".into());
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    Ok(r)
}

/// The most recent MAX_SCAN roots of an operator, newest first — is `hash`
/// among them? Returns its index.
const MAX_SCAN: u64 = 64;

pub async fn find_sealed_index(
    http: &reqwest::Client,
    rpc: &str,
    audit: &[u8; 20],
    operator: &[u8; 32],
    hash: &[u8; 32],
) -> Result<Option<u64>, String> {
    let count = root_count(http, rpc, audit, operator).await?;
    let floor = count.saturating_sub(MAX_SCAN);
    let mut idx = count;
    while idx > floor {
        idx -= 1;
        if root_at(http, rpc, audit, operator, idx).await? == *hash {
            return Ok(Some(idx));
        }
    }
    Ok(None)
}

fn omni32(hex_str: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(norm_omni(hex_str)).map_err(|e| format!("omni hex: {e}"))?;
    b.try_into()
        .map_err(|_| "omni must be 32 bytes".to_string())
}

// ─── /v1/agent/anchors/build — seal existing apps ───────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AnchorsBuildRequest {
    pub operator_omni: String,
    /// The delegates to seal (each must be this master's, with a row).
    pub device_key_hashes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AnchorsBuildResponse {
    #[serde(flatten)]
    pub build: BuildAcceptResponse,
    pub seals: Vec<SealedDelegate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SealedDelegate {
    pub device_key_hash: String,
    #[serde(flatten)]
    pub seal: ContextSeal,
}

/// `POST /v1/agent/anchors/build` (J1_master) — one `appendRoot` per listed
/// delegate, each sealing that delegate's context document composed from its
/// row (version = the row's + 1): the migration for apps installed before the
/// anchor existed, ONE Touch ID. Submit the signed op to `/v1/scope/submit`,
/// then store each document and tell the rows through
/// `/v1/agent/spawn/context/update`.
pub async fn anchors_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<AnchorsBuildRequest>,
) -> Result<Json<AnchorsBuildResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    if req.device_key_hashes.is_empty() {
        return Err(aerr(
            StatusCode::BAD_REQUEST,
            "device_key_hashes: nothing to seal",
        ));
    }
    let (cfg, broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let Some(audit) = audit_contract(&cfg) else {
        return Err(aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "no CredentialAudit address on this stack (CREDENTIAL_AUDIT_ADDRESS / the chain profile) — nothing can be sealed",
        ));
    };
    let operator = omni32(&session_omni).map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let mut trailing: Vec<TrailingCall> = Vec::new();
    let mut seals: Vec<SealedDelegate> = Vec::new();
    for dkh in &req.device_key_hashes {
        let probe = probe_owned_delegate(&state, &cfg.rpc_url, &cfg.registry, &session_omni, dkh)
            .await
            .map_err(|e| aerr(StatusCode::CONFLICT, format!("{dkh}: {e}")))?;
        let ctx = match state.spawn_context_store.get(dkh) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err(aerr(
                    StatusCode::CONFLICT,
                    format!("{dkh}: no spawn context row on this broker — re-hydrate it first"),
                ))
            }
            Err(e) => return Err(aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        };
        let doc = compose_context_doc(ContextDocFacts {
            version: (ctx.context_version.max(0) as u64) + 1,
            previous_hash: Some(ctx.context_hash.clone()).filter(|h| !h.is_empty()),
            label: &ctx.label,
            device_key_hash: &ctx.device_key_hash,
            actor_omni: &format!("0x{}", hex::encode(probe.actor_omni)),
            k10_address: &ctx.k10_address,
            preset_id: &ctx.preset_id,
            chat_channel_id: &ctx.chat_channel_id,
            memory_ns: &ctx.memory_ns,
            bound_channels: &ctx.bound_channels(),
            availability: &ctx.availability,
            memory_namespaces: &ctx.memory_namespaces,
            tz_offset_minutes: ctx.tz_offset_minutes,
        });
        let (json, hash) = doc_bytes_and_hash(&doc);
        trailing.push((
            audit,
            agentkeys_core::erc4337::append_root_calldata(&operator, &hash, doc.version),
        ));
        seals.push(SealedDelegate {
            device_key_hash: format!("0x{}", norm_omni(dkh)),
            seal: ContextSeal {
                context_doc: json,
                context_hash: format!("0x{}", hex::encode(hash)),
                context_version: doc.version,
            },
        });
    }
    let master_account =
        call_operator_master_wallet(&state.http, &cfg.rpc_url, &cfg.registry, &req.operator_omni)
            .await
            .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    if master_account == [0u8; 20] {
        return Err(aerr(
            StatusCode::CONFLICT,
            "operator has no master account on chain",
        ));
    }
    let nonce = call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
    // `register` / `grant` are unused by a trailing-only batch; the omni pair
    // keeps the params honest.
    let register = agentkeys_core::erc4337::AgentRegister {
        device_key_hash: [0u8; 32],
        operator_omni: operator,
        actor_omni: operator,
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
        valid_until: now_unix() + SPONSOR_WINDOW_SECS,
        valid_after: 0,
        broker_signer: cfg.broker_signer,
        register: &register,
        grant: &grant,
    };
    let assembled = assemble_trailing_userop(&params, &trailing, &broker_sk)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(seals = seals.len(), "anchor: seal-existing batch assembled");
    Ok(Json(AnchorsBuildResponse {
        build: assembled.into_build_response(&cfg.entry_point, cfg.chain_id),
        seals,
    }))
}

// ─── /v1/agent/spawn/context/rehydrate ──────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RehydrateRequest {
    pub operator_omni: String,
    /// The context document's exact JSON (the entry body on the memory plane).
    pub context_doc: String,
}

#[derive(Debug, Serialize)]
pub struct RehydrateResponse {
    pub ok: bool,
    pub device_key_hash: String,
    pub label: String,
    #[serde(rename = "sealed_index")]
    pub sealed_index: u64,
    pub context_version: u64,
    pub context_hash: String,
    /// `created` (no row before) · `updated` (an older row) · `current` (the
    /// row already carried this version).
    pub row: String,
}

/// `POST /v1/agent/spawn/context/rehydrate` (J1_master) — rebuild (or
/// refresh) a delegate's spawn-context row from its sealed document: the
/// document's hash must be one of the operator's recent roots on the audit
/// contract, the delegate must be this master's on chain, and the K10 comes
/// back from the signer (custody stacks) — never from the document. What a
/// fresh broker needs after a host switch.
pub async fn rehydrate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RehydrateRequest>,
) -> Result<Json<RehydrateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    let doc: DelegateContextDoc = serde_json::from_str(&req.context_doc)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, format!("context_doc: {e}")))?;
    if doc.schema != CONTEXT_DOC_SCHEMA {
        return Err(aerr(
            StatusCode::BAD_REQUEST,
            format!(
                "context_doc: schema {} (this broker reads {})",
                doc.schema, CONTEXT_DOC_SCHEMA
            ),
        ));
    }
    let hash = agentkeys_core::device_crypto::keccak256(req.context_doc.as_bytes());
    let (cfg, _broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let Some(audit) = audit_contract(&cfg) else {
        return Err(aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "no CredentialAudit address on this stack — a seal cannot be verified",
        ));
    };
    let operator = omni32(&session_omni).map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let sealed_index = find_sealed_index(&state.http, &cfg.rpc_url, &audit, &operator, &hash)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?
        .ok_or_else(|| {
            aerr(
                StatusCode::CONFLICT,
                format!(
                    "context_doc v{} (0x{}) is not among this operator's last {MAX_SCAN} sealed roots — seal it first",
                    doc.version,
                    hex::encode(hash)
                ),
            )
        })?;
    let probe = probe_owned_delegate(
        &state,
        &cfg.rpc_url,
        &cfg.registry,
        &session_omni,
        &doc.device_key_hash,
    )
    .await
    .map_err(|e| aerr(StatusCode::CONFLICT, e))?;
    let chain_actor = format!("0x{}", hex::encode(probe.actor_omni));
    if norm_omni(&chain_actor) != norm_omni(&doc.actor_omni) {
        return Err(aerr(
            StatusCode::CONFLICT,
            "context_doc: actor_omni does not match the chain binding of this device",
        ));
    }
    // The K10: signer custody re-derives it; a legacy keygen stack has no way
    // to bring the secret back — the row is still rebuilt (address only) so
    // the delegate is at least known, loudly.
    let custody = crate::handlers::spawn::delegate_key_custody(
        std::env::var("AGENTKEYS_DELEGATE_KEYS").ok().as_deref(),
        std::env::var("AGENTKEYS_SIGNER_URL").ok().as_deref(),
    )
    .map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let (k10_address, k10_secret_hex) = match &custody {
        crate::handlers::spawn::DelegateKeyCustody::Signer(signer_url) => {
            let master_bearer = crate::handlers::accept::bearer(&headers)?;
            let derived = agentkeys_core::signer_client::DeviceSignerClient::new(signer_url)
                .derive_device(&chain_actor, Some(&doc.label), &master_bearer)
                .await
                .map_err(|e| aerr(StatusCode::BAD_GATEWAY, format!("signer derive: {e}")))?;
            (derived.address, String::new())
        }
        _ => {
            tracing::warn!(
                device_key_hash = %doc.device_key_hash,
                "anchor rehydrate: legacy broker-side keygen — the K10 secret cannot be restored from a document; row rebuilt with the address only"
            );
            (doc.k10_address.clone(), String::new())
        }
    };
    let existing = state
        .spawn_context_store
        .get(&doc.device_key_hash)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row_state = match &existing {
        None => "created",
        Some(c) if c.context_version as u64 >= doc.version && !c.context_hash.is_empty() => {
            "current"
        }
        Some(_) => "updated",
    };
    if row_state != "current" {
        let created_at = existing
            .as_ref()
            .map(|c| c.created_at)
            .unwrap_or(now_unix() as i64);
        let secret = existing
            .as_ref()
            .map(|c| c.k10_secret_hex.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or(k10_secret_hex);
        state
            .spawn_context_store
            .upsert(&crate::storage::SpawnContext {
                device_key_hash: doc.device_key_hash.clone(),
                label: doc.label.clone(),
                chat_channel_id: doc.chat_channel_id.clone(),
                k10_address,
                k10_secret_hex: secret,
                memory_ns: doc.memory_ns.clone(),
                created_at,
                preset_id: doc.preset_id.clone(),
                bound_channels_json: serde_json::to_string(&doc.bound_channels).unwrap_or_default(),
                availability: doc.availability.clone(),
                memory_namespaces: doc.memory_namespaces.clone(),
                tz_offset_minutes: doc.tz_offset_minutes,
                context_version: doc.version as i64,
                context_hash: format!("0x{}", hex::encode(hash)),
            })
            .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    tracing::info!(
        device_key_hash = %doc.device_key_hash,
        label = %doc.label,
        version = doc.version,
        sealed_index,
        row = row_state,
        "anchor: spawn context rehydrated from the sealed document"
    );
    Ok(Json(RehydrateResponse {
        ok: true,
        device_key_hash: doc.device_key_hash,
        label: doc.label,
        sealed_index,
        context_version: doc.version,
        context_hash: format!("0x{}", hex::encode(hash)),
        row: row_state.to_string(),
    }))
}
