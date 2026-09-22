//! #717 — rebind an INSTALLED app's slot in place. Owner decision 2026-09-22:
//! "a commit, not a reinstallation" — ONE Touch ID re-signs the delegate's
//! grant set (set-replace) together with the endpoints' mirror grants (and
//! enrolls an endpoint the new channel needs), then the durable spawn context
//! (#546) takes the new bound channels and the LIVE runtime re-sources its
//! feeds through the daemon's `/v1/sandbox/self/bindings` — no reinstall, no
//! slot consumed, no re-create when the instance runs an image that has the
//! surface.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use agentkeys_protocol::{BoundChannel, EndpointEnrollment, EndpointScope};

use crate::handlers::accept::{
    aerr, call_entrypoint_nonce, call_operator_master_wallet, eth_address_has_code,
    load_accept_config, SPONSOR_WINDOW_SECS,
};
use crate::handlers::scope::{parse_scope_grant, BuildScopeRequest};
use crate::handlers::spawn::{parse_endpoint_enrollments, parse_endpoint_scopes};
use crate::handlers::update::{auth_session, mgmt_request, probe_owned_delegate};
use crate::sponsored_accept::{assemble_rebind_userop, AcceptUserOpParams, BuildAcceptResponse};
use crate::state::SharedState;

#[derive(Debug, Clone, Deserialize)]
pub struct RebindBuildRequest {
    pub operator_omni: String,
    pub device_key_hash: String,
    /// The delegate's FULL new grant set (the compiler's `services`).
    pub services: Vec<String>,
    #[serde(default)]
    pub preserve_service_ids: Vec<String>,
    /// The endpoint actors' FULL resulting sets (the gate that relays the new
    /// channel, the console on a display feed).
    #[serde(default)]
    pub endpoint_scopes: Vec<EndpointScope>,
    /// An endpoint the new channel needs that is not enrolled yet.
    #[serde(default)]
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
}

/// Same shape as the spawn / archive builds: the UserOp envelope FLATTENED
/// (`user_op`, `user_op_hash`, … at the top level — what the daemon, the CLI
/// and the web client read), then the rebind facts. The VE gate caught the
/// nested first cut ("rebind/build carried no user_op_hash").
#[derive(Debug, Serialize)]
pub struct RebindBuildResponse {
    #[serde(flatten)]
    pub build: BuildAcceptResponse,
    pub actor_omni: String,
    pub device_key_hash: String,
    pub services: Vec<String>,
    pub endpoint_scopes: Vec<EndpointScope>,
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `POST /v1/agent/rebind/build` (J1_master) — assemble the rebind batch for
/// a delegate this master owns and return the `userOpHash` the master
/// K11-signs. Submit the signed op to `/v1/scope/submit` (the shared accept
/// relay), then call `/v1/agent/spawn/context/update`.
pub async fn rebind_build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RebindBuildRequest>,
) -> Result<Json<RebindBuildResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    if req.services.is_empty() {
        return Err(aerr(
            StatusCode::BAD_REQUEST,
            "services: a rebind never revokes everything — the compiler's full set is required",
        ));
    }
    let (cfg, broker_sk) =
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
    let master_account =
        call_operator_master_wallet(&state.http, &cfg.rpc_url, &cfg.registry, &req.operator_omni)
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
            "operator master is a legacy EOA, not a passkey P256Account — the Touch-ID \
             rebind requires a P256Account master",
        ));
    }
    let scope_req = BuildScopeRequest {
        operator_omni: req.operator_omni.clone(),
        actor_omni: actor_omni.clone(),
        services: req.services.clone(),
        preserve_service_ids: req.preserve_service_ids.clone(),
        read_only: false,
        max_per_call: "0".into(),
        max_per_period: "0".into(),
        max_total: "0".into(),
        period_seconds: 0,
    };
    let (register, grant) =
        parse_scope_grant(&scope_req).map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let extra = parse_endpoint_scopes(&req.endpoint_scopes)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let enrollments = parse_endpoint_enrollments(&req.endpoint_enrollments, &session_omni)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let nonce = call_entrypoint_nonce(&state.http, &cfg.rpc_url, &cfg.entry_point, &master_account)
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, e))?;
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
    let assembled = assemble_rebind_userop(&params, &extra, &enrollments, &broker_sk)
        .map_err(|e| aerr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(
        device_key_hash = %req.device_key_hash,
        actor = %actor_omni,
        services = req.services.len(),
        endpoints = extra.len(),
        enrollments = enrollments.len(),
        "#717 rebind: batch assembled (setScope delegate + endpoint mirrors)"
    );
    Ok(Json(RebindBuildResponse {
        build: assembled.into_build_response(&cfg.entry_point, cfg.chain_id),
        actor_omni,
        device_key_hash: req.device_key_hash,
        services: req.services,
        endpoint_scopes: req.endpoint_scopes,
        endpoint_enrollments: req.endpoint_enrollments,
    }))
}

// ─── /v1/agent/spawn/context/update ──────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SpawnContextUpdateRequest {
    pub operator_omni: String,
    pub device_key_hash: String,
    #[serde(default)]
    pub bound_channels: Vec<BoundChannel>,
}

/// What happened to the RUNNING runtime, if any.
#[derive(Debug, Serialize)]
pub struct RuntimeResource {
    /// `resubscribed` · `asleep` · `unsupported` · `failed` · `unknown` ·
    /// `no-backend`.
    pub mode: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SpawnContextUpdateResponse {
    pub ok: bool,
    pub device_key_hash: String,
    pub bound_channels: usize,
    pub runtime: RuntimeResource,
}

/// `POST /v1/agent/spawn/context/update` (J1_master) — after the rebind's
/// chain confirm: the durable spawn context takes the new bound channels
/// (every later wake / re-create polls them), and the LIVE instance, if any,
/// is told to re-source its feeds in place. Never a chain write.
pub async fn spawn_context_update(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SpawnContextUpdateRequest>,
) -> Result<Json<SpawnContextUpdateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    let (cfg, _broker_sk) =
        load_accept_config().map_err(|e| aerr(StatusCode::SERVICE_UNAVAILABLE, e))?;
    probe_owned_delegate(
        &state,
        &cfg.rpc_url,
        &cfg.registry,
        &session_omni,
        &req.device_key_hash,
    )
    .await
    .map_err(|e| aerr(StatusCode::CONFLICT, e))?;
    let mut ctx = match state.spawn_context_store.get(&req.device_key_hash) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(aerr(
                StatusCode::CONFLICT,
                "no durable spawn context for this delegate (pre-#546 spawn?) — archive + \
                 reinstall instead",
            ))
        }
        Err(e) => {
            return Err(aerr(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn-context read failed: {e}"),
            ))
        }
    };
    ctx.bound_channels_json = serde_json::to_string(&req.bound_channels)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, format!("bound_channels: {e}")))?;
    state.spawn_context_store.upsert(&ctx).map_err(|e| {
        aerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn-context write failed: {e}"),
        )
    })?;
    let runtime = push_live_bindings(&state, &req.device_key_hash, &req.bound_channels).await;
    tracing::info!(
        device_key_hash = %req.device_key_hash,
        bound = req.bound_channels.len(),
        runtime = %runtime.mode,
        "#717 rebind: spawn context updated — {}",
        runtime.detail
    );
    Ok(Json(SpawnContextUpdateResponse {
        ok: true,
        device_key_hash: req.device_key_hash,
        bound_channels: req.bound_channels.len(),
        runtime,
    }))
}

/// Tell the running instance (if any) its new bound channels through the
/// daemon's `/v1/sandbox/self/bindings`, bearer = the per-delegate management
/// token the broker minted at spawn.
async fn push_live_bindings(
    state: &SharedState,
    device_key_hash: &str,
    bound: &[BoundChannel],
) -> RuntimeResource {
    let Some(backend) = state.sandbox.clone() else {
        return RuntimeResource {
            mode: "no-backend".into(),
            detail: "no sandbox lifecycle configured on this host — the context row is updated, \
                     nothing runs here"
                .into(),
            sandbox_id: None,
        };
    };
    let live = match backend.live_for_device(device_key_hash).await {
        Ok(l) => l,
        Err(e) => {
            return RuntimeResource {
                mode: "unknown".into(),
                detail: format!("list live instances: {e:#}"),
                sandbox_id: None,
            }
        }
    };
    let Some(instance) = live.first() else {
        return RuntimeResource {
            mode: "asleep".into(),
            detail: "no live instance — the next wake polls the new channels (it boots from \
                     the updated context)"
                .into(),
            sandbox_id: None,
        };
    };
    let Some((base, route_headers)) = backend.instance_daemon_endpoint(&instance.id) else {
        return RuntimeResource {
            mode: "unsupported".into(),
            detail: "this backend has no broker-reachable path into the instance — re-create \
                     the runtime (update) to re-source it"
                .into(),
            sandbox_id: Some(instance.id.clone()),
        };
    };
    let token =
        crate::handlers::sandbox::sandbox_mgmt_token(&state.session_keypair, device_key_hash);
    let body =
        serde_json::to_vec(&serde_json::json!({ "bound_channels": bound })).unwrap_or_default();
    match mgmt_request(
        &state.http,
        &base,
        &route_headers,
        &token,
        reqwest::Method::POST,
        "/v1/sandbox/self/bindings",
        Some(body),
        20,
    )
    .await
    {
        Ok(resp) => {
            let v: serde_json::Value = serde_json::from_slice(&resp).unwrap_or_default();
            let feeds = v.get("feeds").and_then(|f| f.as_u64()).unwrap_or(0);
            RuntimeResource {
                mode: "resubscribed".into(),
                detail: format!(
                    "the running instance re-sourced its feeds in place ({feeds} bound \
                     channel(s)) — no restart"
                ),
                sandbox_id: Some(instance.id.clone()),
            }
        }
        Err(e) if e.contains("HTTP 404") => RuntimeResource {
            mode: "unsupported".into(),
            detail: format!(
                "the running instance predates the live-rebind surface ({e}) — re-create it \
                 (update runtime) to re-source"
            ),
            sandbox_id: Some(instance.id.clone()),
        },
        Err(e) => RuntimeResource {
            mode: "failed".into(),
            detail: format!(
                "live push failed ({e}) — the context row is updated; re-create the runtime \
                 (update) to re-source"
            ),
            sandbox_id: Some(instance.id.clone()),
        },
    }
}

// ─── /v1/agent/self/context ─────────────────────────────────────────────────

/// What a delegate reads back from its anchor.
#[derive(Debug, Serialize)]
pub struct SelfContextResponse {
    pub ok: bool,
    pub device_key_hash: String,
    pub label: String,
    pub chat_channel_id: String,
    pub bound_channels: Vec<BoundChannel>,
    pub availability: String,
    pub tz_offset_minutes: i64,
    pub preset_id: String,
}

/// `GET /v1/agent/self/context` (J1_agent) — the delegate reads its OWN
/// durable spawn context: the ANCHOR its bound channels live in (owner
/// decision 2026-09-22: never baked into the image, never frozen in the
/// instance — the sandbox re-reads this and re-sources itself, so a rebind
/// lands without a restart even when the live push never reached it). The
/// session names the device (`identity_value` = the pubkey the resolve
/// proved possession of) → its `device_key_hash` → the row; a session that
/// is not device-bound (a master's) has no row to read.
pub async fn self_context(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<SelfContextResponse>, (StatusCode, Json<serde_json::Value>)> {
    let token = crate::handlers::accept::bearer(&headers)?;
    let claims = crate::jwt::verify::verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &token,
    )
    .map_err(|e| aerr(StatusCode::UNAUTHORIZED, format!("session jwt: {e}")))?;
    let pubkey = claims.agentkeys.identity_value.trim().to_string();
    if pubkey.is_empty() {
        return Err(aerr(
            StatusCode::FORBIDDEN,
            "not a device-bound session — only a delegate reads its own context",
        ));
    }
    let device_key_hash = agentkeys_core::device_crypto::device_key_hash(&pubkey)
        .map_err(|e| aerr(StatusCode::FORBIDDEN, format!("session device: {e}")))?;
    let ctx =
        match state.spawn_context_store.get(&device_key_hash) {
            Ok(Some(c)) => c,
            Ok(None) => return Err(aerr(
                StatusCode::NOT_FOUND,
                "no durable spawn context for this delegate (a device actor, or a pre-#546 spawn)",
            )),
            Err(e) => {
                return Err(aerr(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("spawn-context read failed: {e}"),
                ))
            }
        };
    Ok(Json(SelfContextResponse {
        ok: true,
        device_key_hash: ctx.device_key_hash.clone(),
        label: ctx.label.clone(),
        chat_channel_id: ctx.chat_channel_id.clone(),
        bound_channels: ctx.bound_channels(),
        availability: ctx.availability.clone(),
        tz_offset_minutes: ctx.tz_offset_minutes,
        preset_id: ctx.preset_id.clone(),
    }))
}
