//! #664 / #682 — the master-side APPLICATIONS surface (epic #660, plan §4.6
//! lifecycle + §4.10): the two policy-class registries (`app-registry`,
//! `resource-registry`), the install / uninstall ceremonies over the existing
//! #427 spawn / archive proxies, the per-app dashboard read, the card-action
//! command publish, and resource curation.
//!
//! Records, never authority (D1): every route here either RELAYS a
//! master-signed UserOp to the broker (the ONE Touch ID) or writes a readable
//! doc in the master-only Config data class. The delegate's grant set is
//! compiled by the broker from the template + the bindings; this module
//! compiles the same manifest locally ONLY to derive the ENDPOINT actors'
//! mirror grants (gateway / console) that ride the same batch.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use agentkeys_backend_client::protocol::{
    compile_app, service_channel_pub, service_channel_sub, validate_template, AppInstallBindings,
    AppInstanceRow, AppInstanceStatus, AppRegistryDoc, Availability, BoundChannel, CardCommand,
    CardDocument, ChannelEndpointKind, CompiledApp, ContactSummary, ContactTier,
    EndpointEnrollment, EndpointGrantDelta, EndpointScope, PresetBundle, PresetSummary,
    ResourceItemRow, ResourceKind, ResourceRegistryDoc, Sensitivity, ServiceAnnotation,
    SlotAudience, SlotBinding, TemplateError, APP_REGISTRY_SERVICE, RESOURCE_REGISTRY_SERVICE,
};
use agentkeys_backend_client::protocol::{AppAnchor, ContextSeal, DelegateContextDoc};

use crate::ui_bridge::{
    config_fetch_doc, config_store_doc, ensure_binding_manifest, ensure_channel_named,
    ensure_channel_registry, gateway_admin_call, invalidate_fleet_sync, master_channel_cap,
    now_unix, pairing_err, plant_master_memory_inner, real_config_ctx, registry_err,
    registry_storage_label, resource_entry_remove, resource_object_put,
    sync_gateway_registry_to_config, valid_channel_id, SharedUiBridgeState, UiBridgeState,
};

// ── registry docs ───────────────────────────────────────────────────────────

pub(crate) async fn ensure_app_registry(state: &UiBridgeState) -> Result<AppRegistryDoc, String> {
    if let Some(r) = state.app_registry.read().await.clone() {
        return Ok(r);
    }
    let loaded = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            match config_fetch_doc(&client, &ctx, APP_REGISTRY_SERVICE).await? {
                Some(bytes) => serde_json::from_slice::<AppRegistryDoc>(&bytes)
                    .map_err(|e| format!("app-registry parse: {e}"))?,
                None => AppRegistryDoc::default(),
            }
        }
        None => AppRegistryDoc::default(),
    };
    *state.app_registry.write().await = Some(loaded.clone());
    Ok(loaded)
}

pub(crate) async fn persist_app_registry(
    state: &UiBridgeState,
    next: AppRegistryDoc,
) -> Result<&'static str, String> {
    let storage = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            let bytes =
                serde_json::to_vec(&next).map_err(|e| format!("app-registry serialize: {e}"))?;
            config_store_doc(&client, &ctx, APP_REGISTRY_SERVICE, &bytes).await?;
            "ok"
        }
        None => "cached",
    };
    *state.app_registry.write().await = Some(next);
    Ok(storage)
}

pub(crate) async fn ensure_resource_registry(
    state: &UiBridgeState,
) -> Result<ResourceRegistryDoc, String> {
    if let Some(r) = state.resource_registry.read().await.clone() {
        return Ok(r);
    }
    let loaded = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            match config_fetch_doc(&client, &ctx, RESOURCE_REGISTRY_SERVICE).await? {
                Some(bytes) => {
                    // Row by row: a row this build cannot read is kept opaque and
                    // written back, never dropped and never a 502 for every
                    // resource operation (a newer build may have minted it).
                    let (doc, skipped) = ResourceRegistryDoc::from_slice_lenient(&bytes)
                        .map_err(|e| format!("resource-registry parse: {e}"))?;
                    if skipped > 0 {
                        tracing::warn!(
                            skipped,
                            kept = doc.items.len(),
                            "resource-registry: rows this build cannot read were kept opaque"
                        );
                    }
                    doc
                }
                None => ResourceRegistryDoc::default(),
            }
        }
        None => ResourceRegistryDoc::default(),
    };
    *state.resource_registry.write().await = Some(loaded.clone());
    Ok(loaded)
}

pub(crate) async fn persist_resource_registry(
    state: &UiBridgeState,
    next: ResourceRegistryDoc,
) -> Result<&'static str, String> {
    let storage = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            let bytes = serde_json::to_vec(&next)
                .map_err(|e| format!("resource-registry serialize: {e}"))?;
            config_store_doc(&client, &ctx, RESOURCE_REGISTRY_SERVICE, &bytes).await?;
            "ok"
        }
        None => "cached",
    };
    *state.resource_registry.write().await = Some(next);
    Ok(storage)
}

// ── the install ceremony ────────────────────────────────────────────────────

/// What the daemon keeps between install/build and install/submit (keyed by
/// the delegate's `device_key_hash` from the broker build response), RAM only
/// like the #427 ceremony stash.
#[derive(Debug, Clone)]
pub(crate) struct AppInstallStash {
    pub template_id: String,
    pub template_version: String,
    pub template_schema: u32,
    pub label: String,
    pub bindings: AppInstallBindings,
    pub bound_channels: Vec<BoundChannel>,
    pub audience: Vec<SlotAudience>,
    pub availability: Availability,
    /// #663 — the endpoint device actors this install's ONE Touch ID also
    /// registers (completed on the device side after the confirm).
    pub enrollments: Vec<PendingEnrollment>,
    /// The compiled grant set the broker's build returned — the sheet the owner
    /// signs. Kept HERE because `spawn_submit_core` consumes the #427 ceremony
    /// context at confirm, so a read of `ceremony_context_by_dkh` after the
    /// submit finds nothing (the registry row shipped with `services: []`).
    pub services: Vec<String>,
    /// The anchor seal the batch carries: the context document stored on the
    /// memory plane after the confirm.
    pub context_seal: Option<ContextSeal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingEnrollmentKind {
    Gateway,
    Console,
}

/// One endpoint enrollment folded into an install batch: the claim landed
/// (child omni known), the on-chain register rides the install's UserOp, the
/// device-side completion runs after the confirm.
#[derive(Debug, Clone)]
pub(crate) struct PendingEnrollment {
    pub kind: PendingEnrollmentKind,
    pub request_id: String,
    pub label: String,
    pub child_omni: String,
    pub device_key_hash: String,
    pub device_pubkey: String,
    /// The gateway's transport namespace (gateway only).
    pub transport: String,
    /// The console's K10 file (console only).
    pub key_file: String,
}

/// What the daemon keeps between uninstall/build and uninstall/submit.
#[derive(Debug, Clone)]
pub(crate) struct AppUninstallStash {
    pub resources_kept: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct AppInstallBuildRequest {
    pub template_id: String,
    pub label: String,
    #[serde(default)]
    pub bindings: AppInstallBindings,
    #[serde(default)]
    pub memory_ns: Option<String>,
    #[serde(default)]
    pub memory_inherited: bool,
    /// #663 — fold the not-yet-enrolled endpoint actors the bindings need (the
    /// channel gateway for a messaging slot, this console for a display slot)
    /// into the SAME batch, so the first install is still ONE Touch ID. Off
    /// for headless CI installs (a throwaway runner must not register itself).
    #[serde(default = "default_true")]
    pub enroll_endpoints: bool,
}

/// The daemon's install/build response: the broker's build envelope (what the
/// sheet renders + what the master signs) plus the compiled endpoint scopes.
#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppInstallBuildResponse {
    /// The broker's `BuildSpawnUserOpResponse` verbatim (user_op, hash,
    /// services, annotations, bound_channels, audience, …).
    #[ts(type = "unknown")]
    pub build: serde_json::Value,
    pub template_id: String,
    pub template_version: String,
    pub endpoint_scopes: Vec<EndpointScope>,
    /// #663 — the endpoint device actors this Touch ID ALSO registers (the
    /// sheet says so: "also enrolls the contact gate / this console").
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
    /// The catalog template's manifest, for the sheet's disclosure lines.
    #[ts(type = "unknown")]
    pub manifest: serde_json::Value,
}

fn refused(status: StatusCode, error: &str, rows: Vec<TemplateError>) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "rows": rows,
            "message": rows.iter().map(|r| format!("{} — {}", r.row, r.message)).collect::<Vec<_>>().join("; "),
        })),
    )
        .into_response()
}

/// Fetch a template's bundle from the broker catalog.
pub(crate) async fn fetch_bundle(broker: &str, template_id: &str) -> Result<PresetBundle, String> {
    let url = format!(
        "{}/v1/presets/{}",
        broker.trim_end_matches('/'),
        template_id
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| format!("catalog unreachable: {e}"))?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Err(format!("template '{template_id}' is not in the catalog"));
    }
    if !resp.status().is_success() {
        return Err(format!("catalog HTTP {}", resp.status()));
    }
    resp.json::<PresetBundle>()
        .await
        .map_err(|e| format!("bundle parse: {e}"))
}

/// An endpoint actor's CURRENT grant view: the binding-manifest names plus the
/// on-chain hashes the daemon could not name (echoed as preserve ids so a
/// set-replace never wipes them) — the `/v1/scope/build` preserve posture.
async fn endpoint_current_grants(
    state: &UiBridgeState,
    actor_omni: &str,
) -> (Vec<String>, Vec<String>) {
    let norm = |o: &str| o.trim().trim_start_matches("0x").to_lowercase();
    let want = norm(actor_omni);
    let mut names: Vec<String> = Vec::new();
    if let Ok(manifest) = ensure_binding_manifest(state).await {
        for e in manifest.entries() {
            if norm(&e.actor_omni) == want {
                names = e.granted_service_names.clone();
            }
        }
    }
    let mut preserve: Vec<String> = Vec::new();
    for a in state.actors.read().await.values() {
        if norm(&a.omni_hex) == want || norm(&a.omni) == want {
            if let Some(svcs) = &a.services {
                for s in svcs {
                    if !names.contains(s) {
                        names.push(s.clone());
                    }
                }
            }
            if let Some(ids) = &a.scope_unknown_service_ids {
                // Hashes the daemon already resolved to channel / capability
                // NAMES are re-sent as names, not as preserve ids.
                let resolved: Vec<String> = a
                    .scope_channel_service_ids
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .chain(a.scope_capability_service_ids.clone().unwrap_or_default())
                    .collect();
                for id in ids {
                    if !resolved.contains(id) {
                        preserve.push(id.clone());
                    }
                }
            }
        }
    }
    (names, preserve)
}

/// The endpoint actors' FULL resulting sets after ADDING the compiler's mirror
/// grants (install) — plus the console device's own render + command grants
/// on every display feed.
async fn endpoint_scopes_for_install(
    state: &UiBridgeState,
    deltas: &[EndpointGrantDelta],
    bound_channels: &[BoundChannel],
    console_actor: Option<&str>,
) -> Vec<EndpointScope> {
    let mut all: Vec<EndpointGrantDelta> = deltas.to_vec();
    if let Some(console_actor) = console_actor {
        let mut add: Vec<String> = Vec::new();
        for b in bound_channels
            .iter()
            .filter(|b| b.kind == ChannelEndpointKind::Display)
        {
            add.push(agentkeys_backend_client::protocol::service_channel_sub(
                &b.channel_id,
            ));
            add.push(agentkeys_backend_client::protocol::service_channel_pub(
                &b.channel_id,
            ));
        }
        if !add.is_empty() {
            match all
                .iter_mut()
                .find(|d| d.actor_omni.eq_ignore_ascii_case(console_actor))
            {
                Some(d) => {
                    for s in add {
                        if !d.add.contains(&s) {
                            d.add.push(s);
                        }
                    }
                }
                None => all.push(EndpointGrantDelta {
                    actor_omni: console_actor.to_string(),
                    add,
                }),
            }
        }
    }
    let mut out = Vec::with_capacity(all.len());
    for d in all {
        let (mut services, preserve) = endpoint_current_grants(state, &d.actor_omni).await;
        for s in d.add {
            if !services.contains(&s) {
                services.push(s);
            }
        }
        out.push(EndpointScope {
            actor_omni: d.actor_omni,
            services,
            preserve_service_ids: preserve,
        });
    }
    out
}

/// The endpoint actors' FULL resulting sets after REMOVING one app's feeds
/// (uninstall) — the install's mirror.
async fn endpoint_scopes_for_uninstall(
    state: &UiBridgeState,
    bound_channels: &[BoundChannel],
) -> Vec<EndpointScope> {
    let feeds: Vec<String> = bound_channels
        .iter()
        .map(|b| b.channel_id.clone())
        .collect();
    let drop_set: Vec<String> = feeds
        .iter()
        .flat_map(|f| {
            vec![
                agentkeys_backend_client::protocol::service_channel_pub(f),
                agentkeys_backend_client::protocol::service_channel_sub(f),
            ]
        })
        .collect();
    let mut actors: Vec<String> = bound_channels
        .iter()
        .filter_map(|b| b.endpoint_actor_omni.clone())
        .collect();
    if let Some(console) = state.console_device.read().await.clone() {
        if bound_channels
            .iter()
            .any(|b| b.kind == ChannelEndpointKind::Display)
        {
            actors.push(console.actor_omni);
        }
    }
    actors.sort();
    actors.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    let mut out = Vec::new();
    for actor in actors {
        let (services, preserve) = endpoint_current_grants(state, &actor).await;
        let remaining: Vec<String> = services
            .into_iter()
            .filter(|s| !drop_set.iter().any(|d| d.eq_ignore_ascii_case(s)))
            .collect();
        out.push(EndpointScope {
            actor_omni: actor,
            services: remaining,
            preserve_service_ids: preserve,
        });
    }
    out
}

/// Resolve each slot binding's endpoint actor from the channel registry (a
/// messaging row = the gateway transport, carrying the gateway's actor omni;
/// a display row may carry a paired display device's). Bindings that already
/// name one keep it. Also returns the display names for the derived feeds.
async fn resolve_binding_endpoints(
    state: &UiBridgeState,
    bindings: &mut AppInstallBindings,
) -> Vec<(String, String)> {
    let Ok(reg) = ensure_channel_registry(state).await else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for b in &mut bindings.slots {
        if let Some(row) = reg.channels.iter().find(|c| c.id == b.channel_id) {
            if b.endpoint_actor_omni.is_none() {
                b.endpoint_actor_omni = row.endpoint_actor_omni.clone();
            }
            names.push((b.channel_id.clone(), row.name.clone()));
        }
    }
    names
}

/// POST /v1/master/apps/install/build — the install ceremony, build half.
pub async fn app_install_build(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<AppInstallBuildRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let template_id = req.template_id.trim().to_string();
    let label = req.label.trim().to_string();
    if template_id.is_empty() || label.is_empty() {
        return pairing_err(
            StatusCode::BAD_REQUEST,
            "template_id and label are required",
        );
    }
    // Owner decision 2026-09-07: an install ALWAYS spawns a fresh delegate — a
    // label already installed refuses (uninstall first).
    if let Ok(reg) = ensure_app_registry(&state).await {
        if reg.live().any(|a| a.label == label) {
            return pairing_err(
                StatusCode::CONFLICT,
                "an application with this label is already installed — uninstall it first \
                 (an install always spawns a fresh delegate)",
            );
        }
    }
    let bundle = match fetch_bundle(&broker, &template_id).await {
        Ok(b) => b,
        Err(e) => return pairing_err(StatusCode::BAD_GATEWAY, &e),
    };
    if let Err(rows) = validate_template(
        &bundle.manifest,
        &bundle.skill_filenames(),
        &bundle.knowledge_filenames(),
    ) {
        return refused(StatusCode::BAD_REQUEST, "template_invalid", rows);
    }
    let mut bindings = req.bindings.clone();
    resolve_binding_endpoints(&state, &mut bindings).await;
    // One messaging channel per app: two apps on one channel would both read
    // every family message and both reply (the gate relays a channel to
    // exactly one app).
    if let Ok(reg) = ensure_app_registry(&state).await {
        if let Some(rows) = messaging_channels_in_use(&reg, &bundle.manifest, &bindings, &label) {
            return refused(StatusCode::BAD_REQUEST, "template_bindings_invalid", rows);
        }
    }
    // #663 — ONE Touch ID: the endpoint actors the bindings need but which are
    // not enrolled yet (the channel gateway behind a messaging slot, this
    // console behind a display slot) are claimed NOW and registered in the
    // SAME batch as the delegate; their grants ride `endpoint_scopes`.
    let mut endpoint_enrollments: Vec<EndpointEnrollment> = Vec::new();
    let mut pending_enrollments: Vec<PendingEnrollment> = Vec::new();
    let mut console_actor: Option<String> = state
        .console_device
        .read()
        .await
        .as_ref()
        .map(|d| d.actor_omni.clone());
    if req.enroll_endpoints {
        match plan_enrollments(
            &state,
            &broker,
            &j1,
            &bundle.manifest,
            &label,
            &mut bindings,
            console_actor.is_none(),
        )
        .await
        {
            Ok((enrolls, pendings, console_child)) => {
                endpoint_enrollments = enrolls;
                pending_enrollments = pendings;
                if let Some(c) = console_child {
                    console_actor = Some(c);
                }
            }
            Err(resp) => return resp,
        }
    }
    // Resource bindings: resolve the registry rows (ns / kind / sensitivity)
    // so the broker compiles from facts the master curated, not from the UI.
    if let Ok(resources) = ensure_resource_registry(&state).await {
        for rb in &mut bindings.resources {
            if let Some(item) = resources.find(&rb.item_id) {
                rb.ns = item.ns.clone();
                rb.kind = item.kind;
                rb.sensitivity = item.sensitivity;
            }
        }
    }
    let compiled = match compile_app(
        &bundle.manifest,
        &label,
        req.memory_ns.as_deref(),
        &bindings,
    ) {
        Ok(c) => c,
        Err(rows) => return refused(StatusCode::BAD_REQUEST, "template_bindings_invalid", rows),
    };
    let endpoint_scopes = endpoint_scopes_for_install(
        &state,
        &compiled.endpoint_grants,
        &compiled.bound_channels,
        console_actor.as_deref(),
    )
    .await;
    let mut body = serde_json::json!({
        "operator_omni": operator_omni,
        "label": label,
        "preset_id": template_id,
        "bindings": bindings,
        "endpoint_scopes": endpoint_scopes,
        "endpoint_enrollments": endpoint_enrollments,
    });
    if let Some(ns) = &req.memory_ns {
        body["memory_ns"] = serde_json::json!(ns);
    }
    if req.memory_inherited {
        body["memory_inherited"] = serde_json::json!(true);
    }
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/agent/spawn/build", &j1, &body)
            .await;
    if !resp.status().is_success() {
        return resp;
    }
    let Some(built) = parsed else {
        return pairing_err(StatusCode::BAD_GATEWAY, "broker build returned no JSON");
    };
    let Some(dkh) = built
        .get("device_key_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
    else {
        return pairing_err(
            StatusCode::BAD_GATEWAY,
            "broker build carried no device_key_hash",
        );
    };
    // The #427 stash (the manifest row at confirm) + the app stash.
    state
        .ceremony_context_by_dkh
        .write()
        .await
        .insert(dkh.clone(), built.clone());
    let bound_channels: Vec<BoundChannel> = built
        .get("bound_channels")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| compiled.bound_channels.clone());
    let audience: Vec<SlotAudience> = built
        .get("audience")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| compiled.audience.clone());
    state.app_install_by_dkh.write().await.insert(
        dkh,
        AppInstallStash {
            template_id: template_id.clone(),
            template_version: bundle.manifest.version.clone(),
            template_schema: bundle.manifest.app.schema,
            label: label.clone(),
            bindings,
            bound_channels,
            audience,
            availability: compiled.availability,
            enrollments: pending_enrollments,
            services: built
                .get("services")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_else(|| compiled.services.clone()),
            context_seal: built
                .get("context_seal")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
        },
    );
    (
        StatusCode::OK,
        Json(AppInstallBuildResponse {
            build: built,
            template_id,
            template_version: bundle.manifest.version.clone(),
            endpoint_scopes,
            endpoint_enrollments,
            manifest: serde_json::to_value(&bundle.manifest).unwrap_or_default(),
        }),
    )
        .into_response()
}

fn slot_kind(manifest: &PresetSummary, slot: &str) -> Option<ChannelEndpointKind> {
    manifest
        .app
        .slots
        .iter()
        .find(|s| s.slot == slot)
        .map(|s| s.kind)
}

/// Claim (never sign) the endpoint enrollments this install needs: the
/// channel gateway when a messaging slot binds its transport and it is
/// configured but not enrolled; this console when a display slot is bound and
/// the console is not enrolled. Each claim carries the exact channel-only
/// scope the batch grants (so the broker's pairing poll treats it as a
/// DEVICE — never a delegate to spawn), fills the binding's endpoint actor
/// with the claimed child omni, and is completed on the device side after the
/// install confirms. Returns (the batch's enrollments, the pending rows, the
/// console's new actor when claimed).
#[allow(clippy::type_complexity)]
async fn plan_enrollments(
    state: &UiBridgeState,
    broker: &str,
    j1: &str,
    manifest: &PresetSummary,
    _app_label: &str,
    bindings: &mut AppInstallBindings,
    console_unenrolled: bool,
) -> Result<
    (
        Vec<EndpointEnrollment>,
        Vec<PendingEnrollment>,
        Option<String>,
    ),
    axum::response::Response,
> {
    let mut enrollments = Vec::new();
    let mut pending = Vec::new();
    let mut console_child = None;

    // The channel gateway.
    let unowned_messaging: Vec<usize> = bindings
        .slots
        .iter()
        .enumerate()
        .filter(|(_, b)| {
            b.endpoint_actor_omni.is_none()
                && slot_kind(manifest, &b.slot) == Some(ChannelEndpointKind::Messaging)
        })
        .map(|(i, _)| i)
        .collect();
    if !unowned_messaging.is_empty() {
        match crate::gateway_device::fetch_device_status(state).await {
            // The gate mirrors WHATEVER channel a messaging slot binds (owner
            // decision 2026-09-22: the bound channel is the feed) — until then
            // only a slot bound to the transport row itself got the gate, and
            // any other channel silently bound without an endpoint actor.
            Ok(st) if st.enrolled => {
                for i in unowned_messaging {
                    bindings.slots[i].endpoint_actor_omni = st.actor_omni.clone();
                }
            }
            Ok(st) if st.configured => {
                let targets: Vec<usize> = unowned_messaging;
                if !targets.is_empty() {
                    let start = crate::gateway_device::gateway_pairing_start(state)
                        .await
                        .map_err(|e| {
                            pairing_err(
                                StatusCode::BAD_GATEWAY,
                                &format!("contact gate pairing request: {e}"),
                            )
                        })?;
                    let gw_label = crate::gateway_device::gateway_label(&st.transport);
                    // Pub + sub on every channel these slots bind.
                    let scope = targets
                        .iter()
                        .flat_map(|i| {
                            let ch = bindings.slots[*i].channel_id.clone();
                            vec![service_channel_pub(&ch), service_channel_sub(&ch)]
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    let child = claim_child(broker, j1, &start.pairing_code, &gw_label, &scope)
                        .await
                        .map_err(|e| pairing_err(StatusCode::BAD_GATEWAY, &e))?;
                    for i in targets {
                        bindings.slots[i].endpoint_actor_omni = Some(child.clone());
                    }
                    enrollments.push(EndpointEnrollment {
                        actor_omni: child.clone(),
                        device_key_hash: start.device_key_hash.clone(),
                        pop_sig: start.pop_sig.clone(),
                        label: gw_label.clone(),
                        kind: "gateway".into(),
                        transport: st.transport.clone(),
                    });
                    pending.push(PendingEnrollment {
                        kind: PendingEnrollmentKind::Gateway,
                        request_id: start.request_id,
                        label: gw_label,
                        child_omni: child,
                        device_key_hash: start.device_key_hash,
                        device_pubkey: start.device_pubkey,
                        transport: st.transport,
                        key_file: String::new(),
                    });
                }
            }
            Ok(_) => tracing::info!(
                "#663 install: the contact gate has no device configuration — the messaging slot binds without an endpoint actor (the feed hop idles until the contact gate is converged + enrolled)"
            ),
            Err(e) => tracing::info!(
                "#663 install: no contact gate reachable ({e}) — the messaging slot binds without an endpoint actor"
            ),
        }
    }

    // This console (renders + taps the display feeds).
    let display_feeds: Vec<String> = bindings
        .slots
        .iter()
        .filter(|b| slot_kind(manifest, &b.slot) == Some(ChannelEndpointKind::Display))
        .map(|b| b.channel_id.clone())
        .collect();
    if console_unenrolled && !display_feeds.is_empty() {
        match crate::console_device::console_pairing_start(state).await {
            Ok(start) => {
                let label = crate::console_device::default_label();
                let scope = display_feeds
                    .iter()
                    .flat_map(|d| vec![service_channel_pub(d), service_channel_sub(d)])
                    .collect::<Vec<_>>()
                    .join(",");
                match claim_child(broker, j1, &start.pairing_code, &label, &scope).await {
                    Ok(child) => {
                        enrollments.push(EndpointEnrollment {
                            actor_omni: child.clone(),
                            device_key_hash: start.device_key_hash.clone(),
                            pop_sig: start.pop_sig.clone(),
                            label: label.clone(),
                            kind: "console".into(),
                            transport: String::new(),
                        });
                        pending.push(PendingEnrollment {
                            kind: PendingEnrollmentKind::Console,
                            request_id: start.request_id,
                            label,
                            child_omni: child.clone(),
                            device_key_hash: start.device_key_hash,
                            device_pubkey: start.device_pubkey,
                            transport: String::new(),
                            key_file: start.key_file,
                        });
                        console_child = Some(child);
                    }
                    Err(e) => tracing::warn!(
                        "#663 install: console claim failed ({e}) — taps publish as the master until the console is enrolled from the endpoints tab"
                    ),
                }
            }
            Err(e) => tracing::warn!(
                "#663 install: console pairing request failed ({e}) — taps publish as the master until the console is enrolled from the endpoints tab"
            ),
        }
    }
    Ok((enrollments, pending, console_child))
}

/// The master's claim of an endpoint's pairing code → its child omni, in the
/// canonical `0x` form (`console_device::claim_child_omni`).
async fn claim_child(
    broker: &str,
    j1: &str,
    pairing_code: &str,
    label: &str,
    requested_scope: &str,
) -> Result<String, String> {
    let body =
        agentkeys_cli::agent_admin::agent_claim(broker, pairing_code, label, requested_scope, j1)
            .await
            .map_err(|e| format!("claim ({label}): {e:#}"))?;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    crate::console_device::claim_child_omni(&v, label)
}

/// POST /v1/master/apps/install/submit — the install ceremony, submit half:
/// the #427 spawn submit core (manifest row, opchat name, preset apply) plus
/// the app-registry row, the contacts' `reach`, and the feed display names.
pub async fn app_install_submit(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let (resp, parsed) = crate::ui_bridge::spawn_submit_core(&state, body).await;
    if !resp.status().is_success() {
        return resp;
    }
    let mut installed: Vec<serde_json::Value> = Vec::new();
    for spawned in parsed
        .as_ref()
        .and_then(|v| v.pointer("/ceremony/spawned"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let dkh = spawned
            .get("device_key_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let Some(stash) = state.app_install_by_dkh.write().await.remove(&dkh) else {
            continue;
        };
        let actor_omni = spawned
            .get("actor_omni")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let memory_ns = spawned
            .get("memory_ns")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let chat_channel_id = spawned
            .get("chat_channel_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let services: Vec<String> = if stash.services.is_empty() {
            // Pre-#663 stashes only — the ceremony context is normally gone by now.
            state
                .ceremony_context_by_dkh
                .read()
                .await
                .get(&dkh)
                .and_then(|c| c.get("services"))
                .and_then(|s| serde_json::from_value(s.clone()).ok())
                .unwrap_or_default()
        } else {
            stash.services.clone()
        };
        let reach_aliases: Vec<String> = if stash.audience.is_empty() {
            Vec::new()
        } else {
            vec![stash.label.clone()]
        };
        let row = AppInstanceRow {
            label: stash.label.clone(),
            template_id: stash.template_id.clone(),
            template_version: stash.template_version.clone(),
            template_schema: stash.template_schema,
            actor_omni: actor_omni.clone(),
            device_key_hash: dkh.clone(),
            memory_ns,
            chat_channel_id,
            bindings: stash.bindings.clone(),
            bound_channels: stash.bound_channels.clone(),
            services,
            availability: stash.availability,
            status: AppInstanceStatus::Installed,
            installed_at: now_unix(),
            uninstalled_at: None,
            resources_kept: None,
            reach_aliases: reach_aliases.clone(),
            anchor: stash.context_seal.as_ref().map(|s| AppAnchor {
                version: s.context_version,
                hash: s.context_hash.clone(),
                tx_hash: parsed
                    .as_ref()
                    .and_then(|v| v.get("tx_hash"))
                    .and_then(|t| t.as_str())
                    .map(str::to_string),
                sealed_at: now_unix(),
            }),
        };
        let storage = match ensure_app_registry(&state).await {
            Ok(mut reg) => {
                reg.upsert(row.clone());
                match persist_app_registry(&state, reg).await {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        tracing::warn!(label = %stash.label, "#664 app-registry persist FAILED — {e}");
                        format!("failed: {e}")
                    }
                }
            }
            Err(e) => {
                tracing::warn!(label = %stash.label, "#664 app-registry LOAD failed — {e}");
                format!("failed: {e}")
            }
        };
        // A bound channel the wizard picked is already a registry row; one the
        // CLI bound by raw id is not — register it so its grant chips read
        // (insert-if-absent: an existing row keeps its name).
        for b in &stash.bound_channels {
            ensure_channel_named(
                &state,
                &b.channel_id,
                &b.channel_id,
                &format!(
                    "auto-registered at install — {}'s `{}` slot ({})",
                    stash.label,
                    b.slot,
                    b.kind.as_str()
                ),
            )
            .await;
        }
        // #663 — the endpoint actors this batch registered: ack their
        // rendezvous rows and complete the device side (the gateway proves
        // its binding + gets its messaging row; the console persists itself).
        let enrolled = complete_pending_enrollments(&state, &stash.enrollments).await;
        // The gateway now exists as an actor: the messaging feeds it relays
        // need its outbound subscription to know the app's alias — the reach
        // write below does that through its admin surface.
        // Audience → each allowed contact's `reach` gains the app's alias.
        let reach = apply_reach(&state, &stash.label, &stash.audience, true).await;
        // The gate learns WHERE the app listens (`alias → channel`).
        let app_feeds = apply_app_feeds(&state, &stash.label, &stash.bound_channels, true).await;
        // The anchor: the sealed document, verbatim, into the app's own namespace.
        let context_storage = match &stash.context_seal {
            Some(seal) => {
                match crate::ui_bridge::context_doc_store(
                    &state,
                    &row.memory_ns,
                    &seal.context_doc,
                    seal.context_version,
                )
                .await
                {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        tracing::warn!(label = %stash.label, "anchor: context document store FAILED (the seal IS on chain) — {e}");
                        format!("failed: {e}")
                    }
                }
            }
            None => {
                "unsealed: the broker carried no seal (no audit contract on this stack)".to_string()
            }
        };
        installed.push(serde_json::json!({
            "label": stash.label,
            "template_id": stash.template_id,
            "actor_omni": actor_omni,
            "registry_storage": storage,
            "reach": reach,
            "app_feeds": app_feeds,
            "enrolled": enrolled,
            "anchor": row.anchor,
            "context_storage": context_storage,
        }));
    }
    invalidate_fleet_sync(&state);
    let mut out = parsed.unwrap_or_else(|| serde_json::json!({ "ok": true }));
    out["installed"] = serde_json::json!(installed);
    (StatusCode::OK, Json(out)).into_response()
}

/// Add (or drop) `alias` on every bound contact whose tier is in the slot
/// audience — through the gateway's admin surface (the registry's ONE
/// writer), then snapshot the registry to the Config doc. Best-effort, loud.
async fn apply_reach(
    state: &UiBridgeState,
    alias: &str,
    audience: &[SlotAudience],
    add: bool,
) -> serde_json::Value {
    let tiers: Vec<ContactTier> = audience.iter().flat_map(|a| a.tiers.clone()).collect();
    if tiers.is_empty() && add {
        return serde_json::json!({ "updated": 0, "skipped": "no messaging audience" });
    }
    let contacts = match gateway_admin_call(
        state,
        reqwest::Method::GET,
        "/v1/gateway/admin/contacts",
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(alias, "#664 reach: contact gate unavailable — {e}");
            return serde_json::json!({ "updated": 0, "skipped": e });
        }
    };
    let summaries: Vec<ContactSummary> = contacts
        .get("contacts")
        .and_then(|c| serde_json::from_value(c.clone()).ok())
        .unwrap_or_default();
    let mut updated = 0usize;
    for c in summaries {
        let allowed = tiers.contains(&c.tier);
        let has = c.reach.iter().any(|r| r.eq_ignore_ascii_case(alias));
        let next: Option<Vec<String>> = match (add, allowed, has) {
            (true, true, false) => {
                let mut r = c.reach.clone();
                r.push(alias.to_string());
                Some(r)
            }
            (false, _, true) => Some(
                c.reach
                    .iter()
                    .filter(|r| !r.eq_ignore_ascii_case(alias))
                    .cloned()
                    .collect(),
            ),
            _ => None,
        };
        let Some(reach) = next else { continue };
        match gateway_admin_call(
            state,
            reqwest::Method::POST,
            "/v1/gateway/admin/contacts/update",
            Some(serde_json::json!({ "contact_id": c.contact_id, "reach": reach })),
        )
        .await
        {
            Ok(_) => updated += 1,
            Err(e) => {
                tracing::warn!(contact = %c.contact_id, alias, "#664 reach update failed — {e}")
            }
        }
    }
    if updated > 0 {
        sync_gateway_registry_to_config(state).await;
    }
    serde_json::json!({ "updated": updated })
}

// ── the uninstall ceremony ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AppUninstallBuildRequest {
    #[serde(default)]
    pub resources_kept: bool,
}

/// POST /v1/master/apps/:label/uninstall/build — the archive ceremony, build
/// half, with the endpoint actors' grants minus this app's feeds.
pub async fn app_uninstall_build(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
    Json(req): Json<AppUninstallBuildRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let reg = match ensure_app_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let Some(row) = reg.find(&label).cloned() else {
        return registry_err(
            StatusCode::NOT_FOUND,
            "no installed application with that label",
        );
    };
    if row.status == AppInstanceStatus::Uninstalled {
        return registry_err(StatusCode::CONFLICT, "already uninstalled");
    }
    let endpoint_scopes = endpoint_scopes_for_uninstall(&state, &row.bound_channels).await;
    let body = serde_json::json!({
        "operator_omni": operator_omni,
        "device_key_hash": row.device_key_hash,
        "resources_kept": req.resources_kept,
        "memory_ns": row.memory_ns,
        "endpoint_scopes": endpoint_scopes,
    });
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/agent/archive/build", &j1, &body)
            .await;
    if resp.status().is_success() {
        state.app_uninstall_by_label.write().await.insert(
            row.label.clone(),
            AppUninstallStash {
                resources_kept: req.resources_kept,
            },
        );
        if let Some(mut built) = parsed {
            built["endpoint_scopes"] = serde_json::json!(endpoint_scopes);
            built["label"] = serde_json::json!(row.label);
            return (StatusCode::OK, Json(built)).into_response();
        }
    }
    resp
}

/// POST /v1/master/apps/:label/uninstall/submit — the archive ceremony, submit
/// half: the #427 archive core (manifest row archived) plus the registry row
/// closed and the contacts' `reach` aliases dropped.
pub async fn app_uninstall_submit(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let (resp, parsed) = crate::ui_bridge::archive_submit_core(&state, body).await;
    if !resp.status().is_success() {
        return resp;
    }
    let stash = state.app_uninstall_by_label.write().await.remove(&label);
    let archived_hashes: Vec<String> = parsed
        .as_ref()
        .and_then(|v| v.pointer("/ceremony/archived"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("device_key_hash").and_then(|d| d.as_str()))
                .map(|s| s.to_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let mut closed = serde_json::json!({ "label": label, "closed": false });
    if let Ok(mut reg) = ensure_app_registry(&state).await {
        if let Some(row) = reg.apps.iter_mut().find(|a| a.label == label) {
            let matches = archived_hashes.is_empty()
                || archived_hashes
                    .iter()
                    .any(|h| h == &row.device_key_hash.to_lowercase());
            if matches {
                row.status = AppInstanceStatus::Uninstalled;
                row.uninstalled_at = Some(now_unix());
                row.resources_kept = stash.as_ref().map(|s| s.resources_kept);
                let audience: Vec<SlotAudience> = row
                    .bound_channels
                    .iter()
                    .filter(|b| b.kind == ChannelEndpointKind::Messaging)
                    .map(|b| SlotAudience {
                        slot: b.slot.clone(),
                        tiers: ContactTier::household_template().to_vec(),
                    })
                    .collect();
                let reach_aliases = row.reach_aliases.clone();
                let bound_for_gate = row.bound_channels.clone();
                let storage = match persist_app_registry(&state, reg.clone()).await {
                    Ok(s) => s.to_string(),
                    Err(e) => format!("failed: {e}"),
                };
                let mut reach = serde_json::json!({ "updated": 0 });
                for alias in &reach_aliases {
                    reach = apply_reach(&state, alias, &audience, false).await;
                }
                let app_feeds = apply_app_feeds(&state, &label, &bound_for_gate, false).await;
                closed = serde_json::json!({
                    "label": label,
                    "closed": true,
                    "registry_storage": storage,
                    "reach": reach,
                    "app_feeds": app_feeds,
                });
            }
        }
    }
    invalidate_fleet_sync(&state);
    let mut out = parsed.unwrap_or_else(|| serde_json::json!({ "ok": true }));
    out["uninstalled"] = closed;
    (StatusCode::OK, Json(out)).into_response()
}

// ── reads ───────────────────────────────────────────────────────────────────

/// GET /v1/master/apps — the installed list.
pub async fn list_apps(State(state): State<SharedUiBridgeState>) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    match ensure_app_registry(&state).await {
        Ok(reg) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "apps": reg.apps,
                "storage": registry_storage_label(&state),
                "console_device": state.console_device.read().await.as_ref().map(|d| d.actor_omni.clone()),
            })),
        )
            .into_response(),
        Err(e) => registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    }
}

/// The per-app dashboard read (#682): the row, today's activity attributed to
/// the app's actor, the latest card on its display feed, the annotations for
/// the read-only permissions view.
#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppDashboard {
    pub app: AppInstanceRow,
    pub activity: Vec<crate::ui_bridge::ApiAuditEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub card: Option<CardDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub card_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub card_channel_id: Option<String>,
    #[serde(default)]
    pub annotations: Vec<ServiceAnnotation>,
    /// The console's own device actor when enrolled — the actor a card tap is
    /// attributed to; absent = taps publish as the master (transitional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub console_actor_omni: Option<String>,
    /// The most recent `command` events on the display feed (the owner sees
    /// their own taps attributed).
    #[serde(default)]
    #[ts(type = "unknown[]")]
    pub commands: Vec<serde_json::Value>,
    /// `doc` events on the display feed SINCE the latest card that are NOT
    /// cards — an app improvising JSON instead of the card contract (chef
    /// without its skills, 2026-09-19); the console says so instead of
    /// passing a stale card off as current.
    #[serde(default)]
    pub non_card_docs: u32,
    /// The head of the newest such document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub last_doc_preview: Option<String>,
}

/// Poll a feed as the master (the operator's global visibility, D13) and
/// return the raw events after `after`.
pub(crate) async fn master_feed_events(
    state: &UiBridgeState,
    channel_id: &str,
    after: &str,
    wait_seconds: u64,
    tail: Option<u32>,
) -> Result<(Vec<serde_json::Value>, String), String> {
    let (cap, coords) = master_channel_cap(
        state,
        format!("channel-sub:{channel_id}"),
        agentkeys_backend_client::protocol::CapMintOp::ChannelSubscribe,
    )
    .await?;
    let worker = crate::ui_bridge::channel_worker_url(&coords.broker)?;
    // @backend-fixture: channel_poll_body
    let mut body = serde_json::json!({
        "cap": cap,
        "after": after,
        "wait_seconds": wait_seconds.min(25),
    });
    if let Some(tail) = tail {
        body["tail"] = serde_json::json!(tail);
    }
    let resp = reqwest::Client::new()
        .post(format!("{worker}/v1/channel/poll"))
        .timeout(crate::ui_bridge::worker_poll_budget(wait_seconds.min(25)))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("channel worker poll: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("channel worker poll HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("poll parse: {e}"))?;
    let events = v
        .get("events")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let cursor = v
        .get("cursor")
        .and_then(|c| c.as_str())
        .unwrap_or_default()
        .to_string();
    Ok((events, cursor))
}

/// What a display feed's tail holds: the latest CARD (the #670 contract), the
/// recent command events, and — since that card — how many `doc` events were
/// NOT cards plus the head of the newest one. An app that publishes free-form
/// JSON instead of the card contract (chef without its skills, 2026-09-19)
/// used to leave the page on a stale card with no trace of the newer docs.
#[derive(Debug, Default)]
pub(crate) struct DisplayFeedView {
    pub card: Option<(CardDocument, String)>,
    pub commands: Vec<serde_json::Value>,
    pub non_card_docs: u32,
    pub last_doc_preview: Option<String>,
}

/// Fold a display feed's events (oldest first) into a [`DisplayFeedView`] —
/// pure, so the card / non-card accounting is testable.
pub(crate) fn fold_display_feed(events: &[serde_json::Value]) -> DisplayFeedView {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut view = DisplayFeedView::default();
    let mut commands = Vec::new();
    for ev in events {
        let kind = ev.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match kind {
            "doc" => {
                let bytes = ev
                    .get("body")
                    .and_then(|b| b.as_str())
                    .and_then(|b64| STANDARD.decode(b64).ok())
                    .unwrap_or_default();
                match agentkeys_backend_client::protocol::parse_card(&bytes) {
                    Ok(c) => {
                        let id = ev
                            .get("event_id")
                            .and_then(|e| e.as_str())
                            .unwrap_or("")
                            .to_string();
                        view.card = Some((c, id));
                        view.non_card_docs = 0;
                        view.last_doc_preview = None;
                    }
                    Err(_) => {
                        view.non_card_docs += 1;
                        let text = String::from_utf8_lossy(&bytes);
                        view.last_doc_preview = Some(text.chars().take(160).collect::<String>());
                    }
                }
            }
            "command" => {
                let mut row = ev.clone();
                if let Some(b64) = ev.get("body").and_then(|b| b.as_str()) {
                    if let Ok(bytes) = STANDARD.decode(b64) {
                        if let Ok(cmd) =
                            agentkeys_backend_client::protocol::parse_card_command(&bytes)
                        {
                            row["command"] = serde_json::to_value(cmd).unwrap_or_default();
                        }
                    }
                }
                commands.push(row);
            }
            _ => {}
        }
    }
    let keep = commands.len().saturating_sub(20);
    view.commands = commands.split_off(keep);
    view
}

/// The latest card on a display feed + the recent command events — read as a
/// bounded TAIL of the feed (the worker decrypts only that much).
async fn latest_card(state: &UiBridgeState, channel_id: &str) -> DisplayFeedView {
    let Ok((events, _)) = master_feed_events(
        state,
        channel_id,
        "",
        0,
        Some(crate::ui_bridge::display_feed_tail()),
    )
    .await
    else {
        return DisplayFeedView::default();
    };
    fold_display_feed(&events)
}

#[cfg(test)]
mod display_feed_tests {
    use super::fold_display_feed;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn doc(id: &str, body: &str) -> serde_json::Value {
        serde_json::json!({ "kind": "doc", "event_id": id, "body": STANDARD.encode(body.as_bytes()) })
    }

    #[test]
    fn a_card_wins_and_later_non_card_docs_are_counted_with_a_preview() {
        let card =
            r#"{"card":1,"title":"Chef · tonight","subtitle":"09-18","sections":[],"actions":[]}"#;
        let events = vec![
            doc("e1", card),
            serde_json::json!({ "kind": "lifecycle", "event_id": "e2", "body": "" }),
            doc("e3", r#"{"type":"meal-plan","title":"Today's Meal Plan"}"#),
            doc("e4", r#"{"title":"今日晚餐计划","content":"番茄炒蛋"}"#),
        ];
        let view = fold_display_feed(&events);
        assert_eq!(view.card.as_ref().map(|(_, id)| id.as_str()), Some("e1"));
        assert_eq!(view.non_card_docs, 2);
        assert!(view
            .last_doc_preview
            .as_deref()
            .unwrap()
            .starts_with(r#"{"title":"今日晚餐计划""#));
        // A newer valid card resets the accounting.
        let mut with_new_card = events.clone();
        with_new_card.push(doc("e5", card));
        let view = fold_display_feed(&with_new_card);
        assert_eq!(view.card.as_ref().map(|(_, id)| id.as_str()), Some("e5"));
        assert_eq!(view.non_card_docs, 0);
        assert!(view.last_doc_preview.is_none());
    }
}

/// GET /v1/master/apps/:label — the dashboard.
pub async fn app_dashboard(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let reg = match ensure_app_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let Some(row) = reg.find(&label).cloned() else {
        return registry_err(
            StatusCode::NOT_FOUND,
            "no installed application with that label",
        );
    };
    let norm = |o: &str| o.trim().trim_start_matches("0x").to_lowercase();
    let want = norm(&row.actor_omni);
    let activity: Vec<crate::ui_bridge::ApiAuditEvent> = state
        .audit
        .read()
        .await
        .iter()
        .filter(|e| {
            e.actor == row.label
                || norm(&e.actor_id) == want
                || (e.actor_id.len() >= 12 && want.starts_with(&norm(&e.actor_id)))
        })
        .cloned()
        .collect();
    let display = row
        .bound_channels
        .iter()
        .find(|b| b.kind == ChannelEndpointKind::Display)
        .cloned();
    let DisplayFeedView {
        card,
        commands,
        non_card_docs,
        last_doc_preview,
    } = match &display {
        Some(d) if row.status != AppInstanceStatus::Uninstalled => {
            latest_card(&state, &d.channel_id).await
        }
        _ => DisplayFeedView::default(),
    };
    let annotations: Vec<ServiceAnnotation> = annotations_for(&row);
    (
        StatusCode::OK,
        Json(AppDashboard {
            app: row,
            activity,
            card: card.as_ref().map(|(c, _)| c.clone()),
            card_event_id: card.as_ref().map(|(_, id)| id.clone()),
            card_channel_id: display.map(|d| d.channel_id),
            annotations,
            console_actor_omni: state
                .console_device
                .read()
                .await
                .as_ref()
                .map(|d| d.actor_omni.clone()),
            commands,
            non_card_docs,
            last_doc_preview,
        }),
    )
        .into_response()
}

/// Re-derive the sheet annotations for an installed row from its services +
/// bindings (the broker's build response carried them; the row stores the
/// facts they derive from).
fn annotations_for(row: &AppInstanceRow) -> Vec<ServiceAnnotation> {
    row.services
        .iter()
        .map(|s| {
            let lower = s.to_ascii_lowercase();
            let (role, slot, resource, sensitivity) =
                if lower.contains(&format!(":{}", row.chat_channel_id)) {
                    ("opchat", None, None, None)
                } else if let Some(b) = row
                    .bound_channels
                    .iter()
                    .find(|b| lower.ends_with(&format!(":{}", b.channel_id)))
                {
                    ("slot", Some(b.slot.clone()), None, None)
                } else if lower == format!("knowledge:{}", row.memory_ns) {
                    ("own-knowledge", None, None, None)
                } else if lower == format!("proposal:{}", row.memory_ns) {
                    ("own-proposals", None, None, None)
                } else if let Some(rb) = row
                    .bindings
                    .resources
                    .iter()
                    .find(|rb| lower == format!("knowledge:{}", rb.ns))
                {
                    (
                        "resource",
                        None,
                        Some(rb.name.clone()),
                        Some(rb.sensitivity),
                    )
                } else if lower.starts_with("tool:") {
                    ("tool", None, None, None)
                } else if lower.starts_with("plugin:") {
                    ("plugin", None, None, None)
                } else {
                    ("other", None, None, None)
                };
            ServiceAnnotation {
                service: s.clone(),
                role: role.to_string(),
                slot,
                resource,
                sensitivity,
            }
        })
        .collect()
}

// ── the card-action command ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AppCommandRequest {
    /// The display feed (defaults to the app's first display slot).
    #[serde(default)]
    pub channel_id: Option<String>,
    pub action: String,
    pub command: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default)]
    pub card_updated_at: u64,
}

/// POST /v1/master/apps/:label/command — a card-action tap from the console:
/// a `command` event on the app's display feed, published by the console's
/// OWN device actor when enrolled (#541 / #670), else by the master
/// (transitional — the response says which).
pub async fn app_command(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
    Json(req): Json<AppCommandRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let reg = match ensure_app_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let Some(row) = reg.find(&label).cloned() else {
        return registry_err(
            StatusCode::NOT_FOUND,
            "no installed application with that label",
        );
    };
    let channel_id = match req.channel_id.clone().filter(|c| !c.trim().is_empty()) {
        Some(c) => c,
        None => match row
            .bound_channels
            .iter()
            .find(|b| b.kind == ChannelEndpointKind::Display)
        {
            Some(b) => b.channel_id.clone(),
            None => {
                return registry_err(
                    StatusCode::BAD_REQUEST,
                    "the application has no display slot",
                )
            }
        },
    };
    if !valid_channel_id(&channel_id)
        || req.action.trim().is_empty()
        || req.command.trim().is_empty()
    {
        return registry_err(
            StatusCode::BAD_REQUEST,
            "channel_id, action and command are required",
        );
    }
    let cmd = CardCommand {
        card: agentkeys_backend_client::protocol::CARD_SCHEMA,
        action: req.action.clone(),
        command: req.command.clone(),
        args: req.args.clone(),
        card_updated_at: req.card_updated_at,
    };
    let body = serde_json::to_vec(&cmd).unwrap_or_default();
    match crate::console_device::publish_as_console_or_master(&state, &channel_id, "command", &body)
        .await
    {
        Ok(receipt) => (StatusCode::OK, Json(receipt)).into_response(),
        Err(e) => registry_err(StatusCode::BAD_GATEWAY, &e),
    }
}

// ── resources ───────────────────────────────────────────────────────────────

/// GET /v1/master/resources — the curated items.
pub async fn list_resources(State(state): State<SharedUiBridgeState>) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    match ensure_resource_registry(&state).await {
        Ok(reg) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "items": reg.items,
                "storage": registry_storage_label(&state),
            })),
        )
            .into_response(),
        Err(e) => registry_err(StatusCode::BAD_GATEWAY, &format!("resource registry: {e}")),
    }
}

#[derive(Debug, Deserialize)]
pub struct ResourceAddRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_zh: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    pub ns: String,
    /// The item's content (UTF-8 text / markdown / JSON).
    pub body: String,
    /// D-K5 — the `content_hash` of the row this edit started from; a
    /// different current row is refused with 409 `stale_base` (a diff, never
    /// a silent overwrite). Absent for a new item or a deliberate overwrite.
    #[serde(default)]
    pub base_content_hash: Option<String>,
}

/// Upload caps: 5 MiB of file bytes (a curated profile / document / dataset —
/// the text an app reads is EXTRACTED from it), 8 MiB of JSON body (base64 ×4/3
/// + framing) on the route's body limit.
pub(crate) const RESOURCE_UPLOAD_MAX_BYTES: usize = 5 * 1024 * 1024;
pub(crate) const RESOURCE_UPLOAD_BODY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// POST /v1/master/resources/upload — curate one resource item FROM A FILE:
/// the text is extracted (plain text / markdown / CSV / JSON as UTF-8, PDF via
/// `pdf-extract`, an image as a caption), planted like a pasted item, and the
/// raw bytes are kept as the keyed object `files/<id>` in the same namespace
/// (durable planes only). Re-uploading an id bumps its version and REPLACES the
/// previous text.
#[derive(Debug, Deserialize)]
pub struct ResourceUploadRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_zh: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    pub ns: String,
    pub filename: String,
    #[serde(default)]
    pub content_type: String,
    /// The file bytes, standard base64.
    pub content_b64: String,
    /// D-K5 — see `ResourceAddRequest::base_content_hash`.
    #[serde(default)]
    pub base_content_hash: Option<String>,
}

/// What an app can read out of an uploaded file: its TEXT. Plain text, markdown,
/// CSV, TSV, JSON and YAML are the bytes as UTF-8; a PDF goes through
/// `pdf-extract`; an image carries no text — its entry is a caption pointing
/// at the raw object (kind `gallery`). Anything else is refused (415) rather
/// than stored opaque. Returns the text and how it was obtained.
fn extract_resource_text(
    filename: &str,
    content_type: &str,
    bytes: &[u8],
) -> Result<(String, &'static str), (StatusCode, String)> {
    let lower = filename.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("").to_string();
    let ct = content_type.to_ascii_lowercase();
    let text_like = ct.starts_with("text/")
        || ct == "application/json"
        || ct == "application/csv"
        || ct == "application/x-yaml"
        || matches!(
            ext.as_str(),
            "txt" | "md" | "markdown" | "csv" | "tsv" | "json" | "yaml" | "yml"
        );
    if text_like {
        return Ok((String::from_utf8_lossy(bytes).into_owned(), "text"));
    }
    if ct == "application/pdf" || ext == "pdf" {
        return pdf_extract::extract_text_from_mem(bytes)
            .map(|t| (t, "pdf"))
            .map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("pdf text extraction failed for {filename}: {e}"),
                )
            });
    }
    if ct.starts_with("image/") || matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
        let label = if ct.is_empty() { "image" } else { ct.as_str() };
        return Ok((
            format!("[image] {filename} ({} bytes, {label})", bytes.len()),
            "image",
        ));
    }
    Err((
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        format!(
            "unsupported file type {ct:?} ({filename}) — text, markdown, CSV, JSON, PDF or an image"
        ),
    ))
}

/// Everything a curated item needs once validated (shared by add + upload).
struct ResourceCurate {
    id: String,
    ns: String,
    name: String,
    name_zh: String,
    kind: ResourceKind,
    tags: Vec<String>,
    sensitivity: Sensitivity,
    body: String,
    /// `(filename, content_type, raw bytes)` for an upload.
    provenance: Option<(String, String, Vec<u8>)>,
    base_content_hash: Option<String>,
}

fn validate_resource_head(
    id: &str,
    ns: &str,
    name: &str,
) -> Result<(String, String, String), (StatusCode, &'static str)> {
    let id = id.trim().to_lowercase();
    if !agentkeys_backend_client::protocol::is_valid_resource_id(&id) {
        return Err((
            StatusCode::BAD_REQUEST,
            "resource id must be 1-48 chars of [a-z0-9-], not starting/ending with '-'",
        ));
    }
    let ns = ns.trim().to_string();
    if ns.is_empty() || ns.contains(['/', '\\', '*', '?', ' ']) || ns.contains("..") {
        return Err((StatusCode::BAD_REQUEST, "ns must be a bare namespace name"));
    }
    if ns == agentkeys_backend_client::protocol::PERSONA_NAMESPACE {
        return Err((StatusCode::BAD_REQUEST, "the persona namespace is reserved"));
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required"));
    }
    Ok((id, ns, name))
}

/// Plant + register one curated item. The previous entry under the same key is
/// dropped FIRST so the body is replaced, never accumulated; an upload's raw
/// bytes go to `files/<id>` when a durable memory plane is wired.
async fn curate_resource(
    state: &SharedUiBridgeState,
    c: ResourceCurate,
) -> axum::response::Response {
    let today = {
        let secs = now_unix() as i64;
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    };
    let bytes = c.body.len() as u64;
    let preview: String = c.body.chars().take(120).collect();
    let mut reg = match ensure_resource_registry(state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("resource registry: {e}")),
    };
    // D-K5 — an edit names the row it started from; if the item changed
    // meanwhile (another tab, another device) the save is refused with the
    // current hash so the console shows the diff — never a silent overwrite.
    if let Some(base) = c.base_content_hash.as_deref() {
        let current = reg.find(&c.id).map(|r| r.content_hash.clone());
        if current.as_deref() != Some(base) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "stale_base",
                    "id": c.id,
                    "current_content_hash": current,
                    "current": reg.find(&c.id),
                })),
            )
                .into_response();
        }
    }
    let next_version = reg.find(&c.id).map(|i| i.version + 1).unwrap_or(1);
    if let Err((status, reason)) = resource_entry_remove(state, &c.ns, &c.id, "edit").await {
        return (status, Json(serde_json::json!({ "error": reason }))).into_response();
    }
    let entry = agentkeys_backend_client::protocol::web_api::ApiMemoryEntry {
        ns: c.ns.clone(),
        key: c.id.clone(),
        title: c.name.clone(),
        bytes,
        version: format!("v{next_version}"),
        updated: today,
        preview,
        body: c.body.clone(),
        content_hash: String::new(),
        kind: agentkeys_backend_client::protocol::ContextKind::Resource,
    };
    let plant = plant_master_memory_inner(
        state,
        agentkeys_backend_client::protocol::web_api::MasterMemoryPlantRequest {
            entries: vec![entry],
        },
    )
    .await;
    if let Err((status, reason)) = plant {
        return (status, Json(serde_json::json!({ "error": reason }))).into_response();
    }
    let (filename, content_type, raw_object_key, raw_bytes, raw_stored) = match &c.provenance {
        Some((f, ct, raw)) => {
            let key = format!("files/{}", c.id);
            match resource_object_put(state, &c.ns, &key, raw).await {
                Ok(true) => (f.clone(), ct.clone(), key, raw.len() as u64, Some(true)),
                Ok(false) => (f.clone(), ct.clone(), String::new(), raw.len() as u64, Some(false)),
                Err((status, reason)) => {
                    return (
                        status,
                        Json(serde_json::json!({
                            "error": format!("raw file store failed (the extracted text IS planted in knowledge:{}): {reason}", c.ns)
                        })),
                    )
                        .into_response()
                }
            }
        }
        None => (String::new(), String::new(), String::new(), 0, None),
    };
    let content_hash = crate::ui_bridge::content_hash_for(&c.ns, &c.id, &c.body);
    let version = reg.upsert(ResourceItemRow {
        id: c.id.clone(),
        name: c.name,
        name_zh: c.name_zh,
        ns: c.ns.clone(),
        object_key: c.id.clone(),
        kind: c.kind,
        tags: c
            .tags
            .iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect(),
        sensitivity: c.sensitivity,
        version: 0,
        content_hash,
        bytes,
        created_at: now_unix(),
        updated_at: now_unix(),
        filename,
        content_type,
        raw_object_key,
        raw_bytes,
    });
    let item = reg.find(&c.id).cloned();
    match persist_resource_registry(state, reg).await {
        Ok(storage) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "item": item,
                "version": version,
                "storage": storage,
                "extracted_bytes": bytes,
                "raw_stored": raw_stored,
            })),
        )
            .into_response(),
        Err(e) => registry_err(
            StatusCode::BAD_GATEWAY,
            &format!(
                "resource registry store failed (the item IS planted in knowledge:{}): {e}",
                c.ns
            ),
        ),
    }
}

/// POST /v1/master/resources/add — curate one resource item: plant it as a
/// `resource`-kind canonical memory entry in its namespace (the SAME plant
/// path knowledge uses — nothing enters canonical except through the master),
/// then register it. Re-adding an id bumps its version and replaces the body.
pub async fn add_resource(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ResourceAddRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let (id, ns, name) = match validate_resource_head(&req.id, &req.ns, &req.name) {
        Ok(v) => v,
        Err((status, msg)) => return registry_err(status, msg),
    };
    if req.body.trim().is_empty() {
        return registry_err(StatusCode::BAD_REQUEST, "body is empty");
    }
    curate_resource(
        &state,
        ResourceCurate {
            id,
            ns,
            name,
            name_zh: req.name_zh.trim().to_string(),
            kind: req.kind,
            tags: req.tags,
            sensitivity: req.sensitivity,
            body: req.body,
            provenance: None,
            base_content_hash: req.base_content_hash.clone(),
        },
    )
    .await
}

pub async fn upload_resource(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ResourceUploadRequest>,
) -> axum::response::Response {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let (id, ns, name) = match validate_resource_head(&req.id, &req.ns, &req.name) {
        Ok(v) => v,
        Err((status, msg)) => return registry_err(status, msg),
    };
    let filename = req.filename.trim().to_string();
    if filename.is_empty() {
        return registry_err(StatusCode::BAD_REQUEST, "filename is required");
    }
    let bytes = match STANDARD.decode(req.content_b64.trim()) {
        Ok(b) => b,
        Err(_) => return registry_err(StatusCode::BAD_REQUEST, "content_b64 is not valid base64"),
    };
    if bytes.is_empty() {
        return registry_err(StatusCode::BAD_REQUEST, "the file is empty");
    }
    if bytes.len() > RESOURCE_UPLOAD_MAX_BYTES {
        return registry_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "file too large: {} bytes exceeds the {RESOURCE_UPLOAD_MAX_BYTES}-byte cap",
                bytes.len()
            ),
        );
    }
    let (text, how) = match extract_resource_text(&filename, &req.content_type, &bytes) {
        Ok(v) => v,
        Err((status, reason)) => return registry_err(status, &reason),
    };
    if text.trim().is_empty() {
        return registry_err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("no text could be extracted from {filename} — an app would read nothing"),
        );
    }
    if how == "image" && req.kind != ResourceKind::Gallery {
        return registry_err(
            StatusCode::BAD_REQUEST,
            "an image is a `gallery` item (it carries no text for the other kinds)",
        );
    }
    curate_resource(
        &state,
        ResourceCurate {
            id,
            ns,
            name,
            name_zh: req.name_zh.trim().to_string(),
            kind: req.kind,
            tags: req.tags,
            sensitivity: req.sensitivity,
            body: text,
            provenance: Some((filename, req.content_type.trim().to_string(), bytes)),
            base_content_hash: req.base_content_hash.clone(),
        },
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct ResourceRemoveRequest {
    pub id: String,
    /// Remove even while a live app is bound to the item (its `knowledge:<ns>`
    /// grant stays; the entry it read is gone).
    #[serde(default)]
    pub force: bool,
}

/// POST /v1/master/resources/remove — unregister a curated item and drop its
/// entry from `knowledge:<ns>`. Refused (409 `resource_in_use`) while a live app
/// is bound to it unless `force`. Idempotent: an unknown id is `ok` with
/// `removed:false`. A raw file object stays until the namespace is torn down
/// (the memory worker has no keyed delete).
pub async fn remove_resource(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ResourceRemoveRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let id = req.id.trim().to_lowercase();
    let mut reg = match ensure_resource_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("resource registry: {e}")),
    };
    let Some(row) = reg.find(&id).cloned() else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "removed": false })),
        )
            .into_response();
    };
    if !req.force {
        if let Ok(apps) = ensure_app_registry(&state).await {
            let users: Vec<String> = apps
                .live()
                .filter(|a| a.bindings.resources.iter().any(|rb| rb.item_id == id))
                .map(|a| a.label.clone())
                .collect();
            if !users.is_empty() {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "ok": false,
                        "reason": "resource_in_use",
                        "detail": format!("bound by {}; uninstall them or pass force", users.join(", ")),
                        "apps": users,
                    })),
                )
                    .into_response();
            }
        }
    }
    if let Err((status, reason)) = resource_entry_remove(&state, &row.ns, &row.id, "remove").await {
        return (status, Json(serde_json::json!({ "error": reason }))).into_response();
    }
    reg.remove(&id);
    match persist_resource_registry(&state, reg).await {
        Ok(storage) => (
            StatusCode::OK,
            Json(
                serde_json::json!({ "ok": true, "removed": true, "item": row, "storage": storage }),
            ),
        )
            .into_response(),
        Err(e) => registry_err(
            StatusCode::BAD_GATEWAY,
            &format!(
                "resource registry store failed (the entry IS gone from knowledge:{}): {e}",
                row.ns
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> AppInstanceRow {
        AppInstanceRow {
            label: "chef".into(),
            template_id: "chef".into(),
            template_version: "1.0.0".into(),
            template_schema: 1,
            actor_omni: "0xabc".into(),
            device_key_hash: "0xdef".into(),
            memory_ns: "app-chef".into(),
            chat_channel_id: "opchat-chef".into(),
            bindings: AppInstallBindings {
                resources: vec![agentkeys_backend_client::protocol::ResourceBinding {
                    name: "gene-report".into(),
                    item_id: "gene".into(),
                    ns: "household-health".into(),
                    kind: ResourceKind::Document,
                    sensitivity: Sensitivity::Sensitive,
                }],
                ..Default::default()
            },
            bound_channels: vec![BoundChannel {
                slot: "kitchen_screen".into(),
                kind: ChannelEndpointKind::Display,
                direction: agentkeys_backend_client::protocol::SlotDirection::Pub,
                channel_id: "kitchen-display".into(),
                event_kinds: vec![],
                endpoint_actor_omni: None,
            }],
            services: vec![
                "channel-pub:opchat-chef".into(),
                "knowledge:app-chef".into(),
                "channel-pub:kitchen-display".into(),
                "knowledge:household-health".into(),
                "proposal:app-chef".into(),
                "tool:web".into(),
                "plugin:openviking".into(),
            ],
            availability: Availability::AlwaysOn,
            status: AppInstanceStatus::Installed,
            installed_at: 1,
            uninstalled_at: None,
            resources_kept: None,
            reach_aliases: vec![],
            anchor: None,
        }
    }

    #[test]
    fn annotations_re_derive_the_sheet_sections_from_the_row() {
        let a = annotations_for(&row());
        let role = |svc: &str| {
            a.iter()
                .find(|x| x.service == svc)
                .map(|x| x.role.clone())
                .unwrap()
        };
        assert_eq!(role("channel-pub:opchat-chef"), "opchat");
        assert_eq!(role("knowledge:app-chef"), "own-knowledge");
        assert_eq!(role("channel-pub:kitchen-display"), "slot");
        assert_eq!(role("proposal:app-chef"), "own-proposals");
        assert_eq!(role("tool:web"), "tool");
        assert_eq!(role("plugin:openviking"), "plugin");
        let gene = a
            .iter()
            .find(|x| x.service == "knowledge:household-health")
            .unwrap();
        assert_eq!(gene.role, "resource");
        assert_eq!(gene.sensitivity, Some(Sensitivity::Sensitive));
        assert_eq!(gene.resource.as_deref(), Some("gene-report"));
    }
}

/// Handler-level tests against a MOCK broker (an ephemeral axum server serving
/// the real `presets/conformance` bundle + canned spawn build/submit answers).
/// No config worker, no channel worker, no gateway: those legs degrade the way
/// the handlers document (cached registry, `reach` skipped) — the CI phase-8
/// suite proves them live; this pins the compile/stash/submit/list contract.
/// `POST /v1/master/resources/retype` body (D-K2, `plan/knowledge-repository.md`
/// §5): the type is metadata, so a retype changes the registry row and nothing
/// else — no new version, no re-plant. Tags and the tier are optional.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceRetypeRequest {
    pub id: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub sensitivity: Option<Sensitivity>,
}

pub async fn retype_resource(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ResourceRetypeRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let id = req.id.trim().to_lowercase();
    let mut reg = match ensure_resource_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("resource registry: {e}")),
    };
    let tags = req.tags.map(|t| {
        t.iter()
            .map(|x| x.trim().to_lowercase())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });
    let Some(item) = reg
        .retype(&id, req.kind, tags, req.sensitivity, now_unix())
        .cloned()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "resource_not_found", "id": id })),
        )
            .into_response();
    };
    match persist_resource_registry(&state, reg).await {
        Ok(storage) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "item": item, "storage": storage })),
        )
            .into_response(),
        Err(e) => registry_err(
            StatusCode::BAD_GATEWAY,
            &format!("resource registry store failed: {e}"),
        ),
    }
}

/// D-K2 — every console-created entry is typed: a plain `knowledge`-kind entry
/// the console plants, or merges from a proposal, gets a `note` row under its
/// own key, so the install wizard can bind it like any other item (retyping it
/// on the way). An entry whose key is not a valid item id, or that already has
/// a row (typed by the owner), is left alone. Returns the rows added.
pub(crate) async fn register_note_rows(
    state: &SharedUiBridgeState,
    entries: &[crate::ui_bridge::ApiMemoryEntry],
) -> Result<usize, String> {
    let mut reg = ensure_resource_registry(state).await?;
    let mut added = 0usize;
    let mut refreshed = 0usize;
    for e in entries {
        if e.kind != agentkeys_backend_client::protocol::ContextKind::Knowledge
            || !agentkeys_backend_client::protocol::is_valid_resource_id(&e.key)
        {
            continue;
        }
        let hash = crate::ui_bridge::content_hash_for(&e.ns, &e.key, &e.body);
        if let Some(row) = reg.items.iter_mut().find(|r| r.id == e.key) {
            // D-K5 — identity = key: the plant REPLACED this row's entry; the
            // row keeps its type and follows the content (next version).
            if row.ns == e.ns && row.content_hash != hash {
                row.content_hash = hash;
                row.bytes = e.body.len() as u64;
                row.updated_at = now_unix();
                row.version += 1;
                refreshed += 1;
            }
            continue;
        }
        let now = now_unix();
        reg.upsert(ResourceItemRow {
            id: e.key.clone(),
            name: if e.title.trim().is_empty() {
                e.key.clone()
            } else {
                e.title.clone()
            },
            name_zh: String::new(),
            ns: e.ns.clone(),
            object_key: e.key.clone(),
            kind: ResourceKind::Note,
            tags: Vec::new(),
            sensitivity: Sensitivity::Safe,
            version: 0,
            content_hash: hash,
            bytes: e.body.len() as u64,
            created_at: now,
            updated_at: now,
            filename: String::new(),
            content_type: String::new(),
            raw_object_key: String::new(),
            raw_bytes: 0,
        });
        added += 1;
    }
    if added + refreshed > 0 {
        persist_resource_registry(state, reg).await?;
    }
    Ok(added + refreshed)
}

#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::ui_bridge::{build_state, OnboardingSession, SharedUiBridgeState};
    use agentkeys_backend_client::protocol::{PresetSkillDoc, SlotBinding};
    use axum::extract::{Path, State};
    use axum::routing::{get, post};
    use axum::{Json, Router};

    const DKH: &str = "0xabababababababababababababababababababababababababababababababab";
    const ACTOR: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    fn conformance_bundle() -> serde_json::Value {
        let manifest: PresetSummary =
            serde_json::from_str(include_str!("../../../presets/conformance/preset.json"))
                .expect("the conformance manifest parses as a PresetSummary");
        let bundle = PresetBundle {
            manifest,
            soul_md: include_str!("../../../presets/conformance/SOUL.md").to_string(),
            skills: vec![PresetSkillDoc {
                filename: "perception.md".into(),
                content: include_str!("../../../presets/conformance/skills/perception.md").into(),
            }],
            knowledge: vec![PresetSkillDoc {
                filename: "probe.md".into(),
                content: include_str!("../../../presets/conformance/knowledge/probe.md").into(),
            }],
        };
        serde_json::to_value(&bundle).unwrap()
    }

    async fn mock_broker() -> String {
        let bundle = conformance_bundle();
        let app = Router::new()
            .route(
                "/v1/presets/:id",
                get(move |Path(id): Path<String>| {
                    let b = bundle.clone();
                    async move {
                        if id == "conformance" {
                            (StatusCode::OK, Json(b)).into_response()
                        } else {
                            (
                                StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "error": "unknown preset" })),
                            )
                                .into_response()
                        }
                    }
                }),
            )
            .route(
                "/v1/agent/spawn/build",
                post(|Json(req): Json<serde_json::Value>| async move {
                    Json(serde_json::json!({
                        "device_key_hash": DKH,
                        "label": req["label"],
                        "preset_id": req["preset_id"],
                        "user_op": { "sender": "0x0", "nonce": "0x0" },
                        "endpoint_scopes": req["endpoint_scopes"],
                    }))
                }),
            )
            .route(
                "/v1/agent/spawn/submit",
                post(|| async {
                    Json(serde_json::json!({
                        "ok": true,
                        "tx_hash": "0x9b10",
                        "ceremony": { "spawned": [ {
                            "device_key_hash": DKH,
                            "actor_omni": ACTOR,
                            "memory_ns": "app-probe",
                            "chat_channel_id": "opchat-probe",
                            "label": "probe",
                            "tx_hash": "0x9b10"
                        } ] }
                    }))
                }),
            )
            .route(
                "/v1/agent/archive/build",
                post(|| async {
                    Json(serde_json::json!({ "ok": true, "user_op": { "sender": "0x0" } }))
                }),
            )
            .route(
                "/v1/agent/archive/submit",
                post(|| async {
                    Json(serde_json::json!({
                        "ok": true,
                        "tx_hash": "0x9b11",
                        "ceremony": { "archived": [ { "device_key_hash": DKH, "actor_omni": ACTOR } ] }
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn state_with_session(broker: Option<String>) -> SharedUiBridgeState {
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            broker,
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
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "owner@example.test".into(),
            omni: "0xabababababababababababababababababababababababababababababababab".into(),
            j1: "test-j1".into(),
            wallet: "0x1111111111111111111111111111111111111111".into(),
            identity_only_reason: None,
        });
        state
    }

    async fn read(resp: axum::response::Response) -> (u16, serde_json::Value) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn install_req(label: &str) -> AppInstallBuildRequest {
        AppInstallBuildRequest {
            template_id: "conformance".into(),
            label: label.into(),
            bindings: AppInstallBindings {
                slots: vec![
                    SlotBinding {
                        slot: "probe_chat".into(),
                        channel_id: "conf-chat".into(),
                        endpoint_actor_omni: None,
                    },
                    SlotBinding {
                        slot: "probe_display".into(),
                        channel_id: "conf-display".into(),
                        endpoint_actor_omni: None,
                    },
                ],
                resources: Vec::new(),
                audience: vec![SlotAudience {
                    slot: "probe_chat".into(),
                    tiers: vec![ContactTier::Owner],
                }],
                tz_offset_minutes: 480,
            },
            memory_ns: None,
            memory_inherited: false,
            enroll_endpoints: false,
        }
    }

    #[tokio::test]
    async fn install_build_compiles_the_conformance_sheet_and_stashes_it() {
        let broker = mock_broker().await;
        let state = state_with_session(Some(broker)).await;
        let (status, body) =
            read(app_install_build(State(state.clone()), Json(install_req("probe"))).await).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["template_id"], "conformance");
        let services: Vec<String> =
            serde_json::from_value(body["build"]["services"].clone()).unwrap_or_default();
        let compiled: Vec<String> = serde_json::from_value(body["endpoint_scopes"].clone())
            .map(|_: Vec<serde_json::Value>| Vec::new())
            .unwrap_or_default();
        let _ = compiled;
        assert!(body["endpoint_scopes"].is_array());
        assert!(body["endpoint_enrollments"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true));
        assert!(body["manifest"]["id"] == "conformance");
        // The stash carries the compiled grant set for the submit's registry row.
        let stash = state.app_install_by_dkh.read().await;
        let st = stash
            .get(DKH)
            .expect("install stash keyed by the build's device_key_hash");
        assert_eq!(st.label, "probe");
        assert!(
            st.services.iter().any(|s| s == "tool:schedule"),
            "{:?}",
            st.services
        );
        assert!(
            st.services.iter().any(|s| s == "channel-sub:conf-chat"),
            "{:?}",
            st.services
        );
        assert_eq!(st.bound_channels.len(), 2);
        let _ = services;
    }

    #[tokio::test]
    async fn install_build_refuses_bad_input_before_touching_the_broker() {
        let broker = mock_broker().await;
        // No master session ⇒ 403.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some(broker.clone()),
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
        let (status, _) =
            read(app_install_build(State(state), Json(install_req("probe"))).await).await;
        assert_eq!(status, 403);
        let state = state_with_session(Some(broker)).await;
        // A label outside ^[a-z0-9-]{1,32}$ ⇒ 400.
        let (status, _) =
            read(app_install_build(State(state.clone()), Json(install_req("Bad Label!"))).await)
                .await;
        assert_eq!(status, 400);
        // An unknown template ⇒ the broker's 404 surfaces as 502.
        let mut req = install_req("probe");
        req.template_id = "no-such-template".into();
        let (status, _) = read(app_install_build(State(state.clone()), Json(req)).await).await;
        assert_eq!(status, 502);
        // A binding for a slot the manifest does not declare ⇒ 400 template_bindings_invalid.
        let mut req = install_req("probe");
        req.bindings.slots.push(SlotBinding {
            slot: "no_such_slot".into(),
            channel_id: "x".into(),
            endpoint_actor_omni: None,
        });
        let (status, body) = read(app_install_build(State(state.clone()), Json(req)).await).await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"], "template_bindings_invalid");
        // No broker at all ⇒ 503.
        let state = state_with_session(None).await;
        let (status, _) =
            read(app_install_build(State(state), Json(install_req("probe"))).await).await;
        assert_eq!(status, 503);
    }

    #[tokio::test]
    async fn uninstall_submit_closes_the_row_and_resources_validate_before_any_worker() {
        let broker = mock_broker().await;
        let state = state_with_session(Some(broker)).await;
        let (status, _) =
            read(app_install_build(State(state.clone()), Json(install_req("probe"))).await).await;
        assert_eq!(status, 200);
        let (status, _) = read(
            app_install_submit(
                State(state.clone()),
                Json(serde_json::json!({ "device_key_hash": DKH })),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200);
        // The archive submit closes the row (mock broker reports the archived dkh).
        let (status, body) = read(
            app_uninstall_submit(
                State(state.clone()),
                Path("probe".into()),
                Json(serde_json::json!({ "device_key_hash": DKH })),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["uninstalled"]["label"], "probe", "{body}");
        assert_eq!(body["uninstalled"]["closed"], true, "{body}");
        let (_, apps) = read(list_apps(State(state.clone())).await).await;
        let row = apps["apps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["label"] == "probe")
            .expect("row")
            .clone();
        assert_eq!(row["status"], "uninstalled");
        assert!(row["uninstalled_at"].as_u64().is_some());
        // A second uninstall of a closed row is refused.
        let (status, _) = read(
            app_uninstall_build(
                State(state.clone()),
                Path("probe".into()),
                Json(AppUninstallBuildRequest {
                    resources_kept: false,
                }),
            )
            .await,
        )
        .await;
        assert!(status >= 400, "closed rows cannot be archived again");

        // Resources: the empty registry lists (cached — no config worker here) …
        let (status, items) = read(list_resources(State(state.clone())).await).await;
        assert_eq!(status, 200, "{items}");
        assert!(
            items["items"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(false),
            "{items}"
        );
        // … and every malformed add is refused BEFORE the memory plant.
        let base = |id: &str, ns: &str, name: &str, body: &str| ResourceAddRequest {
            id: id.into(),
            name: name.into(),
            name_zh: String::new(),
            kind: ResourceKind::Document,
            tags: vec!["food".into()],
            sensitivity: Sensitivity::Safe,
            ns: ns.into(),
            body: body.into(),
            base_content_hash: None,
        };
        for (req, why) in [
            (base("Bad Id!", "food-prefs", "Food", "x"), "id"),
            (base("food-prefs", "a/b c", "Food", "x"), "ns"),
            (base("food-prefs", "persona", "Food", "x"), "persona ns"),
            (
                base("food-prefs", "food-prefs", "Food", "   "),
                "empty body",
            ),
            (base("food-prefs", "food-prefs", "", "x"), "name"),
        ] {
            let (status, body) = read(add_resource(State(state.clone()), Json(req)).await).await;
            assert_eq!(status, 400, "{why}: {body}");
        }
        // A well-formed add plants the object (cached here — no memory worker)
        // and registers it as v1; re-adding the same id bumps the version.
        let (status, added) = read(
            add_resource(
                State(state.clone()),
                Json(base("food-prefs", "food-prefs", "Food", "allergies: none")),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{added}");
        assert_eq!(added["version"], 1);
        assert_eq!(added["item"]["id"], "food-prefs");
        assert_eq!(added["item"]["sensitivity"], "safe");
        let (status, again) = read(
            add_resource(
                State(state.clone()),
                Json(base(
                    "food-prefs",
                    "food-prefs",
                    "Food v2",
                    "allergies: peanuts",
                )),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{again}");
        assert_eq!(again["version"], 2);
        let (_, items) = read(list_resources(State(state.clone())).await).await;
        let list = items["items"].as_array().unwrap();
        assert_eq!(list.len(), 1, "{items}");
        assert_eq!(list[0]["version"], 2);
    }

    #[tokio::test]
    async fn retype_changes_the_type_without_a_new_version() {
        let state = state_with_session(None).await;
        let (status, added) = read(
            add_resource(
                State(state.clone()),
                Json(ResourceAddRequest {
                    id: "wifi-note".into(),
                    name: "Wifi".into(),
                    name_zh: String::new(),
                    kind: ResourceKind::Note,
                    tags: vec![],
                    sensitivity: Sensitivity::Safe,
                    ns: "household".into(),
                    body: "SSID home / pass 1234".into(),
                    base_content_hash: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{added}");
        assert_eq!(added["item"]["kind"], "note");
        let (status, re) = read(
            retype_resource(
                State(state.clone()),
                Json(ResourceRetypeRequest {
                    id: "wifi-note".into(),
                    kind: ResourceKind::Profile,
                    tags: Some(vec!["Home".into(), " ".into()]),
                    sensitivity: Some(Sensitivity::Sensitive),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{re}");
        assert_eq!(re["item"]["kind"], "profile");
        assert_eq!(
            re["item"]["version"], 1,
            "a retype is metadata, not a version"
        );
        assert_eq!(re["item"]["tags"][0], "home");
        assert_eq!(re["item"]["sensitivity"], "sensitive");
        let (status, missing) = read(
            retype_resource(
                State(state.clone()),
                Json(ResourceRetypeRequest {
                    id: "nope".into(),
                    kind: ResourceKind::Document,
                    tags: None,
                    sensitivity: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 404, "{missing}");
    }

    #[tokio::test]
    async fn planted_notes_get_a_row_under_a_valid_id_and_never_lose_a_type() {
        let state = state_with_session(None).await;
        let entry = |key: &str, body: &str| crate::ui_bridge::ApiMemoryEntry {
            ns: "personal".into(),
            key: key.into(),
            title: key.into(),
            bytes: body.len() as u64,
            version: "1".into(),
            updated: String::new(),
            preview: body.into(),
            body: body.into(),
            content_hash: String::new(),
            kind: agentkeys_backend_client::protocol::ContextKind::Knowledge,
        };
        let added = register_note_rows(
            &state,
            &[entry("chengdu-trip", "pandas"), entry("Bad Key", "x")],
        )
        .await
        .unwrap();
        assert_eq!(added, 1, "only a valid id becomes a row");
        let reg = ensure_resource_registry(&state).await.unwrap();
        assert_eq!(
            reg.find("chengdu-trip").map(|r| r.kind),
            Some(ResourceKind::Note)
        );
        assert_eq!(
            reg.find("chengdu-trip").map(|r| r.object_key.clone()),
            Some("chengdu-trip".into())
        );
        assert!(reg.find("Bad Key").is_none());
        // the owner types it; a later plant of the same key never downgrades it
        let (status, _) = read(
            retype_resource(
                State(state.clone()),
                Json(ResourceRetypeRequest {
                    id: "chengdu-trip".into(),
                    kind: ResourceKind::Document,
                    tags: None,
                    sensitivity: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200);
        // a replacing plant REFRESHES the typed row (hash, bytes, next version) and keeps its type
        assert_eq!(
            register_note_rows(&state, &[entry("chengdu-trip", "pandas v2")])
                .await
                .unwrap(),
            1
        );
        let row = ensure_resource_registry(&state)
            .await
            .unwrap()
            .find("chengdu-trip")
            .cloned()
            .unwrap();
        assert_eq!(row.kind, ResourceKind::Document);
        assert_eq!(row.version, 2);
        assert_eq!(row.bytes, "pandas v2".len() as u64);
        // same content again: nothing to do
        assert_eq!(
            register_note_rows(&state, &[entry("chengdu-trip", "pandas v2")])
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn an_edit_on_a_stale_base_is_refused_with_the_current_hash() {
        let state = state_with_session(None).await;
        let add = |body: &str, base: Option<&str>| ResourceAddRequest {
            id: "diet".into(),
            name: "Diet".into(),
            name_zh: String::new(),
            kind: ResourceKind::Profile,
            tags: vec![],
            sensitivity: Sensitivity::Safe,
            ns: "household".into(),
            body: body.into(),
            base_content_hash: base.map(str::to_string),
        };
        let (status, v1) =
            read(add_resource(State(state.clone()), Json(add("no peanuts", None))).await).await;
        assert_eq!(status, 200, "{v1}");
        let h1 = v1["item"]["content_hash"].as_str().unwrap().to_string();
        let (status, stale) = read(
            add_resource(
                State(state.clone()),
                Json(add("no shrimp", Some("0xstale"))),
            )
            .await,
        )
        .await;
        assert_eq!(status, 409, "{stale}");
        assert_eq!(stale["error"], "stale_base");
        assert_eq!(stale["current_content_hash"], h1);
        let (status, v2) =
            read(add_resource(State(state.clone()), Json(add("no shrimp", Some(&h1)))).await).await;
        assert_eq!(status, 200, "{v2}");
        assert_eq!(v2["version"], 2);
    }

    #[tokio::test]
    async fn upload_extracts_text_registers_provenance_and_replaces_on_reupload() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let state = state_with_session(None).await;
        let up = |id: &str, filename: &str, ct: &str, bytes: &[u8]| ResourceUploadRequest {
            id: id.into(),
            name: "Food profile".into(),
            name_zh: String::new(),
            kind: ResourceKind::Profile,
            tags: vec!["food".into()],
            sensitivity: Sensitivity::Sensitive,
            ns: "household".into(),
            filename: filename.into(),
            content_type: ct.into(),
            content_b64: STANDARD.encode(bytes),
            base_content_hash: None,
        };
        let (status, body) = read(
            upload_resource(
                State(state.clone()),
                Json(up(
                    "food-prefs",
                    "prefs.md",
                    "text/markdown",
                    b"# Prefs\nno peanuts",
                )),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["version"], 1);
        assert_eq!(body["item"]["filename"], "prefs.md");
        assert_eq!(body["item"]["content_type"], "text/markdown");
        assert_eq!(body["item"]["raw_bytes"], 18);
        assert_eq!(body["extracted_bytes"], 18);
        // no memory plane in this test state: the text is in memory, the file is not
        assert_eq!(body["raw_stored"], false, "{body}");
        assert_eq!(body["item"]["raw_object_key"], "");
        async fn planted(st: &SharedUiBridgeState) -> Vec<String> {
            st.master_memory
                .read()
                .await
                .values()
                .filter(|e| e.ns == "household" && e.key == "food-prefs")
                .map(|e| e.body.clone())
                .collect()
        }
        assert_eq!(
            planted(&state).await,
            vec!["# Prefs\nno peanuts".to_string()]
        );
        // a re-upload REPLACES the text (one entry under the key, the new body) and bumps the version
        let (status, again) = read(
            upload_resource(
                State(state.clone()),
                Json(up(
                    "food-prefs",
                    "prefs-v2.txt",
                    "text/plain",
                    b"no peanuts, no shrimp",
                )),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{again}");
        assert_eq!(again["version"], 2);
        assert_eq!(again["item"]["filename"], "prefs-v2.txt");
        assert_eq!(
            planted(&state).await,
            vec!["no peanuts, no shrimp".to_string()]
        );
        // a pasted re-add also replaces, and clears the file provenance
        let (status, pasted) = read(
            add_resource(
                State(state.clone()),
                Json(ResourceAddRequest {
                    id: "food-prefs".into(),
                    name: "Food profile".into(),
                    name_zh: String::new(),
                    kind: ResourceKind::Profile,
                    tags: vec![],
                    sensitivity: Sensitivity::Safe,
                    ns: "household".into(),
                    body: "pasted v3".into(),
                    base_content_hash: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{pasted}");
        assert_eq!(pasted["version"], 3);
        assert_eq!(pasted["item"]["filename"], "");
        assert_eq!(planted(&state).await, vec!["pasted v3".to_string()]);
        // unsupported type → 415; an image must be a gallery item; oversize → 413
        let (status, b) = read(
            upload_resource(
                State(state.clone()),
                Json(up("zip-1", "x.zip", "application/zip", b"PK")),
            )
            .await,
        )
        .await;
        assert_eq!(status, 415, "{b}");
        let (status, b) = read(
            upload_resource(
                State(state.clone()),
                Json(up("pic-1", "x.png", "image/png", b"\x89PNG")),
            )
            .await,
        )
        .await;
        assert_eq!(status, 400, "{b}");
        let big = vec![b'a'; RESOURCE_UPLOAD_MAX_BYTES + 1];
        let (status, b) = read(
            upload_resource(
                State(state.clone()),
                Json(up("big-1", "big.txt", "text/plain", &big)),
            )
            .await,
        )
        .await;
        assert_eq!(status, 413, "{b}");
        // remove: the row and the entry go; a second remove is a no-op
        let (status, rm) = read(
            remove_resource(
                State(state.clone()),
                Json(ResourceRemoveRequest {
                    id: "food-prefs".into(),
                    force: false,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{rm}");
        assert_eq!(rm["removed"], true);
        assert!(planted(&state).await.is_empty());
        let (_, items) = read(list_resources(State(state.clone())).await).await;
        assert_eq!(items["items"].as_array().unwrap().len(), 0, "{items}");
        let (status, rm2) = read(
            remove_resource(
                State(state.clone()),
                Json(ResourceRemoveRequest {
                    id: "food-prefs".into(),
                    force: false,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(rm2["removed"], false, "{rm2}");
    }

    #[tokio::test]
    async fn install_submit_writes_the_registry_row_with_its_services_and_lists_it() {
        let broker = mock_broker().await;
        let state = state_with_session(Some(broker)).await;
        let (status, built) =
            read(app_install_build(State(state.clone()), Json(install_req("probe"))).await).await;
        assert_eq!(status, 200, "{built}");
        let (status, body) = read(
            app_install_submit(
                State(state.clone()),
                Json(serde_json::json!({ "device_key_hash": DKH, "signature": "0x00" })),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let installed = body["installed"].as_array().expect("installed list");
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0]["label"], "probe");
        assert_eq!(installed[0]["actor_omni"], ACTOR);
        // The registry row (cached — no config worker here) carries the compiled
        // services: the 2026-09-10 regression was an empty list.
        let (status, apps) = read(list_apps(State(state.clone())).await).await;
        assert_eq!(status, 200, "{apps}");
        let row = apps["apps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["label"] == "probe")
            .expect("row")
            .clone();
        assert_eq!(row["status"], "installed");
        assert_eq!(row["template_id"], "conformance");
        let services = row["services"].as_array().unwrap();
        assert!(
            services.iter().any(|s| s == "tool:schedule"),
            "{services:?}"
        );
        assert!(
            services.iter().any(|s| s == "channel-sub:conf-chat"),
            "{services:?}"
        );
        assert_eq!(row["bound_channels"].as_array().unwrap().len(), 2);
        // The dashboard reads the same row (its live legs degrade without workers).
        let (status, dash) =
            read(app_dashboard(State(state.clone()), Path("probe".into())).await).await;
        assert!(status == 200 || status == 502, "dashboard {status}: {dash}");
        // An unknown label is a 404.
        let (status, _) =
            read(app_dashboard(State(state.clone()), Path("nope".into())).await).await;
        assert_eq!(status, 404);
        // The uninstall build asks the broker for the archive op.
        let (status, un) = read(
            app_uninstall_build(
                State(state.clone()),
                Path("probe".into()),
                Json(AppUninstallBuildRequest {
                    resources_kept: true,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{un}");
        // A card tap without a channel worker fails loudly, never silently.
        let (status, cmd) = read(
            app_command(
                State(state.clone()),
                Path("probe".into()),
                Json(AppCommandRequest {
                    channel_id: None,
                    action: "tap".into(),
                    command: "cook".into(),
                    args: serde_json::json!({}),
                    card_updated_at: 0,
                }),
            )
            .await,
        )
        .await;
        assert!(
            status >= 400,
            "command without a worker must not report success: {cmd}"
        );
    }
}

/// Complete the endpoint enrollments a confirmed batch registered (install and
/// rebind alike): ack the rendezvous rows, finish the device side.
async fn complete_pending_enrollments(
    state: &UiBridgeState,
    pending: &[PendingEnrollment],
) -> Vec<serde_json::Value> {
    let mut enrolled: Vec<serde_json::Value> = Vec::new();
    for pe in pending {
        crate::console_device::ack_rendezvous(state, &pe.request_id).await;
        let result = match pe.kind {
            PendingEnrollmentKind::Gateway => crate::gateway_device::finish_gateway_enrollment(
                state,
                &crate::gateway_device::GatewayEnrollPending {
                    request_id: pe.request_id.clone(),
                    label: pe.label.clone(),
                    child_omni: pe.child_omni.clone(),
                    device_key_hash: pe.device_key_hash.clone(),
                    transport: pe.transport.clone(),
                },
            )
            .await
            .map(|v| serde_json::json!({ "kind": "gateway", "ok": true, "result": v })),
            PendingEnrollmentKind::Console => crate::console_device::finish_console_enrollment(
                state,
                &crate::console_device::ConsoleEnrollPending {
                    request_id: pe.request_id.clone(),
                    label: pe.label.clone(),
                    child_omni: pe.child_omni.clone(),
                    device_key_hash: pe.device_key_hash.clone(),
                    device_pubkey: pe.device_pubkey.clone(),
                    key_file: pe.key_file.clone(),
                },
            )
            .await
            .map(|(dev, proven)| {
                serde_json::json!({ "kind": "console", "ok": true, "actor_omni": dev.actor_omni, "label": dev.label, "session_proven": proven })
            }),
        };
        match result {
            Ok(v) => enrolled.push(v),
            Err(e) => {
                tracing::warn!(label = %pe.label, "#663 endpoint enrollment completion FAILED (the binding IS on chain) — {e}");
                enrolled.push(serde_json::json!({ "kind": format!("{:?}", pe.kind).to_lowercase(), "ok": false, "error": e, "actor_omni": pe.child_omni }));
            }
        }
    }
    enrolled
}

/// The messaging channels `bindings` bind that ANOTHER live app already
/// binds — refused: the contact gate relays a channel to exactly one app
/// (two apps on one channel would both read every family message and both
/// reply).
fn messaging_channels_in_use(
    reg: &AppRegistryDoc,
    manifest: &PresetSummary,
    bindings: &AppInstallBindings,
    label: &str,
) -> Option<Vec<TemplateError>> {
    let mut rows = Vec::new();
    for b in &bindings.slots {
        if slot_kind(manifest, &b.slot) != Some(ChannelEndpointKind::Messaging) {
            continue;
        }
        if let Some(other) = reg.live().find(|a| {
            a.label != label
                && a.bound_channels.iter().any(|bc| {
                    bc.kind == ChannelEndpointKind::Messaging && bc.channel_id == b.channel_id
                })
        }) {
            rows.push(TemplateError {
                row: format!("bindings.slots[{}]", b.slot),
                code: "messaging_channel_in_use".into(),
                message: format!(
                    "'{}' is already the messaging channel of `{}` — the contact gate relays a \
                     channel to exactly one app; pick another channel",
                    b.channel_id, other.label
                ),
            });
        }
    }
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}

/// Tell the contact gate which channel this app's messaging slot binds
/// (`alias → channel`), so its inbound hop and its outbound subscription follow
/// the binding (owner decision 2026-09-22: the bound channel IS the feed).
/// `add = false` clears the row (uninstall). Best-effort, loud.
async fn apply_app_feeds(
    state: &UiBridgeState,
    label: &str,
    bound: &[BoundChannel],
    add: bool,
) -> serde_json::Value {
    let messaging: Vec<&BoundChannel> = bound
        .iter()
        .filter(|b| b.kind == ChannelEndpointKind::Messaging)
        .collect();
    if messaging.is_empty() {
        return serde_json::json!({ "updated": 0, "skipped": "no messaging slot" });
    }
    if messaging.len() > 1 {
        tracing::warn!(
            label,
            slots = messaging.len(),
            "#717 app feeds: more than one messaging slot — the gate keys one channel per alias; the first slot's channel is registered"
        );
    }
    let channel = messaging[0].channel_id.clone();
    let body = serde_json::json!({
        "alias": label,
        "channel_id": if add { Some(channel.clone()) } else { None },
    });
    match gateway_admin_call(
        state,
        reqwest::Method::POST,
        "/v1/gateway/admin/apps/update",
        Some(body),
    )
    .await
    {
        Ok(_) => {
            sync_gateway_registry_to_config(state).await;
            serde_json::json!({
                "updated": 1,
                "alias": label,
                "channel_id": if add { channel } else { String::new() },
            })
        }
        Err(e) => {
            tracing::warn!(
                label,
                "#717 app feed registration failed — the gate cannot relay this app until it lands: {e}"
            );
            serde_json::json!({ "updated": 0, "error": e })
        }
    }
}

// ── the rebind ceremony (#717) ───────────────────────────────────────────────
//
// Owner decision 2026-09-22: "a commit, not a reinstallation". A slot change
// on an INSTALLED app is ONE Touch ID — the delegate's grant set re-signed
// (set-replace) with the endpoints' mirrors, the gate enrolled in the same
// batch when the new channel needs it — then the registry row, the gate's
// `alias → channel`, the durable spawn context and the LIVE runtime follow.
// No uninstall, no slot consumed, no re-create while the instance has the
// live-rebind surface.

#[derive(Debug, Clone, Deserialize)]
pub struct AppRebindBuildRequest {
    /// `slot → channel_id` for the slots to change; unlisted slots keep their
    /// binding, resources and the audience are untouched. EMPTY = a template
    /// upgrade: the catalog's current version is applied to the installed
    /// app — its grants and slot directions recompiled over the unchanged
    /// bindings.
    #[serde(default)]
    pub slots: Vec<SlotBinding>,
    #[serde(default = "default_true")]
    pub enroll_endpoints: bool,
}

/// What the daemon keeps between rebind/build and rebind/submit (keyed by the
/// app label), RAM only like the install stash.
#[derive(Debug, Clone)]
pub(crate) struct AppRebindStash {
    pub bindings: AppInstallBindings,
    pub bound_channels: Vec<BoundChannel>,
    pub services: Vec<String>,
    pub enrollments: Vec<PendingEnrollment>,
    pub changes: Vec<String>,
    /// The anchor seal the batch carries (the new context document).
    pub context_seal: Option<ContextSeal>,
    /// A template upgrade: the version the registry row moves to.
    pub template_version: Option<String>,
}

/// What the daemon keeps between anchors/seal/build and /submit: one sealed
/// document per app installed before the anchor existed.
#[derive(Debug, Clone)]
pub(crate) struct AppAnchorSealStash {
    /// `(label, memory_ns, device_key_hash, seal)`
    pub seals: Vec<(String, String, String, ContextSeal)>,
}

#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppRebindBuildResponse {
    /// The broker's rebind build verbatim (user_op, user_op_hash, …).
    #[ts(type = "unknown")]
    pub build: serde_json::Value,
    pub label: String,
    pub services: Vec<String>,
    pub bound_channels: Vec<BoundChannel>,
    pub endpoint_scopes: Vec<EndpointScope>,
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
    /// `slot: old → new`, one per changed slot.
    pub changes: Vec<String>,
}

/// The endpoint actors' FULL resulting sets for a rebind: the install's mirror
/// grants on the NEW channels, minus the pub/sub of the channels this app no
/// longer binds (the gate keeps nothing on a feed it no longer relays).
async fn endpoint_scopes_for_rebind(
    state: &UiBridgeState,
    deltas: &[EndpointGrantDelta],
    bound_now: &[BoundChannel],
    bound_before: &[BoundChannel],
    console_actor: Option<&str>,
) -> Vec<EndpointScope> {
    let dropped: Vec<String> = bound_before
        .iter()
        .filter(|b| !bound_now.iter().any(|n| n.channel_id == b.channel_id))
        .flat_map(|b| {
            vec![
                service_channel_pub(&b.channel_id),
                service_channel_sub(&b.channel_id),
            ]
        })
        .collect();
    let mut scopes = endpoint_scopes_for_install(state, deltas, bound_now, console_actor).await;
    for s in &mut scopes {
        s.services.retain(|svc| !dropped.contains(svc));
    }
    scopes
}

/// What a template upgrade changes for an installed app, as sheet lines: the
/// version, each slot whose direction moved, and — when no channel moved —
/// each grant the new version adds or drops.
pub(crate) fn template_upgrade_changes(
    row: &AppInstanceRow,
    new_version: &str,
    compiled: &CompiledApp,
    list_grants: bool,
) -> Vec<String> {
    let mut changes = vec![format!(
        "template {} → {}",
        row.template_version, new_version
    )];
    for now in &compiled.bound_channels {
        if let Some(before) = row
            .bound_channels
            .iter()
            .find(|b| b.slot == now.slot && b.channel_id == now.channel_id)
        {
            if before.direction != now.direction {
                changes.push(format!(
                    "{}: {} → {}",
                    now.slot,
                    before.direction.as_str(),
                    now.direction.as_str()
                ));
            }
        }
    }
    if list_grants {
        for service in compiled
            .services
            .iter()
            .filter(|s| !row.services.contains(s))
        {
            changes.push(format!("+ {service}"));
        }
        for service in row
            .services
            .iter()
            .filter(|s| !compiled.services.contains(s))
        {
            changes.push(format!("− {service}"));
        }
    }
    changes
}

/// `POST /v1/master/apps/:label/rebind/build` — compile the installed app's
/// manifest with the changed slots, plan the endpoint enrollments the new
/// channels need, and have the broker assemble the ONE-Touch-ID batch.
pub async fn app_rebind_build(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
    Json(req): Json<AppRebindBuildRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    if req.slots.is_empty() {
        return pairing_err(StatusCode::BAD_REQUEST, "slots: nothing to change");
    }
    let row = match ensure_app_registry(&state).await {
        Ok(reg) => match reg.live().find(|a| a.label == label).cloned() {
            Some(r) => r,
            None => {
                return pairing_err(
                    StatusCode::NOT_FOUND,
                    "no installed application with this label",
                )
            }
        },
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let bundle = match fetch_bundle(&broker, &row.template_id).await {
        Ok(b) => b,
        Err(e) => return pairing_err(StatusCode::BAD_GATEWAY, &e),
    };
    if let Err(rows) = validate_template(
        &bundle.manifest,
        &bundle.skill_filenames(),
        &bundle.knowledge_filenames(),
    ) {
        return refused(StatusCode::BAD_REQUEST, "template_invalid", rows);
    }
    // The requested slots over the installed bindings.
    let mut bindings = row.bindings.clone();
    let mut changes: Vec<String> = Vec::new();
    let mut rows_err: Vec<TemplateError> = Vec::new();
    for want in &req.slots {
        if slot_kind(&bundle.manifest, &want.slot).is_none() {
            rows_err.push(TemplateError {
                row: format!("bindings.slots[{}]", want.slot),
                code: "binding_unknown_slot".into(),
                message: format!("'{}' is not a slot of this template", want.slot),
            });
            continue;
        }
        let channel = want.channel_id.trim().to_string();
        if channel.is_empty() {
            rows_err.push(TemplateError {
                row: format!("bindings.slots[{}]", want.slot),
                code: "binding_channel_empty".into(),
                message: format!("slot '{}' binding has an empty channel id", want.slot),
            });
            continue;
        }
        let old = row
            .bound_channels
            .iter()
            .find(|b| b.slot == want.slot)
            .map(|b| b.channel_id.clone())
            .unwrap_or_default();
        if old == channel {
            continue;
        }
        match bindings.slots.iter_mut().find(|b| b.slot == want.slot) {
            Some(b) => {
                b.channel_id = channel.clone();
                b.endpoint_actor_omni = None;
            }
            None => bindings.slots.push(SlotBinding {
                slot: want.slot.clone(),
                channel_id: channel.clone(),
                endpoint_actor_omni: None,
            }),
        }
        changes.push(format!(
            "{}: {} → {}",
            want.slot,
            if old.is_empty() {
                "(unbound)".to_string()
            } else {
                old
            },
            channel
        ));
    }
    if !rows_err.is_empty() {
        return refused(
            StatusCode::BAD_REQUEST,
            "template_bindings_invalid",
            rows_err,
        );
    }
    // A template upgrade: the catalog serves a newer version than the row
    // runs, so its grants and slot directions are recompiled over the bindings.
    let upgrading = bundle.manifest.version != row.template_version;
    let channels_changed = !changes.is_empty();
    if !channels_changed && !upgrading {
        return pairing_err(
            StatusCode::BAD_REQUEST,
            "nothing to change — every listed slot already binds that channel, and the app already runs the template's current version",
        );
    }
    resolve_binding_endpoints(&state, &mut bindings).await;
    if let Ok(reg) = ensure_app_registry(&state).await {
        if let Some(rows) = messaging_channels_in_use(&reg, &bundle.manifest, &bindings, &label) {
            return refused(StatusCode::BAD_REQUEST, "template_bindings_invalid", rows);
        }
    }
    let mut endpoint_enrollments: Vec<EndpointEnrollment> = Vec::new();
    let mut pending_enrollments: Vec<PendingEnrollment> = Vec::new();
    let mut console_actor: Option<String> = state
        .console_device
        .read()
        .await
        .as_ref()
        .map(|d| d.actor_omni.clone());
    if req.enroll_endpoints {
        match plan_enrollments(
            &state,
            &broker,
            &j1,
            &bundle.manifest,
            &label,
            &mut bindings,
            console_actor.is_none(),
        )
        .await
        {
            Ok((enrolls, pendings, console_child)) => {
                endpoint_enrollments = enrolls;
                pending_enrollments = pendings;
                if let Some(c) = console_child {
                    console_actor = Some(c);
                }
            }
            Err(resp) => return resp,
        }
    }
    if let Ok(resources) = ensure_resource_registry(&state).await {
        for rb in &mut bindings.resources {
            if let Some(item) = resources.find(&rb.item_id) {
                rb.ns = item.ns.clone();
                rb.kind = item.kind;
                rb.sensitivity = item.sensitivity;
            }
        }
    }
    let memory_ns = Some(row.memory_ns.as_str()).filter(|m| !m.trim().is_empty());
    let compiled = match compile_app(&bundle.manifest, &label, memory_ns, &bindings) {
        Ok(c) => c,
        Err(rows) => return refused(StatusCode::BAD_REQUEST, "template_bindings_invalid", rows),
    };
    if upgrading {
        changes.extend(template_upgrade_changes(
            &row,
            &bundle.manifest.version,
            &compiled,
            !channels_changed,
        ));
    }
    let endpoint_scopes = endpoint_scopes_for_rebind(
        &state,
        &compiled.endpoint_grants,
        &compiled.bound_channels,
        &row.bound_channels,
        console_actor.as_deref(),
    )
    .await;
    let body = serde_json::json!({
        "operator_omni": operator_omni,
        "device_key_hash": row.device_key_hash,
        "services": compiled.services,
        "endpoint_scopes": endpoint_scopes,
        "endpoint_enrollments": endpoint_enrollments,
        "bound_channels": compiled.bound_channels,
    });
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/agent/rebind/build", &j1, &body)
            .await;
    if !resp.status().is_success() {
        return resp;
    }
    let Some(built) = parsed else {
        return pairing_err(
            StatusCode::BAD_GATEWAY,
            "broker rebind build returned no JSON",
        );
    };
    state.app_rebind_by_label.write().await.insert(
        label.clone(),
        AppRebindStash {
            bindings,
            bound_channels: compiled.bound_channels.clone(),
            services: compiled.services.clone(),
            enrollments: pending_enrollments,
            changes: changes.clone(),
            context_seal: built
                .get("context_seal")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            template_version: upgrading.then(|| bundle.manifest.version.clone()),
        },
    );
    (
        StatusCode::OK,
        Json(AppRebindBuildResponse {
            build: built,
            label,
            services: compiled.services,
            bound_channels: compiled.bound_channels,
            endpoint_scopes,
            endpoint_enrollments,
            changes,
        }),
    )
        .into_response()
}

/// `POST /v1/master/apps/:label/rebind/submit` — the K11-signed rebind op to
/// the broker's accept relay, then everything that follows the confirm: the
/// registry row, the endpoint enrollments, the channel rows, the gate's
/// `alias → channel` (+ reach), the durable spawn context and the LIVE runtime
/// (a re-create only when the instance predates the live-rebind surface).
pub async fn app_rebind_submit(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let Some(stash) = state.app_rebind_by_label.write().await.remove(&label) else {
        return pairing_err(
            StatusCode::CONFLICT,
            "no rebind build pending for this label — build first",
        );
    };
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/scope/submit", &j1, &body).await;
    if !resp.status().is_success() {
        // The op did not land; a new build mints a fresh nonce.
        return resp;
    }
    // 1. the registry row
    let mut previous_bound: Vec<BoundChannel> = Vec::new();
    let mut device_key_hash = String::new();
    let mut memory_ns = String::new();
    let mut audience: Vec<SlotAudience> = Vec::new();
    let tx_hash: Option<String> = parsed
        .as_ref()
        .and_then(|v| v.get("tx_hash"))
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let anchor = stash.context_seal.as_ref().map(|s| AppAnchor {
        version: s.context_version,
        hash: s.context_hash.clone(),
        tx_hash: tx_hash.clone(),
        sealed_at: now_unix(),
    });
    let storage = match ensure_app_registry(&state).await {
        Ok(mut reg) => match reg
            .apps
            .iter_mut()
            .find(|a| a.label == label && a.status == AppInstanceStatus::Installed)
        {
            Some(row) => {
                previous_bound = row.bound_channels.clone();
                device_key_hash = row.device_key_hash.clone();
                memory_ns = row.memory_ns.clone();
                audience = row.bindings.audience.clone();
                row.bindings = stash.bindings.clone();
                row.bound_channels = stash.bound_channels.clone();
                row.services = stash.services.clone();
                if let Some(version) = &stash.template_version {
                    row.template_version = version.clone();
                }
                if anchor.is_some() {
                    row.anchor = anchor.clone();
                }
                match persist_app_registry(&state, reg.clone()).await {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        tracing::warn!(label = %label, "#717 app-registry persist FAILED after the rebind confirm — {e}");
                        format!("failed: {e}")
                    }
                }
            }
            None => "missing: no installed row for this label".to_string(),
        },
        Err(e) => format!("failed: {e}"),
    };
    // 2. the endpoint actors the batch registered
    let enrolled = complete_pending_enrollments(&state, &stash.enrollments).await;
    // 3. the channel rows (insert-if-absent)
    for b in &stash.bound_channels {
        ensure_channel_named(
            &state,
            &b.channel_id,
            &b.channel_id,
            &format!(
                "auto-registered at rebind — {}'s `{}` slot ({})",
                label,
                b.slot,
                b.kind.as_str()
            ),
        )
        .await;
    }
    // 4. the gate: where the app listens now + who may reach it (idempotent)
    let app_feeds = apply_app_feeds(&state, &label, &stash.bound_channels, true).await;
    let reach = apply_reach(&state, &label, &audience, true).await;
    // 4b. the anchor: the sealed document, verbatim, into the app's namespace
    let context_storage = match (&stash.context_seal, memory_ns.is_empty()) {
        (Some(seal), false) => {
            match crate::ui_bridge::context_doc_store(
                &state,
                &memory_ns,
                &seal.context_doc,
                seal.context_version,
            )
            .await
            {
                Ok(s) => s.to_string(),
                Err(e) => {
                    tracing::warn!(label = %label, "anchor: context document store FAILED (the seal IS on chain) — {e}");
                    format!("failed: {e}")
                }
            }
        }
        (Some(_), true) => "skipped: the registry row carries no memory namespace".to_string(),
        (None, _) => "unsealed: the broker carried no seal".to_string(),
    };
    // 5. the durable spawn context + the live runtime
    let mut runtime = serde_json::json!({
        "mode": "skipped",
        "detail": "no device_key_hash on the registry row — the runtime was not told",
    });
    if !device_key_hash.is_empty() {
        let ctx_body = serde_json::json!({
            "operator_omni": operator_omni,
            "device_key_hash": device_key_hash,
            "bound_channels": stash.bound_channels,
            "context_version": stash.context_seal.as_ref().map(|s| s.context_version),
            "context_hash": stash.context_seal.as_ref().map(|s| s.context_hash.clone()),
        });
        let (ctx_resp, ctx_parsed) = crate::ui_bridge::forward_to_broker_value(
            &broker,
            "/v1/agent/spawn/context/update",
            &j1,
            &ctx_body,
        )
        .await;
        runtime = match ctx_parsed {
            Some(v) if ctx_resp.status().is_success() => v
                .get("runtime")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({ "mode": "unknown" })),
            Some(v) => serde_json::json!({
                "mode": "failed",
                "detail": format!(
                    "spawn context update refused: {}",
                    v.get("error").and_then(|e| e.as_str()).unwrap_or("?")
                ),
            }),
            None => serde_json::json!({
                "mode": "failed",
                "detail": format!("spawn context update: HTTP {}", ctx_resp.status()),
            }),
        };
        // An instance without the live surface: re-create it on the updated
        // context (#577), so the rebind still lands without a reinstall.
        if runtime.get("mode").and_then(|m| m.as_str()) == Some("unsupported") {
            let upd_body = serde_json::json!({
                "operator_omni": operator_omni,
                "device_key_hash": device_key_hash,
                "force": false,
            });
            let (u_resp, u_parsed) = crate::ui_bridge::forward_to_broker_value(
                &broker,
                "/v1/agent/update",
                &j1,
                &upd_body,
            )
            .await;
            runtime["recreate"] = if u_resp.status().is_success() {
                serde_json::json!({
                    "ok": true,
                    "sandbox_id": u_parsed.as_ref().and_then(|v| v.pointer("/sandbox/sandbox_id")).cloned(),
                })
            } else {
                serde_json::json!({
                    "ok": false,
                    "status": u_resp.status().as_u16(),
                    "detail": u_parsed.as_ref().and_then(|v| v.get("error")).cloned(),
                })
            };
        }
    }
    // A template upgrade brings the template's new skills and knowledge:
    // re-apply the preset into the live sandbox (what "update runtime" does
    // after a re-create), detached — the apply waits for the bridge.
    let preset_reapply = if stash.template_version.is_some() && !device_key_hash.is_empty() {
        crate::ui_bridge::reapply_preset_after_update(
            &state,
            &broker,
            &device_key_hash,
            None,
            None,
        )
        .await;
        "queued"
    } else {
        "not needed"
    };
    invalidate_fleet_sync(&state);
    tracing::info!(
        label = %label,
        changes = ?stash.changes,
        runtime = %runtime.get("mode").and_then(|m| m.as_str()).unwrap_or("?"),
        "#717 rebind: committed"
    );
    let mut out = parsed.unwrap_or_else(|| serde_json::json!({ "ok": true }));
    out["rebound"] = serde_json::json!({
        "label": label,
        "changes": stash.changes,
        "registry_storage": storage,
        "previous_bound_channels": previous_bound,
        "bound_channels": stash.bound_channels,
        "enrolled": enrolled,
        "app_feeds": app_feeds,
        "reach": reach,
        "anchor": anchor,
        "context_storage": context_storage,
        "runtime": runtime,
        "template_version": stash.template_version,
        "preset_reapply": preset_reapply,
    });
    (StatusCode::OK, Json(out)).into_response()
}

// ── the anchor: seal existing apps · re-hydrate a fresh broker ──────────────

/// `POST /v1/master/apps/anchors/seal/build` — the apps installed before the
/// anchor existed (no `anchor` on their row) get their context document
/// sealed on chain in ONE batch (one Touch ID); the broker composes each
/// document from its row. `labels` narrows the set.
#[derive(Debug, Clone, Deserialize)]
pub struct AppAnchorsSealRequest {
    #[serde(default)]
    pub labels: Vec<String>,
}

pub async fn app_anchors_seal_build(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<AppAnchorsSealRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let reg = match ensure_app_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let targets: Vec<AppInstanceRow> = reg
        .live()
        .filter(|a| req.labels.is_empty() || req.labels.iter().any(|l| l == &a.label))
        .filter(|a| a.anchor.is_none() && !a.device_key_hash.is_empty())
        .cloned()
        .collect();
    if targets.is_empty() {
        return pairing_err(
            StatusCode::BAD_REQUEST,
            "nothing to seal — every installed app already carries an anchor",
        );
    }
    let body = serde_json::json!({
        "operator_omni": operator_omni,
        "device_key_hashes": targets.iter().map(|a| a.device_key_hash.clone()).collect::<Vec<_>>(),
    });
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/agent/anchors/build", &j1, &body)
            .await;
    if !resp.status().is_success() {
        return resp;
    }
    let Some(built) = parsed else {
        return pairing_err(
            StatusCode::BAD_GATEWAY,
            "broker anchors build returned no JSON",
        );
    };
    let mut seals: Vec<(String, String, String, ContextSeal)> = Vec::new();
    for s in built
        .get("seals")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let dkh = s
            .get("device_key_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_lowercase();
        let Ok(seal) = serde_json::from_value::<ContextSeal>(s.clone()) else {
            continue;
        };
        if let Some(app) = targets
            .iter()
            .find(|a| a.device_key_hash.to_lowercase() == dkh)
        {
            seals.push((app.label.clone(), app.memory_ns.clone(), dkh, seal));
        }
    }
    let labels: Vec<String> = seals.iter().map(|(l, _, _, _)| l.clone()).collect();
    *state.app_anchor_seal.write().await = Some(AppAnchorSealStash { seals });
    (
        StatusCode::OK,
        Json(serde_json::json!({ "build": built, "labels": labels })),
    )
        .into_response()
}

/// `POST /v1/master/apps/anchors/seal/submit` — the signed seal batch to the
/// accept relay, then each document onto the memory plane, each row's anchor,
/// and each broker row's cache columns.
pub async fn app_anchors_seal_submit(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let Some(stash) = state.app_anchor_seal.write().await.take() else {
        return pairing_err(StatusCode::CONFLICT, "no seal build pending — build first");
    };
    let (resp, parsed) =
        crate::ui_bridge::forward_to_broker_value(&broker, "/v1/scope/submit", &j1, &body).await;
    if !resp.status().is_success() {
        return resp;
    }
    let tx_hash: Option<String> = parsed
        .as_ref()
        .and_then(|v| v.get("tx_hash"))
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let mut sealed: Vec<serde_json::Value> = Vec::new();
    let mut reg = ensure_app_registry(&state).await.ok();
    for (label, memory_ns, dkh, seal) in &stash.seals {
        let context_storage = match crate::ui_bridge::context_doc_store(
            &state,
            memory_ns,
            &seal.context_doc,
            seal.context_version,
        )
        .await
        {
            Ok(s) => s.to_string(),
            Err(e) => format!("failed: {e}"),
        };
        if let Some(reg) = reg.as_mut() {
            if let Some(row) = reg.apps.iter_mut().find(|a| &a.label == label) {
                row.anchor = Some(AppAnchor {
                    version: seal.context_version,
                    hash: seal.context_hash.clone(),
                    tx_hash: tx_hash.clone(),
                    sealed_at: now_unix(),
                });
            }
        }
        // the broker row caches the seal (bound channels unchanged)
        let ctx_body = serde_json::json!({
            "operator_omni": operator_omni,
            "device_key_hash": dkh,
            "bound_channels": serde_json::from_str::<DelegateContextDoc>(&seal.context_doc)
                .map(|d| d.bound_channels)
                .unwrap_or_default(),
            "context_version": seal.context_version,
            "context_hash": seal.context_hash,
        });
        let (c_resp, _) = crate::ui_bridge::forward_to_broker_value(
            &broker,
            "/v1/agent/spawn/context/update",
            &j1,
            &ctx_body,
        )
        .await;
        sealed.push(serde_json::json!({
            "label": label,
            "version": seal.context_version,
            "hash": seal.context_hash,
            "context_storage": context_storage,
            "broker_row": c_resp.status().as_u16(),
        }));
    }
    let registry_storage = match reg {
        Some(reg) => match persist_app_registry(&state, reg).await {
            Ok(s) => s.to_string(),
            Err(e) => format!("failed: {e}"),
        },
        None => "failed: app registry unavailable".to_string(),
    };
    invalidate_fleet_sync(&state);
    let mut out = parsed.unwrap_or_else(|| serde_json::json!({ "ok": true }));
    out["sealed"] = serde_json::json!(sealed);
    out["registry_storage"] = serde_json::json!(registry_storage);
    (StatusCode::OK, Json(out)).into_response()
}

/// `POST /v1/master/apps/rehydrate` — for every installed app, read its
/// sealed document from the memory plane and have the broker rebuild (or
/// refresh) its spawn-context row from it, verifying the seal on chain. What
/// a fresh broker needs after a host switch; harmless on a current one.
pub async fn apps_rehydrate(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<AppAnchorsSealRequest>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let reg = match ensure_app_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let mut results: Vec<serde_json::Value> = Vec::new();
    for app in reg
        .live()
        .filter(|a| req.labels.is_empty() || req.labels.iter().any(|l| l == &a.label))
    {
        let doc = match crate::ui_bridge::context_doc_load(&state, &app.memory_ns).await {
            Ok((Some(d), _)) => d,
            Ok((None, _)) => {
                results.push(serde_json::json!({ "label": app.label, "skipped": "no context document on the memory plane — seal it first" }));
                continue;
            }
            Err(e) => {
                results.push(serde_json::json!({ "label": app.label, "error": format!("context document read: {e}") }));
                continue;
            }
        };
        let body = serde_json::json!({ "operator_omni": operator_omni, "context_doc": doc });
        let (resp, parsed) = crate::ui_bridge::forward_to_broker_value(
            &broker,
            "/v1/agent/spawn/context/rehydrate",
            &j1,
            &body,
        )
        .await;
        results.push(serde_json::json!({
            "label": app.label,
            "status": resp.status().as_u16(),
            "result": parsed,
        }));
    }
    invalidate_fleet_sync(&state);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "results": results })),
    )
        .into_response()
}

// ── the context document on the operator surface ─────────────────────────────

/// What the application page shows of an app's sealed context document: the
/// parsed fields, the verbatim bytes, their hash, and whether they match the
/// row's seal and the row's bindings.
#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppContextView {
    pub label: String,
    /// Where the document was read from: `memory-plane` · `cache` (no memory
    /// worker configured) · `absent` (never sealed).
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub doc: Option<DelegateContextDoc>,
    /// The stored bytes, verbatim — what the chain root hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub doc_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub anchor: Option<AppAnchor>,
    /// The stored document's hash equals the row's sealed anchor hash.
    pub matches_anchor: bool,
    /// The stored document's bound channels equal the row's.
    pub matches_row: bool,
}

/// The pure half: the view from the stored bytes and the registry row.
pub(crate) fn context_view(
    label: &str,
    source: &str,
    doc_json: Option<String>,
    row: &AppInstanceRow,
) -> AppContextView {
    let hash = doc_json.as_ref().map(|j| {
        format!(
            "0x{}",
            hex::encode(agentkeys_core::device_crypto::keccak256(j.as_bytes()))
        )
    });
    let doc: Option<DelegateContextDoc> = doc_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());
    let matches_anchor = match (&hash, &row.anchor) {
        (Some(h), Some(a)) => h.eq_ignore_ascii_case(&a.hash),
        _ => false,
    };
    let matches_row = doc
        .as_ref()
        .map(|d| d.bound_channels == row.bound_channels)
        .unwrap_or(false);
    AppContextView {
        label: label.to_string(),
        source: source.to_string(),
        doc,
        doc_json,
        hash,
        anchor: row.anchor.clone(),
        matches_anchor,
        matches_row,
    }
}

/// `GET /v1/master/apps/:label/context` — the sealed context document as
/// stored (the anchor), for the operator surface.
pub async fn app_context(
    State(state): State<SharedUiBridgeState>,
    Path(label): Path<String>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let reg = match ensure_app_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("app registry: {e}")),
    };
    let Some(row) = reg.find(&label).cloned() else {
        return registry_err(
            StatusCode::NOT_FOUND,
            "no installed application with that label",
        );
    };
    let (doc_json, source) = match crate::ui_bridge::context_doc_load(&state, &row.memory_ns).await
    {
        Ok((Some(j), src)) => (Some(j), src),
        Ok((None, _)) => (None, "absent"),
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("context document: {e}")),
    };
    (
        StatusCode::OK,
        Json(context_view(&label, source, doc_json, &row)),
    )
        .into_response()
}

#[cfg(test)]
mod context_view_tests {
    use super::*;

    fn row(anchor_hash: Option<&str>, channel: &str) -> AppInstanceRow {
        AppInstanceRow {
            label: "chef".into(),
            template_id: "chef".into(),
            template_version: "1.0.0".into(),
            template_schema: 1,
            actor_omni: "0xactor".into(),
            device_key_hash: "0xdkh".into(),
            memory_ns: "app-chef".into(),
            chat_channel_id: "opchat-chef".into(),
            bindings: Default::default(),
            bound_channels: vec![BoundChannel {
                slot: "family_chat".into(),
                kind: ChannelEndpointKind::Messaging,
                direction: agentkeys_backend_client::protocol::SlotDirection::Duplex,
                channel_id: channel.into(),
                event_kinds: vec![],
                endpoint_actor_omni: None,
            }],
            services: vec![],
            availability: Availability::default(),
            status: AppInstanceStatus::Installed,
            installed_at: 1,
            uninstalled_at: None,
            resources_kept: None,
            reach_aliases: vec![],
            anchor: anchor_hash.map(|h| AppAnchor {
                version: 1,
                hash: h.into(),
                tx_hash: None,
                sealed_at: 1,
            }),
        }
    }

    #[test]
    fn the_view_hashes_the_bytes_and_compares_them_to_the_seal_and_the_row() {
        let doc = DelegateContextDoc {
            schema: agentkeys_backend_client::protocol::CONTEXT_DOC_SCHEMA,
            version: 1,
            previous_hash: None,
            label: "chef".into(),
            device_key_hash: "0xdkh".into(),
            actor_omni: "0xactor".into(),
            k10_address: "0xk10".into(),
            preset_id: "chef".into(),
            chat_channel_id: "opchat-chef".into(),
            memory_ns: "app-chef".into(),
            bound_channels: row(None, "family-chat").bound_channels.clone(),
            availability: "scheduled".into(),
            memory_namespaces: String::new(),
            tz_offset_minutes: 480,
            updated_at: 1,
        };
        let json = serde_json::to_string(&doc).unwrap();
        let hash = format!(
            "0x{}",
            hex::encode(agentkeys_core::device_crypto::keccak256(json.as_bytes()))
        );
        let v = context_view(
            "chef",
            "memory-plane",
            Some(json.clone()),
            &row(Some(&hash), "family-chat"),
        );
        assert!(v.matches_anchor && v.matches_row);
        assert_eq!(v.hash.as_deref(), Some(hash.as_str()));
        assert_eq!(v.doc.as_ref().map(|d| d.version), Some(1));
        // a stale row (different bindings) and a foreign seal are both visible
        let v2 = context_view(
            "chef",
            "memory-plane",
            Some(json),
            &row(Some("0xother"), "kitchen"),
        );
        assert!(!v2.matches_anchor && !v2.matches_row);
        let v3 = context_view("chef", "absent", None, &row(None, "family-chat"));
        assert!(v3.doc.is_none() && v3.hash.is_none() && !v3.matches_anchor);
    }
}

#[cfg(test)]
mod template_upgrade_tests {
    use super::template_upgrade_changes;
    use agentkeys_backend_client::protocol::{AppInstanceRow, CompiledApp};

    fn bound(direction: &str) -> serde_json::Value {
        serde_json::json!([
            { "slot": "family_chat", "kind": "messaging", "direction": "duplex", "channel_id": "family-chat" },
            { "slot": "kitchen_screen", "kind": "display", "direction": direction, "channel_id": "kitchen-display" }
        ])
    }

    fn row() -> AppInstanceRow {
        serde_json::from_value(serde_json::json!({
            "label": "chef",
            "template_id": "chef",
            "template_version": "1.0.0",
            "actor_omni": "0xchef",
            "device_key_hash": "0xhash",
            "memory_ns": "app-chef",
            "chat_channel_id": "opchat-chef",
            "bound_channels": bound("pub"),
            "services": ["channel-sub:family-chat", "channel-pub:family-chat", "channel-pub:kitchen-display"],
            "installed_at": 1
        }))
        .expect("a well-formed row")
    }

    fn compiled() -> CompiledApp {
        serde_json::from_value(serde_json::json!({
            "services": ["channel-sub:family-chat", "channel-pub:family-chat", "channel-sub:kitchen-display", "channel-pub:kitchen-display"],
            "annotations": [],
            "bound_channels": bound("duplex"),
            "audience": [],
            "endpoint_grants": [],
            "memory_ns": "app-chef",
            "chat_channel_id": "opchat-chef",
            "availability": "scheduled",
            "schedule": [],
            "disclosure": [],
            "resource_namespaces": []
        }))
        .expect("a well-formed compile")
    }

    #[test]
    fn a_pure_upgrade_names_the_version_the_direction_and_the_new_grant() {
        assert_eq!(
            template_upgrade_changes(&row(), "1.1.0", &compiled(), true),
            vec![
                "template 1.0.0 → 1.1.0".to_string(),
                "kitchen_screen: pub → duplex".to_string(),
                "+ channel-sub:kitchen-display".to_string(),
            ]
        );
    }

    #[test]
    fn an_upgrade_riding_a_channel_change_leaves_the_grant_lines_to_the_slot_lines() {
        assert_eq!(
            template_upgrade_changes(&row(), "1.1.0", &compiled(), false),
            vec![
                "template 1.0.0 → 1.1.0".to_string(),
                "kitchen_screen: pub → duplex".to_string()
            ]
        );
    }
}
