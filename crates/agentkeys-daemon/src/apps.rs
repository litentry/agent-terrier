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
    compile_app, messaging_feed_id, service_channel_pub, service_channel_sub, validate_template,
    AppInstallBindings, AppInstanceRow, AppInstanceStatus, AppRegistryDoc, Availability,
    BoundChannel, CardCommand, CardDocument, ChannelEndpointKind, ContactSummary, ContactTier,
    EndpointEnrollment, EndpointGrantDelta, EndpointScope, PresetBundle, PresetSummary,
    ResourceItemRow, ResourceKind, ResourceRegistryDoc, Sensitivity, ServiceAnnotation,
    SlotAudience, TemplateError, APP_REGISTRY_SERVICE, RESOURCE_REGISTRY_SERVICE,
};

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
    pub display_names: Vec<(String, String)>,
    /// #663 — the endpoint device actors this install's ONE Touch ID also
    /// registers (completed on the device side after the confirm).
    pub enrollments: Vec<PendingEnrollment>,
    /// The compiled grant set the broker's build returned — the sheet the owner
    /// signs. Kept HERE because `spawn_submit_core` consumes the #427 ceremony
    /// context at confirm, so a read of `ceremony_context_by_dkh` after the
    /// submit finds nothing (the registry row shipped with `services: []`).
    pub services: Vec<String>,
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
    let display_names = resolve_binding_endpoints(&state, &mut bindings).await;
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
            display_names,
            enrollments: pending_enrollments,
            services: built
                .get("services")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_else(|| compiled.services.clone()),
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
    app_label: &str,
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
            Ok(st) if st.enrolled => {
                for i in unowned_messaging {
                    if bindings.slots[i].channel_id == st.transport {
                        bindings.slots[i].endpoint_actor_omni = st.actor_omni.clone();
                    }
                }
            }
            Ok(st) if st.configured => {
                let targets: Vec<usize> = unowned_messaging
                    .into_iter()
                    .filter(|i| bindings.slots[*i].channel_id == st.transport)
                    .collect();
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
                    let feed = messaging_feed_id(&st.transport, app_label);
                    let scope = format!(
                        "{},{}",
                        service_channel_pub(&feed),
                        service_channel_sub(&feed)
                    );
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

/// The master's claim of an endpoint's pairing code → its child omni.
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
    v.get("child_omni")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("claim ({label}) returned no child_omni"))
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
        // Name the derived messaging feeds so grant chips read well.
        for b in &stash.bound_channels {
            if b.kind == ChannelEndpointKind::Messaging {
                let transport_name = stash
                    .display_names
                    .iter()
                    .find(|(id, _)| b.channel_id.starts_with(&format!("{id}-")))
                    .map(|(_, n)| n.clone())
                    .unwrap_or_else(|| "messaging".to_string());
                ensure_channel_named(
                    &state,
                    &b.channel_id,
                    &format!("{} · {}", stash.label, transport_name),
                )
                .await;
            }
        }
        // #663 — the endpoint actors this batch registered: ack their
        // rendezvous rows and complete the device side (the gateway proves
        // its binding + gets its messaging row; the console persists itself).
        let mut enrolled: Vec<serde_json::Value> = Vec::new();
        for pe in &stash.enrollments {
            crate::console_device::ack_rendezvous(&state, &pe.request_id).await;
            let result = match pe.kind {
                PendingEnrollmentKind::Gateway => crate::gateway_device::finish_gateway_enrollment(
                    &state,
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
                    &state,
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
        // The gateway now exists as an actor: the messaging feeds it relays
        // need its outbound subscription to know the app's alias — the reach
        // write below does that through its admin surface.
        // Audience → each allowed contact's `reach` gains the app's alias.
        let reach = apply_reach(&state, &stash.label, &stash.audience, true).await;
        installed.push(serde_json::json!({
            "label": stash.label,
            "template_id": stash.template_id,
            "actor_omni": actor_omni,
            "registry_storage": storage,
            "reach": reach,
            "enrolled": enrolled,
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
                let storage = match persist_app_registry(&state, reg.clone()).await {
                    Ok(s) => s.to_string(),
                    Err(e) => format!("failed: {e}"),
                };
                let mut reach = serde_json::json!({ "updated": 0 });
                for alias in &reach_aliases {
                    reach = apply_reach(&state, alias, &audience, false).await;
                }
                closed = serde_json::json!({
                    "label": label,
                    "closed": true,
                    "registry_storage": storage,
                    "reach": reach,
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
}

/// Poll a feed as the master (the operator's global visibility, D13) and
/// return the raw events after `after`.
pub(crate) async fn master_feed_events(
    state: &UiBridgeState,
    channel_id: &str,
    after: &str,
    wait_seconds: u64,
) -> Result<(Vec<serde_json::Value>, String), String> {
    let (cap, coords) = master_channel_cap(
        state,
        format!("channel-sub:{channel_id}"),
        agentkeys_backend_client::protocol::CapMintOp::ChannelSubscribe,
    )
    .await?;
    let worker = crate::ui_bridge::channel_worker_url(&coords.broker)?;
    // @backend-fixture: channel_poll_body
    let body = serde_json::json!({
        "cap": cap,
        "after": after,
        "wait_seconds": wait_seconds.min(25),
    });
    let resp = reqwest::Client::new()
        .post(format!("{worker}/v1/channel/poll"))
        .timeout(std::time::Duration::from_secs(40))
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

/// The latest card on a display feed + the recent command events.
async fn latest_card(
    state: &UiBridgeState,
    channel_id: &str,
) -> (Option<(CardDocument, String)>, Vec<serde_json::Value>) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let Ok((events, _)) = master_feed_events(state, channel_id, "", 0).await else {
        return (None, Vec::new());
    };
    let mut card = None;
    let mut commands = Vec::new();
    for ev in events {
        let kind = ev.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match kind {
            "doc" => {
                if let Some(b64) = ev.get("body").and_then(|b| b.as_str()) {
                    if let Ok(bytes) = STANDARD.decode(b64) {
                        if let Ok(c) = agentkeys_backend_client::protocol::parse_card(&bytes) {
                            let id = ev
                                .get("event_id")
                                .and_then(|e| e.as_str())
                                .unwrap_or("")
                                .to_string();
                            card = Some((c, id));
                        }
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
    (card, commands.split_off(keep))
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
    let (card, commands) = match &display {
        Some(d) if row.status != AppInstanceStatus::Uninstalled => {
            latest_card(&state, &d.channel_id).await
        }
        _ => (None, Vec::new()),
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
    let next_version = reg.find(&c.id).map(|i| i.version + 1).unwrap_or(1);
    if let Err((status, reason)) = resource_entry_remove(state, &c.ns, &c.id).await {
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
    if let Err((status, reason)) = resource_entry_remove(&state, &row.ns, &row.id).await {
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
                        channel_id: "weixin".into(),
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
            st.services.iter().any(|s| s == "channel-sub:weixin-probe"),
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
            services.iter().any(|s| s == "channel-sub:weixin-probe"),
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
