//! #667 — enrolling the CHANNEL GATEWAY as a device actor (the master's half).
//!
//! The channel gateway (the WeChat iLink / Telegram worker — NOT the metering gate)
//! is a machine on the channel plane, so under arch.md §6.4 it is ONE device
//! actor: its own K10 lives on the broker host
//! (`AGENTKEYS_WEIXIN_DEVICE_KEY_FILE`), its child omni is bound by the master
//! through the ordinary §10.2 pairing — the gateway mints the pairing code
//! (`/v1/gateway/admin/device/pairing-request`), THIS daemon claims it, the
//! binding rides an install's batch (`apps.rs` — the FIRST install that binds
//! the gateway's transport registers it in the SAME batch the app's ONE Touch
//! ID signs) or the standalone accept below, and the gateway proves the
//! binding from its side (`/v1/gateway/admin/device/pairing-complete`). From
//! then on each install's batch grants the gateway actor pub + sub on the
//! app's messaging feed, and the gateway's feed hop relays contact turns.
//!
//! The enrollment also writes the CHANNEL-REGISTRY row an app slot binds to:
//! `id = <transport>` (`weixin` | `telegram`), `kind = messaging`,
//! `endpoint_actor_omni = <the gateway actor>`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use agentkeys_backend_client::protocol::{
    ChannelEndpointKind, GatewayDevicePairingDone, GatewayDevicePairingStart, GatewayDeviceStatus,
};

use crate::console_device::{device_accept_build, device_accept_submit, nominal_device_scope};
use crate::ui_bridge::{
    ensure_channel_endpoint_row, gateway_admin_call, invalidate_fleet_sync, now_unix, pairing_err,
    upsert_binding_manifest_entry, BindingManifestEntry, SharedUiBridgeState, UiBridgeState,
};

/// What the daemon keeps between the claim and the on-chain confirm.
#[derive(Debug, Clone)]
pub(crate) struct GatewayEnrollPending {
    pub request_id: String,
    pub label: String,
    pub child_omni: String,
    pub device_key_hash: String,
    pub transport: String,
}

/// The channel-registry row name for a transport namespace.
pub(crate) fn transport_display_name(transport: &str) -> String {
    match transport {
        "weixin" => "微信 · WeChat".to_string(),
        "telegram" => "Telegram".to_string(),
        other => other.to_string(),
    }
}

/// The device label the gateway's actor is claimed under.
pub(crate) fn gateway_label(transport: &str) -> String {
    let t: String = transport
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(20)
        .collect();
    if t.is_empty() {
        "gateway".to_string()
    } else {
        format!("gateway-{t}")
    }
}

pub(crate) async fn fetch_device_status(
    state: &UiBridgeState,
) -> Result<GatewayDeviceStatus, String> {
    let v = gateway_admin_call(
        state,
        reqwest::Method::GET,
        "/v1/gateway/admin/device/status",
        None,
    )
    .await?;
    serde_json::from_value(v).map_err(|e| format!("contact gate device status parse: {e}"))
}

/// The gateway's pairing request (its K10 mints the code at the broker).
pub(crate) async fn gateway_pairing_start(
    state: &UiBridgeState,
) -> Result<GatewayDevicePairingStart, String> {
    let v = gateway_admin_call(
        state,
        reqwest::Method::POST,
        "/v1/gateway/admin/device/pairing-request",
        Some(serde_json::json!({})),
    )
    .await?;
    serde_json::from_value(v).map_err(|e| format!("pairing-request parse: {e}"))
}

/// After the binding CONFIRMED on chain: the gateway proves it from its side,
/// the manifest + the messaging endpoint row are written, the fleet view is
/// invalidated. Returns the receipt.
pub(crate) async fn finish_gateway_enrollment(
    state: &UiBridgeState,
    pending: &GatewayEnrollPending,
) -> Result<serde_json::Value, String> {
    let done: GatewayDevicePairingDone = gateway_admin_call(
        state,
        reqwest::Method::POST,
        "/v1/gateway/admin/device/pairing-complete",
        Some(serde_json::json!({ "request_id": pending.request_id })),
    )
    .await
    .and_then(|v| serde_json::from_value(v).map_err(|e| format!("pairing-complete parse: {e}")))
    .map_err(|e| {
        format!(
            "the binding is CONFIRMED on chain but the contact gate could not complete its pairing \
             ({e}) — retry the contact gate's device status once the broker's pairing row settles"
        )
    })?;
    // The canonical `0x` form (`normalize_omni_0x`): the gate reports the omni
    // the claim relayed, which is BARE hex — a manifest row and every cap-mint
    // body carry the prefixed form.
    let actor_omni =
        agentkeys_backend_client::normalize_omni_0x(if done.actor_omni.trim().is_empty() {
            pending.child_omni.trim()
        } else {
            done.actor_omni.trim()
        });
    upsert_binding_manifest_entry(
        state,
        BindingManifestEntry {
            actor_omni: actor_omni.clone(),
            device_key_hash: pending.device_key_hash.clone(),
            label: pending.label.clone(),
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
    ensure_channel_endpoint_row(
        state,
        &pending.transport,
        &transport_display_name(&pending.transport),
        ChannelEndpointKind::Messaging,
        &actor_omni,
    )
    .await;
    *state.gateway_enroll_pending.write().await = None;
    invalidate_fleet_sync(state);
    tracing::info!(actor = %actor_omni, transport = %pending.transport, "#667 contact gate ENROLLED as a device actor");
    Ok(serde_json::json!({
        "ok": true,
        "actor_omni": actor_omni,
        "label": pending.label,
        "transport": pending.transport,
        "channel_id": pending.transport,
        "device_key_hash": done.device_key_hash,
        "session_proven": done.session_proven,
    }))
}

/// Keep the messaging endpoint row current with the gateway's actor —
/// throttled to once a minute (called from the status proxy the web app
/// polls). Best-effort, loud.
pub(crate) async fn sync_endpoint_row(state: &UiBridgeState) {
    use std::sync::atomic::Ordering;
    let now = now_unix();
    let last = state.gateway_endpoint_synced_at.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 60 {
        return;
    }
    state
        .gateway_endpoint_synced_at
        .store(now, Ordering::Relaxed);
    match fetch_device_status(state).await {
        Ok(st) => {
            if let Some(actor) = st.actor_omni.as_deref().filter(|a| !a.is_empty()) {
                if !st.transport.is_empty() {
                    ensure_channel_endpoint_row(
                        state,
                        &st.transport,
                        &transport_display_name(&st.transport),
                        ChannelEndpointKind::Messaging,
                        actor,
                    )
                    .await;
                }
            }
        }
        Err(e) => tracing::debug!(
            target: "agentkeys.daemon.ui_bridge",
            "contact gate endpoint row sync skipped ({e})"
        ),
    }
}

/// GET /v1/master/gateway/device — the gateway's device-actor status (and the
/// endpoint row upsert when it is enrolled).
pub async fn gateway_device_status(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    match fetch_device_status(&state).await {
        Ok(st) => {
            if let Some(actor) = st.actor_omni.as_deref().filter(|a| !a.is_empty()) {
                if !st.transport.is_empty() {
                    ensure_channel_endpoint_row(
                        &state,
                        &st.transport,
                        &transport_display_name(&st.transport),
                        ChannelEndpointKind::Messaging,
                        actor,
                    )
                    .await;
                }
            }
            (StatusCode::OK, Json(st)).into_response()
        }
        Err(e) => pairing_err(
            StatusCode::BAD_GATEWAY,
            &format!("contact gate device: {e}"),
        ),
    }
}

/// POST /v1/master/gateway/device/enroll/build — the STANDALONE ceremony (an
/// install that binds the gateway's transport enrolls it in ITS batch
/// instead): the gateway mints its pairing code, the master claims it
/// (`gateway-<transport>`) and builds the accept.
pub async fn gateway_enroll_build(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let status = match fetch_device_status(&state).await {
        Ok(s) => s,
        Err(e) => {
            return pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("contact gate device: {e}"),
            )
        }
    };
    if !status.configured {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "the contact gate has no device configuration (AGENTKEYS_BROKER_URL + \
             AGENTKEYS_WEIXIN_DEVICE_KEY_FILE on the contact gate unit) — converge the broker host",
        );
    }
    if status.enrolled {
        return pairing_err(
            StatusCode::CONFLICT,
            &format!(
                "the contact gate is already enrolled as {}",
                status.actor_omni.unwrap_or_default()
            ),
        );
    }
    let start = match gateway_pairing_start(&state).await {
        Ok(s) => s,
        Err(e) => {
            return pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("contact gate pairing request: {e}"),
            )
        }
    };
    let label = gateway_label(&status.transport);
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
    *state.gateway_enroll_pending.write().await = Some(GatewayEnrollPending {
        request_id: start.request_id.clone(),
        label: label.clone(),
        child_omni: built.child_omni.clone(),
        device_key_hash: start.device_key_hash.clone(),
        transport: status.transport.clone(),
    });
    let mut out = built.build;
    out["label"] = serde_json::json!(label);
    out["actor_omni"] = serde_json::json!(built.child_omni);
    out["transport"] = serde_json::json!(status.transport);
    out["device_key_hash"] = serde_json::json!(start.device_key_hash);
    (StatusCode::OK, Json(out)).into_response()
}

/// POST /v1/master/gateway/device/enroll/submit — submit the signed accept,
/// ack, let the gateway prove the binding, write the endpoint row.
pub async fn gateway_enroll_submit(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(r) = crate::ui_bridge::require_master_session(&state).await {
        return r;
    }
    let Some(pending) = state.gateway_enroll_pending.read().await.clone() else {
        return pairing_err(
            StatusCode::CONFLICT,
            "no contact gate enrollment in flight — run build first",
        );
    };
    if let Err(resp) = device_accept_submit(&state, &pending.request_id, body).await {
        return resp;
    }
    match finish_gateway_enrollment(&state, &pending).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => pairing_err(StatusCode::BAD_GATEWAY, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_names_follow_the_transport() {
        assert_eq!(gateway_label("weixin"), "gateway-weixin");
        assert_eq!(gateway_label("telegram"), "gateway-telegram");
        assert_eq!(gateway_label(""), "gateway");
        assert!(agentkeys_backend_client::protocol::is_valid_label(
            &gateway_label("weixin")
        ));
        assert_eq!(transport_display_name("telegram"), "Telegram");
    }

    /// Without a master session the status read is refused; with one but no
    /// contact gate wired (a loopback broker derives no gate URL) it answers
    /// 502 naming the gate, and the enroll build refuses the same way.
    #[tokio::test]
    async fn status_and_enroll_refuse_without_a_session_or_a_gate() {
        use axum::extract::State;
        let state = crate::ui_bridge::build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some("http://127.0.0.1:9".into()),
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
        let resp = gateway_device_status(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        *state.onboarding_session.write().await = Some(crate::ui_bridge::OnboardingSession {
            email: "owner@example.test".into(),
            omni: format!("0x{}", "ab".repeat(32)),
            j1: "test-j1".into(),
            wallet: format!("0x{}", "11".repeat(20)),
            identity_only_reason: None,
        });
        let resp = gateway_device_status(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("contact gate"), "{text}");
        let resp = gateway_enroll_build(State(state)).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
