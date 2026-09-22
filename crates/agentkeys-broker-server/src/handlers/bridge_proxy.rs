//! `POST /v1/agent/bridge` — the broker-mediated path to ONE delegate's
//! in-sandbox bridge (#715). The console used to call the veFaaS gateway
//! directly (`agent_url` + `x-faas-instance-name`); that gateway now demands
//! the function's secret token, which is STACK-WIDE (one token, every
//! household's sandboxes) and therefore never leaves the broker host. The
//! broker holds it, and it also derives the per-delegate in-pod bearer
//! (`sandbox_bridge_token`) the bridge's chat/context routes require — so the
//! console (any J1_master holder) reaches exactly the delegates it OWNS, on
//! exactly the bridge routes the console needs, and nothing else.
//!
//! Authority chain per request: J1 session (operator match) → on-chain
//! ownership + tier probe of `device_key_hash` (D1: the chain is the registry;
//! the broker keeps no per-operator delegate index) → the delegate's LIVE
//! instance (the named one when given, else the live one) → the allowlisted
//! path → forward through the backend's routing headers (+ the gateway
//! credential) with the derived bridge bearer → the upstream's status + JSON
//! body verbatim. The `/v1/sandbox/mgmt/*` surface is deliberately NOT
//! reachable here: the runtime-home export/import is the broker's own #577
//! business under its own token. The request shape is
//! [`agentkeys_protocol::BridgeProxyBody`] — ONE owner for the console side
//! and this side (D7).

use agentkeys_protocol::BridgeProxyBody;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::handlers::accept::{aerr, load_accept_config};
use crate::handlers::update::{auth_session, probe_owned_delegate};
use crate::state::SharedState;

/// The bridge routes a console may reach through the broker. Everything else
/// (the mgmt surface above all) is refused before any instance is looked up.
const ALLOWED_PATHS: [&str; 6] = [
    "/healthz",
    "/v1/chat",
    "/v1/jobs",
    "/v1/agent/restart",
    "/v1/context/files",
    "/v1/context/apply",
];

/// A chat turn can legitimately run for minutes; everything else is quick.
const CHAT_TIMEOUT_SECS: u64 = 190;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Pure request validation: the method + path allowlist.
pub(crate) fn validate_target(
    method: Option<&str>,
    path: &str,
) -> Result<(reqwest::Method, &'static str), String> {
    let method = match method.map(|m| m.trim().to_ascii_uppercase()) {
        None => reqwest::Method::POST,
        Some(m) if m == "POST" => reqwest::Method::POST,
        Some(m) if m == "GET" => reqwest::Method::GET,
        Some(m) => return Err(format!("method {m:?} is not GET/POST")),
    };
    let path = ALLOWED_PATHS
        .iter()
        .copied()
        .find(|p| *p == path.trim())
        .ok_or_else(|| {
            format!(
                "path {path:?} is not a console-reachable bridge route ({})",
                ALLOWED_PATHS.join(", ")
            )
        })?;
    Ok((method, path))
}

pub async fn agent_bridge(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<BridgeProxyBody>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    let session_omni = auth_session(&state, &headers, &req.operator_omni)?;
    let (method, path) = validate_target(req.method.as_deref(), &req.path)
        .map_err(|e| aerr(StatusCode::BAD_REQUEST, e))?;
    let Some(backend) = state.sandbox.clone() else {
        return Err(aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "no sandbox lifecycle configured on this host — no bridge to reach",
        ));
    };
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

    let live = backend
        .live_for_device(&req.device_key_hash)
        .await
        .map_err(|e| {
            aerr(
                StatusCode::BAD_GATEWAY,
                format!("list live instances: {e:#}"),
            )
        })?;
    let target =
        match req.sandbox_id.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(wanted) => {
                live.iter()
                    .find(|r| r.id == wanted)
                    .map(|r| r.id.clone())
                    .ok_or_else(|| {
                        aerr(
                            StatusCode::CONFLICT,
                            format!(
                        "sandbox {wanted} is not a live instance of this delegate (live: {})",
                        live.iter().map(|r| r.id.as_str()).collect::<Vec<_>>().join(",")
                    ),
                        )
                    })?
            }
            None => live
                .first()
                .map(|r| r.id.clone())
                .ok_or_else(|| aerr(StatusCode::CONFLICT, "no live instance for this delegate"))?,
        };
    let Some((base, route_headers)) = backend.instance_mgmt_endpoint(&target) else {
        return Err(aerr(
            StatusCode::CONFLICT,
            "this backend has no broker-routable bridge path (ECS: the per-task ENI is not \
             guaranteed reachable) — nothing to forward to",
        ));
    };
    let bearer = crate::handlers::sandbox::sandbox_bridge_token(
        &state.session_keypair,
        &req.device_key_hash,
    );

    let timeout = if path == "/v1/chat" {
        CHAT_TIMEOUT_SECS
    } else {
        DEFAULT_TIMEOUT_SECS
    };
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut fwd = state
        .http
        .request(method, &url)
        .bearer_auth(&bearer)
        .timeout(std::time::Duration::from_secs(timeout));
    for (k, v) in &route_headers {
        fwd = fwd.header(k, v);
    }
    if let Some(body) = &req.body {
        fwd = fwd.json(body);
    }
    let resp = fwd.send().await.map_err(|e| {
        aerr(
            StatusCode::BAD_GATEWAY,
            format!("bridge {path} via gateway: transport: {e}"),
        )
    })?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| aerr(StatusCode::BAD_GATEWAY, format!("bridge {path}: body: {e}")))?;
    // The upstream's status + JSON body verbatim (the console's callers judge
    // it — a 503 `starting` healthz is meaningful to them). A non-JSON answer
    // is the gateway's own page while the pod boots: reported, never relayed
    // as if it were the bridge's.
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            let head: String = text.trim().chars().take(200).collect();
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("bridge {path} answered non-JSON (the gateway's own page while the pod boots?)"),
                    "upstream_status": status.as_u16(),
                    "upstream_head": head,
                })),
            )
                .into_response());
        }
    };
    let out = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    Ok((out, Json(value)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_console_bridge_routes_pass_the_allowlist() {
        for p in ALLOWED_PATHS {
            assert!(validate_target(None, p).is_ok(), "{p}");
            assert!(validate_target(Some("get"), p).is_ok(), "{p}");
        }
        // The mgmt surface stays the broker's own; traversal / prefix tricks
        // never match (exact compare).
        for bad in [
            "/v1/sandbox/mgmt/status",
            "/v1/sandbox/mgmt/session/export",
            "/v1/chat/../v1/sandbox/mgmt/status",
            "/v1/chatx",
            "v1/chat",
            "",
        ] {
            assert!(validate_target(None, bad).is_err(), "{bad:?}");
        }
        assert!(validate_target(Some("DELETE"), "/v1/chat").is_err());
        assert_eq!(
            validate_target(Some(" post "), "/v1/chat").unwrap().0,
            reqwest::Method::POST
        );
    }
}
