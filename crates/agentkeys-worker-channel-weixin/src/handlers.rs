//! Gateway HTTP surface — the WeChat callback + the D13 history refusal.
//!
//! - `GET  /wechat/callback`  — the 公众号 echo verification (returns `echostr`
//!   iff the signature checks out).
//! - `POST /wechat/callback`  — the inbound relay: verify → resolve contact →
//!   L3 → route → build the worker-stamped `ChannelEvent` (producer = contact) →
//!   audit. Accepts WeChat XML (real) or JSON `{from,text}` (the mock e2e).
//! - `GET  /v1/gateway/history` — ALWAYS 403 `contact_history_denied` (D13:
//!   contacts have zero feed-history visibility — the refusal is explicit, not a
//!   confusing 404).
//! - `GET  /healthz`.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admin;
use crate::relay;
use crate::signature;
use crate::state::SharedWeixinGatewayState;

pub fn build_router(state: SharedWeixinGatewayState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/wechat/callback",
            get(callback_verify).post(callback_relay),
        )
        .route("/v1/gateway/history", get(history_denied))
        .route("/v1/gateway/contacts", get(list_contacts))
        // #418 — the operator admin surface (parent-control via the daemon
        // proxy). Every route is admin-bearer-gated inside `admin`.
        .route("/v1/gateway/admin/status", get(admin::admin_status))
        .route("/v1/gateway/admin/login/start", post(admin::login_start))
        .route("/v1/gateway/admin/login/status", get(admin::login_status))
        .route("/v1/gateway/admin/login/verify", post(admin::login_verify))
        .route(
            "/v1/gateway/admin/login/disconnect",
            post(admin::login_disconnect),
        )
        .route("/v1/gateway/admin/bind/invite", post(admin::bind_invite))
        .route("/v1/gateway/admin/bind/pending", get(admin::bind_pending))
        .route("/v1/gateway/admin/bind/approve", post(admin::bind_approve))
        .route("/v1/gateway/admin/bind/reject", post(admin::bind_reject))
        .route("/v1/gateway/admin/contacts", get(admin::admin_contacts))
        .route("/v1/gateway/admin/monitor", get(admin::monitor))
        .route("/v1/gateway/admin/history", get(admin::history))
        .route("/v1/gateway/admin/activity", get(admin::activity))
        .route(
            "/v1/gateway/admin/contacts/update",
            post(admin::contacts_update),
        )
        .route(
            "/v1/gateway/admin/contacts/revoke",
            post(admin::contacts_revoke),
        )
        // #424 §2 — the durable-copy surface: the daemon exports the FULL
        // registry into the master-only Config-class doc after every mutation,
        // and imports it back onto an EMPTY (rebuilt) gateway host.
        .route(
            "/v1/gateway/admin/registry/export",
            get(admin::registry_export),
        )
        .route(
            "/v1/gateway/admin/registry/import",
            post(admin::registry_import),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub transport: &'static str,
    pub bound_contacts: usize,
    pub outbound_enabled: bool,
    /// iLink only: millis of the last successful long-poll (`null` = never /
    /// OA) — a stale-token stall shows up here without log access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ilink_last_ok_ms: Option<u64>,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedWeixinGatewayState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        transport: state.config.transport.as_str(),
        bound_contacts: state.registry.snapshot().bound.len(),
        outbound_enabled: state.outbound_enabled(),
        ilink_last_ok_ms: state.ilink_last_ok_ms(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub echostr: String,
}

/// `GET /wechat/callback` — the one-time 公众号 server-config echo verification.
async fn callback_verify(
    State(state): State<SharedWeixinGatewayState>,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    if state.config.allow_unsigned
        || signature::verify(
            &state.config.weixin_token,
            &q.signature,
            &q.timestamp,
            &q.nonce,
        )
    {
        (StatusCode::OK, q.echostr).into_response()
    } else {
        (StatusCode::FORBIDDEN, "signature check failed").into_response()
    }
}

/// D13: contacts have ZERO feed-history visibility. The refusal is an explicit
/// 403 (not a 404) so an operator/auditor can see the invariant is enforced, not
/// merely absent.
async fn history_denied() -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "ok": false,
            "reason": "contact_history_denied",
            "detail": "contacts have no feed-history visibility (D13); ask an agent, which \
                       answers from its own memory. All history lives in parent-control only."
        })),
    )
}

/// `GET /v1/gateway/contacts` — the OPERATOR's parent-control read surface (#410).
/// Admin-bearer-gated (never open — 503 when no admin token is configured, 401 on
/// a bad bearer). Returns the D13-SAFE contact view — `(contact_id, display_name,
/// tier, reach)` only, **no openid, no history** — the routing policy the operator
/// manages, never the third-party PII. Per-contact audit is the operator querying
/// the audit worker for this contact's `GatewayRelay` rows (already emitted); the
/// gateway exposes no history endpoint (that IS the D13 invariant).
async fn list_contacts(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = admin::admin_gate(&state, &headers) {
        return resp;
    }
    let registry = state.registry.snapshot();
    let contacts: Vec<agentkeys_protocol::ContactSummary> =
        registry.bound.iter().map(Into::into).collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "contacts": contacts })),
    )
        .into_response()
}

/// `POST /wechat/callback` — the inbound relay.
async fn callback_relay(
    State(state): State<SharedWeixinGatewayState>,
    Query(q): Query<CallbackQuery>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // 1. Transport authenticity (unless the test bypass is on).
    if !state.config.allow_unsigned
        && !signature::verify(
            &state.config.weixin_token,
            &q.signature,
            &q.timestamp,
            &q.nonce,
        )
    {
        return (StatusCode::FORBIDDEN, "signature check failed").into_response();
    }

    // 2. Parse the inbound — WeChat XML (real) or JSON {from,text} (mock e2e).
    let is_json = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("application/json"))
        .unwrap_or(false)
        || body.trim_start().starts_with('{');
    let (openid, text) = if is_json {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => (
                v.get("from")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                v.get("text")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
            ),
            Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
        }
    } else {
        (
            extract_xml_tag(&body, "FromUserName").unwrap_or_default(),
            extract_xml_tag(&body, "Content").unwrap_or_default(),
        )
    };

    // 3-5. The shared relay core (L3 → routed event → audit) — the SAME path the
    //      iLink loop drives (`relay::process_inbound`).
    let outcome = relay::process_inbound(&state, &openid, &text).await;

    // 6. Reply. Real WeChat wants the plain "success" ack (the agent's reply
    //    comes back async via the outbound send path, which needs the app-secret
    //    — the live proof). The mock e2e reads the JSON decision.
    if is_json {
        (
            StatusCode::OK,
            Json(json!({
                "ok": outcome.decision.allowed,
                "decision": outcome.decision,
                "contact_id": outcome.contact_id,
                "tier": outcome.tier,
                "routed_event": outcome.event,
            })),
        )
            .into_response()
    } else {
        (StatusCode::OK, "success").into_response()
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Extract `<Tag><![CDATA[value]]></Tag>` or `<Tag>value</Tag>` from a WeChat XML
/// message. Minimal (text messages only) — no XML dependency.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let inner = xml[start..end].trim();
    let inner = inner
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
        .unwrap_or(inner);
    Some(inner.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_xml_tag_handles_cdata_and_plain() {
        let xml = "<xml><FromUserName><![CDATA[openid-abc]]></FromUserName>\
                   <Content><![CDATA[/chef 晚饭]]></Content></xml>";
        assert_eq!(
            extract_xml_tag(xml, "FromUserName").as_deref(),
            Some("openid-abc")
        );
        assert_eq!(
            extract_xml_tag(xml, "Content").as_deref(),
            Some("/chef 晚饭")
        );
        let plain = "<xml><Content>hello</Content></xml>";
        assert_eq!(extract_xml_tag(plain, "Content").as_deref(), Some("hello"));
        assert!(extract_xml_tag(xml, "Missing").is_none());
    }
}
