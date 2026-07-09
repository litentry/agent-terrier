//! The OPERATOR admin surface (#418) — parent-control drives these through the
//! daemon proxy (`/v1/master/gateway/*` → `/v1/gateway/admin/*` here). Every
//! endpoint is admin-bearer-gated (constant-time compare; 503 when no token is
//! configured — never open). Two ceremonies live here:
//!
//! 1. **Login** — the iLink QR ceremony over HTTP: `login/start` mints a QR the
//!    app renders, `login/status` drives one server-held poll step per call,
//!    `login/verify` supplies the on-phone pairing number. On `confirmed` the
//!    worker WRITES ITS OWN secrets file (#384 custody stays on this host) and
//!    hot-swaps the inbound loop — no process restart, no laptop.
//! 2. **Bind** — the D5 contact ceremony: `bind/invite` mints a one-time code
//!    for a family member (the app shows it as QR + text), the member echoes it
//!    to the bot (the relay claims it), `bind/pending` shows the D13-safe queue
//!    (bind_code-keyed, NEVER the openid), `bind/approve` is the master's
//!    confirm that actually binds. The model may PROPOSE; only the master's
//!    invite + approve decide (D10).

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use agentkeys_core::audit::{envelope_for, AuditOpKind, AuditResult, ContactBindBody};
use agentkeys_protocol::{
    BindInvite, Contact, GatewayApproveRequest, GatewayApproveResponse, GatewayBindInviteRequest,
    GatewayBindInviteResponse, GatewayContactsResponse, GatewayLoginStartResponse,
    GatewayLoginStatusResponse, GatewayLoginVerifyRequest, GatewayPendingBindView,
    GatewayStatusView, PendingBind, TierProposal,
};

use crate::config::WeixinTransport;
use crate::ilink::IlinkClient;
use crate::ilink_login::{self, LoginOutcome};
use crate::state::{AdminLogin, SharedWeixinGatewayState};

/// Constant-time bearer compare (avoid a timing oracle on the admin token).
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The shared admin gate: `Ok(())` iff a token is configured AND the bearer
/// matches. 503 (never open) / 401 otherwise. The `Err` IS the ready-to-return
/// refusal response — the by-value `Response` is deliberate (every caller
/// returns it immediately), so the size lint doesn't buy anything here.
#[allow(clippy::result_large_err)]
pub(crate) fn admin_gate(
    state: &SharedWeixinGatewayState,
    headers: &HeaderMap,
) -> Result<(), axum::response::Response> {
    let Some(expected) = state.config.admin_token.as_deref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "reason": "admin_disabled",
                "detail": "set AGENTKEYS_WEIXIN_ADMIN_TOKEN to enable the operator admin surface"
            })),
        )
            .into_response());
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !ct_eq(presented, expected) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "reason": "admin_unauthorized"})),
        )
            .into_response());
    }
    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

/// `GET /v1/gateway/admin/status` — the parent-control gateway card.
pub(crate) async fn admin_status(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    let reg = state.registry.snapshot();
    let pending_binds = reg.pending.len() as u32;
    let open_invites = reg
        .invites
        .iter()
        .filter(|i| !reg.pending.iter().any(|p| p.bind_code == i.bind_code))
        .count() as u32;
    let body = GatewayStatusView {
        ok: true,
        transport: match state.config.transport {
            WeixinTransport::Oa => "oa".to_string(),
            WeixinTransport::Ilink => "ilink".to_string(),
        },
        online: state.ilink_online(),
        bot_id: state.current_ilink_bot_id(),
        bound_contacts: reg.bound.len() as u32,
        open_invites,
        pending_binds,
        ilink_last_ok_ms: state.ilink_last_ok_ms(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

// ── login ceremony over HTTP ──────────────────────────────────────────────────

/// `POST /v1/gateway/admin/login/start` — mint the QR. A new start replaces any
/// in-flight session (the old QR goes stale server-side anyway).
pub(crate) async fn login_start(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    if state.config.transport != WeixinTransport::Ilink {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "reason": "transport_not_ilink",
                "detail": "the QR login ceremony is the iLink transport's; this gateway runs `oa`"
            })),
        )
            .into_response();
    }
    // Present the current token so an already-bound account reports
    // `binded_redirect` instead of double-binding. The QR always boots from the
    // FIXED bootstrap host (config; env-overridable for the headless e2e).
    let local_tokens: Vec<String> = state.current_ilink_token().into_iter().collect();
    let bootstrap = state.config.ilink_bootstrap_url.clone();
    let client = IlinkClient::new(&bootstrap, None, &state.config.bot_agent);
    match client.get_bot_qrcode(&local_tokens).await {
        Ok(qr) => {
            let login = AdminLogin {
                login_id: format!("login-{:x}", now_nanos()),
                qrcode: qr.qrcode,
                qrcode_url: qr.qrcode_img_content.clone(),
                base_url: bootstrap,
                pending_verify: None,
            };
            let resp = GatewayLoginStartResponse {
                ok: true,
                login_id: login.login_id.clone(),
                qrcode_url: qr.qrcode_img_content,
            };
            *state.admin_login.lock().await = Some(login);
            info!("admin login ceremony started (QR minted)");
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "reason": "qrcode_mint_failed", "detail": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginStatusQuery {
    pub login_id: String,
}

/// `GET /v1/gateway/admin/login/status?login_id=` — ONE server-held poll step
/// (up to ~35 s). The app loops on this until a terminal status.
pub(crate) async fn login_status(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
    Query(q): Query<LoginStatusQuery>,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    // Snapshot the session WITHOUT holding the lock across the long poll (the
    // verify endpoint needs the lock while we wait).
    let snapshot = { state.admin_login.lock().await.clone() };
    let Some(login) = snapshot.filter(|l| l.login_id == q.login_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "reason": "no_active_login"})),
        )
            .into_response();
    };

    let client = IlinkClient::new(&login.base_url, None, &state.config.bot_agent);
    let status = client
        .get_qrcode_status(&login.qrcode, login.pending_verify.as_deref())
        .await;

    let reply = |status: &str,
                 bot_id: Option<String>,
                 scanned_by: Option<String>,
                 detail: Option<String>| {
        Json(GatewayLoginStatusResponse {
            ok: true,
            status: status.to_string(),
            bot_id,
            scanned_by,
            detail,
        })
        .into_response()
    };

    match status.status.as_str() {
        "wait" => reply("wait", None, None, None),
        "scaned" => {
            // A carried verify code was accepted — clear it.
            if login.pending_verify.is_some() {
                let mut guard = state.admin_login.lock().await;
                if let Some(l) = guard.as_mut().filter(|l| l.login_id == q.login_id) {
                    l.pending_verify = None;
                }
            }
            reply("scaned", None, None, None)
        }
        "scaned_but_redirect" => {
            if let Some(host) = status.redirect_host.filter(|h| !h.is_empty()) {
                let mut guard = state.admin_login.lock().await;
                if let Some(l) = guard.as_mut().filter(|l| l.login_id == q.login_id) {
                    l.base_url = format!("https://{host}");
                }
            }
            reply("scaned", None, None, None)
        }
        "need_verifycode" => {
            let detail = if login.pending_verify.is_some() {
                // The carried code was WRONG — clear it and re-prompt.
                let mut guard = state.admin_login.lock().await;
                if let Some(l) = guard.as_mut().filter(|l| l.login_id == q.login_id) {
                    l.pending_verify = None;
                }
                Some("verify_code_rejected — 请重新输入手机上显示的数字".to_string())
            } else {
                Some("输入手机微信显示的数字以继续".to_string())
            };
            reply("need_verifycode", None, None, detail)
        }
        "verify_code_blocked" => {
            *state.admin_login.lock().await = None;
            reply(
                "verify_code_blocked",
                None,
                None,
                Some("多次输入错误 — 稍后重新发起连接".to_string()),
            )
        }
        "expired" => {
            *state.admin_login.lock().await = None;
            reply(
                "expired",
                None,
                None,
                Some("二维码已过期 — 重新点击连接生成新码".to_string()),
            )
        }
        "binded_redirect" => {
            *state.admin_login.lock().await = None;
            reply(
                "already_bound",
                None,
                None,
                Some("该账号已绑定此网关，沿用现有 token（如需换发请先在微信侧解绑）".to_string()),
            )
        }
        "confirmed" => {
            // Upstream-plugin parity: a confirmed WITHOUT ilink_bot_id is a
            // HALF-BIND (the on-phone authorize didn't finish) — refuse loudly.
            let Some(bot_id) = status.ilink_bot_id.clone().filter(|b| !b.is_empty()) else {
                *state.admin_login.lock().await = None;
                return reply(
                    "failed",
                    None,
                    None,
                    Some(
                        "服务器返回 confirmed 但缺少 ilink_bot_id — 请在手机上点\
                         “连接/授权”完成绑定后重新发起"
                            .to_string(),
                    ),
                );
            };
            let Some(bot_token) = status.bot_token.clone().filter(|t| !t.is_empty()) else {
                *state.admin_login.lock().await = None;
                return reply(
                    "failed",
                    None,
                    None,
                    Some("confirmed 但服务器未返回 bot_token".to_string()),
                );
            };
            let base_url = status
                .baseurl
                .clone()
                .filter(|b| !b.is_empty())
                .unwrap_or_else(|| login.base_url.clone());
            let scanned_by = status.ilink_user_id.clone().unwrap_or_default();

            // #384 custody: the worker persists its OWN secrets file in place.
            let outcome = LoginOutcome {
                bot_token: bot_token.clone(),
                base_url: base_url.clone(),
                bot_id: bot_id.clone(),
                scanned_by: scanned_by.clone(),
            };
            let mut detail = None;
            let secrets_path = std::path::Path::new(&state.config.secrets_file);
            match ilink_login::write_secrets_file(secrets_path, &outcome) {
                Ok(rebound) => info!(
                    path = %state.config.secrets_file,
                    rebound,
                    "admin login confirmed — secrets file upserted"
                ),
                Err(e) => {
                    warn!(error = %e, "admin login confirmed but the secrets-file write FAILED — \
                          the bot is online for THIS process only (a restart loses the token)");
                    detail = Some(format!(
                        "secrets_write_failed: {e} — bot 在线，但重启会丢失 token；\
                         检查 {} 的属主/权限",
                        state.config.secrets_file
                    ));
                }
            }

            // Hot-swap the runtime identity → the supervisor restarts the loop.
            state.set_ilink_identity(bot_token, base_url, bot_id.clone());
            *state.admin_login.lock().await = None;
            reply("connected", Some(bot_id), Some(scanned_by), detail)
        }
        other => reply(
            "wait",
            None,
            None,
            Some(format!("unrecognized status `{other}`")),
        ),
    }
}

/// `POST /v1/gateway/admin/login/verify` — carry the on-phone pairing number.
pub(crate) async fn login_verify(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
    Json(req): Json<GatewayLoginVerifyRequest>,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    let mut guard = state.admin_login.lock().await;
    match guard.as_mut().filter(|l| l.login_id == req.login_id) {
        Some(login) => {
            login.pending_verify = Some(req.verify_code.trim().to_string());
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "reason": "no_active_login"})),
        )
            .into_response(),
    }
}

// ── bind ceremony (D5) ────────────────────────────────────────────────────────

/// `POST /v1/gateway/admin/bind/invite` — mint a one-time invite for a family
/// member. Idempotent-ish: re-inviting the same `contact_id` replaces the open
/// invite (a stale unclaimed code stops working).
pub(crate) async fn bind_invite(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
    Json(req): Json<GatewayBindInviteRequest>,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    if req.contact_id.trim().is_empty() || req.display_name.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"ok": false, "reason": "missing_contact_id_or_display_name"})),
        )
            .into_response();
    }
    // L3 rule, enforced at mint too: only `owner` may hold operator-grade reach.
    if !req.tier.may_hold_operator_grade_reach() {
        if let Some(bad) = req
            .reach
            .iter()
            .find(|a| state.config.operator_grade_aliases.contains(a))
        {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "ok": false,
                    "reason": "operator_grade_reach_denied",
                    "detail": format!("`{bad}` is operator-grade — only the owner tier may hold it")
                })),
            )
                .into_response();
        }
    }

    let result = state.registry.mutate(|reg| {
        let mut code;
        let mut salt = 0u64;
        loop {
            code = mint_bind_code(salt);
            if !reg.invites.iter().any(|i| i.bind_code == code)
                && !reg.pending.iter().any(|p| p.bind_code == code)
            {
                break;
            }
            salt += 1;
        }
        // Replace any open invite for the same contact_id (stale code dies).
        reg.invites.retain(|i| i.contact_id != req.contact_id);
        reg.invites.push(BindInvite {
            bind_code: code.clone(),
            contact_id: req.contact_id.clone(),
            display_name: req.display_name.clone(),
            tier: req.tier,
            reach: req.reach.clone(),
        });
        Ok(code)
    });
    match result {
        Ok(code) => {
            info!(contact_id = %req.contact_id, "bind invite minted");
            let resp = GatewayBindInviteResponse {
                ok: true,
                bind_code: code.clone(),
                send_text: format!("绑定 {code}"),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "reason": "registry_write_failed", "detail": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /v1/gateway/admin/bind/pending` — the D13-safe approve queue.
pub(crate) async fn bind_pending(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    let reg = state.registry.snapshot();
    let views: Vec<GatewayPendingBindView> = reg
        .invites
        .iter()
        .map(|i| GatewayPendingBindView {
            bind_code: i.bind_code.clone(),
            contact_id: i.contact_id.clone(),
            display_name: i.display_name.clone(),
            tier: i.tier,
            reach: i.reach.clone(),
            claimed: reg.pending.iter().any(|p| p.bind_code == i.bind_code),
        })
        .collect();
    (StatusCode::OK, Json(json!({"ok": true, "pending": views}))).into_response()
}

/// `POST /v1/gateway/admin/bind/approve` — the master's confirm (the actual
/// bind). Requires a CLAIMED invite; tier/reach overrides re-run the
/// operator-grade guard.
pub(crate) async fn bind_approve(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
    Json(req): Json<GatewayApproveRequest>,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    let approved: anyhow::Result<Contact> = state.registry.mutate(|reg| {
        let invite = reg
            .invites
            .iter()
            .find(|i| i.bind_code.eq_ignore_ascii_case(&req.bind_code))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("bind_code_unknown"))?;
        let pending = reg
            .pending
            .iter()
            .find(|p| p.bind_code.eq_ignore_ascii_case(&req.bind_code))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("bind_not_claimed"))?;

        let tier = req.tier.unwrap_or(invite.tier);
        let reach = req.reach.clone().unwrap_or_else(|| invite.reach.clone());
        if !tier.may_hold_operator_grade_reach() {
            if let Some(bad) = reach
                .iter()
                .find(|a| state.config.operator_grade_aliases.contains(a))
            {
                anyhow::bail!("operator_grade_reach_denied:{bad}");
            }
        }

        let contact = Contact {
            contact_id: invite.contact_id.clone(),
            transport: pending.transport.clone(),
            transport_id: pending.transport_id.clone(),
            display_name: invite.display_name.clone(),
            tier,
            reach,
        };
        // Rebind-safe: replace any bound row with the same contact_id OR the
        // same transport identity.
        reg.bound.retain(|c| {
            c.contact_id != contact.contact_id
                && !(c.transport == contact.transport && c.transport_id == contact.transport_id)
        });
        reg.bound.push(contact.clone());
        reg.invites
            .retain(|i| !i.bind_code.eq_ignore_ascii_case(&req.bind_code));
        reg.pending
            .retain(|p| !p.bind_code.eq_ignore_ascii_case(&req.bind_code));
        Ok(contact)
    });

    match approved {
        Ok(contact) => {
            emit_contact_bind_audit(&state, &contact, "bound").await;
            info!(contact_id = %contact.contact_id, tier = contact.tier.as_str(), "contact BOUND (master approve)");
            let resp = GatewayApproveResponse {
                ok: true,
                contact: (&contact).into(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            let (code, reason) = match msg.as_str() {
                "bind_code_unknown" => (StatusCode::NOT_FOUND, "bind_code_unknown"),
                "bind_not_claimed" => (StatusCode::CONFLICT, "bind_not_claimed"),
                m if m.starts_with("operator_grade_reach_denied") => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "operator_grade_reach_denied",
                ),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "registry_write_failed"),
            };
            (
                code,
                Json(json!({"ok": false, "reason": reason, "detail": msg})),
            )
                .into_response()
        }
    }
}

/// `GET /v1/gateway/admin/contacts` — the typed contacts view (the #410
/// endpoint's admin-path twin; same D13-safe payload).
pub(crate) async fn admin_contacts(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = admin_gate(&state, &headers) {
        return resp;
    }
    let reg = state.registry.snapshot();
    let body = GatewayContactsResponse {
        ok: true,
        contacts: reg.bound.iter().map(Into::into).collect(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

// ── claim (called by the RELAY on an unknown sender echoing a code) ──────────

/// Try to claim an open invite with an unknown sender's message text. Returns
/// the ack reply on success (`None` = not a bind attempt → stay silent, §9
/// threat 1). The code may be bare or prefixed (`绑定 AK-…` / `bind AK-…`).
pub(crate) fn try_claim_bind(
    state: &crate::state::WeixinGatewayState,
    transport: &str,
    transport_id: &str,
    text: &str,
) -> Option<String> {
    let token = text
        .trim()
        .trim_start_matches("绑定")
        .trim_start_matches("bind")
        .trim_start_matches("BIND")
        .trim();
    if token.is_empty() {
        return None;
    }
    let snapshot = state.registry.snapshot();
    let invite = snapshot
        .invites
        .iter()
        .find(|i| i.bind_code.eq_ignore_ascii_case(token))?
        .clone();

    let claim = state.registry.mutate(|reg| {
        // Latest claim wins (a mistyped scan from the wrong phone is fixed by
        // re-sending from the right one before the master approves).
        reg.pending.retain(|p| p.bind_code != invite.bind_code);
        reg.pending.push(PendingBind {
            transport: transport.to_string(),
            transport_id: transport_id.to_string(),
            bind_code: invite.bind_code.clone(),
            proposal: Some(TierProposal {
                tier: invite.tier,
                reach: invite.reach.clone(),
                rationale: format!("operator invite for {}", invite.display_name),
            }),
        });
        Ok(())
    });
    match claim {
        Ok(()) => {
            info!(contact_id = %invite.contact_id, "bind code CLAIMED — awaiting master approve");
            Some(format!(
                "✅ 已收到绑定码（{}）。等待管理员在家长控制台确认后即可使用。",
                invite.display_name
            ))
        }
        Err(e) => {
            warn!(error = %e, "bind claim registry write failed");
            None
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// A short, unambiguous one-time code: `AK-` + 6 chars from an alphabet with no
/// confusables (no 0/O/1/I). Not a lone security boundary — one-time, replaced
/// on re-invite, and the master's approve gates the actual bind.
fn mint_bind_code(salt: u64) -> String {
    use sha3::{Digest, Keccak256};
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut h = Keccak256::new();
    h.update(now_nanos().to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(salt.to_le_bytes());
    let digest = h.finalize();
    let chars: String = digest
        .iter()
        .take(6)
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    format!("AK-{chars}")
}

async fn emit_contact_bind_audit(
    state: &crate::state::WeixinGatewayState,
    contact: &Contact,
    outcome: &str,
) {
    let Some(audit) = state.audit.as_ref() else {
        return;
    };
    let Some(op_omni) = crate::relay::decode_omni_32(&state.config.operator_omni) else {
        warn!("operator omni not 32-byte hex — skipping contact-bind audit");
        return;
    };
    let body = ContactBindBody {
        transport: contact.transport.clone(),
        contact_id: contact.contact_id.clone(),
        outcome: outcome.to_string(),
        tier: contact.tier.as_str().to_string(),
        reach_count: contact.reach.len() as u32,
    };
    match envelope_for(
        op_omni,
        op_omni,
        AuditOpKind::ContactBind,
        body,
        AuditResult::Success,
        None,
        None,
    ) {
        Ok(env) => {
            if let Err(e) = audit.append(&env).await {
                warn!(error = %e, "contact-bind audit append failed (best-effort)");
            }
        }
        Err(e) => warn!(error = %e, "contact-bind envelope build failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_codes_use_the_safe_alphabet_and_vary_by_salt() {
        let a = mint_bind_code(0);
        let b = mint_bind_code(1);
        for code in [&a, &b] {
            assert!(code.starts_with("AK-") && code.len() == 9, "{code}");
            assert!(code[3..]
                .chars()
                .all(|c| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c)));
        }
        assert_ne!(a, b, "salt must vary the code");
    }

    #[test]
    fn ct_eq_matches_only_equal_strings() {
        assert!(ct_eq("secret", "secret"));
        assert!(!ct_eq("secret", "secreT"));
        assert!(!ct_eq("secret", "secre"));
    }
}
