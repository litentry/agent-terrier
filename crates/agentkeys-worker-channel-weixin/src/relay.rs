//! The transport-NEUTRAL relay core — one inbound turn through the PEP:
//! alias-parse → L3 decide → worker-stamped `ChannelEvent` (allowed turns) →
//! GatewayRelay audit. Both transports converge here: the 公众号 webhook
//! (`handlers::callback_relay`) and the iLink long-poll ([`crate::ilink_loop`]).
//! Adding a transport = a new inbound adapter that calls [`process_inbound`];
//! the L3/registry/router/audit machinery never forks per transport.

use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Keccak256};

use agentkeys_core::audit::{envelope_for, AuditOpKind, AuditResult};
use agentkeys_protocol::{
    parse_alias, ChannelDirection, ChannelEvent, ChannelEventKind, ChannelProducer, GatewayInbound,
    L3Decision,
};

use crate::state::WeixinGatewayState;

/// Everything one inbound turn produced — the decision (for the transport's
/// reply), the resolved contact (for logs/audit), and the routed event.
pub struct RelayOutcome {
    pub inbound: GatewayInbound,
    pub decision: L3Decision,
    pub contact_id: String,
    pub tier: String,
    /// Only on an allowed decision — the worker-stamped event for the target
    /// delegate's feed (producer = the CONTACT, from the registry, never a body
    /// field, §4.1).
    pub event: Option<ChannelEvent>,
    /// #418 bind ceremony: an UNKNOWN sender echoed a live invite code — this
    /// is the in-channel ack (`reason = bind_code_claimed`). The ONE sanctioned
    /// exception to unknown-sender silence (§7.2: the code proves the operator
    /// invited them out-of-band).
    pub claim_ack: Option<String>,
}

/// Run one inbound `(transport_id, text)` turn through L3 + audit for the
/// `weixin` transport family (the OA webhook + iLink callers).
pub async fn process_inbound(
    state: &WeixinGatewayState,
    transport_id: &str,
    raw_text: &str,
) -> RelayOutcome {
    process_inbound_for(state, "weixin", transport_id, raw_text).await
}

/// Run one inbound `(transport, transport_id, text)` turn through L3 + audit.
/// The caller owns transport authenticity (OA signature / iLink bearer session /
/// the Telegram bot-token poll) BEFORE calling; this owns everything after.
/// `transport` is the registry-facing identity namespace (`weixin` | `telegram`,
/// #444) — contacts bind per (transport, transport_id), and the routed event's
/// channel id carries it.
pub async fn process_inbound_for(
    state: &WeixinGatewayState,
    transport: &str,
    transport_id: &str,
    raw_text: &str,
) -> RelayOutcome {
    let (alias, remaining) = parse_alias(raw_text);
    let inbound = GatewayInbound {
        transport: transport.to_string(),
        transport_id: transport_id.to_string(),
        text: remaining,
        alias,
    };

    // L3 (the PEP) — rate check + the pure decision.
    let now_secs = unix_secs();
    let rate_ok = state.rate.check(transport_id, now_secs);
    let registry = state.registry.snapshot();
    let mut decision = crate::l3::decide(&state.config, &registry, &inbound, rate_ok);
    let contact = registry.resolve(&inbound.transport, &inbound.transport_id);
    let (contact_id, tier) = contact
        .map(|c| (c.contact_id.clone(), c.tier.as_str().to_string()))
        .unwrap_or_default();

    // #418 bind ceremony: an unknown sender echoing a LIVE invite code claims
    // it (→ pending, master approves in parent-control). Uses the RAW text —
    // bind codes never start with `/`. Anything else from an unknown sender
    // stays a silent drop.
    let mut claim_ack = None;
    if !decision.allowed && decision.reason == "unknown_contact" {
        if let Some(ack) =
            crate::admin::try_claim_bind(state, &inbound.transport, transport_id, raw_text)
        {
            decision.reason = "bind_code_claimed".to_string();
            claim_ack = Some(ack);
        }
    }

    let event = if decision.allowed {
        Some(ChannelEvent {
            event_id: String::new(), // the channel worker assigns the durable id
            channel_id: format!(
                "{transport}-{}",
                decision.target_alias.clone().unwrap_or_default()
            ),
            direction: ChannelDirection::In,
            producer: ChannelProducer::Contact {
                contact_id: contact_id.clone(),
                tier: tier.clone(),
            },
            kind: ChannelEventKind::Text,
            body: Some(base64_std(inbound.text.as_bytes())),
            body_ref: None,
            ts_millis: now_secs.saturating_mul(1000),
            correlation: None,
        })
    } else {
        None
    };

    emit_relay_audit(state, &inbound, &decision, &contact_id, &tier).await;

    // Live monitor (#1): record this turn for the operator's poll feed. D13-safe
    // — the resolved bound display_name (or "unknown"), NEVER the openid.
    let sender_name = contact
        .map(|c| c.display_name.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let preview: String = raw_text.chars().take(80).collect();
    state.push_monitor_event(
        sender_name,
        if tier.is_empty() {
            "—".to_string()
        } else {
            tier.clone()
        },
        preview,
        decision.allowed,
        decision.reason.clone(),
        decision.target_alias.clone(),
    );

    RelayOutcome {
        inbound,
        decision,
        contact_id,
        tier,
        event,
        claim_ack,
    }
}

/// The in-channel reply for a decision — `None` = SILENT drop (an unknown
/// sender never learns a policy-bearing bot answered, §9 threat 1; a flooding
/// contact gets one terse line, not an amplification loop).
pub fn reply_text_for(decision: &L3Decision) -> Option<String> {
    if decision.allowed {
        return Some(format!(
            "✅ 已转达给 {}",
            decision.target_alias.as_deref().unwrap_or("助手")
        ));
    }
    match decision.reason.as_str() {
        "unknown_contact" => None,
        "rate_limited" => Some("⏳ 消息太频繁，请稍后再试。".to_string()),
        "no_alias" => {
            Some("请用 /别名 指定要找的助手（例如 /chef 晚饭吃什么），或换个说法。".to_string())
        }
        "out_of_reach" => Some("⛔ 你没有访问这个助手的权限。".to_string()),
        "operator_grade_requires_session" => Some(format!(
            "这类信息需要在家长控制台查看：{}",
            decision.operator_grade_deeplink.as_deref().unwrap_or("")
        )),
        other => Some(format!("⛔ 无法转达（{other}）。")),
    }
}

/// The English twin of [`reply_text_for`] — the Telegram transport's replies
/// (#444: stack ② is the global/EN stack). SAME decision → reply mapping,
/// including the unknown-sender SILENT drop; only the language differs.
pub fn reply_text_for_en(decision: &L3Decision) -> Option<String> {
    if decision.allowed {
        return Some(format!(
            "✅ Passed along to {}",
            decision.target_alias.as_deref().unwrap_or("your assistant")
        ));
    }
    match decision.reason.as_str() {
        "unknown_contact" => None,
        "rate_limited" => Some("⏳ Too many messages — try again in a minute.".to_string()),
        "no_alias" => Some(
            "Address an assistant with /alias (e.g. `/chef what's for dinner`), or rephrase."
                .to_string(),
        ),
        "out_of_reach" => Some("⛔ You don't have access to that assistant.".to_string()),
        "operator_grade_requires_session" => Some(format!(
            "That needs the parent-control console: {}",
            decision.operator_grade_deeplink.as_deref().unwrap_or("")
        )),
        other => Some(format!("⛔ Could not pass that along ({other}).")),
    }
}

async fn emit_relay_audit(
    state: &WeixinGatewayState,
    inbound: &GatewayInbound,
    decision: &L3Decision,
    contact_id: &str,
    tier: &str,
) {
    let Some(audit) = state.audit.as_ref() else {
        return;
    };
    let Some(op_omni) = decode_omni_32(&state.config.operator_omni) else {
        tracing::warn!("operator omni not 32-byte hex — skipping gateway audit");
        return;
    };
    let body = agentkeys_core::audit::GatewayRelayBody {
        transport: inbound.transport.clone(),
        contact_id: contact_id.to_string(),
        tier: tier.to_string(),
        target_alias: decision.target_alias.clone().unwrap_or_default(),
        decision: decision.reason.clone(),
        message_hash: keccak_hex(inbound.text.as_bytes()),
    };
    let result = if decision.allowed {
        AuditResult::Success
    } else {
        AuditResult::NotPermitted
    };
    // The owning user is the operator (the GateTurn pattern — actor == operator).
    match envelope_for(
        op_omni,
        op_omni,
        AuditOpKind::GatewayRelay,
        body,
        result,
        None,
        None,
    ) {
        Ok(env) => {
            if let Err(e) = audit.append(&env).await {
                tracing::warn!(error = %e, "gateway relay audit append failed (best-effort)");
            }
        }
        Err(e) => tracing::warn!(error = %e, "gateway relay envelope build failed"),
    }
}

// ── helpers (shared by both transports) ──────────────────────────────────────

pub(crate) fn base64_std(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}

pub(crate) fn keccak_hex(bytes: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(bytes);
    format!("0x{}", hex::encode(h.finalize()))
}

pub(crate) fn decode_omni_32(omni: &str) -> Option<[u8; 32]> {
    let stripped = omni.strip_prefix("0x").unwrap_or(omni);
    let bytes = hex::decode(stripped).ok()?;
    bytes.try_into().ok()
}

pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(allowed: bool, reason: &str) -> L3Decision {
        L3Decision {
            allowed,
            target_alias: allowed.then(|| "chef".to_string()),
            reason: reason.to_string(),
            operator_grade_deeplink: (reason == "operator_grade_requires_session")
                .then(|| "https://pc.local/".to_string()),
            routed_by: None,
        }
    }

    #[test]
    fn reply_maps_every_decision_and_drops_unknown_silently() {
        assert!(reply_text_for(&decision(true, "ok"))
            .unwrap()
            .contains("chef"));
        assert!(
            reply_text_for(&decision(false, "unknown_contact")).is_none(),
            "unknown sender must get NO reply (silent drop)"
        );
        assert!(reply_text_for(&decision(false, "rate_limited")).is_some());
        assert!(reply_text_for(&decision(false, "no_alias"))
            .unwrap()
            .contains("/chef"));
        assert!(reply_text_for(&decision(false, "out_of_reach")).is_some());
        assert!(
            reply_text_for(&decision(false, "operator_grade_requires_session"))
                .unwrap()
                .contains("https://pc.local/")
        );
    }

    #[test]
    fn decode_omni_accepts_0x_and_bare() {
        assert!(decode_omni_32(&format!("0x{}", "ab".repeat(32))).is_some());
        assert!(decode_omni_32(&"cd".repeat(32)).is_some());
        assert!(decode_omni_32("0xdeadbeef").is_none()); // too short
    }
}
