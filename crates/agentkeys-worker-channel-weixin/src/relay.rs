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
    parse_alias, ChannelDirection, ChannelEvent, ChannelEventKind, ChannelProducer, ContactStamp,
    GatewayInbound, L3Decision,
};

use crate::state::WeixinGatewayState;

/// One media original riding the turn (photo / voice) — see [`crate::media`].
pub use crate::media::InboundMedia;

/// #667 — the feed-hop receipt for an allowed turn: what landed on the
/// app's feed (the mock e2e reads it; the loops log it).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedReceipt {
    pub channel_id: String,
    /// The event the app's reply correlates to (the text event when there is
    /// text, else the media event).
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_event_id: Option<String>,
    /// Where the media original lives beside the feed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_ref: Option<String>,
}

/// Everything one inbound turn produced — the decision (for the transport's
/// reply), the resolved contact (for logs/audit), and the routed event.
pub struct RelayOutcome {
    pub inbound: GatewayInbound,
    pub decision: L3Decision,
    pub contact_id: String,
    pub tier: String,
    /// Only on an allowed decision — the worker-stamped event for the target
    /// delegate's feed (producer = the CONTACT, from the registry, never a body
    /// field, §4.1). Carries the worker's event id once the hop landed.
    pub event: Option<ChannelEvent>,
    /// #418 bind ceremony: an UNKNOWN sender echoed a live invite code — this
    /// is the in-channel ack (`reason = bind_code_claimed`). The ONE sanctioned
    /// exception to unknown-sender silence (§7.2: the code proves the operator
    /// invited them out-of-band).
    pub claim_ack: Option<String>,
    /// #667 — the feed hop: `Some` when the turn landed on the app's feed.
    pub feed: Option<FeedReceipt>,
    /// Why the hop did not run / failed (decision-only gateway, device not
    /// enrolled, a worker error) — on the mock responses + in the logs. Never
    /// silent: an allowed turn that reached no feed is a LOUD warn.
    pub feed_error: Option<String>,
    /// The media marker for the reply text, when an original rode along.
    pub media_marker: Option<&'static str>,
}

/// Run one inbound `(transport_id, text)` turn through L3 + audit for the
/// `weixin` transport family (the OA webhook + iLink callers).
pub async fn process_inbound(
    state: &WeixinGatewayState,
    transport_id: &str,
    raw_text: &str,
) -> RelayOutcome {
    process_turn(state, "weixin", transport_id, raw_text, None).await
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
    process_turn(state, transport, transport_id, raw_text, None).await
}

/// The full turn: alias-parse (+ the #667 reach-bounded follow-on routing) →
/// L3 → the FEED HOP for an allowed turn (media original by ref, text event
/// correlated to it, contact stamp) → audit → live monitor.
pub async fn process_turn(
    state: &WeixinGatewayState,
    transport: &str,
    transport_id: &str,
    raw_text: &str,
    media: Option<InboundMedia>,
) -> RelayOutcome {
    let (mut alias, remaining) = parse_alias(raw_text);
    let registry = state.registry.snapshot();
    let contact = registry.resolve(transport, transport_id);

    // #667 — follow-on routing for a MEDIA turn that names no `/alias` (a
    // caption-less photo / voice clip) when the advisory router asks back:
    // the contact's LAST routed alias (the photo belongs to the conversation
    // it was sent into), else the ONLY alias the contact can reach. Both are
    // subsets of `reach` (D10 — never wider than the contact could `/alias`
    // directly), so a crafted caption cannot widen authority. TEXT turns keep
    // today's rule unchanged: no alias + no router match = ask back.
    let mut routed_by_override: Option<&'static str> = None;
    if alias.is_none() && media.is_some() {
        if let Some(c) = contact {
            let verdict =
                crate::router::advisory_route(&remaining, &c.reach, state.config.router_enabled);
            if verdict == crate::router::RouteVerdict::AskBack {
                let sticky = state
                    .device
                    .last_alias(transport, transport_id)
                    .filter(|a| c.reach.iter().any(|r| r.eq_ignore_ascii_case(a)));
                if let Some(a) = sticky {
                    alias = Some(a);
                    routed_by_override = Some("sticky_last_alias");
                } else if c.reach.len() == 1 {
                    alias = Some(c.reach[0].clone());
                    routed_by_override = Some("single_reach");
                }
            }
        }
    }
    let inbound = GatewayInbound {
        transport: transport.to_string(),
        transport_id: transport_id.to_string(),
        text: remaining,
        alias,
    };

    // L3 (the PEP) — rate check + the pure decision.
    let now_secs = unix_secs();
    let rate_ok = state.rate.check(transport_id, now_secs);
    let mut decision = crate::l3::decide(&state.config, &registry, &inbound, rate_ok);
    if decision.allowed && decision.routed_by.is_none() {
        if let Some(r) = routed_by_override {
            decision.routed_by = Some(r.to_string());
        }
    }
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

    let media_marker = media.as_ref().map(|m| m.marker());
    let mut feed = None;
    let mut feed_error = None;
    let event = if decision.allowed {
        let alias = decision.target_alias.clone().unwrap_or_default();
        state.device.set_last_alias(transport, transport_id, &alias);
        let channel_id = agentkeys_protocol::messaging_feed_id(transport, &alias);
        let stamp = ContactStamp {
            contact_id: contact_id.clone(),
            tier: tier.clone(),
        };
        match feed_hop(state, &channel_id, &inbound, media.as_ref(), &stamp).await {
            Ok(r) => feed = Some(r),
            Err(e) => {
                tracing::warn!(
                    channel = %channel_id,
                    contact = %contact_id,
                    "#667 feed hop did NOT land — the turn never reached the app: {e}"
                );
                feed_error = Some(e);
            }
        }
        let has_text = !inbound.text.trim().is_empty();
        let media_only = !has_text && media.is_some();
        Some(ChannelEvent {
            // The worker assigns the durable id; echoed here once the hop landed.
            event_id: feed
                .as_ref()
                .map(|f| f.event_id.clone())
                .unwrap_or_default(),
            channel_id,
            direction: ChannelDirection::In,
            producer: ChannelProducer::Contact {
                contact_id: contact_id.clone(),
                tier: tier.clone(),
            },
            kind: if media_only {
                media
                    .as_ref()
                    .map(|m| m.kind)
                    .unwrap_or(ChannelEventKind::Text)
            } else {
                ChannelEventKind::Text
            },
            body: has_text.then(|| base64_std(inbound.text.as_bytes())),
            body_ref: if media_only {
                feed.as_ref().and_then(|f| f.body_ref.clone())
            } else {
                None
            },
            ts_millis: now_secs.saturating_mul(1000),
            correlation: None,
            audio: None,
            partial: None,
            seq: None,
            stream: None,
            contact: Some(stamp),
            content_type: if media_only {
                media.as_ref().map(|m| m.content_type.clone())
            } else {
                None
            },
            relay_of: if has_text {
                feed.as_ref().and_then(|f| f.media_event_id.clone())
            } else {
                None
            },
        })
    } else {
        None
    };

    emit_relay_audit(
        state,
        &inbound,
        &decision,
        &contact_id,
        &tier,
        media.is_some(),
    )
    .await;

    // Live monitor (#1): record this turn for the operator's poll feed. D13-safe
    // — the resolved bound display_name (or "unknown"), NEVER the openid; a
    // media original is a MARKER here, never bytes.
    let sender_name = contact
        .map(|c| c.display_name.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let mut preview: String = raw_text.chars().take(80).collect();
    if let Some(m) = media_marker {
        preview = if preview.trim().is_empty() {
            m.to_string()
        } else {
            format!("{m} {preview}")
        };
    }
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
        feed,
        feed_error,
        media_marker,
    }
}

/// #667 — the feed hop: the media original by ref (blob-put beside the feed,
/// then an `image` / `audio-clip` event), the text as a `text` event correlated
/// to it (`relay_of`), both stamped with the contact this device relayed for.
/// The worker stamps the producer (this device actor) from the cap; a
/// consumer trusts the `contact` stamp only because the feed's endpoint actor
/// is this gateway (the spawn context's `bound_channels`).
async fn feed_hop(
    state: &WeixinGatewayState,
    channel_id: &str,
    inbound: &GatewayInbound,
    media: Option<&InboundMedia>,
    stamp: &ContactStamp,
) -> Result<FeedReceipt, String> {
    if let Some(b) = state.device.hop_blocker() {
        return Err(b.to_string());
    }
    let operator = state.effective_operator_omni();
    if decode_omni_32(&operator).is_none() {
        return Err(
            "operator omni not armed (connect the contact gate from parent-control 微信网关 → 连接)"
                .to_string(),
        );
    }
    let device = &state.device;
    let mut media_event_id = None;
    let mut body_ref = None;
    if let Some(m) = media {
        let r = device
            .put_blob(&operator, channel_id, &m.content_type, &m.bytes)
            .await
            .map_err(|e| format!("blob-put: {e}"))?;
        let id = device
            .publish(
                &operator,
                channel_id,
                crate::device::PublishArgs {
                    kind: Some(m.kind),
                    body_ref: Some(r.clone()),
                    content_type: Some(m.content_type.clone()),
                    contact: Some(stamp.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| format!("media publish: {e}"))?;
        media_event_id = Some(id);
        body_ref = Some(r);
    }
    let text_event_id = if inbound.text.trim().is_empty() {
        None
    } else {
        Some(
            device
                .publish(
                    &operator,
                    channel_id,
                    crate::device::PublishArgs {
                        kind: Some(ChannelEventKind::Text),
                        body_b64: Some(base64_std(inbound.text.as_bytes())),
                        contact: Some(stamp.clone()),
                        relay_of: media_event_id.clone(),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| format!("text publish: {e}"))?,
        )
    };
    let event_id = text_event_id
        .clone()
        .or_else(|| media_event_id.clone())
        .ok_or_else(|| "nothing to relay (no text, no media)".to_string())?;
    device.remember_correlation(
        &event_id,
        channel_id,
        &inbound.transport,
        &inbound.transport_id,
    );
    if let (Some(m), Some(_)) = (&media_event_id, &text_event_id) {
        // A reply correlated to the photo itself finds the contact too.
        device.remember_correlation(m, channel_id, &inbound.transport, &inbound.transport_id);
    }
    Ok(FeedReceipt {
        channel_id: channel_id.to_string(),
        event_id,
        media_event_id,
        body_ref,
    })
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

/// The reply for a turn that may have carried a media original: the decision
/// reply, plus the relayed-media marker on an allowed turn (`zh` for the
/// weixin family, `en` for Telegram). Same decision → reply mapping as the
/// two functions above (the unknown-sender SILENT drop included).
/// The neutral hint an UNKNOWN sender gets on the private-bot transports
/// instead of dead silence — once per sender per [`UNKNOWN_HINT_WINDOW_SECS`].
/// The L3 decision stays a DROP (nothing is routed, nothing about the household
/// is revealed — D13); this is onboarding copy for the member who added the bot,
/// said hello, and would otherwise conclude the bot is dead (owner walkthrough
/// 2026-09-11). `AGENTKEYS_WEIXIN_UNKNOWN_HINT=0` restores the silent drop.
pub const UNKNOWN_HINT_WINDOW_SECS: u64 = 24 * 60 * 60;
pub const UNKNOWN_HINT_ZH: &str =
    "这是家庭助手机器人。请把家长在“家长控制台 › 联系人”里为你生成的 6 位绑定码发给我（例如：绑定 123456）。";
pub const UNKNOWN_HINT_EN: &str = "This is a family assistant bot. Send me the 6-digit bind code your parent minted in Parent Control › Contacts (e.g. \"bind 123456\").";

pub fn unknown_sender_hint(
    decision: &L3Decision,
    last_hint_secs: Option<u64>,
    now_secs: u64,
    en: bool,
) -> Option<&'static str> {
    if decision.reason != "unknown_contact" {
        return None;
    }
    if let Some(t) = last_hint_secs {
        if now_secs.saturating_sub(t) < UNKNOWN_HINT_WINDOW_SECS {
            return None;
        }
    }
    Some(if en { UNKNOWN_HINT_EN } else { UNKNOWN_HINT_ZH })
}

pub fn reply_text_for_turn(
    decision: &L3Decision,
    media_marker: Option<&str>,
    en: bool,
) -> Option<String> {
    let base = if en {
        reply_text_for_en(decision)?
    } else {
        reply_text_for(decision)?
    };
    match (decision.allowed, media_marker) {
        (true, Some(m)) => Some(format!("{base} {m}")),
        _ => Some(base),
    }
}

async fn emit_relay_audit(
    state: &WeixinGatewayState,
    inbound: &GatewayInbound,
    decision: &L3Decision,
    contact_id: &str,
    tier: &str,
    media: bool,
) {
    let Some(audit) = state.audit.as_ref() else {
        return;
    };
    let Some(op_omni) = decode_omni_32(&state.effective_operator_omni()) else {
        tracing::warn!("operator omni not 32-byte hex — skipping contact gate audit");
        return;
    };
    let body = agentkeys_core::audit::GatewayRelayBody {
        transport: inbound.transport.clone(),
        contact_id: contact_id.to_string(),
        tier: tier.to_string(),
        target_alias: decision.target_alias.clone().unwrap_or_default(),
        decision: decision.reason.clone(),
        message_hash: keccak_hex(inbound.text.as_bytes()),
        media,
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
                tracing::warn!(error = %e, "contact gate relay audit append failed (best-effort)");
            }
        }
        Err(e) => tracing::warn!(error = %e, "contact gate relay envelope build failed"),
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
    fn unknown_sender_hint_is_once_per_window_and_only_for_unknowns() {
        let d = decision(false, "unknown_contact");
        assert_eq!(
            unknown_sender_hint(&d, None, 1_000, false),
            Some(UNKNOWN_HINT_ZH)
        );
        assert_eq!(
            unknown_sender_hint(&d, None, 1_000, true),
            Some(UNKNOWN_HINT_EN)
        );
        assert!(
            unknown_sender_hint(&d, Some(1_000), 1_000 + UNKNOWN_HINT_WINDOW_SECS - 1, false)
                .is_none()
        );
        assert!(
            unknown_sender_hint(&d, Some(1_000), 1_000 + UNKNOWN_HINT_WINDOW_SECS, false).is_some()
        );
        assert!(
            unknown_sender_hint(&decision(false, "out_of_reach"), None, 1_000, false).is_none()
        );
        assert!(unknown_sender_hint(&decision(true, "ok"), None, 1_000, false).is_none());
        // the relay's own mapping still drops unknowns — the hint is a separate, once-only layer
        assert!(reply_text_for(&d).is_none());
    }

    #[test]
    fn decode_omni_accepts_0x_and_bare() {
        assert!(decode_omni_32(&format!("0x{}", "ab".repeat(32))).is_some());
        assert!(decode_omni_32(&"cd".repeat(32)).is_some());
        assert!(decode_omni_32("0xdeadbeef").is_none()); // too short
    }
}
