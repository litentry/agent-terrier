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

use crate::jev::{self, JevVerdict};
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

/// Why an allowed turn did not land on its app's feed, in the terms the
/// member's reply uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedMiss {
    /// No feed is registered for the alias on this gate: the app has no
    /// messaging slot, or was not installed / rebound since the bound channel
    /// became its feed. It can receive nothing until the owner sets it up.
    AppUnregistered,
    /// The gate itself cannot relay yet: no channel worker, its device not
    /// configured or not enrolled, or the operator omni not armed.
    GateNotReady,
    /// The hop ran and a broker or channel-worker call failed.
    HopFailed,
}

/// A feed hop that did not land: the cause, plus the operator-facing detail
/// (the logs and the mock responses' `feed_error`, serialized as that string).
#[derive(Debug, Clone)]
pub struct FeedError {
    pub cause: FeedMiss,
    pub detail: String,
}

impl FeedError {
    fn new(cause: FeedMiss, detail: impl Into<String>) -> Self {
        Self {
            cause,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl serde::Serialize for FeedError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.detail)
    }
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
    /// Why the hop did not run / failed (no feed registered for the alias,
    /// decision-only gateway, device not enrolled, a worker error) — on the
    /// mock responses + in the logs, and named in the member's reply. Never
    /// silent: an allowed turn that reached no feed is a LOUD warn.
    pub feed_error: Option<FeedError>,
    /// The media marker for the reply text, when an original rode along.
    pub media_marker: Option<&'static str>,
    /// The contact's reach (empty for an unknown sender) — the ask-back names
    /// THESE aliases, never a generic example the member cannot use.
    pub reach: Vec<String>,
    /// The bound notice this contact has NOT yet received («✅ 绑定成功…»): the
    /// transport loop sends it FIRST on this turn (the first inbound is the first
    /// moment an iLink bot can answer — no context token exists before it),
    /// then marks the row welcomed. `None` once delivered.
    pub welcome: Option<String>,
    /// #722 — the aliases a `router_ask` named, best first (the reply
    /// composer numbers them; the member answers with the number).
    pub ask_candidates: Vec<String>,
    /// #722 — what the router tier did on this turn (audit + monitor).
    pub router: Option<RouterTrace>,
}

impl RelayOutcome {
    /// The reply this turn gets (`None` = a silent drop) — the ONE reply every
    /// transport sends. An allowed turn says «✅ 已转达» only when its feed hop
    /// landed; otherwise the member is told the message did not reach the app,
    /// and why.
    pub fn reply_text(&self, en: bool, stage_hint: Option<&str>) -> Option<String> {
        if self.decision.allowed && self.feed.is_none() {
            return Some(undelivered_text(
                self.decision.target_alias.as_deref(),
                self.feed_error.as_ref().map(|e| e.cause),
                en,
            ));
        }
        reply_text_for_turn(
            &self.decision,
            self.media_marker,
            en,
            &self.reach,
            &self.ask_candidates,
            stage_hint,
        )
    }
}

/// #722 — the router tier's trace for one turn: which engine answered, the
/// model version, the verdict and its confidence. Never the message.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouterTrace {
    /// `jev` (the model answered) or `deterministic_fallback` (it could not).
    pub engine: String,
    pub model: String,
    /// `route` / `ask` / `malformed` / `unavailable`.
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// The reach aliases the verdict named (the pick, or the ask's list).
    pub candidates: Vec<String>,
}

impl RouterTrace {
    fn fallback(model: &str, verdict: &str) -> Self {
        Self {
            engine: "deterministic_fallback".into(),
            model: model.to_string(),
            verdict: verdict.to_string(),
            confidence: None,
            candidates: Vec::new(),
        }
    }
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
    let (mut alias, mut turn_text) = parse_alias(raw_text);
    let registry = state.registry.snapshot();
    let contact = registry.resolve(transport, transport_id);
    let now_secs = unix_secs();

    // #722 — TEXT turns with no `/alias`, in order: (1) the reply to a live
    // numbered ask delivers the member's ORIGINAL message; (2) one reachable
    // app gets every plain message; (3) the Jev tier picks among the reach —
    // confident → route, unsure → ask (filed after L3 below), unusable /
    // unreachable / unconfigured → nothing here, the whole-word tier in L3
    // runs as today. Every branch stays inside `reach` (D10).
    let mut routed_by_override: Option<&'static str> = None;
    let mut ask_candidates: Vec<String> = Vec::new();
    let mut router_trace: Option<RouterTrace> = None;
    if alias.is_none() && media.is_none() && !turn_text.trim().is_empty() {
        if let Some(c) = contact {
            if let Some((chosen, original)) =
                state.take_ask_reply(transport, transport_id, &turn_text, now_secs)
            {
                alias = Some(chosen);
                turn_text = original;
                routed_by_override = Some("ask_reply");
            } else if c.reach.len() == 1 {
                alias = Some(c.reach[0].clone());
                routed_by_override = Some("single_reach");
            } else if let Some(client) = state.jev.as_ref() {
                let last = state
                    .device
                    .last_alias(transport, transport_id)
                    .filter(|a| c.reach.iter().any(|r| r.eq_ignore_ascii_case(a)));
                let candidates = registry.reach_candidates(&c.reach);
                let req = jev::build_request(
                    &state.config.router.model,
                    &turn_text,
                    c.tier.as_str(),
                    last.as_deref(),
                    &candidates,
                );
                match client.decide(&req).await {
                    Ok(resp) => match jev::verdict_from(
                        &resp,
                        &c.reach,
                        state.config.router.threshold,
                        last.as_deref(),
                        state.config.router.last_agent_weight,
                    ) {
                        JevVerdict::Route {
                            alias: picked,
                            confidence,
                        } => {
                            router_trace = Some(RouterTrace {
                                engine: "jev".into(),
                                model: resp.model.clone(),
                                verdict: "route".into(),
                                confidence: Some(confidence),
                                candidates: vec![picked.clone()],
                            });
                            alias = Some(picked);
                            routed_by_override = Some("jev");
                        }
                        JevVerdict::Ask {
                            candidates,
                            confidence,
                        } => {
                            router_trace = Some(RouterTrace {
                                engine: "jev".into(),
                                model: resp.model.clone(),
                                verdict: "ask".into(),
                                confidence: Some(confidence),
                                candidates: candidates.clone(),
                            });
                            ask_candidates = candidates;
                        }
                        JevVerdict::Malformed(why) => {
                            tracing::warn!(
                                contact = %c.contact_id,
                                model = %resp.model,
                                why,
                                "#722 the decision model's answer was unusable — the deterministic tier runs"
                            );
                            router_trace = Some(RouterTrace::fallback(&resp.model, "malformed"));
                        }
                    },
                    Err(jev::JevError::Unconfigured) => {
                        tracing::info!(
                            contact = %c.contact_id,
                            "#722 the model gate has no decision model yet (503) — the deterministic tier runs"
                        );
                        router_trace = Some(RouterTrace::fallback(
                            &state.config.router.model,
                            "unavailable",
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            contact = %c.contact_id,
                            error = %e,
                            "#722 the model gate did not answer — the deterministic tier runs"
                        );
                        router_trace = Some(RouterTrace::fallback(
                            &state.config.router.model,
                            "unavailable",
                        ));
                    }
                }
            }
        }
    }

    // #667 — follow-on routing for a MEDIA turn that names no `/alias` (a
    // caption-less photo / voice clip) when the advisory router asks back:
    // the contact's LAST routed alias (the photo belongs to the conversation
    // it was sent into), else the ONLY alias the contact can reach. Both are
    // subsets of `reach` (D10 — never wider than the contact could `/alias`
    // directly), so a crafted caption cannot widen authority.
    if alias.is_none() && media.is_some() {
        if let Some(c) = contact {
            let verdict =
                crate::router::advisory_route(&turn_text, &c.reach, state.config.router_enabled);
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
        text: turn_text,
        alias,
    };

    // L3 (the PEP) — rate check + the pure decision.
    let rate_ok = state.rate.check(transport_id, now_secs);
    let mut decision = crate::l3::decide(&state.config, &registry, &inbound, rate_ok);
    if decision.allowed && decision.routed_by.is_none() {
        if let Some(r) = routed_by_override {
            decision.routed_by = Some(r.to_string());
        }
    }
    // #722 — the model was unsure and the whole-word tier found nothing either:
    // the refusal becomes a numbered ask, and the member's original text waits
    // in memory for the answer. A whole-word hit routed instead — no ask.
    if !decision.allowed && decision.reason == "no_alias" && !ask_candidates.is_empty() {
        decision.reason = "router_ask".to_string();
        state.set_pending_ask(
            transport,
            transport_id,
            jev::PendingAsk {
                original_text: inbound.text.clone(),
                candidates: ask_candidates.clone(),
                expires_at_secs: now_secs.saturating_add(state.config.router.ask_ttl_secs),
            },
        );
    } else {
        ask_candidates.clear();
    }
    let (contact_id, tier) = contact
        .map(|c| (c.contact_id.clone(), c.tier.as_str().to_string()))
        .unwrap_or_default();
    let reach: Vec<String> = contact.map(|c| c.reach.clone()).unwrap_or_default();
    // The member's acknowledgement is never missed: a bound contact whose notice
    // could not be delivered at bind time (an iLink bot cannot send before the
    // member's first message) gets it with this very turn, before anything else.
    let welcome = contact.filter(|c| !c.welcomed).map(bound_notice);

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
        // The app's bound channel (registry `apps`, written at install /
        // rebind — the bound channel IS the feed, 2026-09-22). No row = the
        // console never registered this app's feed: the hop cannot land,
        // loudly, until the app is rebound.
        let channel_id = state
            .registry
            .snapshot()
            .app_channel(&alias)
            .map(str::to_string)
            .unwrap_or_default();
        let stamp = ContactStamp {
            contact_id: contact_id.clone(),
            tier: tier.clone(),
        };
        if channel_id.is_empty() {
            tracing::warn!(
                alias = %alias,
                contact = %contact_id,
                "#667 feed hop did NOT land — no channel is registered for this alias on this gate (the app's install / rebind registers it)"
            );
            feed_error = Some(FeedError::new(
                FeedMiss::AppUnregistered,
                format!("app_feed_unregistered:{alias}"),
            ));
        } else {
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
        router_trace.as_ref(),
        &ask_candidates,
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
        decision.routed_by.clone(),
        router_trace.as_ref().and_then(|r| r.confidence),
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
        reach,
        welcome,
        ask_candidates,
        router: router_trace,
    }
}

/// The member's half of the bind ceremony — what they are told in their own
/// chat once bound: who they are to the household and whom they can talk to.
pub fn bound_notice(c: &agentkeys_protocol::Contact) -> String {
    let who = format!("{}（{}）", c.display_name, tier_zh(c.tier));
    if c.reach.is_empty() {
        return format!("✅ 绑定成功：{who}。管理员还没有为你开通可联系的助手，开通后会自动生效。");
    }
    let aliases = c
        .reach
        .iter()
        .map(|a| format!("/{a}"))
        .collect::<Vec<_>>()
        .join("、");
    format!(
        "✅ 绑定成功：{who}。现在可以直接对话这些助手：{aliases}。发“/{} 你好”试试。",
        c.reach[0]
    )
}

pub fn tier_zh(t: agentkeys_protocol::ContactTier) -> &'static str {
    use agentkeys_protocol::ContactTier::*;
    match t {
        Owner => "拥有者",
        Partner => "配偶",
        Elder => "长辈",
        Kid => "孩子",
        Helper => "帮手",
        Guest => "访客",
    }
}

/// The ask-back for a bound contact who named no reachable assistant: it lists
/// THEIR aliases (a generic `/chef` example is useless to someone who cannot
/// reach chef). Empty reach = the generic text (the master grants reach later).
pub fn ask_back_text(reach: &[String], en: bool) -> String {
    if reach.is_empty() {
        return if en {
            "Address an assistant with /alias (e.g. `/chef what's for dinner`), or rephrase."
                .to_string()
        } else {
            "请用 /别名 指定要找的助手（例如 /chef 晚饭吃什么），或换个说法。".to_string()
        };
    }
    let list = reach
        .iter()
        .map(|a| format!("/{a}"))
        .collect::<Vec<_>>()
        .join(if en { ", " } else { "、" });
    if en {
        format!(
            "Address an assistant with /alias — yours: {list} (e.g. `/{} hello`), or rephrase.",
            reach[0]
        )
    } else {
        format!(
            "请用 /别名 指定要找的助手，你可以找：{list}（例如 /{} 你好），或换个说法。",
            reach[0]
        )
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
) -> Result<FeedReceipt, FeedError> {
    if let Some(b) = state.device.hop_blocker() {
        return Err(FeedError::new(FeedMiss::GateNotReady, b));
    }
    let operator = state.effective_operator_omni();
    if decode_omni_32(&operator).is_none() {
        return Err(FeedError::new(
            FeedMiss::GateNotReady,
            "operator omni not armed (connect the contact gate from parent-control 微信网关 → 连接)",
        ));
    }
    let failed =
        |what: &str, e: anyhow::Error| FeedError::new(FeedMiss::HopFailed, format!("{what}: {e}"));
    let device = &state.device;
    let mut media_event_id = None;
    let mut body_ref = None;
    if let Some(m) = media {
        let r = device
            .put_blob(&operator, channel_id, &m.content_type, &m.bytes)
            .await
            .map_err(|e| failed("blob-put", e))?;
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
            .map_err(|e| failed("media publish", e))?;
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
                .map_err(|e| failed("text publish", e))?,
        )
    };
    let event_id = text_event_id
        .clone()
        .or_else(|| media_event_id.clone())
        .ok_or_else(|| {
            FeedError::new(FeedMiss::HopFailed, "nothing to relay (no text, no media)")
        })?;
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
/// contact gets one terse line, not an amplification loop). The allowed line
/// is a delivery receipt: only [`RelayOutcome::reply_text`] reaches it, after
/// the feed hop landed.
fn reply_text_for(decision: &L3Decision) -> Option<String> {
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
        // #722 — the candidate-naming ask is composed by `reply_text_for_turn`
        // (it has the candidates); this is the generic fallback wording.
        "router_ask" => Some("请回复数字选择要找的助手，或用 /别名。".to_string()),
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
fn reply_text_for_en(decision: &L3Decision) -> Option<String> {
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
        "router_ask" => Some(
            "Reply with the number of the assistant you meant, or address it with /alias."
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

/// The reply for a turn that may have carried a media original: the decision
/// reply, plus the relayed-media marker on an allowed turn (`zh` for the
/// weixin family, `en` for Telegram). Same decision → reply mapping as the
/// two functions above (the unknown-sender SILENT drop included).
fn reply_text_for_turn(
    decision: &L3Decision,
    media_marker: Option<&str>,
    en: bool,
    reach: &[String],
    ask_candidates: &[String],
    stage_hint: Option<&str>,
) -> Option<String> {
    let base = if !decision.allowed && decision.reason == "router_ask" {
        jev::ask_text(ask_candidates, en)
    } else if !decision.allowed && decision.reason == "no_alias" {
        ask_back_text(reach, en)
    } else if en {
        reply_text_for_en(decision)?
    } else {
        reply_text_for(decision)?
    };
    let mut out = match (decision.allowed, media_marker) {
        (true, Some(m)) => format!("{base} {m}"),
        _ => base,
    };
    // #693 — the app's launch state rides on an ALLOWED receipt: the member
    // learns why the answer may take a moment, or come without the knowledge.
    if decision.allowed {
        match (stage_hint, en) {
            (Some("loading"), false) => out.push_str("（它还在加载知识，稍等片刻）"),
            (Some("loading"), true) => {
                out.push_str(" (it is still loading its knowledge — one moment)")
            }
            (Some("degraded"), false) => out.push_str("（它的知识暂不可用，会先按已有信息回答）"),
            (Some("degraded"), true) => out.push_str(
                " (its knowledge is unavailable right now — it answers from what it has)",
            ),
            _ => {}
        }
    }
    Some(out)
}

/// The reply for an allowed turn whose feed hop did not land, in place of
/// «✅ 已转达»: the message did not reach the app, why in plain words, and who
/// can fix it (the owner, in parent-control; a failed send is worth a retry).
fn undelivered_text(alias: Option<&str>, cause: Option<FeedMiss>, en: bool) -> String {
    let why = match (cause, en) {
        (Some(FeedMiss::AppUnregistered), false) => {
            "它还没有设置好接收聊天消息。请管理员在家长控制台打开它的应用页设置。"
        }
        (Some(FeedMiss::AppUnregistered), true) => {
            "it isn't set up to receive chat yet. The owner can set it up on its page in Parent Control."
        }
        (Some(FeedMiss::GateNotReady), false) => {
            "微信网关还没有接通。请管理员在家长控制台检查网关设置。"
        }
        (Some(FeedMiss::GateNotReady), true) => {
            "the contact gate isn't connected yet. The owner can check its setup in Parent Control."
        }
        (_, false) => "这次没有发送成功，请稍后再试；一直不行的话请告诉管理员。",
        (_, true) => {
            "it didn't go through this time. Try again in a moment, and tell the owner if it keeps happening."
        }
    };
    if en {
        format!(
            "⚠️ Not delivered to {}: {why}",
            alias.unwrap_or("your assistant")
        )
    } else {
        format!("⚠️ 消息没有送到 {}：{why}", alias.unwrap_or("助手"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn emit_relay_audit(
    state: &WeixinGatewayState,
    inbound: &GatewayInbound,
    decision: &L3Decision,
    contact_id: &str,
    tier: &str,
    media: bool,
    router: Option<&RouterTrace>,
    ask_candidates: &[String],
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
        routed_by: decision.routed_by.clone(),
        confidence_permille: router
            .and_then(|r| r.confidence)
            .map(|c| (c.clamp(0.0, 1.0) * 1000.0).round() as u16),
        candidates: (decision.reason == "router_ask" && !ask_candidates.is_empty())
            .then(|| ask_candidates.to_vec()),
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
    fn ask_back_names_the_contacts_own_reach() {
        let reach = vec!["agent".to_string(), "nanny".to_string()];
        let zh = ask_back_text(&reach, false);
        assert!(
            zh.contains("/agent、/nanny") && zh.contains("/agent 你好"),
            "{zh}"
        );
        let en = ask_back_text(&reach, true);
        assert!(
            en.contains("/agent, /nanny") && en.contains("/agent hello"),
            "{en}"
        );
        assert!(ask_back_text(&[], false).contains("/chef"));
        let turn =
            reply_text_for_turn(&decision(false, "no_alias"), None, false, &reach, &[], None)
                .unwrap();
        assert!(turn.contains("/nanny") && !turn.contains("/chef"), "{turn}");
        assert!(
            reply_text_for_turn(&decision(true, "ok"), Some("📷"), false, &reach, &[], None)
                .unwrap()
                .ends_with("📷")
        );
        // #722 — the model's ask names the candidates, numbered, never the reach list.
        let asked = reply_text_for_turn(
            &decision(false, "router_ask"),
            None,
            false,
            &reach,
            &["nanny".to_string(), "agent".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(
            asked,
            "你是想找 1 nanny 还是 2 agent？回复 1 或 2，或用 /别名（例如 /nanny）。"
        );
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

    fn outcome(
        decision: L3Decision,
        feed: Option<FeedReceipt>,
        feed_error: Option<FeedError>,
    ) -> RelayOutcome {
        RelayOutcome {
            inbound: GatewayInbound {
                transport: "weixin".into(),
                transport_id: "openid-owner".into(),
                text: "今晚吃什么".into(),
                alias: Some("chef".into()),
            },
            decision,
            contact_id: "c-owner".into(),
            tier: "owner".into(),
            event: None,
            claim_ack: None,
            feed,
            feed_error,
            media_marker: Some("📷"),
            reach: vec!["chef".into()],
            welcome: None,
            ask_candidates: Vec::new(),
            router: None,
        }
    }

    #[test]
    fn the_receipt_claims_delivery_only_for_a_landed_hop() {
        let landed = FeedReceipt {
            channel_id: "family-chat".into(),
            event_id: "evt-1".into(),
            media_event_id: None,
            body_ref: None,
        };
        let ok = outcome(decision(true, "ok"), Some(landed), None);
        assert_eq!(
            ok.reply_text(false, Some("loading")).unwrap(),
            "✅ 已转达给 chef 📷（它还在加载知识，稍等片刻）"
        );
        assert_eq!(
            ok.reply_text(true, None).unwrap(),
            "✅ Passed along to chef 📷"
        );

        let missed = |cause| {
            outcome(
                decision(true, "ok"),
                None,
                Some(FeedError::new(cause, "detail for the logs")),
            )
        };
        let cases = [
            (
                FeedMiss::AppUnregistered,
                "⚠️ 消息没有送到 chef：它还没有设置好接收聊天消息。请管理员在家长控制台打开它的应用页设置。",
                "⚠️ Not delivered to chef: it isn't set up to receive chat yet. The owner can set it up on its page in Parent Control.",
            ),
            (
                FeedMiss::GateNotReady,
                "⚠️ 消息没有送到 chef：微信网关还没有接通。请管理员在家长控制台检查网关设置。",
                "⚠️ Not delivered to chef: the contact gate isn't connected yet. The owner can check its setup in Parent Control.",
            ),
            (
                FeedMiss::HopFailed,
                "⚠️ 消息没有送到 chef：这次没有发送成功，请稍后再试；一直不行的话请告诉管理员。",
                "⚠️ Not delivered to chef: it didn't go through this time. Try again in a moment, and tell the owner if it keeps happening.",
            ),
        ];
        for (cause, zh, en) in cases {
            // The launch-state hint and the media marker belong to a delivered
            // turn only.
            assert_eq!(
                missed(cause).reply_text(false, Some("loading")).unwrap(),
                zh
            );
            assert_eq!(missed(cause).reply_text(true, Some("loading")).unwrap(), en);
        }
        // No receipt and no recorded cause still never claims delivery.
        let unknown = outcome(decision(true, "ok"), None, None);
        assert!(unknown
            .reply_text(false, None)
            .unwrap()
            .starts_with("⚠️ 消息没有送到 chef"));

        // Refusals are untouched: the stranger stays silent, the rest reply.
        let stranger = outcome(decision(false, "unknown_contact"), None, None);
        assert!(stranger.reply_text(false, None).is_none());
        assert!(stranger.reply_text(true, None).is_none());
        let refused = outcome(decision(false, "out_of_reach"), None, None);
        assert_eq!(
            refused.reply_text(false, None).unwrap(),
            "⛔ 你没有访问这个助手的权限。"
        );
        // The mock responses carry the detail as a plain string.
        assert_eq!(
            serde_json::to_value(FeedError::new(
                FeedMiss::HopFailed,
                "text publish: HTTP 500"
            ))
            .unwrap(),
            serde_json::json!("text publish: HTTP 500")
        );
    }

    #[test]
    fn receipt_carries_the_apps_launch_state() {
        let reach = vec!["chef".to_string()];
        let zh = reply_text_for_turn(
            &decision(true, "ok"),
            None,
            false,
            &reach,
            &[],
            Some("loading"),
        )
        .unwrap();
        assert!(zh.contains("加载知识"), "{zh}");
        let en = reply_text_for_turn(
            &decision(true, "ok"),
            Some("📷"),
            true,
            &reach,
            &[],
            Some("degraded"),
        )
        .unwrap();
        assert!(en.contains("📷") && en.contains("unavailable"), "{en}");
        let ready =
            reply_text_for_turn(&decision(true, "ok"), None, true, &reach, &[], None).unwrap();
        assert!(!ready.contains("loading"));
        // a refused turn never carries the app's state (nothing was routed)
        let refused = reply_text_for_turn(
            &decision(false, "rate_limited"),
            None,
            false,
            &reach,
            &[],
            Some("loading"),
        )
        .unwrap();
        assert!(!refused.contains("加载"));
        assert_eq!(crate::state::stage_hint("syncing", 1_000), Some("loading"));
        assert_eq!(
            crate::state::stage_hint("degraded", 1_000),
            Some("degraded")
        );
        assert_eq!(crate::state::stage_hint("ready", 1_000), None);
        assert_eq!(
            crate::state::stage_hint("syncing", crate::state::APP_STAGE_TTL_MS + 1),
            None,
            "stale"
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
