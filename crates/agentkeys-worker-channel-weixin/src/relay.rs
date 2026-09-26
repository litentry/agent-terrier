//! The transport-NEUTRAL relay core — one inbound turn through the PEP:
//! resolve the channel (the aggregating transport's hook: `/alias`, an
//! answered ask, the router over the member's own channel documents) → L3
//! decide → the feed hop onto that channel with the addressee → GatewayRelay
//! audit. Every transport converges here: the 公众号 webhook
//! (`handlers::callback_relay`), the iLink long-poll ([`crate::ilink_loop`])
//! and the Telegram poll. Adding a transport = a new inbound adapter that
//! calls [`process_inbound_for`]; a channel-native transport passes the
//! member's channel in and skips the router (see [`crate::transport`]). The
//! L3 / registry / router / audit machinery never forks per transport.

use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Keccak256};

use agentkeys_core::audit::{envelope_for, AuditOpKind, AuditResult};
use agentkeys_protocol::{
    parse_alias, ChannelDirection, ChannelEvent, ChannelEventKind, ChannelProducer, ContactStamp,
    GatewayInbound, L3Decision,
};

use crate::jev::{self, ChannelOption, JevVerdict};
use crate::state::WeixinGatewayState;

/// One media original riding the turn (photo / voice) — see [`crate::media`].
pub use crate::media::InboundMedia;

/// #667 — the feed-hop receipt for an allowed turn: what landed on the
/// channel's feed (the mock e2e reads it; the loops log it).
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

/// Why an allowed turn did not land on its channel's feed, in the terms the
/// member's reply uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedMiss {
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
    /// Only on an allowed decision — the worker-stamped event for the channel's
    /// feed (producer = the CONTACT, from the registry, never a body field,
    /// §4.1). Carries the worker's event id once the hop landed.
    pub event: Option<ChannelEvent>,
    /// #418 bind ceremony: an UNKNOWN sender echoed a live invite code — this
    /// is the in-channel ack (`reason = bind_code_claimed`). The ONE sanctioned
    /// exception to unknown-sender silence (§7.2: the code proves the operator
    /// invited them out-of-band).
    pub claim_ack: Option<String>,
    /// #667 — the feed hop: `Some` when the turn landed on the channel's feed.
    pub feed: Option<FeedReceipt>,
    /// Why the hop did not run / failed (decision-only gateway, device not
    /// enrolled, a worker error) — on the mock responses + in the logs, and
    /// named in the member's reply. Never silent: an allowed turn that
    /// reached no feed is a LOUD warn.
    pub feed_error: Option<FeedError>,
    /// The media marker for the reply text, when an original rode along — or
    /// the note that a photo did not (its app does not take photos).
    pub media_marker: Option<&'static str>,
    /// The display names of the channels this member speaks on (empty for an
    /// unknown sender) — the ask-back names THESE, never a generic example.
    pub channels: Vec<String>,
    /// The display name of the channel the turn went to.
    pub channel_name: Option<String>,
    /// The bound notice this contact has NOT yet received («✅ 绑定成功…»): the
    /// transport loop sends it FIRST on this turn (the first inbound is the first
    /// moment an iLink bot can answer — no context token exists before it),
    /// then marks the row welcomed. `None` once delivered.
    pub welcome: Option<String>,
    /// #722 — the channel ids a `router_ask` named, best first.
    pub ask_candidates: Vec<String>,
    /// The labels the numbered ask shows for them (parallel).
    pub ask_labels: Vec<String>,
    /// #722 — what the router tier did on this turn (audit + monitor).
    pub router: Option<RouterTrace>,
    /// #722 — a line about the member's media appended to the reply: photos
    /// waiting with an ask, a batch delivered, a photo its app does not take,
    /// or held photos released by a message that did not answer the ask.
    pub notice: Option<String>,
}

/// #722 — the reply suffix when a turn's text went on but its photo did not
/// (the app does not take photos).
pub const PHOTO_NOT_TAKEN_ZH: &str = "（照片没有转达：它不接收照片）";
pub const PHOTO_NOT_TAKEN_EN: &str = "(the photo was not passed on — it doesn't take photos)";
/// #722 — the reply suffix when a photo went on as its description.
pub const PHOTO_AS_TEXT_ZH: &str = "（照片已转成文字转达：它不接收照片）";
pub const PHOTO_AS_TEXT_EN: &str = "(the photo went on as a description — it doesn't take photos)";

/// Where a photo goes by the apps' declared kinds alone.
enum PhotoRoute {
    Channel(String, Option<String>, &'static str),
    Ask(Vec<String>, Vec<Option<String>>),
    NoApp,
}

/// The app a media turn addresses on a channel: the one app there that takes
/// the kind, else the channel's default when it takes it, else the first
/// that takes it.
fn media_addressee(
    registry: &agentkeys_protocol::ContactRegistry,
    option: &ChannelOption,
    kind: ChannelEventKind,
) -> Option<String> {
    let taking = option.apps_taking(kind);
    if let [one] = taking.as_slice() {
        return Some(one.alias.clone());
    }
    let default = default_addressee(registry, option);
    if let Some(d) = default.as_deref() {
        if option.takes(d, kind) {
            return default;
        }
    }
    taking.first().map(|a| a.alias.clone())
}

/// The app an unaddressed turn on this channel goes to (the document's
/// default, else its only app).
fn default_addressee(
    registry: &agentkeys_protocol::ContactRegistry,
    option: &ChannelOption,
) -> Option<String> {
    let doc_default = registry
        .channel(&option.id)
        .and_then(|d| d.default_app.clone());
    option.default_app(doc_default.as_deref())
}

/// A photo the model did not route: the one channel of the member's where an
/// app takes it, else the conversation's channel when an app there takes it,
/// else a numbered ask among those that do. Always a subset of the member's
/// channels (D10).
fn route_photo_by_declared_kinds(
    state: &WeixinGatewayState,
    registry: &agentkeys_protocol::ContactRegistry,
    options: &[ChannelOption],
    kind: ChannelEventKind,
    transport: &str,
    transport_id: &str,
    anchor_superseded: bool,
) -> PhotoRoute {
    let candidates: Vec<&ChannelOption> = options
        .iter()
        .filter(|o| !o.apps_taking(kind).is_empty())
        .collect();
    match candidates.as_slice() {
        [] => PhotoRoute::NoApp,
        [one] => PhotoRoute::Channel(
            one.id.clone(),
            media_addressee(registry, one, kind),
            if options.len() > 1 {
                "single_media_channel"
            } else {
                "single_channel"
            },
        ),
        _ => {
            let last = (!anchor_superseded)
                .then(|| state.device.last_channel(transport, transport_id))
                .flatten()
                .and_then(|l| candidates.iter().find(|o| o.id == l).copied());
            match last {
                Some(o) => PhotoRoute::Channel(
                    o.id.clone(),
                    media_addressee(registry, o, kind),
                    "sticky_last_channel",
                ),
                None => {
                    let picked: Vec<&ChannelOption> =
                        candidates.into_iter().take(jev::ASK_CANDIDATES).collect();
                    PhotoRoute::Ask(
                        picked.iter().map(|o| o.id.clone()).collect(),
                        picked
                            .iter()
                            .map(|o| media_addressee(registry, o, kind))
                            .collect(),
                    )
                }
            }
        }
    }
}

impl RelayOutcome {
    /// The reply this turn gets (`None` = a silent drop) — the ONE reply every
    /// transport sends. An allowed turn says «✅ 已转达» only when its feed hop
    /// landed; otherwise the member is told the message did not reach the app,
    /// and why. The #722 media notice rides only a turn that landed: it says
    /// what went on.
    pub fn reply_text(&self, en: bool, stage_hint: Option<&str>) -> Option<String> {
        if self.decision.allowed && self.feed.is_none() {
            return Some(undelivered_text(
                self.decision.target_alias.as_deref(),
                self.feed_error.as_ref().map(|e| e.cause),
                en,
            ));
        }
        let mut out = reply_text_for_turn(
            &self.decision,
            self.channel_name.as_deref(),
            self.media_marker,
            en,
            &self.channels,
            &self.ask_labels,
            stage_hint,
        )?;
        if let Some(n) = &self.notice {
            out.push_str(n);
        }
        Some(out)
    }
}

/// #722 — the router tier's trace for one turn: which engine answered, the
/// model version, the verdict and its confidence. Never the message.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouterTrace {
    /// `jev` (the model answered) or `deterministic_fallback` (it could not).
    pub engine: String,
    pub model: String,
    /// `route` / `follow_up` / `ask` / `malformed` / `unavailable`.
    pub verdict: String,
    /// What the threshold was compared with: the destination pick's
    /// probability, or the `continues` yes/no for a follow-up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// The channel ids the verdict named (the pick, or the ask's list).
    pub candidates: Vec<String>,
}

/// #722 — one model-consulting turn as the router view shows it; the turn's end
/// fills in `total_ms` and `delivered`.
#[allow(clippy::too_many_arguments)]
fn router_exchange(
    c: &agentkeys_protocol::Contact,
    text: &str,
    photo: bool,
    last_channel: Option<&str>,
    req: &agentkeys_protocol::SystemOneRequest,
    resp: Option<&agentkeys_protocol::SystemOneResponse>,
    trace: &RouterTrace,
    routed_to: Option<&str>,
    addressee: Option<&str>,
    (describe_ms, decide_ms): (Option<u64>, u64),
    error: Option<String>,
) -> agentkeys_protocol::RouterExchange {
    agentkeys_protocol::RouterExchange {
        ts_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        contact: c.display_name.clone(),
        tier: c.tier.as_str().to_string(),
        text: text.to_string(),
        photo,
        last_channel: last_channel.map(str::to_string),
        request: serde_json::to_value(req).unwrap_or(serde_json::Value::Null),
        probabilities: resp
            .and_then(|r| r.choice(jev::DESTINATION_QUESTION))
            .map(|(_, p, _)| p.clone())
            .unwrap_or_default(),
        continues: resp.and_then(|r| r.noul(jev::CONTINUES_QUESTION)),
        verdict: trace.verdict.clone(),
        routed_to: routed_to.map(str::to_string),
        addressee: addressee.map(str::to_string),
        confidence: trace.confidence,
        answered_by: resp.map(|r| r.model.clone()).unwrap_or_default(),
        describe_ms,
        decide_ms: Some(decide_ms),
        total_ms: 0,
        delivered: false,
        error,
    }
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
/// #444) — contacts bind per (transport, transport_id).
pub async fn process_inbound_for(
    state: &WeixinGatewayState,
    transport: &str,
    transport_id: &str,
    raw_text: &str,
) -> RelayOutcome {
    process_turn(state, transport, transport_id, raw_text, None).await
}

/// The labels the member reads for a list of channel ids.
fn labels_for(options: &[ChannelOption], ids: &[String]) -> Vec<String> {
    ids.iter()
        .map(|id| {
            options
                .iter()
                .find(|o| &o.id == id)
                .map(|o| o.name.clone())
                .unwrap_or_else(|| id.clone())
        })
        .collect()
}

/// The full turn: resolve the channel (`/alias` → the alias's channel of the
/// member's; a numbered ask's answer; the Jev tier over the member's channel
/// documents; the whole-word tier) → L3 → the FEED HOP for an allowed turn
/// (media original by ref, text event correlated to it, contact stamp, the
/// addressee) → audit → live monitor.
pub async fn process_turn(
    state: &WeixinGatewayState,
    transport: &str,
    transport_id: &str,
    raw_text: &str,
    media: Option<InboundMedia>,
) -> RelayOutcome {
    let turn_started = std::time::Instant::now();
    let (explicit_alias, mut turn_text) = parse_alias(raw_text);
    let registry = state.registry.snapshot();
    let contact = registry.resolve(transport, transport_id);
    let now_secs = unix_secs();
    // #722 — what the router view shows of a turn that consulted a model.
    let mut describe_ms: Option<u64> = None;
    let mut exchange: Option<agentkeys_protocol::RouterExchange> = None;

    // Turns with no `/alias`, in order:
    // 1. The reply to a live numbered ask delivers the member's ORIGINAL
    //    message, with the photo or clip that waited for it.
    // 2. A photo is described first (the stack's vision model, through the
    //    model gate) and routed by that line like a typed message, over the
    //    member's channels; the photo itself goes only to an app whose binding
    //    takes photos — any other app gets the description as text (at
    //    delivery, below; the declared kinds are the disclosed model paths). A
    //    voice clip is routed by its transcript the same way.
    // 3. One channel gets the turn.
    // 4. Text — a message, a caption, a transcript, a photo's description —
    //    goes to the Jev tier over the channels: confident → route, unsure →
    //    ask (filed after L3).
    // 5. A photo the model did not route (no description, or no answer) goes
    //    by the apps' declared kinds: the one channel where an app takes
    //    photos, else the conversation's channel when it does, else a numbered
    //    ask while the photo waits in memory.
    // 6. Nothing decided: the whole-word tier (an app's name, a channel's name
    //    in the text).
    // An unusable / unreachable / unconfigured model leaves the turn to the
    // whole-word tier, as before. Every branch stays inside the member's own
    // channels (D10).
    let mut media = media;
    let mut routed_by_override: Option<&'static str> = None;
    // The resolved channel + the app addressed on it (the transport's `resolve`).
    let mut channel: Option<String> = None;
    let mut addressee: Option<String> = None;
    let mut ask_candidates: Vec<String> = Vec::new();
    let mut ask_addressees: Vec<Option<String>> = Vec::new();
    let mut router_trace: Option<RouterTrace> = None;
    // The member's options: every channel document that lists them with
    // `speak`, rendered for the model; `turn_options` narrows them to the
    // channels an app takes this turn's media on.
    let options: Vec<ChannelOption> = contact
        .map(|c| jev::channel_options(&registry, &c.contact_id))
        .unwrap_or_default();
    let mut turn_options: Vec<ChannelOption> = options.clone();
    // No channel of the member's has an app that takes the media they sent.
    let mut no_media_app = false;
    // An explicit `/alias` names an app on none of the member's channels.
    let mut alias_out_of_reach = false;
    // The member's previous message was asked back and has not reached an app.
    let mut anchor_superseded = false;
    // The ask queue (#722, owner 2026-09-26): messages whose asks ran out, the
    // question still waiting, the one that comes up next, a cancel word, and
    // whether this message's own ask queued behind an older one.
    let mut expired_messages = 0usize;
    let mut waiting_oldest: Option<Vec<String>> = None;
    let mut next_ask: Option<Vec<String>> = None;
    let mut cancelled = false;
    let mut queued_behind = false;
    // This photo joined an ask that already holds photos (how many it holds).
    let mut joined_ask: Option<usize> = None;
    // The answer's further held photos (the first rides as the turn's media).
    let mut extra_media: Vec<InboundMedia> = Vec::new();
    // The photo's one-line description, when it was routed by it (memory
    // only, D13) — what an app that takes no photos receives instead.
    let mut photo_description: Option<String> = None;

    // `/alias`: the alias's channel among the member's own (a household
    // channel first, else its operator channel), addressed to it.
    if let (Some(a), Some(c)) = (explicit_alias.as_deref(), contact) {
        match registry.alias_channel_for(&c.contact_id, a) {
            Some(doc) => {
                channel = Some(doc.id.clone());
                addressee = Some(a.to_lowercase());
            }
            None => alias_out_of_reach = true,
        }
    }
    // A photo sent while an earlier photo waits for its ask joins it.
    if explicit_alias.is_none() && contact.is_some() && turn_text.trim().is_empty() {
        if let Some(m) = media.as_ref() {
            if let Some((labels, held)) =
                state.hold_media_with_ask(transport, transport_id, m.clone(), now_secs)
            {
                ask_candidates = labels;
                joined_ask = Some(held);
            }
        }
    }
    if explicit_alias.is_none() && joined_ask.is_none() {
        if let Some(c) = contact {
            let has_text = !turn_text.trim().is_empty();
            // Only a text turn can answer an ask; any other turn drops it.
            let answer_text = if media.is_none() {
                turn_text.as_str()
            } else {
                ""
            };
            let (ask_reply, expired) =
                state.take_ask_reply(transport, transport_id, answer_text, now_secs);
            if expired.messages > 0 {
                anchor_superseded = true;
                expired_messages = expired.messages;
            }
            match &ask_reply {
                jev::AskReply::Waiting { oldest } => {
                    anchor_superseded = true;
                    waiting_oldest = Some(oldest.clone());
                }
                jev::AskReply::Cancelled { next, .. } => {
                    cancelled = true;
                    next_ask = next.clone();
                }
                jev::AskReply::Answered { next, .. } => next_ask = next.clone(),
                jev::AskReply::NoAsk => {}
            }
            // Describe a photo unless its route is already certain (the
            // member's one channel, and an app there takes photos).
            let is_photo = media
                .as_ref()
                .is_some_and(|m| m.kind == ChannelEventKind::Image);
            let answered = matches!(ask_reply, jev::AskReply::Answered { .. });
            let route_is_certain =
                options.len() == 1 && !options[0].apps_taking(ChannelEventKind::Image).is_empty();
            if is_photo && !answered && !route_is_certain && state.config.router.describe_photos {
                if let (Some(client), Some(m)) = (state.jev.as_ref(), media.as_ref()) {
                    let describe_started = std::time::Instant::now();
                    match client
                        .describe(
                            m,
                            state.config.router.describe_model.as_deref(),
                            state.config.router.describe_timeout_ms,
                        )
                        .await
                    {
                        Ok(d) => photo_description = Some(d),
                        Err(e) => tracing::warn!(
                            contact = %c.contact_id,
                            error = %e,
                            "#722 the photo could not be described — the apps' declared kinds route it"
                        ),
                    }
                    describe_ms = Some(describe_started.elapsed().as_millis() as u64);
                }
            }
            let routing_text = match &photo_description {
                Some(d) => jev::photo_message(&turn_text, d),
                None => turn_text.clone(),
            };
            let has_routing_text = !routing_text.trim().is_empty();
            let narrow_to = match media.as_ref().map(|m| m.kind) {
                Some(ChannelEventKind::AudioClip) if has_text => None,
                Some(ChannelEventKind::Image) if photo_description.is_some() => None,
                kind => kind,
            };
            if let Some(kind) = narrow_to {
                turn_options.retain(|o| !o.apps_taking(kind).is_empty());
            }
            if cancelled {
                // The cancel word is not a message: nothing routes.
            } else if let jev::AskReply::Answered {
                channel: chosen,
                addressee: chosen_app,
                original_text,
                media: held,
                description,
                ..
            } = ask_reply
            {
                channel = Some(chosen);
                addressee = chosen_app;
                turn_text = original_text;
                let mut held = held.into_iter();
                media = held.next();
                extra_media = held.collect();
                photo_description = description;
                routed_by_override = Some("ask_reply");
            } else if !has_routing_text {
                if media.is_some() {
                    match route_photo_by_declared_kinds(
                        state,
                        &registry,
                        &options,
                        media
                            .as_ref()
                            .map(|m| m.kind)
                            .unwrap_or(ChannelEventKind::Image),
                        transport,
                        transport_id,
                        anchor_superseded,
                    ) {
                        PhotoRoute::Channel(id, app, by) => {
                            channel = Some(id);
                            addressee = app;
                            routed_by_override = Some(by);
                        }
                        PhotoRoute::Ask(ids, apps) => {
                            ask_candidates = ids;
                            ask_addressees = apps;
                        }
                        PhotoRoute::NoApp => no_media_app = true,
                    }
                }
            } else if turn_options.is_empty() {
                no_media_app = media.is_some();
            } else if turn_options.len() == 1 {
                let only = &turn_options[0];
                channel = Some(only.id.clone());
                addressee = match media.as_ref().map(|m| m.kind) {
                    Some(kind) => media_addressee(&registry, only, kind),
                    None => default_addressee(&registry, only),
                };
                routed_by_override = Some(if options.len() > 1 {
                    "single_media_channel"
                } else {
                    "single_channel"
                });
            } else {
                if let Some(client) = state.jev.as_ref() {
                    // The follow-up anchor is the channel the member's PREVIOUS
                    // message went to — none when that message was asked back
                    // and never answered (the stored last channel is older).
                    let last = (!anchor_superseded)
                        .then(|| state.device.last_channel(transport, transport_id))
                        .flatten()
                        .filter(|l| turn_options.iter().any(|o| &o.id == l));
                    let req = jev::build_request(
                        &state.config.router.model,
                        &routing_text,
                        &c.display_name,
                        c.tier.as_str(),
                        last.as_deref(),
                        &turn_options,
                    );
                    let option_keys = jev::option_keys(&turn_options);
                    let decide_started = std::time::Instant::now();
                    let decided = client.decide(&req).await;
                    let decide_ms = decide_started.elapsed().as_millis() as u64;
                    let photo = photo_description.is_some();
                    let log = |resp: Option<&agentkeys_protocol::SystemOneResponse>,
                               trace: &RouterTrace,
                               routed_to: Option<&str>,
                               to_app: Option<&str>,
                               error: Option<String>| {
                        router_exchange(
                            c,
                            &routing_text,
                            photo,
                            last.as_deref(),
                            &req,
                            resp,
                            trace,
                            routed_to,
                            to_app,
                            (describe_ms, decide_ms),
                            error,
                        )
                    };
                    match decided {
                        Ok(resp) => match jev::verdict_from(
                            &resp,
                            &option_keys,
                            state.config.router.threshold,
                            last.as_deref(),
                            state.config.router.continue_threshold,
                        ) {
                            JevVerdict::Route {
                                channel: picked,
                                addressee: named,
                                confidence,
                                follow_up,
                            } => {
                                let option = turn_options
                                    .iter()
                                    .find(|o| o.id == picked)
                                    .expect("the verdict is bounded by the options");
                                // The app on the picked channel: the model's
                                // addressee answer for a shared channel, else
                                // the channel's default — and for media, one
                                // that takes it.
                                // A follow-up stays with the app of the previous
                                // turn when it is still on the channel.
                                let previous = follow_up
                                    .then(|| state.device.last_addressee(transport, transport_id))
                                    .flatten()
                                    .filter(|a| {
                                        option.apps.iter().any(|x| x.alias.eq_ignore_ascii_case(a))
                                    });
                                let to_app = match media.as_ref().map(|m| m.kind) {
                                    Some(kind) if photo_description.is_none() => {
                                        media_addressee(&registry, option, kind)
                                    }
                                    _ => previous
                                        .or_else(|| named.clone())
                                        .or_else(|| default_addressee(&registry, option)),
                                };
                                let trace = RouterTrace {
                                    engine: "jev".into(),
                                    model: resp.model.clone(),
                                    verdict: if follow_up { "follow_up" } else { "route" }.into(),
                                    confidence: Some(confidence),
                                    candidates: vec![picked.clone()],
                                };
                                exchange = Some(log(
                                    Some(&resp),
                                    &trace,
                                    Some(&picked),
                                    to_app.as_deref(),
                                    None,
                                ));
                                router_trace = Some(trace);
                                channel = Some(picked);
                                addressee = to_app;
                                routed_by_override =
                                    Some(if follow_up { "jev_follow_up" } else { "jev" });
                            }
                            JevVerdict::Ask {
                                candidates,
                                confidence,
                            } => {
                                let trace = RouterTrace {
                                    engine: "jev".into(),
                                    model: resp.model.clone(),
                                    verdict: "ask".into(),
                                    confidence: Some(confidence),
                                    candidates: candidates.clone(),
                                };
                                exchange = Some(log(Some(&resp), &trace, None, None, None));
                                router_trace = Some(trace);
                                // The pick answers name a channel; the app on a
                                // shared one is the channel's default.
                                ask_addressees = vec![None; candidates.len()];
                                ask_candidates = candidates;
                            }
                            JevVerdict::Malformed(why) => {
                                tracing::warn!(
                                    contact = %c.contact_id,
                                    model = %resp.model,
                                    why,
                                    "#722 the decision model's answer was unusable — the deterministic tier runs"
                                );
                                let trace = RouterTrace::fallback(&resp.model, "malformed");
                                exchange = Some(log(Some(&resp), &trace, None, None, Some(why)));
                                router_trace = Some(trace);
                            }
                        },
                        Err(jev::JevError::Unconfigured) => {
                            tracing::info!(
                                contact = %c.contact_id,
                                "#722 the model gate has no decision model yet (503) — the deterministic tier runs"
                            );
                            let trace =
                                RouterTrace::fallback(&state.config.router.model, "unavailable");
                            exchange = Some(log(
                                None,
                                &trace,
                                None,
                                None,
                                Some("the model gate has no decision model (503)".into()),
                            ));
                            router_trace = Some(trace);
                        }
                        Err(e) => {
                            tracing::warn!(
                                contact = %c.contact_id,
                                error = %e,
                                "#722 the model gate did not answer — the deterministic tier runs"
                            );
                            let trace =
                                RouterTrace::fallback(&state.config.router.model, "unavailable");
                            exchange = Some(log(None, &trace, None, None, Some(e.to_string())));
                            router_trace = Some(trace);
                        }
                    }
                }
                // A described photo the model did not route: its declared kinds.
                if photo_description.is_some() && channel.is_none() && ask_candidates.is_empty() {
                    match route_photo_by_declared_kinds(
                        state,
                        &registry,
                        &options,
                        ChannelEventKind::Image,
                        transport,
                        transport_id,
                        anchor_superseded,
                    ) {
                        PhotoRoute::Channel(id, app, by) => {
                            channel = Some(id);
                            addressee = app;
                            routed_by_override = Some(by);
                        }
                        PhotoRoute::Ask(ids, apps) => {
                            ask_candidates = ids;
                            ask_addressees = apps;
                        }
                        PhotoRoute::NoApp => no_media_app = true,
                    }
                }
            }
        }
    }

    // The whole-word tier: a message that names an app or a channel of the
    // member's goes there whatever the tiers above decided short of a route
    // (a hit routes instead of an ask); a media turn left undecided goes to
    // the conversation's channel when an app there takes it (D10: within the
    // member's channels).
    if channel.is_none() && !cancelled && !alias_out_of_reach && !no_media_app {
        if let Some(c) = contact {
            match crate::router::advisory_route(
                &turn_text,
                &turn_options,
                state.config.router_enabled,
            ) {
                crate::router::RouteVerdict::Route {
                    channel: hit,
                    alias,
                } => {
                    let option = turn_options.iter().find(|o| o.id == hit);
                    addressee = alias.or_else(|| {
                        option.and_then(|o| match media.as_ref().map(|m| m.kind) {
                            Some(kind) => media_addressee(&registry, o, kind),
                            None => default_addressee(&registry, o),
                        })
                    });
                    channel = Some(hit);
                    routed_by_override = Some("advisory_router");
                    ask_candidates.clear();
                    ask_addressees.clear();
                    tracing::debug!(contact = %c.contact_id, "whole-word tier routed the turn");
                }
                crate::router::RouteVerdict::AskBack
                    if media.is_some() && ask_candidates.is_empty() =>
                {
                    let sticky = (!anchor_superseded)
                        .then(|| state.device.last_channel(transport, transport_id))
                        .flatten()
                        .and_then(|l| turn_options.iter().find(|o| o.id == l));
                    if let Some(o) = sticky {
                        addressee = media
                            .as_ref()
                            .and_then(|m| media_addressee(&registry, o, m.kind));
                        channel = Some(o.id.clone());
                        routed_by_override = Some("sticky_last_channel");
                    }
                }
                crate::router::RouteVerdict::AskBack => {}
            }
        }
    }
    let mut inbound = GatewayInbound {
        transport: transport.to_string(),
        transport_id: transport_id.to_string(),
        text: turn_text,
        alias: addressee.clone(),
        channel: channel.clone(),
    };

    // L3 (the PEP) — rate check + the pure decision.
    let rate_ok = state.rate.check(transport_id, now_secs);
    let mut decision = crate::l3::decide(&state.config, &registry, &inbound, rate_ok);
    if decision.allowed && decision.routed_by.is_none() {
        if let Some(r) = routed_by_override {
            decision.routed_by = Some(r.to_string());
        }
    }
    if alias_out_of_reach && !decision.allowed && decision.reason == "no_channel" {
        decision.reason = "out_of_reach".to_string();
    }
    // #722 — the model was unsure (or a photo has two or more possible
    // channels) and the whole-word tier found nothing either: the refusal
    // becomes a numbered ask, and the member's original text — and photo —
    // wait in memory for the answer.
    if !decision.allowed && decision.reason == "no_channel" && !ask_candidates.is_empty() {
        decision.reason = "router_ask".to_string();
        if joined_ask.is_none() {
            let labels = labels_for(&options, &ask_candidates);
            if ask_addressees.len() != ask_candidates.len() {
                ask_addressees = vec![None; ask_candidates.len()];
            }
            if let Some(oldest) = state.queue_ask(
                transport,
                transport_id,
                jev::PendingAsk {
                    original_text: inbound.text.clone(),
                    candidates: ask_candidates.clone(),
                    labels: labels.clone(),
                    addressees: ask_addressees.clone(),
                    asked_at_secs: now_secs,
                    expires_at_secs: now_secs.saturating_add(state.config.router.ask_ttl_secs),
                    media: media.iter().cloned().collect(),
                    description: photo_description.clone(),
                },
            ) {
                // Answers resolve the oldest first: ask that one now; this
                // message's own question comes up once it is answered.
                ask_candidates = oldest;
                queued_behind = true;
            }
        }
    } else {
        ask_candidates.clear();
    }
    // `ask_candidates` holds ids on a fresh ask and the oldest ask's LABELS
    // when this message queued behind it or a photo joined it.
    let ask_labels: Vec<String> = if queued_behind || joined_ask.is_some() {
        ask_candidates.clone()
    } else {
        labels_for(&options, &ask_candidates)
    };
    if cancelled {
        decision.allowed = false;
        decision.reason = "ask_cancelled".to_string();
        decision.target_alias = None;
        decision.channel_id = None;
    }
    // The media rides only to an app that takes it: a caption or transcript
    // still goes on its own; a photo alone to such an app does not go at all.
    let sent_media = media.as_ref().map(|m| m.kind);
    let sent_marker = media.as_ref().map(|m| m.marker());
    let mut media_not_taken = false;
    if decision.allowed {
        if let (Some(target), Some(ch), Some(m)) = (
            decision.target_alias.as_deref(),
            decision.channel_id.as_deref(),
            media.as_ref(),
        ) {
            media_not_taken = !registry
                .channel(ch)
                .is_some_and(|d| d.takes(target, m.kind));
        }
    }
    // A photo that went as its description instead (the app takes no photos).
    let mut photo_as_text = false;
    if media_not_taken {
        media = None;
        match (sent_media, photo_description.as_deref()) {
            (Some(ChannelEventKind::Image), Some(description)) => {
                inbound.text = jev::photo_as_text(&inbound.text, description);
                photo_as_text = true;
            }
            _ if inbound.text.trim().is_empty() => {
                decision.allowed = false;
                decision.target_alias = None;
                decision.channel_id = None;
                decision.routed_by = None;
                decision.reason = "no_media_app".to_string();
            }
            _ => {}
        }
    }
    if !decision.allowed && decision.reason == "no_channel" && no_media_app {
        decision.reason = "no_media_app".to_string();
    }
    let (contact_id, tier) = contact
        .map(|c| (c.contact_id.clone(), c.tier.as_str().to_string()))
        .unwrap_or_default();
    let channels: Vec<String> = options.iter().map(|o| o.name.clone()).collect();
    let channel_name = decision
        .channel_id
        .as_deref()
        .and_then(|id| registry.channel(id))
        .map(|d| d.display_name().to_string());
    // The member's acknowledgement is never missed: a bound contact whose notice
    // could not be delivered at bind time (an iLink bot cannot send before the
    // member's first message) gets it with this very turn, before anything else.
    let welcome = contact
        .filter(|c| !c.welcomed)
        .map(|c| bound_notice(c, &registry));

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
    let mut extra_delivered = 0usize;
    let event = if decision.allowed {
        let alias = decision.target_alias.clone().unwrap_or_default();
        let channel_id = decision.channel_id.clone().unwrap_or_default();
        state
            .device
            .set_last_turn(transport, transport_id, &channel_id, &alias);
        let stamp = ContactStamp {
            contact_id: contact_id.clone(),
            tier: tier.clone(),
        };
        match feed_hop(state, &channel_id, &alias, &inbound, media.as_ref(), &stamp).await {
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
        // #722 — the rest of an answered batch: one media event each.
        if feed.is_some() {
            let media_only = GatewayInbound {
                transport: inbound.transport.clone(),
                transport_id: inbound.transport_id.clone(),
                text: String::new(),
                alias: inbound.alias.clone(),
                channel: inbound.channel.clone(),
            };
            let takes = |m: &InboundMedia| {
                registry
                    .channel(&channel_id)
                    .is_some_and(|d| d.takes(&alias, m.kind))
            };
            for m in extra_media.iter().filter(|m| takes(m)) {
                match feed_hop(state, &channel_id, &alias, &media_only, Some(m), &stamp).await {
                    Ok(_) => extra_delivered += 1,
                    Err(e) => tracing::warn!(
                        channel = %channel_id,
                        contact = %contact_id,
                        "#722 a held photo / clip of the answered batch did NOT land: {e}"
                    ),
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
            addressee: Some(alias),
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
    if let Some(m) = sent_marker {
        preview = if preview.trim().is_empty() {
            m.to_string()
        } else {
            format!("{m} {preview}")
        };
    }
    let target = match (decision.target_alias.as_deref(), channel_name.as_deref()) {
        (Some(a), Some(ch)) => Some(format!("{a} · {ch}")),
        (Some(a), None) => Some(a.to_string()),
        _ => None,
    };
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
        target,
        decision.routed_by.clone(),
        router_trace.as_ref().and_then(|r| r.confidence),
    );

    // #722 — what the member should know about their media on this turn.
    let en = transport == "telegram";
    let mut notes: Vec<String> = Vec::new();
    if let Some(held) = joined_ask {
        notes.push(if en {
            format!("({held} waiting — they go together once you choose)")
        } else {
            format!("（已收到 {held} 个，选择后一起转达）")
        });
    }
    if decision.allowed && extra_delivered > 0 {
        let n = extra_delivered + 1;
        notes.push(if en {
            format!("({n} in all)")
        } else {
            format!("（共 {n} 个）")
        });
    }
    if decision.allowed && photo_as_text {
        notes.push(
            if en {
                PHOTO_AS_TEXT_EN
            } else {
                PHOTO_AS_TEXT_ZH
            }
            .to_string(),
        );
    } else if decision.allowed && media_not_taken && sent_media == Some(ChannelEventKind::Image) {
        notes.push(
            if en {
                PHOTO_NOT_TAKEN_EN
            } else {
                PHOTO_NOT_TAKEN_ZH
            }
            .to_string(),
        );
    }
    if expired_messages > 0 {
        notes.push(jev::expired_note(expired_messages, en));
    }
    if queued_behind {
        notes.push(jev::queued_note(en).to_string());
    } else if let Some(oldest) = &waiting_oldest {
        notes.push(jev::waiting_note(oldest, en));
    }
    if let Some(next) = &next_ask {
        notes.push(jev::next_note(next, en));
    }
    let notice = (!notes.is_empty()).then(|| notes.concat());

    if let Some(mut x) = exchange {
        x.total_ms = turn_started.elapsed().as_millis() as u64;
        x.delivered = feed.is_some();
        state.record_router_exchange(x);
    }

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
        channels,
        channel_name,
        welcome,
        ask_candidates,
        ask_labels,
        router: router_trace,
        notice,
    }
}

/// The member's half of the bind ceremony — what they are told in their own
/// chat once bound: who they are to the household and which channels they are
/// in (the apps bound to each), and that a plain message finds its channel.
pub fn bound_notice(
    c: &agentkeys_protocol::Contact,
    registry: &agentkeys_protocol::ContactRegistry,
) -> String {
    let who = format!("{}（{}）", c.display_name, tier_zh(c.tier));
    let mine = registry.speak_channels(&c.contact_id);
    if mine.is_empty() {
        return format!("✅ 绑定成功：{who}。管理员还没有把你加入任何频道，加入后会自动生效。");
    }
    let listed: Vec<String> = mine
        .iter()
        .map(|d| {
            let apps: Vec<&str> = d.apps.iter().map(|a| a.alias.as_str()).collect();
            if apps.is_empty() {
                d.display_name().to_string()
            } else {
                format!("{}（{}）", d.display_name(), apps.join("、"))
            }
        })
        .collect();
    let first_alias = mine
        .iter()
        .flat_map(|d| d.apps.iter())
        .map(|a| a.alias.clone())
        .next()
        .unwrap_or_else(|| "chef".to_string());
    format!(
        "✅ 绑定成功：{who}。你的频道：{}。直接发消息就会送到合适的频道；也可以用“/{first_alias} 你好”指定助手。",
        listed.join("、")
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

/// The ask-back for a bound member whose message found no channel: it names
/// THEIR channels (a generic example is useless to someone not on it). No
/// channel at all = the owner has not added them anywhere yet.
pub fn ask_back_text(channels: &[String], en: bool) -> String {
    if channels.is_empty() {
        return if en {
            "You are not in any channel yet — the owner adds you from Parent Control.".to_string()
        } else {
            "管理员还没有把你加入任何频道，加入后就可以直接发消息。".to_string()
        };
    }
    let list = channels.join(if en { ", " } else { "、" });
    if en {
        format!(
            "Say what you need and it goes to the right channel — yours: {list}. You can also address an assistant with /alias, or rephrase."
        )
    } else {
        format!(
            "直接说要做什么，会自动送到合适的频道；你的频道：{list}。也可以用 /别名 指定助手，或换个说法。"
        )
    }
}

/// #667 — the feed hop: the media original by ref (blob-put beside the feed,
/// then an `image` / `audio-clip` event), the text as a `text` event correlated
/// to it (`relay_of`), both stamped with the contact this device relayed for
/// and addressed to the app the turn is for. The worker stamps the producer
/// (this device actor) from the cap; a consumer trusts the `contact` stamp
/// only because the feed's endpoint actor is this gateway (the spawn
/// context's `bound_channels`).
async fn feed_hop(
    state: &WeixinGatewayState,
    channel_id: &str,
    addressee: &str,
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
    let to_app = (!addressee.trim().is_empty()).then(|| addressee.to_string());
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
                    addressee: to_app.clone(),
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
                        addressee: to_app,
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
/// is a delivery receipt naming the app and the channel: only
/// [`RelayOutcome::reply_text`] reaches it, after the feed hop landed.
fn reply_text_for(decision: &L3Decision, channel_name: Option<&str>) -> Option<String> {
    if decision.allowed {
        let app = decision.target_alias.as_deref().unwrap_or("助手");
        return Some(match channel_name {
            Some(ch) => format!("✅ 已转达给 {app}（{ch}）"),
            None => format!("✅ 已转达给 {app}"),
        });
    }
    match decision.reason.as_str() {
        "unknown_contact" => None,
        "rate_limited" => Some("⏳ 消息太频繁，请稍后再试。".to_string()),
        "no_channel" => Some(
            "直接说要做什么，会自动送到合适的频道；也可以用 /别名 指定助手，或换个说法。"
                .to_string(),
        ),
        "no_media_app" => {
            Some("你频道里的助手都不接收这类消息（照片或语音），请发文字。".to_string())
        }
        // #722 — the candidate-naming ask is composed by `reply_text_for_turn`
        // (it has the candidates); this is the generic fallback wording.
        "router_ask" => Some("请回复数字选择要发到的频道。".to_string()),
        "out_of_reach" => Some("⛔ 你的频道里没有这个助手。".to_string()),
        "no_membership" => Some("⛔ 你不能在这个频道发言。".to_string()),
        "app_not_on_channel" => Some("⛔ 这个助手不在那个频道。".to_string()),
        "addressee_unclear" => Some("这个频道有几个助手，请用 /别名 说明找谁。".to_string()),
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
fn reply_text_for_en(decision: &L3Decision, channel_name: Option<&str>) -> Option<String> {
    if decision.allowed {
        let app = decision.target_alias.as_deref().unwrap_or("your assistant");
        return Some(match channel_name {
            Some(ch) => format!("✅ Passed along to {app} ({ch})"),
            None => format!("✅ Passed along to {app}"),
        });
    }
    match decision.reason.as_str() {
        "unknown_contact" => None,
        "rate_limited" => Some("⏳ Too many messages — try again in a minute.".to_string()),
        "no_channel" => Some(
            "Say what you need and it goes to the right channel; you can also address an assistant with /alias, or rephrase."
                .to_string(),
        ),
        "no_media_app" => Some(
            "No assistant in your channels takes this kind of message (a photo or a voice clip) — send text."
                .to_string(),
        ),
        "router_ask" => Some("Reply with the number of the channel you meant.".to_string()),
        "out_of_reach" => Some("⛔ That assistant is in none of your channels.".to_string()),
        "no_membership" => Some("⛔ You can't post in that channel.".to_string()),
        "app_not_on_channel" => Some("⛔ That assistant is not in that channel.".to_string()),
        "addressee_unclear" => Some(
            "Several assistants are in that channel — say which with /alias.".to_string(),
        ),
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
    channel_name: Option<&str>,
    media_marker: Option<&str>,
    en: bool,
    channels: &[String],
    ask_labels: &[String],
    stage_hint: Option<&str>,
) -> Option<String> {
    let base = if !decision.allowed && decision.reason == "router_ask" {
        jev::ask_text(ask_labels, en)
    } else if !decision.allowed && decision.reason == "ask_cancelled" {
        jev::cancelled_text(en).to_string()
    } else if !decision.allowed && decision.reason == "no_channel" {
        ask_back_text(channels, en)
    } else if en {
        reply_text_for_en(decision, channel_name)?
    } else {
        reply_text_for(decision, channel_name)?
    };
    let mut out = match (decision.allowed, media_marker) {
        (true, Some(m)) => format!("{base} {m}"),
        (false, Some(m)) if decision.reason == "router_ask" => format!("{m} {base}"),
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
            channel_id: allowed.then(|| "family-chat".to_string()),
            reason: reason.to_string(),
            operator_grade_deeplink: (reason == "operator_grade_requires_session")
                .then(|| "https://pc.local/".to_string()),
            routed_by: None,
        }
    }

    #[test]
    fn ask_back_names_the_members_own_channels() {
        let channels = vec!["家庭群".to_string(), "chef·操作".to_string()];
        let zh = ask_back_text(&channels, false);
        assert!(zh.contains("家庭群、chef·操作"), "{zh}");
        let en = ask_back_text(&channels, true);
        assert!(en.contains("家庭群, chef·操作"), "{en}");
        assert!(ask_back_text(&[], false).contains("没有把你加入"));
        let turn = reply_text_for_turn(
            &decision(false, "no_channel"),
            None,
            None,
            false,
            &channels,
            &[],
            None,
        )
        .unwrap();
        assert!(turn.contains("chef·操作"), "{turn}");
        assert!(reply_text_for_turn(
            &decision(true, "ok"),
            Some("家庭群"),
            Some("📷"),
            false,
            &channels,
            &[],
            None
        )
        .unwrap()
        .ends_with("📷"));
        // #722 — the model's ask names the candidate channels, numbered.
        let asked = reply_text_for_turn(
            &decision(false, "router_ask"),
            None,
            None,
            false,
            &channels,
            &["chef·操作".to_string(), "家庭群".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(asked, "你是想发到 1 chef·操作 还是 2 家庭群？回复 1 或 2。");
    }

    #[test]
    fn reply_maps_every_decision_and_drops_unknown_silently() {
        assert_eq!(
            reply_text_for(&decision(true, "ok"), Some("家庭群")).unwrap(),
            "✅ 已转达给 chef（家庭群）"
        );
        assert!(
            reply_text_for(&decision(false, "unknown_contact"), None).is_none(),
            "unknown sender must get NO reply (silent drop)"
        );
        assert!(reply_text_for(&decision(false, "rate_limited"), None).is_some());
        assert!(reply_text_for(&decision(false, "no_channel"), None)
            .unwrap()
            .contains("/别名"));
        assert!(reply_text_for(&decision(false, "out_of_reach"), None).is_some());
        assert!(reply_text_for(&decision(false, "no_membership"), None).is_some());
        assert!(
            reply_text_for(&decision(false, "operator_grade_requires_session"), None)
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
                channel: Some("family-chat".into()),
            },
            decision,
            contact_id: "c-owner".into(),
            tier: "owner".into(),
            event: None,
            claim_ack: None,
            feed,
            feed_error,
            media_marker: Some("📷"),
            channels: vec!["家庭群".into()],
            channel_name: Some("家庭群".into()),
            welcome: None,
            ask_candidates: Vec::new(),
            ask_labels: Vec::new(),
            router: None,
            notice: None,
        }
    }

    #[test]
    fn a_media_notice_rides_only_a_landed_turn() {
        let landed = FeedReceipt {
            channel_id: "family-chat".into(),
            event_id: "evt-1".into(),
            media_event_id: None,
            body_ref: None,
        };
        let mut ok = outcome(decision(true, "ok"), Some(landed), None);
        ok.notice = Some(PHOTO_AS_TEXT_ZH.into());
        assert_eq!(
            ok.reply_text(false, None).unwrap(),
            format!("✅ 已转达给 chef（家庭群） 📷{PHOTO_AS_TEXT_ZH}")
        );
        let mut missed = outcome(
            decision(true, "ok"),
            None,
            Some(FeedError::new(FeedMiss::HopFailed, "detail for the logs")),
        );
        missed.notice = Some(PHOTO_AS_TEXT_ZH.into());
        assert_eq!(
            missed.reply_text(false, None).unwrap(),
            "⚠️ 消息没有送到 chef：这次没有发送成功，请稍后再试；一直不行的话请告诉管理员。"
        );
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
            "✅ 已转达给 chef（家庭群） 📷（它还在加载知识，稍等片刻）"
        );
        assert_eq!(
            ok.reply_text(true, None).unwrap(),
            "✅ Passed along to chef (家庭群) 📷"
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
            "⛔ 你的频道里没有这个助手。"
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
        let channels = vec!["家庭群".to_string()];
        let zh = reply_text_for_turn(
            &decision(true, "ok"),
            Some("家庭群"),
            None,
            false,
            &channels,
            &[],
            Some("loading"),
        )
        .unwrap();
        assert!(zh.contains("加载知识"), "{zh}");
        let en = reply_text_for_turn(
            &decision(true, "ok"),
            Some("家庭群"),
            Some("📷"),
            true,
            &channels,
            &[],
            Some("degraded"),
        )
        .unwrap();
        assert!(en.contains("📷") && en.contains("unavailable"), "{en}");
        let ready = reply_text_for_turn(
            &decision(true, "ok"),
            Some("家庭群"),
            None,
            true,
            &channels,
            &[],
            None,
        )
        .unwrap();
        assert!(!ready.contains("loading"));
        // a refused turn never carries the app's state (nothing was routed)
        let refused = reply_text_for_turn(
            &decision(false, "rate_limited"),
            None,
            None,
            false,
            &channels,
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
    fn the_bound_notice_lists_the_members_channels_with_their_apps() {
        let mut reg = agentkeys_protocol::ContactRegistry::default();
        let c = agentkeys_protocol::Contact {
            contact_id: "c-mama".into(),
            transport: "weixin".into(),
            transport_id: "o1".into(),
            display_name: "妈妈".into(),
            tier: agentkeys_protocol::ContactTier::Owner,
            legacy_reach: vec![],
            welcomed: false,
        };
        reg.bound.push(c.clone());
        assert!(bound_notice(&c, &reg).contains("没有把你加入"));
        let family = reg.channel_or_new("family-chat");
        family.name = "家庭群".into();
        family.upsert_app(agentkeys_protocol::ChannelApp {
            alias: "chef".into(),
            ..Default::default()
        });
        family.set_member("c-mama", true, true);
        let n = bound_notice(&c, &reg);
        assert!(
            n.contains("家庭群（chef）") && n.contains("/chef 你好"),
            "{n}"
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
        assert!(reply_text_for(&d, None).is_none());
    }

    #[test]
    fn decode_omni_accepts_0x_and_bare() {
        assert!(decode_omni_32(&format!("0x{}", "ab".repeat(32))).is_some());
        assert!(decode_omni_32(&"cd".repeat(32)).is_some());
        assert!(decode_omni_32("0xdeadbeef").is_none()); // too short
    }
}
