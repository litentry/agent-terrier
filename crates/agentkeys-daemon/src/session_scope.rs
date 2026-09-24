//! Typed sessions — the daemon half (owner decision 2026-09-23; vocabulary in
//! `agentkeys-protocol`'s `session_window`). Pure: which session one trigger
//! runs in, who may reset what, the window a lost session held (rebuilt from
//! the feed), and the card a tap was made on. The chat loop does the I/O.

use std::collections::HashMap;

use agentkeys_backend_client::protocol::{
    default_feed_session, parse_card, parse_session_reset, resolve_session, BridgeChatSession,
    BridgeSessionReset, ChannelDirection, ChannelEvent, ChannelEventKind, ChannelProducer,
    PresetSummary, SessionPolicy, SessionResetScope, SessionWindow, CARD_CONTENT_TYPE,
    SCHEDULE_SESSION,
};

use crate::app_runtime::{FeedSpec, OPCHAT_SLOT};

/// How many of a feed's newest events a rebuild reads.
pub const REBUILD_TAIL_EVENTS: u32 = 40;
/// How many of a feed's newest events a card lookup reads.
pub const CARD_LOOKUP_TAIL_EVENTS: u32 = 12;
const REBUILD_MAX_LINES: usize = 30;
const REBUILD_MAX_CHARS: usize = 6_000;
const LINE_MAX_CHARS: usize = 600;
const CARD_MAX_CHARS: usize = 8_000;

/// The reply a refused reset gets (the marker stays in the feed either way).
pub const RESET_REFUSED_REPLY: &str =
    "This conversation can only be restarted from here for your own thread.";

/// The acknowledgement a reset gets on the feed it arrived on.
pub fn reset_ack(scope: SessionResetScope) -> &'static str {
    match scope {
        SessionResetScope::App => {
            "New session started. The next message begins a fresh conversation."
        }
        SessionResetScope::Feed => "Started over. The next message here begins a fresh session.",
        SessionResetScope::Thread => "Started over. Your next message begins a fresh conversation.",
    }
}

/// The template's per-slot session overrides, by slot name.
pub fn slot_session_overrides(template: &PresetSummary) -> HashMap<String, SessionPolicy> {
    template
        .app
        .slots
        .iter()
        .filter_map(|slot| slot.session.map(|policy| (slot.slot.clone(), policy)))
        .collect()
}

/// Whose thread an event belongs to: the contact a relaying gateway stamped,
/// else the producer the worker stamped (never a payload-supplied field).
pub fn thread_party(event: &ChannelEvent) -> String {
    if let Some(stamp) = &event.contact {
        return stamp.contact_id.clone();
    }
    match &event.producer {
        ChannelProducer::Actor { actor_omni } => actor_omni.clone(),
        ChannelProducer::Contact { contact_id, .. } => contact_id.clone(),
    }
}

/// Whether a person outside the household's keys sent the event.
fn from_contact(event: &ChannelEvent) -> bool {
    event.contact.is_some() || matches!(event.producer, ChannelProducer::Contact { .. })
}

fn session_for(policy: SessionPolicy, scope: String, party: Option<String>) -> BridgeChatSession {
    BridgeChatSession {
        window: policy.window,
        scope,
        party: party.filter(|_| policy.window == SessionWindow::Thread),
        idle_minutes: policy.effective_idle_minutes(),
        context: None,
    }
}

/// The session a feed event's turn runs in: its trigger type's default, or
/// the template's override for the slot. `None` = never a turn (lifecycle).
pub fn feed_session(
    feed: &FeedSpec,
    event: &ChannelEvent,
    slot_override: Option<SessionPolicy>,
) -> Option<BridgeChatSession> {
    let policy = resolve_session(default_feed_session(feed.kind, event.kind), slot_override)?;
    Some(session_for(
        policy,
        feed.channel_id.clone(),
        Some(thread_party(event)),
    ))
}

/// The session a clock tick runs in: a clean one, unless the entry's
/// override keeps its runs together.
pub fn schedule_session(label: &str, entry_override: Option<SessionPolicy>) -> BridgeChatSession {
    let policy =
        resolve_session(Some(SCHEDULE_SESSION), entry_override).unwrap_or(SCHEDULE_SESSION);
    session_for(policy, format!("schedule:{label}"), None)
}

/// The daemon's own key for an open session (its "sent since boot" set).
pub fn open_session_key(session: &BridgeChatSession) -> Option<String> {
    session.window.keeps_session().then(|| {
        format!(
            "{}|{}|{}",
            session.window.as_str(),
            session.scope,
            session.party.as_deref().unwrap_or_default()
        )
    })
}

/// What a reset marker ends, given the feed it arrived on and who sent it.
/// `None` = refused: the whole app resets only from the owner's chat, and a
/// contact (a family member behind the gateway) resets only their own thread.
pub fn authorize_reset(
    scope: SessionResetScope,
    feed: &FeedSpec,
    event: &ChannelEvent,
) -> Option<BridgeSessionReset> {
    match scope {
        SessionResetScope::App => {
            (feed.slot == OPCHAT_SLOT && !from_contact(event)).then_some(BridgeSessionReset {
                scope,
                channel: None,
                party: None,
            })
        }
        SessionResetScope::Feed => (!from_contact(event)).then(|| BridgeSessionReset {
            scope,
            channel: Some(feed.channel_id.clone()),
            party: None,
        }),
        SessionResetScope::Thread => Some(BridgeSessionReset {
            scope,
            channel: Some(feed.channel_id.clone()),
            party: Some(thread_party(event)),
        }),
    }
}

fn inline_utf8(event: &ChannelEvent) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    event
        .body
        .as_deref()
        .and_then(|b| STANDARD.decode(b).ok())
        .and_then(|b| String::from_utf8(b).ok())
}

/// Does this marker end the session being rebuilt?
fn marker_covers(event: &ChannelEvent, session: &BridgeChatSession) -> bool {
    if event.kind != ChannelEventKind::Command || event.direction != ChannelDirection::In {
        return false;
    }
    let Some(scope) = inline_utf8(event).and_then(|t| parse_session_reset(t.as_bytes())) else {
        return false;
    };
    match scope {
        SessionResetScope::App | SessionResetScope::Feed => true,
        SessionResetScope::Thread => {
            session.window == SessionWindow::Thread
                && session.party.as_deref() == Some(thread_party(event).as_str())
        }
    }
}

fn clip(text: &str, max: usize) -> String {
    let flat = text.trim().replace('\n', " ");
    if flat.chars().count() <= max {
        return flat;
    }
    let head: String = flat.chars().take(max).collect();
    format!("{head}…")
}

fn describe(event: &ChannelEvent) -> String {
    match event.kind {
        ChannelEventKind::Text | ChannelEventKind::Doc => inline_utf8(event)
            .map(|t| clip(&t, LINE_MAX_CHARS))
            .unwrap_or_else(|| "(a document)".into()),
        ChannelEventKind::Image | ChannelEventKind::Frame => "(a photo)".into(),
        ChannelEventKind::AudioClip => "(a voice clip)".into(),
        ChannelEventKind::Command => "(a button press)".into(),
        ChannelEventKind::Lifecycle => String::new(),
    }
}

/// The window a lost `thread` / `conversation` session held, rebuilt from the
/// feed's newest events (oldest first): the same sender's messages (a thread)
/// or everyone's (a conversation), the delegate's replies to them, back to
/// the newest reset marker, and only while no silence longer than the idle
/// limit separates them. `None` = nothing to restore (a genuinely new session).
pub fn rebuild_window(
    events: &[ChannelEvent],
    session: &BridgeChatSession,
    current_event_id: &str,
    now_ms: u64,
) -> Option<String> {
    let idle_ms = u64::from(session.idle_minutes?) * 60_000;
    let mut inbound_ids: Vec<&str> = Vec::new();
    let mut kept: Vec<&ChannelEvent> = Vec::new();
    for event in events {
        if event.event_id == current_event_id || event.partial == Some(true) {
            continue;
        }
        if marker_covers(event, session) {
            inbound_ids.clear();
            kept.clear();
            continue;
        }
        if matches!(
            event.kind,
            ChannelEventKind::Lifecycle | ChannelEventKind::Command
        ) {
            continue;
        }
        match event.direction {
            ChannelDirection::In => {
                let belongs = match session.window {
                    SessionWindow::Thread => {
                        session.party.as_deref() == Some(thread_party(event).as_str())
                    }
                    _ => true,
                };
                if belongs {
                    inbound_ids.push(&event.event_id);
                    kept.push(event);
                }
            }
            ChannelDirection::Out => {
                if event
                    .correlation
                    .as_deref()
                    .is_some_and(|c| inbound_ids.contains(&c))
                {
                    kept.push(event);
                }
            }
        }
    }
    let mut window: Vec<&ChannelEvent> = Vec::new();
    let mut newer_ts = now_ms;
    for event in kept.iter().rev() {
        if newer_ts.saturating_sub(event.ts_millis) > idle_ms {
            break;
        }
        window.push(event);
        newer_ts = event.ts_millis;
    }
    window.reverse();
    let mut lines: Vec<String> = window
        .iter()
        .map(|e| {
            let who = if e.direction == ChannelDirection::Out {
                "you"
            } else {
                "them"
            };
            format!("[{who}] {}", describe(e))
        })
        .collect();
    if lines.len() > REBUILD_MAX_LINES {
        lines.drain(..lines.len() - REBUILD_MAX_LINES);
    }
    while lines.iter().map(String::len).sum::<usize>() > REBUILD_MAX_CHARS && lines.len() > 1 {
        lines.remove(0);
    }
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "Earlier in this {}, restored from the feed because the open session was lost:\n{}",
        session.window.as_str(),
        lines.join("\n")
    ))
}

/// The card a tap was made on, as context for the tap's own session: the card
/// document on the feed whose `updated_at` the tap names, else the newest card
/// published before the tap. `cards` = the feed's `direction: out` card
/// documents, as (published-at, body).
pub fn tapped_card_context(
    cards: &[(u64, Vec<u8>)],
    card_updated_at: u64,
    tap_ts_millis: u64,
) -> Option<String> {
    let parsed: Vec<(u64, &[u8], u64)> = cards
        .iter()
        .filter_map(|(ts, body)| {
            parse_card(body)
                .ok()
                .map(|c| (*ts, body.as_slice(), c.updated_at))
        })
        .collect();
    let exact = parsed
        .iter()
        .filter(|(_, _, updated)| card_updated_at != 0 && *updated == card_updated_at)
        .max_by_key(|(ts, _, _)| *ts);
    let before_tap = parsed
        .iter()
        .filter(|(ts, _, _)| *ts <= tap_ts_millis)
        .max_by_key(|(ts, _, _)| *ts);
    let (_, body, _) = exact.or(before_tap)?;
    let text = String::from_utf8_lossy(body);
    Some(format!(
        "The card on the screen when this was tapped:\n{}",
        clip(&text, CARD_MAX_CHARS)
    ))
}

/// Whether a feed event is a card document (the kind the display renders).
pub fn is_card_event(event: &ChannelEvent) -> bool {
    event.direction == ChannelDirection::Out
        && event.kind == ChannelEventKind::Doc
        && event.content_type.as_deref() == Some(CARD_CONTENT_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_backend_client::protocol::{
        session_reset_body, ChannelEndpointKind, SlotDirection,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn feed(slot: &str, kind: ChannelEndpointKind) -> FeedSpec {
        FeedSpec {
            slot: slot.into(),
            kind,
            direction: SlotDirection::Duplex,
            channel_id: format!("ch-{slot}"),
            endpoint_actor_omni: None,
        }
    }

    fn event(id: &str, direction: &str, kind: &str, text: &str, ts: u64) -> ChannelEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": id,
            "channel_id": "ch-family",
            "direction": direction,
            "producer": { "actor": { "actor_omni": "0xgateway" } },
            "kind": kind,
            "body": STANDARD.encode(text),
            "ts_millis": ts,
        }))
        .expect("a well-formed test event")
    }

    fn from_member(mut e: ChannelEvent, member: &str) -> ChannelEvent {
        e.contact =
            serde_json::from_value(serde_json::json!({ "contact_id": member, "tier": "adult" }))
                .ok();
        e
    }

    fn reply(id: &str, to: &str, text: &str, ts: u64) -> ChannelEvent {
        let mut e = event(id, "out", "text", text, ts);
        e.correlation = Some(to.into());
        e
    }

    const MIN: u64 = 60_000;

    #[test]
    fn each_trigger_type_gets_its_window() {
        let chat = feed(OPCHAT_SLOT, ChannelEndpointKind::Chat);
        let family = feed("family_chat", ChannelEndpointKind::Messaging);
        let screen = feed("kitchen_screen", ChannelEndpointKind::Display);
        let camera = feed("door_camera", ChannelEndpointKind::Camera);
        let text = event("e1", "in", "text", "hi", 1);
        let s = feed_session(&chat, &text, None).unwrap();
        assert_eq!(
            (s.window, s.idle_minutes, s.party.as_deref()),
            (SessionWindow::Conversation, Some(1440), None)
        );
        let s = feed_session(&family, &from_member(text.clone(), "grandma"), None).unwrap();
        assert_eq!(
            (s.window, s.idle_minutes, s.party.as_deref()),
            (SessionWindow::Thread, Some(30), Some("grandma"))
        );
        let tap = event("e2", "in", "command", "{}", 1);
        assert_eq!(
            feed_session(&screen, &tap, None).unwrap().window,
            SessionWindow::Event
        );
        let frame = event("e3", "in", "frame", "", 1);
        let s = feed_session(&camera, &frame, None).unwrap();
        assert_eq!((s.window, s.idle_minutes), (SessionWindow::None, None));
        assert_eq!(
            feed_session(&chat, &event("e4", "out", "lifecycle", "{}", 1), None),
            None
        );
        let s = schedule_session("morning plan", None);
        assert_eq!(
            (s.window, s.scope.as_str()),
            (SessionWindow::None, "schedule:morning plan")
        );
    }

    #[test]
    fn a_template_override_replaces_the_slot_default() {
        let family = feed("family_chat", ChannelEndpointKind::Messaging);
        let msg = from_member(event("e1", "in", "text", "hi", 1), "grandma");
        let shared = Some(SessionPolicy::new(SessionWindow::Conversation, None));
        let s = feed_session(&family, &msg, shared).unwrap();
        assert_eq!(
            (s.window, s.idle_minutes, s.party.as_deref()),
            (SessionWindow::Conversation, Some(30), None)
        );
        assert_eq!(
            open_session_key(&s).as_deref(),
            Some("conversation|ch-family_chat|")
        );
        let s = schedule_session(
            "plan",
            Some(SessionPolicy::new(SessionWindow::Conversation, Some(600))),
        );
        assert_eq!(
            (s.window, s.idle_minutes),
            (SessionWindow::Conversation, Some(600))
        );
        assert_eq!(open_session_key(&schedule_session("plan", None)), None);
    }

    #[test]
    fn the_template_overrides_are_read_by_slot_name() {
        let template: PresetSummary = serde_json::from_value(serde_json::json!({
            "id": "chef", "version": "1.0.0", "name": "Chef",
            "slots": [
                { "slot": "family_chat", "kind": "messaging", "direction": "duplex", "event_kinds": ["text"],
                  "session": { "window": "conversation", "idle_minutes": 90 } },
                { "slot": "kitchen_screen", "kind": "display", "direction": "duplex", "event_kinds": ["doc"] }
            ]
        }))
        .unwrap();
        let overrides = slot_session_overrides(&template);
        assert_eq!(overrides.len(), 1);
        assert_eq!(
            overrides.get("family_chat"),
            Some(&SessionPolicy::new(SessionWindow::Conversation, Some(90)))
        );
    }

    #[test]
    fn a_contact_resets_only_their_own_thread() {
        let chat = feed(OPCHAT_SLOT, ChannelEndpointKind::Chat);
        let family = feed("family_chat", ChannelEndpointKind::Messaging);
        let owner = event("m", "in", "command", "", 1);
        let member = from_member(event("m", "in", "command", "", 1), "grandma");
        assert_eq!(
            authorize_reset(SessionResetScope::App, &chat, &owner).map(|r| r.scope),
            Some(SessionResetScope::App)
        );
        assert_eq!(
            authorize_reset(SessionResetScope::App, &family, &owner),
            None,
            "app scope only from the owner's chat"
        );
        assert_eq!(
            authorize_reset(SessionResetScope::App, &chat, &member),
            None
        );
        assert_eq!(
            authorize_reset(SessionResetScope::Feed, &family, &member),
            None
        );
        let r = authorize_reset(SessionResetScope::Thread, &family, &member).unwrap();
        assert_eq!(
            (r.channel.as_deref(), r.party.as_deref()),
            (Some("ch-family_chat"), Some("grandma"))
        );
    }

    #[test]
    fn a_rebuilt_thread_holds_only_that_members_exchange_since_the_last_reset() {
        let now = 100 * MIN;
        let session = feed_session(
            &feed("family_chat", ChannelEndpointKind::Messaging),
            &from_member(event("now", "in", "text", "and dessert?", now), "grandma"),
            None,
        )
        .unwrap();
        let events = vec![
            from_member(
                event("a", "in", "text", "old question", now - 90 * MIN),
                "grandma",
            ),
            from_member(
                event(
                    "r",
                    "in",
                    "command",
                    &session_reset_body(SessionResetScope::Thread),
                    now - 50 * MIN,
                ),
                "grandma",
            ),
            from_member(
                event("b", "in", "text", "what's for dinner?", now - 20 * MIN),
                "grandma",
            ),
            reply("b-re", "b", "Noodles.", now - 19 * MIN),
            from_member(
                event("c", "in", "text", "my own question", now - 18 * MIN),
                "grandpa",
            ),
            reply("c-re", "c", "Answer for grandpa.", now - 17 * MIN),
            event("lc", "out", "lifecycle", "{}", now - 10 * MIN),
            from_member(event("now", "in", "text", "and dessert?", now), "grandma"),
        ];
        let text = rebuild_window(&events, &session, "now", now).unwrap();
        assert!(
            text.contains("[them] what's for dinner?") && text.contains("[you] Noodles."),
            "{text}"
        );
        assert!(
            !text.contains("old question"),
            "a reset marker ends the window: {text}"
        );
        assert!(
            !text.contains("grandpa"),
            "another member's thread stays out: {text}"
        );
        assert!(
            !text.contains("and dessert?"),
            "the current message is the prompt, not context"
        );
    }

    #[test]
    fn silence_longer_than_the_idle_limit_means_nothing_to_restore() {
        let now = 200 * MIN;
        let session = feed_session(
            &feed("family_chat", ChannelEndpointKind::Messaging),
            &from_member(event("now", "in", "text", "hi again", now), "grandma"),
            None,
        )
        .unwrap();
        let events = vec![
            from_member(
                event("a", "in", "text", "earlier", now - 45 * MIN),
                "grandma",
            ),
            reply("a-re", "a", "Sure.", now - 44 * MIN),
        ];
        assert_eq!(rebuild_window(&events, &session, "now", now), None);
        // a throwaway window never rebuilds
        let tap = BridgeChatSession {
            window: SessionWindow::Event,
            scope: "ch".into(),
            party: None,
            idle_minutes: None,
            context: None,
        };
        assert_eq!(rebuild_window(&events, &tap, "now", now), None);
    }

    #[test]
    fn a_rebuilt_conversation_is_bounded() {
        let now = 1_000 * MIN;
        let session = feed_session(
            &feed(OPCHAT_SLOT, ChannelEndpointKind::Chat),
            &event("now", "in", "text", "next", now),
            None,
        )
        .unwrap();
        let long = "x".repeat(5_000);
        let mut events = Vec::new();
        for i in 0..40u64 {
            let id = format!("m{i}");
            events.push(event(&id, "in", "text", &long, now - (40 - i) * MIN));
            events.push(reply(
                &format!("{id}-re"),
                &id,
                "ok",
                now - (40 - i) * MIN + 1,
            ));
        }
        let text = rebuild_window(&events, &session, "now", now).unwrap();
        assert!(text.len() < REBUILD_MAX_CHARS + 200, "{}", text.len());
        assert!(text.lines().count() <= REBUILD_MAX_LINES + 1);
        assert!(
            text.ends_with("[you] ok"),
            "the newest exchange survives the cut"
        );
    }

    fn card(title: &str, updated_at: u64) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({ "card": 1, "title": title, "updated_at": updated_at }),
        )
        .unwrap()
    }

    #[test]
    fn a_tap_gets_the_card_it_was_made_on() {
        let cards = vec![
            (10, card("Breakfast", 100)),
            (20, card("Dinner plan", 200)),
            (30, card("Tomorrow", 300)),
        ];
        let exact = tapped_card_context(&cards, 200, 35).unwrap();
        assert!(exact.contains("Dinner plan"), "{exact}");
        // an unknown or missing stamp falls back to the newest card before the tap
        let fallback = tapped_card_context(&cards, 999, 25).unwrap();
        assert!(fallback.contains("Dinner plan"), "{fallback}");
        assert_eq!(
            tapped_card_context(&[(10, b"not a card".to_vec())], 0, 20),
            None
        );
    }
}
