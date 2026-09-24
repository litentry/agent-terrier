//! Typed sessions (owner decision 2026-09-23): the closed vocabulary of what
//! one agent turn sees of the conversation around it, the default window per
//! trigger TYPE, the typed reset marker, and the daemon → bridge session
//! request.
//!
//! A delegate used to run every trigger — the owner's chat, a family message,
//! a card tap, a camera frame, a clock tick — in ONE resident dsh session, so a
//! scheduled plan read a week of unrelated chatter and chef drifted into its
//! own improvised card format. Now each trigger type maps to a window:
//! `none` and `event` run in a throwaway session; `thread` and `conversation`
//! keep one dsh session open for the window's life (and so one OpenViking
//! session — the memory plugin maps them 1:1), ended by silence or a reset.
//! The feed stays the durable record; a session is the working context.

use serde::{Deserialize, Serialize};

use crate::app_template::platform_caps;
use crate::{ChannelEndpointKind, ChannelEventKind};

/// What one turn sees of the conversation around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum SessionWindow {
    /// A throwaway session: only the triggering event.
    None,
    /// A throwaway session: the event plus the one item it points at (the card
    /// a tap was made on).
    Event,
    /// One session per sender on a feed, ended by `idle_minutes` of silence or
    /// a reset.
    Thread,
    /// One session per feed, every sender, ended by `idle_minutes` of silence
    /// or a reset.
    Conversation,
}

impl SessionWindow {
    pub const ALL: [SessionWindow; 4] = [
        SessionWindow::None,
        SessionWindow::Event,
        SessionWindow::Thread,
        SessionWindow::Conversation,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            SessionWindow::None => "none",
            SessionWindow::Event => "event",
            SessionWindow::Thread => "thread",
            SessionWindow::Conversation => "conversation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|w| w.as_str() == s)
    }

    /// Whether the window keeps its session open across triggers.
    pub fn keeps_session(&self) -> bool {
        matches!(self, SessionWindow::Thread | SessionWindow::Conversation)
    }

    /// The idle limit a window runs with when nothing more specific names one.
    pub fn default_idle_minutes(&self) -> Option<u32> {
        match self {
            SessionWindow::Thread => Some(MESSAGING_THREAD_IDLE_MINUTES),
            SessionWindow::Conversation => Some(CONVERSATION_IDLE_MINUTES),
            SessionWindow::None | SessionWindow::Event => None,
        }
    }
}

/// A family member's thread ends after half an hour of silence.
pub const MESSAGING_THREAD_IDLE_MINUTES: u32 = 30;
/// A spoken exchange on the owner's chat ends after two minutes of silence.
pub const VOICE_THREAD_IDLE_MINUTES: u32 = 2;
/// The owner's chat ends after a day of silence (or at "New session").
pub const CONVERSATION_IDLE_MINUTES: u32 = 24 * 60;

/// One trigger type's session policy — a kind and a bound, never a domain
/// (template rule F1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct SessionPolicy {
    pub window: SessionWindow,
    /// `thread` / `conversation`: minutes of silence that end the session.
    /// Absent = the trigger type's default. Refused on `none` / `event`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub idle_minutes: Option<u32>,
}

impl SessionPolicy {
    pub const fn new(window: SessionWindow, idle_minutes: Option<u32>) -> Self {
        Self {
            window,
            idle_minutes,
        }
    }

    /// The idle limit this policy runs with (`None` for a throwaway window).
    pub fn effective_idle_minutes(&self) -> Option<u32> {
        if !self.window.keeps_session() {
            return None;
        }
        self.idle_minutes
            .or_else(|| self.window.default_idle_minutes())
    }
}

/// A clock tick's default: every scheduled run starts clean.
pub const SCHEDULE_SESSION: SessionPolicy = SessionPolicy::new(SessionWindow::None, None);

/// The default session policy of a feed trigger — the slot kind × the event
/// kind (the owner-confirmed table, 2026-09-23). `None` = the event is never a
/// turn (`lifecycle`).
pub fn default_feed_session(
    slot_kind: ChannelEndpointKind,
    event_kind: ChannelEventKind,
) -> Option<SessionPolicy> {
    use ChannelEndpointKind as Slot;
    use ChannelEventKind as Kind;
    use SessionWindow as Window;
    Some(match (slot_kind, event_kind) {
        (_, Kind::Lifecycle) => return None,
        // A card tap is its own session, whatever renders the card.
        (_, Kind::Command) => SessionPolicy::new(Window::Event, None),
        (Slot::Chat, Kind::AudioClip) => {
            SessionPolicy::new(Window::Thread, Some(VOICE_THREAD_IDLE_MINUTES))
        }
        (Slot::Chat, _) => {
            SessionPolicy::new(Window::Conversation, Some(CONVERSATION_IDLE_MINUTES))
        }
        (Slot::Messaging, _) => {
            SessionPolicy::new(Window::Thread, Some(MESSAGING_THREAD_IDLE_MINUTES))
        }
        (Slot::Display, _) => SessionPolicy::new(Window::Event, None),
        (Slot::Camera | Slot::Mic | Slot::Sensor | Slot::Speaker | Slot::Actuator, _) => {
            SessionPolicy::new(Window::None, None)
        }
    })
}

/// A template override replaces the default for every turn on its slot (or
/// schedule entry); a lifecycle event stays never-a-turn. An override that
/// keeps a session but names no idle limit takes the default's limit when the
/// default keeps one too, else the window's own default.
pub fn resolve_session(
    default: Option<SessionPolicy>,
    template_override: Option<SessionPolicy>,
) -> Option<SessionPolicy> {
    let default = default?;
    let Some(chosen) = template_override else {
        return Some(default);
    };
    let idle_minutes = if chosen.window.keeps_session() {
        chosen
            .idle_minutes
            .or(default
                .idle_minutes
                .filter(|_| default.window.keeps_session()))
            .or_else(|| chosen.window.default_idle_minutes())
    } else {
        None
    };
    Some(SessionPolicy::new(chosen.window, idle_minutes))
}

/// The template checker's rule for one policy.
pub fn validate_session_policy(policy: &SessionPolicy) -> Result<(), String> {
    match (policy.window.keeps_session(), policy.idle_minutes) {
        (false, Some(_)) => Err(format!(
            "a {} session ends with its turn — idle_minutes only applies to thread and conversation",
            policy.window.as_str()
        )),
        (true, Some(0)) => Err("idle_minutes must be at least 1".into()),
        (true, Some(m)) if m > platform_caps::MAX_SESSION_IDLE_MINUTES => Err(format!(
            "idle_minutes {m} exceeds the platform cap of {} (a week)",
            platform_caps::MAX_SESSION_IDLE_MINUTES
        )),
        _ => Ok(()),
    }
}

/// How much a reset ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum SessionResetScope {
    /// Every open session of the delegate (the console's "New session"; only
    /// honoured on the owner's chat feed).
    App,
    /// Every open session on the feed the marker arrived on (a device's
    /// "start over"; never from a contact).
    Feed,
    /// The sender's own thread on that feed.
    Thread,
}

impl SessionResetScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionResetScope::App => "app",
            SessionResetScope::Feed => "feed",
            SessionResetScope::Thread => "thread",
        }
    }
}

/// The `command` body that marks a reset on a feed. The marker stays in the
/// feed, so the transcript shows where a new session began and a window
/// rebuilt from the feed stops at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct SessionResetCommand {
    pub session_reset: SessionResetScope,
}

/// Parse a `command` body as a reset marker (`None` = some other command).
pub fn parse_session_reset(body: &[u8]) -> Option<SessionResetScope> {
    serde_json::from_slice::<SessionResetCommand>(body)
        .ok()
        .map(|c| c.session_reset)
}

/// The marker body for `scope` — what a renderer publishes as a `command`.
pub fn session_reset_body(scope: SessionResetScope) -> String {
    serde_json::to_string(&SessionResetCommand {
        session_reset: scope,
    })
    .expect("a one-field struct over a unit enum serializes")
}

/// The `session` field of a bridge `POST /v1/chat` body (daemon → bridge).
/// Absent = the bridge's legacy resident session, which stays for the direct
/// callers that carry no feed (the ESP32 client, the broker's bridge proxy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeChatSession {
    pub window: SessionWindow,
    /// What the session is keyed on: the feed's channel id, or
    /// `schedule:<label>` for a clock tick.
    pub scope: String,
    /// `thread` only: whose thread — the contact id, or the producing actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
    /// `thread` / `conversation`: minutes of silence that end the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_minutes: Option<u32>,
    /// Background for a NEW session only: the card a tap was made on, or the
    /// window rebuilt from the feed when an open session was lost. An open
    /// session that resumes ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// The bridge `POST /v1/session/reset` body (daemon → bridge).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeSessionReset {
    pub scope: SessionResetScope,
    /// `feed` / `thread`: the feed's channel id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// `thread`: whose thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SLOTS: [ChannelEndpointKind; 8] = ChannelEndpointKind::ALL;

    #[test]
    fn the_default_table_is_the_owner_confirmed_one() {
        use SessionWindow as W;
        let d = |s, k| default_feed_session(s, k).map(|p| (p.window, p.idle_minutes));
        assert_eq!(
            d(ChannelEndpointKind::Chat, ChannelEventKind::Text),
            Some((W::Conversation, Some(1440)))
        );
        assert_eq!(
            d(ChannelEndpointKind::Chat, ChannelEventKind::AudioClip),
            Some((W::Thread, Some(2)))
        );
        assert_eq!(
            d(ChannelEndpointKind::Messaging, ChannelEventKind::Text),
            Some((W::Thread, Some(30)))
        );
        assert_eq!(
            d(ChannelEndpointKind::Messaging, ChannelEventKind::Image),
            Some((W::Thread, Some(30)))
        );
        assert_eq!(
            d(ChannelEndpointKind::Display, ChannelEventKind::Command),
            Some((W::Event, None))
        );
        for sensor in [
            ChannelEndpointKind::Camera,
            ChannelEndpointKind::Mic,
            ChannelEndpointKind::Sensor,
        ] {
            assert_eq!(d(sensor, ChannelEventKind::Frame), Some((W::None, None)));
        }
        assert_eq!(SCHEDULE_SESSION.window, W::None);
    }

    #[test]
    fn a_lifecycle_is_never_a_turn_and_a_card_tap_is_always_its_own_session() {
        for slot in ALL_SLOTS {
            assert_eq!(
                default_feed_session(slot, ChannelEventKind::Lifecycle),
                None
            );
            assert_eq!(
                default_feed_session(slot, ChannelEventKind::Command).map(|p| p.window),
                Some(SessionWindow::Event)
            );
        }
    }

    #[test]
    fn every_default_passes_the_template_rule() {
        for slot in ALL_SLOTS {
            for kind in ChannelEventKind::ALL {
                if let Some(p) = default_feed_session(slot, kind) {
                    assert!(validate_session_policy(&p).is_ok(), "{slot:?} × {kind:?}");
                }
            }
        }
    }

    #[test]
    fn an_override_replaces_the_default_and_inherits_a_sensible_idle_limit() {
        let messaging =
            default_feed_session(ChannelEndpointKind::Messaging, ChannelEventKind::Text);
        let display = default_feed_session(ChannelEndpointKind::Display, ChannelEventKind::Command);
        let conversation = Some(SessionPolicy::new(SessionWindow::Conversation, None));
        // keeps the default's own limit when both keep a session
        assert_eq!(
            resolve_session(messaging, conversation),
            Some(SessionPolicy::new(SessionWindow::Conversation, Some(30)))
        );
        // else the window's own default
        assert_eq!(
            resolve_session(display, conversation),
            Some(SessionPolicy::new(SessionWindow::Conversation, Some(1440)))
        );
        // an explicit limit wins; a throwaway override drops any limit
        assert_eq!(
            resolve_session(
                messaging,
                Some(SessionPolicy::new(SessionWindow::Thread, Some(90)))
            ),
            Some(SessionPolicy::new(SessionWindow::Thread, Some(90)))
        );
        assert_eq!(
            resolve_session(
                messaging,
                Some(SessionPolicy::new(SessionWindow::None, None))
            ),
            Some(SessionPolicy::new(SessionWindow::None, None))
        );
        // a lifecycle stays never-a-turn under any override
        assert_eq!(resolve_session(None, conversation), None);
    }

    #[test]
    fn the_template_rule_refuses_meaningless_or_unbounded_limits() {
        assert!(
            validate_session_policy(&SessionPolicy::new(SessionWindow::Event, Some(5))).is_err()
        );
        assert!(
            validate_session_policy(&SessionPolicy::new(SessionWindow::Thread, Some(0))).is_err()
        );
        assert!(validate_session_policy(&SessionPolicy::new(
            SessionWindow::Conversation,
            Some(platform_caps::MAX_SESSION_IDLE_MINUTES + 1)
        ))
        .is_err());
        assert!(validate_session_policy(&SessionPolicy::new(
            SessionWindow::Conversation,
            Some(platform_caps::MAX_SESSION_IDLE_MINUTES)
        ))
        .is_ok());
    }

    #[test]
    fn a_reset_marker_round_trips_and_nothing_else_parses_as_one() {
        for scope in [
            SessionResetScope::App,
            SessionResetScope::Feed,
            SessionResetScope::Thread,
        ] {
            assert_eq!(
                parse_session_reset(session_reset_body(scope).as_bytes()),
                Some(scope)
            );
        }
        assert_eq!(
            session_reset_body(SessionResetScope::App),
            r#"{"session_reset":"app"}"#
        );
        assert_eq!(parse_session_reset(b"jobs"), None);
        assert_eq!(
            parse_session_reset(br#"{"session_reset":"everything"}"#),
            None
        );
        assert_eq!(
            parse_session_reset(br#"{"session_reset":"app","card":1}"#),
            None,
            "a marker carries nothing else"
        );
        assert_eq!(
            parse_session_reset(br#"{"card":1,"action":"a","command":"c"}"#),
            None,
            "a card tap is not a reset"
        );
    }

    /// The daemon ↔ bridge contract has ONE shape: the bridge's TypeScript
    /// parser reads the same fixture (packages/agentkeys-dsh/tests/bridge-sessions.spec.ts).
    #[test]
    fn the_bridge_session_contract_matches_the_shared_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../e2e/fixtures/bridge-protocol/session_contract.json"
        ))
        .expect("fixture is JSON");
        for key in [
            "thread_chat_session",
            "event_chat_session",
            "schedule_chat_session",
        ] {
            let parsed: BridgeChatSession =
                serde_json::from_value(fixture[key].clone()).expect(key);
            assert_eq!(
                serde_json::to_value(&parsed).unwrap(),
                fixture[key],
                "{key}"
            );
        }
        for key in ["app_reset", "thread_reset"] {
            let parsed: BridgeSessionReset =
                serde_json::from_value(fixture[key].clone()).expect(key);
            assert_eq!(
                serde_json::to_value(&parsed).unwrap(),
                fixture[key],
                "{key}"
            );
        }
        assert_eq!(
            fixture["reset_marker_body"],
            session_reset_body(SessionResetScope::App)
        );
    }
}
