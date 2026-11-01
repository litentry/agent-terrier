//! L3 — the audience PEP (§5). Answers "may THIS member publish on THAT
//! channel, addressed to THAT app, through this contact gate?" — computed
//! BEFORE anything reaches an app. The decision is data (a routing verdict),
//! never an authorization: grants stay master-signed + chain-verified; this
//! only gates whether the gateway relays a keyless member's message at all.
//!
//! The order matters (fail-closed, cheapest first): unknown contact → DROP;
//! rate-limited → refuse; no channel resolved → refuse (`no_channel`: the
//! transport's `resolve` — the router, an answered ask, `/alias` — found
//! nowhere, so the relay asks); a channel the member does not speak on →
//! refuse; an addressee not bound there → refuse; an operator-grade app →
//! deep-link (never data over the gateway, regardless of tier); else → route.

use std::collections::HashMap;
use std::sync::Mutex;

use agentkeys_protocol::{ContactRegistry, GatewayInbound, L3Decision};

use crate::config::WeixinGatewayConfig;

/// A per-contact sliding-window rate limiter (§9 threat 3 — anti-flood /
/// anti-Sybil). In-memory + single-worker (the deployment shape); a multi-replica
/// gateway would need a shared store, noted for later.
pub struct RateLimiter {
    max: u32,
    window_secs: u64,
    hits: Mutex<HashMap<String, Vec<u64>>>,
}

impl RateLimiter {
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self {
            max,
            window_secs,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record a hit for `key` at `now_secs`; return true if it is WITHIN the
    /// limit (allowed), false if it EXCEEDS it. `now_secs` is injected so the
    /// logic is deterministically testable.
    pub fn check(&self, key: &str, now_secs: u64) -> bool {
        let mut map = self.hits.lock().expect("rate limiter poisoned");
        let window = self.window_secs;
        let v = map.entry(key.to_string()).or_default();
        v.retain(|&t| now_secs.saturating_sub(t) < window);
        if v.len() as u32 >= self.max {
            return false;
        }
        v.push(now_secs);
        true
    }
}

/// The pure L3 decision, given whether the rate check already passed. Kept pure
/// (no clock, no I/O) so every branch is unit-testable. `inbound.channel` is
/// what the transport resolved (`None` = nothing yet); `inbound.alias` is the
/// addressee when one was named (`/alias`, the router's pick) — absent, the
/// channel's default app takes the turn.
pub fn decide(
    config: &WeixinGatewayConfig,
    registry: &ContactRegistry,
    inbound: &GatewayInbound,
    rate_ok: bool,
) -> L3Decision {
    // 1. Authenticate the human by transport identity. Unknown → DROP (never
    //    reaches an agent, never even acknowledged as a known contact).
    let Some(contact) = registry.resolve(&inbound.transport, &inbound.transport_id) else {
        return refuse("unknown_contact");
    };

    // 2. Rate limit (anti-flood). Computed by the caller against the limiter.
    if !rate_ok {
        return refuse("rate_limited");
    }

    // 3. The channel: resolved by the transport, never guessed here. Nothing
    //    resolved → the relay asks the member (`no_channel`).
    let Some(doc) = inbound
        .channel
        .as_deref()
        .and_then(|id| registry.channel(id))
    else {
        return refuse("no_channel");
    };

    // 4. Membership: may this member publish on this channel at all? The
    //    options were built from their rows, but a `/alias` or an answered
    //    ask is re-checked here (defense-in-depth against a stale ask).
    if !doc.speaks(&contact.contact_id) {
        return refuse("no_membership");
    }

    // 5. The addressee: the named app must be bound to this channel; unnamed,
    //    the channel's default app; a shared channel with no default and no
    //    name is not decidable here (the relay asked, or asks).
    let addressee = match inbound.alias.as_deref() {
        Some(a) => match doc.app(a) {
            Some(row) => row.alias.clone(),
            None => return refuse("app_not_on_channel"),
        },
        None => match doc.default_or_only_app() {
            Some(a) => a.to_string(),
            None => return refuse("addressee_unclear"),
        },
    };

    // 6. Operator-grade guard: operator-grade data (spend/usage/audit) requires
    //    operator-grade auth — NEVER a matching openid alone. Even an `owner`
    //    gets the parent-control deep-link, not the data, over the gateway
    //    (§5/§8).
    if config.is_operator_grade(&addressee) {
        return L3Decision {
            allowed: false,
            target_alias: None,
            channel_id: None,
            reason: "operator_grade_requires_session".to_string(),
            operator_grade_deeplink: Some(config.parent_control_deeplink.clone()),
            routed_by: None,
        };
    }

    L3Decision {
        allowed: true,
        target_alias: Some(addressee),
        channel_id: Some(doc.id.clone()),
        reason: "ok".to_string(),
        operator_grade_deeplink: None,
        routed_by: None,
    }
}

fn refuse(reason: &str) -> L3Decision {
    L3Decision {
        allowed: false,
        target_alias: None,
        channel_id: None,
        reason: reason.to_string(),
        operator_grade_deeplink: None,
        routed_by: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::{ChannelApp, Contact, ContactTier};

    fn cfg() -> WeixinGatewayConfig {
        WeixinGatewayConfig {
            ilink_tokens_file: String::new(),
            unknown_sender_hint: true,
            bind: "127.0.0.1:0".into(),
            transport: crate::config::WeixinTransport::Oa,
            weixin_token: "t".into(),
            weixin_app_id: "app".into(),
            weixin_app_secret: None,
            ilink_bot_token: None,
            ilink_base_url: crate::ilink::ILINK_BOOTSTRAP_BASE_URL.into(),
            ilink_state_file: "/dev/null".into(),
            history_file: String::new(),
            activity_file: String::new(),
            secrets_file: "/dev/null".into(),
            ilink_bootstrap_url: crate::ilink::ILINK_BOOTSTRAP_BASE_URL.into(),
            bot_agent: "AgentKeys/test".into(),
            telegram_bot_token: None,
            telegram_api_base: crate::telegram::TELEGRAM_API_BASE.into(),
            telegram_state_file: "/dev/null".into(),
            registry_file: "/dev/null".into(),
            channel_worker_url: None,
            operator_omni: "0x00".into(),
            audit_worker_url: None,
            operator_grade_aliases: vec!["spend".into(), "usage".into()],
            parent_control_deeplink: "https://pc.local/".into(),
            rate_max: 30,
            rate_window_secs: 60,
            router_enabled: true,
            admin_token: None,
            allow_unsigned: false,
            device: Default::default(),
            router: Default::default(),
        }
    }

    fn registry() -> ContactRegistry {
        let mut reg = ContactRegistry {
            bound: vec![
                Contact {
                    contact_id: "c-owner".into(),
                    transport: "weixin".into(),
                    transport_id: "openid-owner".into(),
                    display_name: "妈妈".into(),
                    tier: ContactTier::Owner,
                    legacy_reach: vec![],
                    welcomed: true,
                },
                Contact {
                    contact_id: "c-kid".into(),
                    transport: "weixin".into(),
                    transport_id: "openid-kid".into(),
                    display_name: "小明".into(),
                    tier: ContactTier::Kid,
                    legacy_reach: vec![],
                    welcomed: true,
                },
            ],
            ..Default::default()
        };
        let family = reg.channel_or_new("family-chat");
        family.upsert_app(ChannelApp {
            alias: "chef".into(),
            ..Default::default()
        });
        family.upsert_app(ChannelApp {
            alias: "doorkeeper".into(),
            ..Default::default()
        });
        family.set_member("c-owner", true, true);
        family.set_member("c-kid", false, true);
        let spend = reg.channel_or_new("money");
        spend.upsert_app(ChannelApp {
            alias: "spend".into(),
            ..Default::default()
        });
        spend.set_member("c-owner", true, true);
        let stories = reg.channel_or_new("stories");
        stories.upsert_app(ChannelApp {
            alias: "storyteller".into(),
            ..Default::default()
        });
        stories.set_member("c-kid", true, true);
        reg
    }

    fn inbound(
        openid: &str,
        channel: Option<&str>,
        alias: Option<&str>,
        text: &str,
    ) -> GatewayInbound {
        GatewayInbound {
            transport: "weixin".into(),
            transport_id: openid.into(),
            text: text.into(),
            alias: alias.map(|s| s.to_string()),
            channel: channel.map(|s| s.to_string()),
        }
    }

    #[test]
    fn a_member_speaking_on_their_channel_is_routed_to_the_named_or_default_app() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound(
                "openid-owner",
                Some("family-chat"),
                Some("doorkeeper"),
                "门口有人吗",
            ),
            true,
        );
        assert!(d.allowed);
        assert_eq!(d.target_alias.as_deref(), Some("doorkeeper"));
        assert_eq!(d.channel_id.as_deref(), Some("family-chat"));
        assert_eq!(d.reason, "ok");
        // Unnamed on a shared channel: the default (the first app bound).
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("family-chat"), None, "晚饭吃什么"),
            true,
        );
        assert!(d.allowed);
        assert_eq!(d.target_alias.as_deref(), Some("chef"));
    }

    #[test]
    fn unknown_openid_is_dropped() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-stranger", Some("family-chat"), Some("chef"), "hi"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "unknown_contact");
    }

    #[test]
    fn a_reader_cannot_publish_and_an_app_not_on_the_channel_is_refused() {
        // The kid only reads the family chat.
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-kid", Some("family-chat"), Some("chef"), "cook"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "no_membership");
        // The kid speaks on stories, but chef is not bound there.
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-kid", Some("stories"), Some("chef"), "cook"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "app_not_on_channel");
        // A channel that does not exist resolves to nothing.
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("nowhere"), None, "hi"),
            true,
        );
        assert_eq!(d.reason, "no_channel");
    }

    #[test]
    fn operator_grade_ask_gets_deeplink_even_for_owner() {
        // The owner asking spend on its channel gets the parent-control
        // deep-link, NOT the data — operator-grade requires operator-grade
        // auth (§8).
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("money"), None, "本周花了多少"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "operator_grade_requires_session");
        assert_eq!(
            d.operator_grade_deeplink.as_deref(),
            Some("https://pc.local/")
        );
    }

    #[test]
    fn no_channel_resolved_is_the_ask_back() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", None, None, "just chatting"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "no_channel");
    }

    #[test]
    fn a_shared_channel_with_no_default_needs_an_addressee() {
        let mut reg = registry();
        reg.channel_mut("family-chat").unwrap().default_app = None;
        let d = decide(
            &cfg(),
            &reg,
            &inbound("openid-owner", Some("family-chat"), None, "hi"),
            true,
        );
        assert_eq!(d.reason, "addressee_unclear");
    }

    #[test]
    fn rate_limited_is_refused() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("family-chat"), Some("chef"), "spam"),
            false,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "rate_limited");
    }

    #[test]
    fn rate_limiter_enforces_window() {
        let rl = RateLimiter::new(2, 60);
        assert!(rl.check("c", 100));
        assert!(rl.check("c", 101));
        assert!(!rl.check("c", 102), "3rd within window is over the limit");
        // After the window slides, the early hits expire.
        assert!(rl.check("c", 200));
    }
}
