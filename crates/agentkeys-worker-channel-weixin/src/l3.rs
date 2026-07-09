//! L3 — the audience PEP (§5). Answers "may THIS contact reach THAT agent
//! through this gateway, and at what grain?" — computed BEFORE anything reaches
//! an agent. The decision is data (a routing verdict), never an authorization:
//! grants stay master-signed + chain-verified; this only gates whether the
//! gateway relays a keyless contact's message at all.
//!
//! The order matters (fail-closed, cheapest first): unknown contact → DROP;
//! rate-limited → refuse; no `/alias` → ask-back (phase 5 router will pick);
//! operator-grade ask → deep-link (never data over the gateway, regardless of
//! tier); out-of-reach → refuse; else → route.

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
/// (no clock, no I/O) so every branch is unit-testable.
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

    // 3. Routing: `/alias` deterministic override first; otherwise the ADVISORY
    //    router (#410) picks among THIS contact's reachable agents (never wider).
    //    Router says ask-back (ambiguous / no match / disabled) → refuse no_alias.
    let (alias, routed_by) = match inbound.alias.as_deref() {
        Some(a) => (a.to_lowercase(), None),
        None => match crate::router::advisory_route(
            &inbound.text,
            &contact.reach,
            config.router_enabled,
        ) {
            crate::router::RouteVerdict::Route(a) => {
                (a.to_lowercase(), Some("advisory_router".to_string()))
            }
            crate::router::RouteVerdict::AskBack => return refuse("no_alias"),
        },
    };

    // 4. Operator-grade guard: operator-grade data (spend/usage/audit) requires
    //    operator-grade auth — NEVER a matching openid alone. Even an `owner`
    //    gets the parent-control deep-link, not the data, over the gateway
    //    (§5/§8). This check is BEFORE reach so it fires even if the alias were
    //    (mis)configured into a contact's reach.
    if config.is_operator_grade(&alias) {
        return L3Decision {
            allowed: false,
            target_alias: None,
            reason: "operator_grade_requires_session".to_string(),
            operator_grade_deeplink: Some(config.parent_control_deeplink.clone()),
            routed_by: None,
        };
    }

    // 5. Reach: may this contact address this alias at all? (Defense-in-depth —
    //    the router already picks from reach, but a `/alias` override is checked
    //    here, and this guards a future router change.)
    if !contact.reach.iter().any(|r| r.to_lowercase() == alias) {
        return refuse("out_of_reach");
    }

    L3Decision {
        allowed: true,
        target_alias: Some(alias),
        reason: "ok".to_string(),
        operator_grade_deeplink: None,
        routed_by,
    }
}

fn refuse(reason: &str) -> L3Decision {
    L3Decision {
        allowed: false,
        target_alias: None,
        reason: reason.to_string(),
        operator_grade_deeplink: None,
        routed_by: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::{Contact, ContactTier};

    fn cfg() -> WeixinGatewayConfig {
        WeixinGatewayConfig {
            bind: "127.0.0.1:0".into(),
            transport: crate::config::WeixinTransport::Oa,
            weixin_token: "t".into(),
            weixin_app_id: "app".into(),
            weixin_app_secret: None,
            ilink_bot_token: None,
            ilink_base_url: crate::ilink::ILINK_BOOTSTRAP_BASE_URL.into(),
            ilink_state_file: "/dev/null".into(),
            secrets_file: "/dev/null".into(),
            ilink_bootstrap_url: crate::ilink::ILINK_BOOTSTRAP_BASE_URL.into(),
            bot_agent: "AgentKeys/test".into(),
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
        }
    }

    fn registry() -> ContactRegistry {
        ContactRegistry {
            bound: vec![
                Contact {
                    contact_id: "c-owner".into(),
                    transport: "weixin".into(),
                    transport_id: "openid-owner".into(),
                    display_name: "妈妈".into(),
                    tier: ContactTier::Owner,
                    reach: vec!["chef".into(), "doorkeeper".into()],
                },
                Contact {
                    contact_id: "c-kid".into(),
                    transport: "weixin".into(),
                    transport_id: "openid-kid".into(),
                    display_name: "小明".into(),
                    tier: ContactTier::Kid,
                    reach: vec!["storyteller".into()],
                },
            ],
            pending: vec![],
            invites: vec![],
        }
    }

    fn inbound(openid: &str, alias: Option<&str>, text: &str) -> GatewayInbound {
        GatewayInbound {
            transport: "weixin".into(),
            transport_id: openid.into(),
            text: text.into(),
            alias: alias.map(|s| s.to_string()),
        }
    }

    #[test]
    fn bound_contact_reaching_allowed_agent_is_routed() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("chef"), "晚饭吃什么"),
            true,
        );
        assert!(d.allowed);
        assert_eq!(d.target_alias.as_deref(), Some("chef"));
        assert_eq!(d.reason, "ok");
    }

    #[test]
    fn unknown_openid_is_dropped() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-stranger", Some("chef"), "hi"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "unknown_contact");
    }

    #[test]
    fn kid_reaching_out_of_reach_agent_is_refused() {
        // The kid may only reach `storyteller`; `chef` is out of reach.
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-kid", Some("chef"), "cook"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "out_of_reach");
    }

    #[test]
    fn operator_grade_ask_gets_deeplink_even_for_owner() {
        // The owner asking `/spend` gets the parent-control deep-link, NOT the
        // data — operator-grade requires operator-grade auth (§8).
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("spend"), "本周花了多少"),
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
    fn no_alias_is_ask_back() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", None, "just chatting"),
            true,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "no_alias");
    }

    #[test]
    fn rate_limited_is_refused() {
        let d = decide(
            &cfg(),
            &registry(),
            &inbound("openid-owner", Some("chef"), "spam"),
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
