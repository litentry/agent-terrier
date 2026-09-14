//! #660 stage 1 — the in-sandbox APP RUNTIME facts (the runtime contract's
//! inputs, plan §4.4): the bound feeds (R1/R3), the app template's bundle
//! (schedule[] for R4, `skills/perception.md` for R2), the availability
//! policy, the household tz offset, and the delegate's own grant view (the
//! `tool:schedule` guard).
//!
//! Every input is OPTIONAL and additive on the #430 chat env contract: a
//! role-preset delegate (no `AGENTKEYS_APP_TEMPLATE`, no
//! `AGENTKEYS_BOUND_CHANNELS`) runs exactly as before — one opchat feed, no
//! schedules, no perception prompt. Pure construction from a lookup fn (the
//! #258 no-env-mutation-in-tests seam); the catalog + grants fetches are the
//! two network legs, both best-effort + loud.

use agentkeys_backend_client::protocol::{
    sandbox_env, Availability, BoundChannel, ChannelEndpointKind, PresetBundle, SlotDirection,
};

/// The default of `AGENTKEYS_SELF_GRANTS_URL` — the co-located daemon's own
/// `/v1/sandbox/self/grants` (the ONE Rust-owned chain read the dsh guard
/// consumes too, `packages/agentkeys-dsh/src/grants.ts DEFAULT_GRANTS_URL`).
pub const DEFAULT_SELF_GRANTS_URL: &str = "http://127.0.0.1:3114/v1/sandbox/self/grants";

/// The reserved slot name of the operator-chat feed every delegate binds —
/// "no special-cased feeds" (plan S6): opchat is a `chat` slot the framework
/// always binds, tagged like any other.
pub const OPCHAT_SLOT: &str = "opchat";

#[derive(Debug, Clone)]
pub struct AppRuntimeConfig {
    /// The feeds beyond opchat (the compiler's `bound_channels`).
    pub bound_channels: Vec<BoundChannel>,
    /// The app template id (`""` = a role preset / blank spawn).
    pub template_id: String,
    pub availability: Availability,
    pub tz_offset_minutes: i64,
    pub self_grants_url: String,
}

impl AppRuntimeConfig {
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let read = |k: &str| lookup(k).filter(|v| !v.trim().is_empty());
        let bound_channels: Vec<BoundChannel> = match read(sandbox_env::BOUND_CHANNELS) {
            Some(json) => match serde_json::from_str(&json) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "#665 app runtime: AGENTKEYS_BOUND_CHANNELS is not a BoundChannel JSON \
                         array — polling opchat only"
                    );
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        let availability = read(sandbox_env::APP_AVAILABILITY)
            .and_then(|v| Availability::parse(v.trim()))
            .unwrap_or_default();
        let tz_offset_minutes = read(sandbox_env::APP_TZ_OFFSET_MINUTES)
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|m| (-14 * 60..=14 * 60).contains(m))
            .unwrap_or(0);
        Self {
            bound_channels,
            template_id: read(sandbox_env::APP_TEMPLATE).unwrap_or_default(),
            availability,
            tz_offset_minutes,
            self_grants_url: read("AGENTKEYS_SELF_GRANTS_URL")
                .unwrap_or_else(|| DEFAULT_SELF_GRANTS_URL.to_string()),
        }
    }

    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// The feed the sandbox polls (R1): every bound `sub`/`duplex` slot plus
    /// the opchat feed, tagged with its slot name + kind.
    pub fn feeds(&self, chat_channel_id: &str) -> Vec<FeedSpec> {
        let mut feeds = vec![FeedSpec {
            slot: OPCHAT_SLOT.to_string(),
            kind: ChannelEndpointKind::Chat,
            direction: SlotDirection::Duplex,
            channel_id: chat_channel_id.to_string(),
            endpoint_actor_omni: None,
        }];
        for b in &self.bound_channels {
            if b.channel_id == chat_channel_id || feeds.iter().any(|f| f.channel_id == b.channel_id)
            {
                continue;
            }
            feeds.push(FeedSpec {
                slot: b.slot.clone(),
                kind: b.kind,
                direction: b.direction,
                channel_id: b.channel_id.clone(),
                endpoint_actor_omni: b.endpoint_actor_omni.clone(),
            });
        }
        feeds
    }

    /// Resolve a `publish-to-slot` target: a slot NAME of a bound pub/duplex
    /// slot (or `opchat`), else a raw channel id the delegate holds a pub
    /// grant for (the worker refuses an ungranted one at cap-mint).
    pub fn resolve_publish_target(&self, slot_or_channel: &str, chat_channel_id: &str) -> String {
        if slot_or_channel == OPCHAT_SLOT {
            return chat_channel_id.to_string();
        }
        self.bound_channels
            .iter()
            .find(|b| b.slot == slot_or_channel && b.direction.writes())
            .map(|b| b.channel_id.clone())
            .unwrap_or_else(|| slot_or_channel.to_string())
    }
}

/// One feed the loop polls / publishes, tagged for the agent turn (R1: "events
/// arrive tagged with slot name, kind, and worker-stamped provenance").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedSpec {
    pub slot: String,
    pub kind: ChannelEndpointKind,
    pub direction: SlotDirection,
    pub channel_id: String,
    pub endpoint_actor_omni: Option<String>,
}

/// Fetch the app template's bundle from the broker catalog (unauthenticated,
/// compiled-in — `GET /v1/presets/:id`). `None` = no template or unreachable
/// (loud); the loop then runs without schedules / a perception prompt.
pub async fn fetch_template_bundle(
    http: &reqwest::Client,
    broker_url: &str,
    template_id: &str,
) -> Option<PresetBundle> {
    if template_id.trim().is_empty() {
        return None;
    }
    let url = format!(
        "{}/v1/presets/{}",
        broker_url.trim_end_matches('/'),
        template_id
    );
    let mut backoff = std::time::Duration::from_secs(2);
    for attempt in 1..=5 {
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<PresetBundle>().await {
                Ok(b) => return Some(b),
                Err(e) => {
                    tracing::warn!(error = %e, template = %template_id, "#660 app runtime: bundle parse failed");
                    return None;
                }
            },
            Ok(resp) => {
                tracing::warn!(
                    status = %resp.status(),
                    template = %template_id,
                    "#660 app runtime: catalog refused the template — no schedules / perception prompt"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(error = %e, attempt, "#660 app runtime: catalog unreachable — retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
            }
        }
    }
    None
}

/// The delegate's granted service NAMES from the co-located daemon's
/// `/v1/sandbox/self/grants` (D1: a read-through of the chain, never a policy
/// source). `None` = unavailable — callers treat every guard as DENIED.
pub async fn fetch_self_grants(
    http: &reqwest::Client,
    url: &str,
    bridge_token: Option<&str>,
) -> Option<Vec<String>> {
    let mut req = http.get(url).timeout(std::time::Duration::from_secs(20));
    if let Some(t) = bridge_token {
        req = req.bearer_auth(t);
    }
    let resp = match req.send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "#669 self-grants unavailable — guards deny");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "#669 self-grants unreachable — guards deny");
            return None;
        }
    };
    let v: serde_json::Value = resp.json().await.ok()?;
    Some(
        v.get("services")?
            .as_array()?
            .iter()
            .filter_map(|s| s.as_str().map(|s| s.to_ascii_lowercase()))
            .collect(),
    )
}

/// The `tool:<class>` guard over a grant view (case-insensitive like the
/// chain's lowercase hashing).
pub fn tool_granted(services: &[String], class: &str) -> bool {
    let want = agentkeys_backend_client::protocol::service_tool(class).to_ascii_lowercase();
    services.iter().any(|s| s.to_ascii_lowercase() == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> String {
        serde_json::to_string(&vec![
            BoundChannel {
                slot: "family_chat".into(),
                kind: ChannelEndpointKind::Messaging,
                direction: SlotDirection::Sub,
                channel_id: "weixin-chef".into(),
                event_kinds: vec![],
                endpoint_actor_omni: Some("0xgw".into()),
            },
            BoundChannel {
                slot: "kitchen_screen".into(),
                kind: ChannelEndpointKind::Display,
                direction: SlotDirection::Pub,
                channel_id: "kitchen-display".into(),
                event_kinds: vec![],
                endpoint_actor_omni: None,
            },
        ])
        .unwrap()
    }

    #[test]
    fn role_preset_env_polls_only_opchat() {
        let cfg = AppRuntimeConfig::from_lookup(|_| None);
        assert!(cfg.bound_channels.is_empty());
        assert_eq!(cfg.availability, Availability::AlwaysOn);
        assert_eq!(cfg.tz_offset_minutes, 0);
        assert_eq!(cfg.self_grants_url, DEFAULT_SELF_GRANTS_URL);
        let feeds = cfg.feeds("opchat-x");
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds[0].slot, OPCHAT_SLOT);
        assert_eq!(feeds[0].channel_id, "opchat-x");
        assert_eq!(cfg.resolve_publish_target("opchat", "opchat-x"), "opchat-x");
        assert_eq!(
            cfg.resolve_publish_target("raw-feed", "opchat-x"),
            "raw-feed"
        );
    }

    #[test]
    fn app_env_adds_the_bound_feeds_and_resolves_slots() {
        let b = bound();
        let cfg = AppRuntimeConfig::from_lookup(|k| match k {
            sandbox_env::BOUND_CHANNELS => Some(b.clone()),
            sandbox_env::APP_TEMPLATE => Some("chef".into()),
            sandbox_env::APP_AVAILABILITY => Some("wake-on-event".into()),
            sandbox_env::APP_TZ_OFFSET_MINUTES => Some("480".into()),
            _ => None,
        });
        assert_eq!(cfg.template_id, "chef");
        assert_eq!(cfg.availability, Availability::WakeOnEvent);
        assert_eq!(cfg.tz_offset_minutes, 480);
        let feeds = cfg.feeds("opchat-chef");
        assert_eq!(feeds.len(), 3);
        assert_eq!(feeds[1].slot, "family_chat");
        assert_eq!(feeds[1].endpoint_actor_omni.as_deref(), Some("0xgw"));
        // A pub-only slot is a publish target, not a poll source (the poller
        // filters on `direction.reads()`).
        assert_eq!(
            cfg.resolve_publish_target("kitchen_screen", "opchat-chef"),
            "kitchen-display"
        );
        // A sub-only slot is not a publish target by NAME (falls through as a
        // raw id the worker will refuse without a pub grant).
        assert_eq!(
            cfg.resolve_publish_target("family_chat", "opchat-chef"),
            "family_chat"
        );
    }

    #[test]
    fn garbage_env_degrades_loudly_to_defaults() {
        let cfg = AppRuntimeConfig::from_lookup(|k| match k {
            sandbox_env::BOUND_CHANNELS => Some("not json".into()),
            sandbox_env::APP_AVAILABILITY => Some("sometimes".into()),
            sandbox_env::APP_TZ_OFFSET_MINUTES => Some("99999".into()),
            _ => None,
        });
        assert!(cfg.bound_channels.is_empty());
        assert_eq!(cfg.availability, Availability::AlwaysOn);
        assert_eq!(cfg.tz_offset_minutes, 0);
    }

    #[test]
    fn tool_guard_is_case_insensitive_over_the_grant_view() {
        let g = vec![
            "knowledge:app-chef".to_string(),
            "TOOL:Schedule".to_string(),
        ];
        assert!(tool_granted(&g, "schedule"));
        assert!(!tool_granted(&g, "web"));
        assert!(!tool_granted(&[], "schedule"));
    }
}
