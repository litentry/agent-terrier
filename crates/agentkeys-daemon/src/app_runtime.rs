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

    /// The spawn env, then this instance's live-rebind override when one was
    /// pushed (`bound_channels_file`) — a `--publish-once` subprocess and a
    /// daemon restart inside the same instance follow the rebind too.
    pub fn from_env() -> Self {
        let mut cfg = Self::from_lookup(|k| std::env::var(k).ok());
        if let Some(bound) = read_bound_channels_override(&bound_channels_file()) {
            cfg.bound_channels = bound;
        }
        cfg
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

/// Where a live rebind (#717) persists this instance's bound channels over the
/// spawn env (`AGENTKEYS_BOUND_CHANNELS_FILE`, default
/// `/var/lib/agentkeys/bound-channels.json`). A re-created instance boots from
/// the broker's updated context and never sees the file.
pub fn bound_channels_file() -> String {
    std::env::var("AGENTKEYS_BOUND_CHANNELS_FILE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/var/lib/agentkeys/bound-channels.json".to_string())
}

pub fn read_bound_channels_override(path: &str) -> Option<Vec<BoundChannel>> {
    let raw = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<Vec<BoundChannel>>(&raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(
                path,
                error = %e,
                "#717 live rebind: the bound-channels override is not a BoundChannel JSON array — ignored"
            );
            None
        }
    }
}

static LIVE_BINDINGS: std::sync::OnceLock<tokio::sync::watch::Sender<Option<Vec<BoundChannel>>>> =
    std::sync::OnceLock::new();

/// The live-rebind channel: `/v1/sandbox/self/bindings` sends, the chat
/// loop's feed supervisor receives.
pub fn live_bindings_sender() -> &'static tokio::sync::watch::Sender<Option<Vec<BoundChannel>>> {
    LIVE_BINDINGS.get_or_init(|| tokio::sync::watch::channel(None).0)
}

pub fn live_bindings_receiver() -> tokio::sync::watch::Receiver<Option<Vec<BoundChannel>>> {
    live_bindings_sender().subscribe()
}

/// Apply a live rebind: persist the override, hand the set to the chat loop.
/// Returns the bound-channel count.
pub fn apply_live_bindings(bound: Vec<BoundChannel>) -> Result<usize, String> {
    let path = bound_channels_file();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(&bound).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("{path}: {e}"))?;
    let n = bound.len();
    live_bindings_sender().send_replace(Some(bound));
    Ok(n)
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

/// How long [`seed_bundle_context_when_bridge_up`] waits for the bridge to
/// answer (`AGENTKEYS_BRIDGE_APPLY_WAIT_SECS`, default 180, 10..=900) — the
/// bridge binds early (#589) but a cold pod can take a minute to reach it.
fn bridge_apply_wait_secs() -> u64 {
    std::env::var("AGENTKEYS_BRIDGE_APPLY_WAIT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| (10..=900).contains(s))
        .unwrap_or(180)
}

/// What the bridge's `/v1/context/files` view says is present.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextPresence {
    pub soul: bool,
    pub skills: usize,
    pub knowledge: usize,
}

/// Parse the bridge's `/v1/context/files` answer (`files[{id, present}]`,
/// `skills[]`, `knowledge[]`) — pure.
pub fn parse_context_presence(v: &serde_json::Value) -> ContextPresence {
    let soul = v
        .get("files")
        .and_then(|f| f.as_array())
        .map(|files| {
            files.iter().any(|f| {
                f.get("id").and_then(|i| i.as_str()) == Some("soul")
                    && f.get("present").and_then(|p| p.as_bool()) == Some(true)
            })
        })
        .unwrap_or(false);
    let count = |k: &str| {
        v.get(k)
            .and_then(|a| a.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    };
    ContextPresence {
        soul,
        skills: count("skills"),
        knowledge: count("knowledge"),
    }
}

/// The `/v1/context/apply` body that fills what the bridge LACKS from the
/// template bundle: the persona only when no SOUL.md is present (and the
/// bundle's passed the persona gate), the skills only when the skills store
/// is empty, the knowledge likewise — name → base64 content, `restart: false`
/// (the bridge re-registers its prompt sections on every apply; the next turn
/// sees them, a turn in flight is never cut). `None` = nothing to seed. Pure.
pub fn bundle_seed_body(
    present: &ContextPresence,
    bundle: &PresetBundle,
    persona_valid: bool,
) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    let docs = |v: &[agentkeys_backend_client::protocol::PresetSkillDoc]| -> serde_json::Map<String, serde_json::Value> {
        v.iter()
            .map(|d| (d.filename.clone(), serde_json::Value::String(b64(&d.content))))
            .collect()
    };
    let mut body = serde_json::Map::new();
    if !present.soul && persona_valid && !bundle.soul_md.trim().is_empty() {
        body.insert(
            "files".into(),
            serde_json::json!({ "soul": b64(&bundle.soul_md) }),
        );
    }
    if present.skills == 0 && !bundle.skills.is_empty() {
        body.insert(
            "skills".into(),
            serde_json::Value::Object(docs(&bundle.skills)),
        );
    }
    if present.knowledge == 0 && !bundle.knowledge.is_empty() {
        body.insert(
            "knowledge".into(),
            serde_json::Value::Object(docs(&bundle.knowledge)),
        );
    }
    if body.is_empty() {
        return None;
    }
    body.insert("restart".into(), serde_json::Value::Bool(false));
    Some(serde_json::Value::Object(body))
}

/// Wait for the local bridge, read what it holds, and seed the missing
/// persona / skills / knowledge from the template bundle. Every outcome is
/// logged; nothing here is load-bearing for the loop.
pub async fn seed_bundle_context_when_bridge_up(
    http: reqwest::Client,
    bridge_url: String,
    bridge_token: Option<String>,
    bundle: PresetBundle,
    persona_valid: bool,
) {
    let base = bridge_url.trim_end_matches('/').to_string();
    let template = bundle.manifest.id.clone();
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(bridge_apply_wait_secs());
    let authed = |req: reqwest::RequestBuilder| match &bridge_token {
        Some(token) => req.bearer_auth(token),
        None => req,
    };
    // The bridge answers /healthz at ANY status once its process is up (503
    // `starting` while no agent holds a session — #711); a transport error
    // means it is not listening yet.
    loop {
        let up = http
            .get(format!("{base}/healthz"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .is_ok();
        if up {
            break;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                template = %template,
                "#660 app runtime: bridge never answered — the template context was NOT seeded at boot"
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    let present = match authed(http.get(format!("{base}/v1/context/files")))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            parse_context_presence(&resp.json::<serde_json::Value>().await.unwrap_or_default())
        }
        Ok(resp) => {
            tracing::warn!(template = %template, status = %resp.status(), "#660 app runtime: bridge context view refused — seeding skipped");
            return;
        }
        Err(e) => {
            tracing::warn!(template = %template, error = %e, "#660 app runtime: bridge context view failed — seeding skipped");
            return;
        }
    };
    if !persona_valid {
        tracing::error!(template = %template, "#660 app runtime: the template's SOUL.md fails the persona gate — not seeded (repo-bundle bug)");
    }
    let Some(body) = bundle_seed_body(&present, &bundle, persona_valid) else {
        tracing::info!(
            template = %template,
            soul = present.soul,
            skills = present.skills,
            knowledge = present.knowledge,
            "#660 app runtime: bridge context already present — nothing to seed"
        );
        return;
    };
    match authed(http.post(format!("{base}/v1/context/apply")))
        .timeout(std::time::Duration::from_secs(30))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let v: serde_json::Value = resp.json().await.unwrap_or_default();
            let n = |k: &str| {
                v.get(k)
                    .and_then(|s| s.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0)
            };
            tracing::info!(
                template = %template,
                files = n("files_written"),
                skills = n("skills_written"),
                knowledge = n("knowledge_written"),
                "#660 app runtime: template context seeded into the bridge at boot"
            );
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(
                template = %template,
                %status,
                body = %text.chars().take(200).collect::<String>(),
                "#660 app runtime: bridge refused the context seed"
            );
        }
        Err(e) => {
            tracing::warn!(template = %template, error = %e, "#660 app runtime: context seed failed");
        }
    }
}

#[cfg(test)]
mod bundle_seed_tests {
    use super::{bundle_seed_body, parse_context_presence, ContextPresence};
    use agentkeys_backend_client::protocol::PresetBundle;

    fn bundle() -> PresetBundle {
        serde_json::from_value(serde_json::json!({
            "manifest": { "id": "chef", "version": "1.0.0", "name": "Chef" },
            "soul_md": "# Chef\n\nA family cook.",
            "skills": [{ "filename": "plan.md", "content": "plan" }],
            "knowledge": [{ "filename": "nutrition-basics.md", "content": "basics" }]
        }))
        .expect("a minimal bundle")
    }

    #[test]
    fn a_bare_bridge_gets_persona_skills_and_knowledge_without_a_restart() {
        let body = bundle_seed_body(&ContextPresence::default(), &bundle(), true).expect("seed");
        assert_eq!(body["files"]["soul"], "IyBDaGVmCgpBIGZhbWlseSBjb29rLg==");
        assert_eq!(body["skills"]["plan.md"], "cGxhbg==");
        assert_eq!(body["knowledge"]["nutrition-basics.md"], "YmFzaWNz");
        assert_eq!(body["restart"], false);
    }

    #[test]
    fn only_what_is_missing_is_seeded_and_a_full_bridge_gets_nothing() {
        let present = ContextPresence {
            soul: true,
            skills: 0,
            knowledge: 1,
        };
        let body = bundle_seed_body(&present, &bundle(), true).expect("skills missing");
        assert!(
            body.get("files").is_none(),
            "an applied persona is never clobbered"
        );
        assert!(body.get("knowledge").is_none());
        assert_eq!(body["skills"]["plan.md"], "cGxhbg==");
        let full = ContextPresence {
            soul: true,
            skills: 4,
            knowledge: 1,
        };
        assert!(bundle_seed_body(&full, &bundle(), true).is_none());
        // A persona that fails the gate is skipped; the docs still seed.
        let body = bundle_seed_body(&ContextPresence::default(), &bundle(), false).expect("docs");
        assert!(body.get("files").is_none());
        assert!(body.get("skills").is_some());
    }

    #[test]
    fn the_bridge_view_parses_into_presence() {
        let v = serde_json::json!({
            "files": [{ "id": "soul", "present": false }, { "id": "agents", "present": true }],
            "skills": ["diary.md", "plan.md"],
            "knowledge": [],
            "cwd": "/opt/agentkeys"
        });
        assert_eq!(
            parse_context_presence(&v),
            ContextPresence {
                soul: false,
                skills: 2,
                knowledge: 0
            }
        );
        assert_eq!(
            parse_context_presence(&serde_json::json!({})),
            ContextPresence::default()
        );
    }
}

#[cfg(test)]
mod live_bindings_tests {
    use super::*;

    #[test]
    fn the_override_file_round_trips_and_garbage_is_ignored() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("ak-bind-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bound-channels.json");
        let bound = vec![BoundChannel {
            slot: "family_chat".into(),
            kind: ChannelEndpointKind::Messaging,
            direction: SlotDirection::Duplex,
            channel_id: "family-chat".into(),
            event_kinds: vec![],
            endpoint_actor_omni: None,
        }];
        std::fs::write(&path, serde_json::to_vec(&bound).unwrap()).unwrap();
        assert_eq!(
            read_bound_channels_override(path.to_str().unwrap()),
            Some(bound)
        );
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(read_bound_channels_override(path.to_str().unwrap()), None);
        assert_eq!(
            read_bound_channels_override(dir.join("absent.json").to_str().unwrap()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
