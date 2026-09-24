//! #667 / #669 R3 — the OUTBOUND half of the feed hop: an app's reply (or an
//! unsolicited publish, e.g. the morning plan to the family chat) lands on the
//! messaging feed as a `direction: out` event; this loop subscribes to every
//! feed this gateway is granted on and delivers each one back through the
//! transport.
//!
//! Which feeds: the channel each reachable app's messaging slot binds — the
//! registry's `apps` table (`alias → channel`, written by the console at
//! install / rebind; owner decision 2026-09-22: the bound channel IS the feed,
//! no `<transport>-<alias>` derivation) joined with every bound contact's
//! `reach` on this transport. Reach still gates who may talk to an app; the
//! table says where the app listens (an alias nobody can reach has no feed to
//! deliver from; a feed the master never granted refuses the sub cap and is
//! retried later, loudly once).
//!
//! Who gets it: a reply correlated to an inbound event id goes to THAT contact
//! (the correlation ring); anything else on the feed is an app-initiated
//! publish and goes to the feed's AUDIENCE — every bound contact on this
//! transport whose reach carries the alias. Streamed deltas (`partial`) and
//! the gateway's own `in` events are skipped; only `text` delivers today
//! (image out is the next leg — the plan's R3 image round-trip).
//!
//! Cursors persist per feed; a fresh feed starts at its CURRENT tail (never a
//! replay of history back to a phone).

use std::collections::HashMap;
use std::time::Duration;

use agentkeys_protocol::{ChannelDirection, ChannelEvent, ChannelEventKind, ContactRegistry};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::WeixinTransport;
use crate::state::SharedWeixinGatewayState;

const RECONCILE_EVERY: Duration = Duration::from_secs(30);
const POLL_WAIT_SECONDS: u64 = 20;
const UNGRANTED_RETRY: Duration = Duration::from_secs(300);
const ERROR_RETRY: Duration = Duration::from_secs(20);

/// The feeds this gateway should be subscribed to: the bound channel of every
/// app some contact on this transport can reach (registry `apps` × `reach`).
pub fn feeds_for_transport(registry: &ContactRegistry, transport: &str) -> Vec<String> {
    let mut feeds: Vec<String> = registry
        .bound
        .iter()
        .filter(|c| c.transport == transport)
        .flat_map(|c| c.reach.iter())
        .filter_map(|alias| registry.app_channel(alias).map(str::to_string))
        .collect();
    feeds.sort();
    feeds.dedup();
    feeds
}

/// The contacts an app-initiated publish on `feed` goes to: everyone on this
/// transport whose reach names an app bound to that channel.
pub fn audience_for(registry: &ContactRegistry, transport: &str, feed: &str) -> Vec<String> {
    let aliases = registry.aliases_on_channel(feed);
    registry
        .bound
        .iter()
        .filter(|c| c.transport == transport)
        .filter(|c| {
            c.reach
                .iter()
                .any(|r| aliases.iter().any(|a| a.eq_ignore_ascii_case(r)))
        })
        .map(|c| c.transport_id.clone())
        .collect()
}

/// Should this event be delivered? `out`, final (not a delta), text.
pub fn deliverable(ev: &ChannelEvent) -> bool {
    ev.direction == ChannelDirection::Out
        && ev.partial != Some(true)
        && ev.kind == ChannelEventKind::Text
        && ev.body.as_deref().is_some_and(|b| !b.is_empty())
}

/// The `stage` word of a lifecycle report (its JSON body).
pub fn lifecycle_stage(ev: &ChannelEvent) -> Option<String> {
    let text = decode_text(ev)?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("stage")?.as_str().map(str::to_string)
}

fn decode_text(ev: &ChannelEvent) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64 = ev.body.as_deref()?;
    let bytes = STANDARD.decode(b64).ok()?;
    String::from_utf8(bytes).ok()
}

/// Send one text to one contact through THIS transport (runtime identity).
pub(crate) async fn deliver(
    state: &SharedWeixinGatewayState,
    transport_id: &str,
    text: &str,
) -> anyhow::Result<()> {
    let cfg = &state.config;
    match cfg.transport {
        WeixinTransport::Ilink => {
            // Per-member bots: the contact's OWN bot carries the send (its token,
            // its host, its context tokens); the owner's bot is the legacy
            // fallback for an id no member bot owns.
            let reg = state.registry.snapshot();
            let owner_id = reg
                .bound
                .iter()
                .find(|c| c.transport == "weixin" && c.transport_id == transport_id)
                .map(|c| c.contact_id.clone());
            let (bot_contact, bot) = owner_id
                .as_deref()
                .and_then(|cid| state.bot_for_contact(cid).map(|b| (cid.to_string(), b)))
                .or_else(|| {
                    state
                        .bot_for_contact(crate::bots::OWNER_CONTACT_ID)
                        .map(|b| (crate::bots::OWNER_CONTACT_ID.to_string(), b))
                })
                .ok_or_else(|| anyhow::anyhow!("iLink offline (no bot token)"))?;
            let base_url = if bot.base_url.is_empty() {
                cfg.ilink_base_url.clone()
            } else {
                bot.base_url.clone()
            };
            let client =
                crate::ilink::IlinkClient::new(&base_url, Some(bot.token.clone()), &cfg.bot_agent);
            let state_file = if bot_contact == crate::bots::OWNER_CONTACT_ID {
                cfg.ilink_state_file.clone()
            } else {
                crate::bots::member_state_file(&cfg.ilink_state_file, &bot_contact)
            };
            // Reply tokens are per bot: a token this bot did not receive (a
            // previous bot's file, or none yet — a fresh bot has no conversation
            // until the member writes first) is not a delivery path. The API
            // answers ret=0 to such a send and the phone shows nothing (measured
            // 2026-09-11), so this is an ERROR, never a silent "delivered".
            let persist = crate::ilink_loop::IlinkPersist::load_for(&state_file, &bot.token);
            let Some(ct) = persist.context_tokens.get(transport_id).map(String::as_str) else {
                anyhow::bail!(
                    "no reply token for this recipient on bot {} yet — deliverable only after their first message",
                    if bot.bot_id.is_empty() { "(legacy)" } else { bot.bot_id.as_str() }
                );
            };
            client.send_text(transport_id, text, Some(ct)).await
        }
        WeixinTransport::Telegram => {
            let token = cfg
                .telegram_bot_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("telegram offline (no bot token)"))?;
            let client = crate::telegram::TelegramClient::new(&cfg.telegram_api_base, &token);
            let persist = crate::telegram_loop::TelegramPersist::load(&cfg.telegram_state_file);
            let chat_id = persist
                .chat_ids
                .get(transport_id)
                .copied()
                .or_else(|| transport_id.parse::<i64>().ok())
                .ok_or_else(|| anyhow::anyhow!("no chat id for {transport_id}"))?;
            client.send_text(chat_id, text).await
        }
        WeixinTransport::Oa => {
            anyhow::bail!("the OA transport has no async send path yet (app-secret template send)")
        }
    }
}

/// One feed's subscriber task.
async fn feed_task(
    state: SharedWeixinGatewayState,
    feed: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let transport = state.config.transport.as_str().to_string();
    let transport_ns = match state.config.transport {
        WeixinTransport::Telegram => "telegram",
        _ => "weixin",
    };
    let device = state.device.clone();
    let operator = state.effective_operator_omni();
    let mut cursor = device.cursor(&feed);
    // A fresh feed: adopt the current tail without delivering history.
    let mut priming = cursor.is_none();
    let mut announced_ungranted = false;
    info!(feed = %feed, transport = %transport, "outbound: subscribing");
    while !*shutdown.borrow() {
        let after = cursor.clone().unwrap_or_default();
        let wait = if priming { 0 } else { POLL_WAIT_SECONDS };
        let polled = tokio::select! {
            r = device.poll(&operator, &feed, &after, wait) => r,
            _ = shutdown.changed() => break,
        };
        match polled {
            Ok((events, next)) => {
                announced_ungranted = false;
                if priming {
                    priming = false;
                    if !next.is_empty() {
                        cursor = Some(next.clone());
                        device.set_cursor(&feed, &next);
                    }
                    continue;
                }
                for ev in events {
                    // #693 — an app's lifecycle report: remember its stage for the
                    // receipt; never a message to deliver.
                    if ev.kind == ChannelEventKind::Lifecycle {
                        if let Some(stage) = lifecycle_stage(&ev) {
                            state.note_app_stage(&feed, &stage, ev.ts_millis);
                        }
                        continue;
                    }
                    if !deliverable(&ev) {
                        continue;
                    }
                    let Some(text) = decode_text(&ev) else {
                        continue;
                    };
                    let targets: Vec<String> = match ev
                        .correlation
                        .as_deref()
                        .and_then(|c| device.lookup_correlation(c))
                    {
                        Some(row) => vec![row.transport_id],
                        None => audience_for(&state.registry.snapshot(), transport_ns, &feed),
                    };
                    if targets.is_empty() {
                        debug!(feed = %feed, event = %ev.event_id, "outbound: no addressee (no correlation, empty audience)");
                    }
                    for to in targets {
                        match deliver(&state, &to, &text).await {
                            Ok(()) => {
                                info!(feed = %feed, event = %ev.event_id, "outbound: delivered")
                            }
                            Err(e) => {
                                warn!(feed = %feed, event = %ev.event_id, error = %e, "outbound: delivery failed")
                            }
                        }
                    }
                }
                if !next.is_empty() && cursor.as_deref() != Some(next.as_str()) {
                    cursor = Some(next.clone());
                    device.set_cursor(&feed, &next);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                let ungranted = msg.contains("not_in_scope")
                    || msg.contains("403")
                    || msg.contains("service_not_in_scope")
                    || msg.contains("cap mint");
                if ungranted {
                    if !announced_ungranted {
                        info!(
                            feed = %feed,
                            "outbound: no subscribe grant on this feed yet (an app install grants it) — retrying every {}s",
                            UNGRANTED_RETRY.as_secs()
                        );
                        announced_ungranted = true;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(UNGRANTED_RETRY) => {}
                        _ = shutdown.changed() => break,
                    }
                } else {
                    warn!(feed = %feed, error = %msg, "outbound: poll failed");
                    tokio::select! {
                        _ = tokio::time::sleep(ERROR_RETRY) => {}
                        _ = shutdown.changed() => break,
                    }
                }
            }
        }
    }
    debug!(feed = %feed, "outbound: subscriber stopped");
}

/// The supervisor `main` spawns: reconciles the feed set from the registry
/// every 30 s, one subscriber task per feed. Idles until the device is
/// enrolled + the channel worker is configured.
pub async fn run(state: SharedWeixinGatewayState, mut shutdown: watch::Receiver<bool>) {
    if !state.config.device.outbound_enabled {
        info!("outbound feed delivery DISABLED (AGENTKEYS_WEIXIN_FEED_OUTBOUND=0)");
        return;
    }
    let transport_ns = match state.config.transport {
        WeixinTransport::Telegram => "telegram",
        _ => "weixin",
    };
    let mut tasks: HashMap<String, (watch::Sender<bool>, tokio::task::JoinHandle<()>)> =
        HashMap::new();
    let mut announced_blocker: Option<&'static str> = None;
    while !*shutdown.borrow() {
        if let Some(b) = state.device.hop_blocker() {
            if announced_blocker != Some(b) {
                info!("outbound feed delivery idle — {b}");
                announced_blocker = Some(b);
            }
        } else {
            announced_blocker = None;
            let wanted = feeds_for_transport(&state.registry.snapshot(), transport_ns);
            let stale: Vec<String> = tasks
                .keys()
                .filter(|f| !wanted.contains(f))
                .cloned()
                .collect();
            for f in stale {
                if let Some((tx, handle)) = tasks.remove(&f) {
                    let _ = tx.send(true);
                    handle.abort();
                    info!(feed = %f, "outbound: unsubscribed (no contact reaches it any more)");
                }
            }
            for f in wanted {
                if tasks.contains_key(&f) {
                    continue;
                }
                let (tx, rx) = watch::channel(false);
                let handle = tokio::spawn(feed_task(state.clone(), f.clone(), rx));
                tasks.insert(f, (tx, handle));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(RECONCILE_EVERY) => {}
            _ = shutdown.changed() => break,
        }
    }
    for (_, (tx, handle)) in tasks.drain() {
        let _ = tx.send(true);
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::{ChannelProducer, Contact, ContactTier};

    fn registry() -> ContactRegistry {
        ContactRegistry {
            bound: vec![
                Contact {
                    contact_id: "c-owner".into(),
                    transport: "weixin".into(),
                    transport_id: "wxid-owner".into(),
                    display_name: "妈妈".into(),
                    tier: ContactTier::Owner,
                    reach: vec!["chef".into(), "Doorkeeper".into()],
                    welcomed: true,
                },
                Contact {
                    contact_id: "c-kid".into(),
                    transport: "weixin".into(),
                    transport_id: "wxid-kid".into(),
                    display_name: "小明".into(),
                    tier: ContactTier::Kid,
                    reach: vec!["chef".into()],
                    welcomed: true,
                },
                Contact {
                    contact_id: "c-tg".into(),
                    transport: "telegram".into(),
                    transport_id: "42".into(),
                    display_name: "A".into(),
                    tier: ContactTier::Partner,
                    reach: vec!["chef".into()],
                    welcomed: true,
                },
            ],
            pending: vec![],
            invites: vec![],
            apps: vec![
                agentkeys_protocol::AppFeed {
                    alias: "chef".into(),
                    channel_id: "family-chat".into(),
                    blurb: None,
                },
                agentkeys_protocol::AppFeed {
                    alias: "doorkeeper".into(),
                    channel_id: "door".into(),
                    blurb: None,
                },
            ],
        }
    }

    #[test]
    fn feeds_and_audience_follow_the_apps_table_and_reach_per_transport() {
        // The bound channel IS the feed (2026-09-22): reach says who may talk
        // to an app, the apps table says where the app listens.
        assert_eq!(
            feeds_for_transport(&registry(), "weixin"),
            vec!["door".to_string(), "family-chat".to_string()]
        );
        assert_eq!(
            feeds_for_transport(&registry(), "telegram"),
            vec!["family-chat"]
        );
        assert_eq!(
            audience_for(&registry(), "weixin", "family-chat"),
            vec!["wxid-owner", "wxid-kid"]
        );
        assert_eq!(
            audience_for(&registry(), "weixin", "door"),
            vec!["wxid-owner"]
        );
        assert!(audience_for(&registry(), "weixin", "weixin-chef").is_empty());
    }

    #[test]
    fn only_final_out_text_delivers() {
        let ev =
            |dir: ChannelDirection, kind: ChannelEventKind, partial: Option<bool>| ChannelEvent {
                event_id: "e".into(),
                channel_id: "weixin-chef".into(),
                direction: dir,
                producer: ChannelProducer::Actor {
                    actor_omni: "0xabc".into(),
                },
                kind,
                body: Some("aGk=".into()),
                body_ref: None,
                ts_millis: 0,
                correlation: None,
                audio: None,
                partial,
                seq: None,
                stream: None,
                contact: None,
                content_type: None,
                relay_of: None,
            };
        assert!(deliverable(&ev(
            ChannelDirection::Out,
            ChannelEventKind::Text,
            None
        )));
        assert!(!deliverable(&ev(
            ChannelDirection::In,
            ChannelEventKind::Text,
            None
        )));
        assert!(!deliverable(&ev(
            ChannelDirection::Out,
            ChannelEventKind::Text,
            Some(true)
        )));
        assert!(!deliverable(&ev(
            ChannelDirection::Out,
            ChannelEventKind::Image,
            None
        )));
        assert_eq!(
            decode_text(&ev(ChannelDirection::Out, ChannelEventKind::Text, None)).as_deref(),
            Some("hi")
        );
    }
}

#[cfg(test)]
mod feed_tests {
    use super::*;

    fn registry() -> ContactRegistry {
        let json = r#"{
          "bound": [
            {"contact_id":"c-owner","transport":"weixin","transport_id":"openid-owner",
             "display_name":"妈妈","tier":"owner","reach":["Chef","doorkeeper"]},
            {"contact_id":"c-kid","transport":"weixin","transport_id":"openid-kid",
             "display_name":"小明","tier":"kid","reach":["storyteller","chef"]},
            {"contact_id":"c-tg","transport":"telegram","transport_id":"1001",
             "display_name":"Alex","tier":"owner","reach":["chef"]}
          ],
          "pending": [],
          "apps": [
            {"alias":"chef","channel_id":"family-chat"},
            {"alias":"doorkeeper","channel_id":"door"},
            {"alias":"storyteller","channel_id":"stories"},
            {"alias":"spend","channel_id":"spend-chat"}
          ]
        }"#;
        serde_json::from_str(json).expect("registry json")
    }

    #[test]
    fn feeds_follow_the_apps_table_per_transport_and_dedupe() {
        let reg = registry();
        let feeds = feeds_for_transport(&reg, "weixin");
        assert_eq!(
            feeds,
            vec![
                "door".to_string(),
                "family-chat".to_string(),
                "stories".to_string()
            ]
        );
        assert_eq!(
            feeds_for_transport(&reg, "telegram"),
            vec!["family-chat".to_string()]
        );
        assert!(feeds_for_transport(&reg, "ilink").is_empty());
        // An app nobody reaches has no feed to deliver from.
        assert!(!feeds.contains(&"spend-chat".to_string()));
    }

    #[test]
    fn an_older_registry_file_without_the_apps_table_still_parses() {
        let reg: ContactRegistry = serde_json::from_str(r#"{"bound": [], "pending": []}"#)
            .expect("pre-2026-09-22 registry json");
        assert!(reg.apps.is_empty());
        assert!(feeds_for_transport(&reg, "weixin").is_empty());
    }

    #[test]
    fn audience_is_reach_bounded_per_transport() {
        let reg = registry();
        let mut chef = audience_for(&reg, "weixin", "family-chat");
        chef.sort();
        assert_eq!(
            chef,
            vec!["openid-kid".to_string(), "openid-owner".to_string()]
        );
        assert_eq!(
            audience_for(&reg, "weixin", "stories"),
            vec!["openid-kid".to_string()]
        );
        assert_eq!(
            audience_for(&reg, "telegram", "family-chat"),
            vec!["1001".to_string()]
        );
        assert!(audience_for(&reg, "weixin", "spend-chat").is_empty());
        assert!(audience_for(&reg, "weixin", "weixin-chef").is_empty());
    }
}
