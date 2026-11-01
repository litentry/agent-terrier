//! #667 / #669 R3 / household channels — the OUTBOUND half of the feed hop:
//! an app's reply (or an unsolicited publish, e.g. the morning plan to the
//! family chat) lands on a channel's feed as a `direction: out` event; this
//! loop subscribes to every channel some member READS and delivers each one
//! back through the transport.
//!
//! Which feeds: every channel document that lists a member of this transport
//! with `read` (the console writes the documents; an app nobody reads has no
//! feed to deliver from; a feed the master never granted refuses the sub cap
//! and is retried later, loudly once).
//!
//! Who gets it: a reply correlated to an inbound event this gate relayed goes
//! to THAT member (the correlation ring); a reply correlated to another
//! endpoint's turn (the console's own conversation) goes to no transport;
//! an uncorrelated event is an app-initiated publish and goes to every
//! READER of the channel on this transport. Streamed deltas (`partial`) and
//! the gateway's own `in` events are skipped; only `text` delivers today
//! (image out is the next leg — the plan's R3 image round-trip).
//!
//! What they read: on an aggregating transport (every one today) the text is
//! labelled `[<channel name>] …` — one thread must say where each message
//! belongs ([`crate::transport::label`]).
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

/// The feeds this gateway should be subscribed to: every channel some member
/// on this transport reads.
pub fn feeds_for_transport(registry: &ContactRegistry, transport: &str) -> Vec<String> {
    let mut feeds: Vec<String> = registry
        .channels
        .iter()
        .filter(|d| {
            d.members.iter().any(|m| {
                m.read
                    && registry
                        .contact(&m.contact_id)
                        .is_some_and(|c| c.transport == transport)
            })
        })
        .map(|d| d.id.clone())
        .collect();
    feeds.sort();
    feeds.dedup();
    feeds
}

/// The members an app-initiated publish on `feed` goes to: every reader of
/// the channel on this transport (their transport ids).
pub fn audience_for(registry: &ContactRegistry, transport: &str, feed: &str) -> Vec<String> {
    let Some(doc) = registry.channel(feed) else {
        return Vec::new();
    };
    doc.members
        .iter()
        .filter(|m| m.read)
        .filter_map(|m| registry.contact(&m.contact_id))
        .filter(|c| c.transport == transport)
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
                    let registry = state.registry.snapshot();
                    let targets: Vec<String> = match ev.correlation.as_deref() {
                        // A reply to a turn this gate relayed: back to that member.
                        Some(c) => match device.lookup_correlation(c) {
                            Some(row) => vec![row.transport_id],
                            // A reply to another endpoint's turn (the console's
                            // own conversation): not for any transport.
                            None => {
                                debug!(feed = %feed, event = %ev.event_id, "outbound: a reply to a turn this gate did not relay — not delivered");
                                Vec::new()
                            }
                        },
                        // An app-initiated publish: every reader of the channel.
                        None => audience_for(&registry, transport_ns, &feed),
                    };
                    if targets.is_empty() && ev.correlation.is_none() {
                        debug!(feed = %feed, event = %ev.event_id, "outbound: no reader on this transport");
                    }
                    let channel_name = registry
                        .channel(&feed)
                        .map(|d| d.display_name().to_string())
                        .unwrap_or_else(|| feed.clone());
                    let text = crate::transport::label(
                        state.config.transport.kind(),
                        &channel_name,
                        &text,
                    );
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
    use agentkeys_protocol::{ChannelApp, ChannelProducer, Contact, ContactTier};

    fn contact(id: &str, transport: &str, tid: &str, tier: ContactTier) -> Contact {
        Contact {
            contact_id: id.into(),
            transport: transport.into(),
            transport_id: tid.into(),
            display_name: id.into(),
            tier,
            legacy_reach: vec![],
            welcomed: true,
        }
    }

    fn registry() -> ContactRegistry {
        let mut reg = ContactRegistry {
            bound: vec![
                contact("c-owner", "weixin", "wxid-owner", ContactTier::Owner),
                contact("c-kid", "weixin", "wxid-kid", ContactTier::Kid),
                contact("c-tg", "telegram", "42", ContactTier::Partner),
            ],
            ..Default::default()
        };
        let family = reg.channel_or_new("family-chat");
        family.name = "家庭群".into();
        family.upsert_app(ChannelApp {
            alias: "chef".into(),
            ..Default::default()
        });
        family.set_member("c-owner", true, true);
        family.set_member("c-kid", false, true);
        family.set_member("c-tg", true, true);
        let door = reg.channel_or_new("door");
        door.upsert_app(ChannelApp {
            alias: "doorkeeper".into(),
            ..Default::default()
        });
        door.set_member("c-owner", true, true);
        let spend = reg.channel_or_new("spend-chat");
        spend.upsert_app(ChannelApp {
            alias: "spend".into(),
            ..Default::default()
        });
        reg
    }

    #[test]
    fn feeds_and_audience_are_the_readers_per_transport() {
        // A channel is a feed to deliver from when a member of the transport
        // reads it; the audience of an app-initiated publish is its readers,
        // a reader who cannot speak included, a channel nobody reads excluded.
        assert_eq!(
            feeds_for_transport(&registry(), "weixin"),
            vec!["door".to_string(), "family-chat".to_string()]
        );
        assert_eq!(
            feeds_for_transport(&registry(), "telegram"),
            vec!["family-chat"]
        );
        assert!(feeds_for_transport(&registry(), "ilink").is_empty());
        assert_eq!(
            audience_for(&registry(), "weixin", "family-chat"),
            vec!["wxid-owner", "wxid-kid"]
        );
        assert_eq!(
            audience_for(&registry(), "weixin", "door"),
            vec!["wxid-owner"]
        );
        assert_eq!(
            audience_for(&registry(), "telegram", "family-chat"),
            vec!["42"]
        );
        assert!(audience_for(&registry(), "weixin", "spend-chat").is_empty());
        assert!(audience_for(&registry(), "weixin", "weixin-chef").is_empty());
    }

    #[test]
    fn a_pre_channel_registry_file_delivers_from_the_migrated_documents() {
        let mut reg: ContactRegistry = serde_json::from_str(
            r#"{
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
        }"#,
        )
        .expect("registry json");
        assert!(reg.migrate_legacy(1));
        assert_eq!(
            feeds_for_transport(&reg, "weixin"),
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
        // An app nobody reaches has no feed to deliver from.
        assert!(audience_for(&reg, "weixin", "spend-chat").is_empty());
        let reg: ContactRegistry = serde_json::from_str(r#"{"bound": [], "pending": []}"#)
            .expect("pre-2026-09-22 registry json");
        assert!(feeds_for_transport(&reg, "weixin").is_empty());
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
                addressee: None,
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
