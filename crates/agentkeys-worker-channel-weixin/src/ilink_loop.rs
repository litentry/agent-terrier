//! The iLink inbound loop — the long-poll twin of the OA webhook. Mirrors the
//! upstream plugin's monitor semantics (monitor.ts): resumable `get_updates_buf`
//! cursor, server-suggested poll window, 2 s retry / 30 s backoff after 3
//! consecutive failures, and a LOUD 60-min pause on the stale-token errcode
//! (`-14` — only a fresh `--login` ceremony revives the transport).
//!
//! Each USER message runs through the SAME relay core as the OA callback
//! ([`crate::relay::process_inbound`]); the decision reply goes straight back
//! via `sendmessage` with the sender's `context_token` echoed (the reply
//! authorization). Tokens + cursor persist across restarts in a small JSON
//! state file next to the registry.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::ilink::{self, IlinkClient};
use crate::relay;
use crate::state::SharedWeixinGatewayState;

const MAX_CONSECUTIVE_FAILURES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(2);
const BACKOFF_DELAY: Duration = Duration::from_secs(30);
const STALE_TOKEN_PAUSE: Duration = Duration::from_secs(60 * 60);

/// Durable loop state: the resumable cursor + the per-user reply tokens.
/// BOTH belong to ONE bot: a `context_token` is issued inside a conversation
/// with the bot that received the message, and the cursor is that bot's
/// server-side position. So the file is keyed by `bot_key` — a fingerprint of
/// the bot token — and a different bot NEVER inherits it (measured 2026-09-11
/// 23:28 on VE prod: the owner's new bot resumed the old bot's file, the bound
/// notice rode a stale token, the API answered `ret=0`, nothing reached the
/// phone, and the row was wrongly marked welcomed).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IlinkPersist {
    /// `bot_key(token)` of the bot this file belongs to; empty = a pre-#688 file
    /// (adopted once by the first bot that loads it).
    #[serde(default)]
    pub bot_key: String,
    #[serde(default)]
    pub get_updates_buf: String,
    /// `from_user_id` → the user's latest `context_token` (echo on sends).
    #[serde(default)]
    pub context_tokens: HashMap<String, String>,
    /// Unix seconds of the last bind hint sent to an unknown sender (once per window).
    #[serde(default)]
    pub hint_sent_secs: HashMap<String, u64>,
}

/// A stable, non-reversible fingerprint of a bot token (sha256, 16 hex chars).
pub fn bot_key(token: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(token.as_bytes());
    hex::encode(&digest[..8])
}

impl IlinkPersist {
    /// Load the state file FOR a bot: a file another bot wrote is discarded
    /// (fresh cursor, no reply tokens — the new bot has no conversation yet);
    /// an unkeyed pre-#688 file is adopted once.
    pub fn load_for(path: &str, token: &str) -> Self {
        let key = bot_key(token);
        let mut p = Self::load(path);
        if p.bot_key.is_empty() {
            p.bot_key = key;
        } else if p.bot_key != key {
            info!(
                path,
                dropped_reply_tokens = p.context_tokens.len(),
                had_cursor = !p.get_updates_buf.is_empty(),
                "ilink state file belonged to a PREVIOUS bot — starting fresh (its cursor and reply tokens are not this bot's)"
            );
            p = Self {
                bot_key: key,
                ..Self::default()
            };
        }
        p
    }

    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                warn!(path, error = %e, "ilink state file unparsable — starting fresh");
                IlinkPersist::default()
            }),
            Err(_) => IlinkPersist::default(),
        }
    }

    /// Atomic write (tmp + rename), `0600` — context tokens are routing-
    /// sensitive, and a torn write must never eat the cursor.
    pub fn save(&self, path: &str) {
        let tmp = format!("{path}.tmp");
        let Ok(raw) = serde_json::to_string(self) else {
            return;
        };
        if let Err(e) = std::fs::write(&tmp, &raw) {
            warn!(path, error = %e, "ilink state write failed");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            warn!(path, error = %e, "ilink state rename failed");
        }
    }
}

/// Sleep that wakes early on shutdown. Returns false when shutting down.
async fn sleep_or_shutdown(d: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => true,
        _ = shutdown.changed() => false,
    }
}

/// The restart-aware SUPERVISOR `main` spawns under the ilink transport (#418).
/// Runs the inbound loop on the state's CURRENT token/base-url; when the admin
/// login ceremony swaps the identity (`set_ilink_identity` bumps the restart
/// signal) it stops the old loop and respawns on the new one — no process
/// restart. With no token it idles (the bot is OFFLINE until the operator
/// connects it from parent-control or the CLI).
/// One inbound loop PER BOT (2026-09-11: one bot per member). Re-diffs the live
/// bot set on every identity change (a member connects, a revoke drops a bot,
/// the owner re-logs in): loops for gone or re-minted bots stop, missing ones
/// start; each keeps its own cursor + context tokens.
pub async fn supervise(state: SharedWeixinGatewayState, mut shutdown: watch::Receiver<bool>) {
    let mut restart_rx = state.subscribe_ilink_restart();
    let mut running: HashMap<
        String,
        (
            crate::bots::MemberBot,
            watch::Sender<bool>,
            tokio::task::JoinHandle<()>,
        ),
    > = HashMap::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        let desired = state.bots_snapshot();
        let mut stale = Vec::new();
        for (id, (bot, _, _)) in running.iter() {
            let keep = desired
                .get(id)
                .is_some_and(|d| d.token == bot.token && d.base_url == bot.base_url);
            if !keep {
                stale.push(id.clone());
            }
        }
        for id in stale {
            if let Some((_, tx, task)) = running.remove(&id) {
                info!(contact = %id, "iLink bot changed or removed — stopping its inbound loop");
                let _ = tx.send(true);
                let _ = task.await;
            }
        }
        for (id, bot) in desired.iter() {
            if bot.token.trim().is_empty() || running.contains_key(id) {
                continue;
            }
            let (tx, rx) = watch::channel(false);
            let task = tokio::spawn(run_with_token(
                state.clone(),
                id.clone(),
                bot.token.clone(),
                bot.base_url.clone(),
                rx,
            ));
            running.insert(id.clone(), (bot.clone(), tx, task));
        }
        if running.is_empty() {
            info!("no iLink bot token — inbound loop idle until a login (parent-control 连接 / --login)");
        }
        tokio::select! {
            _ = restart_rx.changed() => continue,
            _ = shutdown.changed() => break,
        }
    }
    for (_, (_, tx, task)) in running.drain() {
        let _ = tx.send(true);
        let _ = task.await;
    }
}
pub async fn run(state: SharedWeixinGatewayState, shutdown: watch::Receiver<bool>) {
    let Some(token) = state.current_ilink_token() else {
        error!("ilink loop asked to run with no bot token — not started");
        return;
    };
    let base_url = state.current_ilink_base_url();
    run_with_token(
        state,
        crate::bots::OWNER_CONTACT_ID.to_string(),
        token,
        base_url,
        shutdown,
    )
    .await;
}

/// Run the inbound loop on an EXPLICIT identity until `shutdown` flips.
pub async fn run_with_token(
    state: SharedWeixinGatewayState,
    contact_id: String,
    token: String,
    base_url: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let cfg = &state.config;
    let client = IlinkClient::new(&base_url, Some(token.clone()), &cfg.bot_agent);
    let state_file = if contact_id == crate::bots::OWNER_CONTACT_ID {
        cfg.ilink_state_file.clone()
    } else {
        crate::bots::member_state_file(&cfg.ilink_state_file, &contact_id)
    };
    let mut persist = IlinkPersist::load_for(&state_file, &token);

    info!(
        contact = %contact_id,
        base_url = %base_url,
        resumed_cursor = !persist.get_updates_buf.is_empty(),
        known_reply_tokens = persist.context_tokens.len(),
        "ilink inbound loop started"
    );
    if let Err(e) = client.notify("start").await {
        warn!(error = %e, "notifystart failed (best-effort, continuing)");
    }

    let mut next_poll_ms = ilink::DEFAULT_LONG_POLL_TIMEOUT_MS;
    let mut consecutive_failures: u32 = 0;

    while !*shutdown.borrow() {
        let resp = tokio::select! {
            r = client.get_updates(&persist.get_updates_buf, next_poll_ms) => r,
            _ = shutdown.changed() => break,
        };

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                consecutive_failures += 1;
                error!(error = %e, fails = consecutive_failures, "getupdates transport error");
                let delay = if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    consecutive_failures = 0;
                    BACKOFF_DELAY
                } else {
                    RETRY_DELAY
                };
                if !sleep_or_shutdown(delay, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        if resp.is_stale_token() {
            error!(
                "ilink bot token is STALE (errcode -14) — the transport is DOWN until the \
                 operator re-runs `agentkeys-worker-channel-weixin --login` and updates \
                 AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN; pausing polls for 60 min"
            );
            consecutive_failures = 0;
            if !sleep_or_shutdown(STALE_TOKEN_PAUSE, &mut shutdown).await {
                break;
            }
            continue;
        }
        if resp.is_api_error() {
            consecutive_failures += 1;
            error!(
                ret = resp.ret.unwrap_or_default(),
                errcode = resp.errcode.unwrap_or_default(),
                errmsg = resp.errmsg.as_deref().unwrap_or(""),
                fails = consecutive_failures,
                "getupdates API error"
            );
            let delay = if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                consecutive_failures = 0;
                BACKOFF_DELAY
            } else {
                RETRY_DELAY
            };
            if !sleep_or_shutdown(delay, &mut shutdown).await {
                break;
            }
            continue;
        }

        consecutive_failures = 0;
        state.mark_ilink_ok();
        if let Some(ms) = resp.longpolling_timeout_ms.filter(|&ms| ms > 0) {
            next_poll_ms = ms;
        }
        let mut dirty = false;
        if let Some(buf) = resp.get_updates_buf.as_deref().filter(|b| !b.is_empty()) {
            if buf != persist.get_updates_buf {
                persist.get_updates_buf = buf.to_string();
                dirty = true;
            }
        }

        for msg in resp.msgs.unwrap_or_default() {
            // Only USER-authored turns relay; our own BOT echoes are skipped.
            if msg.message_type != Some(ilink::MSG_TYPE_USER) {
                continue;
            }
            let from = msg.from_user_id.clone().unwrap_or_default();
            if from.is_empty() {
                continue;
            }
            if let Some(ct) = msg.context_token.clone().filter(|c| !c.is_empty()) {
                persist.context_tokens.insert(from.clone(), ct);
                dirty = true;
            }
            let text = ilink::message_body_text(&msg);
            // #667 — a photo / voice clip rides the turn as a media original.
            let media = crate::media::first_ilink_media(&state, &msg).await;
            if text.trim().is_empty() && media.is_none() {
                debug!(from = %from, "inbound without relayable text or media — skipped");
                continue;
            }

            crate::bots::learn_transport_id(&state, &contact_id, &from);
            let outcome = relay::process_turn(&state, "weixin", &from, &text, media).await;
            info!(
                from = %from,
                contact = %outcome.contact_id,
                tier = %outcome.tier,
                allowed = outcome.decision.allowed,
                reason = %outcome.decision.reason,
                target = outcome.decision.target_alias.as_deref().unwrap_or(""),
                "ilink inbound relayed"
            );
            if let Some(f) = outcome.feed.as_ref() {
                info!(channel = %f.channel_id, event = %f.event_id, media = f.media_event_id.is_some(), "feed hop landed");
            } else if let Some(e) = outcome.feed_error.as_ref() {
                warn!(reason = %e, "allowed turn did NOT reach a feed");
            }

            // The member's acknowledgement first (this message carries the first
            // context token her bot can answer with); the row is marked welcomed
            // only once the send succeeded, so it is never lost and never repeated.
            if let Some(w) = outcome.welcome.as_deref() {
                let ct = persist.context_tokens.get(&from).map(|s| s.as_str());
                match client.send_text(&from, w, ct).await {
                    Ok(()) => {
                        state.mark_welcomed(&outcome.contact_id);
                        info!(contact = %outcome.contact_id, "bound notice delivered with the member's first message");
                    }
                    Err(e) => {
                        warn!(contact = %outcome.contact_id, error = %e, "bound notice send failed — retried on the next message")
                    }
                }
            }
            let mut reply =
                outcome.claim_ack.clone().or_else(|| {
                    outcome.reply_text(
                        false,
                        outcome.decision.target_alias.as_deref().and_then(|a| {
                            state.app_stage_hint_for_alias(a, relay::unix_secs() * 1000)
                        }),
                    )
                });
            if reply.is_none() && state.config.unknown_sender_hint {
                let now = relay::unix_secs();
                if let Some(hint) = relay::unknown_sender_hint(
                    &outcome.decision,
                    persist.hint_sent_secs.get(&from).copied(),
                    now,
                    false,
                ) {
                    persist.hint_sent_secs.insert(from.clone(), now);
                    dirty = true;
                    reply = Some(hint.to_string());
                }
            }
            if let Some(reply) = reply {
                let ct = persist.context_tokens.get(&from).map(|s| s.as_str());
                if let Err(e) = client.send_text(&from, &reply, ct).await {
                    warn!(to = %from, error = %e, "reply send failed");
                }
            }
        }
        if dirty {
            persist.save(&state_file);
        }
    }

    if let Err(e) = client.notify("stop").await {
        debug!(error = %e, "notifystop failed (best-effort)");
    }
    info!("ilink inbound loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_roundtrips_and_survives_missing_file() {
        let dir = std::env::temp_dir().join(format!("ilink-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json").to_string_lossy().to_string();

        let fresh = IlinkPersist::load(&path);
        assert!(fresh.get_updates_buf.is_empty() && fresh.context_tokens.is_empty());

        let p = IlinkPersist {
            bot_key: String::new(),
            get_updates_buf: "cursor-1".into(),
            context_tokens: HashMap::from([("wxid-a".to_string(), "ctx-a".to_string())]),
            hint_sent_secs: HashMap::new(),
        };
        p.save(&path);

        let back = IlinkPersist::load(&path);
        assert_eq!(back.get_updates_buf, "cursor-1");
        assert_eq!(
            back.context_tokens.get("wxid-a").map(String::as_str),
            Some("ctx-a")
        );

        // An UNKEYED (pre-#688) file is adopted by the first bot that loads it…
        let adopted = IlinkPersist::load_for(&path, "bot-A:secret");
        assert_eq!(adopted.bot_key, bot_key("bot-A:secret"));
        assert_eq!(adopted.get_updates_buf, "cursor-1");
        adopted.save(&path);
        // …the SAME bot resumes it…
        let same = IlinkPersist::load_for(&path, "bot-A:secret");
        assert_eq!(same.get_updates_buf, "cursor-1");
        assert_eq!(same.context_tokens.len(), 1);
        // …and ANOTHER bot never inherits its cursor or reply tokens.
        let other = IlinkPersist::load_for(&path, "bot-B:secret");
        assert_eq!(other.bot_key, bot_key("bot-B:secret"));
        assert!(other.get_updates_buf.is_empty() && other.context_tokens.is_empty());
        assert_ne!(bot_key("bot-A:secret"), bot_key("bot-B:secret"));
        assert_eq!(bot_key("x").len(), 16);

        std::fs::remove_dir_all(&dir).ok();
    }
}
