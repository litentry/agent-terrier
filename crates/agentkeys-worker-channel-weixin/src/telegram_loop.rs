//! The Telegram inbound loop (#444) — the stack-② long-poll twin of
//! [`crate::ilink_loop`]. `getUpdates` with a resumable offset cursor; each
//! private-chat USER message runs through the SAME relay core as every other
//! transport ([`crate::relay::process_inbound_for`] with transport
//! `"telegram"`); the decision reply goes straight back via `sendMessage`.
//!
//! Simpler than iLink by design: the bot token is static (BotFather mints it
//! once; no QR ceremony, no hot-swap supervisor). No token = the loop idles
//! OFFLINE (#418 posture) until the operator fills the secrets file and
//! restarts the unit. A 401/404 (revoked token) pauses polls for 60 min with a
//! LOUD error; a 409 (second consumer on the same token) is a deployment error
//! and backs off the same way — retrying into it would just steal updates
//! back and forth.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::relay;
use crate::state::SharedWeixinGatewayState;
use crate::telegram::{TelegramClient, TgUpdate};

const MAX_CONSECUTIVE_FAILURES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(2);
const BACKOFF_DELAY: Duration = Duration::from_secs(30);
const BAD_TOKEN_PAUSE: Duration = Duration::from_secs(60 * 60);

/// Durable loop state: the `getUpdates` offset cursor + each contact's chat id
/// (private-chat id == user id today, but recording it keeps replies correct
/// if that Bot API invariant ever bends).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TelegramPersist {
    #[serde(default)]
    pub next_offset: i64,
    /// `from_user_id` (decimal string) → the chat to reply into.
    #[serde(default)]
    pub chat_ids: HashMap<String, i64>,
}

impl TelegramPersist {
    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                warn!(path, error = %e, "telegram state file unparsable — starting fresh");
                TelegramPersist::default()
            }),
            Err(_) => TelegramPersist::default(),
        }
    }

    /// Atomic write (tmp + rename), `0600` — a torn write must never eat the
    /// cursor (a reset cursor would replay every backlogged update).
    pub fn save(&self, path: &str) {
        let tmp = format!("{path}.tmp");
        let Ok(raw) = serde_json::to_string(self) else {
            return;
        };
        if let Err(e) = std::fs::write(&tmp, &raw) {
            warn!(path, error = %e, "telegram state write failed");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            warn!(path, error = %e, "telegram state rename failed");
        }
    }
}

/// The highest `update_id` in a batch, as the NEXT offset (`+1` acknowledges
/// the batch per the Bot API cursor contract). `None` = empty batch.
pub fn next_offset_after(updates: &[TgUpdate]) -> Option<i64> {
    updates.iter().map(|u| u.update_id).max().map(|m| m + 1)
}

/// Sleep that wakes early on shutdown. Returns false when shutting down.
async fn sleep_or_shutdown(d: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => true,
        _ = shutdown.changed() => false,
    }
}

/// The loop `main` spawns under the telegram transport. With no token it idles
/// (the bot is OFFLINE until the operator fills the secrets file + restarts —
/// the healthz `outbound_enabled` shows it).
pub async fn run(state: SharedWeixinGatewayState, mut shutdown: watch::Receiver<bool>) {
    let cfg = &state.config;
    let Some(token) = cfg.telegram_bot_token.clone() else {
        info!(
            "telegram loop idle — no bot token (fill AGENTKEYS_TELEGRAM_BOT_TOKEN in the \
             gateway secrets file and restart the unit)"
        );
        let _ = shutdown.changed().await;
        return;
    };
    let client = TelegramClient::new(&cfg.telegram_api_base, &token);
    let state_file = cfg.telegram_state_file.clone();
    let mut persist = TelegramPersist::load(&state_file);

    info!(
        api_base = %cfg.telegram_api_base,
        resumed_offset = persist.next_offset,
        known_chats = persist.chat_ids.len(),
        "telegram inbound loop started"
    );

    let mut consecutive_failures: u32 = 0;

    while !*shutdown.borrow() {
        let resp = tokio::select! {
            r = client.get_updates(persist.next_offset) => r,
            _ = shutdown.changed() => break,
        };

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                consecutive_failures += 1;
                error!(error = %e, fails = consecutive_failures, "getUpdates transport error");
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

        if resp.is_bad_token() {
            error!(
                "telegram bot token is REVOKED/BAD (401/404) — the transport is DOWN until the \
                 operator mints a new token via BotFather and updates \
                 AGENTKEYS_TELEGRAM_BOT_TOKEN; pausing polls for 60 min"
            );
            consecutive_failures = 0;
            if !sleep_or_shutdown(BAD_TOKEN_PAUSE, &mut shutdown).await {
                break;
            }
            continue;
        }
        if resp.is_conflict() {
            error!(
                "getUpdates CONFLICT (409) — another consumer (a second gateway instance or a \
                 leftover webhook) is polling this bot token; fix the deployment (one gateway \
                 per bot). Backing off 60 min instead of stealing updates back and forth"
            );
            consecutive_failures = 0;
            if !sleep_or_shutdown(BAD_TOKEN_PAUSE, &mut shutdown).await {
                break;
            }
            continue;
        }
        if !resp.ok {
            consecutive_failures += 1;
            let retry_after = resp
                .parameters
                .as_ref()
                .and_then(|p| p.retry_after)
                .map(Duration::from_secs);
            error!(
                error_code = resp.error_code.unwrap_or_default(),
                description = resp.description.as_deref().unwrap_or(""),
                fails = consecutive_failures,
                "getUpdates API error"
            );
            let delay = if let Some(ra) = retry_after {
                ra
            } else if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
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
        state.mark_telegram_ok();
        let updates = resp.result.unwrap_or_default();
        let mut dirty = false;
        if let Some(next) = next_offset_after(&updates) {
            persist.next_offset = next;
            dirty = true;
        }

        for update in updates {
            let Some(msg) = update.message else { continue };
            // Only PRIVATE-chat, human-authored text relays: a group reply would
            // broadcast an L3 decision to every member, and other bots' turns
            // are echo/loop bait.
            if msg.chat.r#type != "private" {
                debug!(chat = msg.chat.id, kind = %msg.chat.r#type, "non-private chat — skipped");
                continue;
            }
            let Some(from) = msg.from.as_ref().filter(|u| !u.is_bot) else {
                continue;
            };
            let from_id = from.id.to_string();
            if persist.chat_ids.get(&from_id) != Some(&msg.chat.id) {
                persist.chat_ids.insert(from_id.clone(), msg.chat.id);
                dirty = true;
            }
            let text = msg.text.clone().unwrap_or_default();
            if text.trim().is_empty() {
                debug!(from = %from_id, "inbound without relayable text (media?) — skipped");
                continue;
            }

            let outcome = relay::process_inbound_for(&state, "telegram", &from_id, &text).await;
            info!(
                from = %from_id,
                contact = %outcome.contact_id,
                tier = %outcome.tier,
                allowed = outcome.decision.allowed,
                reason = %outcome.decision.reason,
                target = outcome.decision.target_alias.as_deref().unwrap_or(""),
                "telegram inbound relayed"
            );
            if let Some(event) = outcome.event.as_ref() {
                debug!(channel = %event.channel_id, "routed event built (feed hop pending)");
            }

            let reply = outcome
                .claim_ack
                .clone()
                .or_else(|| relay::reply_text_for_en(&outcome.decision));
            if let Some(reply) = reply {
                if let Err(e) = client.send_text(msg.chat.id, &reply).await {
                    warn!(to = %from_id, error = %e, "reply send failed");
                }
            }
        }
        if dirty {
            persist.save(&state_file);
        }
    }

    info!("telegram inbound loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::{TgChat, TgMessage, TgUpdate, TgUser};

    fn update(id: i64) -> TgUpdate {
        TgUpdate {
            update_id: id,
            message: Some(TgMessage {
                from: Some(TgUser {
                    id: 42,
                    is_bot: false,
                }),
                chat: TgChat {
                    id: 42,
                    r#type: "private".into(),
                },
                text: Some("hi".into()),
            }),
        }
    }

    #[test]
    fn offset_advances_past_the_highest_update() {
        assert_eq!(next_offset_after(&[]), None);
        assert_eq!(next_offset_after(&[update(7), update(3)]), Some(8));
    }

    #[test]
    fn persist_roundtrips_and_survives_missing_file() {
        let dir = std::env::temp_dir().join(format!("tg-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json").to_string_lossy().to_string();

        let fresh = TelegramPersist::load(&path);
        assert_eq!(fresh.next_offset, 0);
        assert!(fresh.chat_ids.is_empty());

        let p = TelegramPersist {
            next_offset: 8,
            chat_ids: HashMap::from([("42".to_string(), 42i64)]),
        };
        p.save(&path);

        let back = TelegramPersist::load(&path);
        assert_eq!(back.next_offset, 8);
        assert_eq!(back.chat_ids.get("42"), Some(&42));

        std::fs::remove_dir_all(&dir).ok();
    }
}
