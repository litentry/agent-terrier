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
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IlinkPersist {
    #[serde(default)]
    pub get_updates_buf: String,
    /// `from_user_id` → the user's latest `context_token` (echo on sends).
    #[serde(default)]
    pub context_tokens: HashMap<String, String>,
}

impl IlinkPersist {
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
pub async fn supervise(state: SharedWeixinGatewayState, mut shutdown: watch::Receiver<bool>) {
    let mut restart_rx = state.subscribe_ilink_restart();
    loop {
        if *shutdown.borrow() {
            return;
        }
        match state.current_ilink_token() {
            None => {
                info!(
                    "iLink loop idle — no bot token yet (connect via parent-control 微信网关 → \
                     连接, or the `--login` CLI)"
                );
                tokio::select! {
                    _ = restart_rx.changed() => continue,
                    _ = shutdown.changed() => return,
                }
            }
            Some(token) => {
                let base_url = state.current_ilink_base_url();
                let (loop_tx, loop_rx) = watch::channel(false);
                let mut task =
                    tokio::spawn(run_with_token(state.clone(), token, base_url, loop_rx));
                tokio::select! {
                    _ = restart_rx.changed() => {
                        info!("iLink identity swapped — restarting the inbound loop");
                        let _ = loop_tx.send(true);
                        let _ = (&mut task).await;
                    }
                    _ = shutdown.changed() => {
                        let _ = loop_tx.send(true);
                        let _ = (&mut task).await;
                        return;
                    }
                    _ = &mut task => {
                        // The loop exited on its own (it only does on shutdown —
                        // errors are handled inside); wait for a swap or shutdown.
                        tokio::select! {
                            _ = restart_rx.changed() => {}
                            _ = shutdown.changed() => return,
                        }
                    }
                }
            }
        }
    }
}

/// Back-compat single-shot entry (the integration tests drive this): run the
/// loop on the state's current identity; no token → return immediately.
pub async fn run(state: SharedWeixinGatewayState, shutdown: watch::Receiver<bool>) {
    let Some(token) = state.current_ilink_token() else {
        error!("ilink loop asked to run with no bot token — not started");
        return;
    };
    let base_url = state.current_ilink_base_url();
    run_with_token(state, token, base_url, shutdown).await;
}

/// Run the inbound loop on an EXPLICIT identity until `shutdown` flips.
pub async fn run_with_token(
    state: SharedWeixinGatewayState,
    token: String,
    base_url: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let cfg = &state.config;
    let client = IlinkClient::new(&base_url, Some(token), &cfg.bot_agent);
    let state_file = cfg.ilink_state_file.clone();
    let mut persist = IlinkPersist::load(&state_file);

    info!(
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
            if text.trim().is_empty() {
                debug!(from = %from, "inbound without relayable text (media?) — skipped");
                continue;
            }

            let outcome = relay::process_inbound(&state, &from, &text).await;
            info!(
                from = %from,
                contact = %outcome.contact_id,
                tier = %outcome.tier,
                allowed = outcome.decision.allowed,
                reason = %outcome.decision.reason,
                target = outcome.decision.target_alias.as_deref().unwrap_or(""),
                "ilink inbound relayed"
            );
            if let Some(event) = outcome.event.as_ref() {
                // Feed delivery is the transport-neutral follow-up (same as the
                // OA path) — the routed event is built + audited; log it here.
                debug!(channel = %event.channel_id, "routed event built (feed hop pending)");
            }

            let reply = outcome
                .claim_ack
                .clone()
                .or_else(|| relay::reply_text_for(&outcome.decision));
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
            get_updates_buf: "cursor-1".into(),
            context_tokens: HashMap::from([("wxid-a".to_string(), "ctx-a".to_string())]),
        };
        p.save(&path);

        let back = IlinkPersist::load(&path);
        assert_eq!(back.get_updates_buf, "cursor-1");
        assert_eq!(
            back.context_tokens.get("wxid-a").map(String::as_str),
            Some("ctx-a")
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
