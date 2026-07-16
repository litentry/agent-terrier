//! Telegram Bot API client (#444) — the stack-② transport twin of [`crate::ilink`].
//! Long-polling `getUpdates` (zero inbound surface: no webhook, no TLS/DNS
//! coupling, no vhost) + `sendMessage` replies. The bot token is the ONE
//! custodied credential (#384): minted once via BotFather, read from the
//! gateway secrets file, NEVER handed to a delegate.
//!
//! The API base is overridable (`AGENTKEYS_TELEGRAM_API_BASE`) so the mock e2e
//! can point the loop at a stub; production is the public Bot API host.

use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The public Bot API host (the default `AGENTKEYS_TELEGRAM_API_BASE`).
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

/// The long-poll window we ask the server to hold `getUpdates` open for.
pub const LONG_POLL_TIMEOUT_SECS: u64 = 50;

/// `Update` — one entry from `getUpdates`. Only `message` is consumed (we
/// subscribe with `allowed_updates=["message"]`); everything else is skipped.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgUpdate {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<TgMessage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgMessage {
    #[serde(default)]
    pub from: Option<TgUser>,
    pub chat: TgChat,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgUser {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgChat {
    pub id: i64,
    /// `private` | `group` | `supergroup` | `channel`. Only PRIVATE chats relay
    /// (a group reply would leak an L3 decision to every member — D13-adjacent).
    #[serde(default)]
    pub r#type: String,
}

/// The Bot API envelope: `{ok, result}` on success, `{ok:false, error_code,
/// description, parameters:{retry_after}}` on failure.
#[derive(Debug, Deserialize)]
pub struct TgResponse<T> {
    pub ok: bool,
    #[serde(default)]
    pub result: Option<T>,
    #[serde(default)]
    pub error_code: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Option<TgResponseParameters>,
}

#[derive(Debug, Deserialize)]
pub struct TgResponseParameters {
    #[serde(default)]
    pub retry_after: Option<u64>,
}

impl<T> TgResponse<T> {
    /// 401/404 = the token is bad/revoked — the stale-token analog: only a new
    /// BotFather token revives the transport, so the loop pauses LOUDLY.
    pub fn is_bad_token(&self) -> bool {
        !self.ok && matches!(self.error_code, Some(401) | Some(404))
    }

    /// 409 = another consumer is long-polling the SAME bot token (a second
    /// gateway instance, or a leftover webhook) — a deployment error to surface,
    /// not to retry into.
    pub fn is_conflict(&self) -> bool {
        !self.ok && self.error_code == Some(409)
    }
}

pub struct TelegramClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl TelegramClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        // The HTTP timeout must OUTLIVE the server-held long poll, or every
        // quiet window would surface as a transport error.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(LONG_POLL_TIMEOUT_SECS + 15))
            .build()
            .unwrap_or_default();
        TelegramClient {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    fn method_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base_url, self.token, method)
    }

    /// One long-poll turn: updates with `update_id >= offset`, held open up to
    /// [`LONG_POLL_TIMEOUT_SECS`]. `offset = last update_id + 1` acknowledges
    /// everything before it (the Bot API's cursor contract).
    pub async fn get_updates(&self, offset: i64) -> anyhow::Result<TgResponse<Vec<TgUpdate>>> {
        let resp = self
            .http
            .get(self.method_url("getUpdates"))
            .query(&[
                ("timeout", LONG_POLL_TIMEOUT_SECS.to_string()),
                ("offset", offset.to_string()),
                ("allowed_updates", r#"["message"]"#.to_string()),
            ])
            .send()
            .await
            .context("getUpdates request")?;
        resp.json::<TgResponse<Vec<TgUpdate>>>()
            .await
            .context("getUpdates decode")
    }

    /// Send one text reply into a chat. Errors are the caller's to log — a
    /// failed reply must never block the relay (the turn is already routed).
    pub async fn send_text(&self, chat_id: i64, text: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(self.method_url("sendMessage"))
            .json(&serde_json::json!({ "chat_id": chat_id, "text": text }))
            .send()
            .await
            .context("sendMessage request")?;
        let body: TgResponse<serde_json::Value> =
            resp.json().await.context("sendMessage decode")?;
        if !body.ok {
            anyhow::bail!(
                "sendMessage refused: error_code={} description={}",
                body.error_code.unwrap_or_default(),
                body.description.as_deref().unwrap_or("")
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getupdates_shape_decodes_and_flags_map() {
        let raw = r#"{"ok":true,"result":[{"update_id":7,"message":{
            "message_id":1,"from":{"id":42,"is_bot":false,"first_name":"A"},
            "chat":{"id":42,"type":"private"},"date":1,"text":"/chef hi"}}]}"#;
        let r: TgResponse<Vec<TgUpdate>> = serde_json::from_str(raw).unwrap();
        assert!(r.ok && !r.is_bad_token() && !r.is_conflict());
        let ups = r.result.unwrap();
        assert_eq!(ups[0].update_id, 7);
        let msg = ups[0].message.as_ref().unwrap();
        assert_eq!(msg.from.as_ref().unwrap().id, 42);
        assert_eq!(msg.chat.r#type, "private");
        assert_eq!(msg.text.as_deref(), Some("/chef hi"));

        let unauthorized: TgResponse<Vec<TgUpdate>> =
            serde_json::from_str(r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#)
                .unwrap();
        assert!(unauthorized.is_bad_token());
        let conflict: TgResponse<Vec<TgUpdate>> =
            serde_json::from_str(r#"{"ok":false,"error_code":409,"description":"Conflict"}"#)
                .unwrap();
        assert!(conflict.is_conflict());
    }

    #[test]
    fn method_url_embeds_token_and_trims_base() {
        let c = TelegramClient::new("https://api.telegram.org/", "123:abc");
        assert_eq!(
            c.method_url("getUpdates"),
            "https://api.telegram.org/bot123:abc/getUpdates"
        );
    }
}
