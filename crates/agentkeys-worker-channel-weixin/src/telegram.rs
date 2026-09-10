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
    /// #667 — a photo message: the available sizes (largest relayed).
    #[serde(default)]
    pub photo: Option<Vec<TgPhotoSize>>,
    /// #667 — a voice message.
    #[serde(default)]
    pub voice: Option<TgVoice>,
    /// The caption of a media message (relayed as the correlated text).
    #[serde(default)]
    pub caption: Option<String>,
}

/// Bot API `PhotoSize` (https://core.telegram.org/bots/api#photosize).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgPhotoSize {
    pub file_id: String,
    #[serde(default)]
    pub width: u64,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub file_size: Option<u64>,
}

/// Bot API `Voice` (https://core.telegram.org/bots/api#voice).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgVoice {
    pub file_id: String,
    #[serde(default)]
    pub duration: Option<u64>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
}

/// Bot API `File` (https://core.telegram.org/bots/api#getfile): `file_path`
/// is fetched from `https://api.telegram.org/file/bot<token>/<file_path>`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TgFile {
    pub file_id: String,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
}

/// The largest photo size (by pixel area).
pub fn largest_photo(sizes: &[TgPhotoSize]) -> Option<&TgPhotoSize> {
    sizes
        .iter()
        .max_by_key(|p| p.width.saturating_mul(p.height))
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

    /// `getFile` — resolve a `file_id` to a downloadable `file_path`
    /// (https://core.telegram.org/bots/api#getfile).
    pub async fn get_file(&self, file_id: &str) -> anyhow::Result<TgFile> {
        let resp = self
            .http
            .get(self.method_url("getFile"))
            .query(&[("file_id", file_id)])
            .send()
            .await
            .context("getFile request")?;
        let body: TgResponse<TgFile> = resp.json().await.context("getFile decode")?;
        if !body.ok {
            anyhow::bail!(
                "getFile refused: error_code={} description={}",
                body.error_code.unwrap_or_default(),
                body.description.as_deref().unwrap_or("")
            );
        }
        body.result
            .ok_or_else(|| anyhow::anyhow!("getFile returned no result"))
    }

    /// Download a file by its `file_path` (`<base>/file/bot<token>/<path>`,
    /// per the getFile reference). Capped at `max_bytes`.
    pub async fn download_file(
        &self,
        file_path: &str,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let url = format!(
            "{}/file/bot{}/{}",
            self.base_url,
            self.token,
            file_path.trim_start_matches('/')
        );
        let resp = self.http.get(&url).send().await.context("file download")?;
        if !resp.status().is_success() {
            anyhow::bail!("file download HTTP {}", resp.status());
        }
        if let Some(len) = resp.content_length() {
            if len as usize > max_bytes {
                anyhow::bail!("file is {len} bytes (max {max_bytes})");
            }
        }
        let bytes = resp.bytes().await.context("file body")?.to_vec();
        if bytes.len() > max_bytes {
            anyhow::bail!("file is {} bytes (max {max_bytes})", bytes.len());
        }
        Ok(bytes)
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

/// #667 — the first media original of a Telegram message: the largest photo
/// size (`image/jpeg` — the Bot API serves photos as JPEG) or the voice clip
/// (its declared `mime_type`, else `audio/ogg`). Failures are LOUD and yield
/// `None` (the caption still relays).
pub async fn first_telegram_media(
    client: &TelegramClient,
    msg: &TgMessage,
    max_bytes: usize,
) -> Option<crate::media::InboundMedia> {
    use agentkeys_protocol::ChannelEventKind;
    let (file_id, kind, content_type) =
        if let Some(p) = msg.photo.as_deref().and_then(largest_photo) {
            (
                p.file_id.clone(),
                ChannelEventKind::Image,
                "image/jpeg".to_string(),
            )
        } else if let Some(v) = msg.voice.as_ref() {
            (
                v.file_id.clone(),
                ChannelEventKind::AudioClip,
                v.mime_type
                    .clone()
                    .unwrap_or_else(|| "audio/ogg".to_string()),
            )
        } else {
            return None;
        };
    let file = match client.get_file(&file_id).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "#667 telegram getFile failed — relaying the caption only");
            return None;
        }
    };
    let Some(path) = file.file_path.filter(|p| !p.is_empty()) else {
        tracing::warn!("#667 telegram getFile returned no file_path");
        return None;
    };
    match client.download_file(&path, max_bytes).await {
        Ok(bytes) => Some(crate::media::InboundMedia {
            kind,
            content_type,
            bytes,
        }),
        Err(e) => {
            tracing::warn!(error = %e, "#667 telegram file download failed — relaying the caption only");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn photo_message_decodes_and_largest_size_wins() {
        let raw = r#"{"ok":true,"result":[{"update_id":8,"message":{
            "message_id":2,"from":{"id":42,"is_bot":false},
            "chat":{"id":42,"type":"private"},"date":1,"caption":"/chef 冰箱",
            "photo":[{"file_id":"small","file_unique_id":"u1","width":90,"height":67,"file_size":1200},
                     {"file_id":"big","file_unique_id":"u2","width":800,"height":600,"file_size":64000}]}}]}"#;
        let r: TgResponse<Vec<TgUpdate>> = serde_json::from_str(raw).unwrap();
        let msg = r.result.unwrap().remove(0).message.unwrap();
        assert_eq!(msg.caption.as_deref(), Some("/chef 冰箱"));
        assert!(msg.text.is_none());
        assert_eq!(
            largest_photo(msg.photo.as_deref().unwrap())
                .unwrap()
                .file_id,
            "big"
        );
        let voice: TgMessage = serde_json::from_str(
            r#"{"chat":{"id":1,"type":"private"},"voice":{"file_id":"v1","duration":3,"mime_type":"audio/ogg"}}"#,
        )
        .unwrap();
        assert_eq!(voice.voice.unwrap().mime_type.as_deref(), Some("audio/ogg"));
    }

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
