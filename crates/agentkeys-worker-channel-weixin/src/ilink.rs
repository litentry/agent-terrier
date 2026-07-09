//! Tencent iLink bot transport — the sanctioned personal-WeChat bot API used by
//! the MIT-licensed [`Tencent/openclaw-weixin`] channel plugin. This module is a
//! Rust re-implementation of that plugin's wire client (shapes mirrored from
//! `src/api/{api,types}.ts` + `src/auth/login-qr.ts`, plugin v2.4.6) so the
//! gateway PEP speaks the transport DIRECTLY — no OpenClaw agent runtime sits in
//! the message path (a relay agent loop would blur the PEP boundary, spec §7).
//!
//! Protocol facts (verified against the plugin source, 2026-07-09):
//! - All calls are `POST {base_url}/ilink/bot/<verb>` with JSON bodies except the
//!   QR-status long-poll (`GET`). Bytes fields ride as base64 strings.
//! - Auth = `Authorization: Bearer <bot_token>` + `AuthorizationType:
//!   ilink_bot_token`; the token is minted by the QR login ceremony
//!   ([`crate::ilink_login`]) and custodied like the OA app-secret (#384).
//! - `getupdates` is a ~35 s server-held long-poll with an opaque resumable
//!   cursor (`get_updates_buf`); a client-side timeout is NORMAL control flow
//!   (retry with the same cursor).
//! - `context_token` arrives per inbound message and MUST be echoed on sends to
//!   that user — it is the reply authorization (the OA reply-window analog).
//! - errcode/ret `-14` = stale bot token → pause (re-login ceremony needed).
//!
//! [`Tencent/openclaw-weixin`]: https://github.com/Tencent/openclaw-weixin

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The fixed bootstrap host for QR login; `get_qrcode_status` may redirect to a
/// per-IDC host, and the confirmed login returns the bot's own `baseurl`.
pub const ILINK_BOOTSTRAP_BASE_URL: &str = "https://ilinkai.weixin.qq.com";
/// `iLink-App-Id` header — a fixed constant in the upstream plugin.
pub const ILINK_APP_ID: &str = "bot";
/// `bot_type` for `get_bot_qrcode` / `get_qrcode_status` (this channel build).
pub const ILINK_BOT_TYPE: &str = "3";
/// Server errcode meaning the bot token is stale — re-run the login ceremony.
pub const STALE_TOKEN_ERRCODE: i64 = -14;

pub const MSG_TYPE_USER: u32 = 1;
pub const MSG_TYPE_BOT: u32 = 2;
pub const MSG_STATE_FINISH: u32 = 2;
pub const ITEM_TYPE_TEXT: u32 = 1;
pub const ITEM_TYPE_VOICE: u32 = 3;

/// Default server-held long-poll window for `getupdates` (the server may
/// suggest a different one via `longpolling_timeout_ms`).
pub const DEFAULT_LONG_POLL_TIMEOUT_MS: u64 = 35_000;
/// Extra client-side margin on top of the long-poll window before aborting.
const LONG_POLL_CLIENT_MARGIN_MS: u64 = 5_000;
/// Timeout for regular API requests (sendmessage, notify*).
const API_TIMEOUT_MS: u64 = 15_000;

// ── wire types (unknown fields tolerated on parse; absent skipped on send) ───

#[derive(Debug, Clone, Serialize)]
pub struct BaseInfo {
    pub channel_version: String,
    /// UA-style self-identification; observability-only upstream.
    pub bot_agent: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TextItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Voice inbound — the platform attaches a server-side transcript in `text`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VoiceItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub item_type: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_item: Option<TextItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice_item: Option<VoiceItem>,
}

/// proto: WeixinMessage. Only the fields the gateway consumes/sends — serde
/// ignores the rest (media items ride CDN references we don't relay yet).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WeixinMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_type: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_state: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_list: Option<Vec<MessageItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_token: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GetUpdatesResp {
    #[serde(default)]
    pub ret: Option<i64>,
    #[serde(default)]
    pub errcode: Option<i64>,
    #[serde(default)]
    pub errmsg: Option<String>,
    #[serde(default)]
    pub msgs: Option<Vec<WeixinMessage>>,
    /// The resumable cursor — cache and echo on the next request.
    #[serde(default)]
    pub get_updates_buf: Option<String>,
    /// Server-suggested window (ms) for the next long-poll.
    #[serde(default)]
    pub longpolling_timeout_ms: Option<u64>,
}

impl GetUpdatesResp {
    /// True when the server signalled an error (ret/errcode non-zero).
    pub fn is_api_error(&self) -> bool {
        self.ret.is_some_and(|r| r != 0) || self.errcode.is_some_and(|e| e != 0)
    }

    /// True when the error is the stale-token code (`-14`) — the bot token is
    /// dead and only a fresh `--login` ceremony revives the transport.
    pub fn is_stale_token(&self) -> bool {
        self.ret == Some(STALE_TOKEN_ERRCODE) || self.errcode == Some(STALE_TOKEN_ERRCODE)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SendMessageResp {
    #[serde(default)]
    pub ret: Option<i64>,
    #[serde(default)]
    pub errmsg: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QrCodeResp {
    pub qrcode: String,
    /// The URL to render as a terminal QR (scan with the phone's WeChat).
    pub qrcode_img_content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QrStatusResp {
    /// wait | scaned | confirmed | expired | scaned_but_redirect |
    /// need_verifycode | verify_code_blocked | binded_redirect
    pub status: String,
    #[serde(default)]
    pub bot_token: Option<String>,
    #[serde(default)]
    pub ilink_bot_id: Option<String>,
    /// The bot's own API base URL — use it for all post-login calls.
    #[serde(default)]
    pub baseurl: Option<String>,
    /// The scanning human's ilink user id (informational).
    #[serde(default)]
    pub ilink_user_id: Option<String>,
    /// New polling host when status == scaned_but_redirect.
    #[serde(default)]
    pub redirect_host: Option<String>,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// `iLink-App-ClientVersion`: uint32 `0x00MMNNPP` (major<<16 | minor<<8 | patch).
pub fn client_version_u32(version: &str) -> u32 {
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    ((major & 0xff) << 16) | ((minor & 0xff) << 8) | (patch & 0xff)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// `X-WECHAT-UIN`: an opaque per-request value — a uint32 rendered as a decimal
/// string, then base64 (mirrors the plugin; not used for auth).
fn random_wechat_uin() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let v = (now_nanos() as u32) ^ (std::process::id().rotate_left(16));
    STANDARD.encode(v.to_string())
}

/// A unique outbound client id (the send-side message id we mint).
pub fn new_client_id() -> String {
    format!("agentkeys-{:x}", now_nanos())
}

/// Extract the human text from an inbound message: the first TEXT item, else a
/// voice transcript (the platform transcribes server-side), else empty.
pub fn message_body_text(msg: &WeixinMessage) -> String {
    let Some(items) = msg.item_list.as_ref() else {
        return String::new();
    };
    for item in items {
        if item.item_type == Some(ITEM_TYPE_TEXT) {
            if let Some(t) = item.text_item.as_ref().and_then(|t| t.text.clone()) {
                return t;
            }
        }
        if item.item_type == Some(ITEM_TYPE_VOICE) {
            if let Some(t) = item.voice_item.as_ref().and_then(|v| v.text.clone()) {
                return t;
            }
        }
    }
    String::new()
}

/// Build the outbound text `WeixinMessage` (send-side shape, mirrors send.ts:
/// `from_user_id` empty, BOT type, FINISH state, one TEXT item, context echo).
pub fn build_text_send(to: &str, text: &str, context_token: Option<&str>) -> WeixinMessage {
    WeixinMessage {
        from_user_id: Some(String::new()),
        to_user_id: Some(to.to_string()),
        client_id: Some(new_client_id()),
        message_type: Some(MSG_TYPE_BOT),
        message_state: Some(MSG_STATE_FINISH),
        item_list: Some(vec![MessageItem {
            item_type: Some(ITEM_TYPE_TEXT),
            text_item: Some(TextItem {
                text: Some(text.to_string()),
            }),
            voice_item: None,
        }]),
        context_token: context_token.map(|s| s.to_string()),
        ..Default::default()
    }
}

// ── client ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct IlinkClient {
    pub base_url: String,
    token: Option<String>,
    bot_agent: String,
    http: reqwest::Client,
}

impl IlinkClient {
    pub fn new(base_url: &str, token: Option<String>, bot_agent: &str) -> Self {
        IlinkClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            bot_agent: bot_agent.to_string(),
            http: reqwest::Client::new(),
        }
    }

    fn base_info(&self) -> BaseInfo {
        BaseInfo {
            channel_version: env!("CARGO_PKG_VERSION").to_string(),
            bot_agent: self.bot_agent.clone(),
        }
    }

    fn common_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("iLink-App-Id", ILINK_APP_ID.to_string()),
            (
                "iLink-App-ClientVersion",
                client_version_u32(env!("CARGO_PKG_VERSION")).to_string(),
            ),
        ]
    }

    async fn post_json(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
        timeout: Duration,
        label: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{}/{}", self.base_url, endpoint);
        let mut req = self
            .http
            .post(&url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .header("AuthorizationType", "ilink_bot_token")
            .header("X-WECHAT-UIN", random_wechat_uin());
        for (k, v) in self.common_headers() {
            req = req.header(k, v);
        }
        if let Some(t) = self.token.as_deref().filter(|t| !t.trim().is_empty()) {
            req = req.header("Authorization", format!("Bearer {}", t.trim()));
        }
        let resp = req
            .json(body)
            .send()
            .await
            .with_context(|| format!("{label}: POST {url}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("{label} {status}: {text}");
        }
        Ok(text)
    }

    /// Long-poll for new messages. A client-side timeout is NORMAL (returns an
    /// empty ok response so the caller just re-polls with the same cursor).
    pub async fn get_updates(
        &self,
        get_updates_buf: &str,
        long_poll_ms: u64,
    ) -> anyhow::Result<GetUpdatesResp> {
        let timeout = Duration::from_millis(long_poll_ms + LONG_POLL_CLIENT_MARGIN_MS);
        let body = serde_json::json!({
            "get_updates_buf": get_updates_buf,
            "base_info": self.base_info(),
        });
        match self
            .post_json("ilink/bot/getupdates", &body, timeout, "getUpdates")
            .await
        {
            Ok(text) => {
                let resp: GetUpdatesResp =
                    serde_json::from_str(&text).context("getUpdates: parsing response")?;
                Ok(resp)
            }
            Err(e) => {
                // reqwest timeout = quiet long-poll window; retry with same buf.
                if e.downcast_ref::<reqwest::Error>()
                    .is_some_and(|re| re.is_timeout())
                {
                    return Ok(GetUpdatesResp {
                        ret: Some(0),
                        get_updates_buf: Some(get_updates_buf.to_string()),
                        ..Default::default()
                    });
                }
                Err(e)
            }
        }
    }

    /// Send one text message to a user; `context_token` MUST be the one from
    /// that user's latest inbound (the reply authorization).
    pub async fn send_text(
        &self,
        to: &str,
        text: &str,
        context_token: Option<&str>,
    ) -> anyhow::Result<()> {
        let msg = build_text_send(to, text, context_token);
        let body = serde_json::json!({ "msg": msg, "base_info": self.base_info() });
        let text = self
            .post_json(
                "ilink/bot/sendmessage",
                &body,
                Duration::from_millis(API_TIMEOUT_MS),
                "sendMessage",
            )
            .await?;
        let resp: SendMessageResp =
            serde_json::from_str(&text).context("sendMessage: parsing response")?;
        if resp.ret.is_some_and(|r| r != 0) {
            anyhow::bail!(
                "sendMessage ret={} errmsg={}",
                resp.ret.unwrap_or_default(),
                resp.errmsg.as_deref().unwrap_or("(none)")
            );
        }
        Ok(())
    }

    /// Lifecycle notify — best-effort (callers log + continue on error).
    pub async fn notify(&self, which: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({ "base_info": self.base_info() });
        self.post_json(
            &format!("ilink/bot/msg/notify{which}"),
            &body,
            Duration::from_millis(API_TIMEOUT_MS),
            &format!("notify{which}"),
        )
        .await?;
        Ok(())
    }

    /// QR login step 1: mint a QR code. `local_tokens` lets the server detect a
    /// bot already bound to these credentials (`binded_redirect`).
    pub async fn get_bot_qrcode(&self, local_tokens: &[String]) -> anyhow::Result<QrCodeResp> {
        let body = serde_json::json!({ "local_token_list": local_tokens });
        let text = self
            .post_json(
                &format!("ilink/bot/get_bot_qrcode?bot_type={ILINK_BOT_TYPE}"),
                &body,
                Duration::from_millis(API_TIMEOUT_MS),
                "fetchQRCode",
            )
            .await?;
        serde_json::from_str(&text).context("fetchQRCode: parsing response")
    }

    /// QR login step 2: long-poll the scan status (GET). A timeout or transient
    /// network error maps to `wait` so the ceremony just keeps polling.
    pub async fn get_qrcode_status(&self, qrcode: &str, verify_code: Option<&str>) -> QrStatusResp {
        let mut endpoint = format!(
            "{}/ilink/bot/get_qrcode_status?qrcode={}",
            self.base_url,
            urlencode(qrcode)
        );
        if let Some(vc) = verify_code {
            endpoint.push_str(&format!("&verify_code={}", urlencode(vc)));
        }
        let mut req = self
            .http
            .get(&endpoint)
            .timeout(Duration::from_millis(DEFAULT_LONG_POLL_TIMEOUT_MS));
        for (k, v) in self.common_headers() {
            req = req.header(k, v);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().await.unwrap_or_default();
                serde_json::from_str(&text).unwrap_or(QrStatusResp {
                    status: "wait".to_string(),
                    bot_token: None,
                    ilink_bot_id: None,
                    baseurl: None,
                    ilink_user_id: None,
                    redirect_host: None,
                })
            }
            _ => QrStatusResp {
                status: "wait".to_string(),
                bot_token: None,
                ilink_bot_id: None,
                baseurl: None,
                ilink_user_id: None,
                redirect_host: None,
            },
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_version_encodes_mm_nn_pp() {
        assert_eq!(client_version_u32("1.0.11"), 0x0001_000B);
        assert_eq!(client_version_u32("2.4.6"), 0x0002_0406);
        assert_eq!(client_version_u32("0.1.0"), 0x0000_0100);
        assert_eq!(client_version_u32("garbage"), 0);
    }

    #[test]
    fn wechat_uin_is_base64_of_a_decimal_u32() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let uin = random_wechat_uin();
        let decoded = STANDARD.decode(&uin).expect("valid base64");
        let s = String::from_utf8(decoded).expect("utf8");
        s.parse::<u32>().expect("decimal u32");
    }

    #[test]
    fn body_text_prefers_text_then_voice_transcript() {
        let msg: WeixinMessage = serde_json::from_str(
            r#"{"from_user_id":"wxid-1","message_type":1,
                "item_list":[{"type":1,"text_item":{"text":"两块饼干"}}],
                "context_token":"ctx-1"}"#,
        )
        .unwrap();
        assert_eq!(message_body_text(&msg), "两块饼干");

        let voice: WeixinMessage = serde_json::from_str(
            r#"{"from_user_id":"wxid-1","message_type":1,
                "item_list":[{"type":3,"voice_item":{"text":"游泳三十分钟","playtime":2100}}]}"#,
        )
        .unwrap();
        assert_eq!(message_body_text(&voice), "游泳三十分钟");

        let empty = WeixinMessage::default();
        assert_eq!(message_body_text(&empty), "");
    }

    #[test]
    fn text_send_shape_matches_plugin_wire() {
        let msg = build_text_send("wxid-kid", "✅ 已转达", Some("ctx-9"));
        let v = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["from_user_id"], "");
        assert_eq!(v["to_user_id"], "wxid-kid");
        assert_eq!(v["message_type"], MSG_TYPE_BOT);
        assert_eq!(v["message_state"], MSG_STATE_FINISH);
        assert_eq!(v["item_list"][0]["type"], ITEM_TYPE_TEXT);
        assert_eq!(v["item_list"][0]["text_item"]["text"], "✅ 已转达");
        assert_eq!(v["context_token"], "ctx-9");
        assert!(v["client_id"].as_str().unwrap().starts_with("agentkeys-"));
        // Absent fields are OMITTED, not null (the plugin's JSON shape).
        assert!(v.get("session_id").is_none());
        assert!(v.get("create_time_ms").is_none());
    }

    #[test]
    fn stale_token_and_api_error_classification() {
        let stale: GetUpdatesResp = serde_json::from_str(r#"{"ret":0,"errcode":-14}"#).unwrap();
        assert!(stale.is_api_error() && stale.is_stale_token());
        let stale2: GetUpdatesResp = serde_json::from_str(r#"{"ret":-14}"#).unwrap();
        assert!(stale2.is_stale_token());
        let plain_err: GetUpdatesResp =
            serde_json::from_str(r#"{"ret":1,"errmsg":"boom"}"#).unwrap();
        assert!(plain_err.is_api_error() && !plain_err.is_stale_token());
        let ok: GetUpdatesResp =
            serde_json::from_str(r#"{"ret":0,"msgs":[],"get_updates_buf":"b1"}"#).unwrap();
        assert!(!ok.is_api_error());
    }

    #[test]
    fn get_updates_resp_parses_realistic_payload() {
        // A realistic getupdates payload (shape per the plugin's types.ts).
        let resp: GetUpdatesResp = serde_json::from_str(
            r#"{"ret":0,
                "msgs":[{"seq":7,"message_id":100123,"from_user_id":"wxid-owner",
                         "to_user_id":"wxid-bot","session_id":"s-1","message_type":1,
                         "message_state":2,"create_time_ms":1789000000000,
                         "item_list":[{"type":1,"text_item":{"text":"/chef 晚饭吃什么"}}],
                         "context_token":"ctx-abc","run_id":"r-1"}],
                "get_updates_buf":"b64cursor==","longpolling_timeout_ms":30000}"#,
        )
        .unwrap();
        assert_eq!(resp.longpolling_timeout_ms, Some(30_000));
        assert_eq!(resp.get_updates_buf.as_deref(), Some("b64cursor=="));
        let m = &resp.msgs.as_ref().unwrap()[0];
        assert_eq!(m.message_type, Some(MSG_TYPE_USER));
        assert_eq!(m.from_user_id.as_deref(), Some("wxid-owner"));
        assert_eq!(m.context_token.as_deref(), Some("ctx-abc"));
        assert_eq!(message_body_text(m), "/chef 晚饭吃什么");
    }

    #[test]
    fn urlencode_escapes_non_unreserved() {
        assert_eq!(urlencode("abc-_.~123"), "abc-_.~123");
        assert_eq!(urlencode("a b+c"), "a%20b%2Bc");
    }
}
