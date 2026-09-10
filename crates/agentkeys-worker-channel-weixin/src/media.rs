//! #667 — inbound MEDIA relay: a photo or voice clip a contact sends becomes
//! an `image` / `audio-clip` event on the app's feed with the ORIGINAL bytes
//! stored beside the feed (`body_ref`), never re-encoded by the gateway — the
//! app's perception adapter (R2) sees exactly what the phone sent.
//!
//! iLink media facts (cited from the MIT plugin this transport mirrors,
//! `Tencent/openclaw-weixin` `src/cdn/{cdn-url,pic-decrypt,aes-ecb}.ts` +
//! `src/media/media-download.ts`, read 2026-09-09):
//! - download = plain `GET` of `CDNMedia.full_url` when the server returns it,
//!   else `<cdn_base>/download?encrypted_query_param=<urlencoded
//!   encrypt_query_param>` (the plugin's `ENABLE_CDN_URL_FALLBACK` path; the
//!   base comes from the account config — here `AGENTKEYS_WEIXIN_ILINK_CDN_BASE_URL`).
//! - decrypt = AES-128-ECB, PKCS7. The key is `base64(aes_key)` decoded: 16
//!   raw bytes (images) or 32 ASCII hex chars parsed as hex (voice / file /
//!   video); an image item may instead carry `aeskey` as a hex string.
//! - no key ⇒ the bytes are plain (`downloadPlainCdnBuffer`).
//!
//! The voice container is DECLARED by the message: `voice_item.encode_type`
//! (`src/api/types.ts`: 1=pcm 2=adpcm 3=feature 4=speex 5=amr 6=silk 7=mp3
//! 8=ogg-speex); the plugin's own download path assumes SILK and transcodes
//! to WAV (`media-download.ts` → `silk-transcode.ts`), so a clip that omits
//! `encode_type` is declared `audio/silk`. The platform transcript rides
//! beside the clip as the caption, so a turn never depends on decoding it.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use agentkeys_protocol::ChannelEventKind;
use anyhow::{anyhow, Context};

use crate::ilink::CdnMedia;

/// One media original ready for the feed hop.
#[derive(Debug, Clone)]
pub struct InboundMedia {
    pub kind: ChannelEventKind,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

impl InboundMedia {
    /// The transcript-preview marker for logs / the live monitor (never the
    /// bytes).
    pub fn marker(&self) -> &'static str {
        match self.kind {
            ChannelEventKind::Image => "📷 [photo]",
            ChannelEventKind::AudioClip => "🎤 [voice]",
            _ => "[media]",
        }
    }
}

/// Parse an iLink AES key: `aes_key` (base64 of 16 raw bytes OR of 32 hex
/// chars) or an image item's `aeskey` (hex).
pub fn parse_ilink_aes_key(
    aes_key_b64: Option<&str>,
    aeskey_hex: Option<&str>,
) -> Option<[u8; 16]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if let Some(h) = aeskey_hex.map(str::trim).filter(|h| !h.is_empty()) {
        if let Ok(bytes) = hex::decode(h) {
            if bytes.len() == 16 {
                return bytes.try_into().ok();
            }
        }
    }
    let b64 = aes_key_b64.map(str::trim).filter(|s| !s.is_empty())?;
    let decoded = STANDARD.decode(b64).ok()?;
    if decoded.len() == 16 {
        return decoded.try_into().ok();
    }
    if decoded.len() == 32 && decoded.iter().all(|b| b.is_ascii_hexdigit()) {
        let hex_str = std::str::from_utf8(&decoded).ok()?;
        let bytes = hex::decode(hex_str).ok()?;
        return bytes.try_into().ok();
    }
    None
}

/// AES-128-ECB decrypt + PKCS7 unpad.
pub fn decrypt_aes128_ecb(key: &[u8; 16], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        anyhow::bail!("ciphertext length {} is not a multiple of 16", data.len());
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    let pad = *out.last().unwrap_or(&0) as usize;
    if pad == 0
        || pad > 16
        || out.len() < pad
        || out[out.len() - pad..].iter().any(|&b| b as usize != pad)
    {
        anyhow::bail!("PKCS7 padding invalid (wrong key?)");
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

/// The download URL for one media descriptor.
pub fn ilink_download_url(media: &CdnMedia, cdn_base: Option<&str>) -> Option<String> {
    if let Some(u) = media.full_url.as_deref().filter(|u| !u.trim().is_empty()) {
        return Some(u.trim().to_string());
    }
    let q = media
        .encrypt_query_param
        .as_deref()
        .filter(|q| !q.trim().is_empty())?;
    let base = cdn_base.map(str::trim).filter(|b| !b.is_empty())?;
    Some(format!(
        "{}/download?encrypted_query_param={}",
        base.trim_end_matches('/'),
        urlencode(q)
    ))
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

/// Fetch (and decrypt when keyed) one iLink media original. `max_bytes` caps
/// the download (a phone photo is a few MB; anything larger is refused loud).
pub async fn fetch_ilink_media(
    http: &reqwest::Client,
    media: &CdnMedia,
    aeskey_hex: Option<&str>,
    cdn_base: Option<&str>,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let url = ilink_download_url(media, cdn_base).ok_or_else(|| {
        anyhow!(
            "media carries no full_url and no cdn base is configured \
             (AGENTKEYS_WEIXIN_ILINK_CDN_BASE_URL) — cannot download"
        )
    })?;
    let resp = http
        .get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("media download")?;
    if !resp.status().is_success() {
        anyhow::bail!("media download HTTP {}", resp.status());
    }
    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            anyhow::bail!("media is {len} bytes (max {max_bytes})");
        }
    }
    let bytes = resp.bytes().await.context("media body")?.to_vec();
    if bytes.len() > max_bytes {
        anyhow::bail!("media is {} bytes (max {max_bytes})", bytes.len());
    }
    match parse_ilink_aes_key(media.aes_key.as_deref(), aeskey_hex) {
        Some(key) => decrypt_aes128_ecb(&key, &bytes),
        None => Ok(bytes),
    }
}

/// #667 — the first media original of an iLink message, downloaded +
/// decrypted (a photo → `image`, a voice clip → `audio-clip`). Failures are
/// LOUD and yield `None` (the text / transcript still relays).
pub async fn first_ilink_media(
    state: &crate::state::WeixinGatewayState,
    msg: &crate::ilink::WeixinMessage,
) -> Option<InboundMedia> {
    let item = crate::ilink::first_media_item(msg)?;
    let dev = &state.config.device;
    let cdn_base = dev.ilink_cdn_base_url.as_deref();
    if let Some(img) = item.image_item.as_ref() {
        let media = img.media.as_ref()?;
        match fetch_ilink_media(
            &state.http,
            media,
            img.aeskey.as_deref(),
            cdn_base,
            dev.media_max_bytes,
        )
        .await
        {
            Ok(bytes) => {
                let content_type = sniff_image_content_type(&bytes).to_string();
                return Some(InboundMedia {
                    kind: ChannelEventKind::Image,
                    content_type,
                    bytes,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "#667 iLink photo download failed — relaying the text only");
                return None;
            }
        }
    }
    if let Some(voice) = item.voice_item.as_ref() {
        let media = voice.media.as_ref()?;
        match fetch_ilink_media(&state.http, media, None, cdn_base, dev.media_max_bytes).await {
            Ok(bytes) => {
                return Some(InboundMedia {
                    kind: ChannelEventKind::AudioClip,
                    content_type: ilink_voice_content_type(voice.encode_type).to_string(),
                    bytes,
                })
            }
            Err(e) => {
                tracing::warn!(error = %e, "#667 iLink voice download failed — relaying the transcript only");
                return None;
            }
        }
    }
    None
}

/// Sniff the image container from its magic bytes (the CDN returns raw
/// pixels' container; iLink does not declare one).
pub fn sniff_image_content_type(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if bytes.starts_with(b"GIF8") {
        "image/gif"
    } else if bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

/// The declared type of an iLink voice clip from its `encode_type` (the
/// plugin's `VoiceItem` enum — see the module note); absent = the plugin's
/// own SILK assumption; an unknown code is passed through as an opaque clip.
pub fn ilink_voice_content_type(encode_type: Option<u32>) -> &'static str {
    match encode_type {
        None | Some(6) => "audio/silk",
        Some(1) => "audio/L16",
        Some(2) => "audio/x-adpcm",
        Some(4) => "audio/speex",
        Some(5) => "audio/amr",
        Some(7) => "audio/mpeg",
        Some(8) => "audio/ogg",
        Some(_) => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    fn encrypt_ecb(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let pad = 16 - (plain.len() % 16);
        let mut data = plain.to_vec();
        data.extend(std::iter::repeat_n(pad as u8, pad));
        for chunk in data.chunks_exact_mut(16) {
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        }
        data
    }

    #[test]
    fn aes_keys_parse_in_both_plugin_formats_and_hex() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let raw = [7u8; 16];
        assert_eq!(
            parse_ilink_aes_key(Some(&STANDARD.encode(raw)), None),
            Some(raw)
        );
        let hex32 = hex::encode(raw);
        assert_eq!(
            parse_ilink_aes_key(Some(&STANDARD.encode(hex32.as_bytes())), None),
            Some(raw)
        );
        assert_eq!(parse_ilink_aes_key(None, Some(&hex32)), Some(raw));
        assert_eq!(parse_ilink_aes_key(Some("!!"), None), None);
        assert_eq!(parse_ilink_aes_key(None, None), None);
    }

    #[test]
    fn ecb_roundtrip_and_bad_key_is_loud() {
        let key = [3u8; 16];
        let plain = b"\xFF\xD8\xFF a jpeg-ish payload of arbitrary length";
        let ct = encrypt_ecb(&key, plain);
        assert_eq!(decrypt_aes128_ecb(&key, &ct).unwrap(), plain);
        assert!(decrypt_aes128_ecb(&[4u8; 16], &ct).is_err());
        assert!(decrypt_aes128_ecb(&key, &ct[..15]).is_err());
    }

    #[test]
    fn download_url_prefers_full_url_then_the_cdn_fallback() {
        let m = CdnMedia {
            encrypt_query_param: Some("a b/c".into()),
            aes_key: None,
            encrypt_type: None,
            full_url: Some("https://cdn.example/x?y=1".into()),
        };
        assert_eq!(
            ilink_download_url(&m, None).as_deref(),
            Some("https://cdn.example/x?y=1")
        );
        let m2 = CdnMedia {
            full_url: None,
            ..m.clone()
        };
        assert_eq!(ilink_download_url(&m2, None), None);
        assert_eq!(
            ilink_download_url(&m2, Some("https://cdn.example/")).as_deref(),
            Some("https://cdn.example/download?encrypted_query_param=a%20b%2Fc")
        );
    }

    #[test]
    fn image_sniffing() {
        assert_eq!(
            sniff_image_content_type(&[0xFF, 0xD8, 0xFF, 0xE0]),
            "image/jpeg"
        );
        assert_eq!(sniff_image_content_type(b"\x89PNG\r\n"), "image/png");
        assert_eq!(
            sniff_image_content_type(b"nope"),
            "application/octet-stream"
        );
    }

    #[test]
    fn voice_type_follows_the_declared_encode_type() {
        assert_eq!(ilink_voice_content_type(Some(6)), "audio/silk");
        assert_eq!(ilink_voice_content_type(None), "audio/silk");
        assert_eq!(ilink_voice_content_type(Some(5)), "audio/amr");
        assert_eq!(ilink_voice_content_type(Some(4)), "audio/speex");
        assert_eq!(ilink_voice_content_type(Some(7)), "audio/mpeg");
        assert_eq!(
            ilink_voice_content_type(Some(3)),
            "application/octet-stream"
        );
    }
}
