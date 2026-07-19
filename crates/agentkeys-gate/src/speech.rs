//! #519 — the gate speech relay: ASR + TTS behind the SAME key-custody
//! posture as the LLM turn. The Doubao speech app tokens are gate-held (#386 —
//! Volcengine's minted STS is rejected by the voice endpoints, so this is the
//! VE twin of the AWS #441 cap→STS speech plane); the sandbox delegate drives
//! the ASR→LLM→TTS pipeline but presents only its `gk_` relay key here and
//! never sees a speech credential.
//!
//! Wire shapes are JSON→JSON with base64 audio, deliberately channel-ready:
//! the consumer is the in-sandbox chat loop turning `audio-clip` channel
//! events around, not an OpenAI SDK — `/v1/chat/completions` stays the only
//! OpenAI-compatible surface.
//!
//! Clients are ported from `agentkeys-volcano-probe` (the proven live probes):
//! ASR = bigmodel submit → poll (status in the `X-Api-Status-Code` header);
//! TTS = V3 unidirectional SSE whose `data:` events carry base64 audio chunks.

use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

use agentkeys_inference_creds::{
    AsrCreds, TtsCreds, DEFAULT_ASR_QUERY_URL, DEFAULT_ASR_SUBMIT_URL, DEFAULT_TTS_SSE_URL,
};

use crate::error::{GateError, GateResult};

/// `POST /v1/audio/transcriptions` body.
#[derive(Debug, Clone, Deserialize)]
pub struct TranscribeRequest {
    /// Base64 of the raw audio container bytes (wav/mp3/…).
    pub audio_b64: String,
    /// Container format hint; defaults to `wav` (what the device mic emits).
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscribeResponse {
    pub text: String,
    /// Decoded input size the relay attributed (mirrors the audit row).
    pub audio_bytes: u64,
    pub duration_ms: u64,
}

/// `POST /v1/audio/speech` body.
#[derive(Debug, Clone, Deserialize)]
pub struct SpeakRequest {
    pub input: String,
    /// Doubao speaker id; defaults to the gate's `TTS_VOICE_TYPE`.
    #[serde(default)]
    pub voice: Option<String>,
    /// Doubao 语速 in [-50, 100] (clamped); 0 = the vendor default.
    #[serde(default)]
    pub speech_rate: Option<i32>,
    /// Output container; defaults to `mp3` (smallest for channel transport).
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub sample_rate: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpeakResponse {
    pub audio_b64: String,
    pub format: String,
    pub audio_bytes: u64,
    pub voice: String,
    pub speech_rate: i32,
    pub duration_ms: u64,
}

#[derive(Debug)]
pub struct AsrOutcome {
    pub text: String,
    pub audio_bytes: u64,
    pub duration: Duration,
}

#[derive(Debug)]
pub struct TtsOutcome {
    pub audio: Vec<u8>,
    pub voice: String,
    pub speech_rate: i32,
    pub format: String,
    pub duration: Duration,
}

/// The relay-side speech client. `None` creds = that leg is unconfigured on
/// this gate — endpoints refuse with 503 `NotConfigured` (a legit, LOUD skip,
/// never a silent fallback).
pub struct SpeechClient {
    http: reqwest::Client,
    pub asr: Option<AsrCreds>,
    pub tts: Option<TtsCreds>,
}

fn header_str(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

impl SpeechClient {
    pub fn new(asr: Option<AsrCreds>, tts: Option<TtsCreds>) -> Self {
        Self {
            http: reqwest::Client::new(),
            asr,
            tts,
        }
    }

    /// Bigmodel ASR: submit inline-base64 audio, poll `/query` every 400 ms
    /// (≤48 s) until `X-Api-Status-Code` reports done. `uid` is the caller's
    /// relay key id — Doubao-side attribution matches the audit row's.
    pub async fn transcribe(
        &self,
        audio: Vec<u8>,
        format: &str,
        uid: &str,
    ) -> GateResult<AsrOutcome> {
        let creds = self.asr.as_ref().ok_or_else(|| {
            GateError::NotConfigured(
                "ASR relay not configured on this gate (no `asr` inference family — \
                 rotate-inference-cred.sh asr)"
                    .into(),
            )
        })?;
        let audio_bytes = audio.len() as u64;
        let request_id = uuid::Uuid::new_v4().to_string();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&audio);
        let start = Instant::now();

        let submit_body = serde_json::json!({
            "user": { "uid": uid },
            "audio": { "format": format, "data": b64 },
            "request": { "model_name": "bigmodel", "enable_itn": true, "enable_punc": true },
        });
        let sresp = self
            .http
            .post(DEFAULT_ASR_SUBMIT_URL)
            .header("X-Api-App-Key", &creds.app_id)
            .header("X-Api-Access-Key", &creds.access_token)
            .header("X-Api-Resource-Id", &creds.resource_id)
            .header("X-Api-Request-Id", &request_id)
            .json(&submit_body)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("asr submit failed: {e}")))?;
        let submit_code = header_str(&sresp, "X-Api-Status-Code");
        if submit_code != "20000000" {
            return Err(GateError::Upstream(format!(
                "asr submit rejected: status {submit_code} {}",
                header_str(&sresp, "X-Api-Message")
            )));
        }

        for _ in 0..120 {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let qresp = self
                .http
                .post(DEFAULT_ASR_QUERY_URL)
                .header("X-Api-App-Key", &creds.app_id)
                .header("X-Api-Access-Key", &creds.access_token)
                .header("X-Api-Resource-Id", &creds.resource_id)
                .header("X-Api-Request-Id", &request_id)
                .json(&serde_json::json!({}))
                .send()
                .await
                .map_err(|e| GateError::Upstream(format!("asr query failed: {e}")))?;
            let code = header_str(&qresp, "X-Api-Status-Code");
            let msg = header_str(&qresp, "X-Api-Message");
            let v: serde_json::Value = qresp.json().await.unwrap_or(serde_json::Value::Null);
            match code.as_str() {
                "20000000" => {
                    let text = v["result"]["text"].as_str().unwrap_or_default().to_string();
                    return Ok(AsrOutcome {
                        text,
                        audio_bytes,
                        duration: start.elapsed(),
                    });
                }
                "20000001" | "20000002" => continue, // processing / queued
                other => {
                    return Err(GateError::Upstream(format!(
                        "asr query failed: status {other} {msg}"
                    )))
                }
            }
        }
        Err(GateError::Upstream(format!(
            "asr timed out after {} ms waiting for the transcript",
            start.elapsed().as_millis()
        )))
    }

    /// Bigmodel TTS V3 (unidirectional SSE): collect the base64 audio chunks
    /// into one clip. Voice defaults to the gate family's `TTS_VOICE_TYPE`;
    /// `speech_rate` is clamped to the documented [-50, 100].
    pub async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        speech_rate: i32,
        format: &str,
        sample_rate: u32,
        uid: &str,
    ) -> GateResult<TtsOutcome> {
        let creds = self.tts.as_ref().ok_or_else(|| {
            GateError::NotConfigured(
                "TTS relay not configured on this gate (no `tts` inference family — \
                 rotate-inference-cred.sh tts)"
                    .into(),
            )
        })?;
        let speaker = voice.unwrap_or(creds.voice_type.as_str()).to_string();
        let speech_rate = speech_rate.clamp(-50, 100);
        let reqid = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "user": { "uid": uid },
            "req_params": {
                "text": text,
                "speaker": speaker,
                "audio_params": {
                    "format": format,
                    "sample_rate": sample_rate,
                    "speech_rate": speech_rate,
                },
            }
        });
        let start = Instant::now();
        let resp = self
            .http
            .post(DEFAULT_TTS_SSE_URL)
            .header("X-Api-App-Id", &creds.app_id)
            .header("X-Api-Access-Key", &creds.access_token)
            .header("X-Api-Resource-Id", &creds.resource_id)
            .header("X-Api-Request-Id", &reqid)
            .json(&body)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("tts request failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(GateError::Upstream(format!("tts returned {status}: {txt}")));
        }
        let mut stream = resp.bytes_stream();
        let mut audio: Vec<u8> = Vec::new();
        let mut buf: Vec<u8> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| GateError::Upstream(format!("tts stream error: {e}")))?;
            buf.extend_from_slice(&chunk);
            while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                let line_bytes: Vec<u8> = buf.drain(..=nl).collect();
                let line = String::from_utf8_lossy(&line_bytes);
                let line = line.trim();
                let Some(payload) = line.strip_prefix("data:") else {
                    continue;
                };
                let payload = payload.trim();
                if payload.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
                    continue;
                };
                if let Some(code) = v["code"].as_i64() {
                    if code != 0 && code != 20_000_000 {
                        errors.push(format!("code={code} message={}", v["message"]));
                    }
                }
                if let Some(b64) = v["data"].as_str() {
                    if !b64.is_empty() {
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                            audio.extend_from_slice(&bytes);
                        }
                    }
                }
            }
        }
        if audio.is_empty() {
            return Err(GateError::Upstream(format!(
                "tts produced no audio — check the speaker (voice id) + resource-id grant. \
                 server events: {}",
                if errors.is_empty() {
                    "(no error events)".to_string()
                } else {
                    errors.join("; ")
                }
            )));
        }
        Ok(TtsOutcome {
            audio,
            voice: speaker,
            speech_rate,
            format: format.to_string(),
            duration: start.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> SpeechClient {
        SpeechClient::new(None, None)
    }

    #[tokio::test]
    async fn unconfigured_legs_refuse_loudly_with_503() {
        let c = client();
        let asr = c.transcribe(vec![0u8; 4], "wav", "k1").await.unwrap_err();
        assert!(matches!(asr, GateError::NotConfigured(_)), "{asr}");
        assert_eq!(asr.status(), 503);
        let tts = c.synthesize("你好", None, 0, "mp3", 24000, "k1").await;
        let tts = tts.unwrap_err();
        assert!(matches!(tts, GateError::NotConfigured(_)), "{tts}");
        assert!(tts.to_string().contains("rotate-inference-cred.sh tts"));
    }

    #[test]
    fn wire_shapes_default_the_optional_fields() {
        let t: TranscribeRequest = serde_json::from_str(r#"{"audio_b64":"AAAA"}"#).unwrap();
        assert!(t.format.is_none());
        let s: SpeakRequest = serde_json::from_str(r#"{"input":"hi"}"#).unwrap();
        assert!(s.voice.is_none() && s.speech_rate.is_none() && s.sample_rate.is_none());
    }
}
