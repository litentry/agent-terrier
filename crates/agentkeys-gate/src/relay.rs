//! The per-turn relay flow: authenticate → deterministic budget check →
//! forward upstream (vendor key attached relay-side) → meter `usage` →
//! `GateTurn` audit row.
//!
//! Body mutations are exactly two: the optional model override, and
//! `stream_options.include_usage = true` on streamed turns (without it the
//! upstream reports no usage on streams — #332 build note). Everything else
//! passes through byte-faithfully.
//!
//! Upstream status triage ("no silent fallback", and the #308-review rule):
//! - 2xx → forward; meter + audit.
//! - 4xx → forward the upstream error verbatim (the caller needs it) + log.
//! - 5xx / transport → operator-log the FULL body, return a safe 502 envelope
//!   (upstream internals are never echoed to callers).

use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::Value;
use tokio_stream::wrappers::ReceiverStream;

use agentkeys_core::audit::{GateTurnBody, SpeechAsrBody, SpeechTtsBody};
use base64::Engine;

use crate::audit::Auditor;
use crate::config::{GateConfig, RelayKey};
use crate::error::{GateError, GateResult};
use crate::meter::Meter;
use crate::openai::{extract_usage, SseUsageScanner, UsageCounters};
use crate::speech::{
    SpeakRequest, SpeakResponse, SpeechClient, TranscribeRequest, TranscribeResponse,
};
use crate::upstream::UpstreamClient;

pub struct Relay {
    pub config: GateConfig,
    pub meter: Arc<Meter>,
    /// #427 — the LIVE key registry (boot keys + broker-minted per-delegate
    /// keys), seeded from `config.keys` and mutated only via the admin surface.
    pub keys: Arc<crate::keys::KeyStore>,
    upstream: UpstreamClient,
    /// #519 — gate-held Doubao speech legs (each independently optional).
    speech: SpeechClient,
    auditor: Option<Arc<Auditor>>,
}

/// What the HTTP layer turns into a response.
pub enum TurnOutput {
    /// Complete body (non-streamed turn or forwarded 4xx).
    Full {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
    /// Streamed body, forwarded chunk-by-chunk while the tee scans for usage.
    Stream {
        status: u16,
        content_type: String,
        rx: ReceiverStream<Result<bytes::Bytes, std::io::Error>>,
    },
}

impl Relay {
    pub fn new(config: GateConfig) -> Self {
        let upstream = UpstreamClient::new(&config.upstream);
        let auditor = config
            .audit_url
            .clone()
            .map(|url| Arc::new(Auditor::new(url, config.aws_region.clone())));
        let keys = Arc::new(crate::keys::KeyStore::from_config(&config));
        let speech = SpeechClient::new(config.speech_asr.clone(), config.speech_tts.clone());
        Self {
            config,
            meter: Arc::new(Meter::default()),
            keys,
            upstream,
            speech,
            auditor,
        }
    }

    /// #519 — ASR through the relay. Attribution mirrors GateTurn (owning
    /// user's omni on the envelope; device/api-key in the body). Token budgets
    /// don't apply (audio has no token denomination) — usage is audited, and a
    /// speech-denominated budget is a #519 follow-up.
    pub async fn handle_transcribe(
        &self,
        caller: &RelayKey,
        req: TranscribeRequest,
    ) -> GateResult<TranscribeResponse> {
        let format = req.format.as_deref().unwrap_or("wav").to_string();
        let audio = base64::engine::general_purpose::STANDARD
            .decode(req.audio_b64.as_bytes())
            .map_err(|e| GateError::BadRequest(format!("audio_b64 is not valid base64: {e}")))?;
        let audio_bytes_in = audio.len() as u64;
        let started = std::time::Instant::now();
        match self.speech.transcribe(audio, &format, &caller.key_id).await {
            Ok(outcome) => {
                let body = SpeechAsrBody {
                    device_id: caller.device_id.clone(),
                    api_key_id: caller.key_id.clone(),
                    audio_bytes_in,
                    transcript_chars: outcome.text.chars().count() as u64,
                    outcome: "ok".into(),
                    duration_ms: outcome.duration.as_millis() as u64,
                };
                let duration_ms = body.duration_ms;
                self.audit_speech_asr(caller, body).await?;
                Ok(TranscribeResponse {
                    text: outcome.text,
                    audio_bytes: audio_bytes_in,
                    duration_ms,
                })
            }
            Err(e @ GateError::NotConfigured(_)) => Err(e),
            Err(e) => {
                let body = SpeechAsrBody {
                    device_id: caller.device_id.clone(),
                    api_key_id: caller.key_id.clone(),
                    audio_bytes_in,
                    transcript_chars: 0,
                    outcome: "upstream_error".into(),
                    duration_ms: started.elapsed().as_millis() as u64,
                };
                if let Some(auditor) = &self.auditor {
                    if let Err(a) = auditor.emit_speech_asr(&caller.user_omni, body).await {
                        tracing::error!(user = %caller.user_omni, error = %a, "SpeechAsr audit append failed");
                    }
                }
                Err(e)
            }
        }
    }

    /// #519 — TTS through the relay; same posture as `handle_transcribe`.
    pub async fn handle_speak(
        &self,
        caller: &RelayKey,
        req: SpeakRequest,
    ) -> GateResult<SpeakResponse> {
        let format = req.format.as_deref().unwrap_or("mp3").to_string();
        let sample_rate = req.sample_rate.unwrap_or(24000);
        let speech_rate = req.speech_rate.unwrap_or(0);
        let chars_in = req.input.chars().count() as u64;
        let started = std::time::Instant::now();
        match self
            .speech
            .synthesize(
                &req.input,
                req.voice.as_deref(),
                speech_rate,
                &format,
                sample_rate,
                &caller.key_id,
            )
            .await
        {
            Ok(outcome) => {
                let body = SpeechTtsBody {
                    device_id: caller.device_id.clone(),
                    api_key_id: caller.key_id.clone(),
                    chars_in,
                    audio_bytes_out: outcome.audio.len() as u64,
                    voice: outcome.voice.clone(),
                    speech_rate: outcome.speech_rate,
                    outcome: "ok".into(),
                    duration_ms: outcome.duration.as_millis() as u64,
                };
                let duration_ms = body.duration_ms;
                self.audit_speech_tts(caller, body).await?;
                Ok(SpeakResponse {
                    audio_b64: base64::engine::general_purpose::STANDARD.encode(&outcome.audio),
                    format: outcome.format,
                    audio_bytes: outcome.audio.len() as u64,
                    voice: outcome.voice,
                    speech_rate: outcome.speech_rate,
                    duration_ms,
                })
            }
            Err(e @ GateError::NotConfigured(_)) => Err(e),
            Err(e) => {
                let body = SpeechTtsBody {
                    device_id: caller.device_id.clone(),
                    api_key_id: caller.key_id.clone(),
                    chars_in,
                    audio_bytes_out: 0,
                    voice: req.voice.clone().unwrap_or_default(),
                    speech_rate,
                    outcome: "upstream_error".into(),
                    duration_ms: started.elapsed().as_millis() as u64,
                };
                if let Some(auditor) = &self.auditor {
                    if let Err(a) = auditor.emit_speech_tts(&caller.user_omni, body).await {
                        tracing::error!(user = %caller.user_omni, error = %a, "SpeechTts audit append failed");
                    }
                }
                Err(e)
            }
        }
    }

    /// Ok-path speech audit: mirrors the chat turn's `require_audit` posture —
    /// the relay work is done, but under require_audit an unrecordable call
    /// fails (tamper-evident audit is the product).
    async fn audit_speech_asr(&self, caller: &RelayKey, body: SpeechAsrBody) -> GateResult<()> {
        if let Some(auditor) = &self.auditor {
            if let Err(e) = auditor.emit_speech_asr(&caller.user_omni, body).await {
                tracing::error!(user = %caller.user_omni, error = %e, "SpeechAsr audit append failed");
                if self.config.require_audit {
                    return Err(GateError::Audit(
                        "transcription completed but could not be recorded (require_audit)".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn audit_speech_tts(&self, caller: &RelayKey, body: SpeechTtsBody) -> GateResult<()> {
        if let Some(auditor) = &self.auditor {
            if let Err(e) = auditor.emit_speech_tts(&caller.user_omni, body).await {
                tracing::error!(user = %caller.user_omni, error = %e, "SpeechTts audit append failed");
                if self.config.require_audit {
                    return Err(GateError::Audit(
                        "synthesis completed but could not be recorded (require_audit)".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn turn_body(
        caller: &RelayKey,
        model: &str,
        streamed: bool,
        outcome: &str,
        usage: &UsageCounters,
    ) -> GateTurnBody {
        GateTurnBody {
            device_id: caller.device_id.clone(),
            api_key_id: caller.key_id.clone(),
            model: model.to_string(),
            streamed,
            outcome: outcome.to_string(),
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            total_tokens: usage.total_tokens,
            cached_tokens: usage.cached_tokens,
            reasoning_tokens: usage.reasoning_tokens,
        }
    }

    /// Best-effort audit for paths that cannot retro-fail the turn (denials,
    /// upstream errors, stream finalizers). Failures are loud in the log.
    async fn audit_best_effort(&self, user_omni: &str, body: GateTurnBody) {
        if let Some(auditor) = &self.auditor {
            if let Err(e) = auditor.emit_turn(user_omni, body).await {
                tracing::error!(user = %user_omni, error = %e, "GateTurn audit append failed");
            }
        }
    }

    pub async fn handle_chat(&self, caller: &RelayKey, raw: &[u8]) -> GateResult<TurnOutput> {
        let mut body: Value = serde_json::from_slice(raw)
            .map_err(|e| GateError::BadRequest(format!("invalid chat completion body: {e}")))?;
        if !body.is_object() {
            return Err(GateError::BadRequest(
                "chat completion body must be a JSON object".into(),
            ));
        }

        if let Some(model) = &self.config.upstream.model_override {
            body["model"] = Value::String(model.clone());
        }
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let streamed = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

        // Deterministic per-user budget gate — before any upstream tokens burn.
        if let Some(budget) = self.config.budget_for(&caller.user_omni) {
            let used = self.meter.used_total(&caller.user_omni);
            if used >= budget {
                let turn = Self::turn_body(
                    caller,
                    &model,
                    streamed,
                    "denied:budget_exceeded",
                    &UsageCounters::default(),
                );
                self.audit_best_effort(&caller.user_omni, turn).await;
                return Err(GateError::Budget(format!(
                    "user token budget exhausted ({used}/{budget})"
                )));
            }
        }
        // #427 per-DELEGATE ceiling under the user budget (epic #425 decision
        // 6: budgets keyed by delegate, rolling up to the user). Read LIVE so
        // an admin re-provision applies without re-auth. Same deterministic
        // 429, same audit row.
        if let Some(key_budget) = self.keys.budget_for_key(&caller.key_id) {
            let key_used = self
                .meter
                .used_total_for_key(&caller.user_omni, &caller.key_id);
            if key_used >= key_budget {
                let turn = Self::turn_body(
                    caller,
                    &model,
                    streamed,
                    "denied:budget_exceeded",
                    &UsageCounters::default(),
                );
                self.audit_best_effort(&caller.user_omni, turn).await;
                return Err(GateError::Budget(format!(
                    "delegate token budget exhausted ({key_used}/{key_budget} for key {})",
                    caller.key_id
                )));
            }
        }

        if streamed {
            // Without include_usage the upstream's final chunk carries no
            // usage and the turn would be unmeterable (#332). Merge into an
            // existing stream_options object; replace a malformed one.
            match body.get_mut("stream_options") {
                Some(Value::Object(opts)) => {
                    opts.insert("include_usage".into(), Value::Bool(true));
                }
                _ => {
                    body["stream_options"] = serde_json::json!({ "include_usage": true });
                }
            }
        }

        let resp = match self.upstream.chat(&body).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(key = %caller.key_id, error = %e, "upstream unreachable");
                let turn = Self::turn_body(
                    caller,
                    &model,
                    streamed,
                    "upstream_error",
                    &UsageCounters::default(),
                );
                self.audit_best_effort(&caller.user_omni, turn).await;
                return Err(e);
            }
        };

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        if !status.is_success() {
            let code = status.as_u16();
            let upstream_body = resp.bytes().await.unwrap_or_default();
            let turn = Self::turn_body(
                caller,
                &model,
                streamed,
                "upstream_error",
                &UsageCounters::default(),
            );
            self.audit_best_effort(&caller.user_omni, turn).await;
            if (400..500).contains(&code) {
                tracing::warn!(key = %caller.key_id, status = code, "upstream 4xx forwarded");
                return Ok(TurnOutput::Full {
                    status: code,
                    content_type,
                    body: upstream_body.to_vec(),
                });
            }
            tracing::error!(
                key = %caller.key_id,
                status = code,
                body = %String::from_utf8_lossy(&upstream_body),
                "upstream 5xx — full body operator-logged, safe envelope returned"
            );
            return Err(GateError::Upstream(format!(
                "upstream returned HTTP {code}"
            )));
        }

        if streamed {
            return Ok(self.stream_turn(caller, model, content_type, resp).await);
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| GateError::Upstream(format!("reading upstream body: {e}")))?;
        let parsed: Value = serde_json::from_slice(&bytes)
            .map_err(|e| GateError::Upstream(format!("unparseable upstream response: {e}")))?;
        let usage = extract_usage(&parsed).unwrap_or_else(|| {
            tracing::warn!(key = %caller.key_id, "upstream 2xx carried no usage object");
            UsageCounters::default()
        });

        // Tokens are burned regardless of audit outcome — record first.
        self.meter.record(
            &caller.user_omni,
            &caller.device_id,
            &caller.key_id,
            &caller.label,
            &usage,
        );
        let turn = Self::turn_body(caller, &model, false, "ok", &usage);
        if let Some(auditor) = &self.auditor {
            if let Err(e) = auditor.emit_turn(&caller.user_omni, turn).await {
                tracing::error!(user = %caller.user_omni, error = %e, "GateTurn audit append failed");
                if self.config.require_audit {
                    return Err(GateError::Audit(
                        "turn completed but could not be recorded (require_audit)".into(),
                    ));
                }
            }
        }

        Ok(TurnOutput::Full {
            status: 200,
            content_type,
            body: bytes.to_vec(),
        })
    }

    /// Tee the SSE stream: bytes go to the caller untouched while the scanner
    /// watches for the final usage chunk; metering + audit run when the
    /// upstream stream ends (a streamed turn cannot be retro-failed, so audit
    /// here is best-effort even under require_audit — documented in #384).
    async fn stream_turn(
        &self,
        caller: &RelayKey,
        model: String,
        content_type: String,
        resp: reqwest::Response,
    ) -> TurnOutput {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
        let meter = Arc::clone(&self.meter);
        let auditor = self.auditor.clone();
        let caller = caller.clone();

        tokio::spawn(async move {
            let mut scanner = SseUsageScanner::default();
            let mut upstream = resp.bytes_stream();
            let mut caller_gone = false;
            while let Some(chunk) = upstream.next().await {
                match chunk {
                    Ok(bytes) => {
                        scanner.feed(&bytes);
                        if !caller_gone && tx.send(Ok(bytes)).await.is_err() {
                            // Caller hung up — keep draining so the usage the
                            // upstream still bills is captured and metered.
                            caller_gone = true;
                        }
                    }
                    Err(e) => {
                        if !caller_gone {
                            let _ = tx
                                .send(Err(std::io::Error::other(format!("upstream stream: {e}"))))
                                .await;
                        }
                        break;
                    }
                }
            }
            let usage = scanner.into_usage().unwrap_or_else(|| {
                tracing::warn!(key = %caller.key_id, "stream ended without a usage chunk");
                UsageCounters::default()
            });
            meter.record(
                &caller.user_omni,
                &caller.device_id,
                &caller.key_id,
                &caller.label,
                &usage,
            );
            if let Some(auditor) = auditor {
                let turn = Relay::turn_body(&caller, &model, true, "ok", &usage);
                if let Err(e) = auditor.emit_turn(&caller.user_omni, turn).await {
                    tracing::error!(user = %caller.user_omni, error = %e, "GateTurn audit append failed");
                }
            }
        });

        TurnOutput::Stream {
            status: 200,
            content_type,
            rx: ReceiverStream::new(rx),
        }
    }

    pub async fn models(&self) -> GateResult<(u16, String, Vec<u8>)> {
        let resp = self.upstream.models().await?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let body = resp
            .bytes()
            .await
            .map_err(|e| GateError::Upstream(format!("reading upstream body: {e}")))?;
        if status >= 500 {
            tracing::error!(
                status,
                body = %String::from_utf8_lossy(&body),
                "upstream 5xx on /models — safe envelope returned"
            );
            return Err(GateError::Upstream(format!(
                "upstream returned HTTP {status}"
            )));
        }
        Ok((status, content_type, body.to_vec()))
    }
}
