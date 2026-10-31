//! Optional speech adapter. The public binary does not discover a provider.
use crate::{
    error::{GateError, GateResult},
    voices::VoicesResponse,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

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
    /// Optional adapter voice identifier.
    #[serde(default)]
    pub voice: Option<String>,
    /// Relative speaking rate; zero selects the adapter default.
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

pub struct SynthesisInput<'a> {
    pub text: &'a str,
    pub voice: Option<&'a str>,
    pub speech_rate: i32,
    pub format: &'a str,
    pub sample_rate: u32,
    pub caller_id: &'a str,
}

#[async_trait::async_trait]
pub trait SpeechBackend: Send + Sync {
    async fn transcribe(
        &self,
        audio: Vec<u8>,
        format: &str,
        caller_id: &str,
    ) -> GateResult<AsrOutcome>;
    async fn synthesize(&self, input: SynthesisInput<'_>) -> GateResult<TtsOutcome>;
    async fn voices(&self) -> GateResult<VoicesResponse>;
}

pub struct SpeechClient {
    backend: Option<Arc<dyn SpeechBackend>>,
}

impl SpeechClient {
    pub fn new(backend: Option<Arc<dyn SpeechBackend>>) -> Self {
        Self { backend }
    }

    fn backend(&self) -> GateResult<&dyn SpeechBackend> {
        self.backend
            .as_deref()
            .ok_or_else(|| GateError::NotConfigured("No speech adapter configured".into()))
    }

    pub async fn transcribe(
        &self,
        audio: Vec<u8>,
        format: &str,
        caller_id: &str,
    ) -> GateResult<AsrOutcome> {
        self.backend()?.transcribe(audio, format, caller_id).await
    }

    pub async fn synthesize(
        &self,
        text: &str,
        voice: Option<&str>,
        speech_rate: i32,
        format: &str,
        sample_rate: u32,
        caller_id: &str,
    ) -> GateResult<TtsOutcome> {
        self.backend()?
            .synthesize(SynthesisInput {
                text,
                voice,
                speech_rate,
                format,
                sample_rate,
                caller_id,
            })
            .await
    }

    pub async fn voices(&self) -> GateResult<VoicesResponse> {
        self.backend()?.voices().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SyntheticSpeech(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl SpeechBackend for SyntheticSpeech {
        async fn transcribe(
            &self,
            audio: Vec<u8>,
            format: &str,
            caller_id: &str,
        ) -> GateResult<AsrOutcome> {
            assert_eq!(format, "wav");
            assert_eq!(caller_id, "caller");
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(AsrOutcome {
                text: "synthetic transcript".into(),
                audio_bytes: audio.len() as u64,
                duration: Duration::ZERO,
            })
        }
        async fn synthesize(&self, input: SynthesisInput<'_>) -> GateResult<TtsOutcome> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(TtsOutcome {
                audio: input.text.as_bytes().to_vec(),
                voice: input.voice.unwrap_or("synthetic").into(),
                speech_rate: input.speech_rate,
                format: input.format.into(),
                duration: Duration::ZERO,
            })
        }
        async fn voices(&self) -> GateResult<VoicesResponse> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(VoicesResponse {
                voices: vec![crate::voices::Voice {
                    id: "synthetic".into(),
                    name: "Test voice".into(),
                    scenario: "test".into(),
                }],
            })
        }
    }

    #[tokio::test]
    async fn explicit_adapter_is_used_and_missing_adapter_does_not_call_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let configured = SpeechClient::new(Some(Arc::new(SyntheticSpeech(calls.clone()))));
        assert_eq!(
            configured
                .transcribe(vec![1, 2], "wav", "caller")
                .await
                .unwrap()
                .audio_bytes,
            2
        );
        assert_eq!(
            configured
                .synthesize("test", None, 0, "wav", 24000, "caller")
                .await
                .unwrap()
                .audio,
            b"test"
        );
        assert_eq!(configured.voices().await.unwrap().voices[0].id, "synthetic");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let missing = SpeechClient::new(None);
        assert_eq!(
            missing
                .transcribe(vec![1], "wav", "caller")
                .await
                .unwrap_err()
                .status(),
            503
        );
        assert_eq!(
            missing
                .synthesize("test", None, 0, "wav", 24000, "caller")
                .await
                .unwrap_err()
                .status(),
            503
        );
        assert_eq!(missing.voices().await.unwrap_err().status(), 503);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn wire_shapes_default_the_optional_fields() {
        let transcription: TranscribeRequest =
            serde_json::from_str(r#"{"audio_b64":"AAAA"}"#).unwrap();
        assert!(transcription.format.is_none());
        let speech: SpeakRequest = serde_json::from_str(r#"{"input":"hi"}"#).unwrap();
        assert!(
            speech.voice.is_none() && speech.speech_rate.is_none() && speech.sample_rate.is_none()
        );
    }
}
