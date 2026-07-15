//! `agentkeys speech …` — the stack-② speech plane (#441, epic #439).
//!
//! Every leg rides the STANDARD cap→STS relay (the epic's consistent-auth
//! principle): mint a `SpeechUse` cap at `/v1/cap/speech` (on-chain `speech`
//! grant checked at mint; master-self rides the #195 skip), redeem it at
//! `/v1/cap/speech-sts` for short-TTL AWS creds valid ONLY for Transcribe
//! streaming + Polly synthesis. No long-lived speech secret exists anywhere on
//! the AWS stack — this module is ALSO the sandbox's consumption reference
//! (the hermes-sandbox image ships this binary).
//!
//! - `speech creds` — mint + redeem, print the scoped creds as JSON (the
//!   sandbox hook feeds them to whatever speech client it embeds).
//! - `speech probe` — prove the relay end-to-end with ONE real TTS call
//!   (Polly `SynthesizeSpeech`) and ONE real ASR call (Transcribe
//!   `StartStreamTranscription` over a short PCM buffer), using ONLY the
//!   relay-minted creds. This is the #441 acceptance check and the harness
//!   step's engine.

use anyhow::{anyhow, Context, Result};
use aws_credential_types::Credentials;
use serde_json::json;

use agentkeys_backend_client::protocol::{CapMintOp, CapMintRequest, SpeechStsResult};
use agentkeys_backend_client::{normalize_omni_0x, BackendClient};

/// Mint a `SpeechUse` cap and redeem it for scoped speech creds.
#[allow(clippy::too_many_arguments)]
pub async fn speech_sts_creds(
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
    broker_url: &str,
    ttl_seconds: u64,
    device_key_file: Option<&str>,
    delegation_file: Option<&str>,
) -> Result<SpeechStsResult> {
    let mut client = BackendClient::new(
        Some(broker_url.to_string()),
        None,
        None,
        None,
        Some(session_bearer.to_string()),
        None,
        None,
        String::new(),
    );
    // #369 DELEGATED mode (sandbox) vs direct K10 mode vs bare — the same
    // three-way the storage clients use (cred_admin::memory_canonical_get).
    let effective_dkh = match delegation_file {
        Some(f) => {
            let (ephemeral, delegation) = crate::delegation_admin::StoredDelegation::load(f)?;
            let dkh = delegation.device_key_hash.clone();
            client = client.with_delegation(ephemeral, delegation);
            dkh
        }
        None => {
            if let Some(kf) = device_key_file {
                let dk = agentkeys_core::device_crypto::DeviceKey::load_or_generate(kf, false)
                    .with_context(|| format!("load device key {kf}"))?;
                client = client.with_device_key(std::sync::Arc::new(dk));
            }
            device_key_hash.to_string()
        }
    };
    let cap = client
        .cap_mint(
            CapMintOp::SpeechUse,
            CapMintRequest {
                operator_omni: normalize_omni_0x(operator_omni),
                actor_omni: normalize_omni_0x(actor_omni),
                service: "speech".to_string(),
                device_key_hash: effective_dkh,
                ttl_seconds,
            },
            session_bearer,
        )
        .await
        .context("cap-mint speech (is the on-chain `speech` grant in place for this actor?)")?;
    client
        .speech_sts(cap, session_bearer)
        .await
        .context("redeem speech cap at /v1/cap/speech-sts")
}

/// `agentkeys speech creds` — print the relay-minted creds as JSON.
#[allow(clippy::too_many_arguments)]
pub async fn speech_creds_cmd(
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
    broker_url: &str,
    ttl_seconds: u64,
    device_key_file: Option<&str>,
    delegation_file: Option<&str>,
) -> Result<String> {
    let creds = speech_sts_creds(
        operator_omni,
        actor_omni,
        device_key_hash,
        session_bearer,
        broker_url,
        ttl_seconds,
        device_key_file,
        delegation_file,
    )
    .await?;
    Ok(serde_json::to_string_pretty(&json!({
        "access_key_id": creds.access_key_id,
        "secret_access_key": creds.secret_access_key,
        "session_token": creds.session_token,
        "expiration": creds.expiration,
        "region": creds.region,
    }))?)
}

fn sdk_config_from(creds: &SpeechStsResult) -> aws_config::SdkConfig {
    let provider = Credentials::new(
        creds.access_key_id.clone(),
        creds.secret_access_key.clone(),
        Some(creds.session_token.clone()),
        None,
        "agentkeys-speech-relay",
    );
    aws_config::SdkConfig::builder()
        .credentials_provider(
            aws_credential_types::provider::SharedCredentialsProvider::new(provider),
        )
        .region(aws_config::Region::new(creds.region.clone()))
        .behavior_version(aws_config::BehaviorVersion::latest())
        .build()
}

/// `agentkeys speech probe` — one real TTS + one real ASR call on the relay
/// creds. Fails loudly if either leg is refused (a 403 here with a valid cap
/// means the IAM role drifted; a cap-mint 403 upstream means no grant).
#[allow(clippy::too_many_arguments)]
pub async fn speech_probe_cmd(
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
    broker_url: &str,
    device_key_file: Option<&str>,
    delegation_file: Option<&str>,
) -> Result<String> {
    let creds = speech_sts_creds(
        operator_omni,
        actor_omni,
        device_key_hash,
        session_bearer,
        broker_url,
        300,
        device_key_file,
        delegation_file,
    )
    .await?;
    let sdk = sdk_config_from(&creds);

    // TTS — Polly SynthesizeSpeech, a real, billable-but-trivial call.
    let polly = aws_sdk_polly::Client::new(&sdk);
    let tts = polly
        .synthesize_speech()
        .output_format(aws_sdk_polly::types::OutputFormat::Mp3)
        .voice_id(aws_sdk_polly::types::VoiceId::Joanna)
        .text("agentkeys speech relay live")
        .send()
        .await
        .context("Polly SynthesizeSpeech refused — TTS leg dead")?;
    let tts_bytes = tts
        .audio_stream
        .collect()
        .await
        .context("collect Polly audio stream")?
        .into_bytes();
    if tts_bytes.is_empty() {
        return Err(anyhow!("Polly returned an empty audio stream"));
    }

    // ASR — Transcribe streaming over ~200ms of 16kHz mono silence. The point
    // is a REAL authenticated stream open + clean close on relay creds; a
    // transcript of silence is legitimately empty.
    let transcribe = aws_sdk_transcribestreaming::Client::new(&sdk);
    let silence = vec![0u8; 6400];
    let audio_stream =
        aws_sdk_transcribestreaming::primitives::event_stream::EventStreamSender::from(
            futures_util::stream::iter(vec![Ok(
                aws_sdk_transcribestreaming::types::AudioStream::AudioEvent(
                    aws_sdk_transcribestreaming::types::AudioEvent::builder()
                        .audio_chunk(aws_sdk_transcribestreaming::primitives::Blob::new(silence))
                        .build(),
                ),
            )]),
        );
    let mut asr = transcribe
        .start_stream_transcription()
        .language_code(aws_sdk_transcribestreaming::types::LanguageCode::EnUs)
        .media_sample_rate_hertz(16000)
        .media_encoding(aws_sdk_transcribestreaming::types::MediaEncoding::Pcm)
        .audio_stream(audio_stream)
        .send()
        .await
        .context("Transcribe StartStreamTranscription refused — ASR leg dead")?;
    // Drain the (possibly empty) transcript events until the stream closes.
    let mut asr_events = 0u32;
    while let Some(ev) = asr
        .transcript_result_stream
        .recv()
        .await
        .context("Transcribe result stream error")?
    {
        let _ = ev;
        asr_events += 1;
        if asr_events >= 3 {
            break;
        }
    }

    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "tts_bytes": tts_bytes.len(),
        "asr_stream_opened": true,
        "asr_events_seen": asr_events,
        "region": creds.region,
        "note": "both legs ran on relay-minted short-TTL creds only",
    }))?)
}
