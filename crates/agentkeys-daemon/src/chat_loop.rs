//! #430 (epic #425 S4) — the DELEGATE-side chat loop, run by the
//! agentkeys-daemon INSTANCE INSIDE the hermes-sandbox (the image ships this
//! daemon under supervisord). The operator chat rides the delegate's
//! OPERATOR-OWNED duplex feed (`opchat-<label>`, D8): the operator publishes
//! `direction: in` events; this loop consumes them, runs each turn through the
//! local bridge (`POST /v1/chat`, persona-framed by #390), and publishes the
//! reply as `direction: out` with `correlation` = the inbound `event_id`.
//!
//! Identity: the delegate's K10 (injected at spawn as
//! `AGENTKEYS_DEVICE_KEY_HEX`, #427) proves possession to the broker's
//! `/v1/agent/resolve` → a fresh `J1_agent` every boot (nothing at rest), and
//! signs the #76 cap-mint PoP. Authority: the on-chain
//! `channel-pub/sub:opchat-<label>` grants from the spawn template — this
//! loop can only ever reach its OWN chat feed (a cross-channel mint is
//! refused at all four §17.5 layers).
//!
//! Boot posture: the FIRST poll fast-forwards to the current cursor without
//! replying (a sandbox restart must not replay-answer history); only events
//! that arrive after boot get replies. Every failure is loud + backed off,
//! never a crash — chat degrades, the sandbox (and its jobs) keep running.

use std::time::Duration;

use agentkeys_backend_client::protocol::{CapMintOp, CapMintRequest};
use agentkeys_backend_client::BackendClient;
use serde::Deserialize;

/// Everything the loop needs, from the sandbox env (injected by the broker's
/// spawn finalize, #427/#430). `None` = not a chat-configured sandbox — the
/// daemon runs exactly as before.
pub struct ChatLoopConfig {
    pub broker_url: String,
    pub channel_worker_url: String,
    pub chat_channel_id: String,
    pub actor_omni: String,
    pub operator_omni: String,
    pub device_key_hex: String,
    pub bridge_url: String,
    pub bridge_token: Option<String>,
    /// #519 — the gate speech-relay base (`AGENTKEYS_GATE_SPEECH_URL`, injected
    /// by the gate-provisioned spawn path together with the gk_ relay key).
    /// `None` = voice turns are refused with a LOUD text reply — never routed
    /// to a base that lacks the speech endpoints (direct-ark boots).
    pub speech_url: Option<String>,
    /// The gk_ relay key (`ARK_API_KEY` in a gate-provisioned sandbox) — the
    /// ONLY credential the voice pipeline holds; speech app tokens stay on the
    /// gate (#386).
    pub speech_bearer: Option<String>,
}

impl ChatLoopConfig {
    /// Env-gated: all of the chat vars present ⇒ `Some`. A PARTIAL set is a
    /// loud warn (a mis-wired spawn should not silently mean "no chat").
    pub fn from_env() -> Option<Self> {
        let need = [
            "AGENTKEYS_BROKER_URL",
            "AGENTKEYS_CHANNEL_WORKER_URL",
            "AGENTKEYS_CHAT_CHANNEL_ID",
            "AGENTKEYS_ACTOR_OMNI",
            "AGENTKEYS_OPERATOR_OMNI",
            "AGENTKEYS_DEVICE_KEY_HEX",
        ];
        let vals: Vec<Option<String>> = need
            .iter()
            .map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
            .collect();
        let present = vals.iter().filter(|v| v.is_some()).count();
        if present == 0 {
            return None;
        }
        if present < need.len() {
            let missing: Vec<&str> = need
                .iter()
                .zip(&vals)
                .filter(|(_, v)| v.is_none())
                .map(|(k, _)| *k)
                .collect();
            tracing::warn!(
                ?missing,
                "#430 chat loop: PARTIAL chat env — the spawn finalize should inject all of \
                 them together; chat loop NOT started"
            );
            return None;
        }
        let mut it = vals.into_iter().map(|v| v.unwrap());
        Some(Self {
            broker_url: it.next().unwrap(),
            channel_worker_url: it.next().unwrap(),
            chat_channel_id: it.next().unwrap(),
            actor_omni: it.next().unwrap(),
            operator_omni: it.next().unwrap(),
            device_key_hex: it.next().unwrap(),
            bridge_url: std::env::var("AGENTKEYS_CHAT_BRIDGE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8090".into()),
            bridge_token: std::env::var("AGENTKEYS_BRIDGE_TOKEN")
                .ok()
                .filter(|t| !t.is_empty()),
            speech_url: std::env::var("AGENTKEYS_GATE_SPEECH_URL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            speech_bearer: std::env::var("ARK_API_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty()),
        })
    }
}

/// Spawn the loop as a background task when the sandbox env configures it.
pub fn spawn_if_configured() {
    let Some(cfg) = ChatLoopConfig::from_env() else {
        return;
    };
    tracing::info!(
        channel = %cfg.chat_channel_id,
        actor = %cfg.actor_omni,
        "#430 chat loop: starting (operator-owned duplex feed)"
    );
    tokio::spawn(async move { run(cfg).await });
}

#[derive(Debug, Deserialize)]
struct ResolveResponse {
    session_jwt: String,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    events: Vec<agentkeys_backend_client::protocol::ChannelEvent>,
    cursor: String,
}

async fn run(cfg: ChatLoopConfig) {
    // Materialize the injected K10 into the daemon's standard key file so the
    // shared DeviceKey/BackendClient machinery (incl. the #76 cap PoP) applies
    // unchanged. 0600, sandbox-local.
    let key_file = std::env::var("AGENTKEYS_DEVICE_KEY_FILE")
        .unwrap_or_else(|_| "~/.agentkeys/agent-device.key".to_string());
    if let Err(e) = agentkeys_core::device_crypto::write_key_0600(
        &shellexpand_home(&key_file),
        &cfg.device_key_hex,
    ) {
        tracing::error!(error = %e, "#430 chat loop: cannot materialize the device key — chat disabled");
        return;
    }
    let device_key = match agentkeys_core::device_crypto::DeviceKey::load_or_generate(
        &key_file, false,
    ) {
        Ok(k) => std::sync::Arc::new(k),
        Err(e) => {
            tracing::error!(error = %e, "#430 chat loop: device key load failed — chat disabled");
            return;
        }
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .expect("reqwest client");

    let mut cursor = String::new();
    let mut fast_forwarded = false;
    let mut session: Option<String> = None;
    let mut backoff = Duration::from_secs(2);

    loop {
        // 1. A valid J1_agent (fresh per boot / re-resolved on expiry).
        if session.is_none() {
            match resolve_session(&http, &cfg, &device_key).await {
                Ok(jwt) => {
                    session = Some(jwt);
                    backoff = Duration::from_secs(2);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "#430 chat loop: resolve failed — retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                    continue;
                }
            }
        }
        let bearer = session.clone().unwrap();
        let client = BackendClient::new(
            Some(cfg.broker_url.clone()),
            None,
            None,
            None,
            Some(bearer.clone()),
            None,
            None,
            std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
        )
        .with_device_key(device_key.clone());

        // 2. Subscribe cap + one long-poll round.
        let sub_cap = match client
            .cap_mint(
                CapMintOp::ChannelSubscribe,
                CapMintRequest {
                    operator_omni: cfg.operator_omni.clone(),
                    actor_omni: cfg.actor_omni.clone(),
                    service: format!("channel-sub:{}", cfg.chat_channel_id),
                    device_key_hash: device_key.device_key_hash().unwrap_or_default(),
                    ttl_seconds: 300,
                },
                &bearer,
            )
            .await
        {
            Ok(c) => c,
            Err(e) => {
                let msg = e.to_string();
                tracing::warn!(error = %msg, "#430 chat loop: channel-sub mint failed");
                if msg.contains("401") || msg.contains("expired") {
                    session = None; // re-resolve
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
        };
        // @backend-fixture: channel_poll_body — compiled from the protocol type
        // family (cap + after + wait_seconds), never a drifting hand-rolled shape.
        let poll_body = serde_json::json!({
            "cap": sub_cap,
            "after": cursor,
            "wait_seconds": if fast_forwarded { 25 } else { 0 },
        });
        let poll: PollResponse = match http
            .post(format!(
                "{}/v1/channel/poll",
                cfg.channel_worker_url.trim_end_matches('/')
            ))
            .json(&poll_body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "#430 chat loop: poll parse failed");
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            },
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "#430 chat loop: poll refused");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "#430 chat loop: poll transport failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
        };
        backoff = Duration::from_secs(2);
        if !poll.cursor.is_empty() {
            cursor = poll.cursor.clone();
        }
        if !fast_forwarded {
            // Boot fast-forward: adopt the current cursor WITHOUT replying —
            // a restart must never replay-answer the transcript.
            fast_forwarded = true;
            if !poll.events.is_empty() {
                tracing::info!(
                    skipped = poll.events.len(),
                    "#430 chat loop: fast-forwarded past existing history at boot"
                );
            }
            continue;
        }

        // 3. Reply to inbound operator turns.
        let publish_ctx = PublishCtx {
            http: &http,
            cfg: &cfg,
            client: &client,
            bearer: &bearer,
            device_key: device_key.as_ref(),
        };
        for event in &poll.events {
            if !matches!(
                event.direction,
                agentkeys_backend_client::protocol::ChannelDirection::In
            ) {
                continue; // our own replies (direction: out) come back on the feed
            }
            // #519 — voice turn: a device published an `audio-clip`. Pipeline
            // runs HERE (agent-side, in the sandbox) but every credentialed
            // leg goes through the gate: ASR → bridge chat → TTS. The reply is
            // published twice, correlated: a `text` event (the transcript-
            // visible reply) and an `audio-clip` event (the spoken reply).
            if matches!(
                event.kind,
                agentkeys_backend_client::protocol::ChannelEventKind::AudioClip
            ) {
                let Some(audio_b64) = event.body.as_deref() else {
                    tracing::warn!(
                        event = %event.event_id,
                        "#519 chat loop: audio-clip with body_ref only — by-reference \
                         audio is a follow-up; turn skipped"
                    );
                    continue;
                };
                match voice_turn(&http, &cfg, audio_b64, event.audio.as_ref()).await {
                    Ok(turn) => {
                        if let Err(e) = publish_event(
                            &publish_ctx,
                            "text",
                            base64_of(turn.reply_text.as_bytes()),
                            &event.event_id,
                        )
                        .await
                        {
                            tracing::warn!(error = %e, "#519 chat loop: voice text-reply publish failed");
                        }
                        if let Err(e) = publish_event(
                            &publish_ctx,
                            "audio-clip",
                            turn.reply_audio_b64,
                            &event.event_id,
                        )
                        .await
                        {
                            tracing::warn!(error = %e, "#519 chat loop: voice audio-reply publish failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "#519 chat loop: voice turn failed");
                        let _ = publish_event(
                            &publish_ctx,
                            "text",
                            base64_of(format!("(voice error: {e})").as_bytes()),
                            &event.event_id,
                        )
                        .await;
                    }
                }
                continue;
            }
            // #525 — a device asked for the background-task list (kind=command,
            // body "jobs"). The device holds no bridge credential, so the list
            // rides the channel: answer from the bridge GET /v1/jobs as a `doc`
            // event (correlated). Other commands are ignored (logged).
            if matches!(
                event.kind,
                agentkeys_backend_client::protocol::ChannelEventKind::Command
            ) {
                let cmd = event
                    .body
                    .as_deref()
                    .and_then(|b64| {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        STANDARD.decode(b64).ok()
                    })
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                if cmd.trim() == "jobs" {
                    let doc = bridge_jobs(&http, &cfg)
                        .await
                        .unwrap_or_else(|e| format!("(jobs error: {e})"));
                    if let Err(e) = publish_event(
                        &publish_ctx,
                        "doc",
                        base64_of(doc.as_bytes()),
                        &event.event_id,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "#525 chat loop: jobs doc publish failed");
                    }
                } else {
                    tracing::info!(cmd = %cmd, "#525 chat loop: unknown command — ignored");
                }
                continue;
            }
            // #528 (Phase 2) — a device published an `image` (a photo/frame).
            // ARK is OpenAI-compatible, so vision rides the EXISTING gate
            // /v1/chat/completions with an `image_url` content part — no new
            // gate surface. Reply is published as a correlated `text` event.
            if matches!(
                event.kind,
                agentkeys_backend_client::protocol::ChannelEventKind::Image
            ) {
                let Some(image_b64) = event.body.as_deref() else {
                    tracing::warn!(event = %event.event_id, "#528 chat loop: image with body_ref only — by-reference is a follow-up; skipped");
                    continue;
                };
                let reply = vision_turn(&http, &cfg, image_b64)
                    .await
                    .unwrap_or_else(|e| format!("(vision error: {e})"));
                if let Err(e) = publish_event(
                    &publish_ctx,
                    "text",
                    base64_of(reply.as_bytes()),
                    &event.event_id,
                )
                .await
                {
                    tracing::warn!(error = %e, "#528 chat loop: vision reply publish failed");
                }
                continue;
            }
            let text = event
                .body
                .as_deref()
                .and_then(|b64| {
                    use base64::{engine::general_purpose::STANDARD, Engine};
                    STANDARD.decode(b64).ok()
                })
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            if text.trim().is_empty() {
                continue;
            }
            let reply = match bridge_chat(&http, &cfg, &text).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "#430 chat loop: bridge /v1/chat failed");
                    format!("(agent error: {e})")
                }
            };
            if let Err(e) = publish_event(
                &publish_ctx,
                "text",
                base64_of(reply.as_bytes()),
                &event.event_id,
            )
            .await
            {
                tracing::warn!(error = %e, "#430 chat loop: reply publish failed — the turn is LOST from the transcript");
            }
            // #537 — the operator (fleet's converse pane) picked a reply voice:
            // ALSO speak the reply as a correlated audio-clip (a device on the
            // channel plays it). Best-effort — the text reply already landed, so
            // a sandbox without the gate relay just logs + stays text-only.
            if let Some(params) = event.audio.as_ref().filter(|a| a.voice.is_some()) {
                match (&cfg.speech_url, &cfg.speech_bearer) {
                    (Some(url), Some(bearer)) => {
                        let base = url.trim_end_matches('/');
                        match tts_synthesize(&http, base, bearer, &reply, Some(params)).await {
                            Ok(audio) => {
                                if let Err(e) =
                                    publish_event(&publish_ctx, "audio-clip", audio, &event.event_id)
                                        .await
                                {
                                    tracing::warn!(error = %e, "#537 chat loop: voiced text-reply publish failed");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "#537 chat loop: text-reply TTS failed — text-only")
                            }
                        }
                    }
                    _ => tracing::info!(
                        "#537 chat loop: text turn asked for a reply voice but this sandbox has no gate relay — text only"
                    ),
                }
            }
        }
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

struct VoiceTurn {
    reply_text: String,
    reply_audio_b64: String,
}

/// Container sniffing from magic bytes — the audio-clip envelope carries no
/// format field yet (typed audio params are the #519 protocol follow-up), and
/// guessing wrong just makes the ASR reject loudly.
fn sniff_audio_format(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
        "wav"
    } else if bytes.len() >= 3
        && (&bytes[..3] == b"ID3" || (bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0))
    {
        "mp3"
    } else if bytes.len() >= 4 && &bytes[..4] == b"OggS" {
        "ogg"
    } else {
        "wav"
    }
}

/// #519 — one voice turn: gate ASR → bridge chat → gate TTS. Refused loudly
/// when the sandbox has no speech relay wiring (direct-ark boots) — the real
/// Ark base has no speech endpoints and a gk_-less call would leak nothing but
/// would fail confusingly deep; this failure names the actual gap instead.
/// #522: the event's declared audio params drive the reply voice/rate and the
/// clip's container; magic-byte sniffing stays the params-less fallback.
async fn voice_turn(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    audio_b64: &str,
    params: Option<&agentkeys_backend_client::protocol::ChannelAudioParams>,
) -> Result<VoiceTurn, String> {
    let (Some(speech_url), Some(bearer)) = (&cfg.speech_url, &cfg.speech_bearer) else {
        return Err(
            "voice turns need the gate speech relay (AGENTKEYS_GATE_SPEECH_URL + gk_ key \
             from a gate-provisioned spawn) — this sandbox has none"
                .into(),
        );
    };
    let decoded = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD
            .decode(audio_b64)
            .map_err(|e| format!("inbound audio is not valid base64: {e}"))?
    };
    let declared_format = params.and_then(|p| p.format.clone());
    let format = declared_format.unwrap_or_else(|| sniff_audio_format(&decoded).to_string());
    let base = speech_url.trim_end_matches('/');

    let resp = http
        .post(format!("{base}/v1/audio/transcriptions"))
        .timeout(Duration::from_secs(120))
        .bearer_auth(bearer)
        .json(&serde_json::json!({ "audio_b64": audio_b64, "format": format }))
        .send()
        .await
        .map_err(|e| format!("gate asr send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("gate asr HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("gate asr parse: {e}"))?;
    let transcript = v
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string();
    if transcript.trim().is_empty() {
        return Err("gate asr returned an empty transcript".into());
    }

    let reply_text = bridge_chat(http, cfg, &transcript).await?;
    let reply_audio_b64 = tts_synthesize(http, base, bearer, &reply_text, params).await?;
    Ok(VoiceTurn {
        reply_text,
        reply_audio_b64,
    })
}

/// #522 — synthesize `text` into a base64 audio clip via the gate TTS relay,
/// honoring the declared reply voice + speech rate (语速). Shared by the
/// audio-clip voice turn AND the #537 text turn that requested a spoken reply
/// (fleet's converse pane picks a voice). `base` is the trimmed gate speech URL.
fn tts_body_for(
    text: &str,
    params: Option<&agentkeys_backend_client::protocol::ChannelAudioParams>,
) -> serde_json::Value {
    let mut body = serde_json::json!({ "input": text });
    if let Some(p) = params {
        if let Some(v) = &p.voice {
            body["voice"] = serde_json::Value::String(v.clone());
        }
        if let Some(r) = p.speech_rate {
            body["speech_rate"] = serde_json::Value::from(r);
        }
    }
    body
}

async fn tts_synthesize(
    http: &reqwest::Client,
    base: &str,
    bearer: &str,
    text: &str,
    params: Option<&agentkeys_backend_client::protocol::ChannelAudioParams>,
) -> Result<String, String> {
    let resp = http
        .post(format!("{base}/v1/audio/speech"))
        .timeout(Duration::from_secs(120))
        .bearer_auth(bearer)
        .json(&tts_body_for(text, params))
        .send()
        .await
        .map_err(|e| format!("gate tts send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("gate tts HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("gate tts parse: {e}"))?;
    let audio = v
        .get("audio_b64")
        .and_then(|a| a.as_str())
        .unwrap_or_default()
        .to_string();
    if audio.is_empty() {
        return Err("gate tts returned no audio".into());
    }
    Ok(audio)
}

/// #528 — the OpenAI-compatible vision request for one image (a JPEG data URI +
/// a describe prompt). Split out so the wire shape is unit-tested without a live
/// call. ARK/Doubao accept the standard `image_url` content part.
fn vision_request_body(image_b64: &str) -> serde_json::Value {
    serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [
                { "type": "image_url",
                  "image_url": { "url": format!("data:image/jpeg;base64,{image_b64}") } },
                { "type": "text",
                  "text": "Describe what you see in this image in one or two sentences." }
            ]
        }],
        "stream": false
    })
}

/// #528 (Phase 2) — one vision turn: POST the image to the gate's
/// OpenAI-compatible `/v1/chat/completions` (same base + gk_ key as the voice
/// legs) and return the text description. ARK is OpenAI-compatible, so this
/// needs no new gate surface. Refused loudly when the sandbox has no gate
/// wiring (direct-ark boots), exactly like `voice_turn`.
async fn vision_turn(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    image_b64: &str,
) -> Result<String, String> {
    let (Some(gate_url), Some(bearer)) = (&cfg.speech_url, &cfg.speech_bearer) else {
        return Err(
            "vision turns need the gate (AGENTKEYS_GATE_SPEECH_URL + gk_ key from a \
             gate-provisioned spawn) — this sandbox has none"
                .into(),
        );
    };
    let base = gate_url.trim_end_matches('/');
    let resp = http
        .post(format!("{base}/v1/chat/completions"))
        .timeout(Duration::from_secs(120))
        .bearer_auth(bearer)
        .json(&vision_request_body(image_b64))
        .send()
        .await
        .map_err(|e| format!("gate vision send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("gate vision HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("gate vision parse: {e}"))?;
    let reply = v["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if reply.trim().is_empty() {
        return Err("gate vision returned an empty description".into());
    }
    Ok(reply)
}

async fn resolve_session(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    device_key: &agentkeys_core::device_crypto::DeviceKey,
) -> Result<String, String> {
    let pop_sig = device_key.pop_sig().map_err(|e| format!("pop: {e}"))?;
    let resp = http
        .post(format!(
            "{}/v1/agent/resolve",
            cfg.broker_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "device_pubkey": device_key.address(),
            "pop_sig": pop_sig,
        }))
        .send()
        .await
        .map_err(|e| format!("resolve send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("resolve HTTP {}", resp.status()));
    }
    resp.json::<ResolveResponse>()
        .await
        .map(|r| r.session_jwt)
        .map_err(|e| format!("resolve parse: {e}"))
}

async fn bridge_chat(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    text: &str,
) -> Result<String, String> {
    let mut req = http
        .post(format!("{}/v1/chat", cfg.bridge_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(180))
        .json(&serde_json::json!({ "text": text, "stream": false }));
    if let Some(token) = &cfg.bridge_token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| format!("bridge send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("bridge HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("bridge parse: {e}"))?;
    Ok(v.get("reply")
        .and_then(|r| r.as_str())
        .unwrap_or("(no reply)")
        .to_string())
}

/// #525 — fetch the delegate's background-task list from the bridge
/// (`GET /v1/jobs` → `[{pgid, pid, cmd, procs}]`) and render it as a compact,
/// device-friendly text doc. The device never talks to the bridge itself —
/// this is the sandbox-side answer to a `command:jobs` channel event.
async fn bridge_jobs(http: &reqwest::Client, cfg: &ChatLoopConfig) -> Result<String, String> {
    let mut req = http
        .get(format!("{}/v1/jobs", cfg.bridge_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(30));
    if let Some(token) = &cfg.bridge_token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| format!("bridge send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("bridge HTTP {}", resp.status()));
    }
    let jobs: Vec<serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| format!("bridge parse: {e}"))?;
    if jobs.is_empty() {
        return Ok("No background tasks running.".to_string());
    }
    let mut out = format!("{} background task(s):\n", jobs.len());
    for j in &jobs {
        let pgid = j.get("pgid").and_then(|v| v.as_i64()).unwrap_or(0);
        let cmd = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("?");
        // Truncate long command lines so a small device screen stays readable.
        let cmd: String = cmd.chars().take(60).collect();
        out.push_str(&format!("• [{pgid}] {cmd}\n"));
    }
    Ok(out)
}

/// The per-poll invariants every publish shares — bundled so the reply
/// helpers stay under clippy's argument ceiling instead of re-threading five
/// context handles per call.
struct PublishCtx<'a> {
    http: &'a reqwest::Client,
    cfg: &'a ChatLoopConfig,
    client: &'a BackendClient,
    bearer: &'a str,
    device_key: &'a agentkeys_core::device_crypto::DeviceKey,
}

async fn publish_event(
    ctx: &PublishCtx<'_>,
    kind: &str,
    body_b64: String,
    correlation: &str,
) -> Result<(), String> {
    let pub_cap = ctx
        .client
        .cap_mint(
            CapMintOp::ChannelPublish,
            CapMintRequest {
                operator_omni: ctx.cfg.operator_omni.clone(),
                actor_omni: ctx.cfg.actor_omni.clone(),
                service: format!("channel-pub:{}", ctx.cfg.chat_channel_id),
                device_key_hash: ctx.device_key.device_key_hash().unwrap_or_default(),
                ttl_seconds: 300,
            },
            ctx.bearer,
        )
        .await
        .map_err(|e| format!("channel-pub mint: {e}"))?;
    // @backend-fixture: channel_publish_body — the protocol-shaped publish.
    let body = serde_json::json!({
        "cap": pub_cap,
        "kind": kind,
        "direction": "out",
        "body_b64": body_b64,
        "correlation": correlation,
    });
    let resp = ctx
        .http
        .post(format!(
            "{}/v1/channel/publish",
            ctx.cfg.channel_worker_url.trim_end_matches('/')
        ))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("publish send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("publish HTTP {}", resp.status()));
    }
    Ok(())
}

fn shellexpand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    p.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // #522/#537 — a declared reply voice + speech rate ride the gate TTS body;
    // no params = the bare input (gate defaults). Same helper feeds both the
    // audio-clip voice turn and the fleet-picked text turn.
    #[test]
    fn tts_body_honors_declared_voice_and_rate() {
        use agentkeys_backend_client::protocol::ChannelAudioParams;
        let bare = tts_body_for("hello", None);
        assert_eq!(bare["input"], "hello");
        assert!(bare.get("voice").is_none());
        assert!(bare.get("speech_rate").is_none());
        let params = ChannelAudioParams {
            voice: Some("zh_female_meilinvyou_moon_bigtts".into()),
            speech_rate: Some(20),
            format: None,
        };
        let body = tts_body_for("你好", Some(&params));
        assert_eq!(body["input"], "你好");
        assert_eq!(body["voice"], "zh_female_meilinvyou_moon_bigtts");
        assert_eq!(body["speech_rate"], 20);
    }

    #[test]
    fn partial_env_is_none_and_loud_not_a_panic() {
        // from_env reads process env; in the test harness none of the chat
        // vars are set, so the loop must be OFF (None) — the common daemon
        // boot outside a sandbox.
        assert!(ChatLoopConfig::from_env().is_none());
    }

    #[test]
    fn vision_request_carries_an_image_url_data_uri_and_prompt() {
        let body = vision_request_body("AAAA");
        let content = &body["messages"][0]["content"];
        assert_eq!(content[0]["type"], "image_url");
        assert_eq!(
            content[0]["image_url"]["url"],
            "data:image/jpeg;base64,AAAA"
        );
        assert_eq!(content[1]["type"], "text");
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn audio_format_sniffing_covers_the_device_containers() {
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&[0, 0, 0, 0]);
        wav.extend_from_slice(b"WAVE");
        assert_eq!(sniff_audio_format(&wav), "wav");
        assert_eq!(sniff_audio_format(b"ID3\x04rest"), "mp3");
        assert_eq!(sniff_audio_format(&[0xFF, 0xFB, 0x90, 0x00]), "mp3");
        assert_eq!(sniff_audio_format(b"OggSxxxx"), "ogg");
        // Unknown bytes default to wav — the ASR then rejects loudly rather
        // than the loop guessing silently.
        assert_eq!(sniff_audio_format(b"\x00\x01\x02\x03"), "wav");
    }
}
