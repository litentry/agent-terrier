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
        for event in &poll.events {
            if !matches!(
                event.direction,
                agentkeys_backend_client::protocol::ChannelDirection::In
            ) {
                continue; // our own replies (direction: out) come back on the feed
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
            if let Err(e) = publish_reply(
                &http,
                &cfg,
                &client,
                &bearer,
                &device_key,
                &reply,
                &event.event_id,
            )
            .await
            {
                tracing::warn!(error = %e, "#430 chat loop: reply publish failed — the turn is LOST from the transcript");
            }
        }
    }
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

async fn publish_reply(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    client: &BackendClient,
    bearer: &str,
    device_key: &agentkeys_core::device_crypto::DeviceKey,
    reply: &str,
    correlation: &str,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let pub_cap = client
        .cap_mint(
            CapMintOp::ChannelPublish,
            CapMintRequest {
                operator_omni: cfg.operator_omni.clone(),
                actor_omni: cfg.actor_omni.clone(),
                service: format!("channel-pub:{}", cfg.chat_channel_id),
                device_key_hash: device_key.device_key_hash().unwrap_or_default(),
                ttl_seconds: 300,
            },
            bearer,
        )
        .await
        .map_err(|e| format!("channel-pub mint: {e}"))?;
    // @backend-fixture: channel_publish_body — the protocol-shaped publish.
    let body = serde_json::json!({
        "cap": pub_cap,
        "kind": "text",
        "direction": "out",
        "body_b64": STANDARD.encode(reply.as_bytes()),
        "correlation": correlation,
    });
    let resp = http
        .post(format!(
            "{}/v1/channel/publish",
            cfg.channel_worker_url.trim_end_matches('/')
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

    #[test]
    fn partial_env_is_none_and_loud_not_a_panic() {
        // from_env reads process env; in the test harness none of the chat
        // vars are set, so the loop must be OFF (None) — the common daemon
        // boot outside a sandbox.
        assert!(ChatLoopConfig::from_env().is_none());
    }
}
