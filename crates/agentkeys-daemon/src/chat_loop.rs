//! #430 (epic #425 S4) — the DELEGATE-side chat loop, run by the
//! agentkeys-daemon INSTANCE INSIDE the dsh-sandbox (the image ships this
//! daemon under supervisord). The operator chat rides the delegate's
//! OPERATOR-OWNED duplex feed (`opchat-<label>`, D8): the operator publishes
//! `direction: in` events; this loop consumes them, runs each turn through the
//! local bridge (`POST /v1/chat`, persona-framed by #390), and publishes the
//! reply as `direction: out` with `correlation` = the inbound `event_id`.
//!
//! Identity — two custody modes (#552): LEGACY spawns inject the K10 itself
//! (`AGENTKEYS_DEVICE_KEY_HEX`, #427); SIGNER-custodied spawns inject a
//! broker-minted J1 (`AGENTKEYS_SESSION_JWT`) instead and every signature
//! (resolve pop, #76 cap-mint PoP) is produced IN the signer's device
//! domain — no key ever exists in this sandbox. Either way the credential
//! proves possession to the broker's `/v1/agent/resolve` → a fresh
//! `J1_agent` (rotated into the signer bearer). Authority: the on-chain
//! `channel-pub/sub:opchat-<label>` grants from the spawn template — this
//! loop can only ever reach its OWN chat feed (a cross-channel mint is
//! refused at all four §17.5 layers).
//!
//! Boot posture: the FIRST poll fast-forwards to the current cursor without
//! replying (a sandbox restart must not replay-answer history); only events
//! that arrive after boot get replies. Every failure is loud + backed off,
//! never a crash — chat degrades, the sandbox (and its jobs) keep running.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agentkeys_backend_client::protocol::{
    CapMintOp, CapMintRequest, ChannelEvent, ChannelEventKind,
};
use agentkeys_backend_client::BackendClient;
use serde::Deserialize;

use crate::app_runtime::{AppRuntimeConfig, FeedSpec, OPCHAT_SLOT};

/// Everything the loop needs, from the sandbox env (injected by the broker's
/// spawn finalize, #427/#430). `None` = not a chat-configured sandbox — the
/// daemon runs exactly as before. Cloned by the #566 memory mirror, which
/// rides the same env contract + credential but keeps its own session.
#[derive(Clone)]
pub struct ChatLoopConfig {
    pub broker_url: String,
    pub channel_worker_url: String,
    pub chat_channel_id: String,
    pub actor_omni: String,
    pub operator_omni: String,
    /// LEGACY custody: the in-env K10. Exactly one of this / `session_jwt`.
    pub device_key_hex: Option<String>,
    /// #552 signer custody: the broker-minted boot J1 (rotated by resolve);
    /// the delegate's K10 lives in the SIGNER and never enters the sandbox.
    pub session_jwt: Option<String>,
    /// #552 — the signer base URL (env override else DERIVED `signer.<zone>`
    /// from the broker host, the `derive_worker_url` convention).
    pub signer_url: Option<String>,
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
    /// #563 — streamed-reply delta coalescing window (ms). Every flush is one
    /// channel publish (an S3 object + an encrypt), so this trades feed churn
    /// against perceived latency; 1000 ms ≈ a sentence per bubble update.
    pub stream_flush_ms: u64,
}

impl ChatLoopConfig {
    /// Env-gated: all of the chat vars present ⇒ `Some`. A PARTIAL set is a
    /// loud warn (a mis-wired spawn should not silently mean "no chat").
    pub fn from_env() -> Option<Self> {
        // The channel worker URL is NOT in this required set — it is DERIVED from
        // the broker's domain + the worker name (the `derive_worker_url`
        // convention shared with the daemon's own `channel_worker_url`), never a
        // separately-injected env a spawn could forget. A remote sandbox already
        // holds its broker host, so it computes `channel.<zone>` itself;
        // AGENTKEYS_CHANNEL_WORKER_URL stays an OPTIONAL override.
        // The names are the shared `sandbox_env` contract (#546/#552) — the
        // broker's spawn paths inject against the same constants, so the set
        // can't drift. Required: the 4 COMMON identity/link envs plus EXACTLY
        // one credential — the legacy in-env K10 (pre-#552 spawns) or the
        // #552 session JWT (signer custody, no key in the sandbox).
        use agentkeys_backend_client::protocol::sandbox_env as env_names;
        let read = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let common: Vec<Option<String>> = env_names::CHAT_COMMON.iter().map(|k| read(k)).collect();
        let device_key_hex = read(env_names::DEVICE_KEY_HEX);
        let session_jwt = read(env_names::SESSION_JWT);
        let present = common.iter().filter(|v| v.is_some()).count()
            + usize::from(device_key_hex.is_some())
            + usize::from(session_jwt.is_some());
        if present == 0 {
            return None;
        }
        let mut missing: Vec<&str> = env_names::CHAT_COMMON
            .iter()
            .zip(&common)
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| *k)
            .collect();
        if device_key_hex.is_none() && session_jwt.is_none() {
            missing.push("AGENTKEYS_DEVICE_KEY_HEX|AGENTKEYS_SESSION_JWT");
        }
        if !missing.is_empty() {
            tracing::warn!(
                ?missing,
                "#430 chat loop: PARTIAL chat env — the spawn finalize should inject the \
                 common set + exactly one credential together; chat loop NOT started"
            );
            return None;
        }
        if device_key_hex.is_some() && session_jwt.is_some() {
            tracing::warn!(
                "#552 chat loop: BOTH AGENTKEYS_DEVICE_KEY_HEX and AGENTKEYS_SESSION_JWT \
                 injected — preferring the local key (legacy custody); fix the spawn path"
            );
        }
        let mut it = common.into_iter().map(|v| v.unwrap());
        let broker_url = it.next().unwrap();
        // env override → else derive `channel.<zone>` from the broker host.
        let channel_worker_url = match std::env::var(
            agentkeys_backend_client::protocol::sandbox_env::CHANNEL_WORKER_URL,
        )
        .ok()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .or_else(|| crate::ui_bridge::derive_worker_url(&broker_url, "channel"))
        {
            Some(u) => u,
            None => {
                tracing::warn!(
                    %broker_url,
                    "#430 chat loop: cannot derive the channel worker URL from the broker \
                     host (and no AGENTKEYS_CHANNEL_WORKER_URL override) — chat loop NOT started"
                );
                return None;
            }
        };
        // #552 signer custody needs the signer URL: env override → else derive
        // `signer.<zone>` from the broker host (same convention as channel).
        let signer_url = read(env_names::SIGNER_URL)
            .map(|u| u.trim_end_matches('/').to_string())
            .or_else(|| crate::ui_bridge::derive_worker_url(&broker_url, "signer"));
        if session_jwt.is_some() && device_key_hex.is_none() && signer_url.is_none() {
            tracing::warn!(
                %broker_url,
                "#552 chat loop: signer custody but the signer URL cannot be derived from \
                 the broker host (and no AGENTKEYS_SIGNER_URL override) — chat loop NOT started"
            );
            return None;
        }
        Some(Self {
            broker_url,
            channel_worker_url,
            chat_channel_id: it.next().unwrap(),
            actor_omni: it.next().unwrap(),
            operator_omni: it.next().unwrap(),
            device_key_hex,
            session_jwt,
            signer_url,
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
            stream_flush_ms: std::env::var("AGENTKEYS_CHAT_STREAM_FLUSH_MS")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|&ms| (100..=10_000).contains(&ms))
                .unwrap_or(1_000),
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

/// The delegate's signing credential — LEGACY in-sandbox K10, or the #552
/// signer custody handle (the key never enters the sandbox; the ROTATING J1
/// in `bearer` authenticates every signer call and is refreshed by resolve).
/// `pub(crate)`: shared with the #566 memory mirror via an `Arc`.
pub(crate) enum DelegateCredential {
    Local {
        key: std::sync::Arc<agentkeys_core::device_crypto::DeviceKey>,
    },
    Signer {
        client: std::sync::Arc<agentkeys_core::signer_client::DeviceSignerClient>,
        bearer: std::sync::Arc<tokio::sync::RwLock<String>>,
        actor_omni: String,
        address: String,
        device_key_hash: String,
    },
}

impl DelegateCredential {
    fn address(&self) -> String {
        match self {
            Self::Local { key } => key.address().to_string(),
            Self::Signer { address, .. } => address.clone(),
        }
    }

    /// Attach this credential's cap-PoP signing to a [`BackendClient`] — the
    /// ONE mapping from custody mode to client config (chat loop + mirror).
    pub(crate) fn configure_client(&self, client: BackendClient) -> BackendClient {
        match self {
            Self::Local { key } => client.with_device_key(key.clone()),
            Self::Signer {
                client: signer,
                bearer,
                device_key_hash,
                ..
            } => client.with_remote_cap_pop(agentkeys_backend_client::RemoteCapPop {
                signer: signer.clone(),
                bearer: bearer.clone(),
                device_key_hash: device_key_hash.clone(),
            }),
        }
    }

    pub(crate) fn device_key_hash(&self) -> String {
        match self {
            Self::Local { key } => key.device_key_hash().unwrap_or_default(),
            Self::Signer {
                device_key_hash, ..
            } => device_key_hash.clone(),
        }
    }

    /// A fresh pop_sig for `/v1/agent/resolve`. Signer mode re-derives (which
    /// also revalidates the bearer against the signer).
    async fn pop_sig(&self) -> Result<String, String> {
        match self {
            Self::Local { key } => key.pop_sig().map_err(|e| format!("pop: {e}")),
            Self::Signer {
                client,
                bearer,
                actor_omni,
                ..
            } => {
                let jwt = bearer.read().await.clone();
                client
                    .derive_device(actor_omni, None, &jwt)
                    .await
                    .map(|d| d.pop_sig)
                    .map_err(|e| format!("signer pop (#552): {e}"))
            }
        }
    }

    /// Resolve handed back a fresh J1: signer mode rotates its bearer so
    /// every subsequent signer call rides the newest session — **newer-wins
    /// by `exp`**. A resolve minted at the short device TTL must never
    /// replace a longer-lived boot J1 while that one is still valid (the
    /// 2026-08-31 agent-i death: the 25h boot J1 was traded for a 5h resolve
    /// J1, and once IT expired nothing could refresh it — the refresh itself
    /// needs a live bearer). A current bearer that is expired or unreadable
    /// always loses to the incoming one.
    pub(crate) async fn on_new_session(&self, jwt: &str) {
        if let Self::Signer { bearer, .. } = self {
            let mut cur = bearer.write().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let cur_exp = jwt_exp_claim(&cur);
            let new_exp = jwt_exp_claim(jwt);
            let keep_current = match (cur_exp, new_exp) {
                (Some(c), Some(n)) => c > now && n < c,
                (Some(c), None) => c > now,
                (None, _) => false,
            };
            if keep_current {
                tracing::debug!(
                    cur_exp,
                    new_exp,
                    "#552 bearer: keeping the longer-lived session (newer-wins by exp)"
                );
                return;
            }
            *cur = jwt.to_string();
        }
    }
}

/// The `exp` claim of a JWT, decoded WITHOUT verification — the daemon is not
/// the token's verifier (the signer/broker are); this only orders two bearers
/// it already holds by lifetime. `None` = unreadable/absent.
fn jwt_exp_claim(jwt: &str) -> Option<u64> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim())
        .ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("exp")?
        .as_u64()
}

/// Build the signing credential. LEGACY: materialize the injected K10 into
/// the daemon's standard key file so the shared DeviceKey/BackendClient
/// machinery (incl. the #76 cap PoP) applies unchanged (0600,
/// sandbox-local). #552 SIGNER custody: no key exists anywhere in this
/// sandbox — bootstrap by asking the signer for the derived address with
/// the injected boot J1. `None` = unrecoverable (already logged loudly).
/// Shared by the chat loop and the #566 `--memory-mirror-once` flag.
pub(crate) async fn build_credential(cfg: &ChatLoopConfig) -> Option<DelegateCredential> {
    let credential = match (&cfg.device_key_hex, &cfg.session_jwt) {
        (Some(key_hex), _) => {
            let key_file = std::env::var("AGENTKEYS_DEVICE_KEY_FILE")
                .unwrap_or_else(|_| "~/.agentkeys/agent-device.key".to_string());
            if let Err(e) =
                agentkeys_core::device_crypto::write_key_0600(&shellexpand_home(&key_file), key_hex)
            {
                tracing::error!(error = %e, "#430 chat loop: cannot materialize the device key — chat disabled");
                return None;
            }
            match agentkeys_core::device_crypto::DeviceKey::load_or_generate(&key_file, false) {
                Ok(k) => DelegateCredential::Local {
                    key: std::sync::Arc::new(k),
                },
                Err(e) => {
                    tracing::error!(error = %e, "#430 chat loop: device key load failed — chat disabled");
                    return None;
                }
            }
        }
        (None, Some(boot_jwt)) => {
            let Some(signer_url) = cfg.signer_url.clone() else {
                tracing::error!(
                    "#552 chat loop: signer custody without a signer URL — chat disabled"
                );
                return None;
            };
            let client = std::sync::Arc::new(
                agentkeys_core::signer_client::DeviceSignerClient::new(signer_url),
            );
            let bearer = std::sync::Arc::new(tokio::sync::RwLock::new(boot_jwt.clone()));
            // Bootstrap derive (retried): learns address + dkh AND proves the
            // boot J1 + signer path work before the loop starts. A boot J1
            // past its TTL is unrecoverable from inside (no key to resolve
            // with) — loud; the next sandbox re-create injects a fresh one.
            let mut backoff = Duration::from_secs(2);
            let derived = loop {
                match client
                    .derive_device(&cfg.actor_omni, None, &bearer.read().await)
                    .await
                {
                    Ok(d) => break d,
                    Err(agentkeys_core::signer_client::SignerClientError::Unauthorized(e)) => {
                        tracing::error!(
                            error = %e,
                            "#552 chat loop: boot J1 REFUSED by the signer (expired?) — \
                             unrecoverable without a key; a sandbox re-create injects a \
                             fresh J1. Chat disabled."
                        );
                        return None;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "#552 chat loop: signer bootstrap failed — retrying");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(120));
                    }
                }
            };
            tracing::info!(
                address = %derived.address,
                "#552 chat loop: signer custody active (healthy, by design — the K10 never \
                 enters the sandbox; the signer signs remotely; address = the custodied \
                 key's derived address)"
            );
            DelegateCredential::Signer {
                client,
                bearer,
                actor_omni: cfg.actor_omni.clone(),
                address: derived.address,
                device_key_hash: derived.device_key_hash,
            }
        }
        (None, None) => {
            tracing::error!("#430 chat loop: no credential (key or session JWT) — chat disabled");
            return None;
        }
    };
    Some(credential)
}

/// The delegate's rotating `J1_agent` — ONE session shared by every feed
/// poller, the publisher, the scheduler and the perception adapter (#665:
/// N feeds, one identity). A 401 from any leg invalidates it; the next leg
/// re-resolves (serialized — no resolve stampede across N pollers).
pub(crate) struct SessionHandle {
    http: reqwest::Client,
    cfg: Arc<ChatLoopConfig>,
    credential: Arc<DelegateCredential>,
    jwt: tokio::sync::RwLock<Option<String>>,
    refresh: tokio::sync::Mutex<()>,
}

impl SessionHandle {
    pub(crate) fn new(
        http: reqwest::Client,
        cfg: Arc<ChatLoopConfig>,
        credential: Arc<DelegateCredential>,
    ) -> Self {
        Self {
            http,
            cfg,
            credential,
            jwt: tokio::sync::RwLock::new(None),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    /// The current bearer, resolving one when none is held.
    pub(crate) async fn bearer(&self) -> Result<String, String> {
        if let Some(j) = self.jwt.read().await.clone() {
            return Ok(j);
        }
        self.refresh().await
    }

    /// Re-resolve (serialized). A concurrent caller that finds a fresh bearer
    /// already stored takes it instead of resolving again.
    pub(crate) async fn refresh(&self) -> Result<String, String> {
        let _guard = self.refresh.lock().await;
        if let Some(j) = self.jwt.read().await.clone() {
            return Ok(j);
        }
        let jwt = resolve_session(&self.http, &self.cfg, &self.credential).await?;
        self.credential.on_new_session(&jwt).await;
        *self.jwt.write().await = Some(jwt.clone());
        Ok(jwt)
    }

    /// Drop `stale` (a bearer a worker/broker just refused) so the next leg
    /// re-resolves; a bearer rotated since is kept.
    pub(crate) async fn invalidate(&self, stale: &str) {
        let mut cur = self.jwt.write().await;
        if cur.as_deref() == Some(stale) {
            *cur = None;
        }
    }

    pub(crate) fn client(&self, bearer: &str) -> BackendClient {
        let client = BackendClient::new(
            Some(self.cfg.broker_url.clone()),
            None,
            None,
            None,
            Some(bearer.to_string()),
            None,
            None,
            std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
        );
        self.credential.configure_client(client)
    }
}

/// #665/#669 — the loop's shared runtime: config, session, publisher, the app
/// template's bundle (perception prompt), and the perception cache.
pub(crate) struct LoopRuntime {
    pub http: reqwest::Client,
    pub cfg: Arc<ChatLoopConfig>,
    pub publisher: Arc<Publisher>,
    pub perception_prompt: Option<String>,
    pub min_confidence: f32,
    pub perception_cache: tokio::sync::Mutex<crate::perception::PerceptionCache>,
}

async fn run(cfg: ChatLoopConfig) {
    let Some(credential) = build_credential(&cfg).await else {
        return;
    };
    let credential = std::sync::Arc::new(credential);
    // #566 — the distribution mirror shares the credential but keeps its own
    // session + cadence, so neither loop can stall the other.
    if let Some(mirror_cfg) = crate::memory_mirror::MirrorConfig::from_chat_env(cfg.clone()) {
        crate::memory_mirror::spawn(mirror_cfg, credential.clone());
    }
    // #594 — the runtime checkpoint (restore-on-boot + periodic durable save),
    // same isolation posture as the mirror: own session, shared credential.
    if let Some(checkpoint_cfg) = crate::checkpoint::CheckpointConfig::from_chat_env(cfg.clone()) {
        crate::checkpoint::spawn(checkpoint_cfg, credential.clone());
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .expect("reqwest client");
    let cfg = Arc::new(cfg);
    let app = Arc::new(AppRuntimeConfig::from_env());
    let session = Arc::new(SessionHandle::new(
        http.clone(),
        cfg.clone(),
        credential.clone(),
    ));
    let publisher = Arc::new(Publisher::new(http.clone(), cfg.clone(), session.clone()));

    // #660 — the app template's bundle: the perception prompt (R2) + the
    // schedule (R4). A role preset has none; loud when the catalog is down.
    let bundle =
        crate::app_runtime::fetch_template_bundle(&http, &cfg.broker_url, &app.template_id).await;
    let perception_prompt = bundle
        .as_ref()
        .and_then(|b| b.perception_prompt().map(str::to_string));
    if !app.template_id.is_empty() {
        tracing::info!(
            template = %app.template_id,
            bound_feeds = app.bound_channels.len(),
            availability = %app.availability.as_str(),
            perception_prompt = perception_prompt.is_some(),
            schedule_entries = bundle.as_ref().map(|b| b.manifest.schedule.len()).unwrap_or(0),
            "#660 app runtime: template facts loaded"
        );
    }
    // R4 — the clock: schedule ticks as agent turns, guard-gated in-loop.
    if let Some(b) = &bundle {
        if !b.manifest.schedule.is_empty() {
            let rt = crate::schedule::ScheduleRuntime {
                schedule: b.manifest.schedule.clone(),
                tz_offset_minutes: app.tz_offset_minutes,
                bridge_url: cfg.bridge_url.clone(),
                bridge_token: cfg.bridge_token.clone(),
                self_grants_url: app.self_grants_url.clone(),
                chat_channel_id: cfg.chat_channel_id.clone(),
                http: http.clone(),
                publisher: publisher.clone(),
            };
            tokio::spawn(crate::schedule::run(rt));
        }
    }

    // R1 — one poller per readable feed, all feeding ONE dispatcher queue.
    let feeds = app.feeds(&cfg.chat_channel_id);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(FeedSpec, ChannelEvent)>(256);
    for feed in feeds.iter().filter(|f| f.direction.reads()) {
        tracing::info!(slot = %feed.slot, channel = %feed.channel_id, kind = %feed.kind.as_str(), "#665 chat loop: polling feed");
        tokio::spawn(poll_feed(
            feed.clone(),
            session.clone(),
            cfg.clone(),
            credential.clone(),
            http.clone(),
            tx.clone(),
        ));
    }
    drop(tx);

    let runtime = LoopRuntime {
        http: http.clone(),
        cfg: cfg.clone(),
        publisher: publisher.clone(),
        perception_prompt,
        min_confidence: crate::perception::min_confidence_from(|k| std::env::var(k).ok()),
        perception_cache: tokio::sync::Mutex::new(crate::perception::PerceptionCache::new(256)),
    };
    while let Some((feed, event)) = rx.recv().await {
        handle_event(&runtime, &feed, &event).await;
    }
    tracing::warn!("#665 chat loop: every feed poller stopped — loop ending");
}

/// One feed's long-poll loop (R1): its own subscribe-cap cache + cursor +
/// boot fast-forward; the shared session. Every event is tagged with the
/// feed's slot before it enters the dispatcher queue.
async fn poll_feed(
    feed: FeedSpec,
    session: Arc<SessionHandle>,
    cfg: Arc<ChatLoopConfig>,
    credential: Arc<DelegateCredential>,
    http: reqwest::Client,
    tx: tokio::sync::mpsc::Sender<(FeedSpec, ChannelEvent)>,
) {
    let mut cursor = String::new();
    let mut fast_forwarded = false;
    let mut backoff = Duration::from_secs(2);
    // #563 — cap reuse: caps carry a 300 s TTL yet were re-minted every poll
    // round, which under #552 remote-PoP custody meant one signer round-trip
    // per delegate per ~26 s poll. Reuse until the refresh margin; any worker
    // refusal invalidates, so revocation / epoch rotation degrade to one extra
    // mint, never a silent stale-cap loop.
    let mut sub_caps = CapCache::default();
    loop {
        // 1. A valid J1_agent (shared; re-resolved on refusal).
        let bearer = match session.bearer().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, slot = %feed.slot, "#430 chat loop: resolve failed — retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
        };
        let client = session.client(&bearer);

        // 2. Subscribe cap (cached, #563) + one long-poll round.
        let sub_cap = match sub_caps.fresh() {
            Some(c) => c,
            None => match client
                .cap_mint(
                    CapMintOp::ChannelSubscribe,
                    CapMintRequest {
                        operator_omni: cfg.operator_omni.clone(),
                        actor_omni: cfg.actor_omni.clone(),
                        service: format!("channel-sub:{}", feed.channel_id),
                        device_key_hash: credential.device_key_hash(),
                        ttl_seconds: 300,
                    },
                    &bearer,
                )
                .await
            {
                Ok(c) => sub_caps.store(c),
                Err(e) => {
                    let msg = e.to_string();
                    tracing::warn!(error = %msg, slot = %feed.slot, channel = %feed.channel_id, "#430 chat loop: channel-sub mint failed");
                    if msg.contains("401") || msg.contains("expired") {
                        session.invalidate(&bearer).await;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                    continue;
                }
            },
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
                    tracing::warn!(error = %e, slot = %feed.slot, "#430 chat loop: poll parse failed");
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            },
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), slot = %feed.slot, "#430 chat loop: poll refused");
                // The cached cap may be revoked / epoch-rotated — next round
                // re-mints instead of replaying a refused token (#563).
                sub_caps.invalidate();
                if resp.status().as_u16() == 401 {
                    session.invalidate(&bearer).await;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, slot = %feed.slot, "#430 chat loop: poll transport failed");
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
                    slot = %feed.slot,
                    "#430 chat loop: fast-forwarded past existing history at boot"
                );
            }
            continue;
        }
        for event in poll.events {
            if tx.send((feed.clone(), event)).await.is_err() {
                return;
            }
        }
    }
}

/// Decode an inline body as UTF-8 text (`""` when absent / not text).
fn inline_text(event: &ChannelEvent) -> String {
    event
        .body
        .as_deref()
        .and_then(|b64| {
            use base64::{engine::general_purpose::STANDARD, Engine};
            STANDARD.decode(b64).ok()
        })
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

/// The event's bytes: the inline body, else the `body_ref` blob fetched from
/// the feed (#667 — originals ride by reference, never downscaled).
async fn event_bytes(
    rt: &LoopRuntime,
    feed: &FeedSpec,
    event: &ChannelEvent,
) -> Result<(Vec<u8>, String), String> {
    if let Some(b64) = event.body.as_deref() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| format!("inline body is not valid base64: {e}"))?;
        return Ok((bytes, event.content_type.clone().unwrap_or_default()));
    }
    if let Some(r) = event.body_ref.as_deref() {
        return rt.publisher.fetch_blob(&feed.channel_id, r).await;
    }
    Err("event carries neither body nor body_ref".into())
}

/// The dispatcher (the four verbs' "perceive → act" hop): one inbound event
/// from one feed → the right per-kind path → the reply on the SAME feed.
async fn handle_event(rt: &LoopRuntime, feed: &FeedSpec, event: &ChannelEvent) {
    if !matches!(
        event.direction,
        agentkeys_backend_client::protocol::ChannelDirection::In
    ) {
        return; // our own replies (direction: out) come back on the feed
    }
    let cfg = &rt.cfg;
    let http = &rt.http;
    let publisher = &rt.publisher;
    let channel = feed.channel_id.as_str();
    let contact_tier = event.contact.as_ref().map(|c| c.tier.as_str());
    match event.kind {
        // #519 — a voice turn on the OPERATOR chat feed (a device conversation):
        // ASR → bridge chat → TTS, published twice (text + audio-clip). On any
        // other feed a clip is a PERCEIVED input (R2) answered in text.
        ChannelEventKind::AudioClip if feed.slot == OPCHAT_SLOT => {
            let (bytes, _ct) = match event_bytes(rt, feed, event).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(event = %event.event_id, error = %e, "#519 chat loop: audio-clip bytes unavailable — turn skipped");
                    return;
                }
            };
            let audio_b64 = base64_of(&bytes);
            match voice_turn(http, cfg, &audio_b64, event.audio.as_ref()).await {
                Ok(turn) => {
                    if let Err(e) = publisher
                        .publish_text_out(channel, &turn.reply_text, &event.event_id)
                        .await
                    {
                        tracing::warn!(error = %e, "#519 chat loop: voice text-reply publish failed");
                    }
                    if let Err(e) = publisher
                        .publish(
                            channel,
                            "audio-clip",
                            turn.reply_audio_b64,
                            &event.event_id,
                            None,
                            None,
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "#519 chat loop: voice audio-reply publish failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "#519 chat loop: voice turn failed");
                    let _ = publisher
                        .publish_text_out(channel, &format!("(voice error: {e})"), &event.event_id)
                        .await;
                }
            }
        }
        // #668 (R2) — a media event becomes a PRE-TURN on the full-resolution
        // original, then the agent's turn; low confidence asks for a closer look.
        ChannelEventKind::Image | ChannelEventKind::Frame | ChannelEventKind::AudioClip => {
            perceive_and_turn(rt, feed, event, contact_tier).await;
        }
        // #525 — a device asked for the background-task list (kind=command,
        // body "jobs"); #670 — a card action tap is a `CardCommand` JSON body
        // handed to the agent as a turn. Other commands are ignored (logged).
        ChannelEventKind::Command => {
            let cmd = inline_text(event);
            if cmd.trim() == "jobs" {
                let doc = bridge_jobs(http, cfg)
                    .await
                    .unwrap_or_else(|e| format!("(jobs error: {e})"));
                if let Err(e) = publisher
                    .publish(
                        channel,
                        "doc",
                        base64_of(doc.as_bytes()),
                        &event.event_id,
                        None,
                        None,
                    )
                    .await
                {
                    tracing::warn!(error = %e, "#525 chat loop: jobs doc publish failed");
                }
                return;
            }
            match agentkeys_backend_client::protocol::parse_card_command(cmd.as_bytes()) {
                Ok(card_cmd) => {
                    let actor = match &event.producer {
                        agentkeys_backend_client::protocol::ChannelProducer::Actor {
                            actor_omni,
                        } => actor_omni.clone(),
                        agentkeys_backend_client::protocol::ChannelProducer::Contact {
                            contact_id,
                            ..
                        } => contact_id.clone(),
                    };
                    let text = format!(
                        "[command · slot {} · action {} · from actor {}]\n{}{}",
                        feed.slot,
                        card_cmd.action,
                        actor,
                        card_cmd.command,
                        if card_cmd.args.is_null() {
                            String::new()
                        } else {
                            format!("\nargs: {}", card_cmd.args)
                        }
                    );
                    let reply = match bridge_chat(http, cfg, &text).await {
                        Ok(r) => r,
                        Err(e) => format!("(agent error: {e})"),
                    };
                    if let Err(e) = publisher
                        .publish_text_out(channel, &reply, &event.event_id)
                        .await
                    {
                        tracing::warn!(error = %e, "#670 chat loop: command reply publish failed");
                    }
                }
                Err(_) => tracing::info!(cmd = %cmd, "#525 chat loop: unknown command — ignored"),
            }
        }
        ChannelEventKind::Text | ChannelEventKind::Doc => {
            let mut text = inline_text(event);
            if text.trim().is_empty() {
                return;
            }
            // #667 — a caption relayed beside a photo (relay_of = the media
            // event id) is a turn about that photo, not a standalone message.
            if let Some(media) = event.relay_of.as_deref() {
                text = format!("[caption for the perceived input {media}]\n{text}");
            }
            if feed.slot != OPCHAT_SLOT {
                text = format!(
                    "[from slot {} ({}){}]\n{text}",
                    feed.slot,
                    feed.kind.as_str(),
                    contact_tier
                        .map(|t| format!(" · a {t} contact"))
                        .unwrap_or_default()
                );
            }
            // #563 — stream ONLY when the inbound turn carries the consumer's
            // explicit hint: a consumer that never sends it (old web app,
            // fleet TUI, devices) gets today's single-shot reply, so partials
            // can never fragment-spam a UI that doesn't merge them.
            let reply = if event.stream == Some(true) {
                match bridge_chat_stream(http, cfg, &text, publisher, channel, &event.event_id)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "#563 chat loop: streamed bridge turn failed");
                        format!("(agent error: {e})")
                    }
                }
            } else {
                match bridge_chat(http, cfg, &text).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "#430 chat loop: bridge /v1/chat failed");
                        format!("(agent error: {e})")
                    }
                }
            };
            if let Err(e) = publisher
                .publish_text_out(channel, &reply, &event.event_id)
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
                        match tts_synthesize(http, base, bearer, &reply, Some(params)).await {
                            Ok(audio) => {
                                if let Err(e) = publisher
                                    .publish(channel, "audio-clip", audio, &event.event_id, None, None)
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

/// #668 — the R2 pre-turn + hand-off for one media event.
async fn perceive_and_turn(
    rt: &LoopRuntime,
    feed: &FeedSpec,
    event: &ChannelEvent,
    contact_tier: Option<&str>,
) {
    let kind = event.kind.as_str();
    let channel = feed.channel_id.as_str();
    let (bytes, content_type) = match event_bytes(rt, feed, event).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(event = %event.event_id, error = %e, "#668 chat loop: media bytes unavailable — turn skipped");
            return;
        }
    };
    let sha = crate::perception::sha256_hex(&bytes);
    let cached = rt.perception_cache.lock().await.get(&sha).cloned();
    let result = match cached {
        Some(r) => {
            tracing::info!(sha = %sha[..12], "#668 perception: cache hit — decoded once");
            r
        }
        None => {
            let prompt = rt
                .perception_prompt
                .clone()
                .unwrap_or_else(|| crate::perception::DEFAULT_PERCEPTION_PROMPT.to_string());
            let outcome = match event.kind {
                ChannelEventKind::AudioClip => {
                    let format = event
                        .audio
                        .as_ref()
                        .and_then(|a| a.format.clone())
                        .unwrap_or_else(|| sniff_audio_format(&bytes).to_string());
                    match gate_transcribe(&rt.http, &rt.cfg, &base64_of(&bytes), &format).await {
                        Ok(transcript) => {
                            gate_completion(
                                &rt.http,
                                &rt.cfg,
                                crate::perception::transcript_request_body(&prompt, &transcript),
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
                _ => {
                    gate_completion(
                        &rt.http,
                        &rt.cfg,
                        crate::perception::image_request_body(
                            &prompt,
                            &content_type,
                            &base64_of(&bytes),
                        ),
                    )
                    .await
                }
            };
            match outcome {
                Ok(reply) => {
                    let r = crate::perception::parse_result(&reply, &sha);
                    rt.perception_cache.lock().await.put(sha.clone(), r.clone());
                    r
                }
                Err(e) => {
                    tracing::warn!(error = %e, kind, "#668 perception: pre-turn failed");
                    let _ = rt
                        .publisher
                        .publish_text_out(
                            channel,
                            &format!("(perception error: {e})"),
                            &event.event_id,
                        )
                        .await;
                    return;
                }
            }
        }
    };
    if crate::perception::needs_closer_look(&result, rt.min_confidence) {
        tracing::info!(
            confidence = result.confidence,
            kind,
            "#668 perception: low confidence — asking for a closer look"
        );
        let _ = rt
            .publisher
            .publish_text_out(
                channel,
                &crate::perception::closer_look_reply(kind),
                &event.event_id,
            )
            .await;
        return;
    }
    let turn = crate::perception::agent_turn_text(&feed.slot, kind, contact_tier, None, &result);
    let reply = match bridge_chat(&rt.http, &rt.cfg, &turn).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "#668 chat loop: agent turn after perception failed");
            format!("(agent error: {e})")
        }
    };
    if let Err(e) = rt
        .publisher
        .publish_text_out(channel, &reply, &event.event_id)
        .await
    {
        tracing::warn!(error = %e, "#668 chat loop: perception reply publish failed");
    }
}

/// One gate `/v1/chat/completions` call (the OpenAI-compatible relay) → the
/// assistant's text. Refused loudly when the sandbox has no gate wiring.
async fn gate_completion(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    body: serde_json::Value,
) -> Result<String, String> {
    let (Some(gate_url), Some(bearer)) = (&cfg.speech_url, &cfg.speech_bearer) else {
        return Err(
            "perception turns need the gate (AGENTKEYS_GATE_SPEECH_URL + gk_ key from a \
             gate-provisioned spawn) — this sandbox has none"
                .into(),
        );
    };
    let base = gate_url.trim_end_matches('/');
    let resp = http
        .post(format!("{base}/v1/chat/completions"))
        .timeout(Duration::from_secs(120))
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("gate completion send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("gate completion HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("gate completion parse: {e}"))?;
    let reply = v["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if reply.trim().is_empty() {
        return Err("gate completion returned an empty reply".into());
    }
    Ok(reply)
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

    let transcript = gate_transcribe(http, cfg, audio_b64, &format).await?;
    let reply_text = bridge_chat(http, cfg, &transcript).await?;
    let reply_audio_b64 = tts_synthesize(http, base, bearer, &reply_text, params).await?;
    Ok(VoiceTurn {
        reply_text,
        reply_audio_b64,
    })
}

/// The gate ASR leg (`/v1/audio/transcriptions`, #519) — shared by the opchat
/// voice turn and the #668 perception adapter.
async fn gate_transcribe(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    audio_b64: &str,
    format: &str,
) -> Result<String, String> {
    let (Some(speech_url), Some(bearer)) = (&cfg.speech_url, &cfg.speech_bearer) else {
        return Err(
            "voice turns need the gate speech relay (AGENTKEYS_GATE_SPEECH_URL + gk_ key \
             from a gate-provisioned spawn) — this sandbox has none"
                .into(),
        );
    };
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
    Ok(transcript)
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

pub(crate) async fn resolve_session(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    credential: &DelegateCredential,
) -> Result<String, String> {
    let pop_sig = credential.pop_sig().await?;
    let resp = http
        .post(format!(
            "{}/v1/agent/resolve",
            cfg.broker_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "device_pubkey": credential.address(),
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
    bridge_chat_at(http, &cfg.bridge_url, cfg.bridge_token.as_deref(), text).await
}

/// One non-streamed bridge `/v1/chat` turn at an explicit bridge base — the
/// #669 scheduler's entry (it holds the url/token, not a `ChatLoopConfig`).
pub(crate) async fn bridge_chat_at(
    http: &reqwest::Client,
    bridge_url: &str,
    bridge_token: Option<&str>,
    text: &str,
) -> Result<String, String> {
    let mut req = http
        .post(format!("{}/v1/chat", bridge_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(180))
        .json(&serde_json::json!({ "text": text, "stream": false }));
    if let Some(token) = bridge_token {
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
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("bridge parse: {e}"))?;
    Ok(render_jobs_doc(&v))
}

/// Render the bridge's job list as a compact device-friendly doc. Accepts
/// BOTH wire shapes — the bare array the #525 daemon expected and the
/// `{jobs: [...]}` object the dsh bridge serves (the #631 "daemon parse bug
/// guard"); a #669 scheduled entry renders with its cron + armed/denied
/// status, a #340 process job with its pgid + command.
fn render_jobs_doc(v: &serde_json::Value) -> String {
    let jobs: Vec<serde_json::Value> = match v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Object(o) => o
            .get("jobs")
            .and_then(|j| j.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    if jobs.is_empty() {
        return "No background tasks running.".to_string();
    }
    let mut out = format!("{} background task(s):\n", jobs.len());
    for j in &jobs {
        if let Some(cron) = j.get("cron").and_then(|c| c.as_str()) {
            let label = j.get("label").and_then(|l| l.as_str()).unwrap_or("?");
            let status = j.get("status").and_then(|s| s.as_str()).unwrap_or("armed");
            out.push_str(&format!("• ⏰ {label} ({cron}) — {status}\n"));
            continue;
        }
        let pgid = j.get("pgid").and_then(|v| v.as_i64()).unwrap_or(0);
        let cmd = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("?");
        // Truncate long command lines so a small device screen stays readable.
        let cmd: String = cmd.chars().take(60).collect();
        out.push_str(&format!("• [{pgid}] {cmd}\n"));
    }
    out
}

/// #563 — one minted cap, reused until near-expiry (mint TTL 300 s, refresh
/// margin 60 s). `fresh()` clones (a cap is a small serde_json::Value);
/// `invalidate()` on any worker refusal so revocation / K3-epoch rotation
/// costs one extra mint, never a stale-cap retry loop.
#[derive(Default)]
pub(crate) struct CapCache {
    slot: Option<(
        agentkeys_backend_client::protocol::CapToken,
        std::time::Instant,
    )>,
}

impl CapCache {
    const TTL: Duration = Duration::from_secs(300);
    const REFRESH_MARGIN: Duration = Duration::from_secs(60);

    fn fresh(&self) -> Option<agentkeys_backend_client::protocol::CapToken> {
        self.slot
            .as_ref()
            .filter(|(_, minted)| minted.elapsed() + Self::REFRESH_MARGIN < Self::TTL)
            .map(|(cap, _)| cap.clone())
    }

    fn store(
        &mut self,
        cap: agentkeys_backend_client::protocol::CapToken,
    ) -> agentkeys_backend_client::protocol::CapToken {
        self.slot = Some((cap.clone(), std::time::Instant::now()));
        cap
    }

    fn invalidate(&mut self) {
        self.slot = None;
    }
}

/// #563 — incremental SSE frame parser for the bridge's `/v1/chat` stream
/// (`data: {json}\n\n` frames; the bridge emits `token` / `tool` /
/// `tool_start` / `done` / `error` objects). Pure: feed chunks, get parsed
/// frames — unit-testable with no sockets.
#[derive(Default)]
struct SseParser {
    buf: String,
}

impl SseParser {
    fn feed(&mut self, chunk: &str) -> Vec<serde_json::Value> {
        self.buf.push_str(chunk);
        let mut out = Vec::new();
        while let Some(end) = self.buf.find("\n\n") {
            let frame: String = self.buf.drain(..end + 2).collect();
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                        out.push(v);
                    }
                }
            }
        }
        out
    }
}

/// #563 — token→delta coalescer. Every flush becomes one channel publish (an
/// S3 object + an envelope encrypt), so raw per-token publishing is out of the
/// question; this batches by wall-clock window (or a size backstop). Pure —
/// the clock is an argument, so tests never sleep.
struct DeltaCoalescer {
    pending: String,
    last_flush: std::time::Instant,
    interval: Duration,
}

impl DeltaCoalescer {
    const SIZE_BACKSTOP: usize = 2048;

    fn new(interval: Duration, now: std::time::Instant) -> Self {
        Self {
            pending: String::new(),
            last_flush: now,
            interval,
        }
    }

    /// Buffer `token`; `Some(delta)` when the window (or size backstop) says
    /// it is time to publish.
    fn push(&mut self, token: &str, now: std::time::Instant) -> Option<String> {
        self.pending.push_str(token);
        if self.pending.is_empty() {
            return None;
        }
        if now.duration_since(self.last_flush) >= self.interval
            || self.pending.len() >= Self::SIZE_BACKSTOP
        {
            self.last_flush = now;
            return Some(std::mem::take(&mut self.pending));
        }
        None
    }

    fn drain(&mut self) -> Option<String> {
        if self.pending.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.pending))
        }
    }
}

/// #665/#669 (R3) — the ONE publisher: any event kind to any bound pub feed
/// (or a reply on the feed a turn arrived on), with a per-channel publish-cap
/// cache (#563 reuse until near-expiry, invalidated on refusal) and the
/// #667 blob legs (a media original beside the feed, fetched by ref).
pub struct Publisher {
    http: reqwest::Client,
    cfg: Arc<ChatLoopConfig>,
    session: Arc<SessionHandle>,
    pub_caps: tokio::sync::Mutex<HashMap<String, CapCache>>,
    sub_caps: tokio::sync::Mutex<HashMap<String, CapCache>>,
}

impl Publisher {
    pub(crate) fn new(
        http: reqwest::Client,
        cfg: Arc<ChatLoopConfig>,
        session: Arc<SessionHandle>,
    ) -> Self {
        Self {
            http,
            cfg,
            session,
            pub_caps: tokio::sync::Mutex::new(HashMap::new()),
            sub_caps: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn cap_for(
        &self,
        channel_id: &str,
        publish: bool,
    ) -> Result<(agentkeys_backend_client::protocol::CapToken, String), String> {
        let caches = if publish {
            &self.pub_caps
        } else {
            &self.sub_caps
        };
        if let Some(c) = caches.lock().await.get(channel_id).and_then(|c| c.fresh()) {
            return Ok((c, String::new()));
        }
        let bearer = self.session.bearer().await?;
        let client = self.session.client(&bearer);
        let (op, service) = if publish {
            (
                CapMintOp::ChannelPublish,
                format!("channel-pub:{channel_id}"),
            )
        } else {
            (
                CapMintOp::ChannelSubscribe,
                format!("channel-sub:{channel_id}"),
            )
        };
        let minted = client
            .cap_mint(
                op,
                CapMintRequest {
                    operator_omni: self.cfg.operator_omni.clone(),
                    actor_omni: self.cfg.actor_omni.clone(),
                    service: service.clone(),
                    device_key_hash: self.session.credential.device_key_hash(),
                    ttl_seconds: 300,
                },
                &bearer,
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("401") || msg.contains("expired") {
                    let session = self.session.clone();
                    let stale = bearer.clone();
                    tokio::spawn(async move { session.invalidate(&stale).await });
                }
                format!("{service} mint: {msg}")
            })?;
        let cap = caches
            .lock()
            .await
            .entry(channel_id.to_string())
            .or_default()
            .store(minted);
        Ok((cap, bearer))
    }

    async fn invalidate_cap(&self, channel_id: &str, publish: bool) {
        let caches = if publish {
            &self.pub_caps
        } else {
            &self.sub_caps
        };
        if let Some(c) = caches.lock().await.get_mut(channel_id) {
            c.invalidate();
        }
    }

    /// Publish one `direction: out` event on `channel_id`.
    pub async fn publish(
        &self,
        channel_id: &str,
        kind: &str,
        body_b64: String,
        correlation: &str,
        partial_seq: Option<u32>,
        content_type: Option<&str>,
    ) -> Result<(), String> {
        let (pub_cap, _) = self.cap_for(channel_id, true).await?;
        // @backend-fixture: channel_publish_body — the protocol-shaped publish.
        // The #563 delta markers + the #667 content type are OPTIONAL additive
        // keys (absent on the plain reply, so the canonical fixture shape is
        // untouched).
        let mut body = serde_json::json!({
            "cap": pub_cap,
            "kind": kind,
            "direction": "out",
            "body_b64": body_b64,
            "correlation": correlation,
        });
        if let Some(seq) = partial_seq {
            body["partial"] = serde_json::json!(true);
            body["seq"] = serde_json::json!(seq);
        }
        if let Some(ct) = content_type.filter(|c| !c.is_empty()) {
            body["content_type"] = serde_json::json!(ct);
        }
        let resp = self
            .http
            .post(format!(
                "{}/v1/channel/publish",
                self.cfg.channel_worker_url.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("publish send: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                // Revoked / rotated — drop the cached cap so the next publish
                // re-mints instead of replaying a refused token (#563).
                self.invalidate_cap(channel_id, true).await;
            }
            return Err(format!("publish HTTP {status}"));
        }
        Ok(())
    }

    /// A `text` reply (`direction: out`).
    pub async fn publish_text_out(
        &self,
        channel_id: &str,
        text: &str,
        correlation: &str,
    ) -> Result<(), String> {
        self.publish(
            channel_id,
            "text",
            base64_of(text.as_bytes()),
            correlation,
            None,
            None,
        )
        .await
    }

    /// #563 — one streamed-reply DELTA (`partial: true`, ordered by `seq`).
    pub async fn publish_delta(
        &self,
        channel_id: &str,
        body_b64: String,
        correlation: &str,
        seq: u32,
    ) -> Result<(), String> {
        self.publish(channel_id, "text", body_b64, correlation, Some(seq), None)
            .await
    }

    /// Publish a body of any size on `channel_id`: inline when it fits the
    /// worker's inline ceiling, else stored beside the feed by ref (#667).
    pub async fn publish_bytes(
        &self,
        channel_id: &str,
        kind: &str,
        bytes: &[u8],
        content_type: &str,
        correlation: &str,
        inline_max: usize,
    ) -> Result<Option<String>, String> {
        if bytes.len() <= inline_max {
            self.publish(
                channel_id,
                kind,
                base64_of(bytes),
                correlation,
                None,
                Some(content_type),
            )
            .await?;
            return Ok(None);
        }
        let body_ref = self.put_blob(channel_id, content_type, bytes).await?;
        let (pub_cap, _) = self.cap_for(channel_id, true).await?;
        let body = serde_json::json!({
            "cap": pub_cap,
            "kind": kind,
            "direction": "out",
            "body_ref": body_ref,
            "correlation": correlation,
            "content_type": content_type,
        });
        let resp = self
            .http
            .post(format!(
                "{}/v1/channel/publish",
                self.cfg.channel_worker_url.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("publish send: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("publish HTTP {}", resp.status()));
        }
        Ok(Some(body_ref))
    }

    /// #667 — store a media original UNCHANGED beside the feed; returns the
    /// `body_ref` an event names.
    pub async fn put_blob(
        &self,
        channel_id: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<String, String> {
        let (pub_cap, _) = self.cap_for(channel_id, true).await?;
        let body = agentkeys_backend_client::protocol::ChannelBlobPutBody {
            cap: pub_cap,
            content_type: content_type.to_string(),
            bytes_b64: base64_of(bytes),
        };
        let resp = self
            .http
            .post(format!(
                "{}/v1/channel/blob-put",
                self.cfg.channel_worker_url.trim_end_matches('/')
            ))
            .timeout(Duration::from_secs(120))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("blob-put send: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                self.invalidate_cap(channel_id, true).await;
            }
            return Err(format!("blob-put HTTP {status}"));
        }
        let put: agentkeys_backend_client::protocol::ChannelBlobPutResp = resp
            .json()
            .await
            .map_err(|e| format!("blob-put parse: {e}"))?;
        Ok(put.body_ref)
    }

    /// #667 — fetch a media original by `body_ref` under the feed's subscribe
    /// cap → `(content_type, bytes)`.
    pub async fn fetch_blob(
        &self,
        channel_id: &str,
        body_ref: &str,
    ) -> Result<(Vec<u8>, String), String> {
        let (sub_cap, _) = self.cap_for(channel_id, false).await?;
        let body = agentkeys_backend_client::protocol::ChannelBlobGetBody {
            cap: sub_cap,
            body_ref: body_ref.to_string(),
        };
        let resp = self
            .http
            .post(format!(
                "{}/v1/channel/blob-get",
                self.cfg.channel_worker_url.trim_end_matches('/')
            ))
            .timeout(Duration::from_secs(120))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("blob-get send: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                self.invalidate_cap(channel_id, false).await;
            }
            return Err(format!("blob-get HTTP {status}"));
        }
        let got: agentkeys_backend_client::protocol::ChannelBlobGetResp = resp
            .json()
            .await
            .map_err(|e| format!("blob-get parse: {e}"))?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD
            .decode(&got.bytes_b64)
            .map_err(|e| format!("blob-get body is not valid base64: {e}"))?;
        Ok((bytes, got.content_type))
    }
}

/// #563 — one STREAMED bridge turn: consumes the bridge's `/v1/chat` SSE
/// (`token`/`tool*`/`done`/`error` frames), publishes coalesced DELTAS as it
/// goes, and returns the FULL reply text for the final publish (+ TTS reuse).
/// Delta-publish failures degrade loudly to single-shot (the final event
/// always carries the whole reply, so a lost delta never loses content).
async fn bridge_chat_stream(
    http: &reqwest::Client,
    cfg: &ChatLoopConfig,
    text: &str,
    publisher: &Publisher,
    channel_id: &str,
    correlation: &str,
) -> Result<String, String> {
    let mut req = http
        .post(format!("{}/v1/chat", cfg.bridge_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(300))
        .json(&serde_json::json!({ "text": text, "stream": true }));
    if let Some(token) = &cfg.bridge_token {
        req = req.bearer_auth(token);
    }
    let mut resp = req.send().await.map_err(|e| format!("bridge send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("bridge HTTP {}", resp.status()));
    }
    let mut parser = SseParser::default();
    let mut coalescer = DeltaCoalescer::new(
        Duration::from_millis(cfg.stream_flush_ms),
        std::time::Instant::now(),
    );
    let mut full = String::new();
    let mut seq: u32 = 0;
    let mut deltas_dead = false;
    let mut done = false;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("bridge stream read: {e}"))?
    {
        for frame in parser.feed(&String::from_utf8_lossy(&chunk)) {
            match frame.get("type").and_then(|t| t.as_str()) {
                Some("token") => {
                    let t = frame.get("text").and_then(|t| t.as_str()).unwrap_or("");
                    full.push_str(t);
                    if deltas_dead {
                        continue;
                    }
                    if let Some(delta) = coalescer.push(t, std::time::Instant::now()) {
                        if let Err(e) = publisher
                            .publish_delta(
                                channel_id,
                                base64_of(delta.as_bytes()),
                                correlation,
                                seq,
                            )
                            .await
                        {
                            // Loud downgrade, not a lost turn: stop streaming
                            // deltas and let the final single-shot carry it all.
                            tracing::warn!(error = %e, "#563 chat loop: delta publish failed — downgrading this turn to single-shot");
                            deltas_dead = true;
                        } else {
                            seq += 1;
                        }
                    }
                }
                Some("done") => {
                    done = true;
                }
                Some("error") => {
                    let msg = frame
                        .get("error")
                        .or_else(|| frame.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("stream error");
                    return Err(msg.to_string());
                }
                // tool_start / tool frames: progress noise for the transcript —
                // the deltas themselves are the progress signal here.
                _ => {}
            }
        }
        if done {
            break;
        }
    }
    if !done {
        return Err("bridge stream ended without a done frame".into());
    }
    if !deltas_dead {
        if let Some(rest) = coalescer.drain() {
            if let Err(e) = publisher
                .publish_delta(channel_id, base64_of(rest.as_bytes()), correlation, seq)
                .await
            {
                tracing::warn!(error = %e, "#563 chat loop: tail delta publish failed — final event still carries the full reply");
            }
        }
    }
    Ok(full)
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

    fn jwt_with_exp(exp: Option<u64>) -> String {
        use base64::Engine as _;
        let payload = match exp {
            Some(e) => format!("{{\"exp\":{e}}}"),
            None => "{}".to_string(),
        };
        format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signer_credential(bearer_jwt: &str) -> DelegateCredential {
        DelegateCredential::Signer {
            client: std::sync::Arc::new(agentkeys_core::signer_client::DeviceSignerClient::new(
                "http://127.0.0.1:1",
            )),
            bearer: std::sync::Arc::new(tokio::sync::RwLock::new(bearer_jwt.to_string())),
            actor_omni: format!("0x{}", "ab".repeat(32)),
            address: "0xabc".into(),
            device_key_hash: "0xdef".into(),
        }
    }

    async fn bearer_of(c: &DelegateCredential) -> String {
        match c {
            DelegateCredential::Signer { bearer, .. } => bearer.read().await.clone(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn jwt_exp_claim_reads_exp_and_rejects_garbage() {
        assert_eq!(jwt_exp_claim(&jwt_with_exp(Some(42))), Some(42));
        assert_eq!(jwt_exp_claim(&jwt_with_exp(None)), None);
        assert_eq!(jwt_exp_claim("not-a-jwt"), None);
        assert_eq!(jwt_exp_claim(""), None);
    }

    // ── the 2026-08-31 agent-i death: a short resolve J1 must not replace a
    //    longer-lived, still-valid boot J1 ─────────────────────────────────
    #[tokio::test]
    async fn on_new_session_keeps_a_longer_lived_valid_bearer() {
        let long = jwt_with_exp(Some(now_secs() + 90_000));
        let short = jwt_with_exp(Some(now_secs() + 18_000));
        let cred = signer_credential(&long);
        cred.on_new_session(&short).await;
        assert_eq!(bearer_of(&cred).await, long);
    }

    #[tokio::test]
    async fn on_new_session_adopts_a_longer_lived_bearer() {
        let short = jwt_with_exp(Some(now_secs() + 18_000));
        let long = jwt_with_exp(Some(now_secs() + 90_000));
        let cred = signer_credential(&short);
        cred.on_new_session(&long).await;
        assert_eq!(bearer_of(&cred).await, long);
    }

    #[tokio::test]
    async fn on_new_session_replaces_an_expired_bearer_even_with_a_shorter_one() {
        let expired = jwt_with_exp(Some(now_secs().saturating_sub(60)));
        let fresh_short = jwt_with_exp(Some(now_secs() + 18_000));
        let cred = signer_credential(&expired);
        cred.on_new_session(&fresh_short).await;
        assert_eq!(bearer_of(&cred).await, fresh_short);
    }

    #[tokio::test]
    async fn on_new_session_replaces_an_unreadable_bearer() {
        let cred = signer_credential("garbage");
        let fresh = jwt_with_exp(Some(now_secs() + 18_000));
        cred.on_new_session(&fresh).await;
        assert_eq!(bearer_of(&cred).await, fresh);
    }

    #[tokio::test]
    async fn on_new_session_keeps_a_valid_bearer_over_an_unreadable_incoming() {
        let valid = jwt_with_exp(Some(now_secs() + 90_000));
        let cred = signer_credential(&valid);
        cred.on_new_session("garbage").await;
        assert_eq!(bearer_of(&cred).await, valid);
    }

    // ── #563: the SSE frame parser is pure — split boundaries anywhere ──────
    #[test]
    fn sse_parser_reassembles_frames_across_arbitrary_chunk_splits() {
        let mut p = SseParser::default();
        // A frame split mid-JSON, plus two frames in one chunk.
        assert!(p.feed("data: {\"type\":\"tok").is_empty());
        let got = p.feed("en\",\"text\":\"He\"}\n\ndata: {\"type\":\"token\",\"text\":\"llo\"}\n\ndata: {\"type\":\"done\"}\n\n");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0]["text"], "He");
        assert_eq!(got[1]["text"], "llo");
        assert_eq!(got[2]["type"], "done");
        // Trailing partial stays buffered.
        assert!(p.feed("data: {\"type\":\"token\"").is_empty());
    }

    // ── #563: the coalescer flushes on the window or the size backstop ──────
    #[test]
    fn delta_coalescer_batches_by_window_and_size() {
        use std::time::{Duration as D, Instant};
        let t0 = Instant::now();
        let mut c = DeltaCoalescer::new(D::from_millis(1000), t0);
        // Inside the window: buffered, no flush.
        assert!(c.push("Hel", t0 + D::from_millis(100)).is_none());
        assert!(c.push("lo ", t0 + D::from_millis(500)).is_none());
        // Window elapsed → one delta carrying everything buffered so far.
        assert_eq!(
            c.push("world", t0 + D::from_millis(1100)).as_deref(),
            Some("Hello world")
        );
        // Size backstop fires even inside the window.
        let big = "x".repeat(DeltaCoalescer::SIZE_BACKSTOP);
        assert_eq!(
            c.push(&big, t0 + D::from_millis(1200)).as_deref(),
            Some(big.as_str())
        );
        // drain() hands back the tail exactly once.
        assert!(c.push("tail", t0 + D::from_millis(1300)).is_none());
        assert_eq!(c.drain().as_deref(), Some("tail"));
        assert!(c.drain().is_none());
    }

    // ── #563: cap reuse honors the refresh margin + invalidation ────────────
    #[test]
    fn cap_cache_reuses_until_margin_and_invalidates() {
        let mut cache = CapCache::default();
        assert!(cache.fresh().is_none());
        let cap = cache.store(serde_json::json!({"sig": "abc"}));
        assert_eq!(cache.fresh(), Some(cap));
        cache.invalidate();
        assert!(cache.fresh().is_none());
    }

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

    /// #669 — the jobs doc reads BOTH bridge shapes and renders scheduled
    /// entries with their cron + status.
    #[test]
    fn jobs_doc_reads_array_and_object_shapes() {
        assert_eq!(
            render_jobs_doc(&serde_json::json!([])),
            "No background tasks running."
        );
        assert_eq!(
            render_jobs_doc(&serde_json::json!({ "jobs": [] })),
            "No background tasks running."
        );
        let doc = render_jobs_doc(&serde_json::json!({ "jobs": [
            { "pgid": 42, "pid": 42, "cmd": "python3 long-running-thing.py --flag", "procs": 1 },
            { "id": "schedule-0-morning", "cron": "0 7 * * *", "label": "morning plan", "status": "armed" }
        ] }));
        assert!(doc.starts_with("2 background task(s):\n"));
        assert!(doc.contains("• [42] python3 long-running-thing.py --flag"));
        assert!(doc.contains("• ⏰ morning plan (0 7 * * *) — armed"));
    }

    #[test]
    fn partial_env_is_none_and_loud_not_a_panic() {
        // from_env reads process env; in the test harness none of the chat
        // vars are set, so the loop must be OFF (None) — the common daemon
        // boot outside a sandbox.
        assert!(ChatLoopConfig::from_env().is_none());
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
