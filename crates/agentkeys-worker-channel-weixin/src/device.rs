//! #667 — the gateway's OWN device actor: the identity the feed hop rides.
//!
//! Before this module the gateway BUILT a routed `ChannelEvent` for an allowed
//! turn and stopped ("feed hop pending") — nothing ever reached a delegate's
//! feed, because the gateway had no actor to mint a channel cap as. Under
//! arch.md §6.4 every machine that touches the channel plane is ONE device
//! actor with its own K10 (`AGENTKEYS_WEIXIN_DEVICE_KEY_FILE`, generated on
//! this host, never leaves it — D3) and an HDKD child omni the master binds
//! through the ordinary §10.2 pairing ceremony (this module's
//! [`GatewayDevice::pairing_request`] / [`GatewayDevice::pairing_complete`]
//! are the device-side halves; the daemon drives the master's claim + the ONE
//! Touch ID). The gateway holds NO grant of its own at enroll time: each app
//! install's batch grants THIS actor pub + sub on the app's messaging feed
//! (`<transport>-<label>`), so a contact's turn lands on a feed the master
//! explicitly opened, and the app's reply comes back down the same feed.
//!
//! The device persists only coordinates + relay bookkeeping in a `0600` JSON
//! beside the transport state files: the actor omni, per-feed poll cursors
//! (a restart never replays history back to a phone), the inbound-event →
//! contact correlation ring (a reply finds its addressee), and each contact's
//! last routed alias (caption-less photos follow the conversation).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentkeys_backend_client::BackendClient;
use agentkeys_core::device_crypto::DeviceKey;
use agentkeys_protocol::{
    CapMintOp, CapMintRequest, ChannelEvent, ChannelEventKind, ChannelPollResp, ContactStamp,
};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::DeviceConfig;

/// How many inbound-event → contact rows the correlation ring keeps.
const CORRELATION_RING_CAP: usize = 2000;
/// Minted channel caps are reused this long (the broker default TTL is longer;
/// a 401/403 on use invalidates early).
const CAP_CACHE_SECS: u64 = 240;
const CAP_TTL_SECS: u64 = 600;

/// The persisted device coordinates + relay bookkeeping.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevicePersist {
    #[serde(default)]
    pub actor_omni: Option<String>,
    #[serde(default)]
    pub device_key_hash: Option<String>,
    #[serde(default)]
    pub device_pubkey: Option<String>,
    #[serde(default)]
    pub enrolled_at: Option<u64>,
    /// The broker the enrollment happened against — an omni is per stack
    /// (#464), so a device enrolled on one broker is NOT enrolled on another.
    #[serde(default)]
    pub broker_url: Option<String>,
    /// `<feed>` → the last delivered poll cursor.
    #[serde(default)]
    pub feed_cursors: HashMap<String, String>,
    #[serde(default)]
    pub correlations: VecDeque<CorrelationRow>,
    /// `<transport>:<transport_id>` → the alias the contact last reached.
    #[serde(default)]
    pub last_alias: HashMap<String, String>,
}

/// One relayed inbound turn: which contact it came from (so the app's reply,
/// correlated to this event id, goes back to that contact).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRow {
    pub event_id: String,
    pub channel_id: String,
    pub transport: String,
    pub transport_id: String,
    pub ts: u64,
}

/// The device-side pairing halves speak the protocol's shapes (the daemon is
/// the other party).
pub use agentkeys_protocol::{
    GatewayDevicePairingDone as PairingDone, GatewayDevicePairingStart as PairingStart,
};

/// One publish onto a feed (the protocol `ChannelPublishBody` shape, built
/// here from typed parts — exactly one of `body_b64` / `body_ref`).
#[derive(Debug, Clone, Default)]
pub struct PublishArgs {
    pub kind: Option<ChannelEventKind>,
    pub body_b64: Option<String>,
    pub body_ref: Option<String>,
    pub content_type: Option<String>,
    pub contact: Option<ContactStamp>,
    pub relay_of: Option<String>,
    pub correlation: Option<String>,
}

pub struct GatewayDevice {
    cfg: DeviceConfig,
    channel_worker_url: Option<String>,
    persist: Mutex<DevicePersist>,
    key: Mutex<Option<Arc<DeviceKey>>>,
    session: tokio::sync::Mutex<Option<(String, u64)>>,
    caps: tokio::sync::Mutex<HashMap<String, (serde_json::Value, u64)>>,
    http: reqwest::Client,
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn norm(u: &str) -> String {
    u.trim().trim_end_matches('/').to_string()
}

impl GatewayDevice {
    /// Load the persisted coordinates (missing file = never enrolled). An
    /// enrollment recorded against a DIFFERENT broker is ignored (the omni
    /// tree is per stack) — loudly, so a stack swap is not a silent unbind.
    pub fn load(cfg: DeviceConfig, channel_worker_url: Option<String>) -> Self {
        let mut persist = DevicePersist::default();
        if !cfg.state_file.is_empty() {
            if let Ok(raw) = std::fs::read_to_string(&cfg.state_file) {
                match serde_json::from_str::<DevicePersist>(&raw) {
                    Ok(p) => persist = p,
                    Err(e) => {
                        warn!(path = %cfg.state_file, error = %e, "contact gate device state unparsable — starting fresh")
                    }
                }
            }
        }
        if let (Some(mine), Some(theirs)) =
            (cfg.broker_url.as_deref(), persist.broker_url.as_deref())
        {
            if norm(mine) != norm(theirs) && persist.actor_omni.is_some() {
                warn!(
                    enrolled_on = %theirs,
                    configured = %mine,
                    "contact gate device was enrolled on a DIFFERENT broker — treating as NOT enrolled \
                     (an omni is per stack); re-enroll from parent-control"
                );
                persist.actor_omni = None;
                persist.enrolled_at = None;
            }
        }
        GatewayDevice {
            cfg,
            channel_worker_url,
            persist: Mutex::new(persist),
            key: Mutex::new(None),
            session: tokio::sync::Mutex::new(None),
            caps: tokio::sync::Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn configured(&self) -> bool {
        self.cfg.broker_url.is_some() && !self.cfg.key_file.is_empty()
    }

    pub fn broker_url(&self) -> Option<String> {
        self.cfg.broker_url.clone()
    }

    pub fn channel_worker_url(&self) -> Option<String> {
        self.channel_worker_url.clone()
    }

    pub fn cfg(&self) -> &DeviceConfig {
        &self.cfg
    }

    pub fn enrolled(&self) -> bool {
        self.persist
            .lock()
            .expect("device lock")
            .actor_omni
            .is_some()
    }

    pub fn actor_omni(&self) -> Option<String> {
        self.persist.lock().expect("device lock").actor_omni.clone()
    }

    pub fn device_key_hash(&self) -> Option<String> {
        self.persist
            .lock()
            .expect("device lock")
            .device_key_hash
            .clone()
    }

    /// Why the feed hop cannot run right now (`None` = it can).
    pub fn hop_blocker(&self) -> Option<&'static str> {
        if self.channel_worker_url.is_none() {
            return Some(
                "no channel worker configured (AGENTKEYS_WORKER_CHANNEL_URL) — decision-only",
            );
        }
        if !self.configured() {
            return Some("contact gate device not configured (AGENTKEYS_BROKER_URL / AGENTKEYS_WEIXIN_DEVICE_KEY_FILE)");
        }
        if !self.enrolled() {
            return Some(
                "contact gate device not enrolled — enroll it from parent-control (微信网关 → 网关身份)",
            );
        }
        None
    }

    fn key(&self) -> anyhow::Result<Arc<DeviceKey>> {
        if let Some(k) = self.key.lock().expect("key lock").clone() {
            return Ok(k);
        }
        if self.cfg.key_file.is_empty() {
            return Err(anyhow!(
                "AGENTKEYS_WEIXIN_DEVICE_KEY_FILE is not configured"
            ));
        }
        let k = Arc::new(
            DeviceKey::load_or_generate(&self.cfg.key_file, false)
                .with_context(|| format!("contact gate K10 {}", self.cfg.key_file))?,
        );
        *self.key.lock().expect("key lock") = Some(k.clone());
        Ok(k)
    }

    fn save(&self) {
        if self.cfg.state_file.is_empty() {
            return;
        }
        let raw = match serde_json::to_string(&*self.persist.lock().expect("device lock")) {
            Ok(r) => r,
            Err(_) => return,
        };
        let tmp = format!("{}.tmp", self.cfg.state_file);
        if let Some(dir) = std::path::Path::new(&self.cfg.state_file).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(&tmp, &raw) {
            warn!(path = %self.cfg.state_file, error = %e, "contact gate device state write failed");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = std::fs::rename(&tmp, &self.cfg.state_file) {
            warn!(path = %self.cfg.state_file, error = %e, "contact gate device state rename failed");
        }
    }

    // ── enrollment (the device-side halves of §10.2) ─────────────────────────

    /// Step 1 (device side): mint the pairing code at the broker with THIS
    /// host's K10. The daemon (master) claims it + builds the accept.
    pub async fn pairing_request(&self) -> anyhow::Result<PairingStart> {
        let broker =
            self.cfg.broker_url.clone().ok_or_else(|| {
                anyhow!("AGENTKEYS_BROKER_URL is not configured on the contact gate")
            })?;
        let key = self.key()?;
        let device_pubkey = key.address().to_string();
        let device_key_hash = key.device_key_hash()?;
        let pop_sig = key.pop_sig()?;
        let resp = self
            .http
            .post(format!("{}/v1/agent/pairing/request", norm(&broker)))
            .json(&serde_json::json!({ "device_pubkey": device_pubkey, "pop_sig": pop_sig }))
            .send()
            .await
            .context("pairing request")?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("pairing request HTTP {status}: {body}");
        }
        let request_id = body
            .get("request_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("pairing request returned no request_id"))?
            .to_string();
        let pairing_code = body
            .get("pairing_code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("pairing request returned no pairing_code"))?
            .to_string();
        {
            let mut p = self.persist.lock().expect("device lock");
            p.device_key_hash = Some(device_key_hash.clone());
            p.device_pubkey = Some(device_pubkey.clone());
        }
        self.save();
        Ok(PairingStart {
            ok: true,
            request_id,
            pairing_code,
            device_pubkey,
            device_key_hash,
            pop_sig,
        })
    }

    /// Step 2 (device side, after the master's accept CONFIRMED): poll the
    /// pairing for the device session, record the actor omni. A poll that is
    /// not ready yet (the broker's own accept/ack ordering) falls back to the
    /// resolve path, which reads the binding from the chain.
    pub async fn pairing_complete(&self, request_id: &str) -> anyhow::Result<PairingDone> {
        let broker =
            self.cfg.broker_url.clone().ok_or_else(|| {
                anyhow!("AGENTKEYS_BROKER_URL is not configured on the contact gate")
            })?;
        let key = self.key()?;
        let device_pubkey = key.address().to_string();
        let device_key_hash = key.device_key_hash()?;
        let mut proven = false;
        let mut actor_omni: Option<String> = None;
        let mut session: Option<String> = None;
        for _ in 0..8 {
            let pop_sig = key.pop_sig()?;
            let resp = self
                .http
                .post(format!("{}/v1/agent/pairing/poll", norm(&broker)))
                .json(&serde_json::json!({
                    "request_id": request_id,
                    "device_pubkey": device_pubkey,
                    "pop_sig": pop_sig,
                }))
                .send()
                .await
                .context("pairing poll")?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            if status.is_success() {
                proven = true;
                session = body
                    .get("session_jwt")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                actor_omni = body
                    .get("actor_omni")
                    .or_else(|| body.get("child_omni"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                break;
            }
            if status.as_u16() == 202 || status.as_u16() == 404 || status.as_u16() == 409 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            anyhow::bail!("pairing poll HTTP {status}: {body}");
        }
        if actor_omni.is_none() {
            // The chain-read path: resolve names the actor the K10 is bound to.
            match self.resolve(&broker, &key).await {
                Ok((jwt, omni)) => {
                    session = Some(jwt);
                    actor_omni = omni;
                }
                Err(e) => warn!(error = %e, "contact gate device resolve after pairing failed"),
            }
        }
        let actor_omni = actor_omni.ok_or_else(|| {
            anyhow!("the binding is not visible yet (pairing poll not ready, resolve returned no actor) — retry in a moment")
        })?;
        {
            let mut p = self.persist.lock().expect("device lock");
            p.actor_omni = Some(actor_omni.clone());
            p.device_key_hash = Some(device_key_hash.clone());
            p.device_pubkey = Some(device_pubkey.clone());
            p.enrolled_at = Some(unix_secs());
            p.broker_url = Some(broker.clone());
        }
        self.save();
        if let Some(jwt) = session {
            let exp = jwt_exp(&jwt).unwrap_or(unix_secs() + 3600);
            *self.session.lock().await = Some((jwt, exp));
        }
        info!(actor_omni = %actor_omni, "contact gate device ENROLLED — feed hop armed");
        Ok(PairingDone {
            ok: true,
            actor_omni,
            device_key_hash,
            device_pubkey,
            session_proven: proven,
        })
    }

    async fn resolve(
        &self,
        broker: &str,
        key: &DeviceKey,
    ) -> anyhow::Result<(String, Option<String>)> {
        let resp = self
            .http
            .post(format!("{}/v1/agent/resolve", norm(broker)))
            .json(&serde_json::json!({
                "device_pubkey": key.address(),
                "pop_sig": key.pop_sig()?,
                "is_device": true,
            }))
            .send()
            .await
            .context("device resolve")?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("device resolve HTTP {status}: {body}");
        }
        let jwt = body
            .get("session_jwt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("resolve returned no session_jwt"))?
            .to_string();
        let omni = body
            .get("actor_omni")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok((jwt, omni))
    }

    /// The device session (`J1_agent` for the gateway actor), resolved from the
    /// K10 and cached until near expiry.
    pub async fn session(&self) -> anyhow::Result<String> {
        let now = unix_secs();
        if let Some((jwt, exp)) = self.session.lock().await.clone() {
            if exp > now + 60 {
                return Ok(jwt);
            }
        }
        let broker = self
            .cfg
            .broker_url
            .clone()
            .ok_or_else(|| anyhow!("AGENTKEYS_BROKER_URL is not configured"))?;
        let key = self.key()?;
        let (jwt, omni) = self.resolve(&broker, &key).await?;
        if let Some(o) = omni {
            let mut p = self.persist.lock().expect("device lock");
            if p.actor_omni.as_deref() != Some(o.as_str()) {
                p.actor_omni = Some(o);
                drop(p);
                self.save();
            }
        }
        let exp = jwt_exp(&jwt).unwrap_or(now + 3600);
        *self.session.lock().await = Some((jwt.clone(), exp));
        Ok(jwt)
    }

    // ── caps + the feed hop ──────────────────────────────────────────────────

    /// A channel cap for `channel_id` in one direction, minted as THIS device
    /// actor (K10 PoP-signed) and cached briefly.
    pub async fn cap(
        &self,
        operator_omni: &str,
        channel_id: &str,
        publish: bool,
    ) -> anyhow::Result<serde_json::Value> {
        let cache_key = format!("{}:{channel_id}", if publish { "pub" } else { "sub" });
        let now = unix_secs();
        if let Some((cap, minted)) = self.caps.lock().await.get(&cache_key) {
            if now.saturating_sub(*minted) < CAP_CACHE_SECS {
                return Ok(cap.clone());
            }
        }
        let broker = self
            .cfg
            .broker_url
            .clone()
            .ok_or_else(|| anyhow!("AGENTKEYS_BROKER_URL is not configured"))?;
        let actor_omni = self
            .actor_omni()
            .ok_or_else(|| anyhow!("contact gate device not enrolled"))?;
        let key = self.key()?;
        let device_key_hash = key.device_key_hash()?;
        let jwt = self.session().await?;
        let client = BackendClient::new(
            Some(broker),
            None,
            None,
            None,
            Some(jwt.clone()),
            None,
            None,
            String::new(),
        )
        .with_device_key(key);
        let (op, service) = if publish {
            (
                CapMintOp::ChannelPublish,
                agentkeys_protocol::service_channel_pub(channel_id),
            )
        } else {
            (
                CapMintOp::ChannelSubscribe,
                agentkeys_protocol::service_channel_sub(channel_id),
            )
        };
        let cap = client
            .cap_mint(
                op,
                CapMintRequest {
                    operator_omni: operator_omni.to_string(),
                    actor_omni,
                    service: service.clone(),
                    device_key_hash,
                    ttl_seconds: CAP_TTL_SECS,
                },
                &jwt,
            )
            .await
            .map_err(|e| anyhow!("cap mint {service}: {e}"))?;
        let cap = serde_json::to_value(&cap).context("cap serialize")?;
        self.caps.lock().await.insert(cache_key, (cap.clone(), now));
        Ok(cap)
    }

    pub async fn invalidate_cap(&self, channel_id: &str, publish: bool) {
        let cache_key = format!("{}:{channel_id}", if publish { "pub" } else { "sub" });
        self.caps.lock().await.remove(&cache_key);
    }

    fn worker(&self) -> anyhow::Result<String> {
        self.channel_worker_url
            .as_deref()
            .map(norm)
            .ok_or_else(|| anyhow!("AGENTKEYS_WORKER_CHANNEL_URL is not configured"))
    }

    /// Publish one `direction: in` event on `channel_id` as this device actor.
    /// Returns the worker-assigned event id.
    pub async fn publish(
        &self,
        operator_omni: &str,
        channel_id: &str,
        args: PublishArgs,
    ) -> anyhow::Result<String> {
        let worker = self.worker()?;
        for attempt in 0..2 {
            let cap = self.cap(operator_omni, channel_id, true).await?;
            // @backend-fixture: channel_publish_body — the protocol-shaped publish
            // (the #667 keys are OPTIONAL additive: contact / content_type /
            // relay_of / body_ref ride only when set).
            let mut body = serde_json::json!({
                "cap": cap,
                "kind": args.kind.unwrap_or(ChannelEventKind::Text),
                "direction": "in",
            });
            if let Some(b) = &args.body_b64 {
                body["body_b64"] = serde_json::json!(b);
            }
            if let Some(r) = &args.body_ref {
                body["body_ref"] = serde_json::json!(r);
            }
            if let Some(c) = &args.correlation {
                body["correlation"] = serde_json::json!(c);
            }
            if let Some(c) = &args.contact {
                body["contact"] = serde_json::json!(c);
            }
            if let Some(ct) = &args.content_type {
                body["content_type"] = serde_json::json!(ct);
            }
            if let Some(r) = &args.relay_of {
                body["relay_of"] = serde_json::json!(r);
            }
            let resp = self
                .http
                .post(format!("{worker}/v1/channel/publish"))
                .json(&body)
                .send()
                .await
                .context("channel publish")?;
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                self.invalidate_cap(channel_id, true).await;
                if attempt == 0 {
                    continue;
                }
            }
            if !status.is_success() {
                anyhow::bail!("channel publish HTTP {status}: {text}");
            }
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            return v
                .get("event_id")
                .and_then(|e| e.as_str())
                .map(str::to_string)
                .ok_or_else(|| anyhow!("publish returned no event_id: {text}"));
        }
        Err(anyhow!("channel publish refused twice (cap)"))
    }

    /// Store one media original beside the feed (`/v1/channel/blob-put`),
    /// returning the `body_ref` the event names.
    pub async fn put_blob(
        &self,
        operator_omni: &str,
        channel_id: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> anyhow::Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let worker = self.worker()?;
        let cap = self.cap(operator_omni, channel_id, true).await?;
        // @backend-fixture: channel_blob_put_body
        let body = serde_json::json!({
            "cap": cap,
            "content_type": content_type,
            "bytes_b64": STANDARD.encode(bytes),
        });
        let resp = self
            .http
            .post(format!("{worker}/v1/channel/blob-put"))
            .json(&body)
            .send()
            .await
            .context("channel blob-put")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            self.invalidate_cap(channel_id, true).await;
        }
        if !status.is_success() {
            anyhow::bail!("channel blob-put HTTP {status}: {text}");
        }
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        v.get("body_ref")
            .and_then(|r| r.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("blob-put returned no body_ref: {text}"))
    }

    /// Poll a feed as this device actor (its subscribe grant), returning the
    /// events after `after` + the next cursor.
    pub async fn poll(
        &self,
        operator_omni: &str,
        channel_id: &str,
        after: &str,
        wait_seconds: u64,
    ) -> anyhow::Result<(Vec<ChannelEvent>, String)> {
        let worker = self.worker()?;
        let cap = self.cap(operator_omni, channel_id, false).await?;
        // @backend-fixture: channel_poll_body
        let body = serde_json::json!({
            "cap": cap,
            "after": after,
            "wait_seconds": wait_seconds,
        });
        let resp = self
            .http
            .post(format!("{worker}/v1/channel/poll"))
            .timeout(Duration::from_secs(wait_seconds + 20))
            .json(&body)
            .send()
            .await
            .context("channel poll")?;
        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            self.invalidate_cap(channel_id, false).await;
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("channel poll HTTP {status}: {text}");
        }
        let parsed: ChannelPollResp = resp.json().await.context("poll decode")?;
        Ok((parsed.events, parsed.cursor))
    }

    // ── relay bookkeeping ────────────────────────────────────────────────────

    pub fn remember_correlation(
        &self,
        event_id: &str,
        channel_id: &str,
        transport: &str,
        transport_id: &str,
    ) {
        {
            let mut p = self.persist.lock().expect("device lock");
            p.correlations.push_back(CorrelationRow {
                event_id: event_id.to_string(),
                channel_id: channel_id.to_string(),
                transport: transport.to_string(),
                transport_id: transport_id.to_string(),
                ts: unix_secs(),
            });
            while p.correlations.len() > CORRELATION_RING_CAP {
                p.correlations.pop_front();
            }
        }
        self.save();
    }

    pub fn lookup_correlation(&self, event_id: &str) -> Option<CorrelationRow> {
        self.persist
            .lock()
            .expect("device lock")
            .correlations
            .iter()
            .rev()
            .find(|r| r.event_id == event_id)
            .cloned()
    }

    pub fn set_last_alias(&self, transport: &str, transport_id: &str, alias: &str) {
        let key = format!("{transport}:{transport_id}");
        let changed = {
            let mut p = self.persist.lock().expect("device lock");
            p.last_alias.get(&key).map(String::as_str) != Some(alias) && {
                p.last_alias.insert(key, alias.to_string());
                true
            }
        };
        if changed {
            self.save();
        }
    }

    pub fn last_alias(&self, transport: &str, transport_id: &str) -> Option<String> {
        self.persist
            .lock()
            .expect("device lock")
            .last_alias
            .get(&format!("{transport}:{transport_id}"))
            .cloned()
    }

    pub fn cursor(&self, feed: &str) -> Option<String> {
        self.persist
            .lock()
            .expect("device lock")
            .feed_cursors
            .get(feed)
            .cloned()
    }

    pub fn set_cursor(&self, feed: &str, cursor: &str) {
        {
            let mut p = self.persist.lock().expect("device lock");
            p.feed_cursors.insert(feed.to_string(), cursor.to_string());
        }
        self.save();
    }
}

/// The `exp` claim of a JWT (unverified read — only for cache expiry).
fn jwt_exp(jwt: &str) -> Option<u64> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("exp").and_then(|e| e.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(state_file: &str) -> DeviceConfig {
        DeviceConfig {
            broker_url: Some("https://broker.example".into()),
            // Never touched by these tests (only `pairing_request` generates it).
            key_file: "/nonexistent/gw-device-test.key".into(),
            state_file: state_file.to_string(),
            ilink_cdn_base_url: None,
            media_max_bytes: 1024,
            outbound_enabled: true,
        }
    }

    #[test]
    fn unconfigured_device_reports_the_blocker_and_never_writes() {
        let d = GatewayDevice::load(DeviceConfig::default(), None);
        assert!(!d.configured() && !d.enrolled());
        assert!(d.hop_blocker().unwrap().contains("no channel worker"));
        let d = GatewayDevice::load(DeviceConfig::default(), Some("http://w".into()));
        assert!(d.hop_blocker().unwrap().contains("not configured"));
        d.set_last_alias("weixin", "wxid-1", "chef");
        assert_eq!(d.last_alias("weixin", "wxid-1").as_deref(), Some("chef"));
    }

    #[test]
    fn persist_roundtrips_and_a_foreign_broker_unenrolls() {
        let dir = std::env::temp_dir().join(format!("gw-device-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json").to_string_lossy().to_string();
        let d = GatewayDevice::load(cfg(&path), Some("http://w".into()));
        assert!(d.hop_blocker().unwrap().contains("not enrolled"));
        d.remember_correlation("ev-1", "weixin-chef", "weixin", "wxid-1");
        d.set_cursor("weixin-chef", "k-9");
        {
            let mut p = d.persist.lock().unwrap();
            p.actor_omni = Some("0xabc".into());
            p.broker_url = Some("https://broker.example".into());
        }
        d.save();
        let back = GatewayDevice::load(cfg(&path), Some("http://w".into()));
        assert!(back.enrolled());
        assert!(back.hop_blocker().is_none());
        assert_eq!(
            back.lookup_correlation("ev-1").unwrap().transport_id,
            "wxid-1"
        );
        assert_eq!(back.cursor("weixin-chef").as_deref(), Some("k-9"));
        let mut other = cfg(&path);
        other.broker_url = Some("https://other.example".into());
        let foreign = GatewayDevice::load(other, Some("http://w".into()));
        assert!(
            !foreign.enrolled(),
            "an enrollment is per broker (per-stack omni)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn jwt_exp_reads_the_claim() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1700000000}"#);
        assert_eq!(jwt_exp(&format!("h.{payload}.s")), Some(1_700_000_000));
        assert_eq!(jwt_exp("garbage"), None);
    }
}

#[cfg(test)]
mod persist_tests {
    use super::*;
    use crate::config::DeviceConfig;

    fn state_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ak-gw-device-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.json").to_string_lossy().to_string()
    }

    fn cfg(state_file: &str, broker: Option<&str>, key_file: &str) -> DeviceConfig {
        DeviceConfig {
            broker_url: broker.map(str::to_string),
            key_file: key_file.to_string(),
            state_file: state_file.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn hop_blocker_names_the_missing_leg_in_order() {
        let d = GatewayDevice::load(cfg("", None, ""), None);
        assert!(!d.configured());
        assert!(d.hop_blocker().unwrap().contains("no channel worker"));
        let d = GatewayDevice::load(cfg("", None, ""), Some("https://channel.example".into()));
        assert!(d.hop_blocker().unwrap().contains("not configured"));
        let d = GatewayDevice::load(
            cfg("", Some("https://broker.example/"), "/tmp/k10.key"),
            Some("https://channel.example/".into()),
        );
        assert!(d.configured());
        assert!(!d.enrolled());
        assert!(d.hop_blocker().unwrap().contains("not enrolled"));
        assert_eq!(d.broker_url().as_deref(), Some("https://broker.example/"));
        assert_eq!(
            d.channel_worker_url().as_deref(),
            Some("https://channel.example/")
        );
        assert_eq!(d.cfg().key_file, "/tmp/k10.key");
    }

    #[test]
    fn state_file_round_trips_and_a_foreign_broker_unenrolls() {
        let state = state_path("rt");
        let persisted = DevicePersist {
            actor_omni: Some("0xabc".into()),
            device_key_hash: Some("0xdkh".into()),
            device_pubkey: Some("0xpub".into()),
            enrolled_at: Some(1),
            broker_url: Some("https://broker.example/".into()),
            ..Default::default()
        };
        std::fs::write(&state, serde_json::to_string(&persisted).unwrap()).unwrap();
        // The same broker (trailing slash normalized) ⇒ enrolled, hop armed.
        let d = GatewayDevice::load(
            cfg(&state, Some("https://broker.example"), "/tmp/k10.key"),
            Some("https://channel.example".into()),
        );
        assert!(d.enrolled());
        assert_eq!(d.actor_omni().as_deref(), Some("0xabc"));
        assert_eq!(d.device_key_hash().as_deref(), Some("0xdkh"));
        assert!(d.hop_blocker().is_none());
        // Correlations persist through save() and survive a reload.
        d.remember_correlation("evt-1", "weixin-chef", "weixin", "openid-1");
        let again = GatewayDevice::load(
            cfg(&state, Some("https://broker.example"), "/tmp/k10.key"),
            None,
        );
        let row = again
            .lookup_correlation("evt-1")
            .expect("correlation persisted");
        assert_eq!(row.channel_id, "weixin-chef");
        assert_eq!(row.transport, "weixin");
        assert_eq!(row.transport_id, "openid-1");
        assert!(again.lookup_correlation("evt-404").is_none());
        assert!(again.enrolled(), "the reload keeps the enrollment");
        // A DIFFERENT broker ⇒ treated as NOT enrolled (an omni is per stack).
        let d = GatewayDevice::load(
            cfg(&state, Some("https://other.example"), "/tmp/k10.key"),
            None,
        );
        assert!(!d.enrolled());
        assert!(d.actor_omni().is_none());
        // Garbage on disk ⇒ a fresh, un-enrolled device (never a crash).
        std::fs::write(&state, "{not json").unwrap();
        let d = GatewayDevice::load(
            cfg(&state, Some("https://broker.example"), "/tmp/k10.key"),
            None,
        );
        assert!(!d.enrolled());
    }
}
