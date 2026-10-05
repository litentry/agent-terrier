//! Gateway process state: the custodied config, the hot registry, the per-contact
//! rate limiter, an audit client, a pooled HTTP client for the feed relay, and —
//! since #418 — the RUNTIME iLink identity (token/base-url/bot-id), which the
//! parent-control admin login ceremony can swap without a process restart.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use agentkeys_core::audit::AuditClient;
use agentkeys_protocol::{GatewayActivityEvent, GatewayMonitorEvent};
use tokio::sync::watch;
use tracing::warn;

use crate::config::WeixinGatewayConfig;
use crate::l3::RateLimiter;
use crate::registry::RegistryHandle;

/// How many recent turns the live monitor (#1) keeps in memory. A ring — old
/// events drop off. Ephemeral by design (D13: not durable history).
const MONITOR_RING_CAP: usize = 200;

/// The in-memory ring the operator's live monitor polls (`/admin/monitor`).
#[derive(Default)]
struct MonitorRing {
    events: VecDeque<GatewayMonitorEvent>,
    next_seq: u64,
}

/// The in-flight ADMIN QR-login session (`/v1/gateway/admin/login/*`). One at a
/// time — a new `login/start` replaces it (the old QR simply goes stale).
#[derive(Debug, Clone)]
pub struct AdminLogin {
    pub login_id: String,
    /// The opaque qr token polled via `get_qrcode_status`.
    pub qrcode: String,
    /// The URL rendered as a QR in parent-control.
    pub qrcode_url: String,
    /// The CURRENT polling host (updated on a `scaned_but_redirect` IDC hop).
    pub base_url: String,
    /// A pairing number the operator typed (carried on the next status poll).
    pub pending_verify: Option<String>,
    /// #502 (plan T9): the connecting master's omni, filled server-side by the
    /// daemon proxy from the authenticated session. Recorded on `connected` —
    /// the tenant identity arrives from the session, never an env stamp.
    /// `None` = old daemon / CLI ceremony → the env-stamp path stays.
    pub operator_omni: Option<String>,
    /// A MEMBER login (2026-09-11): the QR was minted for this contact's open
    /// invite — the scan binds that contact and custodies its own bot token.
    /// `None` = the legacy owner login (secrets-file token).
    pub contact_id: Option<String>,
}

pub struct WeixinGatewayState {
    pub config: WeixinGatewayConfig,
    pub registry: RegistryHandle,
    pub rate: RateLimiter,
    pub http: reqwest::Client,
    /// `None` when `AGENTKEYS_AUDIT_WORKER_URL` is unset (audit disabled).
    pub audit: Option<AuditClient>,
    /// #667 — the gateway's OWN device actor (the feed hop identity): caps,
    /// blobs, polls, the correlation ring. Unenrolled = decision-only.
    pub device: Arc<crate::device::GatewayDevice>,
    /// Millis of the iLink loop's last successful poll (0 = never / OA-only) —
    /// surfaced on `/healthz` so the fleet board can see a stale-token stall.
    ilink_last_ok_ms: AtomicU64,
    /// Millis of the Telegram loop's last successful poll (#444; 0 = never /
    /// other transports) — the same healthz stall signal for stack ②.
    telegram_last_ok_ms: AtomicU64,
    /// #502 (plan T9 first step): the operator omni recorded at CONNECT from
    /// the authenticated master session — the runtime override of the legacy
    /// `AGENTKEYS_WEIXIN_OPERATOR_OMNI` env stamp. `None` until a session-
    /// carrying connect ceremony runs; every audit emit reads the EFFECTIVE
    /// value ([`Self::effective_operator_omni`]).
    runtime_operator_omni: RwLock<Option<String>>,
    /// #693 — the latest lifecycle stage each app published on a feed this
    /// gate delivers from (`feed id` → (stage, ts_millis)); the receipt says
    /// "still loading its knowledge" while the app is not ready.
    app_stage: RwLock<HashMap<String, (String, u64)>>,
    /// The RUNTIME iLink identity — initialized from config, swapped by the
    /// admin login ceremony. The supervisor reads these on every (re)spawn.
    /// Per-member iLink bots, keyed by contact id (`self-owner` = the owner's; the
    /// legacy secrets-file token seeds it) — see `bots.rs`.
    bots: RwLock<std::collections::BTreeMap<String, crate::bots::MemberBot>>,
    /// Bumped to make the supervisor stop the current loop and respawn with the
    /// state's CURRENT token/base-url.
    ilink_restart_tx: watch::Sender<u64>,
    /// The in-flight admin QR-login session, if any.
    pub admin_login: tokio::sync::Mutex<Option<AdminLogin>>,
    /// #722 — the Jev router tier's client (`None` = the whole-word tier only).
    /// Shared with compare-mode tasks, which answer off the turn's path.
    pub jev: Option<Arc<crate::jev::JevClient>>,
    /// #722 — numbered asks waiting for a reply, keyed `transport:id`. MEMORY
    /// ONLY (the member's original text rides here until they answer or the
    /// TTL passes; it never reaches disk or audit — D13).
    pending_asks: Mutex<HashMap<String, VecDeque<crate::jev::PendingAsk>>>,
    /// The live-monitor ring the operator polls (`/admin/monitor`, #1).
    monitor: Mutex<MonitorRing>,
    /// #722 — the last turns that consulted a model, for the router view. RAM
    /// only, like the monitor: a restart empties it. Shared with compare-mode
    /// tasks, whose answers attach to their turn when they arrive.
    pub router_log: Arc<RouterLog>,
}

/// How many model-consulting turns the router view keeps.
pub const ROUTER_LOG_CAP: usize = 30;

/// The router view's turn log: the last [`ROUTER_LOG_CAP`] model-consulting
/// turns, newest first, each numbered. A compare-mode answer can arrive before
/// its turn is recorded (the turn is recorded once its reply is decided) — it
/// waits in `early` and joins the turn then. Memory only (D13).
#[derive(Default)]
pub struct RouterLog {
    inner: Mutex<RouterLogInner>,
}

#[derive(Default)]
struct RouterLogInner {
    next_id: u64,
    ring: VecDeque<agentkeys_protocol::RouterExchange>,
    early: std::collections::BTreeMap<u64, Vec<agentkeys_protocol::RouterAnswer>>,
}

impl RouterLog {
    /// The number the next model-consulting turn is recorded under.
    pub fn next_id(&self) -> u64 {
        let mut inner = self.inner.lock().expect("router log lock");
        inner.next_id += 1;
        inner.next_id
    }

    /// Keep one model-consulting turn (newest first), with any compare-mode
    /// answers that already arrived for it.
    pub fn record(&self, mut x: agentkeys_protocol::RouterExchange) {
        let mut inner = self.inner.lock().expect("router log lock");
        if let Some(early) = inner.early.remove(&x.id) {
            x.compared.extend(early);
        }
        inner.ring.push_front(x);
        inner.ring.truncate(ROUTER_LOG_CAP);
    }

    /// A compare-mode answer for turn `id`: onto the turn when it is kept,
    /// else held until the turn is recorded (turns finish out of order, so an
    /// older id may still be in flight). The held set is bounded: the oldest
    /// ids go first.
    pub fn attach(&self, id: u64, answer: agentkeys_protocol::RouterAnswer) {
        let mut inner = self.inner.lock().expect("router log lock");
        if let Some(x) = inner.ring.iter_mut().find(|x| x.id == id) {
            x.compared.push(answer);
            return;
        }
        inner.early.entry(id).or_default().push(answer);
        while inner.early.len() > ROUTER_LOG_CAP {
            inner.early.pop_first();
        }
    }

    /// The kept turns, newest first.
    pub fn snapshot(&self) -> Vec<agentkeys_protocol::RouterExchange> {
        self.inner
            .lock()
            .expect("router log lock")
            .ring
            .iter()
            .cloned()
            .collect()
    }
}

pub type SharedWeixinGatewayState = Arc<WeixinGatewayState>;

/// A stage report older than this is ignored (a delegate that died mid-sync
/// must not brand every receipt "loading" forever).
pub const APP_STAGE_TTL_MS: u64 = 15 * 60 * 1000;

/// The receipt hint for a stage: `loading` while the app boots / restores /
/// syncs, `degraded` when its knowledge is unavailable, `None` when ready or
/// unknown. Pure over the stage word + age.
pub fn stage_hint(stage: &str, age_ms: u64) -> Option<&'static str> {
    if age_ms > APP_STAGE_TTL_MS {
        return None;
    }
    match stage {
        "booting" | "restoring" | "syncing" => Some("loading"),
        "degraded" => Some("degraded"),
        _ => None,
    }
}

impl WeixinGatewayState {
    /// #693 — remember an app's latest lifecycle stage on one of our feeds.
    pub fn note_app_stage(&self, feed: &str, stage: &str, ts_millis: u64) {
        if let Ok(mut m) = self.app_stage.write() {
            m.insert(feed.to_string(), (stage.to_string(), ts_millis));
        }
    }

    /// The receipt hint for the app behind `feed` (see [`stage_hint`]).
    pub fn app_stage_hint(&self, feed: &str, now_millis: u64) -> Option<&'static str> {
        let (stage, ts) = self.app_stage.read().ok()?.get(feed).cloned()?;
        stage_hint(&stage, now_millis.saturating_sub(ts))
    }

    pub fn build(config: WeixinGatewayConfig) -> anyhow::Result<Self> {
        let registry = RegistryHandle::load(&config.registry_file)?;
        let rate = RateLimiter::new(config.rate_max, config.rate_window_secs);
        let audit = config.audit_worker_url.as_ref().map(AuditClient::new);
        let (ilink_restart_tx, _) = watch::channel(0u64);
        let mut bots = crate::bots::BotStore::load(&config.ilink_tokens_file).bots;
        if let Some(tok) = config
            .ilink_bot_token
            .clone()
            .filter(|t| !t.trim().is_empty())
        {
            bots.entry(crate::bots::OWNER_CONTACT_ID.to_string())
                .or_insert(crate::bots::MemberBot {
                    token: tok,
                    base_url: config.ilink_base_url.clone(),
                    bot_id: String::new(),
                    user_id: String::new(),
                    connected_at_secs: 0,
                });
        }
        let bots = RwLock::new(bots);
        let device = Arc::new(crate::device::GatewayDevice::load(
            config.device.clone(),
            config.channel_worker_url.clone(),
        ));
        let jev = match (
            config.router.jev_active(),
            &config.router.gate_url,
            &config.router.gate_key,
        ) {
            (true, Some(url), Some(key)) => Some(Arc::new(crate::jev::JevClient::new(
                url,
                key,
                config.router.timeout_ms,
            ))),
            _ => None,
        };
        Ok(WeixinGatewayState {
            config,
            registry,
            rate,
            http: reqwest::Client::new(),
            audit,
            device,
            ilink_last_ok_ms: AtomicU64::new(0),
            telegram_last_ok_ms: AtomicU64::new(0),
            runtime_operator_omni: RwLock::new(None),
            app_stage: RwLock::new(HashMap::new()),
            bots,
            ilink_restart_tx,
            admin_login: tokio::sync::Mutex::new(None),
            jev,
            pending_asks: Mutex::new(HashMap::new()),
            monitor: Mutex::new(MonitorRing::default()),
            router_log: Arc::new(RouterLog::default()),
        })
    }

    /// #722 — keep one model-consulting turn for the router view (newest first).
    pub fn record_router_exchange(&self, x: agentkeys_protocol::RouterExchange) {
        self.router_log.record(x);
    }

    pub fn router_log(&self) -> Vec<agentkeys_protocol::RouterExchange> {
        self.router_log.snapshot()
    }

    /// #722 — queue a numbered ask for this contact, behind any that wait.
    /// Returns the OLDEST waiting ask's labels when this one queues behind it
    /// (`None` = this is the question the member sees now).
    pub fn queue_ask(
        &self,
        transport: &str,
        transport_id: &str,
        ask: crate::jev::PendingAsk,
    ) -> Option<Vec<String>> {
        let mut asks = self.pending_asks.lock().expect("pending asks lock");
        let queue = asks
            .entry(format!("{transport}:{transport_id}"))
            .or_default();
        let oldest = queue.front().map(|a| a.labels.clone());
        queue.push_back(ask);
        oldest
    }

    /// #722 — the next message from a contact against their ask queue. Asks
    /// that ran out are dropped first (counted, so the reply can say so). A
    /// message that answers the OLDEST live ask (a number, a channel's id or
    /// its label) → `Answered` with that ask's ORIGINAL text and media; a
    /// cancel word → `Cancelled`; anything else → `Waiting`, and the queue
    /// stays as it is.
    pub fn take_ask_reply(
        &self,
        transport: &str,
        transport_id: &str,
        text: &str,
        now_secs: u64,
    ) -> (crate::jev::AskReply, crate::jev::ExpiredAsks) {
        use crate::jev::AskReply;
        let key = format!("{transport}:{transport_id}");
        let mut asks = self.pending_asks.lock().expect("pending asks lock");
        let mut expired = crate::jev::ExpiredAsks::default();
        let Some(queue) = asks.get_mut(&key) else {
            return (AskReply::NoAsk, expired);
        };
        while queue.front().is_some_and(|a| a.expires_at_secs < now_secs) {
            if let Some(gone) = queue.pop_front() {
                expired.messages += 1;
                expired.media += gone.media.len();
            }
        }
        let oldest = queue
            .front()
            .map(|a| (a.candidates.clone(), a.labels.clone()));
        let reply = match oldest {
            None => AskReply::NoAsk,
            Some(_) if crate::jev::is_cancel(text) => {
                let gone = queue.pop_front().expect("the oldest ask");
                AskReply::Cancelled {
                    released_media: gone.media.len(),
                    next: queue.front().map(|a| a.labels.clone()),
                }
            }
            Some((candidates, labels)) => {
                match crate::jev::parse_ask_reply(text, &candidates, &labels) {
                    Some(i) => {
                        let ask = queue.pop_front().expect("the oldest ask");
                        AskReply::Answered {
                            channel: ask.candidates[i].clone(),
                            addressee: ask.addressees.get(i).cloned().flatten(),
                            original_text: ask.original_text,
                            media: ask.media,
                            description: ask.description,
                            next: queue.front().map(|a| a.labels.clone()),
                        }
                    }
                    None => AskReply::Waiting { oldest: labels },
                }
            }
        };
        if queue.is_empty() {
            asks.remove(&key);
        }
        (reply, expired)
    }

    /// #722 — a photo or clip sent while the NEWEST ask already holds media
    /// joins that batch (the same question) when it arrives within
    /// `PHOTO_BATCH_WINDOW_SECS` of that ask, so a multi-photo send is never
    /// split or lost. `Some((labels, held))` when it joined; `None` = no such
    /// ask (the turn routes on its own; waiting asks stay queued).
    pub fn hold_media_with_ask(
        &self,
        transport: &str,
        transport_id: &str,
        media: crate::media::InboundMedia,
        now_secs: u64,
    ) -> Option<(Vec<String>, usize)> {
        let key = format!("{transport}:{transport_id}");
        let mut asks = self.pending_asks.lock().expect("pending asks lock");
        let ask = asks.get_mut(&key)?.back_mut()?;
        if !crate::jev::joins_photo_batch(ask, now_secs) {
            return None;
        }
        ask.media.push(media);
        Some((ask.labels.clone(), ask.media.len()))
    }

    /// #722 — live asks across every contact's queue (healthz).
    pub fn pending_ask_count(&self) -> usize {
        self.pending_asks
            .lock()
            .expect("pending asks lock")
            .values()
            .map(VecDeque::len)
            .sum()
    }

    /// Record one inbound turn + its L3 decision in the live-monitor ring (#1).
    /// `contact` is the resolved bound `display_name` (or `"unknown"`), never an
    /// openid; `text` should already be a short preview. Assigns the seq + ts.
    #[allow(clippy::too_many_arguments)]
    pub fn push_monitor_event(
        &self,
        contact: String,
        tier: String,
        text: String,
        allowed: bool,
        reason: String,
        target: Option<String>,
        routed_by: Option<String>,
        confidence: Option<f64>,
    ) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut ring = self.monitor.lock().expect("monitor lock");
        let seq = ring.next_seq;
        ring.next_seq += 1;
        let event = GatewayMonitorEvent {
            seq,
            ts_ms,
            contact,
            tier,
            text,
            allowed,
            reason,
            target,
            routed_by,
            confidence,
        };
        ring.events.push_back(event.clone());
        while ring.events.len() > MONITOR_RING_CAP {
            ring.events.pop_front();
        }
        drop(ring);
        self.append_history(&event);
    }

    /// Durably append one turn to the append-only JSONL history log (#419 — the
    /// owner's full, restart-surviving message record + the future stats source;
    /// the ring above is only the live tail). Best-effort: a write failure warns
    /// but never blocks the relay. `0600` — the log holds message content.
    fn append_history(&self, event: &GatewayMonitorEvent) {
        Self::append_jsonl(&self.config.history_file, event, "history");
    }

    /// Append one serde value as a `0600` JSONL line (best-effort; a write
    /// failure warns but never blocks the caller). Shared by the durable message
    /// history and the control-action activity log.
    fn append_jsonl(path: &str, value: &impl serde::Serialize, kind: &str) {
        if path.is_empty() {
            return;
        }
        let Ok(mut line) = serde_json::to_string(value) else {
            return;
        };
        line.push('\n');
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(path) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(line.as_bytes()) {
                    warn!(path, kind, error = %e, "weixin jsonl append failed");
                }
            }
            Err(e) => warn!(path, kind, error = %e, "weixin jsonl open failed"),
        }
    }

    /// Record one durable control-plane action (#419) — the operator's contact
    /// audit trail (invite / claim / bound / rejected / revoked / connect). `on_chain`
    /// mirrors whether the same action was anchored on-chain (operator omni armed).
    pub fn push_activity(&self, action: &str, contact: &str, detail: &str, on_chain: bool) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self::append_jsonl(
            &self.config.activity_file,
            &GatewayActivityEvent {
                ts_ms,
                action: action.to_string(),
                contact: contact.to_string(),
                detail: detail.to_string(),
                on_chain,
            },
            "activity",
        );
    }

    /// Durable control-action audit trail, newest-first, older than `before_ts`.
    pub fn activity(&self, limit: usize, before_ts: Option<u64>) -> Vec<GatewayActivityEvent> {
        let Ok(raw) = std::fs::read_to_string(&self.config.activity_file) else {
            return Vec::new();
        };
        let mut events: Vec<GatewayActivityEvent> = raw
            .lines()
            .filter_map(|l| serde_json::from_str::<GatewayActivityEvent>(l).ok())
            .filter(|e| before_ts.map(|b| e.ts_ms < b).unwrap_or(true))
            .collect();
        // The log is append-order (chronological). Newest-first: reverse first,
        // THEN a stable sort by ts descending — so events sharing a millisecond
        // keep the reversed (later-appended = newer) order instead of flipping by
        // clock timing. (GatewayActivityEvent has no seq to tie-break on, unlike
        // the monitor; two pushes in one ms sorted oldest-first = the CI flake.)
        events.reverse();
        events.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
        events.truncate(limit);
        events
    }

    /// True when the TAMPER-PROOF on-chain audit is armed: the audit worker is
    /// wired AND the EFFECTIVE operator omni decodes to 32-byte hex. Surfaced in
    /// the status so a skipped anchor is LOUD, never silent (#419).
    pub fn audit_on_chain(&self) -> bool {
        self.audit.is_some()
            && crate::relay::decode_omni_32(&self.effective_operator_omni()).is_some()
    }

    /// #502 — the omni every audit row is keyed on: the CONNECT-recorded
    /// session omni when one exists, else the legacy env stamp
    /// (`AGENTKEYS_WEIXIN_OPERATOR_OMNI`, possibly empty/placeholder = unarmed).
    pub fn effective_operator_omni(&self) -> String {
        self.runtime_operator_omni
            .read()
            .expect("operator omni lock")
            .clone()
            .unwrap_or_else(|| self.config.operator_omni.clone())
    }

    /// Record the connecting master's omni (#502). The session value WINS —
    /// a differing armed value is exactly the stale-stamp hazard class (#464:
    /// an env omni baked from a retired namespace) — but never silently:
    /// the override is WARN-logged naming both values.
    pub fn set_runtime_operator_omni(&self, omni: &str) {
        let prior = self.effective_operator_omni();
        if crate::relay::decode_omni_32(&prior).is_some() && prior != omni {
            warn!(
                prior = %prior,
                session = %omni,
                "operator omni OVERRIDDEN at connect — the authenticated session's omni \
                 replaces the previously armed value (stale env stamp?); audit rows now \
                 key on the session omni"
            );
        }
        *self
            .runtime_operator_omni
            .write()
            .expect("operator omni lock") = Some(omni.to_string());
    }

    /// Read up to `limit` durable turns, newest first, strictly older than
    /// `before_ts` (`None` = from newest). Reads the whole JSONL log (fine for a
    /// household's volume; rotation is a follow-up if it ever grows large);
    /// unparsable lines are skipped. The oldest `ts_ms` returned is the caller's
    /// next `before_ts` for paging.
    pub fn history(&self, limit: usize, before_ts: Option<u64>) -> Vec<GatewayMonitorEvent> {
        let path = &self.config.history_file;
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        let mut events: Vec<GatewayMonitorEvent> = raw
            .lines()
            .filter_map(|l| serde_json::from_str::<GatewayMonitorEvent>(l).ok())
            .filter(|e| before_ts.map(|b| e.ts_ms < b).unwrap_or(true))
            .collect();
        events.sort_by(|a, b| b.ts_ms.cmp(&a.ts_ms).then(b.seq.cmp(&a.seq)));
        events.truncate(limit);
        events
    }

    /// Events with `seq >= after` + the next cursor (poll again with it). A fresh
    /// poll (`after = 0`) returns the whole ring.
    pub fn monitor_since(&self, after: u64) -> (u64, Vec<GatewayMonitorEvent>) {
        let ring = self.monitor.lock().expect("monitor lock");
        let events = ring
            .events
            .iter()
            .filter(|e| e.seq >= after)
            .cloned()
            .collect();
        (ring.next_seq, events)
    }

    pub fn mark_ilink_ok(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.ilink_last_ok_ms.store(now, Ordering::Relaxed);
    }

    /// `None` = never polled successfully (or the OA transport).
    pub fn ilink_last_ok_ms(&self) -> Option<u64> {
        match self.ilink_last_ok_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        }
    }

    /// Telegram twin of [`Self::mark_ilink_ok`] (#444) — the loop stamps each
    /// successful poll so healthz can show a bad-token / conflict stall.
    pub fn mark_telegram_ok(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.telegram_last_ok_ms.store(now, Ordering::Relaxed);
    }

    /// `None` = never polled successfully (or a non-telegram transport).
    pub fn telegram_last_ok_ms(&self) -> Option<u64> {
        match self.telegram_last_ok_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        }
    }

    // ── runtime iLink identity (#418 hot-swap) ───────────────────────────────

    pub fn current_ilink_token(&self) -> Option<String> {
        self.owner_or_first_bot().map(|b| b.token)
    }

    pub fn current_ilink_base_url(&self) -> String {
        self.owner_or_first_bot()
            .map(|b| b.base_url)
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| self.config.ilink_base_url.clone())
    }

    pub fn current_ilink_bot_id(&self) -> Option<String> {
        self.owner_or_first_bot()
            .map(|b| b.bot_id)
            .filter(|b| !b.is_empty())
    }

    /// True when a token is loaded (the loop runs / will run) — the `online`
    /// bit the status card shows.
    pub fn ilink_online(&self) -> bool {
        self.bots
            .read()
            .expect("bots lock")
            .values()
            .any(|b| !b.token.trim().is_empty())
    }

    /// True when THIS transport can send a reply RIGHT NOW — the honest healthz
    /// `outbound_enabled`. `config.outbound_enabled()` reads the BOOT-time token,
    /// which is `None` after an admin hot-swap login (the runtime token lives in
    /// state), so it wrongly reports `false` for a bot that is online and DOES
    /// send (the loop calls `send_text` unconditionally). Read the runtime token
    /// first; fall back to config for OA (app-secret) and boot-token iLink.
    pub fn outbound_enabled(&self) -> bool {
        self.current_ilink_token().is_some() || self.config.outbound_enabled()
    }

    /// Swap the runtime identity (a confirmed admin login) and signal the
    /// supervisor to restart the inbound loop on it.
    pub fn set_ilink_identity(
        &self,
        token: String,
        base_url: String,
        bot_id: String,
    ) -> anyhow::Result<()> {
        self.set_member_bot(
            crate::bots::OWNER_CONTACT_ID,
            crate::bots::MemberBot {
                token,
                base_url,
                bot_id,
                user_id: String::new(),
                connected_at_secs: crate::relay::unix_secs(),
            },
        )
    }
    // ── per-member bots (2026-09-11) ─────────────────────────────────────────
    fn owner_or_first_bot(&self) -> Option<crate::bots::MemberBot> {
        let bots = self.bots.read().expect("bots lock");
        bots.get(crate::bots::OWNER_CONTACT_ID)
            .or_else(|| bots.values().next())
            .cloned()
    }
    pub fn bots_snapshot(&self) -> std::collections::BTreeMap<String, crate::bots::MemberBot> {
        self.bots.read().expect("bots lock").clone()
    }
    pub fn bot_for_contact(&self, contact_id: &str) -> Option<crate::bots::MemberBot> {
        self.bots
            .read()
            .expect("bots lock")
            .get(contact_id)
            .cloned()
    }
    /// Every live token — what the login QR mint passes as `local_token_list`.
    pub fn all_ilink_tokens(&self) -> Vec<String> {
        self.bots
            .read()
            .expect("bots lock")
            .values()
            .map(|b| b.token.clone())
            .filter(|t| !t.trim().is_empty())
            .collect()
    }
    /// Insert or replace a member's bot, persist the store, restart the loops.
    /// Store (or replace) a member's bot and restart the inbound loops. The bot
    /// is LIVE either way; `Err` = its token could not be persisted (a restart
    /// drops it) — the caller surfaces that, never swallows it.
    pub fn set_member_bot(
        &self,
        contact_id: &str,
        bot: crate::bots::MemberBot,
    ) -> anyhow::Result<()> {
        self.bots
            .write()
            .expect("bots lock")
            .insert(contact_id.to_string(), bot);
        let persisted = self.persist_bots();
        self.ilink_restart_tx.send_modify(|n| *n += 1);
        persisted
    }
    pub fn remove_member_bot(&self, contact_id: &str) -> Option<crate::bots::MemberBot> {
        let removed = self.bots.write().expect("bots lock").remove(contact_id);
        if removed.is_some() {
            let _ = self.persist_bots();
            self.ilink_restart_tx.send_modify(|n| *n += 1);
        }
        removed
    }
    fn persist_bots(&self) -> anyhow::Result<()> {
        let store = crate::bots::BotStore {
            bots: self.bots_snapshot(),
        };
        if let Err(e) = store.save(&self.config.ilink_tokens_file) {
            tracing::error!(
                path = %self.config.ilink_tokens_file,
                error = %e,
                "member bot tokens NOT persisted — live for THIS process only (a restart loses them); \
                 point AGENTKEYS_WEIXIN_ILINK_TOKENS_FILE at a writable dir (the state dir)"
            );
            return Err(e);
        }
        Ok(())
    }
    /// Live bots whose token is NOT in the tokens file on disk (the file is
    /// missing, unwritable, or stale) — surfaced on the status view so a
    /// silent-until-restart loss is visible while the bots still run.
    pub fn bots_unpersisted(&self) -> u32 {
        let on_disk = crate::bots::BotStore::load(&self.config.ilink_tokens_file).bots;
        self.bots_snapshot()
            .iter()
            .filter(|(id, b)| {
                !b.token.trim().is_empty()
                    && on_disk.get(*id).map(|d| d.token != b.token).unwrap_or(true)
            })
            .count() as u32
    }
    /// The bound notice reached this contact — recorded on the registry row so
    /// it is sent exactly once (at bind when deliverable, else with the first
    /// inbound). Returns whether a row changed.
    pub fn mark_welcomed(&self, contact_id: &str) -> bool {
        self.set_welcomed(contact_id, true)
    }
    /// Set the row's `welcomed` flag (false re-arms the acknowledgement for the
    /// contact's next message). Returns whether a row changed.
    pub fn set_welcomed(&self, contact_id: &str, welcomed: bool) -> bool {
        self.registry
            .mutate(|reg| {
                let mut changed = false;
                for c in reg.bound.iter_mut().filter(|c| c.contact_id == contact_id) {
                    if c.welcomed != welcomed {
                        c.welcomed = welcomed;
                        changed = true;
                    }
                }
                Ok(changed)
            })
            .unwrap_or_else(|e| {
                tracing::warn!(contact_id, welcomed, error = %e, "welcomed flag NOT persisted");
                false
            })
    }

    /// Clear the runtime identity (operator disconnect) — the supervisor stops
    /// the inbound loop, so the bot goes OFFLINE immediately. Pair with blanking
    /// the persisted secrets token ([`crate::ilink_login::clear_secrets_file`])
    /// so a restart stays offline until the next login.
    pub fn clear_ilink_identity(&self) {
        self.remove_member_bot(crate::bots::OWNER_CONTACT_ID);
    }

    /// Subscribe to loop-restart signals (the supervisor holds one).
    pub fn subscribe_ilink_restart(&self) -> watch::Receiver<u64> {
        self.ilink_restart_tx.subscribe()
    }
}

#[cfg(test)]
mod router_log_tests {
    use super::*;
    use agentkeys_protocol::{RouterAnswer, RouterExchange};

    fn turn(id: u64) -> RouterExchange {
        RouterExchange {
            id,
            ts_ms: id,
            contact: "妈妈".into(),
            tier: "owner".into(),
            text: "今晚吃什么".into(),
            photo: false,
            last_channel: None,
            request: serde_json::Value::Null,
            probabilities: Default::default(),
            continues: None,
            verdict: "route".into(),
            routed_to: Some("family-chat".into()),
            addressee: None,
            confidence: Some(0.9),
            answered_by: "kev-9b".into(),
            describe_ms: None,
            decide_ms: Some(200),
            input_tokens: None,
            output_tokens: None,
            total_ms: 300,
            delivered: true,
            error: None,
            compared: Vec::new(),
        }
    }

    fn answer(model: &str) -> RouterAnswer {
        RouterAnswer {
            model: model.into(),
            answered_by: model.into(),
            probabilities: Default::default(),
            continues: None,
            verdict: "route".into(),
            routed_to: Some("family-chat".into()),
            addressee: None,
            confidence: Some(0.8),
            decide_ms: 650,
            input_tokens: Some(300),
            output_tokens: Some(20),
            error: None,
        }
    }

    #[test]
    fn a_compared_answer_joins_its_turn_whichever_arrives_first() {
        let log = RouterLog::default();
        let (a, b) = (log.next_id(), log.next_id());
        assert!(b > a);
        // b's turn is recorded first; a's answer arrives while a is in flight.
        log.record(turn(b));
        log.attach(a, answer("jev-1.13.0"));
        log.record(turn(a));
        // b's answer arrives after its turn.
        log.attach(b, answer("jev-1.13.0"));
        let kept = log.snapshot();
        assert_eq!(kept.iter().map(|x| x.id).collect::<Vec<_>>(), vec![a, b]);
        assert!(kept.iter().all(|x| x.compared.len() == 1), "{kept:?}");
    }

    #[test]
    fn the_log_and_the_held_answers_stay_bounded() {
        let log = RouterLog::default();
        for _ in 0..(ROUTER_LOG_CAP + 5) {
            let id = log.next_id();
            log.record(turn(id));
        }
        assert_eq!(log.snapshot().len(), ROUTER_LOG_CAP);
        for id in 1000..(1000 + 2 * ROUTER_LOG_CAP as u64) {
            log.attach(id, answer("jev-1.13.0"));
        }
        assert!(log.inner.lock().unwrap().early.len() <= ROUTER_LOG_CAP);
        // An answer for a turn long gone never lands on a kept one.
        log.attach(1, answer("jev-1.13.0"));
        assert!(log.snapshot().iter().all(|x| x.compared.is_empty()));
    }
}
