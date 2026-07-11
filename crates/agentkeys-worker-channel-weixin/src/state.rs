//! Gateway process state: the custodied config, the hot registry, the per-contact
//! rate limiter, an audit client, a pooled HTTP client for the feed relay, and —
//! since #418 — the RUNTIME iLink identity (token/base-url/bot-id), which the
//! parent-control admin login ceremony can swap without a process restart.

use std::collections::VecDeque;
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
}

pub struct WeixinGatewayState {
    pub config: WeixinGatewayConfig,
    pub registry: RegistryHandle,
    pub rate: RateLimiter,
    pub http: reqwest::Client,
    /// `None` when `AGENTKEYS_AUDIT_WORKER_URL` is unset (audit disabled).
    pub audit: Option<AuditClient>,
    /// Millis of the iLink loop's last successful poll (0 = never / OA-only) —
    /// surfaced on `/healthz` so the fleet board can see a stale-token stall.
    ilink_last_ok_ms: AtomicU64,
    /// The RUNTIME iLink identity — initialized from config, swapped by the
    /// admin login ceremony. The supervisor reads these on every (re)spawn.
    ilink_token: RwLock<Option<String>>,
    ilink_base_url: RwLock<String>,
    ilink_bot_id: RwLock<Option<String>>,
    /// Bumped to make the supervisor stop the current loop and respawn with the
    /// state's CURRENT token/base-url.
    ilink_restart_tx: watch::Sender<u64>,
    /// The in-flight admin QR-login session, if any.
    pub admin_login: tokio::sync::Mutex<Option<AdminLogin>>,
    /// The live-monitor ring the operator polls (`/admin/monitor`, #1).
    monitor: Mutex<MonitorRing>,
}

pub type SharedWeixinGatewayState = Arc<WeixinGatewayState>;

impl WeixinGatewayState {
    pub fn build(config: WeixinGatewayConfig) -> anyhow::Result<Self> {
        let registry = RegistryHandle::load(&config.registry_file)?;
        let rate = RateLimiter::new(config.rate_max, config.rate_window_secs);
        let audit = config.audit_worker_url.as_ref().map(AuditClient::new);
        let (ilink_restart_tx, _) = watch::channel(0u64);
        let ilink_token = RwLock::new(config.ilink_bot_token.clone());
        let ilink_base_url = RwLock::new(config.ilink_base_url.clone());
        Ok(WeixinGatewayState {
            config,
            registry,
            rate,
            http: reqwest::Client::new(),
            audit,
            ilink_last_ok_ms: AtomicU64::new(0),
            ilink_token,
            ilink_base_url,
            ilink_bot_id: RwLock::new(None),
            ilink_restart_tx,
            admin_login: tokio::sync::Mutex::new(None),
            monitor: Mutex::new(MonitorRing::default()),
        })
    }

    /// Record one inbound turn + its L3 decision in the live-monitor ring (#1).
    /// `contact` is the resolved bound `display_name` (or `"unknown"`), never an
    /// openid; `text` should already be a short preview. Assigns the seq + ts.
    pub fn push_monitor_event(
        &self,
        contact: String,
        tier: String,
        text: String,
        allowed: bool,
        reason: String,
        target: Option<String>,
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
    /// wired AND the operator omni decodes to 32-byte hex. Surfaced in the status
    /// so a skipped anchor is LOUD, never silent (#419).
    pub fn audit_on_chain(&self) -> bool {
        self.audit.is_some() && crate::relay::decode_omni_32(&self.config.operator_omni).is_some()
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

    // ── runtime iLink identity (#418 hot-swap) ───────────────────────────────

    pub fn current_ilink_token(&self) -> Option<String> {
        self.ilink_token.read().expect("token lock").clone()
    }

    pub fn current_ilink_base_url(&self) -> String {
        self.ilink_base_url.read().expect("base lock").clone()
    }

    pub fn current_ilink_bot_id(&self) -> Option<String> {
        self.ilink_bot_id.read().expect("bot lock").clone()
    }

    /// True when a token is loaded (the loop runs / will run) — the `online`
    /// bit the status card shows.
    pub fn ilink_online(&self) -> bool {
        self.ilink_token
            .read()
            .expect("token lock")
            .as_deref()
            .is_some_and(|t| !t.trim().is_empty())
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
    pub fn set_ilink_identity(&self, token: String, base_url: String, bot_id: String) {
        *self.ilink_token.write().expect("token lock") = Some(token);
        *self.ilink_base_url.write().expect("base lock") = base_url;
        *self.ilink_bot_id.write().expect("bot lock") = Some(bot_id);
        self.ilink_restart_tx.send_modify(|n| *n += 1);
    }

    /// Clear the runtime identity (operator disconnect) — the supervisor stops
    /// the inbound loop, so the bot goes OFFLINE immediately. Pair with blanking
    /// the persisted secrets token ([`crate::ilink_login::clear_secrets_file`])
    /// so a restart stays offline until the next login.
    pub fn clear_ilink_identity(&self) {
        *self.ilink_token.write().expect("token lock") = None;
        *self.ilink_bot_id.write().expect("bot lock") = None;
        self.ilink_restart_tx.send_modify(|n| *n += 1);
    }

    /// Subscribe to loop-restart signals (the supervisor holds one).
    pub fn subscribe_ilink_restart(&self) -> watch::Receiver<u64> {
        self.ilink_restart_tx.subscribe()
    }
}
