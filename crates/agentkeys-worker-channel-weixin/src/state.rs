//! Gateway process state: the custodied config, the hot registry, the per-contact
//! rate limiter, an audit client, a pooled HTTP client for the feed relay, and —
//! since #418 — the RUNTIME iLink identity (token/base-url/bot-id), which the
//! parent-control admin login ceremony can swap without a process restart.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use agentkeys_core::audit::AuditClient;
use tokio::sync::watch;

use crate::config::WeixinGatewayConfig;
use crate::l3::RateLimiter;
use crate::registry::RegistryHandle;

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
        })
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

    /// Swap the runtime identity (a confirmed admin login) and signal the
    /// supervisor to restart the inbound loop on it.
    pub fn set_ilink_identity(&self, token: String, base_url: String, bot_id: String) {
        *self.ilink_token.write().expect("token lock") = Some(token);
        *self.ilink_base_url.write().expect("base lock") = base_url;
        *self.ilink_bot_id.write().expect("bot lock") = Some(bot_id);
        self.ilink_restart_tx.send_modify(|n| *n += 1);
    }

    /// Subscribe to loop-restart signals (the supervisor holds one).
    pub fn subscribe_ilink_restart(&self) -> watch::Receiver<u64> {
        self.ilink_restart_tx.subscribe()
    }
}
