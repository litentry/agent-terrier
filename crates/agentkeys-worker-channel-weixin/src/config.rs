//! Gateway config + credential custody (#384 pattern). The ONE WeChat bot
//! credential is read ONCE at boot from env / a `0600` secret file and never
//! leaves this process — a delegate never sees it (the e2e greps for that).

use anyhow::{anyhow, bail, Context};

/// Operator-grade alias defaults — even an `owner` asking one of these over the
/// gateway gets the parent-control deep-link, NEVER the data (the L3 rule that
/// operator-grade data needs operator-grade auth, §5/§8). Override with
/// `AGENTKEYS_WEIXIN_OPERATOR_GRADE_ALIASES` (comma-separated).
const DEFAULT_OPERATOR_GRADE_ALIASES: &str = "spend,usage,stats,cost,audit,billing";

/// Where the iLink loop persists its resumable cursor + per-user reply tokens
/// (override with `AGENTKEYS_WEIXIN_ILINK_STATE_FILE`; the systemd unit's
/// state dir is writable by the service user).
const DEFAULT_ILINK_STATE_FILE: &str = "/var/lib/agentkeys/weixin-ilink-state.json";
/// Where the Telegram loop persists its offset cursor + reply chat ids (#444;
/// override with `AGENTKEYS_TELEGRAM_STATE_FILE`).
const DEFAULT_TELEGRAM_STATE_FILE: &str = "/var/lib/agentkeys/telegram-state.json";
/// Durable message-history log — the writable state dir (append-only, #419).
const DEFAULT_HISTORY_FILE: &str = "/var/lib/agentkeys/weixin-history.jsonl";
/// Durable control-action audit log — the writable state dir (#419).
const DEFAULT_ACTIVITY_FILE: &str = "/var/lib/agentkeys/weixin-activity.jsonl";

/// Which chat transport this gateway instance drives. ONE gateway process =
/// ONE transport; the relay core (L3/registry/router/audit) is shared. (The
/// crate keeps its historical `weixin` name — it IS the household channel
/// gateway; #444 added the non-WeChat transport below.)
///
/// - [`Oa`]: the 公众号 webhook (verified Service Account) — the production /
///   compliance path. Needs the public callback vhost + the OA credentials.
/// - [`Ilink`]: the Tencent iLink personal-bot long-poll (the openclaw-weixin
///   protocol) — the first-experiment path (decided 2026-07-09): QR-scan a
///   SPARE personal account, no public endpoint, no entity verification.
/// - [`Telegram`]: the Bot-API long-poll (#444) — stack ②'s no-备案 chat
///   transport. Zero inbound surface (no webhook/vhost); the BotFather token
///   is the one custodied credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeixinTransport {
    Oa,
    Ilink,
    Telegram,
}

impl WeixinTransport {
    pub fn as_str(&self) -> &'static str {
        match self {
            WeixinTransport::Oa => "weixin-oa",
            WeixinTransport::Ilink => "weixin-ilink",
            WeixinTransport::Telegram => "telegram",
        }
    }
}

/// Per-contact rate limit defaults (a crude anti-flood + anti-Sybil guard, §9
/// threat 3): at most N messages per window seconds.
const DEFAULT_RATE_MAX: u32 = 30;
const DEFAULT_RATE_WINDOW_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct WeixinGatewayConfig {
    pub bind: String,
    /// Which transport this instance drives (`AGENTKEYS_WEIXIN_TRANSPORT`,
    /// default `oa`). The OA credentials are required only under `oa`; the
    /// iLink bot token only under `ilink`.
    pub transport: WeixinTransport,
    /// The WeChat callback verification token (the `Token` set in the 公众号
    /// console) — used to verify inbound callback signatures. NOT a secret that
    /// grants sending; the app-secret is. (OA transport only.)
    pub weixin_token: String,
    /// The 公众号 `AppID` — carried for outbound send + attribution; never handed
    /// to an agent. (OA transport only.)
    pub weixin_app_id: String,
    /// The 公众号 `AppSecret` — the scarce SENDING credential. Custodied here,
    /// NEVER in any agent env (#384). Present enables outbound; absent = inbound-
    /// relay-only (the MVP posture). (OA transport only.)
    pub weixin_app_secret: Option<String>,
    /// The iLink bot token minted by the `--login` QR ceremony — BOTH the
    /// receive session and the SENDING credential under `ilink` (#384 custody,
    /// same duty as the OA app-secret). Env or `0600` file.
    pub ilink_bot_token: Option<String>,
    /// The bot's own API base URL (the `confirmed` login returns it; defaults
    /// to the bootstrap host).
    pub ilink_base_url: String,
    /// The iLink loop's durable state file (resumable cursor + reply tokens).
    pub ilink_state_file: String,
    /// The secrets file the ADMIN login ceremony self-writes on `confirmed`
    /// (`AGENTKEYS_WEIXIN_SECRETS_FILE`, default the canonical broker path).
    /// The #384 custody home — the worker upserts the managed keys in place.
    pub secrets_file: String,
    /// The FIXED QR-login bootstrap host (`AGENTKEYS_WEIXIN_ILINK_BOOTSTRAP_URL`,
    /// default the upstream constant). Distinct from `ilink_base_url` — after a
    /// login the bot's own IDC host lands in the secrets file as the BASE url,
    /// but a RE-login must still bootstrap from the fixed host (upstream-plugin
    /// behavior). Overridable for the headless e2e's mock.
    pub ilink_bootstrap_url: String,
    /// UA-style `bot_agent` self-identification (observability-only upstream).
    pub bot_agent: String,
    /// The Telegram bot token from BotFather (#444) — BOTH the receive session
    /// and the SENDING credential under `telegram` (#384 custody, same duty as
    /// the OA app-secret / iLink token). Env or `0600` file; absent = the bot
    /// boots OFFLINE and idles (fill the secrets file + restart the unit).
    pub telegram_bot_token: Option<String>,
    /// The Bot API base (`AGENTKEYS_TELEGRAM_API_BASE`, default the public
    /// host) — overridable so the mock e2e can point the loop at a stub.
    pub telegram_api_base: String,
    /// The Telegram loop's durable state file (offset cursor + reply chat ids).
    pub telegram_state_file: String,
    /// Path to the master-authored contact registry JSON (`policy`-class doc,
    /// §14.5). Gateway-READ only; the master writes it (parent-control / CLI).
    pub registry_file: String,
    /// Append-only JSONL log of EVERY inbound turn — the owner's durable,
    /// restart-surviving message history + the future stats source (#419).
    /// `AGENTKEYS_WEIXIN_HISTORY_FILE`, default under the writable state dir.
    /// Empty disables durable history (the live ring still works).
    pub history_file: String,
    /// Append-only JSONL log of every CONTROL action (invite / claim / bound /
    /// rejected / revoked / connect) — the operator's durable contact-audit
    /// trail (#419), surfaced in parent-control. `AGENTKEYS_WEIXIN_ACTIVITY_FILE`,
    /// default under the writable state dir; empty disables it.
    pub activity_file: String,
    /// The channel-worker base URL the gateway relays inbound turns into (the
    /// operator-owned household feed). `None` = decision-only mode (the mock e2e
    /// asserts the routed event without a live feed).
    pub channel_worker_url: Option<String>,
    /// The OPERATOR omni this household gateway belongs to (`0x`+64hex). Every
    /// gateway audit row carries it as BOTH the actor + operator omni (the
    /// GateTurn pattern — usage accrues to the owning user). One bot per operator.
    pub operator_omni: String,
    /// The audit-service worker URL for the best-effort GatewayRelay/ContactBind
    /// rows (the #229 emitter posture; unset = audit disabled with a WARN).
    pub audit_worker_url: Option<String>,
    /// Aliases that are operator-grade → always answered with the deep-link.
    pub operator_grade_aliases: Vec<String>,
    /// The parent-control deep-link handed back for operator-grade asks.
    pub parent_control_deeplink: String,
    pub rate_max: u32,
    pub rate_window_secs: u64,
    /// #410 — the advisory router (a no-`/alias` message picks among the contact's
    /// reachable agents). Default ON; `AGENTKEYS_WEIXIN_ROUTER=0` degrades to
    /// `/alias`-only (D10 — disabling is not a failure).
    pub router_enabled: bool,
    /// #410 — admin bearer for the operator-only parent-control read surfaces
    /// (`GET /v1/gateway/contacts`). When unset, those endpoints are DISABLED
    /// (503) — never open. The operator sets it + parent-control calls with it
    /// (D13: the operator has global visibility, contacts never do).
    pub admin_token: Option<String>,
    /// TEST-ONLY (`AGENTKEYS_WEIXIN_ALLOW_UNSIGNED=1`): skip callback-signature
    /// verification so the mock e2e can drive `/wechat/callback` without the
    /// token. Refused in prod by leaving it unset (the CLI prints a WARN when on).
    pub allow_unsigned: bool,
}

impl WeixinGatewayConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = std::env::var("WORKER_BIND").unwrap_or_else(|_| "127.0.0.1:9100".to_string());

        let transport = match std::env::var("AGENTKEYS_WEIXIN_TRANSPORT")
            .unwrap_or_else(|_| "oa".to_string())
            .trim()
            .to_lowercase()
            .as_str()
        {
            "oa" | "official-account" | "" => WeixinTransport::Oa,
            "ilink" | "openclaw" | "openclaw-weixin" => WeixinTransport::Ilink,
            "telegram" | "tg" => WeixinTransport::Telegram,
            other => bail!(
                "AGENTKEYS_WEIXIN_TRANSPORT={other} is not a transport — use `oa` (公众号 \
                 webhook, production), `ilink` (personal-bot long-poll, experiment) or \
                 `telegram` (Bot-API long-poll, stack ② #444)"
            ),
        };

        // OA credentials — REQUIRED under `oa`, ignored under the long-poll transports.
        let (weixin_token, weixin_app_id) = match transport {
            WeixinTransport::Oa => (
                std::env::var("AGENTKEYS_WEIXIN_TOKEN").context(
                    "AGENTKEYS_WEIXIN_TOKEN must be set (the 公众号 callback verification token)",
                )?,
                std::env::var("AGENTKEYS_WEIXIN_APP_ID")
                    .context("AGENTKEYS_WEIXIN_APP_ID must be set")?,
            ),
            WeixinTransport::Ilink | WeixinTransport::Telegram => (
                std::env::var("AGENTKEYS_WEIXIN_TOKEN").unwrap_or_default(),
                std::env::var("AGENTKEYS_WEIXIN_APP_ID").unwrap_or_default(),
            ),
        };

        // The app-secret (the OA SENDING credential) — env or 0600 file, the
        // #384 custody shape. Absent = inbound-relay-only.
        let weixin_app_secret = secret_from_env(
            "AGENTKEYS_WEIXIN_APP_SECRET",
            "AGENTKEYS_WEIXIN_APP_SECRET_FILE",
        )?;

        // The iLink bot token (#384 custody, minted by the QR login ceremony —
        // CLI `--login` or the parent-control admin flow). Absent under `ilink`
        // is NOT fatal anymore (#418): the worker boots OFFLINE and idles until
        // the operator completes the in-app login (which mints the token, writes
        // the secrets file, and hot-starts the loop) — but it warns LOUDLY so an
        // unconfigured prod box is visible, never a silent no-op.
        let ilink_bot_token = secret_from_env(
            "AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN",
            "AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN_FILE",
        )?;
        if transport == WeixinTransport::Ilink && ilink_bot_token.is_none() {
            eprintln!(
                "==> agentkeys-worker-channel-weixin: iLink transport with NO bot token — the \
                 bot is OFFLINE until the operator connects it (parent-control → 微信网关 → \
                 连接, or `agentkeys-worker-channel-weixin --login`). healthz shows online=false."
            );
        }
        let ilink_base_url = std::env::var("AGENTKEYS_WEIXIN_ILINK_BASE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::ilink::ILINK_BOOTSTRAP_BASE_URL.to_string());
        let ilink_state_file = std::env::var("AGENTKEYS_WEIXIN_ILINK_STATE_FILE")
            .unwrap_or_else(|_| DEFAULT_ILINK_STATE_FILE.to_string());
        let history_file = std::env::var("AGENTKEYS_WEIXIN_HISTORY_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_HISTORY_FILE.to_string());
        let activity_file = std::env::var("AGENTKEYS_WEIXIN_ACTIVITY_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_ACTIVITY_FILE.to_string());
        let secrets_file = std::env::var("AGENTKEYS_WEIXIN_SECRETS_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::ilink_login::DEFAULT_SECRETS_FILE.to_string());
        let ilink_bootstrap_url = std::env::var("AGENTKEYS_WEIXIN_ILINK_BOOTSTRAP_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::ilink::ILINK_BOOTSTRAP_BASE_URL.to_string());
        let bot_agent = std::env::var("AGENTKEYS_WEIXIN_BOT_AGENT")
            .unwrap_or_else(|_| concat!("AgentKeys/", env!("CARGO_PKG_VERSION")).to_string());

        // The Telegram bot token (#444, #384 custody — minted once via
        // BotFather). Absent under `telegram` is NOT fatal (the #418 posture):
        // the worker boots OFFLINE and idles until the operator fills the
        // secrets file and restarts the unit — but it warns LOUDLY.
        let telegram_bot_token = secret_from_env(
            "AGENTKEYS_TELEGRAM_BOT_TOKEN",
            "AGENTKEYS_TELEGRAM_BOT_TOKEN_FILE",
        )?;
        if transport == WeixinTransport::Telegram && telegram_bot_token.is_none() {
            eprintln!(
                "==> agentkeys-worker-channel-weixin: telegram transport with NO bot token — the \
                 bot is OFFLINE until the operator sets AGENTKEYS_TELEGRAM_BOT_TOKEN in the \
                 gateway secrets file (mint one via @BotFather) and restarts the unit. healthz \
                 shows outbound_enabled=false."
            );
        }
        let telegram_api_base = std::env::var("AGENTKEYS_TELEGRAM_API_BASE")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::telegram::TELEGRAM_API_BASE.to_string());
        let telegram_state_file = std::env::var("AGENTKEYS_TELEGRAM_STATE_FILE")
            .unwrap_or_else(|_| DEFAULT_TELEGRAM_STATE_FILE.to_string());

        match transport {
            WeixinTransport::Ilink => eprintln!(
                "==> agentkeys-worker-channel-weixin: iLink transport — bot token custodied \
                 (long-poll inbound + outbound send) — it is NEVER handed to a delegate (#384)."
            ),
            WeixinTransport::Telegram => eprintln!(
                "==> agentkeys-worker-channel-weixin: telegram transport (#444) — bot token \
                 custodied (long-poll inbound + outbound send) — it is NEVER handed to a \
                 delegate (#384)."
            ),
            WeixinTransport::Oa if weixin_app_secret.is_some() => eprintln!(
                "==> agentkeys-worker-channel-weixin: bot app-secret custodied (outbound send \
                 enabled) — it is NEVER handed to a delegate (#384)."
            ),
            WeixinTransport::Oa => eprintln!(
                "==> agentkeys-worker-channel-weixin: no app-secret — inbound-relay-only (set \
                 AGENTKEYS_WEIXIN_APP_SECRET[_FILE] to enable outbound send)."
            ),
        }

        let registry_file = std::env::var("AGENTKEYS_WEIXIN_CONTACT_REGISTRY_FILE").context(
            "AGENTKEYS_WEIXIN_CONTACT_REGISTRY_FILE must be set (the master-authored contact \
             registry JSON — policy data class, §14.5)",
        )?;

        let channel_worker_url = std::env::var("AGENTKEYS_WORKER_CHANNEL_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let operator_omni = std::env::var("AGENTKEYS_WEIXIN_OPERATOR_OMNI")
            .context("AGENTKEYS_WEIXIN_OPERATOR_OMNI must be set (the household operator omni)")?;
        // #424 §3 — a template placeholder / malformed omni silently DISARMED
        // the on-chain contact audit (#419's silent-skip). Boot must be LOUD:
        // the value passes (relay/monitor still run) but every bind/reject/
        // revoke skips its chain anchor until the operator arms it.
        if crate::relay::decode_omni_32(&operator_omni).is_none() {
            eprintln!(
                "==> ⚠️  agentkeys-worker-channel-weixin: AGENTKEYS_WEIXIN_OPERATOR_OMNI is not \
                 0x+64-hex — ON-CHAIN CONTACT AUDIT UNARMED at boot: bind/reject/revoke will NOT \
                 anchor on chain. It self-arms at the next parent-control 连接 ceremony (#502: \
                 the session's omni is recorded at connect + persisted); the env stamp \
                 (WEIXIN_OPERATOR_OMNI + setup-broker-host.sh, #424 §3) remains the manual/CLI \
                 fallback."
            );
        }

        let audit_worker_url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        if audit_worker_url.is_none() {
            eprintln!(
                "==> agentkeys-worker-channel-weixin: AGENTKEYS_AUDIT_WORKER_URL unset — gateway \
                 relay/bind audit rows DISABLED (set it to durably audit each turn, #229)."
            );
        }

        let operator_grade_aliases = std::env::var("AGENTKEYS_WEIXIN_OPERATOR_GRADE_ALIASES")
            .unwrap_or_else(|_| DEFAULT_OPERATOR_GRADE_ALIASES.to_string())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let parent_control_deeplink = std::env::var("AGENTKEYS_WEIXIN_PARENT_CONTROL_DEEPLINK")
            .unwrap_or_else(|_| "https://parent-control.agentkeys.local/".to_string());

        let rate_max = std::env::var("AGENTKEYS_WEIXIN_RATE_MAX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_RATE_MAX);
        let rate_window_secs = std::env::var("AGENTKEYS_WEIXIN_RATE_WINDOW_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_RATE_WINDOW_SECS);

        // Advisory router (#410) — default ON; only an explicit falsy value disables.
        let router_enabled = !matches!(
            std::env::var("AGENTKEYS_WEIXIN_ROUTER").as_deref(),
            Ok("0") | Ok("false") | Ok("no")
        );

        let admin_token = std::env::var("AGENTKEYS_WEIXIN_ADMIN_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let allow_unsigned = matches!(
            std::env::var("AGENTKEYS_WEIXIN_ALLOW_UNSIGNED").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        );
        if allow_unsigned {
            eprintln!(
                "==> ⚠️  agentkeys-worker-channel-weixin: AGENTKEYS_WEIXIN_ALLOW_UNSIGNED=1 — \
                 callback SIGNATURE VERIFICATION DISABLED (test/mock only; NEVER in prod)."
            );
        }

        if transport == WeixinTransport::Oa && weixin_token.trim().is_empty() {
            return Err(anyhow!("AGENTKEYS_WEIXIN_TOKEN must be non-empty"));
        }

        Ok(WeixinGatewayConfig {
            bind,
            transport,
            weixin_token,
            weixin_app_id,
            weixin_app_secret,
            ilink_bot_token,
            ilink_base_url,
            ilink_state_file,
            history_file,
            activity_file,
            secrets_file,
            ilink_bootstrap_url,
            bot_agent,
            telegram_bot_token,
            telegram_api_base,
            telegram_state_file,
            registry_file,
            channel_worker_url,
            operator_omni,
            audit_worker_url,
            operator_grade_aliases,
            parent_control_deeplink,
            rate_max,
            rate_window_secs,
            router_enabled,
            admin_token,
            allow_unsigned,
        })
    }

    pub fn is_operator_grade(&self, alias: &str) -> bool {
        let a = alias.to_lowercase();
        self.operator_grade_aliases.iter().any(|g| g == &a)
    }

    /// True when THIS transport can send back to a contact (the reply path).
    pub fn outbound_enabled(&self) -> bool {
        match self.transport {
            WeixinTransport::Oa => self.weixin_app_secret.is_some(),
            WeixinTransport::Ilink => self.ilink_bot_token.is_some(),
            WeixinTransport::Telegram => self.telegram_bot_token.is_some(),
        }
    }
}

/// Read a secret from `<VAR>` or, failing that, a `0600` file named by
/// `<VAR>_FILE` (the #384 custody shape). Empty values count as absent.
fn secret_from_env(var: &str, file_var: &str) -> anyhow::Result<Option<String>> {
    // A `REPLACE_ME…` template placeholder is UNSET, not a value — the broker
    // secrets template ships placeholders, and the #418 offline-boot gateway
    // must idle on them (never long-poll Tencent with placeholder garbage).
    let not_placeholder = |s: String| {
        if s.starts_with("REPLACE_ME") {
            eprintln!("==> {var}: template placeholder ({s}) — treated as UNSET");
            None
        } else {
            Some(s)
        }
    };
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => Ok(not_placeholder(v.trim().to_string())),
        _ => match std::env::var(file_var) {
            Ok(p) if !p.trim().is_empty() => {
                let s = std::fs::read_to_string(&p)
                    .with_context(|| format!("reading {file_var} {p}"))?;
                let s = s.trim().to_string();
                Ok(if s.is_empty() {
                    None
                } else {
                    not_placeholder(s)
                })
            }
            _ => Ok(None),
        },
    }
}
