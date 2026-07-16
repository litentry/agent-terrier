//! WeChat gateway worker — #407 / `docs/spec/agent-channel-decoupling.md` §7.
//!
//! The concrete first `gateway` (D4): the capability boundary between the
//! family (externally-authenticated `contact`s) and the delegates that already
//! run. It:
//!
//! 1. **Custodies the ONE WeChat bot credential** the #384 gate-custody way
//!    (env / secret file, NEVER in any agent's environment) — [`config`].
//! 2. **Verifies** every platform callback (the WeChat signature) — [`signature`].
//! 3. **Authenticates** each human by transport identity (openid) against the
//!    master-curated **contact registry** (`policy`-class doc) — [`registry`].
//! 4. **Enforces L3** BEFORE anything reaches an agent — reach, per-contact rate
//!    limit, the operator-grade-needs-operator-grade-auth rule — [`l3`].
//! 5. **Routes** deterministically (`/alias`; the advisory router is phase 5) and
//!    relays into the target delegate's channel feed, auditing each turn.
//!
//! **A PEP, never an authority** — it holds no master key, mints no grant; a
//! contact holds no caps and (D13) sees no feed history. The tier proposal at
//! bind time is advisory (D10) — the registry only ever gains a contact through
//! the master's confirm.

//! Three interchangeable transports drive the same PEP (`AGENTKEYS_WEIXIN_TRANSPORT`):
//! the 公众号 webhook (`oa` — production/compliance), the Tencent iLink
//! personal-bot long-poll (`ilink` — the first-experiment path; see [`ilink`]),
//! and the Telegram Bot-API long-poll (`telegram` — stack ②'s no-备案 channel,
//! #444; see [`telegram`]). All converge on [`relay`], so policy never forks
//! per transport. (The crate keeps its historical `weixin` name — it IS the
//! household channel gateway.)

pub mod admin;
pub mod config;
pub mod handlers;
pub mod ilink;
pub mod ilink_login;
pub mod ilink_loop;
pub mod l3;
pub mod registry;
pub mod relay;
pub mod router;
pub mod signature;
pub mod state;
pub mod telegram;
pub mod telegram_loop;

pub use config::{WeixinGatewayConfig, WeixinTransport};
pub use state::WeixinGatewayState;
