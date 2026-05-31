//! §10.2 agent-bootstrap endpoints (issue #144).
//!
//! Three endpoints implement the link-code ceremony with the master submitting
//! the on-chain binding (decision 1 — no contract change, no broker chain key):
//!
//! - `POST /v1/agent/create` (master, `J1_master`-gated) — mint a one-time link
//!   code bound to the HDKD child omni `O_agent = SHA256(.. || O_master || "//label")`.
//! - `POST /v1/auth/link-code/redeem` (agent, no bearer) — verify the agent's
//!   `pop_sig`, consume the code, mint `J1_agent`, and stash the device artifact
//!   as a pending binding.
//! - `GET /v1/agent/pending-bindings` (master, `J1_master`-gated) — pull the
//!   redeemed-but-unbound rows to approve (the push-notification substrate).
//!
//! The broker never K11-verifies on the agent path — agents are K10-only per the
//! contract (`registerAgentDevice` writes `k11CredId = 0`). The master's K11
//! gesture happens later, when it submits the on-chain binding + scope grant.

pub mod create;
pub mod pending;
pub mod redeem;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{BrokerError, BrokerResult};

/// Unix seconds, mapped to `BrokerError::Internal` on the (impossible) clock-skew error.
pub(crate) fn unix_now() -> BrokerResult<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| BrokerError::Internal(format!("clock before unix epoch: {e}")))?
        .as_secs() as i64)
}

/// Session-JWT TTL (seconds) for `J1_agent` — same env + default as the wallet
/// session path (`wallet_verify`), so agent and master sessions age uniformly.
pub(crate) fn session_jwt_ttl_seconds() -> u64 {
    std::env::var(crate::env::BROKER_SESSION_JWT_TTL_SECONDS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(18_000)
}
