//! §10.2 agent-bootstrap endpoints — **method A, agent-initiated** (issue #144,
//! flipped from master-initiated; design doc
//! `docs/archived/agent-initiated-pairing-method-a.md`).
//!
//! The agent shows a code, the master claims it (the Matter/HomeKit IoT model),
//! and the master still submits the on-chain binding (decision 1 — no contract
//! change, no broker chain key):
//!
//! - `POST /v1/agent/pairing/request` (agent, no bearer) — verify the agent's
//!   `pop_sig`, store an UNBOUND request (naming no master), return a
//!   `pairing_code` to display + a secret `request_id` retrieval ticket.
//! - `POST /v1/agent/pairing/claim` (master, `J1_master`-gated) — claim the
//!   code; derive the HDKD child omni `O_agent = SHA256(.. || O_master || "//label")`,
//!   mark the request claimed, and stash the device artifact as a pending binding.
//! - `POST /v1/agent/pairing/poll` (agent, no bearer) — once claimed, re-prove
//!   device-key possession (fresh `pop_sig`) and mint + retrieve `J1_agent`.
//! - `GET /v1/agent/pending-bindings` (master, `J1_master`-gated) — pull the
//!   claimed-but-unbound rows to approve (the push-notification substrate).
//!
//! The broker never K11-verifies on the agent path — agents are K10-only per the
//! contract (`registerAgentDevice` writes `k11CredId = 0`). The master's K11
//! gesture happens later, when it submits the on-chain binding + scope grant.
//!
//! Agent-side unbind / factory-reset + re-pair is out of this PR (→ #156); on-
//! chain agent self-revoke is out of this PR (→ #155).

pub mod claim;
pub mod decline;
pub mod delegation;
pub mod pending;
pub mod poll;
pub mod request;
pub mod resolve;

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

/// #642 — TTL for the `J1_agent` a delegate SANDBOX boots with. A pod lives a
/// full 24 h veFaaS lease; the interactive 5 h default left every cap-minted
/// leg in the pod (checkpoint saves, the #566 mirror, cred fetches) dead for
/// the lease tail — measured live (first `ExpiredSignature` 5 h after spawn)
/// while chat kept answering. The J1 dies with the pod and every re-create
/// mints fresh, so this tracks the lease, not a login session; masters keep
/// the 5 h default above.
pub(crate) fn delegate_session_jwt_ttl_seconds() -> u64 {
    delegate_session_jwt_ttl_from(
        std::env::var(crate::env::BROKER_DELEGATE_SESSION_JWT_TTL_SECONDS).ok(),
    )
}

/// Pure core of [`delegate_session_jwt_ttl_seconds`] (the no-env-mutation
/// test seam).
pub(crate) fn delegate_session_jwt_ttl_from(raw: Option<String>) -> u64 {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v >= 60)
        .unwrap_or(90_000)
}

#[cfg(test)]
mod ttl_tests {
    use super::*;

    #[test]
    fn delegate_ttl_defaults_to_a_full_lease_and_rejects_garbage() {
        assert_eq!(delegate_session_jwt_ttl_from(None), 90_000);
        assert_eq!(delegate_session_jwt_ttl_from(Some("86400".into())), 86_400);
        // Garbage and sub-minute values fall back to the lease-tracking default.
        assert_eq!(delegate_session_jwt_ttl_from(Some("nope".into())), 90_000);
        assert_eq!(delegate_session_jwt_ttl_from(Some("0".into())), 90_000);
    }
}
