//! `AuditAnchor` trait — the audit layer of the pluggable broker.
//!
//! Phase 0 ships `SqliteAnchor` (port of existing `audit.rs`). Phase C
//! adds `EvmTestnetAnchor` (Base Sepolia) behind the `audit-evm` feature
//! gate. Multiple anchors can be registered; `BROKER_AUDIT_POLICY`
//! selects the multi-write strategy. See plan §3 + §3.5 + §Phase C.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::Readiness;

pub mod breaker;
#[cfg(feature = "audit-evm")]
pub mod evm;
#[cfg(feature = "audit-sqlite")]
pub mod sqlite;

pub use breaker::{BreakerConfig, BreakerError, BreakerState, CircuitBreaker};
#[cfg(feature = "audit-evm")]
pub use evm::{EvmAuditConfig, EvmAuditError, EvmStubAnchor};
#[cfg(feature = "audit-sqlite")]
pub use sqlite::SqliteAnchor;

/// The canonical record written to every configured audit anchor when a
/// credential is minted. The `record_hash` is `SHA256(canonical_cbor(record))`
/// computed once and used as the de-duplication key across anchors.
///
/// Per plan §2 (load-bearing invariant): no credential leaves the broker
/// process unless an audit record naming `(omni_account, wallet, agent_id,
/// service)` has been durably persisted to **every** configured anchor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// ULID assigned by the broker before any anchor write.
    pub id: String,
    /// Unix epoch seconds at the moment the broker received the mint request.
    pub minted_at: i64,
    /// SHA256 of the canonical CBOR encoding of the record (excluding `id`
    /// and `minted_at` since they are anchor metadata, not request data).
    pub record_hash: String,
    /// OmniAccount of the user the broker authenticated.
    pub omni_account: String,
    /// EVM-style 0x-prefixed lowercase hex address of the daemon wallet.
    pub wallet: String,
    /// The agent identifier the mint applies to (typically a daemon address).
    pub agent_id: String,
    /// The service name (e.g., `"s3"`, `"openrouter"`) the credentials
    /// authorize use of.
    pub service: String,
    /// The grant_id (Phase B+) under which this mint executed. Empty
    /// string in Phase 0 (grants land in Phase B).
    pub grant_id: String,
    /// Outcome string: `"ok"`, `"auth_failed"`, `"backend_error"`, etc.
    pub outcome: String,
    /// Optional human-readable detail captured for failure cases.
    pub outcome_detail: Option<String>,
}

/// Receipt returned by an `AuditAnchor::anchor` call. Stored alongside the
/// record so reconciliation jobs can re-verify durability.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Anchor name (matches `AuditAnchor::name`).
    pub anchor: String,
    /// Anchor-specific receipt JSON. For SQLite: `{"row_id": <i64>}`. For
    /// EVM: `{"tx_hash": "0x…", "block_number": <u64>, "log_index": <u32>}`.
    pub receipt: serde_json::Value,
    /// Unix epoch seconds at the moment durability was confirmed.
    pub anchored_at: i64,
}

/// Errors an audit anchor may return. The mint handler treats every error
/// as "credentials must not be released" — the response gate is the audit
/// write success.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("circuit open: {0}")]
    CircuitOpen(String),
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("verification mismatch: {0}")]
    VerificationMismatch(String),
    #[error("not found")]
    NotFound,
    #[error("internal: {0}")]
    Internal(String),
}

#[async_trait]
pub trait AuditAnchor: Send + Sync {
    /// Stable kebab-case name. E.g., `"sqlite"`, `"evm_testnet"`.
    fn name(&self) -> &'static str;

    /// Operational state. **MUST NOT default to `Ready`** — implementations
    /// check their own backing store, RPC, or fee-payer balance.
    fn ready(&self) -> Readiness;

    /// Durably persist the record. Must not return `Ok` until the write is
    /// observable — for SQLite that means after `COMMIT` (WAL+FULL); for EVM
    /// that means after the transaction receipt is in a finalized block (or
    /// the operator's chosen confirmation depth).
    async fn anchor(&self, record: &AuditRecord) -> Result<AnchorReceipt, AuditError>;

    /// Re-verify durability. Used by the reconciliation job and by the
    /// post-deploy operator runbook. Returns `Ok(true)` if the receipt
    /// still resolves to the same record_hash.
    async fn verify(
        &self,
        record: &AuditRecord,
        receipt: &AnchorReceipt,
    ) -> Result<bool, AuditError>;
}

/// Multi-anchor write policy as selected by `BROKER_AUDIT_POLICY`.
///
/// `DualStrict` is the default: refuse credential release on any anchor
/// failure (strongest invariant, mints serve 500 if EVM unavailable).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditPolicy {
    DualStrict,
    SqlitePrimary,
    EvmPrimary,
}

impl AuditPolicy {
    pub fn parse(s: &str) -> Result<Self, AuditError> {
        match s {
            "dual_strict" => Ok(Self::DualStrict),
            "sqlite_primary" => Ok(Self::SqlitePrimary),
            "evm_primary" => Ok(Self::EvmPrimary),
            other => Err(AuditError::Internal(format!(
                "unknown BROKER_AUDIT_POLICY: {} (expected dual_strict | sqlite_primary | evm_primary)",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_policy_parse_round_trip() {
        assert_eq!(
            AuditPolicy::parse("dual_strict").unwrap(),
            AuditPolicy::DualStrict
        );
        assert_eq!(
            AuditPolicy::parse("sqlite_primary").unwrap(),
            AuditPolicy::SqlitePrimary
        );
        assert_eq!(
            AuditPolicy::parse("evm_primary").unwrap(),
            AuditPolicy::EvmPrimary
        );
        assert!(AuditPolicy::parse("nonsense").is_err());
    }

    #[test]
    fn audit_record_serialize_round_trip() {
        let r = AuditRecord {
            id: "01HZ".into(),
            minted_at: 1_700_000_000,
            record_hash: "deadbeef".into(),
            omni_account: "0x7f".into(),
            wallet: "0xabc".into(),
            agent_id: "0xabc".into(),
            service: "s3".into(),
            grant_id: String::new(),
            outcome: "ok".into(),
            outcome_detail: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: AuditRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }
}
