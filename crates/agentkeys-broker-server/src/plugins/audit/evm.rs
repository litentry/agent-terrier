//! EVM audit anchor — Phase C, US-031 (`audit-evm` feature).
//!
//! Per plan §Phase C: anchors AuditRecord onto Base Sepolia by submitting
//! a transaction to the deployed `AgentKeysAudit` contract. The full
//! alloy-based implementation lands in a Phase E operator hardening pass
//! along with the Foundry-deployed contract; this module ships:
//!
//! - `EvmAuditConfig` — the env-var-driven configuration shape (RPC URL,
//!   chain ID, contract address, fee-payer keystore + password).
//! - `EvmStubAnchor` — a unit-test-only fixture that simulates the EVM
//!   round-trip (issuance → receipt-poll → confirmed) WITHOUT a network
//!   dependency. Production uses the eventual `EvmAuditAnchor` (deferred
//!   to V0.1-FOLLOWUPS — alloy crate adds substantial compile time).
//!
//! The three-state lifecycle methods on `SqliteAnchor` (US-032) drive
//! the dual-anchor write protocol: SQLite row inserted as `pending`,
//! EVM tx submitted, SQLite promoted to `confirmed` on receipt; on
//! failure → `quarantined` with the reconciler retrying.
//!
//! Boot validates `EvmAuditConfig` from env vars and refuses to boot if
//! `BROKER_EVM_RPC_URL`, `BROKER_EVM_CHAIN_ID`, etc. are missing or
//! invalid (Tier 1) and the RPC `eth_chainId` returns the wrong value
//! (Tier 2 reachability).

use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::json;

use super::{AnchorReceipt, AuditAnchor, AuditError, AuditRecord};
use crate::plugins::Readiness;

const ANCHOR_NAME: &str = "evm_testnet";

#[derive(Debug, Clone)]
pub struct EvmAuditConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub fee_payer_keystore_path: std::path::PathBuf,
    pub fee_payer_password_file: std::path::PathBuf,
    pub fee_payer_min_balance_wei: u128,
    /// Per-OmniAccount daily transaction budget. Plan §Phase C gas-drain
    /// mitigations (US-034) — defends against an attacker amplifying a
    /// stolen JWT into draining the fee-payer wallet. Configurable via
    /// `BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET`. Default 100.
    pub per_identity_daily_tx_budget: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum EvmAuditError {
    #[error("rpc unreachable: {0}")]
    RpcUnreachable(String),
    #[error("tx revert: {0}")]
    TxRevert(String),
    #[error("fee payer underfunded (have {have_wei}, floor {floor_wei})")]
    FeePayerUnderfunded { have_wei: u128, floor_wei: u128 },
    #[error("config: {0}")]
    Config(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<EvmAuditError> for AuditError {
    fn from(e: EvmAuditError) -> Self {
        match e {
            EvmAuditError::RpcUnreachable(_) => AuditError::Network(e.to_string()),
            EvmAuditError::FeePayerUnderfunded { .. } | EvmAuditError::TxRevert(_) => {
                AuditError::Storage(e.to_string())
            }
            EvmAuditError::Config(_) | EvmAuditError::Internal(_) => {
                AuditError::Internal(e.to_string())
            }
        }
    }
}

/// Test-only stub anchor that simulates EVM round-trip latency + success
/// or canned failure modes WITHOUT pulling in alloy. Used by Phase C
/// integration tests + the V0.1-FOLLOWUPS reconciliation harness.
///
/// `simulate_failure: Some(reason)` makes `anchor()` return the failure
/// — the dual-write reconciler then sees the SQLite row in `pending`
/// and promotes it to `quarantined`. This is the load-bearing test
/// surface for plan §2 case (f) (dual-anchor partial failure).
pub struct EvmStubAnchor {
    pub anchored_records: Mutex<Vec<String>>, // record IDs
    pub simulate_failure: Mutex<Option<EvmAuditError>>,
    pub readiness: Mutex<Readiness>,
}

impl EvmStubAnchor {
    pub fn new() -> Self {
        Self {
            anchored_records: Mutex::new(Vec::new()),
            simulate_failure: Mutex::new(None),
            readiness: Mutex::new(Readiness::ready_with("evm-stub")),
        }
    }

    pub fn set_simulate_failure(&self, err: Option<EvmAuditError>) {
        *self.simulate_failure.lock().unwrap() = err;
    }

    pub fn set_readiness(&self, r: Readiness) {
        *self.readiness.lock().unwrap() = r;
    }

    pub fn anchored_count(&self) -> usize {
        self.anchored_records.lock().unwrap().len()
    }
}

impl Default for EvmStubAnchor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditAnchor for EvmStubAnchor {
    fn name(&self) -> &'static str {
        ANCHOR_NAME
    }

    fn ready(&self) -> Readiness {
        self.readiness
            .lock()
            .map(|r| r.clone())
            .unwrap_or_else(|_| Readiness::unready("readiness mutex poisoned"))
    }

    async fn anchor(&self, record: &AuditRecord) -> Result<AnchorReceipt, AuditError> {
        if let Some(err) = self.simulate_failure.lock().unwrap().take() {
            return Err(err.into());
        }
        let mut anchored = self.anchored_records.lock().unwrap();
        anchored.push(record.id.clone());
        // Simulate a deterministic tx hash from the record id for tests.
        let tx_hash = format!("0xstub{:x}", anchored.len() - 1);
        Ok(AnchorReceipt {
            anchor: ANCHOR_NAME.to_string(),
            receipt: json!({
                "tx_hash": tx_hash,
                "block_number": 1_000_000 + anchored.len() as u64,
                "row_id": record.id,
            }),
            anchored_at: record.minted_at,
        })
    }

    async fn verify(
        &self,
        record: &AuditRecord,
        receipt: &AnchorReceipt,
    ) -> Result<bool, AuditError> {
        if receipt.anchor != ANCHOR_NAME {
            return Err(AuditError::VerificationMismatch(format!(
                "receipt is for anchor {} not {}",
                receipt.anchor, ANCHOR_NAME
            )));
        }
        let anchored = self.anchored_records.lock().unwrap();
        if anchored.contains(&record.id) {
            Ok(true)
        } else {
            Err(AuditError::NotFound)
        }
    }
}

impl EvmAuditConfig {
    /// Validate static fields. Network reachability + chain_id match are
    /// Tier-2 checks (boot-to-Unready) wired in `boot::tier2_evm_probe`.
    pub fn validate(&self) -> Result<(), EvmAuditError> {
        if self.rpc_url.is_empty() {
            return Err(EvmAuditError::Config("rpc_url empty".into()));
        }
        if self.chain_id == 0 {
            return Err(EvmAuditError::Config("chain_id must be non-zero".into()));
        }
        if !self.contract_address.starts_with("0x") || self.contract_address.len() != 42 {
            return Err(EvmAuditError::Config(format!(
                "contract_address must be 0x-prefixed 42-char hex, got {:?}",
                self.contract_address
            )));
        }
        if !self.fee_payer_keystore_path.exists() {
            return Err(EvmAuditError::Config(format!(
                "fee-payer keystore path does not exist: {}",
                self.fee_payer_keystore_path.display()
            )));
        }
        if !self.fee_payer_password_file.exists() {
            return Err(EvmAuditError::Config(format!(
                "fee-payer password file does not exist: {}",
                self.fee_payer_password_file.display()
            )));
        }
        if self.per_identity_daily_tx_budget == 0 {
            return Err(EvmAuditError::Config(
                "per_identity_daily_tx_budget must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(id: &str) -> AuditRecord {
        AuditRecord {
            id: id.into(),
            minted_at: 1_700_000_000,
            record_hash: "h".into(),
            omni_account: "0xom".into(),
            wallet: "0xw".into(),
            agent_id: "0xag".into(),
            service: "s3".into(),
            grant_id: String::new(),
            outcome: "ok".into(),
            outcome_detail: None,
        }
    }

    #[tokio::test]
    async fn stub_anchor_records_and_verifies() {
        let a = EvmStubAnchor::new();
        let r = record("01EVM1");
        let receipt = a.anchor(&r).await.unwrap();
        assert_eq!(receipt.anchor, "evm_testnet");
        assert!(a.verify(&r, &receipt).await.unwrap());
        assert_eq!(a.anchored_count(), 1);
    }

    #[tokio::test]
    async fn stub_anchor_simulates_failure() {
        let a = EvmStubAnchor::new();
        a.set_simulate_failure(Some(EvmAuditError::RpcUnreachable(
            "connection refused".into(),
        )));
        let r = record("01EVMFAIL");
        let res = a.anchor(&r).await;
        assert!(matches!(res, Err(AuditError::Network(_))));
        // failure consumed → next call succeeds
        let r2 = record("01EVMOK");
        a.anchor(&r2).await.unwrap();
        assert_eq!(a.anchored_count(), 1);
    }

    #[tokio::test]
    async fn stub_anchor_verify_unknown_returns_not_found() {
        let a = EvmStubAnchor::new();
        let r = record("01EVMNEVER");
        let receipt = AnchorReceipt {
            anchor: "evm_testnet".into(),
            receipt: json!({}),
            anchored_at: 0,
        };
        assert!(matches!(
            a.verify(&r, &receipt).await,
            Err(AuditError::NotFound)
        ));
    }

    #[tokio::test]
    async fn stub_readiness_can_be_set() {
        let a = EvmStubAnchor::new();
        assert!(a.ready().is_ready());
        a.set_readiness(Readiness::degraded("circuit half-open"));
        assert!(a.ready().is_degraded());
        a.set_readiness(Readiness::unready("rpc down"));
        assert!(a.ready().is_unready());
    }

    #[test]
    fn config_validate_accepts_well_formed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kp = tmp.path().join("kp.json");
        let pw = tmp.path().join("pw");
        std::fs::write(&kp, "{}").unwrap();
        std::fs::write(&pw, "secret").unwrap();
        let c = EvmAuditConfig {
            rpc_url: "https://rpc.example".into(),
            chain_id: 84532,
            contract_address: "0x".to_string() + &"a".repeat(40),
            fee_payer_keystore_path: kp,
            fee_payer_password_file: pw,
            fee_payer_min_balance_wei: 1_000_000_000_000_000,
            per_identity_daily_tx_budget: 100,
        };
        c.validate().unwrap();
    }

    #[test]
    fn config_validate_rejects_empty_rpc() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kp = tmp.path().join("kp.json");
        let pw = tmp.path().join("pw");
        std::fs::write(&kp, "{}").unwrap();
        std::fs::write(&pw, "s").unwrap();
        let c = EvmAuditConfig {
            rpc_url: String::new(),
            chain_id: 84532,
            contract_address: "0x".to_string() + &"a".repeat(40),
            fee_payer_keystore_path: kp,
            fee_payer_password_file: pw,
            fee_payer_min_balance_wei: 0,
            per_identity_daily_tx_budget: 1,
        };
        assert!(matches!(c.validate(), Err(EvmAuditError::Config(_))));
    }

    #[test]
    fn config_validate_rejects_bad_address() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kp = tmp.path().join("kp.json");
        let pw = tmp.path().join("pw");
        std::fs::write(&kp, "{}").unwrap();
        std::fs::write(&pw, "s").unwrap();
        let c = EvmAuditConfig {
            rpc_url: "https://rpc.example".into(),
            chain_id: 84532,
            contract_address: "not-an-address".into(),
            fee_payer_keystore_path: kp,
            fee_payer_password_file: pw,
            fee_payer_min_balance_wei: 0,
            per_identity_daily_tx_budget: 1,
        };
        assert!(matches!(c.validate(), Err(EvmAuditError::Config(_))));
    }

    #[test]
    fn config_validate_rejects_zero_chain_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kp = tmp.path().join("kp.json");
        let pw = tmp.path().join("pw");
        std::fs::write(&kp, "{}").unwrap();
        std::fs::write(&pw, "s").unwrap();
        let c = EvmAuditConfig {
            rpc_url: "https://rpc.example".into(),
            chain_id: 0,
            contract_address: "0x".to_string() + &"a".repeat(40),
            fee_payer_keystore_path: kp,
            fee_payer_password_file: pw,
            fee_payer_min_balance_wei: 0,
            per_identity_daily_tx_budget: 1,
        };
        assert!(matches!(c.validate(), Err(EvmAuditError::Config(_))));
    }
}
