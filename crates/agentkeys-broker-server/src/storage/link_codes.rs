//! `LinkCodeStore` — the §10.2 agent-bootstrap link code + pending-binding
//! record (issue #144).
//!
//! One row models the full pairing lifecycle:
//!
//! ```text
//! issued      (master ran /v1/agent/create — code bound to a child omni)
//!   → consumed (agent redeemed at /v1/auth/link-code/redeem — device_pubkey +
//!               pop_sig captured; J1_agent minted)
//!   → bound     (master pulled the pending binding + submitted registerAgentDevice)
//! ```
//!
//! So this store doubles as the **pending-binding** record the master pulls
//! (the substrate behind the production push notification): a `consumed` row
//! that is not yet `bound` is "agent-A wants to pair + wants `[requested_scope]`".
//!
//! SQLite (not in-memory) because the broker restarts between demo phases; an
//! in-memory store would silently drop codes and produce confusing redeem-404s.
//! Mirrors the single-use / TTL / race-safety posture of `oauth_pending.rs`
//! (atomic `UPDATE ... WHERE consumed_at IS NULL`), but returns `BrokerError`
//! since it's consumed by broker handlers (not the auth-plugin layer).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{BrokerError, BrokerResult};

/// Link-code TTL — the window in which an agent must redeem (arch.md §10.2).
pub const LINK_CODE_TTL_SECONDS: i64 = 600;

/// SQLite-backed link-code + pending-binding store.
pub struct LinkCodeStore {
    conn: Mutex<Connection>,
}

/// Outcome of [`LinkCodeStore::consume`].
#[derive(Debug, PartialEq, Eq)]
pub enum LinkCodeConsume {
    /// Code was unused + unexpired; consume succeeded. Carries the values the
    /// redeem handler needs to mint `J1_agent`.
    Available {
        child_omni: String,
        operator_omni: String,
        label: String,
        requested_scope: String,
    },
    /// Code never existed or was already redeemed (collapsed to one variant so
    /// a prober can't distinguish — same posture as the OAuth2/email stores).
    NotFoundOrConsumed,
    /// Code existed + unused but past its TTL.
    Expired,
}

/// A redeemed-but-not-yet-bound row — what the master pulls from
/// `GET /v1/agent/pending-bindings` to approve.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PendingBinding {
    pub link_code: String,
    pub child_omni: String,
    pub operator_omni: String,
    pub label: String,
    pub requested_scope: String,
    pub device_pubkey: String,
    pub pop_sig: String,
}

impl LinkCodeStore {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrokerError::Internal(format!("create link_codes dir: {e}")))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| BrokerError::Internal(format!("open link_codes db: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> BrokerResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| BrokerError::Internal(format!("open in-memory link_codes db: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> BrokerResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| BrokerError::Internal(format!("link_codes mutex poisoned: {e}")))
    }

    fn init_schema(&self) -> BrokerResult<()> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS link_codes (
                link_code       TEXT PRIMARY KEY,
                child_omni      TEXT NOT NULL,
                operator_omni   TEXT NOT NULL,
                label           TEXT NOT NULL,
                requested_scope TEXT NOT NULL,
                issued_at       INTEGER NOT NULL,
                expires_at      INTEGER NOT NULL,
                consumed_at     INTEGER,
                device_pubkey   TEXT,
                pop_sig         TEXT,
                bound_at        INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_link_codes_operator
                ON link_codes(operator_omni);
             CREATE INDEX IF NOT EXISTS idx_link_codes_expires_at
                ON link_codes(expires_at);",
        )
        .map_err(|e| BrokerError::Internal(format!("init link_codes schema: {e}")))?;
        Ok(())
    }

    /// Mint a new link code bound to a child omni (master ran `/v1/agent/create`).
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        link_code: &str,
        child_omni: &str,
        operator_omni: &str,
        label: &str,
        requested_scope: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> BrokerResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO link_codes
                (link_code, child_omni, operator_omni, label, requested_scope, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                link_code,
                child_omni,
                operator_omni,
                label,
                requested_scope,
                issued_at,
                expires_at
            ],
        )
        .map_err(|e| BrokerError::Internal(format!("insert link_code: {e}")))?;
        Ok(())
    }

    /// Atomically redeem the code, persisting `device_pubkey` + `pop_sig` onto
    /// the row (state → consumed/pending-binding). Race-safe via the conditional
    /// `UPDATE ... WHERE consumed_at IS NULL`.
    pub fn consume(
        &self,
        link_code: &str,
        device_pubkey: &str,
        pop_sig: &str,
        now: i64,
    ) -> BrokerResult<LinkCodeConsume> {
        let conn = self.lock()?;
        let peek: Option<(String, String, String, i64, Option<i64>)> = conn
            .query_row(
                "SELECT child_omni, operator_omni, label, expires_at, consumed_at
                 FROM link_codes WHERE link_code = ?1",
                params![link_code],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("peek link_code: {e}")))?;

        let (child_omni, operator_omni, label, expires_at, consumed_at) = match peek {
            None => return Ok(LinkCodeConsume::NotFoundOrConsumed),
            Some(t) => t,
        };
        if consumed_at.is_some() {
            return Ok(LinkCodeConsume::NotFoundOrConsumed);
        }
        if expires_at < now {
            return Ok(LinkCodeConsume::Expired);
        }
        let requested_scope: String = conn
            .query_row(
                "SELECT requested_scope FROM link_codes WHERE link_code = ?1",
                params![link_code],
                |row| row.get(0),
            )
            .map_err(|e| BrokerError::Internal(format!("read requested_scope: {e}")))?;
        let rows = conn
            .execute(
                "UPDATE link_codes
                 SET consumed_at = ?1, device_pubkey = ?2, pop_sig = ?3
                 WHERE link_code = ?4 AND consumed_at IS NULL",
                params![now, device_pubkey, pop_sig, link_code],
            )
            .map_err(|e| BrokerError::Internal(format!("update link_code: {e}")))?;
        if rows == 0 {
            // Lost the race to a concurrent redeem.
            Ok(LinkCodeConsume::NotFoundOrConsumed)
        } else {
            Ok(LinkCodeConsume::Available {
                child_omni,
                operator_omni,
                label,
                requested_scope,
            })
        }
    }

    /// Rows that have been redeemed but not yet bound on-chain, for one operator
    /// — the master's pending-approval queue. Returns oldest-first.
    pub fn pending_bindings(&self, operator_omni: &str) -> BrokerResult<Vec<PendingBinding>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT link_code, child_omni, operator_omni, label, requested_scope,
                        device_pubkey, pop_sig
                 FROM link_codes
                 WHERE operator_omni = ?1 AND consumed_at IS NOT NULL AND bound_at IS NULL
                 ORDER BY consumed_at ASC",
            )
            .map_err(|e| BrokerError::Internal(format!("prepare pending_bindings: {e}")))?;
        let rows = stmt
            .query_map(params![operator_omni], |row| {
                Ok(PendingBinding {
                    link_code: row.get(0)?,
                    child_omni: row.get(1)?,
                    operator_omni: row.get(2)?,
                    label: row.get(3)?,
                    requested_scope: row.get(4)?,
                    device_pubkey: row.get(5)?,
                    pop_sig: row.get(6)?,
                })
            })
            .map_err(|e| BrokerError::Internal(format!("query pending_bindings: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| BrokerError::Internal(format!("row pending_bindings: {e}")))?);
        }
        Ok(out)
    }

    /// Mark a redeemed row as bound (the master acked its on-chain submit), so
    /// it drops out of [`pending_bindings`]. Scoped to `operator_omni` — an
    /// operator can only ack its own bindings. Idempotent: a second ack matches
    /// nothing. Returns the updated row count (1 = acked, 0 = unknown/already-bound).
    pub fn mark_bound(
        &self,
        link_code: &str,
        operator_omni: &str,
        now: i64,
    ) -> BrokerResult<usize> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "UPDATE link_codes SET bound_at = ?1
                 WHERE link_code = ?2 AND operator_omni = ?3
                   AND consumed_at IS NOT NULL AND bound_at IS NULL",
                params![now, link_code, operator_omni],
            )
            .map_err(|e| BrokerError::Internal(format!("mark_bound link_code: {e}")))?;
        Ok(n)
    }

    /// Janitor — DELETE expired codes that were never redeemed. Consumed rows are
    /// kept (the master may still need to bind them — a binding doesn't expire).
    pub fn purge_expired(&self, now: i64, retention_seconds: i64) -> BrokerResult<usize> {
        let conn = self.lock()?;
        let cutoff = now - retention_seconds;
        let n = conn
            .execute(
                "DELETE FROM link_codes WHERE expires_at < ?1 AND consumed_at IS NULL",
                params![cutoff],
            )
            .map_err(|e| BrokerError::Internal(format!("purge link_codes: {e}")))?;
        Ok(n)
    }

    /// Writability probe for `/readyz`.
    pub fn writable(&self) -> bool {
        let Ok(conn) = self.conn.lock() else {
            return false;
        };
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _readyz_probe (id INTEGER PRIMARY KEY)",
            [],
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> LinkCodeStore {
        LinkCodeStore::open_in_memory().unwrap()
    }

    #[test]
    fn issue_then_consume_round_trip() {
        let s = store();
        s.issue("lc-1", "child", "op", "agent-a", "memory", 100, 700)
            .unwrap();
        let out = s.consume("lc-1", "0xdev", "0xpop", 200).unwrap();
        assert_eq!(
            out,
            LinkCodeConsume::Available {
                child_omni: "child".into(),
                operator_omni: "op".into(),
                label: "agent-a".into(),
                requested_scope: "memory".into(),
            }
        );
    }

    #[test]
    fn second_redeem_is_rejected() {
        let s = store();
        s.issue("lc-1", "child", "op", "agent-a", "memory", 100, 700)
            .unwrap();
        let _ = s.consume("lc-1", "0xdev", "0xpop", 200).unwrap();
        let replay = s.consume("lc-1", "0xdev", "0xpop", 250).unwrap();
        assert_eq!(replay, LinkCodeConsume::NotFoundOrConsumed);
    }

    #[test]
    fn expired_code_is_not_consumable() {
        let s = store();
        s.issue("lc-1", "child", "op", "agent-a", "memory", 100, 200)
            .unwrap();
        assert_eq!(
            s.consume("lc-1", "0xdev", "0xpop", 9999).unwrap(),
            LinkCodeConsume::Expired
        );
    }

    #[test]
    fn unknown_code_is_not_found() {
        let s = store();
        assert_eq!(
            s.consume("nope", "0xdev", "0xpop", 100).unwrap(),
            LinkCodeConsume::NotFoundOrConsumed
        );
    }

    #[test]
    fn pending_bindings_returns_consumed_unbound_rows() {
        let s = store();
        s.issue("lc-1", "childA", "op", "agent-a", "memory", 100, 700)
            .unwrap();
        s.issue("lc-2", "childB", "op-other", "agent-b", "memory", 100, 700)
            .unwrap();
        // Not redeemed yet → no pending binding.
        assert!(s.pending_bindings("op").unwrap().is_empty());
        s.consume("lc-1", "0xdevA", "0xpopA", 200).unwrap();
        let pend = s.pending_bindings("op").unwrap();
        assert_eq!(pend.len(), 1);
        assert_eq!(pend[0].child_omni, "childA");
        assert_eq!(pend[0].device_pubkey, "0xdevA");
        assert_eq!(pend[0].pop_sig, "0xpopA");
        // Different operator's redemption doesn't leak.
        assert!(s
            .pending_bindings("op")
            .unwrap()
            .iter()
            .all(|b| b.operator_omni == "op"));
    }

    #[test]
    fn mark_bound_clears_from_pending() {
        let s = store();
        s.issue("lc-1", "childA", "op", "agent-a", "memory", 100, 700)
            .unwrap();
        s.consume("lc-1", "0xdevA", "0xpopA", 200).unwrap();
        assert_eq!(s.pending_bindings("op").unwrap().len(), 1);
        assert_eq!(s.mark_bound("lc-1", "op", 300).unwrap(), 1);
        assert!(s.pending_bindings("op").unwrap().is_empty());
        // Idempotent: a second ack matches nothing.
        assert_eq!(s.mark_bound("lc-1", "op", 400).unwrap(), 0);
        // Operator-scoped: a different operator cannot ack this binding.
        s.issue("lc-2", "childZ", "op", "agent-z", "memory", 100, 700)
            .unwrap();
        s.consume("lc-2", "0xdevZ", "0xpopZ", 200).unwrap();
        assert_eq!(s.mark_bound("lc-2", "other-op", 300).unwrap(), 0);
        assert_eq!(s.pending_bindings("op").unwrap().len(), 1);
    }

    #[test]
    fn purge_drops_unredeemed_expired_keeps_pending() {
        let s = store();
        s.issue("stale", "childA", "op", "agent-a", "memory", 50, 100)
            .unwrap();
        s.issue("redeemed", "childB", "op", "agent-b", "memory", 50, 100)
            .unwrap();
        s.consume("redeemed", "0xdevB", "0xpopB", 60).unwrap();
        let n = s.purge_expired(10_000, 100).unwrap();
        assert_eq!(n, 1); // only the unredeemed-expired "stale" row
                          // The redeemed row survives as a pending binding.
        assert_eq!(s.pending_bindings("op").unwrap().len(), 1);
    }

    #[test]
    fn issue_rejects_duplicate_code() {
        let s = store();
        s.issue("dup", "c", "op", "agent-a", "memory", 100, 700)
            .unwrap();
        assert!(s
            .issue("dup", "c", "op", "agent-a", "memory", 100, 700)
            .is_err());
    }
}
