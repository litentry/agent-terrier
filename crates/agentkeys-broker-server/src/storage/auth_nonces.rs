//! Single-use nonce table for the WalletSig auth method (US-006).
//!
//! Per plan §3.5.1: SIWE messages embed a nonce that the broker generates
//! at challenge-time and consumes at verify-time. Single-use is enforced
//! at DB level via UNIQUE on `nonce` + a race-safe conditional UPDATE.
//!
//! Lifecycle:
//! 1. `issue(address, expires_at)` — INSERT a fresh nonce row tied to the
//!    requesting wallet address.
//! 2. `consume(nonce)` — atomic UPDATE to set `consumed_at`. Returns the
//!    associated address if successful, NoneOrAlreadyConsumed otherwise.
//! 3. `purge_expired(now)` — periodic janitor to keep the table small.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::plugins::auth::AuthError;

/// SQLite-backed nonce store.
pub struct AuthNonceStore {
    conn: Mutex<Connection>,
}

/// What `consume` returns when no row matches or the row was already used.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// Nonce row was unused; consume succeeded; returns the bound address.
    Consumed { address: String, expires_at: i64 },
    /// Either the nonce never existed, or it was already consumed
    /// (we collapse those cases — distinguishing them would let an
    /// attacker probe the nonce table).
    NotFoundOrConsumed,
    /// Nonce existed and was unused but is past its expiration.
    Expired,
}

impl AuthNonceStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::Internal(format!("create auth_nonces dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open auth_nonces db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuthError::Internal(format!("open in-memory auth_nonces db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("auth_nonces mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS auth_nonces (
                nonce        TEXT PRIMARY KEY,
                address      TEXT NOT NULL,
                issued_at    INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                consumed_at  INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_auth_nonces_address ON auth_nonces(address);
             CREATE INDEX IF NOT EXISTS idx_auth_nonces_expires_at ON auth_nonces(expires_at);",
        )
        .map_err(|e| AuthError::Internal(format!("init auth_nonces schema: {}", e)))?;
        Ok(())
    }

    /// Insert a fresh nonce. Returns InvalidRequest if the nonce string is
    /// already in the table (extraordinarily unlikely with 32-byte CSPRNG —
    /// indicates clock-rollback or RNG failure).
    pub fn issue(
        &self,
        nonce: &str,
        address: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO auth_nonces (nonce, address, issued_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![nonce, address, issued_at, expires_at],
        )
        .map_err(|e| AuthError::Internal(format!("insert auth_nonce: {}", e)))?;
        Ok(())
    }

    /// Atomically consume a nonce. Returns the bound address + expiry on
    /// success, or `NotFoundOrConsumed` / `Expired`.
    ///
    /// Race-safe: the UPDATE has `WHERE consumed_at IS NULL` so two
    /// concurrent consume calls for the same nonce can both target the
    /// row, but only one will see `rows_affected = 1`. The other sees
    /// `0` and treats it as already-consumed.
    pub fn consume(&self, nonce: &str, now: i64) -> Result<ConsumeOutcome, AuthError> {
        let conn = self.lock()?;

        // First peek: is the nonce expired? If so we don't want to consume it.
        let peek: Option<(String, i64, i64, Option<i64>)> = conn
            .query_row(
                "SELECT address, issued_at, expires_at, consumed_at FROM auth_nonces WHERE nonce = ?1",
                params![nonce],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("peek auth_nonce: {}", e)))?;

        let (address, _issued_at, expires_at, consumed_at) = match peek {
            None => return Ok(ConsumeOutcome::NotFoundOrConsumed),
            Some(t) => t,
        };

        if consumed_at.is_some() {
            return Ok(ConsumeOutcome::NotFoundOrConsumed);
        }
        if expires_at < now {
            return Ok(ConsumeOutcome::Expired);
        }

        // Race-safe atomic consume.
        let rows = conn
            .execute(
                "UPDATE auth_nonces SET consumed_at = ?1 WHERE nonce = ?2 AND consumed_at IS NULL",
                params![now, nonce],
            )
            .map_err(|e| AuthError::Internal(format!("update auth_nonce: {}", e)))?;

        if rows == 0 {
            // Lost the race to another request.
            Ok(ConsumeOutcome::NotFoundOrConsumed)
        } else {
            Ok(ConsumeOutcome::Consumed {
                address,
                expires_at,
            })
        }
    }

    /// Periodic janitor — DELETE rows older than `retention_seconds` past
    /// expiration. Caller chooses cadence (e.g., every 10 min).
    pub fn purge_expired(&self, now: i64, retention_seconds: i64) -> Result<usize, AuthError> {
        let conn = self.lock()?;
        let cutoff = now - retention_seconds;
        let n = conn
            .execute(
                "DELETE FROM auth_nonces WHERE expires_at < ?1",
                params![cutoff],
            )
            .map_err(|e| AuthError::Internal(format!("purge auth_nonces: {}", e)))?;
        Ok(n)
    }

    /// Quick writability probe used by the WalletSig plugin's `ready()`.
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

    fn store() -> AuthNonceStore {
        AuthNonceStore::open_in_memory().unwrap()
    }

    #[test]
    fn issue_then_consume_round_trip() {
        let s = store();
        s.issue("nonce-A", "0xabc", 100, 200).unwrap();
        let r = s.consume("nonce-A", 150).unwrap();
        assert_eq!(
            r,
            ConsumeOutcome::Consumed {
                address: "0xabc".into(),
                expires_at: 200
            }
        );
    }

    #[test]
    fn consume_unknown_nonce_returns_not_found() {
        let s = store();
        let r = s.consume("never-issued", 100).unwrap();
        assert_eq!(r, ConsumeOutcome::NotFoundOrConsumed);
    }

    #[test]
    fn replay_attempt_returns_not_found_or_consumed() {
        let s = store();
        s.issue("nonce-B", "0xabc", 100, 200).unwrap();
        let first = s.consume("nonce-B", 150).unwrap();
        assert!(matches!(first, ConsumeOutcome::Consumed { .. }));
        // Second consume MUST fail (replay defense).
        let second = s.consume("nonce-B", 160).unwrap();
        assert_eq!(second, ConsumeOutcome::NotFoundOrConsumed);
    }

    #[test]
    fn expired_nonce_is_not_consumable() {
        let s = store();
        s.issue("nonce-C", "0xabc", 100, 200).unwrap();
        // now > expires_at
        let r = s.consume("nonce-C", 300).unwrap();
        assert_eq!(r, ConsumeOutcome::Expired);
        // Even after the failed expired-consume, the row's consumed_at
        // must NOT have been set — but since we collapse to "not consumed"
        // semantics anyway, a subsequent consume at a now-too-late time
        // continues to report Expired (not Consumed).
        let r2 = s.consume("nonce-C", 350).unwrap();
        assert_eq!(r2, ConsumeOutcome::Expired);
    }

    #[test]
    fn issue_rejects_duplicate_nonce() {
        let s = store();
        s.issue("dup", "0xabc", 100, 200).unwrap();
        assert!(s.issue("dup", "0xabc", 100, 200).is_err());
    }

    #[test]
    fn purge_removes_expired_rows() {
        let s = store();
        s.issue("old-1", "0xabc", 100, 200).unwrap();
        s.issue("old-2", "0xabc", 100, 200).unwrap();
        // Fresh row's expires_at must be > cutoff (now - retention) so
        // purge keeps it. cutoff = 10000 - 100 = 9900; pick 20000.
        s.issue("fresh", "0xabc", 1000, 20000).unwrap();
        // now=10000, retention=100 → cutoff=9900; rows with expires_at<9900 deleted.
        let n = s.purge_expired(10000, 100).unwrap();
        assert_eq!(n, 2);
        // Fresh row still consumable (consume time within fresh.expires_at).
        assert!(matches!(
            s.consume("fresh", 15000).unwrap(),
            ConsumeOutcome::Consumed { .. }
        ));
    }

    #[test]
    fn writable_reports_true_for_open_db() {
        let s = store();
        assert!(s.writable());
    }
}
