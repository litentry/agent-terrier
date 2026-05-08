//! `IdempotencyStore` — Idempotency-Key dedup (Phase D-rest, US-037).
//!
//! Per plan §Phase D-rest: clients send `Idempotency-Key: <ulid>` on
//! mint endpoints. The broker:
//! 1. Hashes the request body to a deterministic fingerprint.
//! 2. Looks up the key — if present + body_hash matches, returns the
//!    cached response (no re-mint, no STS quota).
//! 3. If present + body_hash differs → 422 (caller bug).
//! 4. If absent → mint normally, store the response on success.
//!
//! Window default 5 minutes.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::plugins::auth::AuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// Key never seen; caller proceeds with normal mint flow.
    NotSeen,
    /// Key + body_hash match → caller returns the cached response body.
    Replay { response_body: String },
    /// Key matches but body_hash differs → caller returns 422.
    Conflict,
}

pub struct IdempotencyStore {
    conn: Mutex<Connection>,
}

impl IdempotencyStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuthError::Internal(format!("create idempotency dir: {}", e))
            })?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open idempotency db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuthError::Internal(format!("open in-memory idempotency db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("idempotency mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS idempotency_keys (
                key            TEXT PRIMARY KEY,
                body_hash      TEXT NOT NULL,
                response_body  TEXT NOT NULL,
                stored_at      INTEGER NOT NULL,
                expires_at     INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_idempotency_expires
                ON idempotency_keys(expires_at);",
        )
        .map_err(|e| AuthError::Internal(format!("init idempotency schema: {}", e)))?;
        Ok(())
    }

    /// Hash a request body to a deterministic fingerprint. Used as the
    /// idempotency dedup key alongside the Idempotency-Key header.
    pub fn body_hash(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    }

    /// Look up a (key, body_hash) pair. Returns:
    /// - NotSeen → key absent or expired (caller proceeds with mint).
    /// - Replay → key + body_hash match (return cached response).
    /// - Conflict → key matches but body_hash differs (caller bug).
    pub fn check(
        &self,
        key: &str,
        body_hash: &str,
        now: i64,
    ) -> Result<IdempotencyOutcome, AuthError> {
        let conn = self.lock()?;
        let row: Option<(String, String, i64)> = conn
            .query_row(
                "SELECT body_hash, response_body, expires_at FROM idempotency_keys WHERE key = ?1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("idempotency check: {}", e)))?;
        match row {
            None => Ok(IdempotencyOutcome::NotSeen),
            Some((stored_hash, _, expires_at)) if expires_at <= now => {
                let _ = stored_hash;
                Ok(IdempotencyOutcome::NotSeen)
            }
            Some((stored_hash, response_body, _)) if stored_hash == body_hash => {
                Ok(IdempotencyOutcome::Replay { response_body })
            }
            Some(_) => Ok(IdempotencyOutcome::Conflict),
        }
    }

    /// Store a successful response keyed by (key, body_hash). Idempotent —
    /// re-storing under the same key is a no-op (caller raced and lost).
    pub fn store(
        &self,
        key: &str,
        body_hash: &str,
        response_body: &str,
        stored_at: i64,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO idempotency_keys
                (key, body_hash, response_body, stored_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key, body_hash, response_body, stored_at, expires_at],
        )
        .map_err(|e| AuthError::Internal(format!("idempotency store: {}", e)))?;
        Ok(())
    }

    /// Janitor — drop expired rows.
    pub fn purge_expired(&self, now: i64) -> Result<usize, AuthError> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "DELETE FROM idempotency_keys WHERE expires_at <= ?1",
                params![now],
            )
            .map_err(|e| AuthError::Internal(format!("idempotency purge: {}", e)))?;
        Ok(n)
    }

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

    fn store() -> IdempotencyStore {
        IdempotencyStore::open_in_memory().unwrap()
    }

    #[test]
    fn body_hash_is_sha256_hex() {
        let h = IdempotencyStore::body_hash(b"hello");
        assert_eq!(h.len(), 64);
        assert_eq!(h, IdempotencyStore::body_hash(b"hello"));
        assert_ne!(h, IdempotencyStore::body_hash(b"world"));
    }

    #[test]
    fn check_not_seen_for_unknown_key() {
        let s = store();
        let r = s.check("k1", "abc", 100).unwrap();
        assert_eq!(r, IdempotencyOutcome::NotSeen);
    }

    #[test]
    fn store_then_check_returns_replay() {
        let s = store();
        s.store("k1", "abc", r#"{"creds":"..."}"#, 100, 1000).unwrap();
        let r = s.check("k1", "abc", 200).unwrap();
        match r {
            IdempotencyOutcome::Replay { response_body } => {
                assert!(response_body.contains("creds"));
            }
            other => panic!("expected Replay, got {:?}", other),
        }
    }

    #[test]
    fn check_returns_conflict_when_body_hash_differs() {
        let s = store();
        s.store("k1", "abc", "body1", 100, 1000).unwrap();
        let r = s.check("k1", "xyz", 200).unwrap();
        assert_eq!(r, IdempotencyOutcome::Conflict);
    }

    #[test]
    fn expired_key_treated_as_not_seen() {
        let s = store();
        s.store("k1", "abc", "body", 100, 200).unwrap();
        let r = s.check("k1", "abc", 9999).unwrap();
        assert_eq!(r, IdempotencyOutcome::NotSeen);
    }

    #[test]
    fn store_is_idempotent_under_race() {
        let s = store();
        s.store("k1", "abc", "body1", 100, 1000).unwrap();
        // Concurrent caller stores under same key — INSERT OR IGNORE.
        s.store("k1", "abc", "body2", 100, 1000).unwrap();
        let r = s.check("k1", "abc", 200).unwrap();
        match r {
            IdempotencyOutcome::Replay { response_body } => {
                // First write wins.
                assert_eq!(response_body, "body1");
            }
            other => panic!("expected Replay, got {:?}", other),
        }
    }

    #[test]
    fn purge_drops_expired_rows() {
        let s = store();
        s.store("old", "h1", "body1", 100, 200).unwrap();
        s.store("fresh", "h2", "body2", 100, 9999).unwrap();
        let n = s.purge_expired(500).unwrap();
        assert_eq!(n, 1);
        let r = s.check("fresh", "h2", 600).unwrap();
        assert!(matches!(r, IdempotencyOutcome::Replay { .. }));
    }
}
