//! `EmailTokenStore` — single-use email-link token storage + per-request
//! status (Phase A.1, US-017).
//!
//! Per plan §3.5.3:
//!
//! - Token bytes = 32 from CSPRNG, base64url. We store ONLY `SHA256(token)`
//!   so a database exfiltration cannot recover usable tokens.
//! - `email_tokens` UNIQUE on `token_hash` + race-safe conditional UPDATE
//!   on `consumed_at IS NULL` enforce single-use.
//! - Two TTLs: token expiry (10 min default) gates verify-time freshness;
//!   `request_status` rows survive longer so the CLI poll can retrieve
//!   the verified session_jwt within the post-click window.
//! - Phase A.1 collapses token + per-request status into ONE module so
//!   the issue/consume/peek-status loop is colocated.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::plugins::auth::AuthError;

/// SQLite-backed email token + per-request status store.
pub struct EmailTokenStore {
    conn: Mutex<Connection>,
}

/// Outcome of `consume_token`.
#[derive(Debug, PartialEq, Eq)]
pub enum EmailConsumeOutcome {
    /// Token was unused; consume succeeded; returns the `request_id` and
    /// `email` so the caller can mint the session JWT and update the
    /// per-request status row.
    Consumed { request_id: String, email: String },
    /// Either the token never existed, or it was already consumed
    /// (collapsed to one variant so an attacker cannot probe the table).
    NotFoundOrConsumed,
    /// Token existed and was unused but is past its expiration.
    Expired,
}

/// Outcome of `peek_status` — read by the CLI polling endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailRequestStatus {
    /// Email sent, awaiting click.
    Pending,
    /// Token consumed; verified identity is ready for pickup.
    Verified {
        session_jwt: String,
        omni_account: String,
        expires_at: i64,
    },
    /// Token expired before consumption, or click failed.
    Failed { reason: String },
    /// No such request_id (or already-cleaned-up).
    Unknown,
}

impl EmailTokenStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::Internal(format!("create email tokens dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open email tokens db: {}", e)))?;
        let store = Self { conn: Mutex::new(conn) };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuthError::Internal(format!("open in-memory email tokens db: {}", e)))?;
        let store = Self { conn: Mutex::new(conn) };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("email tokens mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS email_tokens (
                token_hash   TEXT PRIMARY KEY,
                request_id   TEXT NOT NULL UNIQUE,
                email        TEXT NOT NULL,
                issued_at    INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                consumed_at  INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_email_tokens_request_id ON email_tokens(request_id);
             CREATE INDEX IF NOT EXISTS idx_email_tokens_email ON email_tokens(email);
             CREATE INDEX IF NOT EXISTS idx_email_tokens_expires_at ON email_tokens(expires_at);

             CREATE TABLE IF NOT EXISTS email_request_status (
                request_id     TEXT PRIMARY KEY,
                status         TEXT NOT NULL CHECK(status IN ('pending','verified','failed')),
                session_jwt    TEXT,
                omni_account   TEXT,
                expires_at     INTEGER NOT NULL,
                failure_reason TEXT
             );",
        )
        .map_err(|e| AuthError::Internal(format!("init email tokens schema: {}", e)))?;
        Ok(())
    }

    /// Hash a raw token for storage / lookup. We never persist the raw
    /// token — only `SHA256(token)`.
    pub fn hash_token(token: &str) -> String {
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        hex::encode(h.finalize())
    }

    /// Issue a new (request_id, token_hash) row + a corresponding
    /// `pending` status row. Caller stores the raw token only long enough
    /// to put it in the magic-link URL fragment.
    pub fn issue(
        &self,
        token: &str,
        request_id: &str,
        email: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let token_hash = Self::hash_token(token);
        let conn = self.lock()?;

        // Both rows must land or neither — wrap in a transaction.
        let tx = conn.unchecked_transaction()
            .map_err(|e| AuthError::Internal(format!("begin tx: {}", e)))?;
        tx.execute(
            "INSERT INTO email_tokens (token_hash, request_id, email, issued_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![token_hash, request_id, email, issued_at, expires_at],
        )
        .map_err(|e| AuthError::Internal(format!("insert email_token: {}", e)))?;
        tx.execute(
            "INSERT INTO email_request_status (request_id, status, expires_at)
             VALUES (?1, 'pending', ?2)",
            params![request_id, expires_at],
        )
        .map_err(|e| AuthError::Internal(format!("insert email_request_status: {}", e)))?;
        tx.commit()
            .map_err(|e| AuthError::Internal(format!("commit email issue: {}", e)))?;
        Ok(())
    }

    /// Atomically consume a token by raw value. Internally hashes and
    /// runs `WHERE consumed_at IS NULL` conditional UPDATE.
    pub fn consume_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<EmailConsumeOutcome, AuthError> {
        let token_hash = Self::hash_token(token);
        let conn = self.lock()?;

        let peek: Option<(String, String, i64, Option<i64>)> = conn
            .query_row(
                "SELECT request_id, email, expires_at, consumed_at
                 FROM email_tokens WHERE token_hash = ?1",
                params![token_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("peek email_token: {}", e)))?;

        let (request_id, email, expires_at, consumed_at) = match peek {
            None => return Ok(EmailConsumeOutcome::NotFoundOrConsumed),
            Some(t) => t,
        };
        if consumed_at.is_some() {
            return Ok(EmailConsumeOutcome::NotFoundOrConsumed);
        }
        if expires_at < now {
            return Ok(EmailConsumeOutcome::Expired);
        }

        let rows = conn
            .execute(
                "UPDATE email_tokens SET consumed_at = ?1
                 WHERE token_hash = ?2 AND consumed_at IS NULL",
                params![now, token_hash],
            )
            .map_err(|e| AuthError::Internal(format!("update email_token: {}", e)))?;
        if rows == 0 {
            // Lost the race to another verify call.
            Ok(EmailConsumeOutcome::NotFoundOrConsumed)
        } else {
            Ok(EmailConsumeOutcome::Consumed { request_id, email })
        }
    }

    /// Mark a request as verified (called by /verify after consume_token
    /// succeeded + session JWT minted).
    pub fn mark_verified(
        &self,
        request_id: &str,
        session_jwt: &str,
        omni_account: &str,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        let rows = conn
            .execute(
                "UPDATE email_request_status
                 SET status = 'verified',
                     session_jwt = ?2,
                     omni_account = ?3,
                     expires_at = ?4
                 WHERE request_id = ?1 AND status = 'pending'",
                params![request_id, session_jwt, omni_account, expires_at],
            )
            .map_err(|e| AuthError::Internal(format!("mark_verified: {}", e)))?;
        if rows == 0 {
            return Err(AuthError::Internal(format!(
                "mark_verified: no pending row for request_id={}",
                request_id
            )));
        }
        Ok(())
    }

    /// Mark a request as failed (token expired before click, etc.).
    pub fn mark_failed(&self, request_id: &str, reason: &str) -> Result<(), AuthError> {
        let conn = self.lock()?;
        let _ = conn
            .execute(
                "UPDATE email_request_status
                 SET status = 'failed', failure_reason = ?2
                 WHERE request_id = ?1 AND status = 'pending'",
                params![request_id, reason],
            )
            .map_err(|e| AuthError::Internal(format!("mark_failed: {}", e)))?;
        Ok(())
    }

    /// CLI poll endpoint reads this. Returns `Unknown` if request_id
    /// never existed (or was purged).
    pub fn peek_status(&self, request_id: &str) -> Result<EmailRequestStatus, AuthError> {
        // Tuple alias to keep clippy::type_complexity quiet — the SELECT
        // returns 5 nullable / non-nullable columns.
        type StatusRow = (String, Option<String>, Option<String>, i64, Option<String>);
        let conn = self.lock()?;
        let row: Option<StatusRow> = conn
            .query_row(
                "SELECT status, session_jwt, omni_account, expires_at, failure_reason
                 FROM email_request_status WHERE request_id = ?1",
                params![request_id],
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
            .map_err(|e| AuthError::Internal(format!("peek_status: {}", e)))?;
        let (status, session_jwt, omni_account, expires_at, failure_reason) = match row {
            None => return Ok(EmailRequestStatus::Unknown),
            Some(t) => t,
        };
        match status.as_str() {
            "pending" => Ok(EmailRequestStatus::Pending),
            "verified" => Ok(EmailRequestStatus::Verified {
                session_jwt: session_jwt.unwrap_or_default(),
                omni_account: omni_account.unwrap_or_default(),
                expires_at,
            }),
            "failed" => Ok(EmailRequestStatus::Failed {
                reason: failure_reason.unwrap_or_else(|| "unknown".into()),
            }),
            other => Err(AuthError::Internal(format!(
                "unknown status string in row: {}",
                other
            ))),
        }
    }

    /// Periodic janitor — DELETE expired token rows + their status rows.
    pub fn purge_expired(&self, now: i64, retention_seconds: i64) -> Result<usize, AuthError> {
        let conn = self.lock()?;
        let cutoff = now - retention_seconds;
        let token_n = conn
            .execute(
                "DELETE FROM email_tokens WHERE expires_at < ?1",
                params![cutoff],
            )
            .map_err(|e| AuthError::Internal(format!("purge email_tokens: {}", e)))?;
        let _ = conn
            .execute(
                "DELETE FROM email_request_status WHERE expires_at < ?1 AND status != 'verified'",
                params![cutoff],
            )
            .map_err(|e| AuthError::Internal(format!("purge email_request_status: {}", e)))?;
        Ok(token_n)
    }

    /// Quick writability probe used by the EmailLink plugin's `ready()`.
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

    fn store() -> EmailTokenStore {
        EmailTokenStore::open_in_memory().unwrap()
    }

    #[test]
    fn issue_creates_pending_row_and_token() {
        let s = store();
        s.issue("tok-abc", "req-1", "alice@x.com", 100, 700).unwrap();
        assert_eq!(s.peek_status("req-1").unwrap(), EmailRequestStatus::Pending);
    }

    #[test]
    fn consume_then_mark_verified_round_trip() {
        let s = store();
        s.issue("tok-abc", "req-1", "alice@x.com", 100, 700).unwrap();
        let outcome = s.consume_token("tok-abc", 200).unwrap();
        assert_eq!(
            outcome,
            EmailConsumeOutcome::Consumed {
                request_id: "req-1".into(),
                email: "alice@x.com".into()
            }
        );
        s.mark_verified("req-1", "eyJsess", "0xomni", 800).unwrap();
        let status = s.peek_status("req-1").unwrap();
        match status {
            EmailRequestStatus::Verified {
                session_jwt,
                omni_account,
                expires_at,
            } => {
                assert_eq!(session_jwt, "eyJsess");
                assert_eq!(omni_account, "0xomni");
                assert_eq!(expires_at, 800);
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn replay_token_returns_not_found_or_consumed() {
        let s = store();
        s.issue("tok-abc", "req-1", "alice@x.com", 100, 700).unwrap();
        let _ = s.consume_token("tok-abc", 200).unwrap();
        let replay = s.consume_token("tok-abc", 250).unwrap();
        assert_eq!(replay, EmailConsumeOutcome::NotFoundOrConsumed);
    }

    #[test]
    fn expired_token_is_not_consumable() {
        let s = store();
        s.issue("tok-old", "req-1", "alice@x.com", 100, 200).unwrap();
        // now > expires_at
        let r = s.consume_token("tok-old", 9999).unwrap();
        assert_eq!(r, EmailConsumeOutcome::Expired);
    }

    #[test]
    fn issue_rejects_duplicate_request_id() {
        let s = store();
        s.issue("tok-1", "req-dup", "alice@x.com", 100, 700).unwrap();
        // Different token but duplicate request_id: rejected by UNIQUE constraint.
        assert!(s.issue("tok-2", "req-dup", "alice@x.com", 100, 700).is_err());
    }

    #[test]
    fn unknown_request_id_returns_unknown() {
        let s = store();
        assert_eq!(
            s.peek_status("never-issued").unwrap(),
            EmailRequestStatus::Unknown
        );
    }

    #[test]
    fn mark_failed_clears_pending() {
        let s = store();
        s.issue("tok-x", "req-x", "a@b.com", 100, 700).unwrap();
        s.mark_failed("req-x", "expired before click").unwrap();
        match s.peek_status("req-x").unwrap() {
            EmailRequestStatus::Failed { reason } => assert!(reason.contains("expired")),
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn purge_removes_expired_rows() {
        let s = store();
        s.issue("tok-old1", "req-old1", "a@b.com", 50, 100).unwrap();
        s.issue("tok-old2", "req-old2", "a@b.com", 50, 150).unwrap();
        s.issue("tok-fresh", "req-fresh", "a@b.com", 1000, 20000)
            .unwrap();
        let n = s.purge_expired(10000, 100).unwrap();
        assert_eq!(n, 2);
        // Fresh row still consumable.
        let r = s.consume_token("tok-fresh", 15000).unwrap();
        assert!(matches!(r, EmailConsumeOutcome::Consumed { .. }));
    }

    #[test]
    fn hash_token_is_sha256_hex() {
        let h = EmailTokenStore::hash_token("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable: same input → same hash.
        assert_eq!(h, EmailTokenStore::hash_token("hello"));
    }
}
