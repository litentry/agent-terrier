//! `OAuth2PendingStore` — single-use OAuth2 PKCE-verifier + status row
//! (Phase A.2, US-020/021).
//!
//! Per plan §3.5.4: each `POST /v1/auth/oauth2/start` mints a `request_id`
//! and stores `(provider, pkce_verifier, nonce, expires_at)` plus a
//! `pending` status row. On `GET /auth/oauth2/callback`, the broker verifies
//! the state HMAC, atomically consumes this row (UPDATE … WHERE consumed_at
//! IS NULL), exchanges the code at the provider, verifies the id_token,
//! mints a session JWT, and updates the row to `verified` (or `failed`).
//! The CLI polls `/v1/auth/oauth2/status/{request_id}` which reads the row.
//!
//! The state-row layout mirrors `email_request_status` from US-017 with
//! provider + PKCE-verifier + nonce columns added. PKCE verifier stays in
//! the broker only — never sent to the provider until the callback returns.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::plugins::auth::AuthError;

/// SQLite-backed pending-flow store.
pub struct OAuth2PendingStore {
    conn: Mutex<Connection>,
}

/// Outcome of `consume`.
#[derive(Debug, PartialEq, Eq)]
pub enum OAuth2PendingConsume {
    /// Row was unused; consume succeeded; returns the `(provider,
    /// pkce_verifier, nonce)` for the caller to drive the token-exchange
    /// + id-token-verify flow.
    Available {
        provider: String,
        pkce_verifier: String,
        nonce: String,
    },
    /// Either the request_id never existed, or it was already consumed
    /// (collapsed to one variant — same posture as email tokens — so an
    /// attacker probing the table can't distinguish).
    NotFoundOrConsumed,
    /// Row existed and was unused but past its expiration.
    Expired,
}

/// Outcome of `peek_status` — read by the CLI polling endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuth2PendingStatus {
    /// `start` issued, awaiting callback.
    Pending,
    /// Callback completed; verified identity is ready for pickup.
    Verified {
        session_jwt: String,
        omni_account: String,
        identity_value: String,
        expires_at: i64,
    },
    /// Callback failed (provider rejection, expired flow, id_token verify failure).
    Failed { reason: String },
    /// No such request_id (or already-purged).
    Unknown,
}

impl OAuth2PendingStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuthError::Internal(format!("create oauth2_pending dir: {}", e))
            })?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open oauth2_pending db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            AuthError::Internal(format!("open in-memory oauth2_pending db: {}", e))
        })?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("oauth2_pending mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS oauth2_pending (
                request_id     TEXT PRIMARY KEY,
                provider       TEXT NOT NULL,
                pkce_verifier  TEXT NOT NULL,
                nonce          TEXT NOT NULL,
                issued_at      INTEGER NOT NULL,
                expires_at     INTEGER NOT NULL,
                consumed_at    INTEGER,
                status         TEXT NOT NULL DEFAULT 'pending'
                                CHECK(status IN ('pending','verified','failed')),
                session_jwt    TEXT,
                omni_account   TEXT,
                identity_value TEXT,
                failure_reason TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_oauth2_pending_provider
                ON oauth2_pending(provider);
             CREATE INDEX IF NOT EXISTS idx_oauth2_pending_expires_at
                ON oauth2_pending(expires_at);",
        )
        .map_err(|e| AuthError::Internal(format!("init oauth2_pending schema: {}", e)))?;
        Ok(())
    }

    /// Issue a new pending row keyed by `request_id`.
    pub fn issue(
        &self,
        request_id: &str,
        provider: &str,
        pkce_verifier: &str,
        nonce: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO oauth2_pending
                (request_id, provider, pkce_verifier, nonce, issued_at, expires_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            params![
                request_id,
                provider,
                pkce_verifier,
                nonce,
                issued_at,
                expires_at
            ],
        )
        .map_err(|e| AuthError::Internal(format!("insert oauth2_pending: {}", e)))?;
        Ok(())
    }

    /// Atomically consume the pending row. Race-safe via the conditional
    /// UPDATE on `consumed_at IS NULL` (mirrors email_tokens pattern).
    pub fn consume(
        &self,
        request_id: &str,
        now: i64,
    ) -> Result<OAuth2PendingConsume, AuthError> {
        let conn = self.lock()?;
        let peek: Option<(String, String, String, i64, Option<i64>)> = conn
            .query_row(
                "SELECT provider, pkce_verifier, nonce, expires_at, consumed_at
                 FROM oauth2_pending WHERE request_id = ?1",
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
            .map_err(|e| AuthError::Internal(format!("peek oauth2_pending: {}", e)))?;

        let (provider, pkce_verifier, nonce, expires_at, consumed_at) = match peek {
            None => return Ok(OAuth2PendingConsume::NotFoundOrConsumed),
            Some(t) => t,
        };
        if consumed_at.is_some() {
            return Ok(OAuth2PendingConsume::NotFoundOrConsumed);
        }
        if expires_at < now {
            return Ok(OAuth2PendingConsume::Expired);
        }
        let rows = conn
            .execute(
                "UPDATE oauth2_pending SET consumed_at = ?1
                 WHERE request_id = ?2 AND consumed_at IS NULL",
                params![now, request_id],
            )
            .map_err(|e| AuthError::Internal(format!("update oauth2_pending: {}", e)))?;
        if rows == 0 {
            // Lost the race to another callback.
            Ok(OAuth2PendingConsume::NotFoundOrConsumed)
        } else {
            Ok(OAuth2PendingConsume::Available {
                provider,
                pkce_verifier,
                nonce,
            })
        }
    }

    /// Mark a request as verified (called by the callback handler after
    /// the provider's id_token verified + session JWT minted).
    pub fn mark_verified(
        &self,
        request_id: &str,
        session_jwt: &str,
        omni_account: &str,
        identity_value: &str,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        let rows = conn
            .execute(
                "UPDATE oauth2_pending
                 SET status = 'verified',
                     session_jwt = ?2,
                     omni_account = ?3,
                     identity_value = ?4,
                     expires_at = ?5
                 WHERE request_id = ?1 AND status = 'pending'",
                params![request_id, session_jwt, omni_account, identity_value, expires_at],
            )
            .map_err(|e| AuthError::Internal(format!("mark_verified oauth2_pending: {}", e)))?;
        if rows == 0 {
            return Err(AuthError::Internal(format!(
                "mark_verified: no pending row for request_id={}",
                request_id
            )));
        }
        Ok(())
    }

    /// Mark a request as failed (provider rejection, code-exchange failure,
    /// id_token expired, etc.).
    pub fn mark_failed(&self, request_id: &str, reason: &str) -> Result<(), AuthError> {
        let conn = self.lock()?;
        let _ = conn
            .execute(
                "UPDATE oauth2_pending
                 SET status = 'failed', failure_reason = ?2
                 WHERE request_id = ?1 AND status = 'pending'",
                params![request_id, reason],
            )
            .map_err(|e| AuthError::Internal(format!("mark_failed oauth2_pending: {}", e)))?;
        Ok(())
    }

    /// CLI poll endpoint reads this. Returns `Unknown` if request_id
    /// never existed.
    pub fn peek_status(&self, request_id: &str) -> Result<OAuth2PendingStatus, AuthError> {
        type StatusRow = (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
            Option<String>,
        );
        let conn = self.lock()?;
        let row: Option<StatusRow> = conn
            .query_row(
                "SELECT status, session_jwt, omni_account, identity_value, expires_at, failure_reason
                 FROM oauth2_pending WHERE request_id = ?1",
                params![request_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("peek_status oauth2_pending: {}", e)))?;
        let (status, session_jwt, omni_account, identity_value, expires_at, failure_reason) =
            match row {
                None => return Ok(OAuth2PendingStatus::Unknown),
                Some(t) => t,
            };
        match status.as_str() {
            "pending" => Ok(OAuth2PendingStatus::Pending),
            "verified" => Ok(OAuth2PendingStatus::Verified {
                session_jwt: session_jwt.unwrap_or_default(),
                omni_account: omni_account.unwrap_or_default(),
                identity_value: identity_value.unwrap_or_default(),
                expires_at,
            }),
            "failed" => Ok(OAuth2PendingStatus::Failed {
                reason: failure_reason.unwrap_or_else(|| "unknown".into()),
            }),
            other => Err(AuthError::Internal(format!(
                "unknown oauth2_pending status: {}",
                other
            ))),
        }
    }

    /// Janitor — DELETE rows past retention, used by the periodic purge job.
    pub fn purge_expired(&self, now: i64, retention_seconds: i64) -> Result<usize, AuthError> {
        let conn = self.lock()?;
        let cutoff = now - retention_seconds;
        let n = conn
            .execute(
                "DELETE FROM oauth2_pending WHERE expires_at < ?1 AND status != 'verified'",
                params![cutoff],
            )
            .map_err(|e| AuthError::Internal(format!("purge oauth2_pending: {}", e)))?;
        Ok(n)
    }

    /// Quick writability probe used by the OAuth2 plugin's `ready()`.
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

    fn store() -> OAuth2PendingStore {
        OAuth2PendingStore::open_in_memory().unwrap()
    }

    #[test]
    fn issue_creates_pending_row() {
        let s = store();
        s.issue("req-1", "google", "pkce-verifier", "nonce-x", 100, 700)
            .unwrap();
        assert_eq!(s.peek_status("req-1").unwrap(), OAuth2PendingStatus::Pending);
    }

    #[test]
    fn consume_then_mark_verified_round_trip() {
        let s = store();
        s.issue("req-1", "google", "pkce-verifier", "nonce-x", 100, 700)
            .unwrap();
        let outcome = s.consume("req-1", 200).unwrap();
        assert_eq!(
            outcome,
            OAuth2PendingConsume::Available {
                provider: "google".into(),
                pkce_verifier: "pkce-verifier".into(),
                nonce: "nonce-x".into(),
            }
        );
        s.mark_verified("req-1", "eyJsess", "0xomni", "google-sub-1", 800)
            .unwrap();
        let status = s.peek_status("req-1").unwrap();
        match status {
            OAuth2PendingStatus::Verified {
                session_jwt,
                omni_account,
                identity_value,
                expires_at,
            } => {
                assert_eq!(session_jwt, "eyJsess");
                assert_eq!(omni_account, "0xomni");
                assert_eq!(identity_value, "google-sub-1");
                assert_eq!(expires_at, 800);
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn replay_callback_returns_not_found_or_consumed() {
        let s = store();
        s.issue("req-1", "google", "pv", "nx", 100, 700).unwrap();
        let _ = s.consume("req-1", 200).unwrap();
        let replay = s.consume("req-1", 250).unwrap();
        assert_eq!(replay, OAuth2PendingConsume::NotFoundOrConsumed);
    }

    #[test]
    fn expired_flow_is_not_consumable() {
        let s = store();
        s.issue("req-1", "google", "pv", "nx", 100, 200).unwrap();
        let r = s.consume("req-1", 9999).unwrap();
        assert_eq!(r, OAuth2PendingConsume::Expired);
    }

    #[test]
    fn issue_rejects_duplicate_request_id() {
        let s = store();
        s.issue("req-dup", "google", "pv1", "nx", 100, 700).unwrap();
        assert!(s
            .issue("req-dup", "google", "pv2", "nx", 100, 700)
            .is_err());
    }

    #[test]
    fn unknown_request_id_returns_unknown() {
        let s = store();
        assert_eq!(
            s.peek_status("never-issued").unwrap(),
            OAuth2PendingStatus::Unknown
        );
    }

    #[test]
    fn mark_failed_clears_pending() {
        let s = store();
        s.issue("req-x", "google", "pv", "nx", 100, 700).unwrap();
        s.mark_failed("req-x", "user_denied").unwrap();
        match s.peek_status("req-x").unwrap() {
            OAuth2PendingStatus::Failed { reason } => assert!(reason.contains("user_denied")),
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn purge_removes_expired_unverified_rows() {
        let s = store();
        s.issue("old", "google", "pv", "nx", 50, 100).unwrap();
        s.issue("fresh", "google", "pv", "nx", 1000, 20000).unwrap();
        let n = s.purge_expired(10000, 100).unwrap();
        assert_eq!(n, 1);
        // Fresh row still pending.
        assert_eq!(s.peek_status("fresh").unwrap(), OAuth2PendingStatus::Pending);
    }

    #[test]
    fn purge_keeps_verified_rows_for_cli_poll() {
        let s = store();
        s.issue("req-v", "google", "pv", "nx", 50, 100).unwrap();
        s.consume("req-v", 60).unwrap();
        s.mark_verified("req-v", "eyJ", "0xomni", "sub", 200).unwrap();
        // Even though expires_at < cutoff, verified rows are preserved.
        let _ = s.purge_expired(10000, 50).unwrap();
        match s.peek_status("req-v").unwrap() {
            OAuth2PendingStatus::Verified { .. } => {}
            other => panic!("expected Verified preserved, got {:?}", other),
        }
    }
}
