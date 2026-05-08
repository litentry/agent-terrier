//! `EmailRateLimitStore` — sliding bucket store for the email-link auth
//! method's rate limits (per-email-per-hour + per-IP-per-minute).
//!
//! Per plan §3.5.3 + Phase A.1 acceptance: configurable buckets via
//! `BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY` (default 5) and
//! `BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY` (default 30).
//!
//! Implementation is a fixed-window counter per `(bucket_id, window_start)`.
//! Window granularity is the bucket's natural unit (hour or minute) so the
//! schema stays simple and the SQL stays atomic.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::plugins::auth::AuthError;

pub struct EmailRateLimitStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed { remaining: i64 },
    Denied { retry_after_seconds: i64 },
}

impl EmailRateLimitStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::Internal(format!("create email rate limits dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open email rate limits db: {}", e)))?;
        let store = Self { conn: Mutex::new(conn) };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuthError::Internal(format!("open in-memory email rate limits db: {}", e)))?;
        let store = Self { conn: Mutex::new(conn) };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("email rate limit mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS email_rate_limits (
                bucket_id     TEXT NOT NULL,
                window_start  INTEGER NOT NULL,
                count         INTEGER NOT NULL,
                PRIMARY KEY (bucket_id, window_start)
             );
             CREATE INDEX IF NOT EXISTS idx_email_rate_limits_window
                ON email_rate_limits(window_start);",
        )
        .map_err(|e| AuthError::Internal(format!("init email_rate_limits schema: {}", e)))?;
        Ok(())
    }

    /// Atomically increment `bucket_id`'s count for the window containing
    /// `now`. Returns `Allowed` if the post-increment count is still ≤
    /// `limit`; otherwise `Denied`.
    ///
    /// `window_seconds` is the bucket's natural granularity:
    /// 3600 (hour) for per-email; 60 (minute) for per-IP.
    pub fn check_and_increment(
        &self,
        bucket_id: &str,
        now: i64,
        window_seconds: i64,
        limit: i64,
    ) -> Result<RateLimitOutcome, AuthError> {
        if window_seconds <= 0 || limit <= 0 {
            return Err(AuthError::Internal(format!(
                "invalid rate-limit config: window={}s limit={}",
                window_seconds, limit
            )));
        }
        let window_start = (now / window_seconds) * window_seconds;
        let conn = self.lock()?;

        // Read existing count (if any) for this (bucket, window).
        let existing: Option<i64> = conn
            .query_row(
                "SELECT count FROM email_rate_limits
                 WHERE bucket_id = ?1 AND window_start = ?2",
                params![bucket_id, window_start],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("peek rate limit: {}", e)))?;
        let current = existing.unwrap_or(0);

        if current + 1 > limit {
            let next_window_start = window_start + window_seconds;
            let retry_after = (next_window_start - now).max(1);
            return Ok(RateLimitOutcome::Denied {
                retry_after_seconds: retry_after,
            });
        }

        // Atomic increment via UPSERT.
        conn.execute(
            "INSERT INTO email_rate_limits (bucket_id, window_start, count)
             VALUES (?1, ?2, 1)
             ON CONFLICT(bucket_id, window_start) DO UPDATE
                SET count = count + 1",
            params![bucket_id, window_start],
        )
        .map_err(|e| AuthError::Internal(format!("upsert rate limit: {}", e)))?;

        Ok(RateLimitOutcome::Allowed {
            remaining: limit - (current + 1),
        })
    }

    /// Quick writability probe used by /readyz aggregators (Codex
    /// round-1 Vector 10 P2 mitigation: OAuth2Auth::ready() calls this
    /// alongside `pending_store.writable()` so a corrupt rate-limit DB
    /// doesn't sneak past liveness checks).
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

    /// Periodic janitor — drop windows older than 2× the largest
    /// configured window. Caller decides cadence.
    pub fn purge_old_windows(&self, now: i64, retention_seconds: i64) -> Result<usize, AuthError> {
        let conn = self.lock()?;
        let cutoff = now - retention_seconds;
        let n = conn
            .execute(
                "DELETE FROM email_rate_limits WHERE window_start < ?1",
                params![cutoff],
            )
            .map_err(|e| AuthError::Internal(format!("purge rate limits: {}", e)))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> EmailRateLimitStore {
        EmailRateLimitStore::open_in_memory().unwrap()
    }

    #[test]
    fn first_request_allowed_with_remaining() {
        let s = store();
        let r = s
            .check_and_increment("email:a@b.com", 1000, 3600, 5)
            .unwrap();
        assert_eq!(r, RateLimitOutcome::Allowed { remaining: 4 });
    }

    #[test]
    fn limit_enforced_within_window() {
        let s = store();
        for i in 0..5 {
            let r = s
                .check_and_increment("email:a@b.com", 1000 + i, 3600, 5)
                .unwrap();
            assert!(matches!(r, RateLimitOutcome::Allowed { .. }), "iter {}", i);
        }
        // 6th request is denied.
        let r = s.check_and_increment("email:a@b.com", 1010, 3600, 5).unwrap();
        match r {
            RateLimitOutcome::Denied { retry_after_seconds } => {
                assert!(retry_after_seconds > 0 && retry_after_seconds <= 3600);
            }
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn separate_buckets_dont_collide() {
        let s = store();
        for _ in 0..5 {
            let _ = s
                .check_and_increment("email:a@b.com", 1000, 3600, 5)
                .unwrap();
        }
        // Different bucket — fresh allowance.
        let r = s
            .check_and_increment("email:other@b.com", 1000, 3600, 5)
            .unwrap();
        assert_eq!(r, RateLimitOutcome::Allowed { remaining: 4 });
    }

    #[test]
    fn new_window_resets_count() {
        let s = store();
        for _ in 0..5 {
            let _ = s
                .check_and_increment("email:a@b.com", 1000, 3600, 5)
                .unwrap();
        }
        // Move into the next hour window.
        let r = s
            .check_and_increment("email:a@b.com", 5000, 3600, 5)
            .unwrap();
        assert_eq!(r, RateLimitOutcome::Allowed { remaining: 4 });
    }

    #[test]
    fn invalid_config_errors() {
        let s = store();
        assert!(s.check_and_increment("k", 0, 0, 5).is_err());
        assert!(s.check_and_increment("k", 0, 3600, 0).is_err());
    }

    #[test]
    fn purge_drops_old_windows() {
        let s = store();
        let _ = s
            .check_and_increment("email:a@b.com", 100, 3600, 5)
            .unwrap();
        // now=10000, retention=100 → cutoff=9900; the window at ~0 < 9900 is purged.
        let n = s.purge_old_windows(10000, 100).unwrap();
        assert_eq!(n, 1);
    }
}
