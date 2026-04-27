use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::error::{BrokerError, BrokerResult};

pub struct AuditLog {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct MintRecord<'a> {
    pub requester_token: &'a str,
    pub requester_wallet: &'a str,
    pub requested_role: &'a str,
    pub session_duration_seconds: i32,
    pub sts_session_name: &'a str,
    pub outcome: MintOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintOutcome {
    Ok,
    AuthFailed,
    BackendError,
    StsError,
}

impl MintOutcome {
    fn as_str(self) -> &'static str {
        match self {
            MintOutcome::Ok => "ok",
            MintOutcome::AuthFailed => "auth_failed",
            MintOutcome::BackendError => "backend_error",
            MintOutcome::StsError => "sts_error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MintRow {
    pub minted_at: i64,
    pub requester_token_hash: String,
    pub requester_wallet: String,
    pub requested_role: String,
    pub session_duration_seconds: i32,
    pub sts_session_name: String,
    pub outcome: String,
    pub outcome_detail: Option<String>,
}

impl AuditLog {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrokerError::AuditError(format!("create audit dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| BrokerError::AuditError(format!("open audit db: {}", e)))?;
        let log = Self { conn: Mutex::new(conn) };
        log.init_schema()?;
        Ok(log)
    }

    pub fn open_in_memory() -> BrokerResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| BrokerError::AuditError(format!("open in-memory audit db: {}", e)))?;
        let log = Self { conn: Mutex::new(conn) };
        log.init_schema()?;
        Ok(log)
    }

    fn lock_conn(&self) -> BrokerResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| BrokerError::AuditError(format!("audit mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> BrokerResult<()> {
        let conn = self.lock_conn()?;
        // WAL + FULL sync: audit log durability matters more than write throughput.
        // FULL fsyncs the WAL on every commit so a power loss loses at most the
        // currently in-flight mint, not the last N rows.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS mint_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                minted_at INTEGER NOT NULL,
                requester_token_hash TEXT NOT NULL,
                requester_wallet TEXT NOT NULL,
                requested_role TEXT NOT NULL,
                session_duration_seconds INTEGER NOT NULL,
                sts_session_name TEXT NOT NULL,
                outcome TEXT NOT NULL,
                outcome_detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_mint_log_minted_at ON mint_log(minted_at);
            CREATE INDEX IF NOT EXISTS idx_mint_log_wallet ON mint_log(requester_wallet);",
        )
        .map_err(|e| BrokerError::AuditError(format!("init schema: {}", e)))?;
        Ok(())
    }

    pub fn record_mint(&self, record: MintRecord<'_>, detail: Option<&str>) -> BrokerResult<()> {
        // Compute timestamp + hash before grabbing the lock so the critical
        // section is purely the SQLite write.
        let token_hash = hash_token(record.requester_token);
        let now = now_secs();
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO mint_log
             (minted_at, requester_token_hash, requester_wallet, requested_role,
              session_duration_seconds, sts_session_name, outcome, outcome_detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                now as i64,
                token_hash,
                record.requester_wallet,
                record.requested_role,
                record.session_duration_seconds,
                record.sts_session_name,
                record.outcome.as_str(),
                detail,
            ],
        )
        .map_err(|e| BrokerError::AuditError(format!("insert mint: {}", e)))?;
        Ok(())
    }

    pub fn count(&self) -> BrokerResult<i64> {
        let conn = self.lock_conn()?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM mint_log", [], |row| row.get(0))
            .map_err(|e| BrokerError::AuditError(format!("count: {}", e)))?;
        Ok(n)
    }

    pub fn last_row(&self) -> BrokerResult<Option<MintRow>> {
        let conn = self.lock_conn()?;
        let row = conn
            .query_row(
                "SELECT minted_at, requester_token_hash, requester_wallet, requested_role,
                        session_duration_seconds, sts_session_name, outcome, outcome_detail
                 FROM mint_log ORDER BY id DESC LIMIT 1",
                [],
                |row| {
                    Ok(MintRow {
                        minted_at: row.get(0)?,
                        requester_token_hash: row.get(1)?,
                        requester_wallet: row.get(2)?,
                        requested_role: row.get(3)?,
                        session_duration_seconds: row.get(4)?,
                        sts_session_name: row.get(5)?,
                        outcome: row.get(6)?,
                        outcome_detail: row.get(7)?,
                    })
                },
            )
            .ok();
        Ok(row)
    }
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn now_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            tracing::warn!(error = %e, "system clock is before unix epoch; audit row will record minted_at=0");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_deterministic_sha256_hex() {
        let a = hash_token("hello");
        let b = hash_token("hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_distinguishes_tokens() {
        assert_ne!(hash_token("alpha"), hash_token("beta"));
    }

    #[test]
    fn record_mint_roundtrip() {
        let log = AuditLog::open_in_memory().unwrap();
        log.record_mint(
            MintRecord {
                requester_token: "secret-token",
                requester_wallet: "0xabc",
                requested_role: "arn:aws:iam::000:role/foo",
                session_duration_seconds: 3600,
                sts_session_name: "agentkeys-0xabc-123",
                outcome: MintOutcome::Ok,
            },
            None,
        )
        .unwrap();
        assert_eq!(log.count().unwrap(), 1);
        let row = log.last_row().unwrap().expect("expected one row");
        assert_eq!(row.requester_wallet, "0xabc");
        assert_eq!(row.outcome, "ok");
        assert_eq!(row.requester_token_hash, hash_token("secret-token"));
        assert!(row.outcome_detail.is_none());
    }

    #[test]
    fn record_mint_persists_failure_detail() {
        let log = AuditLog::open_in_memory().unwrap();
        log.record_mint(
            MintRecord {
                requester_token: "x",
                requester_wallet: "unknown",
                requested_role: "arn:aws:iam::000:role/foo",
                session_duration_seconds: 3600,
                sts_session_name: "(unauthenticated)",
                outcome: MintOutcome::AuthFailed,
            },
            Some("bearer rejected by backend"),
        )
        .unwrap();
        let row = log.last_row().unwrap().unwrap();
        assert_eq!(row.outcome, "auth_failed");
        assert_eq!(row.outcome_detail.as_deref(), Some("bearer rejected by backend"));
    }
}
