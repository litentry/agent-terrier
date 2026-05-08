//! `GrantStore` — capability-grant storage (Phase B, US-025).
//!
//! Per plan §3.5.5: grants are first-class data, not implicit storage rows.
//! Each grant authorizes a `daemon_address` to mint AWS credentials for a
//! specific `(service, scope_path)` on behalf of a master OmniAccount,
//! bounded by `expires_at` + `max_uses`. The mint flow resolves the
//! active grant atomically (`UPDATE … SET used_count=used_count+1`).
//!
//! `audit_proof` is the broker's ES256-signed JWT over the grant content
//! (canonical claim shape). Tampering with the SQLite row breaks JWT
//! verification — defense-in-depth against DB exfiltration.
//!
//! Phase E will swap canonical JSON for canonical CBOR per V0.1-FOLLOWUPS
//! R1-F3 (codex round 1). The wire shape stays compact-JWS either way.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::plugins::auth::AuthError;

/// Outcome of `try_consume` — atomic match-and-increment on `(omni, daemon, service)`.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantConsumeOutcome {
    /// Grant matched + was unexpired + had remaining uses + non-revoked;
    /// `used_count` incremented; returns the resolved grant_id.
    Consumed { grant_id: String, audit_proof: String },
    /// No grant exists for `(omni, daemon, service)`.
    NoGrant,
    /// Grant exists but is revoked.
    Revoked,
    /// Grant exists but is expired.
    Expired,
    /// Grant exists but `used_count >= max_uses`.
    Exhausted,
}

/// Public-shape grant row. Used by `list` and the audit-proof verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub grant_id: String,
    pub master_omni_account: String,
    pub daemon_address: String,
    pub service: String,
    pub scope_path: String,
    pub granted_at: i64,
    pub expires_at: i64,
    pub max_uses: i64,
    pub used_count: i64,
    pub revoked_at: Option<i64>,
    pub audit_proof: String,
}

pub struct GrantStore {
    conn: Mutex<Connection>,
}

impl GrantStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::Internal(format!("create grants dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open grants db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuthError::Internal(format!("open in-memory grants db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("grants mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS grants (
                grant_id            TEXT PRIMARY KEY,
                master_omni_account TEXT NOT NULL,
                daemon_address      TEXT NOT NULL,
                service             TEXT NOT NULL,
                scope_path          TEXT NOT NULL,
                granted_at          INTEGER NOT NULL,
                expires_at          INTEGER NOT NULL,
                max_uses            INTEGER NOT NULL,
                used_count          INTEGER NOT NULL DEFAULT 0,
                revoked_at          INTEGER,
                audit_proof         TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_grants_master ON grants(master_omni_account);
             CREATE INDEX IF NOT EXISTS idx_grants_daemon ON grants(daemon_address);
             CREATE INDEX IF NOT EXISTS idx_grants_service ON grants(service);",
        )
        .map_err(|e| AuthError::Internal(format!("init grants schema: {}", e)))?;
        Ok(())
    }

    /// Insert a new grant. Caller mints `audit_proof` (compact JWS) before
    /// calling and passes it as `audit_proof`.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        grant_id: &str,
        master_omni_account: &str,
        daemon_address: &str,
        service: &str,
        scope_path: &str,
        granted_at: i64,
        expires_at: i64,
        max_uses: i64,
        audit_proof: &str,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO grants
                (grant_id, master_omni_account, daemon_address, service, scope_path,
                 granted_at, expires_at, max_uses, used_count, revoked_at, audit_proof)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, NULL, ?9)",
            params![
                grant_id,
                master_omni_account,
                daemon_address,
                service,
                scope_path,
                granted_at,
                expires_at,
                max_uses,
                audit_proof,
            ],
        )
        .map_err(|e| AuthError::Internal(format!("insert grant: {}", e)))?;
        Ok(())
    }

    /// Mark a grant `revoked` (sets `revoked_at`). Idempotent — re-revoke
    /// is a no-op (no-op = 0 rows updated, surfaces to caller).
    pub fn revoke(
        &self,
        grant_id: &str,
        master_omni_account: &str,
        revoked_at: i64,
    ) -> Result<bool, AuthError> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "UPDATE grants
                 SET revoked_at = ?1
                 WHERE grant_id = ?2 AND master_omni_account = ?3 AND revoked_at IS NULL",
                params![revoked_at, grant_id, master_omni_account],
            )
            .map_err(|e| AuthError::Internal(format!("revoke grant: {}", e)))?;
        Ok(n == 1)
    }

    /// List active + revoked grants for a master OmniAccount. Used by
    /// `GET /v1/grant/list`.
    pub fn list_for_master(&self, master_omni_account: &str) -> Result<Vec<Grant>, AuthError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT grant_id, master_omni_account, daemon_address, service, scope_path,
                        granted_at, expires_at, max_uses, used_count, revoked_at, audit_proof
                 FROM grants
                 WHERE master_omni_account = ?1
                 ORDER BY granted_at DESC",
            )
            .map_err(|e| AuthError::Internal(format!("prepare list grants: {}", e)))?;
        let rows = stmt
            .query_map(params![master_omni_account], |row| {
                Ok(Grant {
                    grant_id: row.get(0)?,
                    master_omni_account: row.get(1)?,
                    daemon_address: row.get(2)?,
                    service: row.get(3)?,
                    scope_path: row.get(4)?,
                    granted_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    max_uses: row.get(7)?,
                    used_count: row.get(8)?,
                    revoked_at: row.get(9)?,
                    audit_proof: row.get(10)?,
                })
            })
            .map_err(|e| AuthError::Internal(format!("query list grants: {}", e)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| AuthError::Internal(format!("row: {}", e)))?);
        }
        Ok(out)
    }

    /// Look up the current state of a grant for diagnostics / verify-time.
    pub fn lookup(&self, grant_id: &str) -> Result<Option<Grant>, AuthError> {
        let conn = self.lock()?;
        let g = conn
            .query_row(
                "SELECT grant_id, master_omni_account, daemon_address, service, scope_path,
                        granted_at, expires_at, max_uses, used_count, revoked_at, audit_proof
                 FROM grants WHERE grant_id = ?1",
                params![grant_id],
                |row| {
                    Ok(Grant {
                        grant_id: row.get(0)?,
                        master_omni_account: row.get(1)?,
                        daemon_address: row.get(2)?,
                        service: row.get(3)?,
                        scope_path: row.get(4)?,
                        granted_at: row.get(5)?,
                        expires_at: row.get(6)?,
                        max_uses: row.get(7)?,
                        used_count: row.get(8)?,
                        revoked_at: row.get(9)?,
                        audit_proof: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("lookup grant: {}", e)))?;
        Ok(g)
    }

    /// Atomically resolve + consume a grant for `(omni, daemon, service)`.
    /// Plan §3.5.5 invariant — used by the mint handler; failure modes
    /// (NoGrant / Revoked / Expired / Exhausted) all map to 403.
    ///
    /// Codex round-2 Vector 5 P1 mitigation: the consume is ONE atomic
    /// `UPDATE … RETURNING` (rusqlite ≥ SQLite 3.35) so no Rust-level
    /// peek-then-update race exists. A separate diagnostic query runs
    /// only when the atomic update returns no rows, to classify the
    /// reason (NoGrant / Revoked / Expired / Exhausted) for the caller.
    pub fn try_consume(
        &self,
        master_omni_account: &str,
        daemon_address: &str,
        service: &str,
        now: i64,
    ) -> Result<GrantConsumeOutcome, AuthError> {
        let conn = self.lock()?;
        // Single-statement atomic resolve + consume. We rely on
        // SQLite's UPDATE … FROM … RETURNING (3.35+, bundled rusqlite).
        // The inner SELECT picks the newest matching live grant; the
        // outer UPDATE increments only if the row's still live.
        let consumed: Option<(String, String)> = conn
            .query_row(
                "UPDATE grants
                 SET used_count = used_count + 1
                 WHERE grant_id = (
                    SELECT grant_id FROM grants
                    WHERE master_omni_account = ?1
                      AND daemon_address = ?2
                      AND service = ?3
                      AND revoked_at IS NULL
                      AND expires_at > ?4
                      AND used_count < max_uses
                    ORDER BY granted_at DESC
                    LIMIT 1
                 )
                 RETURNING grant_id, audit_proof",
                params![master_omni_account, daemon_address, service, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("atomic grant consume: {}", e)))?;
        if let Some((grant_id, audit_proof)) = consumed {
            return Ok(GrantConsumeOutcome::Consumed {
                grant_id,
                audit_proof,
            });
        }
        // No row consumed — classify why for the caller's 403 message.
        // This branch never fires on the hot path (where consume
        // succeeded above); only when the grant is gone or unusable.
        let peek: Option<(i64, Option<i64>, i64, i64)> = conn
            .query_row(
                "SELECT expires_at, revoked_at, max_uses, used_count
                 FROM grants
                 WHERE master_omni_account = ?1
                   AND daemon_address = ?2
                   AND service = ?3
                 ORDER BY granted_at DESC
                 LIMIT 1",
                params![master_omni_account, daemon_address, service],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("classify grant: {}", e)))?;
        match peek {
            None => Ok(GrantConsumeOutcome::NoGrant),
            Some((_, Some(_), _, _)) => Ok(GrantConsumeOutcome::Revoked),
            Some((expires_at, None, _, _)) if expires_at < now => Ok(GrantConsumeOutcome::Expired),
            Some((_, None, max_uses, used_count)) if used_count >= max_uses => {
                Ok(GrantConsumeOutcome::Exhausted)
            }
            // Race: row was live during the diagnostic SELECT but not
            // during the UPDATE … RETURNING. Treat as Exhausted (caller
            // gets 403 + retry hint).
            Some(_) => Ok(GrantConsumeOutcome::Exhausted),
        }
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

    fn store() -> GrantStore {
        GrantStore::open_in_memory().unwrap()
    }

    #[test]
    fn create_and_lookup_round_trip() {
        let s = store();
        s.create(
            "grn-1",
            "0xomni-master",
            "0xdaemon-1",
            "s3",
            "bots/0xdaemon-1/",
            100,
            1000,
            10,
            "eyJhdWRpdF9wcm9vZi5qd3QifQ.fake",
        )
        .unwrap();
        let g = s.lookup("grn-1").unwrap().unwrap();
        assert_eq!(g.master_omni_account, "0xomni-master");
        assert_eq!(g.daemon_address, "0xdaemon-1");
        assert_eq!(g.max_uses, 10);
        assert_eq!(g.used_count, 0);
        assert!(g.revoked_at.is_none());
    }

    #[test]
    fn try_consume_increments_used_count_and_returns_id() {
        let s = store();
        s.create("grn-1", "om", "da", "s3", "p/", 100, 1000, 5, "p")
            .unwrap();
        let outcome = s.try_consume("om", "da", "s3", 200).unwrap();
        assert!(matches!(outcome, GrantConsumeOutcome::Consumed { ref grant_id, .. } if grant_id == "grn-1"));
        let g = s.lookup("grn-1").unwrap().unwrap();
        assert_eq!(g.used_count, 1);
    }

    #[test]
    fn try_consume_returns_no_grant_when_unknown() {
        let s = store();
        let outcome = s.try_consume("om", "da", "s3", 200).unwrap();
        assert!(matches!(outcome, GrantConsumeOutcome::NoGrant));
    }

    #[test]
    fn try_consume_rejects_expired_grant() {
        let s = store();
        s.create("grn-1", "om", "da", "s3", "p/", 100, 200, 5, "p")
            .unwrap();
        let outcome = s.try_consume("om", "da", "s3", 999).unwrap();
        assert!(matches!(outcome, GrantConsumeOutcome::Expired));
    }

    #[test]
    fn try_consume_rejects_revoked_grant() {
        let s = store();
        s.create("grn-1", "om", "da", "s3", "p/", 100, 1000, 5, "p")
            .unwrap();
        let did = s.revoke("grn-1", "om", 150).unwrap();
        assert!(did);
        let outcome = s.try_consume("om", "da", "s3", 200).unwrap();
        assert!(matches!(outcome, GrantConsumeOutcome::Revoked));
    }

    #[test]
    fn try_consume_rejects_exhausted_grant() {
        let s = store();
        s.create("grn-1", "om", "da", "s3", "p/", 100, 1000, 1, "p")
            .unwrap();
        s.try_consume("om", "da", "s3", 200).unwrap();
        let outcome = s.try_consume("om", "da", "s3", 200).unwrap();
        assert!(matches!(outcome, GrantConsumeOutcome::Exhausted));
    }

    #[test]
    fn revoke_only_succeeds_for_correct_master() {
        let s = store();
        s.create("grn-1", "om-real", "da", "s3", "p/", 100, 1000, 5, "p")
            .unwrap();
        // Wrong master cannot revoke.
        assert!(!s.revoke("grn-1", "om-attacker", 200).unwrap());
        // Right master can.
        assert!(s.revoke("grn-1", "om-real", 200).unwrap());
        // Re-revoke is no-op.
        assert!(!s.revoke("grn-1", "om-real", 300).unwrap());
    }

    #[test]
    fn list_for_master_orders_newest_first() {
        let s = store();
        s.create("grn-1", "om", "d1", "s3", "p/", 100, 1000, 5, "p")
            .unwrap();
        s.create("grn-2", "om", "d2", "s3", "p/", 200, 1000, 5, "p")
            .unwrap();
        let grants = s.list_for_master("om").unwrap();
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].grant_id, "grn-2");
        assert_eq!(grants[1].grant_id, "grn-1");
    }

    #[test]
    fn most_recent_matching_grant_wins() {
        let s = store();
        s.create("grn-old", "om", "da", "s3", "old/", 100, 1000, 5, "p1")
            .unwrap();
        s.create("grn-new", "om", "da", "s3", "new/", 200, 1000, 5, "p2")
            .unwrap();
        let outcome = s.try_consume("om", "da", "s3", 300).unwrap();
        assert!(matches!(
            outcome,
            GrantConsumeOutcome::Consumed { ref grant_id, .. } if grant_id == "grn-new"
        ));
    }
}
