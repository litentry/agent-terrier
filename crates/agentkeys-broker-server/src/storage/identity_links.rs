//! `IdentityLinkStore` — multi-identity binding (Phase B, US-028).
//!
//! Per plan §3.5.5 + §Phase B: a master OmniAccount can attach
//! additional verified identities (email, oauth2_google, second EVM
//! wallet, etc.). These additional identities are NOT direct mint
//! authority — that's the role of the grant store. They support the
//! recovery flow: if the original master wallet is lost, an authenticated
//! caller via a linked identity can request a recovery grant on a NEW
//! daemon address, but the recovery grant itself is signed by an
//! existing master via /v1/grant/create. There is NO email-only
//! takeover path (Codex P0 #4 from earlier session).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::plugins::auth::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityLink {
    pub omni_account: String,
    /// Canonical identity-type string ("evm", "email", "oauth2_google", …)
    /// — same convention as `IdentityType::canonical()`.
    pub identity_type: String,
    pub identity_value: String,
    pub linked_at: i64,
}

pub struct IdentityLinkStore {
    conn: Mutex<Connection>,
}

impl IdentityLinkStore {
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::Internal(format!("create identity_links dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| AuthError::Internal(format!("open identity_links db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuthError::Internal(format!("open in-memory identity_links db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthError> {
        self.conn
            .lock()
            .map_err(|e| AuthError::Internal(format!("identity_links mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS identity_links (
                omni_account    TEXT NOT NULL,
                identity_type   TEXT NOT NULL,
                identity_value  TEXT NOT NULL,
                linked_at       INTEGER NOT NULL,
                PRIMARY KEY (omni_account, identity_type, identity_value)
             );
             CREATE INDEX IF NOT EXISTS idx_identity_links_lookup
                ON identity_links(identity_type, identity_value);",
        )
        .map_err(|e| AuthError::Internal(format!("init identity_links schema: {}", e)))?;
        Ok(())
    }

    /// Link a new identity to a master OmniAccount. Idempotent on
    /// `(omni_account, identity_type, identity_value)`.
    pub fn link(
        &self,
        omni_account: &str,
        identity_type: &str,
        identity_value: &str,
        linked_at: i64,
    ) -> Result<(), AuthError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO identity_links
                (omni_account, identity_type, identity_value, linked_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![omni_account, identity_type, identity_value, linked_at],
        )
        .map_err(|e| AuthError::Internal(format!("insert identity_link: {}", e)))?;
        Ok(())
    }

    /// Lookup the master OmniAccount that owns a given identity. Used by
    /// the recovery flow to discover which master should be solicited
    /// to issue a recovery grant.
    pub fn owner_of(
        &self,
        identity_type: &str,
        identity_value: &str,
    ) -> Result<Option<String>, AuthError> {
        let conn = self.lock()?;
        let owner: Option<String> = conn
            .query_row(
                "SELECT omni_account FROM identity_links
                 WHERE identity_type = ?1 AND identity_value = ?2",
                params![identity_type, identity_value],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AuthError::Internal(format!("owner_of identity_link: {}", e)))?;
        Ok(owner)
    }

    /// List all identities linked to a master OmniAccount. Used by the
    /// recovery flow's "notify all linked addresses".
    pub fn list_for_master(&self, omni_account: &str) -> Result<Vec<IdentityLink>, AuthError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT omni_account, identity_type, identity_value, linked_at
                 FROM identity_links WHERE omni_account = ?1
                 ORDER BY linked_at DESC",
            )
            .map_err(|e| AuthError::Internal(format!("prepare list_for_master: {}", e)))?;
        let rows = stmt
            .query_map(params![omni_account], |row| {
                Ok(IdentityLink {
                    omni_account: row.get(0)?,
                    identity_type: row.get(1)?,
                    identity_value: row.get(2)?,
                    linked_at: row.get(3)?,
                })
            })
            .map_err(|e| AuthError::Internal(format!("query identity_links: {}", e)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| AuthError::Internal(format!("row: {}", e)))?);
        }
        Ok(out)
    }

    /// Unlink an identity. Returns true if a row was deleted.
    pub fn unlink(
        &self,
        omni_account: &str,
        identity_type: &str,
        identity_value: &str,
    ) -> Result<bool, AuthError> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "DELETE FROM identity_links
                 WHERE omni_account = ?1 AND identity_type = ?2 AND identity_value = ?3",
                params![omni_account, identity_type, identity_value],
            )
            .map_err(|e| AuthError::Internal(format!("unlink identity_link: {}", e)))?;
        Ok(n == 1)
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

    fn store() -> IdentityLinkStore {
        IdentityLinkStore::open_in_memory().unwrap()
    }

    #[test]
    fn link_and_lookup_round_trip() {
        let s = store();
        s.link("0xomni-master", "email", "alice@example.com", 100)
            .unwrap();
        let owner = s.owner_of("email", "alice@example.com").unwrap();
        assert_eq!(owner.as_deref(), Some("0xomni-master"));
    }

    #[test]
    fn link_is_idempotent() {
        let s = store();
        s.link("0xom", "email", "a@b.com", 100).unwrap();
        s.link("0xom", "email", "a@b.com", 200).unwrap();
        let all = s.list_for_master("0xom").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].linked_at, 100); // first write wins (INSERT OR IGNORE)
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let s = store();
        let r = s.owner_of("email", "ghost@example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn list_for_master_orders_newest_first() {
        let s = store();
        s.link("0xom", "email", "a@b.com", 100).unwrap();
        s.link("0xom", "oauth2_google", "google-sub-1", 200)
            .unwrap();
        s.link("0xom", "evm", "0xsecondwallet", 150).unwrap();
        let all = s.list_for_master("0xom").unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].identity_type, "oauth2_google"); // newest
        assert_eq!(all[2].identity_type, "email"); // oldest
    }

    #[test]
    fn unlink_returns_true_on_match() {
        let s = store();
        s.link("0xom", "email", "a@b.com", 100).unwrap();
        assert!(s.unlink("0xom", "email", "a@b.com").unwrap());
        assert!(!s.unlink("0xom", "email", "a@b.com").unwrap());
        assert!(s.list_for_master("0xom").unwrap().is_empty());
    }

    #[test]
    fn cross_master_lookup_isolated() {
        let s = store();
        s.link("0xalice", "email", "a@b.com", 100).unwrap();
        s.link("0xbob", "email", "b@c.com", 200).unwrap();
        assert_eq!(
            s.owner_of("email", "a@b.com").unwrap().as_deref(),
            Some("0xalice")
        );
        assert_eq!(
            s.owner_of("email", "b@c.com").unwrap().as_deref(),
            Some("0xbob")
        );
        assert_eq!(s.list_for_master("0xalice").unwrap().len(), 1);
    }
}
