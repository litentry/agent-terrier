//! `WalletStore` — single-table SQLite store for (OmniAccount, address)
//! bindings used by `ClientSideKeystoreProvisioner`.
//!
//! Schema mirrors plan §3.5: `(omni_account TEXT, address TEXT lowercase
//! 0x-hex, role TEXT in {'master','daemon'}, parent_address TEXT NULLABLE,
//! created_at INTEGER unix-seconds)`. Composite PK on `(omni_account,
//! address)` so a user can have multiple wallets and re-binding the same
//! address is idempotent.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::plugins::wallet::{WalletAddress, WalletBinding, WalletError, WalletRole};

/// SQLite-backed wallet binding store. Single-process; multi-thread via mutex.
pub struct WalletStore {
    conn: Mutex<Connection>,
}

impl WalletStore {
    pub fn open(path: &Path) -> Result<Self, WalletError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WalletError::Storage(format!("create wallets dir: {}", e)))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| WalletError::Storage(format!("open wallets db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, WalletError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WalletError::Storage(format!("open in-memory wallets db: {}", e)))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, WalletError> {
        self.conn
            .lock()
            .map_err(|e| WalletError::Storage(format!("wallet store mutex poisoned: {}", e)))
    }

    fn init_schema(&self) -> Result<(), WalletError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS wallets (
                omni_account     TEXT NOT NULL,
                address          TEXT NOT NULL,
                role             TEXT NOT NULL CHECK(role IN ('master','daemon')),
                parent_address   TEXT,
                created_at       INTEGER NOT NULL,
                PRIMARY KEY (omni_account, address)
             );
             CREATE INDEX IF NOT EXISTS idx_wallets_omni_account ON wallets(omni_account);",
        )
        .map_err(|e| WalletError::Storage(format!("init wallets schema: {}", e)))?;
        Ok(())
    }

    /// Insert (omni_account, address, role, parent_address). Idempotent
    /// when re-called with the same `(omni_account, address, role)` tuple.
    /// Returns `Storage("role mismatch")` if the same `(omni_account, address)`
    /// already exists with a different role (the only legitimate disambiguator
    /// for an address is the role + parent, so a role flip would be silent
    /// data corruption).
    pub fn bind(
        &self,
        omni_account: &str,
        address: &WalletAddress,
        role: WalletRole,
        parent_address: Option<&WalletAddress>,
        created_at: u64,
    ) -> Result<WalletBinding, WalletError> {
        let conn = self.lock()?;
        // Check existing.
        let existing: Option<(String, Option<String>, i64)> = conn
            .query_row(
                "SELECT role, parent_address, created_at
                 FROM wallets
                 WHERE omni_account = ?1 AND address = ?2",
                params![omni_account, address.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| WalletError::Storage(format!("lookup existing: {}", e)))?;

        if let Some((existing_role, existing_parent, existing_created_at)) = existing {
            // Idempotent if role matches; error otherwise.
            if existing_role != role.as_str() {
                return Err(WalletError::Storage(format!(
                    "role mismatch for ({}, {}): existing={}, requested={}",
                    omni_account,
                    address,
                    existing_role,
                    role.as_str()
                )));
            }
            // Parent must match too — an address bound under one parent
            // and re-bound under another would be a daemon switching masters.
            let req_parent = parent_address.map(|p| p.as_str().to_string());
            if existing_parent != req_parent {
                return Err(WalletError::Storage(format!(
                    "parent mismatch for ({}, {}): existing={:?}, requested={:?}",
                    omni_account, address, existing_parent, req_parent
                )));
            }
            // Reconstruct WalletBinding from existing row.
            return Ok(WalletBinding {
                omni_account: omni_account.to_string(),
                address: address.clone(),
                role,
                parent_address: existing_parent
                    .map(|p| WalletAddress::parse(&p))
                    .transpose()?,
                created_at: existing_created_at as u64,
            });
        }

        // Fresh insert.
        conn.execute(
            "INSERT INTO wallets (omni_account, address, role, parent_address, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                omni_account,
                address.as_str(),
                role.as_str(),
                parent_address.map(|p| p.as_str().to_string()),
                created_at as i64,
            ],
        )
        .map_err(|e| WalletError::Storage(format!("insert wallet: {}", e)))?;

        Ok(WalletBinding {
            omni_account: omni_account.to_string(),
            address: address.clone(),
            role,
            parent_address: parent_address.cloned(),
            created_at,
        })
    }

    /// Return all wallet bindings for an OmniAccount.
    pub fn list_for_omni_account(
        &self,
        omni_account: &str,
    ) -> Result<Vec<WalletBinding>, WalletError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT address, role, parent_address, created_at
                 FROM wallets
                 WHERE omni_account = ?1",
            )
            .map_err(|e| WalletError::Storage(format!("prepare list: {}", e)))?;
        let rows = stmt
            .query_map(params![omni_account], |row| {
                let addr_str: String = row.get(0)?;
                let role_str: String = row.get(1)?;
                let parent: Option<String> = row.get(2)?;
                let created_at: i64 = row.get(3)?;
                Ok((addr_str, role_str, parent, created_at))
            })
            .map_err(|e| WalletError::Storage(format!("query list: {}", e)))?;

        let mut out = Vec::new();
        for row in rows {
            let (addr_str, role_str, parent, created_at) =
                row.map_err(|e| WalletError::Storage(format!("decode row: {}", e)))?;
            out.push(WalletBinding {
                omni_account: omni_account.to_string(),
                address: WalletAddress::parse(&addr_str)?,
                role: WalletRole::parse(&role_str)?,
                parent_address: parent.as_deref().map(WalletAddress::parse).transpose()?,
                created_at: created_at as u64,
            });
        }
        Ok(out)
    }

    /// Quick writability probe used by `ready()`.
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
