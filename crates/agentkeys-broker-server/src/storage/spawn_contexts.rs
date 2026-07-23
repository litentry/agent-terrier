//! `SpawnContextStore` — the DURABLE half of the #427 spawn-ceremony context
//! (#546): everything a delegate-sandbox RE-create needs, keyed by
//! `device_key_hash`.
//!
//! The ceremony's `PendingCeremonyStore` row is one-shot RAM by design (build →
//! submit, seconds). But the sandbox itself is not: a veFaaS instance expires,
//! an ECS task dies, a backend-registry desync duplicates — and the resolve/poll
//! ensure path then (re)creates the runtime. Before #546 that path had NOTHING
//! to inject (the one-shot row was consumed at spawn), so re-created sandboxes
//! came up chat-silent: no `AGENTKEYS_CHAT_CHANNEL_ID`, no identity envs, no
//! K10 — the in-sandbox chat loop never started and the delegate's
//! `opchat-<label>` feed went unanswered. This store is the reconstruction
//! source: `finalize_spawn` writes the row at ceremony confirm, EVERY create
//! path reads it, and a confirmed `revokeAgentDevice` (archive / unpair / fleet
//! revoke) deletes it.
//!
//! **This store is REGISTERED EXCEPTION E2 in arch.md §1a (Design rules).** It
//! bends D2 (stateless broker) and D3 (a key lives only on the machine it
//! identifies): `k10_secret_hex` — the delegate's private key — sits at rest
//! for the LIFETIME OF THE BINDING (deleted on revoke). The scope bound,
//! rationale, diagram (`docs/assets/spawn-context-custody-tradeoff.svg`) and
//! revert path live in that registry — do not re-justify or widen the store
//! here. The interim #551 KEK wrap was SKIPPED (owner decision 2026-07-23);
//! **#552 LANDED**: on a stack flipped to `AGENTKEYS_DELEGATE_KEYS=signer`
//! every NEW spawn is signer-custodied — the row stores the K10 ADDRESS only
//! (`k10_secret_hex = ""`; re-creates mint a fresh J1 instead of injecting a
//! key). The secret column now serves ONLY pre-flip legacy delegates and
//! empties as they archive+respawn; re-homing the readable half to the
//! Config data class (full D2) is the recorded tail. The row is
//! provisioning data, never authority: it deliberately carries NO omnis (the
//! ensure path injects chain-read identity per D1), and a forged row cannot
//! widen scope — every cap-mint is still chain-verified at the worker.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{BrokerError, BrokerResult};

/// One delegate's durable spawn context — the re-create injection set. NO
/// omni columns on purpose: identity comes from the chain at ensure time
/// (D1); a mirrored copy here could only drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnContext {
    /// Normalized (lowercase, no `0x`) 32-byte device key hash.
    pub device_key_hash: String,
    /// The delegate's readable label (household PII — stays off-chain; the
    /// anchor carries only its hash). Cosmetic for gate rollups + logs.
    pub label: String,
    /// The duplex operator-chat feed id (`opchat-<label>`, #425 S4).
    pub chat_channel_id: String,
    /// The delegate K10 EVM address (#552) — under signer custody it is all a
    /// re-create needs (the J1 `device_pubkey` claim); no secret exists.
    pub k10_address: String,
    /// The delegate K10 secret (hex) — LEGACY rows only (§1a E2 plaintext,
    /// pre-#552 spawns); EMPTY for signer-custodied delegates.
    pub k10_secret_hex: String,
    pub created_at: i64,
}

/// SQLite-backed durable spawn-context store (#546).
pub struct SpawnContextStore {
    conn: Mutex<Connection>,
}

/// Lowercase + strip `0x` so ceremony writes, chain-read lookups and calldata-
/// decoded deletes all key identically (the same normalization as
/// `handlers::accept::norm_omni`, kept local so storage stays handler-free).
fn norm(hash: &str) -> String {
    hash.trim().trim_start_matches("0x").to_lowercase()
}

impl SpawnContextStore {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrokerError::Internal(format!("create spawn-contexts dir: {e}")))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| BrokerError::Internal(format!("open spawn-contexts db: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> BrokerResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| BrokerError::Internal(format!("open in-memory spawn-contexts db: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> BrokerResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| BrokerError::Internal(format!("spawn-contexts mutex poisoned: {e}")))
    }

    fn init_schema(&self) -> BrokerResult<()> {
        self.lock()?
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 CREATE TABLE IF NOT EXISTS spawn_contexts (
                    device_key_hash TEXT PRIMARY KEY,
                    label           TEXT NOT NULL,
                    chat_channel_id TEXT NOT NULL,
                    k10_address     TEXT NOT NULL DEFAULT '',
                    k10_secret_hex  TEXT NOT NULL,
                    created_at      INTEGER NOT NULL
                 );",
            )
            .map_err(|e| BrokerError::Internal(format!("init spawn-contexts schema: {e}")))?;
        // #552 migration for pre-existing #546 DBs: add the address column.
        // "duplicate column name" = already migrated (or fresh) — a no-op.
        match self.lock()?.execute(
            "ALTER TABLE spawn_contexts ADD COLUMN k10_address TEXT NOT NULL DEFAULT ''",
            [],
        ) {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
            Err(e) => Err(BrokerError::Internal(format!(
                "migrate spawn-contexts (k10_address): {e}"
            ))),
        }
    }

    /// Insert-or-replace the delegate's context. A respawn after archive mints
    /// a NEW device_key_hash, so a replace only ever fires on a re-submitted
    /// ceremony for the same binding — last write wins.
    pub fn upsert(&self, ctx: &SpawnContext) -> BrokerResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO spawn_contexts
                 (device_key_hash, label, chat_channel_id, k10_address, k10_secret_hex, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    norm(&ctx.device_key_hash),
                    ctx.label,
                    ctx.chat_channel_id,
                    ctx.k10_address,
                    ctx.k10_secret_hex,
                    ctx.created_at,
                ],
            )
            .map_err(|e| BrokerError::Internal(format!("upsert spawn context: {e}")))?;
        Ok(())
    }

    pub fn get(&self, device_key_hash: &str) -> BrokerResult<Option<SpawnContext>> {
        self.lock()?
            .query_row(
                "SELECT device_key_hash, label, chat_channel_id, k10_address, k10_secret_hex,
                        created_at
                 FROM spawn_contexts WHERE device_key_hash = ?1",
                params![norm(device_key_hash)],
                |row| {
                    Ok(SpawnContext {
                        device_key_hash: row.get(0)?,
                        label: row.get(1)?,
                        chat_channel_id: row.get(2)?,
                        k10_address: row.get(3)?,
                        k10_secret_hex: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("get spawn context: {e}")))
    }

    /// Delete on confirmed revoke (archive / unpair / fleet revoke) — bounds
    /// the K10-at-rest window to the binding's live lifetime. Returns whether
    /// a row existed (a device binding or a pre-#546 delegate has none).
    pub fn delete(&self, device_key_hash: &str) -> BrokerResult<bool> {
        let n = self
            .lock()?
            .execute(
                "DELETE FROM spawn_contexts WHERE device_key_hash = ?1",
                params![norm(device_key_hash)],
            )
            .map_err(|e| BrokerError::Internal(format!("delete spawn context: {e}")))?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(dkh: &str) -> SpawnContext {
        SpawnContext {
            device_key_hash: dkh.to_string(),
            label: "watchdog".into(),
            chat_channel_id: "opchat-watchdog".into(),
            k10_address: "0xabcd".into(),
            k10_secret_hex: "0xdead".into(),
            created_at: 1_700_000_000,
        }
    }

    /// #552 — a pre-#546-schema DB (no k10_address column) migrates in place
    /// on open; legacy rows read back with an empty address.
    #[test]
    fn open_migrates_a_pre_552_schema_in_place() {
        let path = std::env::temp_dir().join(format!(
            "agentkeys-spawn-ctx-migrate-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE spawn_contexts (
                    device_key_hash TEXT PRIMARY KEY,
                    label           TEXT NOT NULL,
                    chat_channel_id TEXT NOT NULL,
                    k10_secret_hex  TEXT NOT NULL,
                    created_at      INTEGER NOT NULL
                 );
                 INSERT INTO spawn_contexts VALUES ('aa', 'w', 'opchat-w', '0xdead', 1);",
            )
            .unwrap();
        }
        let store = SpawnContextStore::open(&path).unwrap();
        let legacy = store.get("aa").unwrap().expect("legacy row");
        assert_eq!(legacy.k10_secret_hex, "0xdead");
        assert_eq!(legacy.k10_address, "");
        // Re-open (second migration run) is a no-op, and new-shape rows work.
        drop(store);
        let store = SpawnContextStore::open(&path).unwrap();
        store.upsert(&ctx(&"bb".repeat(32))).unwrap();
        assert_eq!(
            store.get(&"bb".repeat(32)).unwrap().unwrap().k10_address,
            "0xabcd"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn round_trips_and_normalizes_the_key() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        store
            .upsert(&ctx(&format!("0x{}", "AB".repeat(32))))
            .unwrap();
        // 0x-prefix and case are normalized on both write and read.
        let got = store.get(&"ab".repeat(32)).unwrap().expect("row");
        assert_eq!(got.device_key_hash, "ab".repeat(32));
        assert_eq!(got.chat_channel_id, "opchat-watchdog");
        assert_eq!(got.k10_secret_hex, "0xdead");
    }

    #[test]
    fn get_is_none_for_unknown_and_survives_repeat_reads() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        store.upsert(&ctx(&"11".repeat(32))).unwrap();
        assert!(store.get(&"99".repeat(32)).unwrap().is_none());
        // NOT one-shot (unlike the RAM pending row): every create path reads it.
        assert!(store.get(&"11".repeat(32)).unwrap().is_some());
        assert!(store.get(&"11".repeat(32)).unwrap().is_some());
    }

    #[test]
    fn upsert_replaces_and_delete_bounds_the_at_rest_window() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        let dkh = "11".repeat(32);
        store.upsert(&ctx(&dkh)).unwrap();
        let mut newer = ctx(&dkh);
        newer.k10_secret_hex = "0xbeef".into();
        store.upsert(&newer).unwrap();
        assert_eq!(store.get(&dkh).unwrap().unwrap().k10_secret_hex, "0xbeef");
        assert!(store.delete(&format!("0x{dkh}")).unwrap());
        assert!(store.get(&dkh).unwrap().is_none());
        assert!(!store.delete(&dkh).unwrap());
    }
}
