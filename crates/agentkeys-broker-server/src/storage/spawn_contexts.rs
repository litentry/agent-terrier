//! `SpawnContextStore` — the DURABLE half of the #427 spawn-ceremony context
//! (#546): everything a delegate-sandbox RE-create needs, keyed by
//! `device_key_hash`.
//!
//! The ceremony's `PendingCeremonyStore` row is consumed at submission. This
//! store retains runtime reconstruction data across restarts: `finalize_spawn`
//! writes it after confirmation, creation paths read it, and confirmed
//! `revokeAgentDevice` deletes it.
//!
//! Delegate keys remain in the configured signer. Rows contain only public
//! identity and runtime reconstruction data, never authority. Old databases
//! containing delegate key material are refused before schema migration.

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
    /// #594 — the delegate's own `knowledge:<ns>` namespace (bare name). Injected
    /// as `AGENTKEYS_MEMORY_NS` on every create so the in-sandbox checkpoint
    /// loop addresses the right grant even when the namespace was INHERITED
    /// (#425 O2, ns ≠ label). EMPTY on pre-#594 rows — the daemon then derives
    /// ns from the `opchat-<label>` channel id (the ceremony's default rule).
    pub memory_ns: String,
    pub created_at: i64,
    /// #663 — the app template the delegate was installed from (`""` = a
    /// blank / role-preset spawn). Injected as `AGENTKEYS_APP_TEMPLATE` so
    /// the in-sandbox daemon can fetch its schedule + perception prompt from
    /// the broker catalog; the sweeper reads the template's schedule for the
    /// `scheduled` availability policy.
    pub preset_id: String,
    /// #665 — the feeds the sandbox polls / publishes beyond opchat: the
    /// compiler's `bound_channels` as JSON (`""` = none). Provisioning
    /// pointers — feed ids the chain already grants — never authority
    /// (arch.md §1a E2, amended for #660).
    pub bound_channels_json: String,
    /// #669 — the app's `availability` wire spelling (`""` = always-on).
    pub availability: String,
    /// #666 — the comma-separated namespace list the distribution mirror
    /// probes (own ns + bound resource namespaces); `""` = the mirror's
    /// defaults.
    pub memory_namespaces: String,
    /// #669 — the household's UTC offset in minutes for cron evaluation.
    pub tz_offset_minutes: i64,
    /// The sealed context document this row caches (2026-09-22: the anchor
    /// lives on the memory plane + chain; `0` / empty = never sealed).
    pub context_version: i64,
    pub context_hash: String,
}

impl SpawnContext {
    pub fn has_valid_device_address(&self) -> bool {
        agentkeys_core::device_crypto::device_key_hash(&self.k10_address)
            .is_ok_and(|hash| norm(&hash) == norm(&self.device_key_hash))
    }

    /// The parsed `bound_channels` (an unparseable / empty column = none —
    /// loud in the log, never a crash).
    pub fn bound_channels(&self) -> Vec<agentkeys_protocol::BoundChannel> {
        if self.bound_channels_json.trim().is_empty() {
            return Vec::new();
        }
        match serde_json::from_str(&self.bound_channels_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    device_key_hash = %self.device_key_hash,
                    error = %e,
                    "#665 spawn-context bound_channels column is not valid JSON — treated as none"
                );
                Vec::new()
            }
        }
    }

    pub fn availability(&self) -> agentkeys_protocol::Availability {
        agentkeys_protocol::Availability::parse(&self.availability).unwrap_or_default()
    }
}

/// Columns an earlier schema had and the current one must not: dropped in
/// place on open (see `init_schema`).
const RETIRED_COLUMNS: [&str; 3] = ["operator_omni", "actor_omni", "k10_secret_hex"];

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

    fn reject_legacy_keys(connection: &Connection) -> BrokerResult<()> {
        let has_key_column = connection
            .prepare(
                "SELECT 1 FROM pragma_table_info('spawn_contexts') WHERE name = 'k10_secret_hex'",
            )
            .and_then(|mut statement| statement.exists([]))
            .map_err(|error| {
                BrokerError::Internal(format!("inspect spawn-context schema: {error}"))
            })?;
        if has_key_column {
            let has_keys: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM spawn_contexts WHERE k10_secret_hex IS NOT NULL
                    AND length(CAST(k10_secret_hex AS BLOB)) > 0)",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    BrokerError::Internal(format!("inspect legacy spawn context: {error}"))
                })?;
            if has_keys {
                return Err(BrokerError::Internal(
                    "spawn-context database contains legacy delegate key material; startup refused without migration. Preserve this database privately and use a fresh local development state or an explicitly reviewed recovery procedure".into(),
                ));
            }
        }
        Ok(())
    }

    fn init_schema(&self) -> BrokerResult<()> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| {
                BrokerError::Internal(format!("begin spawn-context migration: {error}"))
            })?;
        Self::reject_legacy_keys(&transaction)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS spawn_contexts (
                device_key_hash TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                chat_channel_id TEXT NOT NULL,
                k10_address TEXT NOT NULL DEFAULT '',
                memory_ns TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                preset_id TEXT NOT NULL DEFAULT '',
                bound_channels TEXT NOT NULL DEFAULT '',
                availability TEXT NOT NULL DEFAULT '',
                memory_namespaces TEXT NOT NULL DEFAULT '',
                tz_offset_minutes INTEGER NOT NULL DEFAULT 0
            );",
            )
            .map_err(|error| {
                BrokerError::Internal(format!("init spawn-context schema: {error}"))
            })?;
        for (col, ddl) in [
            (
                "k10_address",
                "ALTER TABLE spawn_contexts ADD COLUMN k10_address TEXT NOT NULL DEFAULT ''",
            ),
            (
                "memory_ns",
                "ALTER TABLE spawn_contexts ADD COLUMN memory_ns TEXT NOT NULL DEFAULT ''",
            ),
            // #660 stage 1 — the app-runtime columns (#663/#665/#666/#669).
            (
                "preset_id",
                "ALTER TABLE spawn_contexts ADD COLUMN preset_id TEXT NOT NULL DEFAULT ''",
            ),
            (
                "bound_channels",
                "ALTER TABLE spawn_contexts ADD COLUMN bound_channels TEXT NOT NULL DEFAULT ''",
            ),
            (
                "availability",
                "ALTER TABLE spawn_contexts ADD COLUMN availability TEXT NOT NULL DEFAULT ''",
            ),
            (
                "memory_namespaces",
                "ALTER TABLE spawn_contexts ADD COLUMN memory_namespaces TEXT NOT NULL DEFAULT ''",
            ),
            (
                "tz_offset_minutes",
                "ALTER TABLE spawn_contexts ADD COLUMN tz_offset_minutes INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "context_version",
                "ALTER TABLE spawn_contexts ADD COLUMN context_version INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "context_hash",
                "ALTER TABLE spawn_contexts ADD COLUMN context_hash TEXT NOT NULL DEFAULT ''",
            ),
        ] {
            match transaction.execute(ddl, []) {
                Ok(_) => {}
                Err(e) if e.to_string().contains("duplicate column name") => {}
                Err(e) => {
                    return Err(BrokerError::Internal(format!(
                        "migrate spawn-contexts ({col}): {e}"
                    )))
                }
            }
        }
        for column in RETIRED_COLUMNS {
            let present = transaction
                .prepare("SELECT 1 FROM pragma_table_info('spawn_contexts') WHERE name = ?1")
                .and_then(|mut statement| statement.exists(params![column]))
                .map_err(|error| {
                    BrokerError::Internal(format!("inspect spawn-context column: {error}"))
                })?;
            if present {
                transaction
                    .execute(
                        &format!("ALTER TABLE spawn_contexts DROP COLUMN {column}"),
                        [],
                    )
                    .map_err(|error| {
                        BrokerError::Internal(format!("drop retired spawn-context column: {error}"))
                    })?;
            }
        }
        transaction.commit().map_err(|error| {
            BrokerError::Internal(format!("commit spawn-context migration: {error}"))
        })?;
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|error| {
                BrokerError::Internal(format!("configure spawn-context database: {error}"))
            })?;
        Ok(())
    }

    /// Insert or replace public reconstruction data for the same device binding.
    pub fn upsert(&self, ctx: &SpawnContext) -> BrokerResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO spawn_contexts
                 (device_key_hash, label, chat_channel_id, k10_address,
                  memory_ns, created_at, preset_id, bound_channels, availability,
                  memory_namespaces, tz_offset_minutes, context_version, context_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    norm(&ctx.device_key_hash),
                    ctx.label,
                    ctx.chat_channel_id,
                    ctx.k10_address,
                    ctx.memory_ns,
                    ctx.created_at,
                    ctx.preset_id,
                    ctx.bound_channels_json,
                    ctx.availability,
                    ctx.memory_namespaces,
                    ctx.tz_offset_minutes,
                    ctx.context_version,
                    ctx.context_hash,
                ],
            )
            .map_err(|e| BrokerError::Internal(format!("upsert spawn context: {e}")))?;
        Ok(())
    }

    pub fn get(&self, device_key_hash: &str) -> BrokerResult<Option<SpawnContext>> {
        self.lock()?
            .query_row(
                "SELECT device_key_hash, label, chat_channel_id, k10_address,
                        memory_ns, created_at, preset_id, bound_channels, availability,
                        memory_namespaces, tz_offset_minutes, context_version, context_hash
                 FROM spawn_contexts WHERE device_key_hash = ?1",
                params![norm(device_key_hash)],
                row_to_ctx,
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("get spawn context: {e}")))
    }

    /// #594 — every durable row, the lease sweeper's work-list. The row set is
    /// small (one per live delegate binding) and provisioning data only —
    /// authority is still the per-row chain probe the sweeper performs.
    pub fn list(&self) -> BrokerResult<Vec<SpawnContext>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT device_key_hash, label, chat_channel_id, k10_address,
                        memory_ns, created_at, preset_id, bound_channels, availability,
                        memory_namespaces, tz_offset_minutes, context_version, context_hash
                 FROM spawn_contexts ORDER BY created_at",
            )
            .map_err(|e| BrokerError::Internal(format!("list spawn contexts: {e}")))?;
        let rows = stmt
            .query_map([], row_to_ctx)
            .map_err(|e| BrokerError::Internal(format!("list spawn contexts: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(format!("list spawn contexts: {e}")))
    }

    /// Delete reconstruction data on confirmed revocation; return whether a row existed.
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

/// The ONE column → struct mapping (get + list share it so a new column can
/// never land in one query and not the other).
fn row_to_ctx(row: &rusqlite::Row<'_>) -> rusqlite::Result<SpawnContext> {
    Ok(SpawnContext {
        device_key_hash: row.get(0)?,
        label: row.get(1)?,
        chat_channel_id: row.get(2)?,
        k10_address: row.get(3)?,
        memory_ns: row.get(4)?,
        created_at: row.get(5)?,
        preset_id: row.get(6)?,
        bound_channels_json: row.get(7)?,
        availability: row.get(8)?,
        memory_namespaces: row.get(9)?,
        tz_offset_minutes: row.get(10)?,
        context_version: row.get(11)?,
        context_hash: row.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bearing_legacy_database_is_rejected_without_modification() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.sqlite");
        let synthetic_secret = "synthetic-key-must-stay-in-fixture";
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE spawn_contexts (device_key_hash TEXT PRIMARY KEY,
                    label TEXT NOT NULL, chat_channel_id TEXT NOT NULL,
                    k10_secret_hex TEXT NOT NULL, created_at INTEGER NOT NULL);",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO spawn_contexts VALUES ('aa', 'label', 'chat', ?1, 1)",
                    params![synthetic_secret],
                )
                .unwrap();
        }
        let original_bytes = std::fs::read(&path).unwrap();
        let error = match SpawnContextStore::open(&path) {
            Ok(_) => panic!("key-bearing database was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("legacy delegate key material"), "{error}");
        assert!(!error.contains(synthetic_secret));
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        let connection = Connection::open(&path).unwrap();
        let retained: String = connection
            .query_row(
                "SELECT k10_secret_hex FROM spawn_contexts WHERE device_key_hash = 'aa'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, synthetic_secret);
    }

    fn ctx(dkh: &str) -> SpawnContext {
        SpawnContext {
            device_key_hash: dkh.to_string(),
            label: "watchdog".into(),
            chat_channel_id: "opchat-watchdog".into(),
            k10_address: "0xabcd".into(),
            memory_ns: "watchdog".into(),
            created_at: 1_700_000_000,
            preset_id: String::new(),
            bound_channels_json: String::new(),
            availability: String::new(),
            memory_namespaces: String::new(),
            tz_offset_minutes: 0,
            context_version: 0,
            context_hash: String::new(),
        }
    }

    /// #660 — the app-runtime columns round-trip, the JSON accessor parses,
    /// and a pre-#660 row (no columns) reads back as a role-preset delegate.
    #[test]
    fn app_runtime_columns_round_trip_and_default_for_legacy_rows() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        let mut c = ctx(&"33".repeat(32));
        c.preset_id = "chef".into();
        c.bound_channels_json = serde_json::to_string(&vec![agentkeys_protocol::BoundChannel {
            slot: "family_chat".into(),
            kind: agentkeys_protocol::ChannelEndpointKind::Messaging,
            direction: agentkeys_protocol::SlotDirection::Sub,
            channel_id: "weixin-chef".into(),
            event_kinds: vec![agentkeys_protocol::ChannelEventKind::Text],
            endpoint_actor_omni: Some("0xgw".into()),
            default_app: None,
        }])
        .unwrap();
        c.availability = "wake-on-event".into();
        c.memory_namespaces = "app-chef,household-health".into();
        c.tz_offset_minutes = 480;
        store.upsert(&c).unwrap();
        let got = store.get(&"33".repeat(32)).unwrap().unwrap();
        assert_eq!(got.preset_id, "chef");
        assert_eq!(got.bound_channels().len(), 1);
        assert_eq!(got.bound_channels()[0].channel_id, "weixin-chef");
        assert_eq!(
            got.availability(),
            agentkeys_protocol::Availability::WakeOnEvent
        );
        assert_eq!(got.memory_namespaces, "app-chef,household-health");
        assert_eq!(got.tz_offset_minutes, 480);
        let legacy = ctx(&"44".repeat(32));
        store.upsert(&legacy).unwrap();
        let got = store
            .list()
            .unwrap()
            .into_iter()
            .find(|r| r.label == "watchdog" && r.preset_id.is_empty())
            .unwrap();
        assert!(got.bound_channels().is_empty());
        assert_eq!(
            got.availability(),
            agentkeys_protocol::Availability::AlwaysOn
        );
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
                 INSERT INTO spawn_contexts VALUES ('aa', 'w', 'opchat-w', '', 1);",
            )
            .unwrap();
        }
        let store = SpawnContextStore::open(&path).unwrap();
        let legacy = store.get("aa").unwrap().expect("legacy row");
        assert_eq!(legacy.k10_address, "");
        // #594 — pre-#594 rows migrate with an empty ns (daemon derives from
        // the channel id).
        assert_eq!(legacy.memory_ns, "");
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
    fn open_drops_the_retired_omni_columns_so_upserts_work_again() {
        let path = std::env::temp_dir().join(format!(
            "agentkeys-spawn-ctx-retired-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE spawn_contexts (
                    device_key_hash TEXT PRIMARY KEY,
                    operator_omni   TEXT NOT NULL,
                    actor_omni      TEXT NOT NULL,
                    label           TEXT NOT NULL,
                    chat_channel_id TEXT NOT NULL,
                    k10_secret_hex  TEXT NOT NULL,
                    created_at      INTEGER NOT NULL
                 );
                 INSERT INTO spawn_contexts VALUES ('aa', '0xop', '0xac', 'w', 'opchat-w', '', 1);",
            )
            .unwrap();
        }
        let store = SpawnContextStore::open(&path).unwrap();
        let columns: Vec<String> = store
            .lock()
            .unwrap()
            .prepare("SELECT name FROM pragma_table_info('spawn_contexts')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for retired in RETIRED_COLUMNS {
            assert!(
                !columns.iter().any(|c| c == retired),
                "{retired} still present: {columns:?}"
            );
        }
        let legacy = store.get("aa").unwrap().expect("the legacy row survives");
        assert_eq!(legacy.label, "w");
        store.upsert(&ctx(&"bb".repeat(32))).unwrap();
        assert_eq!(
            store.get(&"bb".repeat(32)).unwrap().unwrap().label,
            "watchdog"
        );
        // A second open finds nothing to drop.
        drop(store);
        let store = SpawnContextStore::open(&path).unwrap();
        store.upsert(&ctx(&"cc".repeat(32))).unwrap();
        assert_eq!(store.list().unwrap().len(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn runtime_identity_requires_an_address_matching_its_device_hash() {
        let key = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let address = agentkeys_core::device_crypto::evm_address(key.verifying_key());
        let hash = agentkeys_core::device_crypto::device_key_hash(&address).unwrap();
        let mut context = ctx(&hash);
        context.k10_address = address;
        assert!(context.has_valid_device_address());
        context.device_key_hash = "00".repeat(32);
        assert!(!context.has_valid_device_address());
        context.k10_address.clear();
        assert!(!context.has_valid_device_address());
    }

    #[test]
    fn fresh_schema_has_no_delegate_key_column() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        let key_columns: usize = store.lock().unwrap().query_row(
            "SELECT count(*) FROM pragma_table_info('spawn_contexts') WHERE name = 'k10_secret_hex'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(key_columns, 0);
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
        assert_eq!(got.k10_address, "0xabcd");
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
    fn upsert_replaces_and_delete_removes_reconstruction_data() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        let dkh = "11".repeat(32);
        store.upsert(&ctx(&dkh)).unwrap();
        let mut newer = ctx(&dkh);
        newer.label = "updated-label".into();
        store.upsert(&newer).unwrap();
        assert_eq!(store.get(&dkh).unwrap().unwrap().label, "updated-label");
        assert!(store.delete(&format!("0x{dkh}")).unwrap());
        assert!(store.get(&dkh).unwrap().is_none());
        assert!(!store.delete(&dkh).unwrap());
    }

    /// #594 — the sweeper's work-list: every row, oldest first, round-tripped
    /// with the new ns column.
    #[test]
    fn list_returns_all_rows_in_created_order() {
        let store = SpawnContextStore::open_in_memory().unwrap();
        assert!(store.list().unwrap().is_empty());
        let mut older = ctx(&"11".repeat(32));
        older.created_at = 1;
        store.upsert(&older).unwrap();
        store.upsert(&ctx(&"22".repeat(32))).unwrap();
        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].device_key_hash, "11".repeat(32));
        assert_eq!(rows[1].memory_ns, "watchdog");
    }
}
