//! `PairingRequestStore` — the §10.2 **agent-initiated** pairing request +
//! pending-binding record (method A, replaces issue #144's master-initiated
//! link code).
//!
//! One row models the full pairing lifecycle, but the direction is inverted vs
//! the old `link_codes` table: the **agent** opens the row (unbound, naming no
//! master), and the **master** later claims it by code:
//!
//! ```text
//! requested   (agent ran POST /v1/agent/pairing/request — device_pubkey +
//!              pop_sig captured; operator/child_omni still ∅; pairing_code minted)
//!   → claimed  (master ran POST /v1/agent/pairing/claim — scanned/entered the
//!              code; operator_omni = the master, child_omni = HDKD(O_master,//label))
//!   → bound     (master pulled the pending binding + submitted registerAgentDevice
//!              + POST /v1/agent/pending-bindings/ack)
//! ```
//!
//! Why agent-first (vs the old master-first `link_codes`): a no-keyboard IoT
//! device can only *show* a code (QR/screen), not accept one typed into it — the
//! Matter/HomeKit convention. The request is **unbound + inert** until a master
//! deliberately claims the code, so an agent still can't attach itself to a
//! master or flood one (Sybil-safe — the master's claim is the sole binder,
//! exactly as the master's mint was under method M).
//!
//! `J1_agent` is **not** minted or stored here — it is minted fresh at poll time
//! (`handlers/agent/poll.rs`) once the agent re-proves device-key possession, so
//! no bearer secret sits at rest in SQLite and the JWT TTL starts at retrieval.
//! This store only holds the request lifecycle state.
//!
//! SQLite (not in-memory) because the broker restarts between demo phases; an
//! in-memory store would silently drop requests and produce confusing claim/poll
//! 404s. Race-safety mirrors `oauth_pending.rs` (atomic `UPDATE ... WHERE
//! claimed_at IS NULL`); returns `BrokerError` since broker handlers consume it.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{BrokerError, BrokerResult};

/// Pairing-request TTL — the window in which a master must claim the agent's
/// request (arch.md §10.2). Same 600s as the old link-code TTL.
pub const PAIRING_REQUEST_TTL_SECONDS: i64 = 600;

/// SQLite-backed pairing-request + pending-binding store.
pub struct PairingRequestStore {
    conn: Mutex<Connection>,
}

/// Outcome of [`PairingRequestStore::claim`] (master claims by `pairing_code`).
#[derive(Debug, PartialEq, Eq)]
pub enum PairingClaim {
    /// Code was unclaimed + unexpired; claim succeeded. Carries the device
    /// artifact the master reviews before `registerAgentDevice` (the M
    /// second-factor, preserved) + records as a pending binding.
    Claimed {
        request_id: String,
        device_pubkey: String,
        pop_sig: String,
    },
    /// Code never existed or was already claimed (collapsed to one variant so a
    /// prober can't distinguish — same posture as the OAuth2/email stores).
    NotFoundOrClaimed,
    /// Code existed + unclaimed but past its TTL.
    Expired,
}

/// Outcome of [`PairingRequestStore::poll`] (agent polls by `request_id`,
/// proving device-key possession out of band in the handler).
#[derive(Debug, PartialEq, Eq)]
pub enum PairingPoll {
    /// Request exists + unexpired but no master has claimed it yet.
    Pending,
    /// A master has claimed the request — carries everything the poll handler
    /// needs to mint `J1_agent` fresh.
    Claimed {
        operator_omni: String,
        child_omni: String,
        label: String,
        requested_scope: String,
    },
    /// `request_id` never existed, or the supplied `device_pubkey` doesn't match
    /// the row (binding mismatch hidden behind one variant — a prober holding a
    /// guessed request_id but the wrong device key can't distinguish).
    NotFound,
    /// Request expired before any master claimed it.
    Expired,
}

/// A claimed-but-not-yet-bound row — what the master pulls from
/// `GET /v1/agent/pending-bindings` to approve. `request_id` is the stable
/// handle the master acks by (the method-A analog of the old `link_code`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PendingBinding {
    pub request_id: String,
    pub child_omni: String,
    pub operator_omni: String,
    pub label: String,
    pub requested_scope: String,
    pub device_pubkey: String,
    pub pop_sig: String,
}

/// The `SELECT` shape `poll()` reads:
/// `(device_pubkey, expires_at, claimed_at, operator_omni, child_omni, label, requested_scope)`.
/// The four `Option<String>`s are NULL until a master claims the request.
type PollRow = (
    String,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl PairingRequestStore {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrokerError::Internal(format!("create pairing_requests dir: {e}")))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| BrokerError::Internal(format!("open pairing_requests db: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> BrokerResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            BrokerError::Internal(format!("open in-memory pairing_requests db: {e}"))
        })?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> BrokerResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| BrokerError::Internal(format!("pairing_requests mutex poisoned: {e}")))
    }

    fn init_schema(&self) -> BrokerResult<()> {
        let conn = self.lock()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS pairing_requests (
                request_id      TEXT PRIMARY KEY,
                pairing_code    TEXT NOT NULL UNIQUE,
                device_pubkey   TEXT NOT NULL,
                pop_sig         TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                expires_at      INTEGER NOT NULL,
                claimed_at      INTEGER,
                operator_omni   TEXT,
                child_omni      TEXT,
                label           TEXT,
                requested_scope TEXT,
                bound_at        INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_pairing_requests_operator
                ON pairing_requests(operator_omni);
             CREATE INDEX IF NOT EXISTS idx_pairing_requests_expires_at
                ON pairing_requests(expires_at);",
        )
        .map_err(|e| BrokerError::Internal(format!("init pairing_requests schema: {e}")))?;
        Ok(())
    }

    /// Open a new **unbound** pairing request (agent ran `/v1/agent/pairing/request`).
    /// `operator_omni` / `child_omni` / `label` / `requested_scope` are NULL until
    /// a master claims the `pairing_code`.
    pub fn issue(
        &self,
        request_id: &str,
        pairing_code: &str,
        device_pubkey: &str,
        pop_sig: &str,
        created_at: i64,
        expires_at: i64,
    ) -> BrokerResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO pairing_requests
                (request_id, pairing_code, device_pubkey, pop_sig, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request_id,
                pairing_code,
                device_pubkey,
                pop_sig,
                created_at,
                expires_at
            ],
        )
        .map_err(|e| BrokerError::Internal(format!("insert pairing_request: {e}")))?;
        Ok(())
    }

    /// Atomically claim the request by `pairing_code` (master ran
    /// `/v1/agent/pairing/claim`), assigning the operator + HDKD child omni +
    /// label + requested scope onto the row (state → claimed/pending-binding).
    /// Race-safe via the conditional `UPDATE ... WHERE claimed_at IS NULL`.
    #[allow(clippy::too_many_arguments)]
    pub fn claim(
        &self,
        pairing_code: &str,
        operator_omni: &str,
        child_omni: &str,
        label: &str,
        requested_scope: &str,
        now: i64,
    ) -> BrokerResult<PairingClaim> {
        let conn = self.lock()?;
        let peek: Option<(String, String, String, i64, Option<i64>)> = conn
            .query_row(
                "SELECT request_id, device_pubkey, pop_sig, expires_at, claimed_at
                 FROM pairing_requests WHERE pairing_code = ?1",
                params![pairing_code],
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
            .map_err(|e| BrokerError::Internal(format!("peek pairing_code: {e}")))?;

        let (request_id, device_pubkey, pop_sig, expires_at, claimed_at) = match peek {
            None => return Ok(PairingClaim::NotFoundOrClaimed),
            Some(t) => t,
        };
        if claimed_at.is_some() {
            return Ok(PairingClaim::NotFoundOrClaimed);
        }
        if expires_at < now {
            return Ok(PairingClaim::Expired);
        }
        let rows = conn
            .execute(
                "UPDATE pairing_requests
                 SET claimed_at = ?1, operator_omni = ?2, child_omni = ?3,
                     label = ?4, requested_scope = ?5
                 WHERE pairing_code = ?6 AND claimed_at IS NULL",
                params![
                    now,
                    operator_omni,
                    child_omni,
                    label,
                    requested_scope,
                    pairing_code
                ],
            )
            .map_err(|e| BrokerError::Internal(format!("update pairing_request: {e}")))?;
        if rows == 0 {
            // Lost the race to a concurrent claim.
            Ok(PairingClaim::NotFoundOrClaimed)
        } else {
            Ok(PairingClaim::Claimed {
                request_id,
                device_pubkey,
                pop_sig,
            })
        }
    }

    /// Read the request's current state for the agent's poll (`request_id` is the
    /// agent's secret retrieval ticket). `device_pubkey` MUST match the row's
    /// stored device key — a mismatch collapses to [`PairingPoll::NotFound`] so a
    /// prober holding a guessed `request_id` (but not the device key) learns
    /// nothing. The handler verifies the fresh `pop_sig` against `device_pubkey`
    /// BEFORE calling this (stateless), so this method does no crypto.
    pub fn poll(
        &self,
        request_id: &str,
        device_pubkey: &str,
        now: i64,
    ) -> BrokerResult<PairingPoll> {
        let conn = self.lock()?;
        let row: Option<PollRow> = conn
            .query_row(
                "SELECT device_pubkey, expires_at, claimed_at,
                        operator_omni, child_omni, label, requested_scope
                 FROM pairing_requests WHERE request_id = ?1",
                params![request_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("poll pairing_request: {e}")))?;

        let (
            stored_pubkey,
            expires_at,
            claimed_at,
            operator_omni,
            child_omni,
            label,
            requested_scope,
        ) = match row {
            None => return Ok(PairingPoll::NotFound),
            Some(t) => t,
        };
        // Bind the poll to the device key — a guessed request_id without the
        // matching device key is indistinguishable from an unknown one.
        if stored_pubkey.to_lowercase() != device_pubkey.to_lowercase() {
            return Ok(PairingPoll::NotFound);
        }
        if claimed_at.is_none() {
            // Unclaimed: expired vs still-pending.
            if expires_at < now {
                return Ok(PairingPoll::Expired);
            }
            return Ok(PairingPoll::Pending);
        }
        // Claimed rows don't expire (a binding the master is approving is
        // long-lived), so we don't re-check expires_at here.
        Ok(PairingPoll::Claimed {
            operator_omni: operator_omni.unwrap_or_default(),
            child_omni: child_omni.unwrap_or_default(),
            label: label.unwrap_or_default(),
            requested_scope: requested_scope.unwrap_or_default(),
        })
    }

    /// Rows that have been claimed but not yet bound on-chain, for one operator
    /// — the master's pending-approval queue. Returns oldest-first.
    pub fn pending_bindings(&self, operator_omni: &str) -> BrokerResult<Vec<PendingBinding>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT request_id, child_omni, operator_omni, label, requested_scope,
                        device_pubkey, pop_sig
                 FROM pairing_requests
                 WHERE operator_omni = ?1 AND claimed_at IS NOT NULL AND bound_at IS NULL
                 ORDER BY claimed_at ASC",
            )
            .map_err(|e| BrokerError::Internal(format!("prepare pending_bindings: {e}")))?;
        let rows = stmt
            .query_map(params![operator_omni], |row| {
                Ok(PendingBinding {
                    request_id: row.get(0)?,
                    child_omni: row.get(1)?,
                    operator_omni: row.get(2)?,
                    label: row.get(3)?,
                    requested_scope: row.get(4)?,
                    device_pubkey: row.get(5)?,
                    pop_sig: row.get(6)?,
                })
            })
            .map_err(|e| BrokerError::Internal(format!("query pending_bindings: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| BrokerError::Internal(format!("row pending_bindings: {e}")))?);
        }
        Ok(out)
    }

    /// Mark a claimed row as bound (the master acked its on-chain submit), so it
    /// drops out of [`pending_bindings`]. Scoped to `operator_omni` — an operator
    /// can only ack its own bindings. Idempotent: a second ack matches nothing.
    /// Returns the updated row count (1 = acked, 0 = unknown/already-bound).
    pub fn mark_bound(
        &self,
        request_id: &str,
        operator_omni: &str,
        now: i64,
    ) -> BrokerResult<usize> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "UPDATE pairing_requests SET bound_at = ?1
                 WHERE request_id = ?2 AND operator_omni = ?3
                   AND claimed_at IS NOT NULL AND bound_at IS NULL",
                params![now, request_id, operator_omni],
            )
            .map_err(|e| BrokerError::Internal(format!("mark_bound pairing_request: {e}")))?;
        Ok(n)
    }

    /// Janitor — DELETE expired requests that were never claimed. Claimed rows are
    /// kept (the master may still need to bind them — a binding doesn't expire).
    pub fn purge_expired(&self, now: i64, retention_seconds: i64) -> BrokerResult<usize> {
        let conn = self.lock()?;
        let cutoff = now - retention_seconds;
        let n = conn
            .execute(
                "DELETE FROM pairing_requests WHERE expires_at < ?1 AND claimed_at IS NULL",
                params![cutoff],
            )
            .map_err(|e| BrokerError::Internal(format!("purge pairing_requests: {e}")))?;
        Ok(n)
    }

    /// Writability probe for `/readyz`.
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

    fn store() -> PairingRequestStore {
        PairingRequestStore::open_in_memory().unwrap()
    }

    #[test]
    fn request_then_claim_round_trip() {
        let s = store();
        s.issue("req-1", "code-1", "0xdev", "0xpop", 100, 700)
            .unwrap();
        let out = s
            .claim("code-1", "op", "child", "agent-a", "memory", 200)
            .unwrap();
        assert_eq!(
            out,
            PairingClaim::Claimed {
                request_id: "req-1".into(),
                device_pubkey: "0xdev".into(),
                pop_sig: "0xpop".into(),
            }
        );
    }

    #[test]
    fn second_claim_is_rejected() {
        let s = store();
        s.issue("req-1", "code-1", "0xdev", "0xpop", 100, 700)
            .unwrap();
        let _ = s
            .claim("code-1", "op", "child", "agent-a", "memory", 200)
            .unwrap();
        let replay = s
            .claim("code-1", "op2", "child2", "agent-a", "memory", 250)
            .unwrap();
        assert_eq!(replay, PairingClaim::NotFoundOrClaimed);
    }

    #[test]
    fn expired_request_is_not_claimable() {
        let s = store();
        s.issue("req-1", "code-1", "0xdev", "0xpop", 100, 200)
            .unwrap();
        assert_eq!(
            s.claim("code-1", "op", "child", "agent-a", "memory", 9999)
                .unwrap(),
            PairingClaim::Expired
        );
    }

    #[test]
    fn unknown_code_is_not_found() {
        let s = store();
        assert_eq!(
            s.claim("nope", "op", "child", "agent-a", "memory", 100)
                .unwrap(),
            PairingClaim::NotFoundOrClaimed
        );
    }

    #[test]
    fn poll_pending_then_claimed() {
        let s = store();
        s.issue("req-1", "code-1", "0xdev", "0xpop", 100, 700)
            .unwrap();
        assert_eq!(s.poll("req-1", "0xdev", 200).unwrap(), PairingPoll::Pending);
        s.claim("code-1", "op", "child", "agent-a", "memory", 250)
            .unwrap();
        assert_eq!(
            s.poll("req-1", "0xdev", 300).unwrap(),
            PairingPoll::Claimed {
                operator_omni: "op".into(),
                child_omni: "child".into(),
                label: "agent-a".into(),
                requested_scope: "memory".into(),
            }
        );
    }

    #[test]
    fn poll_with_wrong_device_is_not_found() {
        let s = store();
        s.issue("req-1", "code-1", "0xdev", "0xpop", 100, 700)
            .unwrap();
        // Right request_id, wrong device key → indistinguishable from unknown.
        assert_eq!(
            s.poll("req-1", "0xWRONG", 200).unwrap(),
            PairingPoll::NotFound
        );
    }

    #[test]
    fn poll_device_match_is_case_insensitive() {
        let s = store();
        // device_pubkey stored as mixed-case "0xAbCd"; poll with lowercase.
        s.issue("req-1", "code-1", "0xAbCd", "0xpop", 100, 700)
            .unwrap();
        assert_eq!(
            s.poll("req-1", "0xabcd", 200).unwrap(),
            PairingPoll::Pending
        );
    }

    #[test]
    fn poll_unclaimed_expired_is_expired() {
        let s = store();
        s.issue("req-1", "code-1", "0xdev", "0xpop", 100, 200)
            .unwrap();
        assert_eq!(
            s.poll("req-1", "0xdev", 9999).unwrap(),
            PairingPoll::Expired
        );
    }

    #[test]
    fn poll_unknown_request_is_not_found() {
        let s = store();
        assert_eq!(s.poll("nope", "0xdev", 100).unwrap(), PairingPoll::NotFound);
    }

    #[test]
    fn pending_bindings_returns_claimed_unbound_rows() {
        let s = store();
        s.issue("req-1", "code-1", "0xdevA", "0xpopA", 100, 700)
            .unwrap();
        s.issue("req-2", "code-2", "0xdevB", "0xpopB", 100, 700)
            .unwrap();
        // Not claimed yet → no pending binding.
        assert!(s.pending_bindings("op").unwrap().is_empty());
        s.claim("code-1", "op", "childA", "agent-a", "memory", 200)
            .unwrap();
        s.claim("code-2", "op-other", "childB", "agent-b", "memory", 200)
            .unwrap();
        let pend = s.pending_bindings("op").unwrap();
        assert_eq!(pend.len(), 1);
        assert_eq!(pend[0].request_id, "req-1");
        assert_eq!(pend[0].child_omni, "childA");
        assert_eq!(pend[0].device_pubkey, "0xdevA");
        assert_eq!(pend[0].pop_sig, "0xpopA");
        // Different operator's claim doesn't leak.
        assert!(s
            .pending_bindings("op")
            .unwrap()
            .iter()
            .all(|b| b.operator_omni == "op"));
    }

    #[test]
    fn mark_bound_clears_from_pending() {
        let s = store();
        s.issue("req-1", "code-1", "0xdevA", "0xpopA", 100, 700)
            .unwrap();
        s.claim("code-1", "op", "childA", "agent-a", "memory", 200)
            .unwrap();
        assert_eq!(s.pending_bindings("op").unwrap().len(), 1);
        assert_eq!(s.mark_bound("req-1", "op", 300).unwrap(), 1);
        assert!(s.pending_bindings("op").unwrap().is_empty());
        // Idempotent: a second ack matches nothing.
        assert_eq!(s.mark_bound("req-1", "op", 400).unwrap(), 0);
        // Operator-scoped: a different operator cannot ack this binding.
        s.issue("req-2", "code-2", "0xdevZ", "0xpopZ", 100, 700)
            .unwrap();
        s.claim("code-2", "op", "childZ", "agent-z", "memory", 200)
            .unwrap();
        assert_eq!(s.mark_bound("req-2", "other-op", 300).unwrap(), 0);
        assert_eq!(s.pending_bindings("op").unwrap().len(), 1);
    }

    #[test]
    fn purge_drops_unclaimed_expired_keeps_pending() {
        let s = store();
        s.issue("stale", "code-stale", "0xdevA", "0xpopA", 50, 100)
            .unwrap();
        s.issue("claimed", "code-claimed", "0xdevB", "0xpopB", 50, 100)
            .unwrap();
        s.claim("code-claimed", "op", "childB", "agent-b", "memory", 60)
            .unwrap();
        let n = s.purge_expired(10_000, 100).unwrap();
        assert_eq!(n, 1); // only the unclaimed-expired "stale" row
                          // The claimed row survives as a pending binding.
        assert_eq!(s.pending_bindings("op").unwrap().len(), 1);
    }

    #[test]
    fn issue_rejects_duplicate_request_id() {
        let s = store();
        s.issue("dup", "code-1", "0xdev", "0xpop", 100, 700)
            .unwrap();
        assert!(s
            .issue("dup", "code-2", "0xdev", "0xpop", 100, 700)
            .is_err());
    }

    #[test]
    fn issue_rejects_duplicate_pairing_code() {
        let s = store();
        s.issue("req-1", "dupcode", "0xdev", "0xpop", 100, 700)
            .unwrap();
        assert!(s
            .issue("req-2", "dupcode", "0xdev", "0xpop", 100, 700)
            .is_err());
    }
}
