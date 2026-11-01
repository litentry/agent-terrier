//! `AgentDelegationStore` — the device→sandbox delegation rendezvous (issue #369
//! origination side).
//!
//! The sandbox and the device are never online at the same place: the sandbox
//! runs in the cloud, the device (K10 holder) is an ESP32 on a LAN. The broker is
//! the rendezvous — but it stays UNTRUSTED, exactly as in #76/#367: it only
//! relays a device-signed delegation, it cannot forge one (the `delegation_sig`
//! is the DEVICE's, verified by the worker). One row models the lifecycle:
//!
//! ```text
//! requested  (sandbox ran POST /v1/agent/delegation/request, J1-gated — the
//!             device is derived from the J1's device_pubkey claim, NOT
//!             client-supplied, so a sandbox can't request for another device;
//!             sandbox_pubkey + requested_scope captured; signed_* still ∅)
//!   → signed  (device ran POST /v1/agent/delegation/sign, pop_sig-gated — it
//!             co-signed delegation_payload(device_key_hash, sandbox_pubkey,
//!             scope, expires_at) with K10; delegation_sig + final scope/expiry
//!             recorded)
//! ```
//!
//! The sandbox then polls `/v1/agent/delegation/poll` (J1-gated) for the
//! `delegation_sig` and attaches it as the cap-mint `delegation_path`.
//!
//! SQLite (mirroring `pairing_requests.rs`) so a broker restart between a request
//! and a sign doesn't silently drop the rendezvous. Rows are short-lived
//! (`DELEGATION_REQUEST_TTL_SECONDS`); `request()` opportunistically purges expired
//! rows so the table stays bounded without a background janitor. Returns
//! `BrokerError` since broker handlers consume it.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{BrokerError, BrokerResult};

/// How long a delegation REQUEST stays open for the device to sign it. The device
/// polls `/pending` frequently while active, so this is short; an unsigned request
/// past it returns `Expired` and the sandbox re-requests.
pub const DELEGATION_REQUEST_TTL_SECONDS: i64 = 300;

/// SQLite-backed device→sandbox delegation rendezvous store.
pub struct AgentDelegationStore {
    conn: Mutex<Connection>,
}

/// One unsigned request the device discovers via `/pending` (it must co-sign a
/// delegation for `sandbox_pubkey` bounded by `requested_scope` + a TTL).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PendingDelegationRequest {
    pub request_id: String,
    pub sandbox_pubkey: String,
    pub requested_scope: String,
    pub requested_ttl_seconds: i64,
    pub expires_at: i64,
}

/// What the device needs to co-sign a request (read before `record_signature`):
/// the `sandbox_pubkey` the delegation must bind + the scope the sandbox asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum SignTarget {
    Ready {
        sandbox_pubkey: String,
        requested_scope: String,
    },
    /// `request_id` unknown for this device, or already signed (one variant so a
    /// prober can't distinguish).
    NotFoundOrSigned,
    /// The request's sign window elapsed before the device co-signed.
    Expired,
}

/// Outcome of [`AgentDelegationStore::record_signature`].
#[derive(Debug, PartialEq, Eq)]
pub enum DelegationSign {
    Signed,
    /// Lost the race (already signed) or unknown for this device.
    NotFoundOrSigned,
    Expired,
}

/// Outcome of [`AgentDelegationStore::poll`] (sandbox polls by `request_id`).
#[derive(Debug, PartialEq, Eq)]
pub enum DelegationPoll {
    /// Exists + unexpired but the device hasn't co-signed yet.
    Pending,
    /// The device co-signed — carries exactly what the sandbox attaches as the
    /// cap-mint `delegation_path`.
    Signed {
        scope: String,
        expires_at: i64,
        delegation_sig: String,
    },
    /// `request_id` unknown, or the supplied `device_key_hash` (from the sandbox's
    /// J1) doesn't match the row — binding mismatch hidden behind one variant.
    NotFound,
    /// Sign window elapsed before the device co-signed.
    Expired,
}

/// The `poll()` SELECT row: `(req_expires_at, signed_at, scope, deleg_expires_at,
/// delegation_sig)` — the four trailing `Option`s are NULL until the device signs.
type PollRow = (
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<String>,
);

impl AgentDelegationStore {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        let conn = Connection::open(path).map_err(|e| {
            BrokerError::Internal(format!("open agent_delegations db {}: {e}", path.display()))
        })?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> BrokerResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            BrokerError::Internal(format!("open in-memory agent_delegations db: {e}"))
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
            .map_err(|e| BrokerError::Internal(format!("agent_delegations mutex poisoned: {e}")))
    }

    fn init_schema(&self) -> BrokerResult<()> {
        self.lock()?
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 CREATE TABLE IF NOT EXISTS agent_delegations (
                    request_id            TEXT PRIMARY KEY,
                    device_key_hash       TEXT NOT NULL,
                    operator_omni         TEXT NOT NULL,
                    actor_omni            TEXT NOT NULL,
                    sandbox_pubkey        TEXT NOT NULL,
                    requested_scope       TEXT NOT NULL,
                    requested_ttl_seconds INTEGER NOT NULL,
                    created_at            INTEGER NOT NULL,
                    expires_at            INTEGER NOT NULL,
                    signed_at             INTEGER,
                    scope                 TEXT,
                    deleg_expires_at      INTEGER,
                    delegation_sig        TEXT
                 );
                 CREATE INDEX IF NOT EXISTS idx_agent_delegations_device
                    ON agent_delegations(device_key_hash);
                 CREATE INDEX IF NOT EXISTS idx_agent_delegations_expires_at
                    ON agent_delegations(expires_at);",
            )
            .map_err(|e| BrokerError::Internal(format!("init agent_delegations schema: {e}")))?;
        Ok(())
    }

    /// Open a new delegation request (sandbox ran `/v1/agent/delegation/request`).
    /// Opportunistically purges expired rows first so the table stays bounded
    /// without a janitor, and supersedes any prior OPEN (unsigned) request for the
    /// SAME `(device_key_hash, sandbox_pubkey)` so a re-request doesn't accumulate.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        request_id: &str,
        device_key_hash: &str,
        operator_omni: &str,
        actor_omni: &str,
        sandbox_pubkey: &str,
        requested_scope: &str,
        requested_ttl_seconds: i64,
        created_at: i64,
        expires_at: i64,
    ) -> BrokerResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM agent_delegations WHERE expires_at <= ?1 AND signed_at IS NULL",
            params![created_at],
        )
        .map_err(|e| BrokerError::Internal(format!("purge expired agent_delegations: {e}")))?;
        conn.execute(
            "DELETE FROM agent_delegations
             WHERE LOWER(device_key_hash) = LOWER(?1)
               AND LOWER(sandbox_pubkey) = LOWER(?2)
               AND signed_at IS NULL",
            params![device_key_hash, sandbox_pubkey],
        )
        .map_err(|e| BrokerError::Internal(format!("supersede open agent_delegations: {e}")))?;
        conn.execute(
            "INSERT INTO agent_delegations
                (request_id, device_key_hash, operator_omni, actor_omni, sandbox_pubkey,
                 requested_scope, requested_ttl_seconds, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request_id,
                device_key_hash,
                operator_omni,
                actor_omni,
                sandbox_pubkey,
                requested_scope,
                requested_ttl_seconds,
                created_at,
                expires_at
            ],
        )
        .map_err(|e| BrokerError::Internal(format!("insert agent_delegation: {e}")))?;
        Ok(())
    }

    /// Unsigned, unexpired requests for `device_key_hash` (device ran `/pending`).
    pub fn pending(
        &self,
        device_key_hash: &str,
        now: i64,
    ) -> BrokerResult<Vec<PendingDelegationRequest>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT request_id, sandbox_pubkey, requested_scope, requested_ttl_seconds, expires_at
                 FROM agent_delegations
                 WHERE LOWER(device_key_hash) = LOWER(?1)
                   AND signed_at IS NULL
                   AND expires_at > ?2
                 ORDER BY created_at ASC",
            )
            .map_err(|e| BrokerError::Internal(format!("prepare pending agent_delegations: {e}")))?;
        let rows = stmt
            .query_map(params![device_key_hash, now], |r| {
                Ok(PendingDelegationRequest {
                    request_id: r.get(0)?,
                    sandbox_pubkey: r.get(1)?,
                    requested_scope: r.get(2)?,
                    requested_ttl_seconds: r.get(3)?,
                    expires_at: r.get(4)?,
                })
            })
            .map_err(|e| BrokerError::Internal(format!("query pending agent_delegations: {e}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| BrokerError::Internal(format!("read pending agent_delegations: {e}")))?;
        Ok(rows)
    }

    /// Read what the device needs to co-sign a request (the `sandbox_pubkey` the
    /// delegation must bind), bound to `device_key_hash` so a device can only ever
    /// sign its OWN requests.
    pub fn sign_target(
        &self,
        request_id: &str,
        device_key_hash: &str,
        now: i64,
    ) -> BrokerResult<SignTarget> {
        let conn = self.lock()?;
        let row: Option<(String, String, i64, Option<i64>)> = conn
            .query_row(
                "SELECT sandbox_pubkey, requested_scope, expires_at, signed_at
                 FROM agent_delegations
                 WHERE request_id = ?1 AND LOWER(device_key_hash) = LOWER(?2)",
                params![request_id, device_key_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("read sign_target: {e}")))?;
        match row {
            None => Ok(SignTarget::NotFoundOrSigned),
            Some((_, _, _, Some(_signed))) => Ok(SignTarget::NotFoundOrSigned),
            Some((_, _, expires_at, None)) if expires_at <= now => Ok(SignTarget::Expired),
            Some((sandbox_pubkey, requested_scope, _, None)) => Ok(SignTarget::Ready {
                sandbox_pubkey,
                requested_scope,
            }),
        }
    }

    /// Record the device's co-signature (device ran `/sign`). Atomic conditional
    /// UPDATE (`signed_at IS NULL AND expires_at > now`) so a concurrent double-sign
    /// loses the race rather than overwriting. The handler verifies the signature
    /// (defense-in-depth) before calling this; the worker re-verifies regardless.
    pub fn record_signature(
        &self,
        request_id: &str,
        device_key_hash: &str,
        scope: &str,
        deleg_expires_at: i64,
        delegation_sig: &str,
        now: i64,
    ) -> BrokerResult<DelegationSign> {
        let conn = self.lock()?;
        let updated = conn
            .execute(
                "UPDATE agent_delegations
                 SET signed_at = ?1, scope = ?2, deleg_expires_at = ?3, delegation_sig = ?4
                 WHERE request_id = ?5 AND LOWER(device_key_hash) = LOWER(?6)
                   AND signed_at IS NULL AND expires_at > ?1",
                params![
                    now,
                    scope,
                    deleg_expires_at,
                    delegation_sig,
                    request_id,
                    device_key_hash
                ],
            )
            .map_err(|e| BrokerError::Internal(format!("record delegation signature: {e}")))?;
        if updated == 1 {
            return Ok(DelegationSign::Signed);
        }
        // 0 rows: either unknown/already-signed, or expired. Disambiguate for a
        // clearer device-facing error (the row still exists when merely expired).
        let exists: Option<i64> = conn
            .query_row(
                "SELECT expires_at FROM agent_delegations
                 WHERE request_id = ?1 AND LOWER(device_key_hash) = LOWER(?2)
                   AND signed_at IS NULL",
                params![request_id, device_key_hash],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("disambiguate sign failure: {e}")))?;
        match exists {
            Some(_) => Ok(DelegationSign::Expired),
            None => Ok(DelegationSign::NotFoundOrSigned),
        }
    }

    /// Read a request's state (sandbox ran `/poll`), bound to `device_key_hash` (the
    /// sandbox's J1 device) so a sandbox can only poll its OWN device's requests.
    pub fn poll(
        &self,
        request_id: &str,
        device_key_hash: &str,
        now: i64,
    ) -> BrokerResult<DelegationPoll> {
        let conn = self.lock()?;
        let row: Option<PollRow> = conn
            .query_row(
                "SELECT expires_at, signed_at, scope, deleg_expires_at, delegation_sig
                 FROM agent_delegations
                 WHERE request_id = ?1 AND LOWER(device_key_hash) = LOWER(?2)",
                params![request_id, device_key_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(format!("poll agent_delegation: {e}")))?;
        match row {
            None => Ok(DelegationPoll::NotFound),
            Some((_, Some(_signed), Some(scope), Some(expires_at), Some(delegation_sig))) => {
                Ok(DelegationPoll::Signed {
                    scope,
                    expires_at,
                    delegation_sig,
                })
            }
            // Unsigned: pending until its window elapses.
            Some((req_expires, None, _, _, _)) if req_expires > now => Ok(DelegationPoll::Pending),
            Some(_) => Ok(DelegationPoll::Expired),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AgentDelegationStore {
        AgentDelegationStore::open_in_memory().unwrap()
    }

    fn req(s: &AgentDelegationStore, id: &str, dkh: &str, sandbox: &str, created: i64, exp: i64) {
        s.request(
            id, dkh, "0xop", "0xactor", sandbox, "memory", 3600, created, exp,
        )
        .unwrap();
    }

    #[test]
    fn request_then_pending_then_sign_then_poll() {
        let s = store();
        req(&s, "r1", "0xdkh", "0xsandbox", 100, 400);

        // Device discovers the open request.
        let pending = s.pending("0xdkh", 200).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "r1");
        assert_eq!(pending[0].sandbox_pubkey, "0xsandbox");

        // Sandbox polling sees pending.
        assert_eq!(s.poll("r1", "0xdkh", 200).unwrap(), DelegationPoll::Pending);

        // Device reads the sign target then records its signature.
        assert_eq!(
            s.sign_target("r1", "0xdkh", 200).unwrap(),
            SignTarget::Ready {
                sandbox_pubkey: "0xsandbox".into(),
                requested_scope: "memory".into(),
            }
        );
        assert_eq!(
            s.record_signature("r1", "0xdkh", "memory", 4000, "0xsig", 200)
                .unwrap(),
            DelegationSign::Signed
        );

        // No longer pending; sandbox poll now returns the signature.
        assert!(s.pending("0xdkh", 250).unwrap().is_empty());
        assert_eq!(
            s.poll("r1", "0xdkh", 250).unwrap(),
            DelegationPoll::Signed {
                scope: "memory".into(),
                expires_at: 4000,
                delegation_sig: "0xsig".into(),
            }
        );
    }

    #[test]
    fn poll_is_bound_to_the_requesting_device() {
        let s = store();
        req(&s, "r1", "0xdeviceA", "0xsandbox", 100, 400);
        // A different device's J1 cannot read the request.
        assert_eq!(
            s.poll("r1", "0xdeviceB", 200).unwrap(),
            DelegationPoll::NotFound
        );
        // Nor can a different device sign it.
        assert_eq!(
            s.sign_target("r1", "0xdeviceB", 200).unwrap(),
            SignTarget::NotFoundOrSigned
        );
    }

    #[test]
    fn expired_request_cannot_be_signed_or_polled() {
        let s = store();
        req(&s, "r1", "0xdkh", "0xsandbox", 100, 400);
        // now=500 is past expires_at=400.
        assert_eq!(
            s.sign_target("r1", "0xdkh", 500).unwrap(),
            SignTarget::Expired
        );
        assert_eq!(
            s.record_signature("r1", "0xdkh", "memory", 4000, "0xsig", 500)
                .unwrap(),
            DelegationSign::Expired
        );
        assert_eq!(s.poll("r1", "0xdkh", 500).unwrap(), DelegationPoll::Expired);
    }

    #[test]
    fn double_sign_loses_the_race() {
        let s = store();
        req(&s, "r1", "0xdkh", "0xsandbox", 100, 400);
        assert_eq!(
            s.record_signature("r1", "0xdkh", "memory", 4000, "0xsig", 200)
                .unwrap(),
            DelegationSign::Signed
        );
        // A second sign is a no-op (already signed).
        assert_eq!(
            s.record_signature("r1", "0xdkh", "memory", 4000, "0xother", 200)
                .unwrap(),
            DelegationSign::NotFoundOrSigned
        );
    }

    #[test]
    fn re_request_supersedes_open_row_and_purges_expired() {
        let s = store();
        req(&s, "old", "0xdkh", "0xsandbox", 100, 400);
        // Re-request for the same (device, sandbox) supersedes the open row.
        req(&s, "new", "0xdkh", "0xsandbox", 150, 450);
        assert_eq!(
            s.poll("old", "0xdkh", 200).unwrap(),
            DelegationPoll::NotFound
        );
        let pending = s.pending("0xdkh", 200).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "new");

        // A request after a long gap purges the now-expired "new" row.
        req(&s, "fresh", "0xdkh", "0xsandbox2", 9999, 10299);
        assert_eq!(
            s.poll("new", "0xdkh", 9999).unwrap(),
            DelegationPoll::NotFound
        );
    }
}
