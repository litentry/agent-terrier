//! Durable master session coordinates for the ui-bridge (issue #220).
//!
//! A daemon restart (a `dev.sh` rebuild, or Ctrl-C + rerun) drops the master's
//! in-memory `onboarding_session` + `registered_master`, so the web memory/config
//! pages used to 502 (`master device not registered on chain yet …`) and force a
//! full re-onboarding ceremony — even though nothing durable was lost. This module
//! persists the *coordinates* needed to resume (operator omni, device key hash,
//! the J1 while valid) to `~/.agentkeys/daemon-<wallet>/master-session.json`
//! (mode 0600), mirroring the agent daemon's `session.json` pattern (arch.md
//! §11.2). On startup the ui-bridge rehydrates from this file:
//!
//!   - a still-valid J1 → zero-prompt restore (no re-onboarding, no
//!     `--master-device-key-hash`);
//!   - an expired/absent J1 → the coords are still loaded so the web app can
//!     prompt exactly ONE passkey re-auth instead of a full re-onboarding.
//!
//! The on-chain `SidecarRegistry` binding is the real source of truth; the device
//! key hash is `keccak(operator_omni)` (see
//! `agentkeys_core::device_crypto::device_key_hash_from_omni`) so the file is a
//! convenience cache, never an authority. The WASM-in-browser host reuses the same
//! shape behind the `lib/client` contract with IndexedDB in place of the file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name inside each `daemon-<wallet>` directory holding the master coords.
/// Distinct from the agent daemon's `session.json` (which holds a typed
/// `agentkeys_types::Session`) so the two never collide on a shared directory.
const MASTER_SESSION_FILE: &str = "master-session.json";

/// Directory prefix under `~/.agentkeys/` for per-wallet daemon state, matching
/// the agent daemon convention (`session_store` writes `daemon-<id>/session.json`).
const DAEMON_DIR_PREFIX: &str = "daemon-";

/// Fallback J1 lifetime when the bearer JWT carries no `exp` claim — matches the
/// 5h TTL `init_flow::build_session_from_jwt` stamps on the managed-wallet session.
const DEFAULT_J1_TTL_SECS: u64 = 18_000;

/// The durable master session coordinates. Everything here is either public
/// (omni, device hash, wallet, email) or a bearer the daemon already holds in
/// memory (the J1) — no secret key material is persisted (K10/K11 stay in the OS
/// keychain / Secure Enclave per the K-inventory).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMasterSession {
    /// Schema marker so a future field change can be detected/migrated.
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// The master's managed-wallet address (`0x` + 40 hex) — the persistence key
    /// (`daemon-<wallet>/`). Empty only for identity-only sessions, which are not
    /// persisted; on the real path this is always set.
    pub wallet: String,
    /// The verified operator email (shown after restore; never a credential).
    #[serde(default)]
    pub email: String,
    /// The broker URL this session was minted against (#373 stack scoping).
    /// Two side-by-side stacks (Heima-AWS / Heima-VE) share `~/.agentkeys`, and
    /// under per-stack identity namespaces (#464) a foreign-stack record is a
    /// DIFFERENT identity — rehydrating it poisons every broker call (the
    /// 2026-07-16 incident: the AWS daemon rehydrated a VE-minted record and
    /// every cap-mint 401'd `InvalidSignature`). Empty on legacy records,
    /// which therefore match only a broker-less daemon.
    #[serde(default)]
    pub broker_url: String,
    /// The EVM `operator_omni` (master-self ⇒ operator == actor). Normalized
    /// `0x`-prefixed. `device_key_hash` is derivable from this alone.
    pub operator_omni: String,
    /// `keccak(operator_omni)` cached for convenience; re-derivable any time.
    pub device_key_hash: String,
    /// The J1 (EVM-omni) session JWT — the daemon's authenticated bearer.
    pub j1: String,
    /// Unix seconds when this record was written (dedup tiebreak in `load_latest`).
    pub created_at_unix: u64,
    /// Unix seconds the J1 stops being usable (from its `exp` claim, else
    /// `created_at_unix + DEFAULT_J1_TTL_SECS`). Drives valid-vs-expired at startup.
    pub j1_exp_unix: u64,
}

fn default_schema() -> u32 {
    1
}

impl PersistedMasterSession {
    /// `true` when the cached J1 is still usable at `now_unix` (with a small skew
    /// guard so a J1 about to expire is treated as expired — better one early
    /// re-auth than a mid-request 401).
    pub fn j1_valid_at(&self, now_unix: u64) -> bool {
        !self.j1.is_empty() && self.j1_exp_unix > now_unix.saturating_add(J1_EXPIRY_SKEW_SECS)
    }
}

/// Treat a J1 within this window of expiry as already expired.
const J1_EXPIRY_SKEW_SECS: u64 = 30;

/// Handle to the on-disk master-session store rooted at `~/.agentkeys/`.
/// Constructed only for the real ui-bridge run; tests inject a tempdir root so
/// they never touch the developer's `$HOME`.
#[derive(Clone, Debug)]
pub struct MasterSessionStore {
    /// The `~/.agentkeys` base directory (NOT including `daemon-<wallet>`).
    base: PathBuf,
}

impl MasterSessionStore {
    /// Root the store at an explicit `~/.agentkeys` base directory.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Resolve `~/.agentkeys` from `$HOME` (`$USERPROFILE` on Windows). Returns
    /// `None` when no home can be resolved — persistence is then disabled rather
    /// than writing to a surprising relative path.
    pub fn from_home_env() -> Option<Self> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        if home.is_empty() {
            return None;
        }
        Some(Self::new(PathBuf::from(home).join(".agentkeys")))
    }

    fn session_dir(&self, key: &str) -> PathBuf {
        self.base
            .join(format!("{DAEMON_DIR_PREFIX}{}", safe_key(key)))
    }

    fn session_path(&self, key: &str) -> PathBuf {
        self.session_dir(key).join(MASTER_SESSION_FILE)
    }

    /// The persistence key for a record: the wallet when set, else the omni — so
    /// a session with no managed-wallet address still lands under a stable dir.
    fn key_for(session: &PersistedMasterSession) -> &str {
        if !session.wallet.is_empty() {
            &session.wallet
        } else {
            &session.operator_omni
        }
    }

    /// Persist `session` to `~/.agentkeys/daemon-<wallet>/master-session.json`
    /// (mode 0600). Best-effort — a write failure is logged by the caller, never
    /// fatal to the live in-memory session.
    pub fn save(&self, session: &PersistedMasterSession) -> std::io::Result<()> {
        let path = self.session_path(Self::key_for(session));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(session)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_0600(&path, json.as_bytes())
    }

    /// Load the most-recently-written master session for THIS stack. The master
    /// plane is singular per (machine, stack) — not per machine: `load_latest`
    /// scans every `daemon-*/master-session.json`, considers ONLY records whose
    /// `broker_url` matches the daemon's (#373 — stacks share `~/.agentkeys`;
    /// under #464 a foreign-stack record is a different identity), and returns
    /// the newest by `created_at_unix` so a stale record from a prior wallet
    /// never shadows the current one. Legacy records (no `broker_url`) match
    /// only a broker-less daemon — one explicit sign-in re-persists them with
    /// the stack stamp.
    pub fn load_latest(&self, broker_url: &str) -> Option<PersistedMasterSession> {
        let want = normalize_broker(broker_url);
        let mut newest: Option<PersistedMasterSession> = None;
        let rd = std::fs::read_dir(&self.base).ok()?;
        for entry in rd.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(DAEMON_DIR_PREFIX) {
                continue;
            }
            let path = entry.path().join(MASTER_SESSION_FILE);
            let Ok(json) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<PersistedMasterSession>(&json) else {
                continue;
            };
            if normalize_broker(&parsed.broker_url) != want {
                tracing::info!(
                    target: "agentkeys.daemon.master_session",
                    wallet = %parsed.wallet,
                    record_broker = %parsed.broker_url,
                    daemon_broker = %broker_url,
                    "skipping persisted master session from another stack (#373 scoping — sign in on this stack once to persist it here)"
                );
                continue;
            }
            if newest
                .as_ref()
                .map(|n| parsed.created_at_unix >= n.created_at_unix)
                .unwrap_or(true)
            {
                newest = Some(parsed);
            }
        }
        newest
    }

    /// Remove every `daemon-*/master-session.json` under the root. Logout reset
    /// (issue #220 acceptance: the same email re-verifies to the same omni, so
    /// nothing durable is lost). The master plane is singular per machine, so this
    /// is a full reset, not a cross-wallet wipe.
    pub fn clear_all(&self) -> std::io::Result<()> {
        let Ok(rd) = std::fs::read_dir(&self.base) else {
            return Ok(());
        };
        for entry in rd.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(DAEMON_DIR_PREFIX)
            {
                continue;
            }
            let path = entry.path().join(MASTER_SESSION_FILE);
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }
}

/// Sanitize a wallet/omni into a single safe path segment (defense in depth — the
/// inputs are hex, but never let an odd value escape `~/.agentkeys/`). ASCII
/// alnum + `-_.` pass through lowercased; anything else becomes `_`.
fn safe_key(key: &str) -> String {
    let mapped: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() || mapped == "." || mapped == ".." {
        "_master".to_string()
    } else {
        mapped
    }
}

/// Write `bytes` to `path` truncating, mode 0600 on unix.
fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Current unix time in seconds (0 on a pre-epoch clock — never panics).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the `exp` claim (unix seconds) from a JWT WITHOUT verifying its
/// signature — the daemon holds the J1 as an opaque bearer (the broker signs it);
/// it only needs the expiry to decide valid-vs-re-auth at startup. Returns `None`
/// when the token isn't a parseable JWT or has no numeric `exp`.
/// Broker-URL equality for stack scoping: scheme/host casing and a trailing
/// slash are cosmetic, never a different stack.
fn normalize_broker(url: &str) -> String {
    url.trim().trim_end_matches('/').to_lowercase()
}

pub fn jwt_exp_unix(token: &str) -> Option<u64> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("exp").and_then(|v| v.as_u64())
}

/// Compute the J1 expiry to persist: the JWT `exp` when present, else
/// `created_at + DEFAULT_J1_TTL_SECS` (matches the managed-wallet session TTL).
pub fn j1_expiry_for(j1: &str, created_at_unix: u64) -> u64 {
    jwt_exp_unix(j1).unwrap_or_else(|| created_at_unix.saturating_add(DEFAULT_J1_TTL_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BROKER: &str = "https://broker.example";

    fn sample(wallet: &str, created: u64, exp: u64) -> PersistedMasterSession {
        PersistedMasterSession {
            schema: 1,
            wallet: wallet.to_string(),
            email: "sara@example.com".to_string(),
            broker_url: TEST_BROKER.to_string(),
            operator_omni: format!("0x{}", "ab".repeat(32)),
            device_key_hash: format!("0x{}", "cd".repeat(32)),
            j1: "eyJ.fake.jwt".to_string(),
            created_at_unix: created,
            j1_exp_unix: exp,
        }
    }

    fn temp_store() -> (MasterSessionStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = MasterSessionStore::new(tmp.path().join(".agentkeys"));
        (store, tmp)
    }

    #[test]
    fn save_then_load_latest_roundtrips() {
        let (store, _tmp) = temp_store();
        let s = sample("0xWALLET", 100, 9_999_999_999);
        store.save(&s).expect("save");
        let loaded = store.load_latest(TEST_BROKER).expect("load");
        assert_eq!(loaded, s);
    }

    #[test]
    fn load_latest_skips_records_from_another_stack() {
        // #373 scoping: the NEWEST record belongs to another stack (a different
        // broker) — it must never shadow this stack's own (older) record. This
        // is the 2026-07-16 bleed: the AWS daemon rehydrated a newer VE-minted
        // record and every broker call 401'd InvalidSignature.
        let (store, _tmp) = temp_store();
        store.save(&sample("0xMINE", 100, 5)).expect("save mine");
        let mut foreign = sample("0xTHEIRS", 200, 5);
        foreign.broker_url = "https://broker.other-stack.example".into();
        store.save(&foreign).expect("save foreign");

        let loaded = store.load_latest(TEST_BROKER).expect("load");
        assert_eq!(loaded.wallet, "0xMINE", "foreign newest must be skipped");
        // Trailing slash / casing are cosmetic, not a different stack.
        assert!(store.load_latest("HTTPS://broker.example/").is_some());
        // The other stack still finds its own record.
        assert_eq!(
            store
                .load_latest("https://broker.other-stack.example")
                .expect("foreign load")
                .wallet,
            "0xTHEIRS"
        );
    }

    #[test]
    fn legacy_records_match_only_a_brokerless_daemon() {
        // Pre-#373 records carry no broker_url: a broker-configured daemon must
        // skip them (one explicit sign-in re-persists with the stamp); only a
        // broker-less (script-mode) daemon still rehydrates them.
        let (store, _tmp) = temp_store();
        let mut legacy = sample("0xLEGACY", 100, 5);
        legacy.broker_url = String::new();
        store.save(&legacy).expect("save legacy");
        assert!(store.load_latest(TEST_BROKER).is_none());
        assert_eq!(store.load_latest("").expect("load").wallet, "0xLEGACY");
    }

    #[test]
    fn save_writes_under_daemon_wallet_dir_mode_0600() {
        let (store, tmp) = temp_store();
        let s = sample("0xWaLLeT", 1, 2);
        store.save(&s).expect("save");
        // Wallet is lowercased into the dir name.
        let path = tmp
            .path()
            .join(".agentkeys")
            .join("daemon-0xwallet")
            .join("master-session.json");
        assert!(path.exists(), "expected {path:?} to exist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "master-session.json must be 0600");
        }
    }

    #[test]
    fn load_latest_picks_newest_by_created_at() {
        let (store, _tmp) = temp_store();
        store.save(&sample("0xOLD", 100, 5)).expect("save old");
        store.save(&sample("0xNEW", 200, 5)).expect("save new");
        let loaded = store.load_latest(TEST_BROKER).expect("load");
        assert_eq!(loaded.wallet, "0xNEW");
    }

    #[test]
    fn clear_all_wipes_every_master_record_and_is_idempotent() {
        let (store, _tmp) = temp_store();
        store.save(&sample("0xA", 1, 2)).expect("save a");
        store.save(&sample("0xB", 2, 3)).expect("save b");
        store.clear_all().expect("clear all");
        assert!(store.load_latest(TEST_BROKER).is_none());
        // Second clear on an already-empty root is a no-op, not an error.
        store.clear_all().expect("clear all again");
    }

    #[test]
    fn j1_valid_at_respects_expiry_with_skew() {
        let s = sample("0xW", 0, 1_000);
        assert!(s.j1_valid_at(900), "well before expiry → valid");
        assert!(!s.j1_valid_at(1_000), "at expiry → expired");
        assert!(!s.j1_valid_at(990), "within the 30s skew window → expired");
    }

    #[test]
    fn j1_valid_at_false_when_j1_empty() {
        let mut s = sample("0xW", 0, u64::MAX);
        s.j1 = String::new();
        assert!(
            !s.j1_valid_at(0),
            "empty J1 is never valid even with a far exp"
        );
    }

    #[test]
    fn jwt_exp_unix_reads_exp_claim() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        // header.payload.signature with payload {"exp": 1893456000}
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1893456000,"sub":"x"}"#);
        let token = format!("aGVhZGVy.{payload}.c2ln");
        assert_eq!(jwt_exp_unix(&token), Some(1_893_456_000));
    }

    #[test]
    fn jwt_exp_unix_none_for_garbage() {
        assert_eq!(jwt_exp_unix("not-a-jwt"), None);
        assert_eq!(jwt_exp_unix(""), None);
        assert_eq!(jwt_exp_unix("a.b.c"), None);
    }

    #[test]
    fn j1_expiry_for_falls_back_to_default_ttl() {
        // No parseable exp → created_at + 18000.
        assert_eq!(
            j1_expiry_for("not.a.jwt", 1_000),
            1_000 + DEFAULT_J1_TTL_SECS
        );
    }

    #[test]
    fn load_latest_none_on_empty_root() {
        let (store, _tmp) = temp_store();
        assert!(store.load_latest(TEST_BROKER).is_none());
    }

    #[test]
    fn safe_key_blocks_path_traversal() {
        // The path separator is neutralized to `_`, collapsing a would-be
        // traversal into a single inert segment (`.` is a safe filename char, so
        // the leading dots survive — but `..escape` with no `/` can't traverse).
        let escaped = safe_key("../escape");
        assert_eq!(escaped, ".._escape");
        assert!(!escaped.contains('/'), "must contain no path separator");
        // Reserved path components fold to a stable inert name.
        assert_eq!(safe_key(""), "_master");
        assert_eq!(safe_key("."), "_master");
        assert_eq!(safe_key(".."), "_master");
        assert_eq!(safe_key("0xABC"), "0xabc");
    }
}
