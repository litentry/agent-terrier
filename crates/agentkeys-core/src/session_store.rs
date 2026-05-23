use agentkeys_types::Session;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const KEYRING_SERVICE: &str = "agentkeys";

/// Marker file written alongside (but NOT overwriting) the session.json in a
/// session's fallback directory whenever the real credential lives in the OS
/// keyring instead of the file. Kept distinct from session.json so that
/// switching between keyring and file modes does not destroy the real
/// file-mode credential (codex PR #24 P2).
const KEYRING_MARKER_FILE: &str = ".keyring_managed";

/// Directory name used under the base directory to hold per-session state.
const AGENTKEYS_DIR: &str = ".agentkeys";

/// File name used inside each session directory to hold the serialized session.
const SESSION_FILE: &str = "session.json";

/// Reserved prefix for rewritten session_ids. User-supplied inputs that
/// start with this prefix are also forced through the rewrite path so
/// collisions between rewrites and raw names are impossible (codex PR
/// #24 v6 P2). The prefix uses only characters in the safe alphabet
/// (`_`, ascii-alpha) so that the output remains valid as both a keyring
/// account and a filesystem directory name on Windows / Linux / macOS.
const REWRITE_PREFIX: &str = "__agk_";

/// Whether to consult the OS keyring.
///
/// `Auto` tries the keyring first and falls back to file storage — the
/// production default. `FileOnly` skips the keyring entirely, which tests,
/// CI runners, and headless environments rely on.
///
/// Exposing this as an explicit enum on `SessionStore` replaces the
/// implicit `AGENTKEYS_SESSION_STORE` env-var read that callers used to
/// rely on. Tests can now opt into file-only mode via a constructor
/// argument instead of mutating process-global env (issue #34).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyringMode {
    Auto,
    FileOnly,
}

/// Handle to a session store rooted at an explicit `base_dir` with an
/// explicit `KeyringMode`.
///
/// Everything path-related lives under `<base_dir>/.agentkeys/`. Replaces
/// the previous set of free functions that read `$HOME` and
/// `AGENTKEYS_SESSION_STORE` on every call. Callers that need test
/// isolation (or a non-default deploy root) now construct a `SessionStore`
/// explicitly instead of mutating process-global env vars. Existing
/// production callers keep using the thin free-function wrappers below,
/// which construct `SessionStore::from_env()` on each call.
#[derive(Debug, Clone)]
pub struct SessionStore {
    base_dir: PathBuf,
    keyring_mode: KeyringMode,
}

impl SessionStore {
    /// Construct a store rooted at `base_dir` that never touches the OS
    /// keyring. Intended for tests and headless environments — lets a
    /// tempdir-scoped test avoid both `$HOME` mutation and the keychain.
    ///
    /// This is the only public constructor that accepts a custom `base_dir`.
    /// `KeyringMode::Auto` is intentionally not offered for custom roots:
    /// keyring entries are keyed on `session_id` alone and do not incorporate
    /// `base_dir`, so two stores at different roots sharing a `session_id`
    /// would silently alias through the OS keychain. Forcing the file path
    /// for custom roots keeps isolation by construction (codex /codex review
    /// on PR #43 [P2]).
    pub fn file_only(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            keyring_mode: KeyringMode::FileOnly,
        }
    }

    /// Construct a store from the process environment: `$HOME` (or
    /// `$USERPROFILE`, falling back to `"."`) for the base dir, and
    /// `AGENTKEYS_SESSION_STORE=file` for the keyring mode. This is the
    /// production path and is what every legacy free-function wrapper
    /// below resolves to. It is also the only constructor that may return
    /// `KeyringMode::Auto` — the home-rooted single-root invariant the
    /// keyring namespace assumes.
    pub fn from_env() -> Self {
        let keyring_mode = match std::env::var("AGENTKEYS_SESSION_STORE").as_deref() {
            Ok("file") => KeyringMode::FileOnly,
            _ => KeyringMode::Auto,
        };
        Self {
            base_dir: home_dir_from_env(),
            keyring_mode,
        }
    }

    /// The base directory this store is rooted at. Everything lives under
    /// `<base_dir>/.agentkeys/`.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// The configured keyring mode.
    pub fn keyring_mode(&self) -> KeyringMode {
        self.keyring_mode
    }

    fn skip_keyring(&self) -> bool {
        matches!(self.keyring_mode, KeyringMode::FileOnly)
    }

    fn session_dir(&self, session_id: &str) -> PathBuf {
        // Route through sanitize_for_keyring so session_ids containing path
        // separators, '..', or null bytes can't escape ~/.agentkeys (codex PR
        // #24 v2 P2 — path traversal via --session-id).
        self.base_dir
            .join(AGENTKEYS_DIR)
            .join(sanitize_for_keyring(session_id))
    }

    /// Path to the on-disk `session.json` for `session_id`. Exposed for
    /// tests that want to assert presence/absence without reaching through
    /// save/load.
    pub fn session_path(&self, session_id: &str) -> PathBuf {
        self.session_dir(session_id).join(SESSION_FILE)
    }

    fn marker_path(&self, session_id: &str) -> PathBuf {
        self.session_dir(session_id).join(KEYRING_MARKER_FILE)
    }

    /// Save `session` under `session_id`. Tries the keyring first (when
    /// `KeyringMode::Auto`), falls back to
    /// `<base_dir>/.agentkeys/<session_id>/session.json` (mode 0600).
    ///
    /// On a successful keyring save, also drops an empty `.keyring_managed`
    /// marker file so `list_ids` can discover keyring-stored sessions (OS
    /// keychain APIs don't expose a prefix-scan without per-entry
    /// permission prompts). The marker is NEVER written over an existing
    /// session.json, so toggling between keyring and file modes doesn't
    /// destroy the real fallback (codex PR #24 P2).
    pub fn save(&self, session: &Session, session_id: &str) -> Result<()> {
        let json = serde_json::to_string(session).context("serialize session")?;

        if !self.skip_keyring() && try_keyring_save(&json, session_id) {
            // Marker file is best-effort: it's only required for
            // prefix-scan discovery (daemon-restart path). Direct-load
            // callers like `master` look up by known id, so a missing
            // marker doesn't break them. If the marker can't land
            // (read-only HOME, missing filesystem), the keyring entry
            // is still the authoritative store — emit a diagnostic on
            // stderr and return Ok (codex PR #24 v4 P2).
            let marker = self.marker_path(session_id);
            if let Some(parent) = marker.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!(
                        "[agentkeys] warning: could not create marker dir {}: {e}. \
                         Session saved in keyring; prefix-scan discovery may fail on restart.",
                        parent.display()
                    );
                    return Ok(());
                }
            }
            if let Err(e) = std::fs::File::create(&marker) {
                eprintln!(
                    "[agentkeys] warning: could not write keyring marker {}: {e}. \
                     Session saved in keyring; prefix-scan discovery may fail on restart.",
                    marker.display()
                );
            }
            return Ok(());
        }

        self.save_to_file(&json, session_id)
    }

    /// Load the session for `session_id`. Tries the keyring first (when
    /// `KeyringMode::Auto`, bounded by a 2s timeout), falls back to the
    /// file.
    pub fn load(&self, session_id: &str) -> Result<Session> {
        if !self.skip_keyring() {
            if let Some(json) = try_keyring_load(session_id) {
                return serde_json::from_str(&json).context("deserialize session from keyring");
            }
        }
        self.load_from_file(session_id)
    }

    /// Enumerate session IDs that have a persisted session under
    /// `<base_dir>/.agentkeys/`. Looks for either a real `session.json`
    /// (file mode) or the `.keyring_managed` marker (keyring mode) in each
    /// candidate directory. Results are sorted alphabetically so daemon
    /// startup is deterministic across runs (codex PR #24 P1).
    pub fn list_ids(&self, prefix: &str) -> Vec<String> {
        let root = self.base_dir.join(AGENTKEYS_DIR);
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(&root) else {
            return out;
        };
        for entry in rd.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(prefix) {
                continue;
            }
            let dir = entry.path();
            if dir.join(SESSION_FILE).exists() || dir.join(KEYRING_MARKER_FILE).exists() {
                out.push(name);
            }
        }
        out.sort();
        out
    }

    /// Load a session with legacy-location fallback. Used by the master
    /// CLI (session_id = "master") after #12 namespacing — old installs
    /// have the session stored under keyring account=`session` or file
    /// `<base_dir>/.agentkeys/session.json`. Try the new location first,
    /// then fall back to the legacy locations so existing users stay
    /// logged in across the upgrade.
    pub fn load_with_legacy_fallback(&self, session_id: &str) -> Result<Session> {
        if let Ok(s) = self.load(session_id) {
            return Ok(s);
        }
        if session_id == "master" {
            // Legacy keyring account: "session"
            if !self.skip_keyring() {
                if let Some(json) = try_keyring_load("session") {
                    return serde_json::from_str(&json)
                        .context("deserialize legacy session from keyring");
                }
            }
            // Legacy file: <base_dir>/.agentkeys/session.json
            let legacy = self.base_dir.join(AGENTKEYS_DIR).join(SESSION_FILE);
            if let Ok(json) = std::fs::read_to_string(&legacy) {
                return serde_json::from_str(&json).context("deserialize legacy session from file");
            }
        }
        anyhow::bail!(
            "no session found for id={session_id} at {} (keyring mode: {:?}; legacy fallbacks apply only to id=\"master\")",
            self.session_path(session_id).display(),
            self.keyring_mode,
        )
    }

    /// Remove the session entry for `session_id` only (does not affect
    /// other ids). Blocks on the keyring delete (up to 2 seconds) so
    /// callers know the credential is actually gone before `clear`
    /// returns. Previously fire-and-forget, which let `cmd_revoke` report
    /// success while the keyring entry was still live — next command
    /// would load the stale session (codex PR #24 v8 P1).
    pub fn clear(&self, session_id: &str) -> Result<()> {
        if !self.skip_keyring() {
            let deleted = try_keyring_delete(session_id);
            if !deleted {
                return Err(anyhow::anyhow!(
                    "keyring delete failed or timed out for session_id={session_id}; local session may still be loadable on next command"
                ));
            }
        }
        let path = self.session_path(session_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("remove session file {}", path.display()))?;
        }
        let marker = self.marker_path(session_id);
        if marker.exists() {
            let _ = std::fs::remove_file(&marker);
        }
        Ok(())
    }

    fn save_to_file(&self, json: &str, session_id: &str) -> Result<()> {
        let path = self.session_path(session_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            let mut file = opts
                .open(&path)
                .with_context(|| format!("open session file {}", path.display()))?;
            file.write_all(json.as_bytes())
                .with_context(|| format!("write session file {}", path.display()))?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&path, json)
                .with_context(|| format!("write session file {}", path.display()))?;
        }

        Ok(())
    }

    fn load_from_file(&self, session_id: &str) -> Result<Session> {
        let path = self.session_path(session_id);
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("read session file at {}", path.display()))?;
        serde_json::from_str(&json).context("deserialize session from file")
    }
}

fn home_dir_from_env() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
}

// ---- Legacy free-function API -------------------------------------------
//
// Thin wrappers that construct `SessionStore::from_env()` on every call,
// preserving the behavior the daemon, older CLI helpers, and integration
// tests already depend on. New code should prefer building a `SessionStore`
// explicitly so the base dir and keyring mode are visible at the call site.

/// Path to the on-disk session.json for `session_id`, resolved from
/// `$HOME`. Exposed for tests and for legacy callers — new code should use
/// [`SessionStore::session_path`] on a store you own.
pub fn fallback_path(session_id: &str) -> PathBuf {
    SessionStore::from_env().session_path(session_id)
}

/// Save `session` under `session_id` using a store built from the process
/// env. See [`SessionStore::save`] for semantics.
pub fn save_session(session: &Session, session_id: &str) -> Result<()> {
    SessionStore::from_env().save(session, session_id)
}

/// Load the session for `session_id` using a store built from the process
/// env. See [`SessionStore::load`] for semantics.
pub fn load_session(session_id: &str) -> Result<Session> {
    SessionStore::from_env().load(session_id)
}

/// Enumerate session IDs under `$HOME/.agentkeys/` with the given prefix.
/// See [`SessionStore::list_ids`] for semantics.
pub fn list_fallback_session_ids(prefix: &str) -> Vec<String> {
    SessionStore::from_env().list_ids(prefix)
}

/// Load a session with legacy-location fallback using a store built from
/// the process env. See [`SessionStore::load_with_legacy_fallback`] for
/// semantics.
pub fn load_session_with_legacy_fallback(session_id: &str) -> Result<Session> {
    SessionStore::from_env().load_with_legacy_fallback(session_id)
}

/// Remove the session entry for `session_id` using a store built from the
/// process env. See [`SessionStore::clear`] for semantics.
pub fn clear_session(session_id: &str) -> Result<()> {
    SessionStore::from_env().clear(session_id)
}

/// Sanitize `session_id` for use as a keyring account name AND filesystem
/// directory name. Windows Credential Manager rejects null bytes, Linux
/// `secret-service` rejects non-UTF8 and is quirky about shell-reserved
/// chars, macOS is tolerant. Any filesystem rejects `""`, `"."`, `".."`
/// as path components (traversal vectors).
///
/// Accept-as-is rule: ASCII alnum + `-_.`, unchanged, non-empty, non-reserved
/// (not `"."` / `".."`), not starting with `REWRITE_PREFIX`, ≤128 chars.
/// Anything failing those rules goes through the stable rewrite path:
///   `__agk_<truncated-safe-chars>-<sha256(s)[..4] hex-lower>`
/// SHA-256 (not `DefaultHasher`) keeps the suffix stable across Rust
/// toolchain versions so persisted IDs remain reachable after upgrades
/// (codex PR #24 v3 P2).
pub(crate) fn sanitize_for_keyring(s: &str) -> String {
    const MAX: usize = 128;

    let safe: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();

    // Force rewrite if the input is empty, a reserved path component, starts
    // with the reserved rewrite prefix, exceeds the length cap, or was
    // normalised (sanitized differs from original). Path traversal via `..`
    // is explicitly blocked by the reserved-path check (codex PR #24 v6 P1).
    let is_reserved = s.is_empty() || s == "." || s == "..";
    let starts_with_prefix = s.starts_with(REWRITE_PREFIX);
    let accepts_as_is = safe == s && safe.len() <= MAX && !is_reserved && !starts_with_prefix;

    if accepts_as_is {
        return safe;
    }

    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.as_bytes());
    let hash = hex::encode(&digest[..4]); // 8 hex chars
                                          // Reserve room for the prefix + '-' + 8-char suffix.
    let prefix_max = MAX.saturating_sub(REWRITE_PREFIX.len() + 1 + 8);
    let body = if safe.len() > prefix_max {
        &safe[..prefix_max]
    } else {
        &safe
    };
    format!("{}{}-{}", REWRITE_PREFIX, body, hash)
}

fn try_keyring_save(json: &str, session_id: &str) -> bool {
    let json_owned = json.to_string();
    let account = sanitize_for_keyring(session_id);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = keyring::Entry::new(KEYRING_SERVICE, &account)
            .and_then(|e| e.set_password(&json_owned));
        let _ = tx.send(result.is_ok());
    });
    rx.recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or(false)
}

fn try_keyring_load(session_id: &str) -> Option<String> {
    let account = sanitize_for_keyring(session_id);
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let result = keyring::Entry::new(KEYRING_SERVICE, &account)
            .ok()
            .and_then(|e| e.get_password().ok());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Some(json)) => Some(json),
        _ => None,
    }
}

/// Synchronously delete the keyring entry for `session_id`, bounded by a
/// 2-second timeout (same pattern as try_keyring_save/load so a hung
/// keychain doesn't freeze the CLI). Returns true if the entry was
/// successfully removed OR was already absent. Returns false on timeout
/// or a real error — callers rely on this signal so `clear_session` can
/// surface the failure instead of claiming success while a stale entry
/// remains (codex PR #24 v8 P1).
fn try_keyring_delete(session_id: &str) -> bool {
    let account = sanitize_for_keyring(session_id);
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        let result = match keyring::Entry::new(KEYRING_SERVICE, &account) {
            Ok(entry) => match entry.delete_password() {
                Ok(()) => true,
                // A missing entry is not a failure — the intent is
                // "nothing of this name should remain".
                Err(keyring::Error::NoEntry) => true,
                Err(_) => false,
            },
            Err(_) => false,
        };
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_types::{Session, WalletAddress};

    fn make_session(token: &str, wallet: &str) -> Session {
        Session {
            token: token.to_string(),
            wallet: WalletAddress(wallet.to_string()),
            scope: None,
            created_at: 0,
            ttl_seconds: 86400,
        }
    }

    /// Build a `SessionStore` rooted at a fresh tempdir with keyring
    /// disabled. Returns the store together with the tempdir so the
    /// caller can keep it alive for the lifetime of the test — dropping
    /// the tempdir would wipe the session state mid-assertion.
    ///
    /// Replaces the previous `with_temp_home` helper which mutated
    /// process-global `$HOME` / `AGENTKEYS_SESSION_STORE` under a mutex.
    /// Tests are now fully hermetic and can run in parallel without a
    /// shared lock.
    fn test_store() -> (SessionStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::file_only(tmp.path().to_path_buf());
        (store, tmp)
    }

    #[test]
    fn save_load_session_roundtrip_master() {
        let (store, _tmp) = test_store();
        let session = make_session("tok-master", "0xMASTER");
        store.save(&session, "master").expect("save");
        let loaded = store.load("master").expect("load");
        assert_eq!(loaded.token, "tok-master");
        assert_eq!(loaded.wallet.0, "0xMASTER");
    }

    #[test]
    fn save_load_session_roundtrip_daemon_wallet() {
        let (store, _tmp) = test_store();
        let session = make_session("tok-daemon", "0xABC");
        store.save(&session, "daemon-0xABC").expect("save");
        let loaded = store.load("daemon-0xABC").expect("load");
        assert_eq!(loaded.token, "tok-daemon");
        assert_eq!(loaded.wallet.0, "0xABC");
    }

    #[test]
    fn two_daemons_do_not_collide() {
        let (store, _tmp) = test_store();
        let sess_a = make_session("tok-a", "0xA");
        let sess_b = make_session("tok-b", "0xB");
        store.save(&sess_a, "daemon-A").expect("save A");
        store.save(&sess_b, "daemon-B").expect("save B");

        let loaded_a = store.load("daemon-A").expect("load A");
        let loaded_b = store.load("daemon-B").expect("load B");
        assert_eq!(loaded_a.token, "tok-a");
        assert_eq!(loaded_b.token, "tok-b");
        assert_ne!(loaded_a.token, loaded_b.token);
    }

    #[test]
    fn clear_session_removes_entry_only_for_that_id() {
        let (store, _tmp) = test_store();
        let sess_master = make_session("tok-master", "0xMASTER");
        let sess_daemon = make_session("tok-daemon", "0xDAEMON");
        store.save(&sess_master, "master").expect("save master");
        store
            .save(&sess_daemon, "daemon-0xDAEMON")
            .expect("save daemon");

        store.clear("daemon-0xDAEMON").expect("clear daemon");

        let loaded = store.load("master").expect("load master after clear");
        assert_eq!(loaded.token, "tok-master");

        assert!(store.load("daemon-0xDAEMON").is_err());
    }

    // Codex PR #24 P1 — list_ids must sort deterministically.
    #[test]
    fn list_ids_is_sorted() {
        let (store, _tmp) = test_store();
        // Insert in non-alphabetical order; enumerate must still return sorted.
        store
            .save(&make_session("t1", "0xZ"), "daemon-0xZZZ")
            .expect("save Z");
        store
            .save(&make_session("t2", "0xA"), "daemon-0xAAA")
            .expect("save A");
        store
            .save(&make_session("t3", "0xM"), "daemon-0xMMM")
            .expect("save M");

        let ids = store.list_ids("daemon-");
        assert_eq!(
            ids,
            vec![
                "daemon-0xAAA".to_string(),
                "daemon-0xMMM".to_string(),
                "daemon-0xZZZ".to_string(),
            ],
            "daemon session ids must be sorted alphabetically"
        );
    }

    // Codex PR #24 P1 — keyring account name must be sanitized for
    // cross-platform safety (Windows null-byte rejection, Linux non-UTF8).
    #[test]
    fn sanitize_for_keyring_preserves_ascii_alnum_and_safe_punctuation() {
        assert_eq!(sanitize_for_keyring("daemon-0xABC"), "daemon-0xABC");
        assert_eq!(sanitize_for_keyring("master"), "master");
        assert_eq!(sanitize_for_keyring("a_b.c-d"), "a_b.c-d");
    }

    #[test]
    fn sanitize_for_keyring_replaces_unsafe_chars_and_appends_hash() {
        let a = sanitize_for_keyring("name/with\\slashes");
        let b = sanitize_for_keyring("name_with_slashes");
        assert_ne!(
            a, b,
            "inputs differing only in unsafe chars must not collide"
        );

        let with_null = sanitize_for_keyring("alias\0null");
        assert!(!with_null.contains('\0'), "null bytes must be stripped");
        assert!(
            with_null.starts_with("__agk_alias_null-"),
            "got: {with_null}"
        );
    }

    // Codex PR #24 v3 P2 — hash must be stable across Rust/toolchain
    // upgrades. SHA-256 of "foo/bar" (first 4 bytes, hex-lower) is
    // `cc5d46bd`. If this test ever fails after a dep upgrade, we lost
    // persistence stability and any sanitized session_id would become
    // unreachable.
    #[test]
    fn sanitize_for_keyring_uses_stable_sha256_suffix() {
        assert_eq!(sanitize_for_keyring("foo/bar"), "__agk_foo_bar-cc5d46bd");
    }

    // Codex PR #24 v6 P1 — reserved path components (".", "..", "") must
    // never be returned as-is; they'd escape ~/.agentkeys or alias the
    // legacy root file. Force-rewrite moves them under the __agk_ namespace.
    #[test]
    fn sanitize_for_keyring_rejects_reserved_path_components() {
        let dot = sanitize_for_keyring(".");
        let dotdot = sanitize_for_keyring("..");
        let empty = sanitize_for_keyring("");
        assert!(dot.starts_with("__agk_"), "got: {dot}");
        assert!(dotdot.starts_with("__agk_"), "got: {dotdot}");
        assert!(empty.starts_with("__agk_"), "got: {empty}");
        // Distinct outputs — each reserved value must not alias another.
        assert_ne!(dot, dotdot);
        assert_ne!(dot, empty);
        assert_ne!(dotdot, empty);
    }

    // Codex PR #24 v6 P2 — user-supplied ids starting with the reserved
    // rewrite prefix must be pushed through the rewrite path again, so
    // they can't collide with the deterministic output of a rewritten
    // input.
    #[test]
    fn sanitize_for_keyring_rewrites_prefix_collisions() {
        let from_unsafe = sanitize_for_keyring("foo/bar");
        assert_eq!(from_unsafe, "__agk_foo_bar-cc5d46bd");

        // User picks the exact rewritten form as their session_id.
        let from_mimic = sanitize_for_keyring("__agk_foo_bar-cc5d46bd");
        assert_ne!(
            from_unsafe, from_mimic,
            "user-supplied id starting with rewrite prefix must not alias the rewrite output"
        );
        assert!(
            from_mimic.starts_with("__agk___agk_"),
            "expected nested rewrite, got: {from_mimic}"
        );
    }

    #[test]
    fn sanitize_for_keyring_truncates_oversized_input() {
        let long = "a".repeat(500);
        let sanitized = sanitize_for_keyring(&long);
        assert!(sanitized.len() <= 128, "got len {}", sanitized.len());
        // Two different long inputs with different hashes should not collide.
        let long_b = format!("{}b", "a".repeat(499));
        let sanitized_b = sanitize_for_keyring(&long_b);
        assert_ne!(
            sanitized, sanitized_b,
            "long distinct inputs must not collide"
        );
    }

    // Codex PR #24 P2 — keyring save must never overwrite the real file
    // fallback's session.json. The marker file is a separate `.keyring_managed`.
    // This test runs in file-only mode (no keyring), so we verify directly:
    // save writes session.json (not the marker), and toggling back to
    // keyring mode (if it were active) would write the marker without
    // touching session.json.
    #[test]
    fn file_mode_save_writes_session_json_not_marker() {
        let (store, tmp) = test_store();
        store
            .save(&make_session("t", "0xW"), "daemon-0xWWW")
            .expect("save");
        let sess = tmp
            .path()
            .join(AGENTKEYS_DIR)
            .join("daemon-0xWWW")
            .join(SESSION_FILE);
        let marker = tmp
            .path()
            .join(AGENTKEYS_DIR)
            .join("daemon-0xWWW")
            .join(KEYRING_MARKER_FILE);
        assert!(sess.exists(), "session.json must exist in file mode");
        assert!(
            !marker.exists(),
            "file-mode save must not write the keyring marker"
        );
    }

    // Codex PR #24 v2 P2 — path traversal via user-supplied session_id.
    // A session_id of `../escape` or `foo/bar` must NOT write outside
    // ~/.agentkeys/. Sanitization folds these to a safe directory name.
    #[test]
    fn save_session_does_not_escape_agentkeys_dir_on_path_traversal() {
        let (store, tmp) = test_store();
        let session = make_session("t", "0xP");
        // Attempt to escape via relative traversal.
        store
            .save(&session, "../escape")
            .expect("save should succeed (sanitized)");
        // Verify NO file was written outside the tempdir's .agentkeys/.
        let parent = tmp.path().parent().expect("tmp has a parent");
        let escape_candidates = [
            parent.join("escape"),
            tmp.path().join("escape"),
            tmp.path().join("..").join("escape"),
        ];
        for bad in &escape_candidates {
            assert!(
                !bad.exists(),
                "path traversal wrote outside ~/.agentkeys: {}",
                bad.display()
            );
        }
        // Verify the actual write landed inside .agentkeys/ under a
        // sanitized directory name (contains the 8-char hash suffix).
        let root = tmp.path().join(AGENTKEYS_DIR);
        let any_inside = std::fs::read_dir(&root)
            .expect("read agentkeys root")
            .filter_map(Result::ok)
            .any(|e| e.path().join(SESSION_FILE).exists());
        assert!(
            any_inside,
            "sanitized directory with session.json must exist inside ~/.agentkeys"
        );
    }

    #[test]
    fn save_session_rejects_forward_slash_in_session_id() {
        let (store, tmp) = test_store();
        store
            .save(&make_session("t", "0xS"), "foo/bar")
            .expect("save");
        // The separator must be normalised, so no subdir named "bar"
        // under an intermediate "foo" dir.
        let unwanted = tmp.path().join(AGENTKEYS_DIR).join("foo").join("bar");
        assert!(
            !unwanted.exists(),
            "forward-slash session_id created nested directory: {}",
            unwanted.display()
        );
    }

    // Codex PR #24 v8 P1 — clear must be synchronous.
    // In file-only mode the keyring path is skipped entirely, so clear
    // must succeed and wipe the file immediately. After it returns, load
    // must not succeed.
    #[test]
    fn clear_session_is_synchronous_in_file_mode() {
        let (store, _tmp) = test_store();
        store
            .save(&make_session("t", "0xC"), "daemon-0xCCC")
            .expect("save");
        assert!(
            store.load("daemon-0xCCC").is_ok(),
            "session loadable before clear"
        );

        store.clear("daemon-0xCCC").expect("clear");

        // Immediately (no sleep) — the deletion must have happened
        // synchronously inside clear, not in a detached thread.
        assert!(
            store.load("daemon-0xCCC").is_err(),
            "session still loadable after clear returned"
        );
    }

    // Verifies list_ids discovers both a real session.json entry AND a
    // marker-only entry (would-be keyring-managed in prod).
    #[test]
    fn list_ids_finds_marker_only_directories() {
        let (store, tmp) = test_store();
        store
            .save(&make_session("t1", "0xF"), "daemon-0xFFF")
            .expect("save file");

        // Simulate a keyring-managed session: directory with only the marker.
        let dir = tmp.path().join(AGENTKEYS_DIR).join("daemon-0xKEY");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::File::create(dir.join(KEYRING_MARKER_FILE)).unwrap();

        let ids = store.list_ids("daemon-");
        assert!(ids.contains(&"daemon-0xFFF".to_string()));
        assert!(
            ids.contains(&"daemon-0xKEY".to_string()),
            "marker-only entries must be discoverable, got: {ids:?}"
        );
    }
}
