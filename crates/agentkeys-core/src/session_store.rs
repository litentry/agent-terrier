use agentkeys_types::Session;
use anyhow::{Context, Result};
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "agentkeys";

/// Marker file written alongside (but NOT overwriting) the session.json in a
/// session's fallback directory whenever the real credential lives in the OS
/// keyring instead of the file. Kept distinct from session.json so that
/// switching between keyring and file modes does not destroy the real
/// file-mode credential (codex PR #24 P2).
const KEYRING_MARKER_FILE: &str = ".keyring_managed";

pub fn fallback_path(session_id: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    // Route through sanitize_for_keyring so session_ids containing path
    // separators, '..', or null bytes can't escape ~/.agentkeys (codex PR
    // #24 v2 P2 — path traversal via --session-id).
    PathBuf::from(home)
        .join(".agentkeys")
        .join(sanitize_for_keyring(session_id))
        .join("session.json")
}

fn marker_path(session_id: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".agentkeys")
        .join(sanitize_for_keyring(session_id))
        .join(KEYRING_MARKER_FILE)
}

/// Reserved prefix for rewritten session_ids. User-supplied inputs that
/// start with this prefix are also forced through the rewrite path so
/// collisions between rewrites and raw names are impossible (codex PR
/// #24 v6 P2). The prefix uses only characters in the safe alphabet
/// (`_`, ascii-alpha) so that the output remains valid as both a keyring
/// account and a filesystem directory name on Windows / Linux / macOS.
const REWRITE_PREFIX: &str = "__agk_";

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
    let accepts_as_is =
        safe == s && safe.len() <= MAX && !is_reserved && !starts_with_prefix;

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

/// Returns true if keyring should be skipped (tests, CI, headless).
/// Set AGENTKEYS_SESSION_STORE=file to force file-only mode.
fn should_skip_keyring() -> bool {
    std::env::var("AGENTKEYS_SESSION_STORE")
        .map(|v| v == "file")
        .unwrap_or(false)
}

/// Save session under session_id. Tries keyring first (non-blocking, 2s timeout),
/// falls back to ~/.agentkeys/<session_id>/session.json (mode 0600).
/// Set AGENTKEYS_SESSION_STORE=file to skip keyring entirely.
///
/// On a successful keyring save, also drops an empty `.keyring_managed`
/// marker file in ~/.agentkeys/<session_id>/ so `list_fallback_session_ids`
/// can discover keyring-stored sessions (OS keychain APIs don't expose a
/// prefix-scan without per-entry permission prompts). The marker is NEVER
/// written over an existing session.json, so toggling between keyring and
/// file modes doesn't destroy the real fallback (codex PR #24 P2).
pub fn save_session(session: &Session, session_id: &str) -> Result<()> {
    let json = serde_json::to_string(session).context("serialize session")?;

    if !should_skip_keyring() {
        if try_keyring_save(&json, session_id) {
            // Marker file is best-effort: it's only required for
            // prefix-scan discovery (daemon-restart path). Direct-load
            // callers like `master` look up by known id, so a missing
            // marker doesn't break them. If the marker can't land
            // (read-only HOME, missing filesystem), the keyring entry
            // is still the authoritative store — emit a diagnostic on
            // stderr and return Ok (codex PR #24 v4 P2).
            let marker = marker_path(session_id);
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
    }

    save_to_file(&json, session_id)
}

/// Load session for session_id. Tries keyring first (non-blocking, 2s timeout),
/// falls back to file.
pub fn load_session(session_id: &str) -> Result<Session> {
    if !should_skip_keyring() {
        if let Some(json) = try_keyring_load(session_id) {
            return serde_json::from_str(&json).context("deserialize session from keyring");
        }
    }
    load_from_file(session_id)
}

/// Enumerate session IDs that have a persisted session under `~/.agentkeys/`.
/// Looks for either a real `session.json` (file mode) or the
/// `.keyring_managed` marker (keyring mode) in each candidate directory.
/// Results are sorted alphabetically so daemon startup is deterministic
/// across runs (codex PR #24 P1 — nondeterministic daemon selection).
///
/// Keyring-only entries without a marker are NOT enumerated — we rely on
/// the marker file as the discovery signal because most OS keychain APIs
/// don't support prefix-scan without per-entry permission prompts.
pub fn list_fallback_session_ids(prefix: &str) -> Vec<String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let root = PathBuf::from(home).join(".agentkeys");
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
        if dir.join("session.json").exists() || dir.join(KEYRING_MARKER_FILE).exists() {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// Load a session with legacy-location fallback. Used by the master CLI
/// (session_id = "master") after #12 namespacing — old installs have the
/// session stored under keyring account=`session` or file
/// `~/.agentkeys/session.json`. Try the new location first, then fall
/// back to the legacy locations so existing users stay logged in across
/// the upgrade.
pub fn load_session_with_legacy_fallback(session_id: &str) -> Result<Session> {
    if let Ok(s) = load_session(session_id) {
        return Ok(s);
    }
    if session_id == "master" {
        // Legacy keyring account: "session"
        if !should_skip_keyring() {
            if let Some(json) = try_keyring_load("session") {
                return serde_json::from_str(&json)
                    .context("deserialize legacy session from keyring");
            }
        }
        // Legacy file: ~/.agentkeys/session.json
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let legacy = PathBuf::from(home).join(".agentkeys").join("session.json");
        if let Ok(json) = std::fs::read_to_string(&legacy) {
            return serde_json::from_str(&json)
                .context("deserialize legacy session from file");
        }
    }
    load_session(session_id)
}

/// Remove session entry for session_id only (does not affect other ids).
/// Blocks on the keyring delete (up to 2 seconds) so callers know the
/// credential is actually gone before clear_session returns. Previously
/// fire-and-forget, which let `cmd_revoke` report success while the
/// keyring entry was still live — next command would load the stale
/// session (codex PR #24 v8 P1).
pub fn clear_session(session_id: &str) -> Result<()> {
    if !should_skip_keyring() {
        let deleted = try_keyring_delete(session_id);
        if !deleted {
            return Err(anyhow::anyhow!(
                "keyring delete failed or timed out for session_id={session_id}; local session may still be loadable on next command"
            ));
        }
    }
    let path = fallback_path(session_id);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove session file {}", path.display()))?;
    }
    let marker = marker_path(session_id);
    if marker.exists() {
        let _ = std::fs::remove_file(&marker);
    }
    Ok(())
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

fn save_to_file(json: &str, session_id: &str) -> Result<()> {
    let path = fallback_path(session_id);
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

fn load_from_file(session_id: &str) -> Result<Session> {
    let path = fallback_path(session_id);
    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("read session file at {}", path.display()))?;
    serde_json::from_str(&json).context("deserialize session from file")
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

    /// Run a closure with AGENTKEYS_SESSION_STORE=file and HOME pointing at a unique tempdir.
    /// Uses a mutex to prevent concurrent tests from clobbering the shared process environment.
    fn with_temp_home<F: FnOnce(&std::path::Path)>(f: F) {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().expect("env lock");
        let tmp = tempfile::tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("AGENTKEYS_SESSION_STORE", "file");
            std::env::set_var("HOME", tmp.path().to_str().unwrap());
        }
        f(tmp.path());
        unsafe {
            std::env::remove_var("AGENTKEYS_SESSION_STORE");
        }
        drop(tmp);
    }

    #[test]
    fn save_load_session_roundtrip_master() {
        with_temp_home(|_| {
            let session = make_session("tok-master", "0xMASTER");
            save_session(&session, "master").expect("save");
            let loaded = load_session("master").expect("load");
            assert_eq!(loaded.token, "tok-master");
            assert_eq!(loaded.wallet.0, "0xMASTER");
        });
    }

    #[test]
    fn save_load_session_roundtrip_daemon_wallet() {
        with_temp_home(|_| {
            let session = make_session("tok-daemon", "0xABC");
            save_session(&session, "daemon-0xABC").expect("save");
            let loaded = load_session("daemon-0xABC").expect("load");
            assert_eq!(loaded.token, "tok-daemon");
            assert_eq!(loaded.wallet.0, "0xABC");
        });
    }

    #[test]
    fn two_daemons_do_not_collide() {
        with_temp_home(|_| {
            let sess_a = make_session("tok-a", "0xA");
            let sess_b = make_session("tok-b", "0xB");
            save_session(&sess_a, "daemon-A").expect("save A");
            save_session(&sess_b, "daemon-B").expect("save B");

            let loaded_a = load_session("daemon-A").expect("load A");
            let loaded_b = load_session("daemon-B").expect("load B");
            assert_eq!(loaded_a.token, "tok-a");
            assert_eq!(loaded_b.token, "tok-b");
            assert_ne!(loaded_a.token, loaded_b.token);
        });
    }

    #[test]
    fn clear_session_removes_entry_only_for_that_id() {
        with_temp_home(|_| {
            let sess_master = make_session("tok-master", "0xMASTER");
            let sess_daemon = make_session("tok-daemon", "0xDAEMON");
            save_session(&sess_master, "master").expect("save master");
            save_session(&sess_daemon, "daemon-0xDAEMON").expect("save daemon");

            clear_session("daemon-0xDAEMON").expect("clear daemon");

            let loaded = load_session("master").expect("load master after clear");
            assert_eq!(loaded.token, "tok-master");

            assert!(load_session("daemon-0xDAEMON").is_err());
        });
    }

    // Codex PR #24 P1 — list_fallback_session_ids must sort deterministically.
    #[test]
    fn list_fallback_session_ids_is_sorted() {
        with_temp_home(|_| {
            // Insert in non-alphabetical order; enumerate must still return sorted.
            save_session(&make_session("t1", "0xZ"), "daemon-0xZZZ").expect("save Z");
            save_session(&make_session("t2", "0xA"), "daemon-0xAAA").expect("save A");
            save_session(&make_session("t3", "0xM"), "daemon-0xMMM").expect("save M");

            let ids = list_fallback_session_ids("daemon-");
            assert_eq!(
                ids,
                vec![
                    "daemon-0xAAA".to_string(),
                    "daemon-0xMMM".to_string(),
                    "daemon-0xZZZ".to_string(),
                ],
                "daemon session ids must be sorted alphabetically"
            );
        });
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
        assert_ne!(a, b, "inputs differing only in unsafe chars must not collide");

        let with_null = sanitize_for_keyring("alias\0null");
        assert!(!with_null.contains('\0'), "null bytes must be stripped");
        assert!(with_null.starts_with("__agk_alias_null-"), "got: {with_null}");
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
        assert_ne!(sanitized, sanitized_b, "long distinct inputs must not collide");
    }

    // Codex PR #24 P2 — keyring save must never overwrite the real file
    // fallback's session.json. The marker file is a separate `.keyring_managed`.
    // This test runs in AGENTKEYS_SESSION_STORE=file mode (no keyring), so
    // we verify directly: save writes session.json (not the marker), and
    // toggling back to keyring mode (if it were active) would write the
    // marker without touching session.json.
    #[test]
    fn file_mode_save_writes_session_json_not_marker() {
        with_temp_home(|tmp| {
            save_session(&make_session("t", "0xW"), "daemon-0xWWW").expect("save");
            let sess = tmp.join(".agentkeys").join("daemon-0xWWW").join("session.json");
            let marker = tmp.join(".agentkeys").join("daemon-0xWWW").join(".keyring_managed");
            assert!(sess.exists(), "session.json must exist in file mode");
            assert!(
                !marker.exists(),
                "file-mode save must not write the keyring marker"
            );
        });
    }

    // Codex PR #24 v2 P2 — path traversal via user-supplied session_id.
    // A session_id of `../escape` or `foo/bar` must NOT write outside
    // ~/.agentkeys/. Sanitization folds these to a safe directory name.
    #[test]
    fn save_session_does_not_escape_agentkeys_dir_on_path_traversal() {
        with_temp_home(|tmp| {
            let session = make_session("t", "0xP");
            // Attempt to escape via relative traversal.
            save_session(&session, "../escape").expect("save should succeed (sanitized)");
            // Verify NO file was written outside ~/.agentkeys/.
            let parent = tmp.parent().expect("tmp has a parent");
            let escape_candidates = [
                parent.join("escape"),
                tmp.join("escape"),
                tmp.join("..").join("escape"),
            ];
            for bad in &escape_candidates {
                assert!(
                    !bad.exists(),
                    "path traversal wrote outside ~/.agentkeys: {}",
                    bad.display()
                );
            }
            // Verify the actual write landed inside ~/.agentkeys/ under a
            // sanitized directory name (contains the 8-char hash suffix).
            let root = tmp.join(".agentkeys");
            let any_inside = std::fs::read_dir(&root)
                .expect("read agentkeys root")
                .filter_map(Result::ok)
                .any(|e| e.path().join("session.json").exists());
            assert!(any_inside, "sanitized directory with session.json must exist inside ~/.agentkeys");
        });
    }

    #[test]
    fn save_session_rejects_forward_slash_in_session_id() {
        with_temp_home(|tmp| {
            save_session(&make_session("t", "0xS"), "foo/bar").expect("save");
            // The separator must be normalised, so no subdir named "bar"
            // under an intermediate "foo" dir.
            let unwanted = tmp.join(".agentkeys").join("foo").join("bar");
            assert!(
                !unwanted.exists(),
                "forward-slash session_id created nested directory: {}",
                unwanted.display()
            );
        });
    }

    // Codex PR #24 v8 P1 — clear_session must be synchronous.
    // In file-mode (AGENTKEYS_SESSION_STORE=file) the keyring path is
    // skipped entirely, so clear_session must succeed and wipe the file
    // immediately. After it returns, load_session must not succeed.
    #[test]
    fn clear_session_is_synchronous_in_file_mode() {
        with_temp_home(|_| {
            save_session(&make_session("t", "0xC"), "daemon-0xCCC").expect("save");
            assert!(load_session("daemon-0xCCC").is_ok(), "session loadable before clear");

            clear_session("daemon-0xCCC").expect("clear");

            // Immediately (no sleep) — the deletion must have happened
            // synchronously inside clear_session, not in a detached thread.
            assert!(
                load_session("daemon-0xCCC").is_err(),
                "session still loadable after clear_session returned"
            );
        });
    }

    // Verifies list_fallback_session_ids discovers both a real session.json
    // entry AND a marker-only entry (would-be keyring-managed in prod).
    #[test]
    fn list_fallback_session_ids_finds_marker_only_directories() {
        with_temp_home(|tmp| {
            save_session(&make_session("t1", "0xF"), "daemon-0xFFF").expect("save file");

            // Simulate a keyring-managed session: directory with only the marker.
            let dir = tmp.join(".agentkeys").join("daemon-0xKEY");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::File::create(dir.join(".keyring_managed")).unwrap();

            let ids = list_fallback_session_ids("daemon-");
            assert!(ids.contains(&"daemon-0xFFF".to_string()));
            assert!(
                ids.contains(&"daemon-0xKEY".to_string()),
                "marker-only entries must be discoverable, got: {ids:?}"
            );
        });
    }
}
