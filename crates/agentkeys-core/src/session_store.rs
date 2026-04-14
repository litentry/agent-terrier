use agentkeys_types::Session;
use anyhow::{Context, Result};
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "agentkeys";

fn fallback_path(session_id: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".agentkeys")
        .join(session_id)
        .join("session.json")
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
pub fn save_session(session: &Session, session_id: &str) -> Result<()> {
    let json = serde_json::to_string(session).context("serialize session")?;

    if !should_skip_keyring() {
        if try_keyring_save(&json, session_id) {
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

/// Enumerate session IDs that have a persisted fallback file under
/// `~/.agentkeys/`. Useful for the daemon's default-startup path, which
/// needs to find a previously-paired `daemon-<wallet>` session without
/// knowing the wallet up front.
///
/// Returns IDs in filesystem order (unsorted). Keyring-only entries are
/// NOT enumerated (most OS keychain APIs don't support prefix-scan without
/// a wallet-wide permission prompt); this function only inspects the file
/// fallback directory, which is sufficient for the current use case.
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
        if name.starts_with(prefix) && entry.path().join("session.json").exists() {
            out.push(name);
        }
    }
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
pub fn clear_session(session_id: &str) -> Result<()> {
    if !should_skip_keyring() {
        try_keyring_delete(session_id);
    }
    let path = fallback_path(session_id);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove session file {}", path.display()))?;
    }
    Ok(())
}

fn try_keyring_save(json: &str, session_id: &str) -> bool {
    let json_owned = json.to_string();
    let account = session_id.to_string();
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
    let account = session_id.to_string();
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

fn try_keyring_delete(session_id: &str) {
    let account = session_id.to_string();
    std::thread::spawn(move || {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &account) {
            let _ = entry.delete_password();
        }
    });
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
}
