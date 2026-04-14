use agentkeys_types::Session;
use anyhow::{Context, Result};
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "agentkeys";
const KEYRING_USER: &str = "session";

pub fn fallback_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let mut path = PathBuf::from(home);
    path.push(".agentkeys");
    path.push("session.json");
    path
}

/// Returns true if keyring should be skipped (tests, CI, headless).
/// Set AGENTKEYS_SESSION_STORE=file to force file-only mode.
fn should_skip_keyring() -> bool {
    std::env::var("AGENTKEYS_SESSION_STORE")
        .map(|v| v == "file")
        .unwrap_or(false)
}

/// Save session. Tries keyring first (non-blocking attempt), falls back to ~/.agentkeys/session.json.
/// Set AGENTKEYS_SESSION_STORE=file to skip keyring entirely (for tests/CI).
pub fn save_session(session: &Session) -> Result<()> {
    let json = serde_json::to_string(session).context("serialize session")?;

    if !should_skip_keyring() {
        if try_keyring_save(&json) {
            return Ok(());
        }
    }

    save_to_file(&json)
}

/// Load session. Tries keyring first (non-blocking), falls back to file.
/// Set AGENTKEYS_SESSION_STORE=file to skip keyring entirely (for tests/CI).
pub fn load_session() -> Result<Session> {
    if !should_skip_keyring() {
        if let Some(json) = try_keyring_load() {
            return serde_json::from_str(&json).context("deserialize session from keyring");
        }
    }
    load_from_file()
}

/// Attempt keyring save with a 2-second timeout. Returns true if successful.
fn try_keyring_save(json: &str) -> bool {
    let json_owned = json.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .and_then(|e| e.set_password(&json_owned));
        let _ = tx.send(result.is_ok());
    });
    rx.recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or(false)
}

/// Attempt keyring load with a 2-second timeout. Returns Some(json) if successful.
fn try_keyring_load() -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let result = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .ok()
            .and_then(|e| e.get_password().ok());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Some(json)) => Some(json),
        _ => None,
    }
}

fn save_to_file(json: &str) -> Result<()> {
    let path = fallback_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create ~/.agentkeys dir")?;
    }
    std::fs::write(&path, json).context("write session file")?;
    Ok(())
}

fn load_from_file() -> Result<Session> {
    let path = fallback_path();
    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("read session file at {}", path.display()))?;
    serde_json::from_str(&json).context("deserialize session from file")
}

/// Delete the locally stored session from both keyring and file.
/// Best-effort: ignores "not found" errors. Returns Err only if both
/// attempts failed with non-NotFound errors.
///
/// When `AGENTKEYS_SESSION_STORE=file` is set, the keyring branch is skipped
/// entirely (no 2-second timeout, no chance of spurious keyring errors).
pub fn clear_session() -> Result<()> {
    let keyring_result = if should_skip_keyring() {
        Ok(())
    } else {
        try_keyring_delete()
    };
    let file_result = delete_session_file();

    match (keyring_result, file_result) {
        (Err(ke), Err(fe)) => {
            Err(anyhow::anyhow!("could not clear session: keyring: {}; file: {}", ke, fe))
        }
        _ => Ok(()),
    }
}

fn try_keyring_delete() -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<()>>();
    std::thread::spawn(move || {
        let result = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|e| anyhow::anyhow!("{}", e))
            .and_then(|e| e.delete_password().map_err(|ke| anyhow::anyhow!("{}", ke)));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("not found") || msg.contains("no such") || msg.contains("no password") {
                Ok(())
            } else {
                Err(e)
            }
        }
        Err(_) => Ok(()),
    }
}

fn delete_session_file() -> Result<()> {
    let path = fallback_path();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("remove {}: {}", path.display(), e)),
    }
}

