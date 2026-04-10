use agentkeys_types::Session;
use anyhow::{Context, Result};
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "agentkeys";
const KEYRING_USER: &str = "session";

fn fallback_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let mut path = PathBuf::from(home);
    path.push(".agentkeys");
    path.push("session.json");
    path
}

/// Save session. Tries keyring first (non-blocking attempt), falls back to ~/.agentkeys/session.json.
/// On platforms where keyring blocks (headless macOS, CI), falls back immediately.
pub fn save_session(session: &Session) -> Result<()> {
    let json = serde_json::to_string(session).context("serialize session")?;

    // Try keyring with a thread-based timeout to avoid blocking indefinitely.
    if try_keyring_save(&json) {
        return Ok(());
    }

    save_to_file(&json)
}

/// Load session. Tries keyring first (non-blocking), falls back to file.
pub fn load_session() -> Result<Session> {
    if let Some(json) = try_keyring_load() {
        return serde_json::from_str(&json).context("deserialize session from keyring");
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
