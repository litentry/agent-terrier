use std::fs;
use std::path::PathBuf;

use agentkeys_types::{Session, WalletAddress};
use anyhow::Context;

pub fn session_dir() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME env var not set")?;
    let dir = PathBuf::from(home).join(".agentkeys");
    fs::create_dir_all(&dir).context("create ~/.agentkeys")?;
    Ok(dir)
}

pub fn session_file_path() -> anyhow::Result<PathBuf> {
    Ok(session_dir()?.join("session"))
}

pub fn write_session_file(token: &str) -> anyhow::Result<()> {
    let path = session_file_path()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        use std::io::Write;
        let mut file = opts.open(&path).context("open session file")?;
        file.write_all(token.as_bytes()).context("write session file")?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&path, token).context("write session file")?;
    }

    Ok(())
}

pub fn read_session_file() -> anyhow::Result<String> {
    let path = session_file_path()?;
    let token = fs::read_to_string(&path).context("read session file")?;
    Ok(token.trim().to_string())
}

pub fn build_session_from_token(token: String) -> Session {
    Session {
        token,
        wallet: WalletAddress("local".into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    }
}
