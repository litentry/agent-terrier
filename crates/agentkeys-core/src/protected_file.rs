use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

use anyhow::{ensure, Result};
use zeroize::Zeroizing;

pub const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

#[cfg(unix)]
fn validate(file: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "secret must be a regular file");
    ensure!(
        metadata.permissions().mode() & 0o077 == 0
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() },
        "secret must be owner-only, owned by this user and have no hard links"
    );
    Ok(())
}

#[cfg(not(unix))]
fn validate(_file: &File) -> Result<()> {
    anyhow::bail!("secret storage requires Unix file permissions")
}

fn options() -> Result<OpenOptions> {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    anyhow::bail!("secret storage requires Unix file permissions");
    Ok(options)
}

pub fn open_read(path: &str) -> Result<File> {
    let file = options()?.read(true).open(path)?;
    validate(&file)?;
    Ok(file)
}

pub fn read_text(path: &str) -> Result<Zeroizing<String>> {
    let file = open_read(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_SECRET_FILE_BYTES,
        "secret file exceeds size limit"
    );
    let mut contents = Zeroizing::new(String::new());
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_string(&mut contents)?;
    ensure!(
        contents.len() as u64 <= MAX_SECRET_FILE_BYTES,
        "secret file exceeds size limit"
    );
    Ok(contents)
}

pub fn write(path: &str, contents: &[u8], create_new: bool) -> Result<()> {
    ensure!(
        contents.len() as u64 <= MAX_SECRET_FILE_BYTES,
        "secret file exceeds size limit"
    );
    let mut options = options()?;
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    let mut file = options.open(path)?;
    validate(&file)?;
    file.set_len(0)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}
