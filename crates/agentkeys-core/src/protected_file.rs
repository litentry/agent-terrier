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

pub fn read_token(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let contents = read_text(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("credential path must be UTF-8"))?,
    )?;
    let token = contents.trim();
    ensure!(
        !token.is_empty()
            && !token
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
        "credential file must contain one nonempty token"
    );
    Ok(Zeroizing::new(token.to_owned()))
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

/// Caller serializes writers. An error after rename requires fail-closed recovery.
#[cfg(unix)]
pub fn replace_atomic(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    use std::ffi::CString;
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    };

    ensure!(
        contents.len() as u64 <= MAX_SECRET_FILE_BYTES,
        "secret file exceeds size limit"
    );
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let filename = CString::new(
        path.file_name()
            .ok_or_else(|| anyhow::anyhow!("secret path needs a filename"))?
            .as_bytes(),
    )?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o022 == 0,
        "secret directory must be owned by this user and not writable by group or others"
    );
    let directory_fd = directory.as_raw_fd();
    let existing_fd = unsafe {
        libc::openat(
            directory_fd,
            filename.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if existing_fd >= 0 {
        let existing = unsafe { File::from_raw_fd(existing_fd) };
        validate(&existing)?;
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    let random: [u8; 16] = rand::random();
    let temporary = CString::new(format!(".agent-terrier-{}.tmp", hex::encode(random)))?;
    let temporary_fd = unsafe {
        libc::openat(
            directory_fd,
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        temporary_fd >= 0,
        "could not create private temporary file: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(temporary_fd) };
    let result = (|| -> Result<()> {
        validate(&file)?;
        file.write_all(contents)?;
        file.sync_all()?;
        let renamed = unsafe {
            libc::renameat(
                directory_fd,
                temporary.as_ptr(),
                directory_fd,
                filename.as_ptr(),
            )
        };
        ensure!(
            renamed == 0,
            "could not replace secret file: {}",
            std::io::Error::last_os_error()
        );
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory_fd, temporary.as_ptr(), 0);
        }
    }
    result
}

#[cfg(not(unix))]
pub fn replace_atomic(_path: &std::path::Path, _contents: &[u8]) -> Result<()> {
    anyhow::bail!("secret storage requires Unix file permissions")
}
