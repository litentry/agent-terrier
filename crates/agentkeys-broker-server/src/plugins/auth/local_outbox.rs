use std::path::{Path, PathBuf};

use agentkeys_core::protected_file;
use async_trait::async_trait;
use serde::Serialize;
use zeroize::Zeroizing;

use super::{EmailSendError, EmailSender};

const MAX_OUTBOX_FILES: usize = 1024;
const MAX_RECIPIENT_BYTES: usize = 320;
const MAX_LINK_BYTES: usize = 4096;
const READINESS_FILE: &str = ".readiness.json";

pub struct LocalEmailOutbox {
    directory: PathBuf,
    writer: std::sync::Mutex<()>,
}

impl LocalEmailOutbox {
    pub fn from_configuration(
        development_only: bool,
        backend: Option<&str>,
        directory: Option<&str>,
    ) -> Result<Self, EmailSendError> {
        if !development_only || !matches!(backend, None | Some("local-outbox")) {
            return Err(EmailSendError::Config(
                "local email delivery requires development mode and the local-outbox backend"
                    .into(),
            ));
        }
        let directory = directory
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                EmailSendError::Config("set an absolute BROKER_EMAIL_OUTBOX_DIR".into())
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&directory)
                .map_err(|_| {
                    EmailSendError::Config("cannot create local email directory".into())
                })?;
        }
        #[cfg(not(unix))]
        return Err(EmailSendError::Config(
            "local email requires Unix file permissions".into(),
        ));
        let outbox = Self {
            directory,
            writer: std::sync::Mutex::new(()),
        };
        outbox.probe()?;
        Ok(outbox)
    }

    fn probe(&self) -> Result<(), EmailSendError> {
        validate_directory(&self.directory)?;
        protected_file::replace_atomic(&self.directory.join(READINESS_FILE), b"{}").map_err(|_| {
            EmailSendError::Verify("local email directory is not safely writable".into())
        })
    }
}

fn validate_directory(directory: &Path) -> Result<(), EmailSendError> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| EmailSendError::Verify("local email directory is unavailable".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0 {
            return Ok(());
        }
    }
    Err(EmailSendError::Verify(
        "local email requires an owner-private directory without links".into(),
    ))
}

#[derive(Serialize)]
struct LocalMessage<'a> {
    development_only: bool,
    recipient: &'a str,
    landing_url: &'a str,
}

#[async_trait]
impl EmailSender for LocalEmailOutbox {
    async fn send_magic_link(&self, to: &str, landing_url: &str) -> Result<(), EmailSendError> {
        let _writer = self
            .writer
            .lock()
            .map_err(|_| EmailSendError::Send("local outbox writer unavailable".into()))?;
        self.probe()?;
        if to.is_empty()
            || to.len() > MAX_RECIPIENT_BYTES
            || landing_url.is_empty()
            || landing_url.len() > MAX_LINK_BYTES
        {
            return Err(EmailSendError::Send(
                "local email exceeds its input bounds".into(),
            ));
        }
        let entries = std::fs::read_dir(&self.directory)
            .map_err(|_| EmailSendError::Send("cannot inspect local email directory".into()))?;
        let mut count = 0;
        for entry in entries.take(MAX_OUTBOX_FILES) {
            entry.map_err(|_| EmailSendError::Send("cannot inspect local email entry".into()))?;
            count += 1;
        }
        if count >= MAX_OUTBOX_FILES {
            return Err(EmailSendError::Send(
                "local email directory is full; remove old messages".into(),
            ));
        }
        let mut identifier = [0u8; 32];
        getrandom::getrandom(&mut identifier)
            .map_err(|_| EmailSendError::Send("cannot create local message identity".into()))?;
        let message = Zeroizing::new(
            serde_json::to_vec(&LocalMessage {
                development_only: true,
                recipient: to,
                landing_url,
            })
            .map_err(|_| EmailSendError::Send("cannot encode local email".into()))?,
        );
        let destination = self
            .directory
            .join(format!("{}.json", hex::encode(identifier)));
        protected_file::replace_atomic(&destination, message.as_slice())
            .map_err(|_| EmailSendError::Send("cannot persist private local email".into()))
    }

    async fn verify_sender_ready(&self) -> Result<(), EmailSendError> {
        self.probe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[tokio::test]
    async fn explicit_local_delivery_is_private_and_refuses_unsafe_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("outbox");
        let path = directory.to_str().unwrap();
        assert!(LocalEmailOutbox::from_configuration(false, None, Some(path)).is_err());
        assert!(!directory.exists());
        assert!(
            LocalEmailOutbox::from_configuration(true, Some("unsupported"), Some(path)).is_err()
        );
        assert!(!directory.exists());
        assert!(LocalEmailOutbox::from_configuration(true, None, Some("relative")).is_err());
        assert!(LocalEmailOutbox::from_configuration(true, None, None).is_err());
        let outbox = LocalEmailOutbox::from_configuration(true, None, Some(path)).unwrap();
        outbox
            .send_magic_link(
                "recipient@example.test",
                "http://localhost/sign-in#t=synthetic",
            )
            .await
            .unwrap();
        let entries: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 2);
        for file in &entries {
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        let message_path = entries
            .iter()
            .find(|entry| entry.file_name().unwrap() != READINESS_FILE)
            .unwrap();
        let message: serde_json::Value = serde_json::from_str(
            &protected_file::read_text(message_path.to_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(message["recipient"], "recipient@example.test");
        assert_eq!(
            message["landing_url"],
            "http://localhost/sign-in#t=synthetic"
        );
        assert_eq!(message["development_only"], true);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(outbox
            .send_magic_link("recipient@example.test", "synthetic")
            .await
            .is_err());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let unrelated = temporary.path().join("unrelated");
        std::fs::write(&unrelated, b"unchanged").unwrap();
        std::fs::remove_file(directory.join(READINESS_FILE)).unwrap();
        symlink(&unrelated, directory.join(READINESS_FILE)).unwrap();
        assert!(outbox
            .send_magic_link("recipient@example.test", "synthetic")
            .await
            .is_err());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"unchanged");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
        let alias = temporary.path().join("alias");
        symlink(&directory, &alias).unwrap();
        assert!(LocalEmailOutbox::from_configuration(true, None, alias.to_str()).is_err());
    }
}
