use std::path::Path;

use agentkeys_core::protected_file;
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroizing;

use crate::error::{BrokerError, BrokerResult};

fn path_text(path: &Path) -> BrokerResult<&str> {
    path.to_str()
        .ok_or_else(|| BrokerError::Internal("keypair path must be UTF-8".into()))
}

pub(crate) fn create(path: &Path, keypair: &impl Serialize) -> BrokerResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let mut directories = std::fs::DirBuilder::new();
        directories.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directories.mode(0o700);
        }
        directories
            .create(parent)
            .map_err(|error| BrokerError::Internal(format!("create keypair directory: {error}")))?;
    }
    let encoded = Zeroizing::new(
        serde_json::to_vec_pretty(keypair)
            .map_err(|error| BrokerError::Internal(format!("serialize keypair: {error}")))?,
    );
    protected_file::write(path_text(path)?, &encoded, true)
        .map_err(|error| BrokerError::Internal(format!("create protected keypair: {error}")))
}

pub(crate) fn load<Keypair: DeserializeOwned>(path: &Path) -> BrokerResult<Keypair> {
    let encoded = protected_file::read_text(path_text(path)?)
        .map_err(|error| BrokerError::Internal(format!("read protected keypair: {error}")))?;
    serde_json::from_str(&encoded)
        .map_err(|error| BrokerError::Internal(format!("parse keypair: {error}")))
}
