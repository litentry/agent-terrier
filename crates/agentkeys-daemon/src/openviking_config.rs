use std::path::Path;

use agentkeys_core::protected_file;
use agentkeys_memory_openviking::server_config::{
    config_file_path, engine_configured, plan_server_config, ServerConfigPlan,
};
use anyhow::{Context, Result};

pub fn render_at_boot() -> Result<()> {
    render(|key| std::env::var(key).ok())
}

fn render(lookup: impl Fn(&str) -> Option<String>) -> Result<()> {
    if !engine_configured(&lookup) {
        return Ok(());
    }
    let path = std::path::PathBuf::from(config_file_path(&lookup));
    match plan_server_config(lookup, |path| Path::new(path).is_file()) {
        ServerConfigPlan::Rendered { config, summary } => {
            if let Err(error) = write_server_config(&path, &config) {
                clear_stale(&path)
                    .context("Cannot remove stale memory configuration after write failure")?;
                return Err(error.context("Cannot write private memory configuration"));
            }
            tracing::info!(%summary, "openviking: server configuration rendered");
        }
        ServerConfigPlan::Disabled { reason } => {
            clear_stale(&path)?;
            tracing::info!(%reason, "openviking: disabled");
        }
        ServerConfigPlan::Refused { reason } => {
            clear_stale(&path)?;
            anyhow::bail!("Memory configuration refused: {reason}");
        }
    }
    Ok(())
}

fn write_server_config(path: &Path, config: &serde_json::Value) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(parent)?;
    let contents = zeroize::Zeroizing::new(serde_json::to_vec_pretty(config)?);
    protected_file::replace_atomic(path, &contents)
}

fn clear_stale(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    drop(protected_file::open_read(
        path.to_str()
            .context("Memory configuration path must be UTF-8")?,
    )?);
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> serde_json::Value {
        serde_json::json!({"embedding":{"dense":{"api_key":"synthetic-config-secret"}}})
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_configuration_survives_restart_and_rejects_unsafe_destinations() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested/ov.conf");
        write_server_config(&path, &configuration()).unwrap();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let before = std::fs::read(&path).unwrap();
        write_server_config(&path, &configuration()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(write_server_config(&path, &serde_json::json!({"changed":true})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked = directory.path().join("linked.conf");
        symlink(&path, &linked).unwrap();
        assert!(write_server_config(&linked, &configuration()).is_err());
        assert!(clear_stale(&linked).is_err());
        std::fs::remove_file(&linked).unwrap();
        std::fs::hard_link(&path, &linked).unwrap();
        assert!(write_server_config(&linked, &configuration()).is_err());
        assert!(clear_stale(&linked).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&linked).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(write_server_config(&path, &configuration()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn predictable_temporary_symlink_cannot_receive_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ov.conf");
        let victim = directory.path().join("unrelated.txt");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("tmp")).unwrap();
        write_server_config(&path, &configuration()).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            configuration()
        );
    }

    #[test]
    fn invalid_or_disabled_configuration_cannot_reuse_a_stale_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ov.conf");
        for provider in ["unsupported", "disabled"] {
            write_server_config(&path, &configuration()).unwrap();
            let result = render(|key| match key {
                "OPENVIKING_CONFIG_FILE" => Some(path.to_str().unwrap().into()),
                "OPENVIKING_EMBED_PROVIDER" => Some(provider.into()),
                _ => None,
            });
            assert_eq!(result.is_ok(), provider == "disabled");
            assert!(!path.exists());
        }
        render(|key| (key == "OPENVIKING_CONFIG_FILE").then(|| path.to_str().unwrap().into()))
            .unwrap();
        assert!(path.is_file());
    }

    #[test]
    fn failed_persistence_stops_startup_and_clears_owned_stale_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ov.conf");
        write_server_config(&path, &configuration()).unwrap();
        let result = render(|key| match key {
            "OPENVIKING_CONFIG_FILE" => Some(path.to_str().unwrap().into()),
            "OPENVIKING_EMBED_API_BASE" => Some(agentkeys_core::models::default_base_url().into()),
            "OPENVIKING_EMBED_API_KEY" => {
                Some("x".repeat(protected_file::MAX_SECRET_FILE_BYTES as usize))
            }
            _ => None,
        });
        assert!(result.is_err());
        assert!(!path.exists());
    }
}
