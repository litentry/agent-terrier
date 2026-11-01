use super::*;
use agentkeys_protocol::runtime_layout::STATE_DIRECTORY;
use serde_json::Value;

impl DockerRuntime {
    pub(super) fn state_volume_name(&self, device: &str) -> String {
        format!("{}-{device}-state", self.config.namespace)
    }

    pub(super) async fn state_volume_metadata(
        &self,
        device: &str,
        actor: &str,
    ) -> Result<Option<Value>> {
        let name = self.state_volume_name(device);
        let existing = self
            .command
            .execute(
                &[
                    "volume".into(),
                    "ls".into(),
                    "--filter".into(),
                    format!("name=^{name}$"),
                    "--format".into(),
                    "{{.Name}}".into(),
                ],
                None,
            )
            .await?;
        if existing.is_empty() {
            return Ok(None);
        }
        ensure!(
            std::str::from_utf8(&existing)?.trim() == name,
            "ambiguous runtime state volume"
        );
        let output = self
            .command
            .execute(&["volume".into(), "inspect".into(), name.clone()], None)
            .await?;
        let mut volumes: Vec<Value> = serde_json::from_slice(&output)?;
        ensure!(volumes.len() == 1, "ambiguous runtime state metadata");
        let volume = volumes.remove(0);
        ensure!(
            volume["Name"].as_str() == Some(&name)
                && volume["Driver"].as_str() == Some("local")
                && volume["Scope"].as_str() == Some("local")
                && volume["Labels"][OWNER_LABEL].as_str() == Some(&self.config.namespace)
                && volume["Labels"][DEVICE_LABEL].as_str() == Some(device)
                && volume["Labels"][ACTOR_LABEL].as_str() == Some(actor)
                && (volume["Options"].is_null()
                    || volume["Options"]
                        .as_object()
                        .is_some_and(|options| options.is_empty())),
            "runtime state volume ownership or driver mismatch"
        );
        Ok(Some(volume))
    }

    pub(super) async fn ensure_state_volume(&self, device: &str, actor: &str) -> Result<String> {
        let name = self.state_volume_name(device);
        if self.state_volume_metadata(device, actor).await?.is_none() {
            self.command
                .execute(
                    &[
                        "volume".into(),
                        "create".into(),
                        "--driver".into(),
                        "local".into(),
                        "--label".into(),
                        format!("{OWNER_LABEL}={}", self.config.namespace),
                        "--label".into(),
                        format!("{DEVICE_LABEL}={device}"),
                        "--label".into(),
                        format!("{ACTOR_LABEL}={actor}"),
                        name.clone(),
                    ],
                    None,
                )
                .await?;
        }
        self.state_volume_metadata(device, actor)
            .await?
            .context("runtime state volume missing")?;
        Ok(name)
    }

    pub(super) async fn verify_state_mount(&self, container: &Container) -> Result<()> {
        let labels = container
            .config
            .labels
            .as_ref()
            .context("container labels missing")?;
        let device = normalize_identity(labels.get(DEVICE_LABEL).context("device label missing")?)?;
        let actor = normalize_identity(labels.get(ACTOR_LABEL).context("actor label missing")?)?;
        let mounts: Vec<_> = container
            .mounts
            .iter()
            .filter(|mount| mount["Type"] != "tmpfs")
            .collect();
        ensure!(
            mounts.len() == 1
                && mounts[0]["Type"] == "volume"
                && mounts[0]["Name"].as_str() == Some(self.state_volume_name(&device).as_str())
                && mounts[0]["Destination"] == STATE_DIRECTORY
                && mounts[0]["RW"] == true,
            "runtime state mount mismatch"
        );
        self.state_volume_metadata(&device, &actor)
            .await?
            .context("runtime state volume missing")?;
        Ok(())
    }

    /// Explicitly discard stopped actor state. Ordinary teardown always preserves it.
    pub async fn reset_state_for_device(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
    ) -> Result<bool> {
        let device = normalize_identity(device_key_hash)?;
        let actor = normalize_identity(actor_omni)?;
        let _guard = self.locks.lock(&device).await;
        ensure!(
            self.containers_for_device(&device).await?.is_empty(),
            "remove the runtime before resetting its state"
        );
        if self.state_volume_metadata(&device, &actor).await?.is_none() {
            return Ok(false);
        }
        self.command
            .execute(
                &[
                    "volume".into(),
                    "rm".into(),
                    self.state_volume_name(&device),
                ],
                None,
            )
            .await?;
        Ok(true)
    }
}
