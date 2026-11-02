use super::*;
use serde_json::Value;

impl DockerRuntime {
    pub async fn reset_local(config: DockerConfig) -> Result<usize> {
        Self::local(config).reset_owned_state().await
    }

    async fn owned_names(&self, kind: &str, format: &str) -> Result<Vec<String>> {
        let mut arguments = vec![kind.into(), "ls".into()];
        if kind == "container" {
            arguments.extend(["--all".into(), "--no-trunc".into()]);
        }
        arguments.extend([
            "--filter".into(),
            format!("label={OWNER_LABEL}={}", self.config.namespace),
            "--format".into(),
            format.into(),
        ]);
        let output = self.command.execute(&arguments, None).await?;
        Ok(std::str::from_utf8(&output)?
            .split_whitespace()
            .map(str::to_owned)
            .collect())
    }

    pub(super) async fn reset_owned_state(&self) -> Result<usize> {
        let mut actors = BTreeMap::new();
        let names = self.owned_names("volume", "{{.Name}}").await?;
        for name in names {
            ensure!(
                name.starts_with(&format!("{}-", self.config.namespace))
                    && name.ends_with("-state"),
                "unexpected owned state volume name"
            );
            let output = self
                .command
                .execute(&["volume".into(), "inspect".into(), name.clone()], None)
                .await?;
            let volumes: Vec<Value> = serde_json::from_slice(&output)?;
            ensure!(volumes.len() == 1, "ambiguous reset volume metadata");
            let labels = &volumes[0]["Labels"];
            let device = normalize_identity(
                labels[DEVICE_LABEL]
                    .as_str()
                    .context("missing reset device")?,
            )?;
            let actor = normalize_identity(
                labels[ACTOR_LABEL]
                    .as_str()
                    .context("missing reset actor")?,
            )?;
            ensure!(
                self.state_volume_name(&device) == name,
                "reset volume name mismatch"
            );
            self.state_volume_metadata(&device, &actor)
                .await?
                .context("reset volume disappeared")?;
            ensure!(
                actors.insert(device, actor).is_none(),
                "duplicate reset device"
            );
        }
        let identifiers = self.owned_names("container", "{{.ID}}").await?;
        for container in self.inspect(&identifiers).await? {
            let labels = container
                .config
                .labels
                .as_ref()
                .context("missing reset labels")?;
            let device =
                normalize_identity(labels.get(DEVICE_LABEL).context("missing reset device")?)?;
            let actor =
                normalize_identity(labels.get(ACTOR_LABEL).context("missing reset actor")?)?;
            ensure!(
                actors.get(&device) == Some(&actor),
                "reset container and state owner mismatch"
            );
        }
        let mut network_devices = Vec::new();
        for name in self.owned_names("network", "{{.Name}}").await? {
            let prefix = format!("{}-", self.config.namespace);
            let device = normalize_identity(
                name.strip_prefix(&prefix)
                    .context("reset network name mismatch")?,
            )?;
            let network = self
                .network_metadata(&device)
                .await?
                .context("reset network disappeared")?;
            ensure!(
                network["Containers"]
                    .as_object()
                    .is_some_and(|containers| containers
                        .keys()
                        .all(|identifier| identifiers.contains(identifier))),
                "reset network contains an unrelated container"
            );
            network_devices.push(device);
        }
        for (device, actor) in &actors {
            self.kill_for_device(device).await?;
            self.reset_state_for_device(device, actor).await?;
        }
        for device in network_devices {
            self.remove_network(&device).await?;
        }
        for (kind, format) in [
            ("container", "{{.ID}}"),
            ("volume", "{{.Name}}"),
            ("network", "{{.Name}}"),
        ] {
            ensure!(
                self.owned_names(kind, format).await?.is_empty(),
                "owned runtime resources remain after reset"
            );
        }
        Ok(actors.len())
    }
}
