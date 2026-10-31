use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

pub struct Engine {
    pub socket: PathBuf,
}

impl Engine {
    pub async fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let mut command = tokio::process::Command::new("docker");
        command.env_clear();
        for name in ["PATH", "HOME", "TMPDIR", "DOCKER_CONFIG"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            command
                .arg("--host")
                .arg(format!("unix://{}", self.socket.display()))
                .args(arguments)
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        ensure!(
            output.status.success(),
            "Docker qualification operation failed: {}",
            output.status
        );
        Ok(output.stdout)
    }

    pub async fn inspect(&self, id: &str) -> Result<Value> {
        let values: Vec<Value> =
            serde_json::from_slice(&self.run(&["container", "inspect", id]).await?)?;
        values.into_iter().next().context("container missing")
    }
}
