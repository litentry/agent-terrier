use super::*;
use crate::managed_agent::{RuntimeBootstrap, MAX_BOOTSTRAP_BYTES, SERVICE_ENVIRONMENT};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;

#[derive(Clone)]
pub struct ManagedDockerConfig {
    pub chain_profile: agentkeys_core::chain_profile::ChainProfile,
    pub transport_script: PathBuf,
    pub disk_policy: DiskPolicy,
}

impl ManagedDockerConfig {
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let disk_policy = DiskPolicy::from_json(lookup("AGENT_TERRIER_RUNTIME_DISK_POLICY"))?;
        let transport_script = lookup("AGENT_TERRIER_TRANSPORT_SCRIPT")
            .context("managed Docker runtime requires AGENT_TERRIER_TRANSPORT_SCRIPT")?;
        let (mut chain_profile, _) = agentkeys_core::chain_profile::ChainProfile::resolve(
            None,
            lookup("AGENTKEYS_CHAIN").as_deref(),
            lookup("AGENTKEYS_CHAIN_PROFILE_FILE").as_deref(),
        )?;
        if let Some(rpc) =
            agentkeys_core::chain_profile::rpc_http_override(&chain_profile.name, lookup)
        {
            chain_profile.rpc.http = rpc;
        }
        let configuration = Self {
            chain_profile,
            transport_script: PathBuf::from(transport_script),
            disk_policy,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<()> {
        self.chain_profile.require_local_development(true, None)?;
        self.disk_policy.validate()?;
        ensure!(
            self.transport_script.is_absolute()
                && std::fs::canonicalize(&self.transport_script)? == self.transport_script
                && std::fs::symlink_metadata(&self.transport_script)?.is_file(),
            "transport script must be an explicit canonical source file"
        );
        Ok(())
    }
}

pub(super) struct ManagedLease {
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ManagedLease {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ManagedLease {
    pub(super) fn active(&self) -> bool {
        !self.task.is_finished()
    }

    pub(super) async fn close(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

async fn read_frame(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> Result<serde_json::Value> {
    let mut frame = Vec::new();
    (&mut *reader)
        .take((MAX_BOOTSTRAP_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .await?;
    ensure!(
        frame.len() <= MAX_BOOTSTRAP_BYTES && frame.last() == Some(&b'\n'),
        "invalid runtime readiness frame"
    );
    serde_json::from_slice(&frame).context("invalid runtime readiness JSON")
}

async fn finish(child: &mut Child, timeout: Duration) {
    if tokio::time::timeout(timeout, child.wait()).await.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

impl LocalDockerCommand {
    pub(super) async fn launch_managed(
        &self,
        id: &str,
        settings: &ManagedDockerConfig,
        mut bootstrap: RuntimeBootstrap,
    ) -> Result<ManagedLease> {
        let targets: BTreeMap<_, _> = SERVICE_ENVIRONMENT
            .iter()
            .map(|(service, name)| ((*service).to_owned(), bootstrap.environment[*name].clone()))
            .chain(std::iter::once((
                "chain".into(),
                bootstrap.chain_profile.rpc.http.clone(),
            )))
            .collect();
        let mut attached = self
            .command(|name| std::env::var_os(name))
            .args(["container", "start", "--attach", "--interactive", id])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut control = attached
            .stdin
            .take()
            .context("runtime control input missing")?;
        let mut output = BufReader::new(
            attached
                .stdout
                .take()
                .context("runtime control output missing")?,
        );
        let startup = async {
            loop {
                ensure!(
                    attached.try_wait()?.is_none(),
                    "runtime exited before transport startup"
                );
                let state = self
                    .execute(
                        &[
                            "container".into(),
                            "inspect".into(),
                            "--format".into(),
                            "{{.State.Running}}".into(),
                            id.into(),
                        ],
                        None,
                    )
                    .await?;
                if std::str::from_utf8(&state)?.trim() == "true" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            self.check_disk(id, &settings.disk_policy).await?;
            let mut command = tokio::process::Command::new("node");
            command.env_clear();
            for name in ["PATH", "HOME", "TMPDIR", "DOCKER_CONFIG"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            let mut transport = command
                .arg(&settings.transport_script)
                .args(["host", "--socket"])
                .arg(&self.socket)
                .args([
                    "--container",
                    id,
                    "--targets",
                    &serde_json::to_string(&targets)?,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let lifeline = transport
                .stdin
                .take()
                .context("transport control input missing")?;
            let mut transport_output = BufReader::new(
                transport
                    .stdout
                    .take()
                    .context("transport readiness output missing")?,
            );
            let readiness = read_frame(&mut transport_output).await?;
            let endpoints = readiness["endpoints"]
                .as_object()
                .context("transport endpoint map missing")?;
            ensure!(
                readiness["protocol"] == 1
                    && endpoints.len() == targets.len()
                    && targets.keys().all(|name| endpoints.contains_key(name)),
                "transport endpoint map mismatch"
            );
            for (name, target) in &targets {
                let endpoint = endpoints[name]
                    .as_str()
                    .context("invalid translated endpoint")?;
                agentkeys_protocol::model_config::require_local_endpoint(endpoint)
                    .map_err(anyhow::Error::msg)?;
                let endpoint = reqwest::Url::parse(endpoint)?;
                ensure!(
                    endpoint.host_str() == Some("127.0.0.1")
                        && endpoint.port().is_some()
                        && endpoint.path() == reqwest::Url::parse(target)?.path(),
                    "translated endpoint mismatch"
                );
            }
            for (service, name) in SERVICE_ENVIRONMENT {
                bootstrap
                    .environment
                    .insert((*name).into(), endpoints[*service].as_str().unwrap().into());
            }
            if bootstrap
                .environment
                .contains_key(agentkeys_protocol::model_runtime::SPEECH_URL)
            {
                let origin = agentkeys_protocol::model_runtime::relay_origin(
                    &bootstrap.environment[agentkeys_protocol::model_runtime::BASE_URL],
                )
                .to_owned();
                bootstrap
                    .environment
                    .insert(agentkeys_protocol::model_runtime::SPEECH_URL.into(), origin);
            }
            bootstrap.chain_profile.rpc.http = endpoints["chain"].as_str().unwrap().into();
            bootstrap.validate()?;
            let mut frame = zeroize::Zeroizing::new(serde_json::to_vec(&bootstrap)?);
            frame.push(b'\n');
            ensure!(
                frame.len() <= MAX_BOOTSTRAP_BYTES,
                "bootstrap configuration exceeds input limit"
            );
            control.write_all(&frame).await?;
            control.flush().await?;
            let readiness = read_frame(&mut output).await?;
            ensure!(
                readiness["ready"] == true
                    && readiness["surface"] == "local-agent-processes"
                    && readiness["agent_url"]
                        == format!(
                            "http://127.0.0.1:{}",
                            agentkeys_protocol::sandbox_env::SANDBOX_BRIDGE_PORT
                        )
                    && readiness["daemon_url"]
                        == format!(
                            "http://127.0.0.1:{}",
                            agentkeys_protocol::sandbox_env::SANDBOX_DAEMON_PORT
                        ),
                "managed runtime readiness mismatch"
            );
            ensure!(
                transport.try_wait()?.is_none() && attached.try_wait()?.is_none(),
                "runtime startup process exited"
            );
            Ok::<_, anyhow::Error>((transport, lifeline, transport_output))
        };
        let (mut transport, lifeline, mut transport_output) =
            tokio::time::timeout(COMMAND_TIMEOUT, startup)
                .await
                .context("managed runtime startup timed out")??;
        let (shutdown, stopping) = tokio::sync::oneshot::channel();
        let disk_command = LocalDockerCommand {
            socket: self.socket.clone(),
        };
        let disk_container = id.to_owned();
        let disk_policy = settings.disk_policy.clone();
        let task = tokio::spawn(async move {
            let mut runtime_sink = tokio::io::sink();
            let mut transport_sink = tokio::io::sink();
            tokio::select! {
                reason = disk_command.monitor_disk(&disk_container, &disk_policy) => {
                    if let Err(reason) = reason {
                        eprintln!("Local agent {disk_container} disk policy requested shutdown: {reason}");
                    }
                    let stopped = disk_command.execute(&["container".into(), "stop".into(), "--time=2".into(), disk_container], None).await;
                    if stopped.is_err() {
                        eprintln!("Development disk policy could not confirm container shutdown; inspect the local Docker engine.");
                    }
                },
                _ = stopping => {},
                _ = attached.wait() => {},
                _ = transport.wait() => {},
                _ = tokio::io::copy(&mut output, &mut runtime_sink) => {},
                _ = tokio::io::copy(&mut transport_output, &mut transport_sink) => {},
            }
            drop(control);
            finish(&mut attached, Duration::from_secs(15)).await;
            drop(lifeline);
            finish(&mut transport, Duration::from_secs(5)).await;
        });
        Ok(ManagedLease {
            task,
            shutdown: Some(shutdown),
        })
    }
}
