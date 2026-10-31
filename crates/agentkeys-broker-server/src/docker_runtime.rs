use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use crate::sandbox_backend::{
    CreateEnvProvider, DelegateLocks, EnsureOutcome, InstanceImageInfo, LiveRuntime, RuntimeImage,
    SandboxRuntime,
};

const OWNER_LABEL: &str = "org.agent-terrier.runtime";
const DEVICE_LABEL: &str = "org.agent-terrier.device";
const ACTOR_LABEL: &str = "org.agent-terrier.actor";
const DEFAULT_MEMORY_MIB: u32 = 2048;
const DEFAULT_CPU_COUNT: u32 = 2;
const PROCESS_LIMIT: u32 = 256;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct DockerConfig {
    pub socket: PathBuf,
    pub namespace: String,
    pub image: String,
    pub memory_mib: u32,
    pub cpu_count: u32,
}

impl DockerConfig {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let Some(image) = get("AGENT_TERRIER_SANDBOX_IMAGE") else {
            return Ok(None);
        };
        ensure!(
            get("AGENT_TERRIER_LOCAL_DEV").as_deref() == Some("1"),
            "Docker runtime requires explicit AGENT_TERRIER_LOCAL_DEV=1"
        );
        let (profile, _) = agentkeys_core::chain_profile::ChainProfile::resolve(
            None,
            get("AGENTKEYS_CHAIN").as_deref(),
            get("AGENTKEYS_CHAIN_PROFILE_FILE").as_deref(),
        )?;
        let rpc_override = agentkeys_core::chain_profile::rpc_http_override(&profile.name, &get);
        profile.require_local_development(true, rpc_override.as_deref())?;
        ensure!(
            !image.trim().is_empty()
                && !image.starts_with('-')
                && !image.contains(char::is_whitespace),
            "invalid local image reference"
        );
        let namespace =
            get("AGENT_TERRIER_RUNTIME_NAMESPACE").unwrap_or_else(|| "agent-terrier-local".into());
        ensure!(
            !namespace.is_empty()
                && namespace.len() <= 48
                && namespace.bytes().all(|value| value.is_ascii_lowercase()
                    || value.is_ascii_digit()
                    || value == b'-'),
            "invalid runtime namespace"
        );
        let socket = PathBuf::from(
            get("AGENT_TERRIER_DOCKER_SOCKET").unwrap_or_else(|| "/var/run/docker.sock".into()),
        );
        ensure!(
            socket.is_absolute() && !socket.to_string_lossy().contains("://"),
            "Docker socket must be a local absolute path"
        );
        let number = |name: &str, fallback: u32, maximum: u32| -> Result<u32> {
            let value = get(name)
                .map(|value| value.parse())
                .transpose()
                .with_context(|| format!("invalid {name}"))?
                .unwrap_or(fallback);
            ensure!(
                value > 0 && value <= maximum,
                "{name} is outside the supported range"
            );
            Ok(value)
        };
        Ok(Some(Self {
            socket,
            namespace,
            image,
            memory_mib: number(
                "AGENT_TERRIER_SANDBOX_MEMORY_MIB",
                DEFAULT_MEMORY_MIB,
                65536,
            )?,
            cpu_count: number("AGENT_TERRIER_SANDBOX_CPUS", DEFAULT_CPU_COUNT, 64)?,
        }))
    }
}

#[async_trait]
trait DockerCommand: Send + Sync {
    async fn execute(&self, arguments: &[String], input: Option<Vec<u8>>) -> Result<Vec<u8>>;
}

struct LocalDockerCommand {
    socket: PathBuf,
}

impl LocalDockerCommand {
    fn command(&self, get: impl Fn(&str) -> Option<std::ffi::OsString>) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("docker");
        command.env_clear();
        for name in ["PATH", "HOME", "TMPDIR", "DOCKER_CONFIG"] {
            if let Some(value) = get(name) {
                command.env(name, value);
            }
        }
        command
            .arg("--host")
            .arg(format!("unix://{}", self.socket.display()));
        command
    }
}

#[async_trait]
impl DockerCommand for LocalDockerCommand {
    async fn execute(&self, arguments: &[String], input: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let mut command = self.command(|name| std::env::var_os(name));
        command
            .args(arguments)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let result = tokio::time::timeout(COMMAND_TIMEOUT, async {
            let mut child = command.spawn().context("start local Docker client")?;
            if let Some(input) = input {
                let mut stdin = child.stdin.take().context("open Docker input pipe")?;
                stdin
                    .write_all(&input)
                    .await
                    .context("write Docker environment input")?;
                stdin.shutdown().await?;
            }
            Ok::<_, anyhow::Error>(child.wait_with_output().await?)
        })
        .await
        .context("local Docker command timed out")??;
        ensure!(
            result.status.success(),
            "local Docker command failed (status {}); inspect Docker locally for details",
            result.status
        );
        Ok(result.stdout)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Container {
    id: String,
    image: String,
    config: ContainerConfig,
    state: ContainerState,
    network_settings: NetworkSettings,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    image: String,
    labels: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    running: bool,
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkSettings {
    ports: Option<HashMap<String, Option<Vec<PortBinding>>>>,
}

#[derive(Deserialize)]
struct PortBinding {
    #[serde(rename = "HostIp")]
    host_ip: String,
    #[serde(rename = "HostPort")]
    host_port: String,
}

#[derive(Deserialize)]
struct Image {
    #[serde(rename = "Id")]
    id: String,
}

type EndpointCache = RwLock<HashMap<String, HashMap<u16, String>>>;

pub struct DockerRuntime {
    config: DockerConfig,
    command: Arc<dyn DockerCommand>,
    locks: DelegateLocks,
    endpoints: EndpointCache,
}

impl DockerRuntime {
    pub async fn connect(config: DockerConfig) -> Result<Self> {
        let command = Arc::new(LocalDockerCommand {
            socket: config.socket.clone(),
        });
        let runtime = Self {
            config,
            command,
            locks: DelegateLocks::default(),
            endpoints: RwLock::default(),
        };
        runtime.current_image().await?;
        Ok(runtime)
    }

    async fn current_image(&self) -> Result<Image> {
        let arguments = vec!["image".into(), "inspect".into(), self.config.image.clone()];
        let output = self.command.execute(&arguments, None).await?;
        let images: Vec<Image> =
            serde_json::from_slice(&output).context("read local image identity")?;
        let image = images
            .into_iter()
            .next()
            .context("local image is absent; load or build it before starting")?;
        ensure!(
            image.id.starts_with("sha256:")
                && image.id.len() == 71
                && hex::decode(&image.id[7..]).is_ok(),
            "Docker returned an invalid image digest"
        );
        Ok(image)
    }

    async fn inspect(&self, ids: &[String]) -> Result<Vec<Container>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        for id in ids {
            normalize_identity(id)?;
        }
        let mut arguments = vec!["container".into(), "inspect".into()];
        arguments.extend_from_slice(ids);
        let output = self.command.execute(&arguments, None).await?;
        let containers: Vec<Container> =
            serde_json::from_slice(&output).context("read local container metadata")?;
        ensure!(
            containers.len() == ids.len(),
            "Docker returned an incomplete container inventory"
        );
        for container in &containers {
            ensure!(
                ids.contains(&container.id),
                "Docker returned an unexpected container identity"
            );
            let labels = container
                .config
                .labels
                .as_ref()
                .context("container ownership labels missing")?;
            ensure!(
                labels.get(OWNER_LABEL) == Some(&self.config.namespace),
                "refusing a container outside this runtime namespace"
            );
            normalize_identity(&container.id)?;
            self.cache_endpoints(container)?;
        }
        Ok(containers)
    }

    async fn containers_for_device(&self, device: &str) -> Result<Vec<Container>> {
        let arguments = vec![
            "container".into(),
            "ls".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("label={OWNER_LABEL}={}", self.config.namespace),
            "--filter".into(),
            format!("label={DEVICE_LABEL}={device}"),
            "--format".into(),
            "{{.ID}}".into(),
        ];
        let output = self.command.execute(&arguments, None).await?;
        let ids: Vec<String> = std::str::from_utf8(&output)?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let containers = self.inspect(&ids).await?;
        ensure!(
            containers.iter().all(|container| container
                .config
                .labels
                .as_ref()
                .and_then(|labels| labels.get(DEVICE_LABEL))
                .map(String::as_str)
                == Some(device)),
            "container device ownership mismatch"
        );
        Ok(containers)
    }

    fn cache_endpoints(&self, container: &Container) -> Result<()> {
        let mut endpoints = HashMap::new();
        if let Some(ports) = &container.network_settings.ports {
            for (port, bindings) in ports {
                let Some(port) = port
                    .strip_suffix("/tcp")
                    .and_then(|value| value.parse::<u16>().ok())
                else {
                    continue;
                };
                if let Some(bindings) = bindings {
                    for binding in bindings {
                        ensure!(
                            binding.host_ip == "127.0.0.1",
                            "refusing a runtime port exposed beyond localhost"
                        );
                        let host_port: u16 = binding
                            .host_port
                            .parse()
                            .context("invalid published port")?;
                        ensure!(host_port > 0, "Docker returned an invalid published port");
                        endpoints.insert(port, format!("http://127.0.0.1:{host_port}"));
                    }
                }
            }
        }
        self.endpoints
            .write()
            .map_err(|_| anyhow::anyhow!("runtime endpoint cache poisoned"))?
            .insert(container.id.clone(), endpoints);
        Ok(())
    }

    async fn remove(&self, container: &Container) -> Result<()> {
        self.command
            .execute(
                &[
                    "container".into(),
                    "rm".into(),
                    "--force".into(),
                    container.id.clone(),
                ],
                None,
            )
            .await?;
        self.endpoints
            .write()
            .map_err(|_| anyhow::anyhow!("runtime endpoint cache poisoned"))?
            .remove(&container.id);
        Ok(())
    }

    fn network_name(&self, device: &str) -> String {
        format!("{}-{device}", self.config.namespace)
    }

    async fn network_metadata(&self, device: &str) -> Result<Option<serde_json::Value>> {
        let name = self.network_name(device);
        let existing = self
            .command
            .execute(
                &[
                    "network".into(),
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
            "ambiguous runtime network"
        );
        let output = self
            .command
            .execute(&["network".into(), "inspect".into(), name.clone()], None)
            .await?;
        let mut networks: Vec<serde_json::Value> = serde_json::from_slice(&output)?;
        ensure!(networks.len() == 1, "ambiguous runtime network metadata");
        let network = networks.remove(0);
        ensure!(
            network["Name"].as_str() == Some(&name)
                && network["Driver"].as_str() == Some("bridge")
                && network["Labels"][OWNER_LABEL].as_str() == Some(&self.config.namespace)
                && network["Labels"][DEVICE_LABEL].as_str() == Some(device)
                && network["Options"]["com.docker.network.bridge.enable_icc"].as_str()
                    == Some("false"),
            "runtime network ownership or isolation mismatch"
        );
        normalize_identity(
            network["Id"]
                .as_str()
                .context("runtime network ID missing")?,
        )?;
        Ok(Some(network))
    }

    async fn ensure_network(&self, device: &str) -> Result<String> {
        let name = self.network_name(device);
        if self.network_metadata(device).await?.is_none() {
            self.command
                .execute(
                    &[
                        "network".into(),
                        "create".into(),
                        "--driver".into(),
                        "bridge".into(),
                        "--opt".into(),
                        "com.docker.network.bridge.enable_icc=false".into(),
                        "--label".into(),
                        format!("{OWNER_LABEL}={}", self.config.namespace),
                        "--label".into(),
                        format!("{DEVICE_LABEL}={device}"),
                        name.clone(),
                    ],
                    None,
                )
                .await?;
        }
        self.network_metadata(device)
            .await?
            .context("runtime network missing")?;
        Ok(name)
    }

    async fn remove_network(&self, device: &str) -> Result<()> {
        let Some(network) = self.network_metadata(device).await? else {
            return Ok(());
        };
        ensure!(
            network["Containers"]
                .as_object()
                .is_some_and(|containers| containers.is_empty()),
            "runtime network is still in use; refusing removal"
        );
        let id = network["Id"]
            .as_str()
            .context("runtime network ID missing")?;
        self.command
            .execute(&["network".into(), "rm".into(), id.into()], None)
            .await?;
        Ok(())
    }
}

fn normalize_identity(value: &str) -> Result<String> {
    let normalized = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase();
    ensure!(
        normalized.len() == 64 && hex::decode(&normalized).is_ok(),
        "runtime identity must be a 32-byte hex value"
    );
    Ok(normalized)
}

fn environment_input(
    actor: &str,
    base: &[(String, String)],
    additional: Vec<(String, String)>,
) -> Result<Vec<u8>> {
    use agentkeys_protocol::sandbox_env;
    let allowed_names: Vec<&str> = sandbox_env::CHAT_COMMON
        .into_iter()
        .chain(sandbox_env::CHAT_CREDENTIAL_ANY)
        .chain([
            sandbox_env::MGMT_TOKEN,
            sandbox_env::BRIDGE_TOKEN,
            sandbox_env::CHANNEL_WORKER_URL,
            sandbox_env::SIGNER_URL,
            sandbox_env::MEMORY_NS,
            sandbox_env::BOUND_CHANNELS,
            sandbox_env::APP_TEMPLATE,
            sandbox_env::APP_AVAILABILITY,
            sandbox_env::MEMORY_NAMESPACES,
            sandbox_env::WAKE_SINCE_MS,
            sandbox_env::APP_TZ_OFFSET_MINUTES,
            "AGENTKEYS_CHAIN",
            "AGENT_TERRIER_LOCAL_DEV",
        ])
        .collect();
    let mut environment = BTreeMap::new();
    for (name, value) in base.iter().cloned().chain(additional) {
        ensure!(
            allowed_names.contains(&name.as_str()),
            "unsupported sandbox environment entry"
        );
        if let Some(previous) = environment.insert(name.clone(), value.clone()) {
            ensure!(previous == value, "conflicting sandbox environment entries");
        }
    }
    for name in sandbox_env::CHAT_COMMON
        .into_iter()
        .chain([sandbox_env::MGMT_TOKEN, sandbox_env::BRIDGE_TOKEN])
    {
        ensure!(
            environment
                .get(name)
                .is_some_and(|value: &String| !value.trim().is_empty()),
            "missing required sandbox configuration: {name}"
        );
    }
    ensure!(
        normalize_identity(&environment[sandbox_env::ACTOR_OMNI])? == actor,
        "sandbox actor identity mismatch"
    );
    normalize_identity(&environment[sandbox_env::OPERATOR_OMNI])?;
    let credentials = sandbox_env::CHAT_CREDENTIAL_ANY
        .iter()
        .filter(|name| {
            environment
                .get(**name)
                .is_some_and(|value| !value.trim().is_empty())
        })
        .count();
    ensure!(
        credentials == 1,
        "sandbox requires exactly one actor credential"
    );
    for (name, expected) in [
        ("AGENTKEYS_CHAIN", "anvil"),
        ("AGENT_TERRIER_LOCAL_DEV", "1"),
    ] {
        ensure!(
            environment.get(name).is_none_or(|value| value == expected),
            "development runtime configuration mismatch for {name}"
        );
        environment.insert(name.into(), expected.into());
    }
    let mut output = Vec::new();
    for (name, value) in environment {
        ensure!(
            !name.is_empty()
                && name.bytes().all(|value| value.is_ascii_uppercase()
                    || value.is_ascii_digit()
                    || value == b'_')
                && !value.contains(['\n', '\r', '\0']),
            "invalid sandbox environment entry"
        );
        output.extend_from_slice(format!("{name}={value}\n").as_bytes());
    }
    Ok(output)
}

#[async_trait]
impl SandboxRuntime for DockerRuntime {
    fn kind(&self) -> &'static str {
        "docker"
    }
    fn runtime_ref(&self) -> String {
        self.config.namespace.clone()
    }
    fn current_image_tag(&self) -> Option<String> {
        Some(self.config.image.clone())
    }

    async fn current_images(&self) -> Result<Vec<RuntimeImage>> {
        Ok(vec![RuntimeImage {
            image_id: self.current_image().await?.id,
            image_url: self.config.image.clone(),
            status: "available".into(),
        }])
    }

    async fn ensure_for_delegate_with_envs(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        base_envs: &[(String, String)],
        on_create: CreateEnvProvider,
    ) -> Result<EnsureOutcome> {
        let device = normalize_identity(device_key_hash)?;
        let actor = normalize_identity(actor_omni)?;
        let _guard = self.locks.lock(&device).await;
        let existing = self.containers_for_device(&device).await?;
        ensure!(
            existing.len() <= 1,
            "multiple runtimes claim this device; refusing ambiguous ownership"
        );
        for container in &existing {
            ensure!(
                container
                    .config
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(ACTOR_LABEL))
                    == Some(&actor),
                "container actor ownership mismatch"
            );
            if container.state.running {
                return Ok(EnsureOutcome {
                    sandbox_id: container.id.clone(),
                    created: false,
                    status: container.state.status.clone(),
                    agent_url: self
                        .instance_mgmt_endpoint(&container.id)
                        .map(|endpoint| endpoint.0),
                });
            }
        }
        let image = self.current_image().await?;
        let input = environment_input(&actor, base_envs, on_create().await)?;
        let network = self.ensure_network(&device).await?;
        for container in &existing {
            self.remove(container).await?;
        }
        let mut arguments = vec![
            "container".into(),
            "create".into(),
            "--pull=never".into(),
            "--name".into(),
            format!("{}-{device}", self.config.namespace),
            "--label".into(),
            format!("{OWNER_LABEL}={}", self.config.namespace),
            "--label".into(),
            format!("{DEVICE_LABEL}={device}"),
            "--label".into(),
            format!("{ACTOR_LABEL}={actor}"),
            "--network".into(),
            network,
            "--add-host".into(),
            "host.docker.internal:host-gateway".into(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--user=1000:1000".into(),
            format!("--pids-limit={PROCESS_LIMIT}"),
            format!("--memory={}m", self.config.memory_mib),
            format!("--cpus={}", self.config.cpu_count),
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m".into(),
            "--tmpfs=/home/agent:rw,nosuid,nodev,uid=1000,gid=1000,size=512m".into(),
            "--env-file=/dev/stdin".into(),
        ];
        for port in [
            agentkeys_protocol::sandbox_env::SANDBOX_BRIDGE_PORT,
            agentkeys_protocol::sandbox_env::SANDBOX_DAEMON_PORT,
        ] {
            arguments.extend(["--publish".into(), format!("127.0.0.1::{port}")]);
        }
        arguments.push(image.id);
        let output = self.command.execute(&arguments, Some(input)).await?;
        let id = normalize_identity(std::str::from_utf8(&output)?.trim())?;
        self.command
            .execute(&["container".into(), "start".into(), id.clone()], None)
            .await?;
        let containers = self.inspect(std::slice::from_ref(&id)).await?;
        let container = containers.first().context("created container missing")?;
        ensure!(container.state.running, "created container is not running");
        Ok(EnsureOutcome {
            sandbox_id: id.clone(),
            created: true,
            status: container.state.status.clone(),
            agent_url: self.instance_mgmt_endpoint(&id).map(|endpoint| endpoint.0),
        })
    }

    async fn live_for_device(&self, device_key_hash: &str) -> Result<Vec<LiveRuntime>> {
        let device = normalize_identity(device_key_hash)?;
        Ok(self
            .containers_for_device(&device)
            .await?
            .into_iter()
            .filter(|container| container.state.running)
            .map(|container| LiveRuntime {
                id: container.id,
                status: container.state.status,
                expire_at: String::new(),
            })
            .collect())
    }

    async fn kill_for_device(&self, device_key_hash: &str) -> Result<Vec<String>> {
        let device = normalize_identity(device_key_hash)?;
        let _guard = self.locks.lock(&device).await;
        let containers = self.containers_for_device(&device).await?;
        let mut removed = Vec::new();
        for container in containers {
            self.remove(&container).await?;
            removed.push(container.id);
        }
        self.remove_network(&device).await?;
        Ok(removed)
    }

    async fn booted_image_info(&self, sandbox_id: &str) -> Result<Option<InstanceImageInfo>> {
        let id = normalize_identity(sandbox_id)?;
        Ok(self
            .inspect(&[id])
            .await?
            .first()
            .map(|container| InstanceImageInfo {
                image_id: container.image.clone(),
                image_ref: container.config.image.clone(),
            }))
    }

    fn instance_endpoint(
        &self,
        sandbox_id: &str,
        port: u16,
    ) -> Option<(String, Vec<(String, String)>)> {
        let endpoints = self.endpoints.read().ok()?;
        Some((endpoints.get(sandbox_id)?.get(&port)?.clone(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    type RecordedCommand = (Vec<String>, Option<Vec<u8>>);

    #[test]
    fn docker_client_has_only_explicit_environment_and_socket() {
        let client = LocalDockerCommand {
            socket: PathBuf::from("/tmp/test-docker.sock"),
        };
        let command = client.command(|name| Some(format!("test-{name}").into()));
        let environment: Vec<_> = command.as_std().get_envs().map(|(name, _)| name).collect();
        assert_eq!(environment.len(), 4);
        for name in ["PATH", "HOME", "TMPDIR", "DOCKER_CONFIG"] {
            assert!(environment.contains(&std::ffi::OsStr::new(name)));
        }
        let arguments: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(arguments, ["--host", "unix:///tmp/test-docker.sock"]);
    }

    #[derive(Default)]
    struct FakeEngine {
        container: Mutex<Option<serde_json::Value>>,
        calls: Mutex<Vec<RecordedCommand>>,
        image_missing: std::sync::atomic::AtomicBool,
        network_exists: std::sync::atomic::AtomicBool,
        foreign_network: std::sync::atomic::AtomicBool,
        start_fails: std::sync::atomic::AtomicBool,
    }

    fn device() -> String {
        hex::encode([1; 32])
    }
    fn actor() -> String {
        hex::encode([2; 32])
    }
    fn container_id() -> String {
        hex::encode([3; 32])
    }
    fn image_id() -> String {
        format!("sha256:{}", hex::encode([4; 32]))
    }

    fn container(namespace: &str, actor: &str, host: &str, running: bool) -> serde_json::Value {
        json!({
            "Id": container_id(), "Image": image_id(),
            "Config": {"Image": "local:test", "Labels": {
                OWNER_LABEL: namespace, DEVICE_LABEL: device(), ACTOR_LABEL: actor,
            }},
            "State": {"Running": running, "Status": if running { "running" } else { "exited" }},
            "NetworkSettings": {"Ports": {
                format!("{}/tcp", agentkeys_protocol::sandbox_env::SANDBOX_BRIDGE_PORT): [{"HostIp": host, "HostPort": "18090"}],
            }},
        })
    }

    #[async_trait]
    impl DockerCommand for FakeEngine {
        async fn execute(&self, arguments: &[String], input: Option<Vec<u8>>) -> Result<Vec<u8>> {
            tokio::task::yield_now().await;
            self.calls.lock().unwrap().push((arguments.to_vec(), input));
            let verbs = (arguments[0].as_str(), arguments[1].as_str());
            let output = match verbs {
                ("image", "inspect") => {
                    ensure!(
                        !self.image_missing.load(Ordering::SeqCst),
                        "test image missing"
                    );
                    json!([{"Id": image_id()}]).to_string()
                }
                ("container", "ls") => {
                    if self.container.lock().unwrap().is_some() {
                        container_id()
                    } else {
                        String::new()
                    }
                }
                ("container", "inspect") => {
                    json!([self.container.lock().unwrap().as_ref().unwrap()]).to_string()
                }
                ("container", "create") => {
                    *self.container.lock().unwrap() =
                        Some(container("test-runtime", &actor(), "127.0.0.1", false));
                    container_id()
                }
                ("container", "start") => {
                    ensure!(!self.start_fails.load(Ordering::SeqCst), "test start failed");
                    if let Some(container) = self.container.lock().unwrap().as_mut() {
                        container["State"] = json!({"Running": true, "Status": "running"});
                    }
                    container_id()
                },
                ("container", "rm") => {
                    *self.container.lock().unwrap() = None;
                    container_id()
                }
                ("network", "ls") => if self.network_exists.load(Ordering::SeqCst) { format!("test-runtime-{}", device()) } else { String::new() },
                ("network", "create") => {
                    self.network_exists.store(true, Ordering::SeqCst);
                    "network-created".into()
                },
                ("network", "inspect") => json!([{
                    "Id": hex::encode([6; 32]), "Name": format!("test-runtime-{}", device()), "Driver": "bridge", "Containers": {},
                    "Labels": { OWNER_LABEL: if self.foreign_network.load(Ordering::SeqCst) { "foreign" } else { "test-runtime" }, DEVICE_LABEL: device() },
                    "Options": {"com.docker.network.bridge.enable_icc": "false"},
                }]).to_string(),
                ("network", "rm") => {
                    self.network_exists.store(false, Ordering::SeqCst);
                    "network-removed".into()
                },
                _ => panic!("unexpected Docker operation"),
            };
            Ok(output.into_bytes())
        }
    }

    fn runtime(engine: Arc<FakeEngine>) -> DockerRuntime {
        DockerRuntime {
            config: DockerConfig {
                socket: PathBuf::from("/var/run/docker.sock"),
                namespace: "test-runtime".into(),
                image: "local:test".into(),
                memory_mib: DEFAULT_MEMORY_MIB,
                cpu_count: DEFAULT_CPU_COUNT,
            },
            command: engine,
            locks: DelegateLocks::default(),
            endpoints: RwLock::default(),
        }
    }

    fn test_identity_environment() -> Vec<(String, String)> {
        use agentkeys_protocol::sandbox_env;
        vec![
            (
                sandbox_env::BROKER_URL.into(),
                "http://host.docker.internal:8080".into(),
            ),
            (sandbox_env::CHAT_CHANNEL_ID.into(), "opchat-test".into()),
            (sandbox_env::ACTOR_OMNI.into(), actor()),
            (sandbox_env::OPERATOR_OMNI.into(), hex::encode([5; 32])),
            (
                sandbox_env::SESSION_JWT.into(),
                "test-only-actor-credential".into(),
            ),
            (
                sandbox_env::BRIDGE_TOKEN.into(),
                "test-only-in-memory".into(),
            ),
            (
                sandbox_env::MGMT_TOKEN.into(),
                "test-only-management".into(),
            ),
        ]
    }

    fn create_environment(counter: Arc<AtomicUsize>) -> CreateEnvProvider {
        Box::new(move || {
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                test_identity_environment()
            })
        })
    }

    #[tokio::test]
    async fn ensure_reuses_owned_runtime_without_reminting_credentials() {
        let engine = Arc::new(FakeEngine::default());
        let runtime = runtime(engine.clone());
        let creates = Arc::new(AtomicUsize::new(0));
        let first = runtime
            .ensure_for_delegate_with_envs(
                &device(),
                &actor(),
                &[],
                create_environment(creates.clone()),
            )
            .await
            .unwrap();
        let second = runtime
            .ensure_for_delegate_with_envs(
                &format!("0x{}", device().to_uppercase()),
                &actor(),
                &[],
                create_environment(creates.clone()),
            )
            .await
            .unwrap();
        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.sandbox_id, second.sandbox_id);
        assert_eq!(creates.load(Ordering::SeqCst), 1);
        let calls = engine.calls.lock().unwrap();
        let (arguments, input) = calls
            .iter()
            .find(|(arguments, _)| arguments[1] == "create" && arguments[0] == "container")
            .unwrap();
        assert_eq!(arguments.last(), Some(&image_id()));
        for flag in [
            "--pull=never",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=1000:1000",
        ] {
            assert!(arguments.iter().any(|argument| argument == flag));
        }
        assert!(!arguments
            .iter()
            .any(|argument| argument.contains("test-only-in-memory")
                || argument.contains("docker.sock")));
        let input = std::str::from_utf8(input.as_ref().unwrap()).unwrap();
        assert!(input.contains("AGENTKEYS_BRIDGE_TOKEN=test-only-in-memory"));
        assert!(input.contains("AGENTKEYS_CHAIN=anvil"));
        assert_eq!(
            runtime.instance_mgmt_endpoint(&container_id()).unwrap().0,
            "http://127.0.0.1:18090"
        );
    }

    #[tokio::test]
    async fn concurrent_ensure_creates_once_and_failed_start_can_be_retried() {
        let engine = Arc::new(FakeEngine::default());
        let runtime = runtime(engine.clone());
        let creates = Arc::new(AtomicUsize::new(0));
        let device = device();
        let actor = actor();
        let (first, second) = tokio::join!(
            runtime.ensure_for_delegate_with_envs(
                &device,
                &actor,
                &[],
                create_environment(creates.clone())
            ),
            runtime.ensure_for_delegate_with_envs(
                &device,
                &actor,
                &[],
                create_environment(creates.clone())
            ),
        );
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_ne!(first.created, second.created);
        assert_eq!(first.sandbox_id, second.sandbox_id);
        assert_eq!(creates.load(Ordering::SeqCst), 1);
        runtime.kill_for_device(&device).await.unwrap();
        engine.start_fails.store(true, Ordering::SeqCst);
        let failed = runtime
            .ensure_for_delegate_with_envs(
                &device,
                &actor,
                &[],
                create_environment(creates.clone()),
            )
            .await
            .unwrap_err();
        assert!(failed.to_string().contains("start failed"));
        assert!(runtime.instance_mgmt_endpoint(&container_id()).is_none());
        engine.start_fails.store(false, Ordering::SeqCst);
        assert!(
            runtime
                .ensure_for_delegate_with_envs(
                    &device,
                    &actor,
                    &[],
                    create_environment(creates.clone())
                )
                .await
                .unwrap()
                .created
        );
        runtime.kill_for_device(&device).await.unwrap();
        assert!(!engine.network_exists.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn foreign_actor_is_denied_without_create_or_delete() {
        let engine = Arc::new(FakeEngine::default());
        *engine.container.lock().unwrap() = Some(container(
            "test-runtime",
            &hex::encode([9; 32]),
            "127.0.0.1",
            true,
        ));
        let runtime = runtime(engine.clone());
        let creates = Arc::new(AtomicUsize::new(0));
        let error = runtime
            .ensure_for_delegate_with_envs(
                &device(),
                &actor(),
                &[],
                create_environment(creates.clone()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("actor ownership mismatch"));
        assert_eq!(creates.load(Ordering::SeqCst), 0);
        assert!(engine.container.lock().unwrap().is_some());
        assert!(engine
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(arguments, _)| !["create", "rm", "start"].contains(&arguments[1].as_str())));
    }

    #[tokio::test]
    async fn teardown_never_removes_foreign_namespace_or_nonlocal_port() {
        for (namespace, host, expected_error) in [
            ("foreign", "127.0.0.1", "outside this runtime namespace"),
            ("test-runtime", "0.0.0.0", "beyond localhost"),
        ] {
            let engine = Arc::new(FakeEngine::default());
            *engine.container.lock().unwrap() = Some(container(namespace, &actor(), host, true));
            let error = runtime(engine.clone())
                .kill_for_device(&device())
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected_error));
            assert!(engine.container.lock().unwrap().is_some());
            assert!(engine
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(arguments, _)| arguments[1] != "rm"));
        }
        let engine = Arc::new(FakeEngine::default());
        *engine.container.lock().unwrap() =
            Some(container("test-runtime", &actor(), "127.0.0.1", true));
        assert_eq!(
            runtime(engine.clone())
                .kill_for_device(&device())
                .await
                .unwrap(),
            vec![container_id()]
        );
        assert!(engine.container.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_image_preserves_the_stopped_container() {
        let engine = Arc::new(FakeEngine::default());
        *engine.container.lock().unwrap() =
            Some(container("test-runtime", &actor(), "127.0.0.1", false));
        engine.image_missing.store(true, Ordering::SeqCst);
        let result = runtime(engine.clone())
            .ensure_for_delegate_with_envs(
                &device(),
                &actor(),
                &[],
                crate::sandbox_backend::no_create_envs(),
            )
            .await;
        assert!(result.unwrap_err().to_string().contains("image missing"));
        assert!(engine.container.lock().unwrap().is_some());
        assert!(engine
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(arguments, _)| arguments[1] != "rm"));
    }

    #[test]
    fn configuration_rejects_nonlocal_chain_and_remote_engine() {
        let base = BTreeMap::from([
            ("AGENT_TERRIER_SANDBOX_IMAGE", "local:test"),
            ("AGENT_TERRIER_LOCAL_DEV", "1"),
            ("AGENTKEYS_CHAIN", "anvil"),
        ]);
        assert!(
            DockerConfig::from_lookup(|key| base.get(key).map(|value| value.to_string()))
                .unwrap()
                .is_some()
        );
        for (key, value) in [
            ("AGENT_TERRIER_LOCAL_DEV", "0"),
            ("AGENTKEYS_CHAIN", "public-chain"),
            ("AGENT_TERRIER_DOCKER_SOCKET", "tcp://remote.example:2375"),
        ] {
            let mut config = base.clone();
            config.insert(key, value);
            assert!(DockerConfig::from_lookup(|key| config
                .get(key)
                .map(|value| value.to_string()))
            .is_err());
        }
    }

    #[test]
    fn environment_injection_and_chain_override_fail_without_echoing_values() {
        for (name, value) in [
            ("CUSTOM", "test-canary\nINJECTED=1"),
            ("AGENTKEYS_CHAIN", "public-chain"),
        ] {
            let error = environment_input(
                &actor(),
                &[(name.into(), value.into())],
                test_identity_environment(),
            )
            .unwrap_err();
            assert!(!error.to_string().contains(value));
        }
        assert!(normalize_identity("../other-runtime").is_err());
        let mut conflicting = test_identity_environment();
        conflicting.push((
            agentkeys_protocol::sandbox_env::ACTOR_OMNI.into(),
            hex::encode([9; 32]),
        ));
        assert!(environment_input(&actor(), &[], conflicting)
            .unwrap_err()
            .to_string()
            .contains("conflicting"));
    }

    #[tokio::test]
    async fn incomplete_identity_never_creates_or_replaces_a_runtime() {
        use agentkeys_protocol::sandbox_env;
        for missing in [
            sandbox_env::SESSION_JWT,
            sandbox_env::BRIDGE_TOKEN,
            sandbox_env::MGMT_TOKEN,
            sandbox_env::BROKER_URL,
        ] {
            let engine = Arc::new(FakeEngine::default());
            *engine.container.lock().unwrap() =
                Some(container("test-runtime", &actor(), "127.0.0.1", false));
            let mut environment = test_identity_environment();
            environment.retain(|(name, _)| name != missing);
            let error = runtime(engine.clone())
                .ensure_for_delegate_with_envs(
                    &device(),
                    &actor(),
                    &environment,
                    crate::sandbox_backend::no_create_envs(),
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("required sandbox configuration")
                    || error.to_string().contains("exactly one actor credential")
            );
            assert!(engine.container.lock().unwrap().is_some());
            assert!(engine
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(arguments, _)| !["create", "start", "rm"].contains(&arguments[1].as_str())));
        }
    }

    #[tokio::test]
    async fn unrelated_credentials_and_conflicting_actor_are_rejected_without_side_effects() {
        for (name, value, expected) in [
            (
                "UNRELATED_SECRET",
                "test-sensitive-canary".to_string(),
                "unsupported sandbox environment entry",
            ),
            (
                agentkeys_protocol::sandbox_env::ACTOR_OMNI,
                hex::encode([9; 32]),
                "actor identity mismatch",
            ),
        ] {
            let engine = Arc::new(FakeEngine::default());
            let mut environment = test_identity_environment();
            environment.retain(|(key, _)| key != name);
            environment.push((name.into(), value.clone()));
            let error = runtime(engine.clone())
                .ensure_for_delegate_with_envs(
                    &device(),
                    &actor(),
                    &environment,
                    crate::sandbox_backend::no_create_envs(),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected));
            assert!(!error.to_string().contains(&value));
            assert!(engine
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(arguments, _)| !["create", "rm", "start"].contains(&arguments[1].as_str())));
        }
    }

    #[tokio::test]
    async fn foreign_network_is_preserved_and_owned_network_is_removed_after_teardown() {
        let engine = Arc::new(FakeEngine::default());
        engine.network_exists.store(true, Ordering::SeqCst);
        engine.foreign_network.store(true, Ordering::SeqCst);
        let runtime = runtime(engine.clone());
        let error = runtime
            .ensure_for_delegate_with_envs(
                &device(),
                &actor(),
                &test_identity_environment(),
                crate::sandbox_backend::no_create_envs(),
            )
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("network ownership or isolation mismatch"));
        assert!(engine
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(arguments, _)| !["create", "start", "rm"].contains(&arguments[1].as_str())));
        engine.foreign_network.store(false, Ordering::SeqCst);
        runtime
            .ensure_for_delegate_with_envs(
                &device(),
                &actor(),
                &test_identity_environment(),
                crate::sandbox_backend::no_create_envs(),
            )
            .await
            .unwrap();
        runtime.kill_for_device(&device()).await.unwrap();
        assert!(!engine.network_exists.load(Ordering::SeqCst));
        assert!(engine.container.lock().unwrap().is_none());
        assert!(runtime.instance_mgmt_endpoint(&container_id()).is_none());
    }
}
