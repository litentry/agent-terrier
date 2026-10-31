use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentkeys_protocol::sandbox_env;
use agentkeys_runtime::docker_runtime::{DockerConfig, DockerRuntime};
use agentkeys_runtime::{CreateEnvProvider, SandboxRuntime};
use anyhow::{ensure, Context, Result};
use serde_json::Value;

struct Engine {
    socket: PathBuf,
}

impl Engine {
    async fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
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

    async fn inspect(&self, id: &str) -> Result<Value> {
        let values: Vec<Value> =
            serde_json::from_slice(&self.run(&["container", "inspect", id]).await?)?;
        values.into_iter().next().context("container missing")
    }
}

fn environment(actor: &str, count: Arc<AtomicUsize>) -> CreateEnvProvider {
    let actor = actor.to_owned();
    Box::new(move || {
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            let mut environment = vec![
                (
                    sandbox_env::BROKER_URL.into(),
                    "http://host.docker.internal:8080".into(),
                ),
                (sandbox_env::CHAT_CHANNEL_ID.into(), "qualification".into()),
                (sandbox_env::ACTOR_OMNI.into(), actor),
                (sandbox_env::OPERATOR_OMNI.into(), hex::encode([5; 32])),
                (
                    sandbox_env::SESSION_JWT.into(),
                    "synthetic-local-session".into(),
                ),
                (
                    sandbox_env::MGMT_TOKEN.into(),
                    "synthetic-local-management".into(),
                ),
                (
                    sandbox_env::BRIDGE_TOKEN.into(),
                    "synthetic-local-bridge".into(),
                ),
            ];
            environment.extend(agentkeys_protocol::model_runtime::relay_environment(
                "http://host.docker.internal:8077/v1",
                "synthetic-local-model".into(),
            ));
            environment
        })
    })
}

#[tokio::test]
#[ignore = "explicit local Docker socket and preloaded BusyBox image required; see Docker qualification wiki"]
async fn real_docker_lifecycle_and_isolation() -> Result<()> {
    let socket = PathBuf::from(std::env::var("AGENT_TERRIER_TEST_DOCKER_SOCKET")?);
    ensure!(
        socket.is_absolute(),
        "qualification needs an absolute local socket"
    );
    let base_image = std::env::var("AGENT_TERRIER_TEST_BASE_IMAGE")?;
    ensure!(
        !base_image.starts_with('-') && !base_image.contains(char::is_whitespace),
        "invalid base image"
    );
    let engine = Engine {
        socket: socket.clone(),
    };
    engine.run(&["image", "inspect", &base_image]).await?;
    let namespace = format!("terrier-check-{}", uuid::Uuid::new_v4().simple());
    let fixture_image = format!("{namespace}:fixture");
    let context = tempfile::tempdir()?;
    let bridge_port = sandbox_env::SANDBOX_BRIDGE_PORT;
    let daemon_port = sandbox_env::SANDBOX_DAEMON_PORT;
    let entrypoint = format!("mkdir -p /tmp/www && echo local-runtime-ok > /tmp/www/index.html && httpd -f -p {bridge_port} -h /tmp/www & exec httpd -f -p {daemon_port} -h /tmp");
    let command = serde_json::to_string(&["sh", "-c", &entrypoint])?;
    std::fs::write(
        context.path().join("Dockerfile"),
        format!("FROM {base_image}\nCMD {command}\n"),
    )?;
    engine
        .run(&[
            "build",
            "--pull=false",
            "--network=none",
            "--tag",
            &fixture_image,
            context.path().to_str().context("non-UTF8 test path")?,
        ])
        .await?;
    let config = DockerConfig {
        socket,
        namespace: namespace.clone(),
        image: fixture_image.clone(),
        memory_mib: 128,
        cpu_count: 1,
    };
    let runtime = DockerRuntime::connect(config.clone()).await?;
    let first_device = hex::encode([1; 32]);
    let second_device = hex::encode([2; 32]);
    let first_actor = hex::encode([3; 32]);
    let second_actor = hex::encode([4; 32]);
    let count = Arc::new(AtomicUsize::new(0));
    let qualification = async {
        let first = runtime.ensure_for_delegate_with_envs(&first_device, &first_actor, &[], environment(&first_actor, count.clone())).await?;
        ensure!(first.created, "first ensure must create");
        let again = runtime.ensure_for_delegate_with_envs(&first_device, &first_actor, &[], environment(&first_actor, count.clone())).await?;
        ensure!(!again.created && again.sandbox_id == first.sandbox_id && count.load(Ordering::SeqCst) == 1, "reuse must not remint");
        let metadata = engine.inspect(&first.sandbox_id).await?;
        ensure!(metadata["Config"]["User"] == "1000:1000" && metadata["HostConfig"]["ReadonlyRootfs"] == true, "runtime confinement missing");
        ensure!(metadata["HostConfig"]["CapDrop"].as_array().is_some_and(|items| items.iter().any(|item| item == "ALL")), "capabilities not dropped");
        ensure!(metadata["Mounts"].as_array().is_some_and(|items| items.iter().all(|item| item["Type"] == "tmpfs")), "unexpected host mount");
        let configuration = metadata["Config"]["Env"].as_array().context("environment missing")?;
        ensure!(configuration.iter().filter_map(Value::as_str).any(|value| value == "AGENTKEYS_MODEL_API_KEY=synthetic-local-model"), "model relay configuration missing");
        ensure!(!configuration.iter().filter_map(Value::as_str).any(|value| value.starts_with("AWS_") || value.starts_with("DOCKER_")), "host credentials inherited");
        let response = engine.run(&["exec", &first.sandbox_id, "sh", "-c", &format!("test \"$(id -u)\" = 1000 && touch /tmp/writable && ! touch /forbidden 2>/dev/null && wget -qO- http://127.0.0.1:{bridge_port}")]).await?;
        ensure!(response == b"local-runtime-ok\n", "positive local HTTP control failed");
        ensure!(metadata["NetworkSettings"]["Ports"].as_object().is_some_and(|ports| ports.values().all(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty))), "container ports must not be published");
        let (endpoint, headers) = runtime.instance_mgmt_endpoint(&first.sandbox_id).context("missing host management endpoint")?;
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let mut request = client.get(&endpoint);
            for (name, value) in &headers { request = request.header(name, value); }
            if let Ok(response) = request.send().await {
                if response.status().is_success() && response.text().await? == "local-runtime-ok\n" { break; }
            }
            ensure!(tokio::time::Instant::now() < deadline, "authorized host management endpoint is unavailable");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        ensure!(client.get(&endpoint).send().await?.status() == 403, "missing forwarding proof was accepted");
        ensure!(runtime.ensure_for_delegate_with_envs(&first_device, &second_actor, &[], environment(&second_actor, count.clone())).await.is_err(), "foreign actor reused the runtime");
        ensure!(count.load(Ordering::SeqCst) == 1, "denial minted a credential");
        let foreign = DockerRuntime::connect(DockerConfig { namespace: format!("foreign-{}", uuid::Uuid::new_v4().simple()), ..config.clone() }).await?;
        ensure!(foreign.booted_image_info(&first.sandbox_id).await.is_err(), "foreign namespace accessed metadata");
        ensure!(foreign.kill_for_device(&first_device).await?.is_empty(), "foreign namespace removed a runtime");
        ensure!(engine.inspect(&first.sandbox_id).await?["State"]["Running"] == true, "negative test changed the authorized runtime");
        let second = runtime.ensure_for_delegate_with_envs(&second_device, &second_actor, &[], environment(&second_actor, count.clone())).await?;
        let second_metadata = engine.inspect(&second.sandbox_id).await?;
        let second_response = engine.run(&["exec", &second.sandbox_id, "wget", "-T", "2", "-qO-", &format!("http://127.0.0.1:{bridge_port}")]).await?;
        ensure!(second_response == b"local-runtime-ok\n", "cross-runtime target positive control failed");
        let network = format!("{namespace}-{second_device}");
        let second_ip = second_metadata["NetworkSettings"]["Networks"][&network]["IPAddress"].as_str().context("second runtime address missing")?;
        ensure!(engine.run(&["exec", &first.sandbox_id, "wget", "-T", "1", "-qO-", &format!("http://{second_ip}:{bridge_port}")]).await.is_err(), "cross-runtime network access succeeded");
        let (second_endpoint, second_headers) = runtime.instance_mgmt_endpoint(&second.sandbox_id).context("second management endpoint missing")?;
        let mut wrong_proof = client.get(&second_endpoint);
        for (name, value) in &headers { wrong_proof = wrong_proof.header(name, value); }
        ensure!(wrong_proof.send().await?.status() == 403, "another runtime forwarding proof was accepted");
        let mut authorized = client.get(&second_endpoint);
        for (name, value) in &second_headers { authorized = authorized.header(name, value); }
        ensure!(authorized.send().await?.text().await? == "local-runtime-ok\n", "second host positive control failed");
        let host_port = reqwest::Url::parse(&second_endpoint)?.port().context("host management port missing")?;
        let denied = engine.run(&["exec", &first.sandbox_id, "sh", "-c", &format!("! wget -T 2 -S -O- http://host.docker.internal:{host_port} 2>&1")]).await?;
        ensure!(std::str::from_utf8(&denied)?.contains("403 Forbidden"), "host forwarding did not refuse the other actor");
        ensure!(engine.inspect(&second.sandbox_id).await?["State"]["Running"] == true, "cross-runtime probe changed the target");
        engine.run(&["container", "stop", "--time", "1", &first.sandbox_id]).await?;
        let restarted = runtime.ensure_for_delegate_with_envs(&first_device, &first_actor, &[], environment(&first_actor, count.clone())).await?;
        ensure!(restarted.created && restarted.sandbox_id != first.sandbox_id && count.load(Ordering::SeqCst) == 3, "restart did not create a fresh runtime credential");
        ensure!(runtime.kill_for_device(&first_device).await? == [restarted.sandbox_id.clone()], "remove returned wrong runtime");
        ensure!(runtime.instance_mgmt_endpoint(&restarted.sandbox_id).is_none() && runtime.live_for_device(&first_device).await?.is_empty(), "removed runtime remained discoverable");
        ensure!(runtime.live_for_device(&second_device).await?.len() == 1, "removal affected another device");
        Ok::<_, anyhow::Error>(())
    }.await;
    let first_cleanup = runtime.kill_for_device(&first_device).await;
    let second_cleanup = runtime.kill_for_device(&second_device).await;
    let image_cleanup = engine.run(&["image", "rm", &fixture_image]).await;
    qualification?;
    first_cleanup?;
    second_cleanup?;
    image_cleanup?;
    Ok(())
}
