use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_protocol::{model_runtime, sandbox_env};
use agentkeys_runtime::docker_runtime::{DockerConfig, DockerRuntime, ManagedDockerConfig};
use agentkeys_runtime::managed_agent::SERVICE_ENVIRONMENT;
use agentkeys_runtime::{CreateEnvProvider, SandboxBackend, SandboxRuntime};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};

mod support;
use support::Engine;

#[derive(Clone)]
struct ModelFixture {
    token: String,
    requests: Arc<Mutex<Vec<Value>>>,
}

async fn completion(
    State(fixture): State<ModelFixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {}", fixture.token))
    {
        return (StatusCode::UNAUTHORIZED, "").into_response();
    }
    fixture.requests.lock().unwrap().push(body.clone());
    let mut response = String::new();
    for (delta, finish) in [
        (json!({"role":"assistant"}), Value::Null),
        (
            json!({"content":"Managed Docker fixture reply."}),
            Value::Null,
        ),
        (json!({}), json!("stop")),
    ] {
        response.push_str(&format!(
            "data: {}\n\n",
            json!({"id":"local-completion", "object":"chat.completion.chunk",
            "model":body["model"], "choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
        ));
    }
    response.push_str("data: [DONE]\n\n");
    ([("content-type", "text/event-stream")], response).into_response()
}

fn credential_callback(
    actor: &str,
    origin: &str,
    model_token: &str,
    bridge_token: &str,
    count: Arc<AtomicUsize>,
) -> CreateEnvProvider {
    let mut environment: BTreeMap<String, String> = SERVICE_ENVIRONMENT
        .iter()
        .map(|(_, name)| ((*name).into(), origin.into()))
        .collect();
    environment.insert(model_runtime::BASE_URL.into(), format!("{origin}/v1"));
    environment.insert(model_runtime::API_KEY.into(), model_token.into());
    environment.insert(model_runtime::MODEL_ID.into(), "local-test-model".into());
    environment.insert(model_runtime::SPEECH_URL.into(), origin.into());
    environment.insert(sandbox_env::MEMORY_NS.into(), "fixture-memory".into());
    environment.insert(sandbox_env::ACTOR_OMNI.into(), actor.into());
    environment.insert(sandbox_env::OPERATOR_OMNI.into(), hex::encode([8; 32]));
    environment.insert(sandbox_env::CHAT_CHANNEL_ID.into(), "opchat-fixture".into());
    environment.insert(sandbox_env::BRIDGE_TOKEN.into(), bridge_token.into());
    environment.insert(
        sandbox_env::MGMT_TOKEN.into(),
        uuid::Uuid::new_v4().simple().to_string(),
    );
    environment.insert(
        sandbox_env::SESSION_JWT.into(),
        uuid::Uuid::new_v4().simple().to_string(),
    );
    Box::new(move || {
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            environment.into_iter().collect()
        })
    })
}

async fn chat(
    runtime: &dyn SandboxRuntime,
    id: &str,
    token: &str,
    message: &str,
) -> Result<reqwest::Response> {
    let (origin, headers) = runtime
        .instance_mgmt_endpoint(id)
        .context("runtime endpoint missing")?;
    let mut request = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?
        .post(format!("{origin}/v1/chat"))
        .bearer_auth(token)
        .json(&json!({"text":message}));
    for (name, value) in headers {
        request = request.header(name, value);
    }
    Ok(request.send().await?)
}

#[tokio::test]
#[ignore = "explicit local Docker socket, reviewed preloaded agent image and Node required"]
async fn managed_docker_controller_transport_and_persistence() -> Result<()> {
    let socket = PathBuf::from(std::env::var("AGENT_TERRIER_TEST_DOCKER_SOCKET")?);
    let image = std::env::var("AGENT_TERRIER_TEST_AGENT_IMAGE")?;
    let namespace = format!("terrier-managed-{}", uuid::Uuid::new_v4().simple());
    let config = DockerConfig {
        socket: socket.clone(),
        namespace: namespace.clone(),
        image,
        memory_mib: 512,
        cpu_count: 1,
    };
    let engine = Engine { socket };
    let fixture = ModelFixture {
        token: uuid::Uuid::new_v4().simple().to_string(),
        requests: Arc::default(),
    };
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/v1/chat/completions", post(completion))
        .fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let mut profile = ChainProfile::load_builtin("anvil")?;
    profile.rpc.http = origin.clone();
    let settings = ManagedDockerConfig {
        chain_profile: profile,
        transport_script: std::fs::canonicalize(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packages/agent-terrier-runtime/service-transport.mjs"),
        )?,
    };
    let profile_file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(&profile_file, &settings.chain_profile)?;
    let configuration = BTreeMap::from([
        ("AGENT_TERRIER_SANDBOX_IMAGE", config.image.clone()),
        ("AGENT_TERRIER_LOCAL_DEV", "1".into()),
        (
            "AGENTKEYS_CHAIN_PROFILE_FILE",
            profile_file.path().to_str().unwrap().into(),
        ),
        (
            "AGENT_TERRIER_DOCKER_SOCKET",
            config.socket.to_str().unwrap().into(),
        ),
        ("AGENT_TERRIER_RUNTIME_NAMESPACE", namespace.clone()),
        (
            "AGENT_TERRIER_SANDBOX_MEMORY_MIB",
            config.memory_mib.to_string(),
        ),
        ("AGENT_TERRIER_SANDBOX_CPUS", config.cpu_count.to_string()),
        (
            "AGENT_TERRIER_TRANSPORT_SCRIPT",
            settings.transport_script.to_str().unwrap().into(),
        ),
    ]);
    let runtime = SandboxBackend::from_lookup(|name| configuration.get(name).cloned())
        .await?
        .context("configured runtime missing")?;
    let first_device = hex::encode([1; 32]);
    let first_actor = hex::encode([2; 32]);
    let second_device = hex::encode([3; 32]);
    let second_actor = hex::encode([4; 32]);
    let bridge_token = uuid::Uuid::new_v4().simple().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let credentials = |actor: &str| {
        credential_callback(actor, &origin, &fixture.token, &bridge_token, count.clone())
    };
    let scenario = async {
        let first = runtime
            .ensure_for_delegate_with_envs(
                &first_device,
                &first_actor,
                &[],
                credentials(&first_actor),
            )
            .await?;
        let inspected = engine.inspect(&first.sandbox_id).await?;
        ensure!(
            inspected["HostConfig"]["NetworkMode"] == "none"
                && inspected["HostConfig"]["ReadonlyRootfs"] == true,
            "managed container isolation changed"
        );
        let saved_metadata = serde_json::to_string(&inspected)?;
        ensure!(
            !saved_metadata.contains(&bridge_token)
                && !saved_metadata.contains(&fixture.token)
                && !saved_metadata.contains("AGENTKEYS_SESSION_JWT"),
            "Docker metadata retained runtime credentials"
        );
        let denial = chat(&*runtime, &first.sandbox_id, "wrong-proof", "denied").await?;
        ensure!(
            denial.status() == StatusCode::UNAUTHORIZED
                && fixture.requests.lock().unwrap().is_empty(),
            "unauthorized chat reached model"
        );
        let marker = format!("remember-{}", uuid::Uuid::new_v4().simple());
        let reply = chat(&*runtime, &first.sandbox_id, &bridge_token, &marker).await?;
        ensure!(reply.status().is_success(), "managed chat failed");
        ensure!(
            reply
                .text()
                .await?
                .contains("Managed Docker fixture reply."),
            "model reply missing"
        );
        let reused = runtime
            .ensure_for_delegate_with_envs(
                &first_device,
                &first_actor,
                &[],
                credentials(&first_actor),
            )
            .await?;
        ensure!(
            reused.sandbox_id == first.sandbox_id
                && !reused.created
                && count.load(Ordering::SeqCst) == 1,
            "managed reuse minted credentials"
        );
        let competing = DockerRuntime::connect_managed(config.clone(), settings.clone()).await?;
        ensure!(
            competing
                .ensure_for_delegate_with_envs(
                    &first_device,
                    &first_actor,
                    &[],
                    credentials(&first_actor)
                )
                .await
                .is_err()
                && count.load(Ordering::SeqCst) == 1,
            "second controller adopted active runtime"
        );
        drop(competing);
        runtime.kill_for_device(&first_device).await?;
        let restored = runtime
            .ensure_for_delegate_with_envs(
                &first_device,
                &first_actor,
                &[],
                credentials(&first_actor),
            )
            .await?;
        ensure!(
            restored.sandbox_id != first.sandbox_id,
            "container was not replaced"
        );
        ensure!(
            chat(&*runtime, &restored.sandbox_id, &bridge_token, "recall")
                .await?
                .status()
                .is_success(),
            "restored chat failed"
        );
        ensure!(
            fixture.requests.lock().unwrap().last().unwrap()["messages"]
                .to_string()
                .contains(&marker),
            "container replacement lost conversation"
        );
        let abandoned = DockerRuntime::connect_managed(config.clone(), settings.clone()).await?;
        let second = abandoned
            .ensure_for_delegate_with_envs(
                &second_device,
                &second_actor,
                &[],
                credentials(&second_actor),
            )
            .await?;
        ensure!(
            chat(
                &abandoned,
                &second.sandbox_id,
                &bridge_token,
                "separate actor"
            )
            .await?
            .status()
            .is_success(),
            "second actor chat failed"
        );
        ensure!(
            !fixture.requests.lock().unwrap().last().unwrap()["messages"]
                .to_string()
                .contains(&marker),
            "cross-actor conversation leak"
        );
        drop(abandoned);
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if engine.inspect(&second.sandbox_id).await?["State"]["Running"] == false {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("abandoned controller left container running")??;
        runtime.kill_for_device(&second_device).await?;
        let failure_source = tempfile::tempdir()?;
        let failure_script = failure_source.path().join("fail.mjs");
        std::fs::write(&failure_script, "process.exit(23);\n")?;
        let failing = DockerRuntime::connect_managed(
            config.clone(),
            ManagedDockerConfig {
                transport_script: std::fs::canonicalize(failure_script)?,
                ..settings.clone()
            },
        )
        .await?;
        ensure!(
            failing
                .ensure_for_delegate_with_envs(
                    &second_device,
                    &second_actor,
                    &[],
                    credentials(&second_actor)
                )
                .await
                .is_err(),
            "broken transport started runtime"
        );
        let remaining = engine
            .run(&[
                "container",
                "ls",
                "--all",
                "--filter",
                &format!("label=org.agent-terrier.device={second_device}"),
                "--filter",
                &format!("label=org.agent-terrier.runtime={namespace}"),
                "--format",
                "{{.ID}}",
            ])
            .await?;
        ensure!(
            remaining.is_empty(),
            "failed startup left an owned container"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    for (device, actor) in [
        (&first_device, &first_actor),
        (&second_device, &second_actor),
    ] {
        runtime.kill_for_device(device).await?;
        DockerRuntime::connect_managed(config.clone(), settings.clone())
            .await?
            .reset_state_for_device(device, actor)
            .await?;
    }
    server.abort();
    scenario
}
