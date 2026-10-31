use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use agentkeys_protocol::{runtime_layout::STATE_DIRECTORY, sandbox_env};
use agentkeys_runtime::managed_agent::{
    RuntimeBootstrap, MAX_BOOTSTRAP_BYTES, RUNTIME_SCRIPT, STARTUP_TIMEOUT_SECONDS,
};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

#[derive(Parser)]
struct Arguments {
    #[arg(long, default_value = STATE_DIRECTORY)]
    state_dir: PathBuf,
    #[arg(long, default_value = RUNTIME_SCRIPT)]
    runtime_script: PathBuf,
    #[arg(long, default_value = "agentkeys-daemon")]
    daemon_binary: PathBuf,
    #[arg(long, default_value_t = sandbox_env::SANDBOX_DAEMON_PORT)]
    daemon_port: u16,
    #[arg(long, default_value_t = sandbox_env::SANDBOX_BRIDGE_PORT)]
    agent_port: u16,
}

fn private_directory(path: &Path, create: bool) -> Result<()> {
    if create && !path.try_exists()? {
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && std::fs::canonicalize(path)? == path
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() },
        "runtime state must be a canonical private owned directory"
    );
    Ok(())
}

fn lock_state(path: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join(".runtime.lock"))?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() },
        "unsafe runtime lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "runtime state is already in use"
    );
    Ok(lock)
}

fn child_command(
    program: &Path,
    home: &Path,
    environment: &std::collections::BTreeMap<String, String>,
) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ["PATH", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .envs(environment)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn stop(child: &mut Child) {
    if let Some(id) = child.id() {
        unsafe {
            libc::kill(id as libc::pid_t, libc::SIGTERM);
        }
    }
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

async fn health(client: &reqwest::Client, port: u16, daemon: bool) -> bool {
    let Ok(response) = client
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
    else {
        return false;
    };
    if !response.status().is_success() {
        return false;
    }
    if !daemon {
        return true;
    }
    response
        .json::<serde_json::Value>()
        .await
        .is_ok_and(|body| body["ok"] == true && body["surface"] == "ui-bridge")
}

async fn authenticated_health(
    client: &reqwest::Client,
    port: u16,
    route: &str,
    token: &str,
) -> bool {
    client
        .get(format!("http://127.0.0.1:{port}{route}"))
        .bearer_auth(token)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

async fn run(arguments: Arguments) -> Result<()> {
    ensure!(
        arguments.daemon_port != 0
            && arguments.agent_port != 0
            && arguments.daemon_port != arguments.agent_port,
        "runtime ports must be distinct and nonzero"
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let mut bytes = Zeroizing::new(Vec::new());
    let mut limited_input = (&mut input).take((MAX_BOOTSTRAP_BYTES + 1) as u64);
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(STARTUP_TIMEOUT_SECONDS), limited_input.read_until(b'\n', &mut bytes)) => {
            result.context("bootstrap input deadline exceeded")??;
        }
        _ = terminate.recv() => return Ok(()),
        _ = interrupt.recv() => return Ok(()),
    }
    ensure!(
        bytes.len() <= MAX_BOOTSTRAP_BYTES && bytes.last() == Some(&b'\n'),
        "invalid or oversized bootstrap frame"
    );
    let configuration: RuntimeBootstrap = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid bootstrap configuration"))?;
    configuration.validate()?;
    drop(bytes);
    let daemon_reservation =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, arguments.daemon_port))?;
    let agent_reservation =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, arguments.agent_port))?;
    private_directory(&arguments.state_dir, false)?;
    let _lock = lock_state(&arguments.state_dir)?;
    let home = arguments.state_dir.join("home");
    let sessions = arguments.state_dir.join("runtime");
    let work = arguments.state_dir.join("work");
    for directory in [&home, &sessions, &work] {
        private_directory(directory, true)?;
    }
    let temporary = tempfile::tempdir()?;
    let profile = temporary.path().join("chain-profile.json");
    agentkeys_core::protected_file::write(
        profile.to_str().context("invalid profile path")?,
        &serde_json::to_vec(&configuration.chain_profile)?,
        true,
    )?;
    let daemon_origin = format!("http://127.0.0.1:{}", arguments.daemon_port);
    let agent_origin = format!("http://127.0.0.1:{}", arguments.agent_port);
    let mut daemon_command =
        child_command(&arguments.daemon_binary, &home, &configuration.environment);
    daemon_command
        .env("AGENTKEYS_CHAIN_PROFILE_FILE", &profile)
        .args([
            "--ui-bridge",
            "--ui-bridge-bind",
            &format!("127.0.0.1:{}", arguments.daemon_port),
        ])
        .env("AGENTKEYS_CHAT_BRIDGE_URL", &agent_origin)
        .env("AGENTKEYS_SANDBOX_BRIDGE_URL", &agent_origin)
        .env(
            "AGENTKEYS_SANDBOX_BRIDGE_TOKEN",
            &configuration.environment[sandbox_env::BRIDGE_TOKEN],
        );
    drop(daemon_reservation);
    let mut daemon = daemon_command.spawn().context("daemon could not start")?;
    let mut agent_command =
        child_command(Path::new("node"), &home, &configuration.agent_environment());
    agent_command
        .arg(&arguments.runtime_script)
        .arg("--state-dir")
        .arg(&sessions)
        .arg("--work-dir")
        .arg(&work)
        .arg("--port")
        .arg(arguments.agent_port.to_string())
        .arg("--daemon-url")
        .arg(&daemon_origin);
    drop(agent_reservation);
    let mut agent = match agent_command.spawn() {
        Ok(child) => child,
        Err(_) => {
            stop(&mut daemon).await;
            anyhow::bail!("agent could not start");
        }
    };
    let result = async {
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(500)).build()?;
        let mut extra = [0u8; 1];
        let controller = async {
            let length = input.read(&mut extra).await?;
            ensure!(length == 0, "unexpected additional bootstrap input");
            Ok::<(), anyhow::Error>(())
        };
        tokio::pin!(controller);
        let readiness = async {
            loop {
                let token = &configuration.environment[sandbox_env::BRIDGE_TOKEN];
                if health(&client, arguments.daemon_port, true).await && health(&client, arguments.agent_port, false).await
                    && authenticated_health(&client, arguments.daemon_port, "/v1/sandbox/self/actions", token).await
                    && authenticated_health(&client, arguments.agent_port, "/v1/jobs", token).await {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(STARTUP_TIMEOUT_SECONDS), readiness) => { result.context("runtime readiness deadline exceeded")??; }
            result = &mut controller => return result,
            _ = terminate.recv() => return Ok(()),
            _ = interrupt.recv() => return Ok(()),
            _ = daemon.wait() => anyhow::bail!("daemon exited before readiness"),
            _ = agent.wait() => anyhow::bail!("agent exited before readiness"),
        }
        let readiness = serde_json::json!({ "ready": true, "surface": "local-agent-processes", "daemon_url": daemon_origin, "agent_url": agent_origin });
        let mut output = tokio::io::stdout();
        output.write_all(format!("{readiness}\n").as_bytes()).await?;
        output.flush().await?;
        tokio::select! {
            result = &mut controller => result,
            _ = terminate.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
            _ = daemon.wait() => anyhow::bail!("daemon exited unexpectedly"),
            _ = agent.wait() => anyhow::bail!("agent exited unexpectedly"),
        }
    }.await;
    stop(&mut agent).await;
    stop(&mut daemon).await;
    result
}

fn main() {
    let arguments = Arguments::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("async runtime");
    let result = runtime.block_on(run(arguments));
    if result.is_err() {
        eprintln!("Local agent startup or supervision failed; check explicit configuration and component readiness.");
    }
    std::process::exit(i32::from(result.is_err()));
}
