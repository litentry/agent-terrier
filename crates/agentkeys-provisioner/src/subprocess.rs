use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use agentkeys_types::ProvisionEvent;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use crate::error::{ProvisionError, ProvisionResult};

#[derive(Debug, Clone)]
pub struct SubprocessConfig {
    pub wall_clock_secs: u64,
}

impl Default for SubprocessConfig {
    fn default() -> Self {
        Self { wall_clock_secs: 120 }
    }
}

#[derive(Debug)]
pub struct SubprocessOutcome {
    pub events: Vec<ProvisionEvent>,
    pub exit_code: Option<i32>,
    pub stderr: String,
}

pub async fn spawn_and_collect(
    command: &[&str],
    env: HashMap<String, String>,
    cwd: Option<&Path>,
    config: SubprocessConfig,
) -> ProvisionResult<SubprocessOutcome> {
    if command.is_empty() {
        return Err(ProvisionError::Internal("empty subprocess command".into()));
    }
    let mut cmd = Command::new(command[0]);
    cmd.args(&command[1..]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    cmd.envs(env.iter());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProvisionError::Internal("subprocess stdout missing".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProvisionError::Internal("subprocess stderr missing".into()))?;

    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = String::new();
        let _ = reader.read_to_string(&mut buf).await;
        buf
    });

    let events_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        let mut events: Vec<ProvisionEvent> = Vec::new();
        while let Some(line) = reader.next_line().await.transpose() {
            match line {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<ProvisionEvent>(trimmed) {
                        Ok(event) => events.push(event),
                        Err(source) => {
                            return Err(ProvisionError::MalformedEvent {
                                line: trimmed.to_string(),
                                source,
                            });
                        }
                    }
                }
                Err(io_err) => {
                    return Err(ProvisionError::Internal(format!(
                        "subprocess stdout read error: {io_err}"
                    )));
                }
            }
        }
        Ok(events)
    });

    let timeout_secs = config.wall_clock_secs;
    let wait_result = timeout(Duration::from_secs(timeout_secs), child.wait()).await;
    let status = match wait_result {
        Ok(result) => result?,
        Err(_elapsed) => {
            // kill the child; best-effort cleanup
            let _ = child.kill().await;
            return Err(ProvisionError::Timeout {
                timeout_secs,
            });
        }
    };

    let events = events_task
        .await
        .map_err(|e| ProvisionError::Internal(format!("events task join: {e}")))??;
    let stderr_buf = stderr_task.await.unwrap_or_default();

    if !status.success() && !events.iter().any(is_terminal_event) {
        return Err(ProvisionError::SubprocessFailed {
            exit_code: status.code(),
            stderr: stderr_buf.clone(),
        });
    }

    Ok(SubprocessOutcome {
        events,
        exit_code: status.code(),
        stderr: stderr_buf,
    })
}

fn is_terminal_event(event: &ProvisionEvent) -> bool {
    matches!(
        event,
        ProvisionEvent::Success { .. } | ProvisionEvent::Error { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn shell_command(script: &str) -> [&str; 3] {
        ["sh", "-c", Box::leak(script.to_string().into_boxed_str())]
    }

    #[tokio::test]
    async fn spawn_and_receive_progress_then_success() {
        let script = r#"
printf '{"type":"progress","step":"creating_account"}\n'
printf '{"type":"progress","step":"waiting_for_email"}\n'
printf '{"type":"success","api_key":"sk-or-v1-real12345"}\n'
"#;
        let cmd = shell_command(script);
        let outcome =
            spawn_and_collect(&cmd, HashMap::new(), None, SubprocessConfig::default())
                .await
                .expect("subprocess should succeed");
        assert_eq!(outcome.events.len(), 3);
        matches!(outcome.events.last(), Some(ProvisionEvent::Success { .. }));
    }

    #[tokio::test]
    async fn subprocess_timeout_triggers_error() {
        let cmd = shell_command("sleep 10");
        let config = SubprocessConfig { wall_clock_secs: 1 };
        let err = spawn_and_collect(&cmd, HashMap::new(), None, config)
            .await
            .expect_err("should time out");
        match err {
            ProvisionError::Timeout { timeout_secs } => assert_eq!(timeout_secs, 1),
            other => panic!("expected Timeout, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_malformed_json_aborts() {
        let script = r#"
printf '{"type":"progress","step":"ok"}\n'
printf 'not json at all\n'
printf '{"type":"success","api_key":"x"}\n'
"#;
        let cmd = shell_command(script);
        let err = spawn_and_collect(&cmd, HashMap::new(), None, SubprocessConfig::default())
            .await
            .expect_err("malformed line should abort");
        match err {
            ProvisionError::MalformedEvent { line, .. } => {
                assert_eq!(line, "not json at all");
            }
            other => panic!("expected MalformedEvent, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn subprocess_error_event_propagates_as_success_flag() {
        let script = r#"
printf '{"type":"progress","step":"starting"}\n'
printf '{"type":"error","code":"store_failed","details":"backend 500"}\n'
exit 0
"#;
        let cmd = shell_command(script);
        let outcome =
            spawn_and_collect(&cmd, HashMap::new(), None, SubprocessConfig::default())
                .await
                .expect("exit 0 with error event is a valid subprocess outcome");
        assert!(outcome
            .events
            .iter()
            .any(|e| matches!(e, ProvisionEvent::Error { .. })));
    }

    #[tokio::test]
    async fn subprocess_failed_exit_without_terminal_event() {
        let script = r#"
printf '{"type":"progress","step":"died"}\n'
exit 3
"#;
        let cmd = shell_command(script);
        let err = spawn_and_collect(&cmd, HashMap::new(), None, SubprocessConfig::default())
            .await
            .expect_err("non-zero exit without terminal event should error");
        match err {
            ProvisionError::SubprocessFailed { exit_code, .. } => {
                assert_eq!(exit_code, Some(3));
            }
            other => panic!("expected SubprocessFailed, got {:?}", other),
        }
    }
}
