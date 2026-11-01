use std::time::{SystemTime, UNIX_EPOCH};

use agentkeys_backend_client::protocol::RuntimeTeardownOutcome;
use agentkeys_core::device_crypto::DeviceKey;
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};

use crate::agent_operation::{AgentOperationJournal, AgentOperationRecord};
use crate::{agent_admin, local_data, CommandContext};

#[derive(clap::Args)]
pub struct AgentOptions {
    #[command(subcommand)]
    pub action: AgentAction,
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub device_key_file: String,
    #[arg(long)]
    pub session_file: String,
    #[arg(long)]
    pub broker_url: String,
    #[arg(long)]
    pub key_file: String,
    #[arg(long)]
    pub operations_dir: String,
    #[arg(long, default_value = "localhost")]
    pub rp_id: String,
}

#[derive(clap::Subcommand)]
pub enum AgentAction {
    Spawn {
        #[arg(long)]
        label: String,
        #[arg(long, default_value = "")]
        preset_id: String,
        #[arg(long, default_value = "")]
        memory_ns: String,
        #[arg(long)]
        memory_inherited: bool,
    },
    Archive {
        #[arg(long)]
        device_key_hash: String,
        #[arg(long, default_value = "")]
        memory_ns: String,
    },
    Receipt {
        #[arg(long)]
        operation_file: String,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("local agent operation is incomplete; inspect the receipt before retrying")]
pub struct IncompleteOperation(pub Value);

fn hash(value: &Value) -> Option<String> {
    let raw = value.as_str()?.strip_prefix("0x")?;
    (raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("0x{}", raw.to_ascii_lowercase()))
}

fn no_error(value: &Value) -> bool {
    value.is_object() && (value["error"].is_null() || value["error"].as_str() == Some(""))
}

fn receipt(action: &str, response: &Value) -> Value {
    let device = hash(&response["device_key_hash"]);
    let transaction = hash(&response["tx_hash"]);
    let operation = hash(&response["user_op_hash"]);
    let pending = response["pending"] == true;
    let block = response["block_number"]
        .as_str()
        .and_then(|value| u64::from_str_radix(value.strip_prefix("0x")?, 16).ok());
    let confirmed = !pending
        && (response["pending"].is_null() || response["pending"].is_boolean())
        && transaction.is_some()
        && operation.is_some()
        && block.is_some();
    let collection = if action == "spawn" {
        "spawned"
    } else {
        "archived"
    };
    let row = response["ceremony"][collection]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| device.is_some() && hash(&row["device_key_hash"]) == device)
        });
    let relay_ready = row.is_some_and(|row| {
        no_error(row)
            && no_error(&row["gate"])
            && matches!(
                (action, row["gate"]["status"].as_str()),
                ("spawn", Some("provisioned" | "recovered"))
                    | ("archive", Some("deprovisioned" | "not-provisioned"))
            )
    });
    let runtime_ready = row.is_some_and(|row| {
        no_error(&row["sandbox"])
            && row["sandbox"]["status"] == "running"
            && row["sandbox"]["sandbox_id"]
                .as_str()
                .is_some_and(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    });
    let cleanup = response["ceremony"]["runtime_teardown"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find_map(|row| {
                let outcome: RuntimeTeardownOutcome = serde_json::from_value(row.clone()).ok()?;
                (device.is_some() && hash(&json!(outcome.device_key_hash)) == device)
                    .then_some(outcome)
            })
        });
    let runtime_stopped = cleanup
        .as_ref()
        .is_some_and(|outcome| outcome.runtime_stopped);
    let context_removed = cleanup
        .as_ref()
        .is_some_and(|outcome| outcome.context_removed);
    let resources_kept = row.is_some_and(|row| row["resources_kept"] == true);
    let complete = confirmed
        && relay_ready
        && if action == "spawn" {
            runtime_ready
        } else {
            runtime_stopped
                && context_removed
                && resources_kept
                && cleanup
                    .as_ref()
                    .is_some_and(|outcome| outcome.error.is_none())
        };
    json!({"development_only":true, "action":action, "complete":complete,
        "chain_confirmed":confirmed, "pending":pending, "tx_hash":transaction,
        "user_op_hash":operation, "block_number":block, "device_key_hash":device,
        "actor_omni":response["actor_omni"].as_str().and_then(|actor| hash(&json!(agentkeys_backend_client::protocol::normalize_omni_0x(actor)))), "relay_ready":relay_ready,
        "runtime_ready":runtime_ready, "runtime_stopped":runtime_stopped,
        "context_removed":context_removed, "resources_kept":resources_kept})
}

pub async fn execute(context: &CommandContext, options: &AgentOptions) -> Result<Value> {
    let development = context.development_signing()?;
    development.require_local_service(&options.broker_url)?;
    let key =
        DeviceKey::load(&options.device_key_file).context("load existing owner request key")?;
    let binding = local_data::CredentialOptions {
        action: local_data::CredentialAction::Fetch,
        service: String::new(),
        operator_omni: options.operator_omni.clone(),
        device_key_file: options.device_key_file.clone(),
        session_file: options.session_file.clone(),
        broker_url: options.broker_url.clone(),
        cred_url: String::new(),
        secret_stdin: false,
    };
    let session = local_data::load_session(
        &binding,
        &key,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let bearer = &session.session.session_jwt;
    let claimed = agent_admin::operator_omni_from_bearer(bearer)
        .map_err(|_| anyhow!("invalid local session bearer"))?;
    ensure!(
        claimed
            .trim_start_matches("0x")
            .eq_ignore_ascii_case(options.operator_omni.trim_start_matches("0x")),
        "session bearer belongs to another owner"
    );
    let request_device_key_hash = key.device_key_hash()?;
    let journal = AgentOperationJournal {
        directory: std::path::Path::new(&options.operations_dir),
        operator_omni: &options.operator_omni,
        broker_url: &options.broker_url,
        request_device_key_hash: &request_device_key_hash,
    };
    let (action, result) = match &options.action {
        AgentAction::Spawn {
            label,
            preset_id,
            memory_ns,
            memory_inherited,
        } => {
            ensure!(
                !label.is_empty()
                    && label.len() <= 128
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                "agent label must contain 1 to 128 letters, digits, hyphens or underscores"
            );
            (
                "spawn",
                agent_admin::agent_spawn(
                    &development,
                    &options.broker_url,
                    label,
                    preset_id,
                    memory_ns,
                    *memory_inherited,
                    &options.key_file,
                    &options.rp_id,
                    bearer,
                    Some(&journal),
                )
                .await,
            )
        }
        AgentAction::Archive {
            device_key_hash,
            memory_ns,
        } => {
            ensure!(
                hash(&json!(device_key_hash)).is_some(),
                "invalid device key hash"
            );
            (
                "archive",
                agent_admin::agent_archive(
                    &development,
                    &options.broker_url,
                    device_key_hash,
                    true,
                    memory_ns,
                    &options.key_file,
                    &options.rp_id,
                    bearer,
                    Some(&journal),
                )
                .await,
            )
        }
        AgentAction::Receipt { operation_file } => {
            let record = AgentOperationRecord::load(operation_file, &journal, &development)?;
            let result =
                agent_admin::agent_receipt(&development, &options.broker_url, bearer, &record)
                    .await
                    .and_then(|mut response| {
                        response["device_key_hash"] = json!(record.device_key_hash);
                        response["actor_omni"] = json!(record.actor_omni);
                        Ok(serde_json::to_string(&response)?)
                    });
            (record.action.name(), result)
        }
    };
    let response: Value = match result {
        Ok(encoded) => {
            serde_json::from_str(&encoded).map_err(|_| anyhow!("invalid local agent response"))?
        }
        Err(error) => {
            if let Some(unknown) = error.downcast_ref::<agent_admin::SubmissionUncertain>() {
                let mut pending = receipt(
                    action,
                    &json!({"pending":true,"user_op_hash":unknown.user_op_hash}),
                );
                pending["submission_status"] = json!("unknown");
                return Err(IncompleteOperation(pending).into());
            }
            if let Some(status) = error.downcast_ref::<agent_admin::RequestStatus>() {
                return Err(anyhow!("local agent request failed (HTTP {})", status.0));
            }
            return Err(anyhow!("local agent request failed; check local services and the protected development passkey"));
        }
    };
    let output = receipt(action, &response);
    if output["complete"] != true {
        return Err(IncompleteOperation(output).into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmed() -> Value {
        json!({"device_key_hash":format!("0x{}", "11".repeat(32)),
            "tx_hash":format!("0x{}", "22".repeat(32)), "block_number":"0x1",
            "user_op_hash":format!("0x{}", "33".repeat(32))})
    }

    #[test]
    fn partial_spawn_keeps_transaction_identity_without_echoing_backend_errors() {
        let mut response = confirmed();
        response["actor_omni"] = json!("55".repeat(32));
        assert_eq!(
            receipt("spawn", &response)["actor_omni"],
            format!("0x{}", "55".repeat(32))
        );
        response["ceremony"] = json!({"spawned":[{"device_key_hash":response["device_key_hash"],
            "gate":{"status":"provisioned","error":null},
            "sandbox":{"status":"running","sandbox_id":"44".repeat(32),"error":null}}]});
        assert_eq!(receipt("spawn", &response)["complete"], true);
        response["ceremony"]["spawned"][0]["sandbox"]["error"] =
            json!("synthetic-secret-must-not-echo");
        let output = receipt("spawn", &response);
        assert_eq!(output["complete"], false);
        assert_eq!(output["chain_confirmed"], true);
        assert_eq!(output["tx_hash"], response["tx_hash"]);
        assert!(!output.to_string().contains("synthetic-secret"));
        response["pending"] = json!(true);
        assert_eq!(receipt("spawn", &response)["chain_confirmed"], false);
        response["pending"] = json!("invalid");
        assert_eq!(receipt("spawn", &response)["chain_confirmed"], false);
    }

    #[test]
    fn archive_requires_confirmed_cleanup_and_retained_resources() {
        let mut response = confirmed();
        response["ceremony"] = json!({"archived":[{"device_key_hash":response["device_key_hash"],
            "resources_kept":true,"gate":{"status":"deprovisioned","error":null}}]});
        assert_eq!(receipt("archive", &response)["complete"], false);
        response["ceremony"]["runtime_teardown"] = json!([RuntimeTeardownOutcome {
            device_key_hash: response["device_key_hash"].as_str().unwrap().into(),
            context_removed: true,
            runtime_stopped: true,
            error: None,
        }]);
        assert_eq!(receipt("archive", &response)["complete"], true);
        response["ceremony"]["runtime_teardown"][0]["context_removed"] = json!(false);
        response["ceremony"]["runtime_teardown"][0]["error"] = json!("spawn_context_delete_failed");
        assert_eq!(receipt("archive", &response)["runtime_stopped"], true);
        assert_eq!(receipt("archive", &response)["complete"], false);
        response["ceremony"]["runtime_teardown"][0]["runtime_stopped"] = json!(false);
        assert_eq!(receipt("archive", &response)["complete"], false);
        assert_eq!(receipt("archive", &json!({}))["complete"], false);
    }
}
