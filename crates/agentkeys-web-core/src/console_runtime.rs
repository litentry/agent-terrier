use crate::{
    broker::BrokerClient,
    console::{broker_error, decode, encode, invalid},
    console_documents::ConsoleDocuments,
    data::{DataClient, DataError, DataSession},
    document_helpers::date_utc,
};
use agentkeys_protocol::{console::*, console_chain::ConsoleFleet, BridgeProxyBody, PresetBundle};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

fn norm(value: &str) -> String {
    value.trim_start_matches("0x").to_ascii_lowercase()
}
pub async fn actor_device(
    broker: &BrokerClient,
    session: &DataSession<'_>,
    actor: Option<&str>,
) -> Result<String, DataError> {
    let fleet: ConsoleFleet = broker
        .get_json("/v1/console/fleet", Some(session.bearer))
        .await
        .map_err(broker_error)?;
    let devices: Vec<_> = fleet
        .devices
        .iter()
        .filter(|entry| {
            !entry.device.revoked
                && entry.device.tier == 2
                && actor.is_none_or(|actor| norm(actor) == norm(&entry.device.actor_omni))
        })
        .collect();
    if devices.len() != 1 {
        return Err(invalid("select one active delegate for this operation"));
    }
    Ok(devices[0].device.device_key_hash.clone())
}
pub async fn bridge(
    broker: &BrokerClient,
    session: &DataSession<'_>,
    device: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, DataError> {
    broker
        .post_json(
            "/v1/agent/bridge",
            Some(session.bearer),
            &BridgeProxyBody {
                operator_omni: session.operator_omni.into(),
                device_key_hash: device.into(),
                sandbox_id: None,
                method: Some(method.into()),
                path: path.into(),
                body,
            },
        )
        .await
        .map_err(broker_error)
}
fn confirm_context_files(result: &Value, field: &str, expected: &[&str]) -> Result<(), DataError> {
    if result.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(invalid("runtime did not confirm context application"));
    }
    let written = result
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("runtime omitted {field}")))?;
    if expected
        .iter()
        .any(|name| !written.iter().any(|item| item.as_str() == Some(name)))
    {
        return Err(invalid(format!("runtime did not confirm all {field}")));
    }
    Ok(())
}
pub async fn apply_persona(
    broker: &BrokerClient,
    session: &DataSession<'_>,
    actor: &str,
    body: &str,
    version: u32,
) -> ApiPersonaEditResponse {
    let result = async {
        let device = actor_device(broker, session, Some(actor)).await?;
        let result = bridge(
            broker,
            session,
            &device,
            "POST",
            "/v1/context/apply",
            Some(json!({"files":{"soul":STANDARD.encode(body)},"restart":true})),
        )
        .await?;
        confirm_context_files(&result, "files_written", &["SOUL.md"])?;
        Ok::<_, DataError>(result)
    }
    .await;
    match result {
        Ok(value) => ApiPersonaEditResponse {
            ok: true,
            version,
            applied: true,
            apply_detail: value.to_string(),
        },
        Err(error) => ApiPersonaEditResponse {
            ok: true,
            version,
            applied: false,
            apply_detail: format!("Persona saved; runtime application failed: {error}"),
        },
    }
}
pub async fn apply_preset(
    broker: &BrokerClient,
    data: &DataClient,
    session: &DataSession<'_>,
    actor: &str,
    device_hash: &str,
    preset_id: &str,
) -> Result<Value, DataError> {
    if preset_id.is_empty()
        || !preset_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid("invalid preset id"));
    }
    let bundle: PresetBundle = broker
        .get_json(&format!("/v1/presets/{preset_id}"), Some(session.bearer))
        .await
        .map_err(broker_error)?;
    let verified_device = actor_device(broker, session, Some(actor)).await?;
    if norm(&verified_device) != norm(device_hash) {
        return Err(invalid("preset target differs from active delegate"));
    }
    let documents = ConsoleDocuments::new(data.clone());
    let version = documents
        .persona_edit(
            session,
            actor,
            &bundle.soul_md,
            &date_utc(session.now_unix_seconds),
        )
        .await?;
    let skills: serde_json::Map<String, Value> = bundle
        .skills
        .iter()
        .map(|document| {
            (
                document.filename.clone(),
                json!(STANDARD.encode(&document.content)),
            )
        })
        .collect();
    let knowledge: serde_json::Map<String, Value> = bundle
        .knowledge
        .iter()
        .map(|document| {
            (
                document.filename.clone(),
                json!(STANDARD.encode(&document.content)),
            )
        })
        .collect();
    let result=bridge(broker,session,device_hash,"POST","/v1/context/apply",Some(json!({"files":{"soul":STANDARD.encode(&bundle.soul_md)},"skills":skills,"knowledge":knowledge,"restart":true}))).await
        .map_err(|error|invalid(format!("Persona v{version} saved; preset runtime application failed: {error}")))?;
    confirm_context_files(&result, "files_written", &["SOUL.md"])
        .map_err(|error| invalid(format!("Persona v{version} saved; {error}")))?;
    for (field, documents) in [
        ("skills_written", &bundle.skills),
        ("knowledge_written", &bundle.knowledge),
    ] {
        let expected = documents
            .iter()
            .map(|document| document.filename.as_str())
            .collect::<Vec<_>>();
        if !expected.is_empty() {
            confirm_context_files(&result, field, &expected)
                .map_err(|error| invalid(format!("Persona v{version} saved; {error}")))?;
        }
    }
    Ok(
        json!({"ok":true,"preset_id":preset_id,"version":version,"applied":true,"detail":result.to_string(),"sandbox_id":result.get("sandbox_id")}),
    )
}

pub async fn request(
    broker: &BrokerClient,
    data: &DataClient,
    session: &DataSession<'_>,
    method: &str,
    path: &str,
    body: Value,
) -> Result<Option<Value>, DataError> {
    let documents = ConsoleDocuments::new(data.clone());
    let result = match (method, path) {
        ("POST", "/v1/master/agent/preset/reapply") => {
            let actor = body
                .get("actor_omni")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("actor_omni required"))?;
            let manifest: crate::data::VersionedConfig<BindingManifest> = documents
                .config_read(session, BINDING_MANIFEST_SERVICE)
                .await?;
            let row = manifest
                .bindings
                .iter()
                .find(|row| norm(&row.actor_omni) == norm(actor))
                .ok_or_else(|| invalid("delegate metadata missing"))?;
            apply_preset(
                broker,
                data,
                session,
                actor,
                &row.device_key_hash,
                row.preset_id
                    .as_deref()
                    .ok_or_else(|| invalid("delegate has no preset"))?,
            )
            .await?
        }
        ("POST", "/v1/agent/image-status") => {
            let request: DaemonImageStatusRequest = decode(body)?;
            let result:Value=broker.post_json(path,Some(session.bearer),&json!({"operator_omni":session.operator_omni,"device_key_hashes":request.device_key_hashes})).await.map_err(broker_error)?;
            encode(decode::<ApiImageStatus>(result)?)?
        }
        ("POST", "/v1/agent/update") => {
            let request: DaemonAgentUpdateRequest = decode(body)?;
            let result:Value=broker.post_json(path,Some(session.bearer),&json!({"operator_omni":session.operator_omni,"device_key_hash":request.device_key_hash,"force":request.force})).await.map_err(broker_error)?;
            let mapped = ApiAgentUpdateResult {
                device_key_hash: request.device_key_hash.clone(),
                old_sandbox_ids: decode(
                    result
                        .get("old_sandbox_ids")
                        .cloned()
                        .ok_or_else(|| invalid("update receipt missing old_sandbox_ids"))?,
                )?,
                sandbox_id: result
                    .pointer("/sandbox/sandbox_id")
                    .and_then(Value::as_str)
                    .map(String::from),
                sandbox_status: result
                    .pointer("/sandbox/status")
                    .and_then(Value::as_str)
                    .map(String::from),
                sandbox_error: result
                    .pointer("/sandbox/error")
                    .and_then(Value::as_str)
                    .map(String::from),
                session_migrated: result
                    .pointer("/session/migrated")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| invalid("update receipt missing session migration status"))?,
                session_detail: result
                    .pointer("/session/detail")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("update receipt missing session detail"))?
                    .into(),
            };
            let mut manifest: crate::data::VersionedConfig<BindingManifest> = documents
                .config_read(session, BINDING_MANIFEST_SERVICE)
                .await?;
            if let Some(row) = manifest
                .bindings
                .iter_mut()
                .find(|row| norm(&row.device_key_hash) == norm(&request.device_key_hash))
            {
                let mut runtime = row.runtime.clone().unwrap_or(ApiRuntimeStatus {
                    gate_status: String::new(),
                    gate_error: None,
                    spawn_error: None,
                });
                runtime.spawn_error = mapped.sandbox_error.clone();
                row.runtime = Some(runtime);
                row.updated_at = session.now_unix_seconds;
                let actor = row.actor_omni.clone();
                let preset = row.preset_id.clone();
                documents
                    .config_write(session, BINDING_MANIFEST_SERVICE, &manifest)
                    .await
                    .map_err(|error| {
                        invalid(format!(
                            "Runtime update completed; metadata save failed: {error}"
                        ))
                    })?;
                if mapped.sandbox_error.is_none() {
                    if let Some(preset) = preset {
                        apply_preset(
                            broker,
                            data,
                            session,
                            &actor,
                            &request.device_key_hash,
                            &preset,
                        )
                        .await?;
                    }
                }
            }
            encode(mapped)?
        }
        _ if path.starts_with("/v1/master/agent/context") && method == "GET" => {
            let actor = body
                .get("actor_omni")
                .and_then(Value::as_str)
                .map(String::from);
            let device = actor_device(broker, session, actor.as_deref()).await?;
            let result = bridge(broker, session, &device, "GET", "/v1/context/files", None).await?;
            json!({"configured":true,"files":result.get("files").ok_or_else(||invalid("runtime omitted context files"))?})
        }
        ("POST", "/v1/master/agent/restart") => {
            let device = actor_device(
                broker,
                session,
                body.get("actor_omni").and_then(Value::as_str),
            )
            .await?;
            bridge(broker, session, &device, "POST", "/v1/agent/restart", None).await?
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_application_requires_actual_file_receipts() {
        assert!(confirm_context_files(
            &json!({"ok":true,"files_written":["SOUL.md"]}),
            "files_written",
            &["SOUL.md"]
        )
        .is_ok());
        for value in [
            json!({}),
            json!({"ok":false,"files_written":["SOUL.md"]}),
            json!({"ok":true,"files_written":["USER.md"]}),
        ] {
            assert!(confirm_context_files(&value, "files_written", &["SOUL.md"]).is_err());
        }
    }
}
