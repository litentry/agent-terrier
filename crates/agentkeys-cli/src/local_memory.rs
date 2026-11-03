use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentkeys_backend_client::protocol::{
    console::default_stored_version,
    sandbox_actions::{RECALL_MAX_ENTRY_BYTES, RECALL_MAX_NAMESPACE_BYTES},
    web_api::{ApiMemoryEntry, MasterMemoryPlantRequest},
    ContextKind,
};
use agentkeys_core::{device_crypto::DeviceKey, protected_file};
use agentkeys_web_core::{
    console_documents::ConsoleDocuments,
    data::{DataClient, DataEndpoints, DataError, DataSession},
    device::DeviceIdentity,
    document_helpers::{valid_history_coords, ApiMemoryEntryExt},
};
use anyhow::{anyhow, ensure, Result};
use serde_json::{json, Value};

use crate::{local_data, CommandContext};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum MemoryAction {
    Plant,
    Read,
}

#[derive(clap::Args)]
pub struct MemoryOptions {
    pub action: MemoryAction,
    pub namespace: String,
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub body_stdin: bool,
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub device_key_file: String,
    #[arg(long)]
    pub session_file: String,
    #[arg(long)]
    pub broker_url: String,
    #[arg(long)]
    pub memory_url: String,
    #[arg(long)]
    pub config_url: String,
    #[arg(long)]
    pub signer_url: String,
    #[arg(long)]
    pub credential_url: String,
}

fn request_error(error: DataError) -> anyhow::Error {
    match error {
        DataError::Http { status, .. } => anyhow!("local memory request failed (HTTP {status})"),
        DataError::Transport(_) => anyhow!("local memory service is unreachable"),
        _ => anyhow!("local memory response is invalid or unsupported"),
    }
}

pub async fn execute(context: &CommandContext, options: &MemoryOptions) -> Result<Value> {
    let development = context.development_signing()?;
    for endpoint in [
        &options.broker_url,
        &options.memory_url,
        &options.config_url,
        &options.signer_url,
        &options.credential_url,
    ] {
        development.require_local_service(endpoint)?;
    }
    let planting = matches!(options.action, MemoryAction::Plant);
    ensure!(
        planting == options.body_stdin && planting == options.key.is_some(),
        "only memory plant requires --key and --body-stdin"
    );
    ensure!(
        planting || options.title.is_none(),
        "--title requires memory plant"
    );
    ensure!(
        options.namespace.len() <= RECALL_MAX_NAMESPACE_BYTES
            && valid_history_coords(
                &options.namespace,
                options.key.as_deref().unwrap_or("entry")
            ),
        "invalid knowledge namespace or entry key"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let key = DeviceKey::load(&options.device_key_file)?;
    let session = local_data::load_session(
        &options.session_file,
        &options.broker_url,
        &options.operator_omni,
        &key,
        now,
    )?;
    let encoded = protected_file::read_text(&options.device_key_file)?;
    let device = DeviceIdentity::from_secret_hex(&encoded)?;
    ensure!(
        device.device_key_hash()? == key.device_key_hash()?,
        "owner request key changed during loading"
    );
    drop(encoded);
    let documents = ConsoleDocuments::new(DataClient::with_client(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?,
        DataEndpoints {
            broker_url: options.broker_url.clone(),
            signer_url: options.signer_url.clone(),
            memory_url: options.memory_url.clone(),
            config_url: options.config_url.clone(),
            credential_url: options.credential_url.clone(),
            audit_url: None,
            classify_url: None,
        },
    ));
    let authority = DataSession {
        bearer: &session.session.session_jwt,
        operator_omni: &options.operator_omni,
        actor_omni: &options.operator_omni,
        device: &device,
        now_unix_seconds: now,
    };
    match options.action {
        MemoryAction::Read => {
            let document = documents
                .namespace_read(&authority, &options.namespace)
                .await
                .map_err(request_error)?;
            let entries = document
                .document
                .into_iter()
                .map(|stored| ApiMemoryEntry::from_stored(&options.namespace, stored))
                .collect::<Vec<_>>();
            Ok(json!({"development_only":true, "namespace":options.namespace, "entries":entries}))
        }
        MemoryAction::Plant => {
            let mut body = String::new();
            std::io::stdin()
                .take(RECALL_MAX_ENTRY_BYTES as u64 + 1)
                .read_to_string(&mut body)?;
            ensure!(!body.trim().is_empty(), "knowledge body must not be empty");
            let key = options.key.as_deref().expect("validated entry key");
            let entry = ApiMemoryEntry {
                ns: options.namespace.clone(),
                key: key.into(),
                title: options.title.as_deref().unwrap_or(key).into(),
                bytes: body.len() as u64,
                version: default_stored_version(),
                updated: now.to_string(),
                preview: String::new(),
                body,
                content_hash: String::new(),
                kind: ContextKind::Knowledge,
            };
            ensure!(
                serde_json::to_vec(&entry.to_stored())?.len() <= RECALL_MAX_ENTRY_BYTES,
                "knowledge entry exceeds the local retrieval size limit"
            );
            let result = documents
                .plant(
                    &authority,
                    MasterMemoryPlantRequest {
                        entries: vec![entry],
                    },
                )
                .await
                .map_err(request_error)?;
            ensure!(result.taxonomy_status == "ok",
                "knowledge was stored but its category index failed; retry the same plant operation");
            Ok(json!({"development_only":true, "namespace":options.namespace, "result":result}))
        }
    }
}
