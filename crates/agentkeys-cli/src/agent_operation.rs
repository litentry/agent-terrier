use std::path::Path;

use agentkeys_backend_client::protocol::BuildAcceptUserOpResponse;
use agentkeys_core::protected_file;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::development_signing::DevelopmentSigning;

const RECORD_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOperationKind {
    Spawn,
    Archive,
}

impl AgentOperationKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Archive => "archive",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationRecord {
    version: u32,
    development_only: bool,
    operator_omni: String,
    broker_url: String,
    request_device_key_hash: String,
    pub action: AgentOperationKind,
    pub device_key_hash: String,
    pub actor_omni: Option<String>,
    pub build: BuildAcceptUserOpResponse,
}

pub struct AgentOperationJournal<'a> {
    pub directory: &'a Path,
    pub operator_omni: &'a str,
    pub broker_url: &'a str,
    pub request_device_key_hash: &'a str,
}

impl AgentOperationJournal<'_> {
    pub fn save(&self, action: AgentOperationKind, response: &impl Serialize) -> Result<()> {
        let response = serde_json::to_value(response)?;
        let mut build: BuildAcceptUserOpResponse = serde_json::from_value(response.clone())?;
        build.user_op.signature = "0x".into();
        let operation_hash = canonical_hash(&build.user_op_hash)?;
        let record = AgentOperationRecord {
            version: RECORD_VERSION,
            development_only: true,
            operator_omni: canonical_hash(self.operator_omni)?,
            broker_url: self.broker_url.to_owned(),
            request_device_key_hash: canonical_hash(self.request_device_key_hash)?,
            action,
            device_key_hash: canonical_hash(
                response["device_key_hash"]
                    .as_str()
                    .context("missing device identity")?,
            )?,
            actor_omni: response["actor_omni"]
                .as_str()
                .map(canonical_hash)
                .transpose()?,
            build,
        };
        let path = self.directory.join(format!("{operation_hash}.json"));
        protected_file::write(
            path.to_str().context("operation path must be UTF-8")?,
            &serde_json::to_vec(&record)?,
            true,
        )
        .context("save protected operation before submission")?;
        std::fs::File::open(self.directory)?.sync_all()?;
        Ok(())
    }
}

impl AgentOperationRecord {
    pub fn load(
        path: &str,
        binding: &AgentOperationJournal<'_>,
        development: &DevelopmentSigning,
    ) -> Result<Self> {
        let contents =
            protected_file::read_text(path).context("read protected operation record")?;
        let record: Self = serde_json::from_str(&contents).context("invalid operation record")?;
        ensure!(
            record.version == RECORD_VERSION && record.development_only,
            "operation is not a supported development record"
        );
        ensure!(
            record.operator_omni == canonical_hash(binding.operator_omni)?,
            "operation belongs to another owner"
        );
        ensure!(
            record.broker_url == binding.broker_url,
            "operation belongs to another broker"
        );
        ensure!(
            record.request_device_key_hash == canonical_hash(binding.request_device_key_hash)?,
            "operation belongs to another request key"
        );
        canonical_hash(&record.device_key_hash)?;
        if let Some(actor) = &record.actor_omni {
            canonical_hash(actor)?;
        }
        ensure!(
            record.build.user_op.signature == "0x",
            "operation record must not contain a signature"
        );
        development.verify_build(
            &record.build.user_op,
            &record.build.user_op_hash,
            &record.build.entry_point,
            record.build.chain_id,
        )?;
        Ok(record)
    }
}

fn canonical_hash(value: &str) -> Result<String> {
    let normalized = agentkeys_backend_client::protocol::normalize_omni_0x(value);
    let raw = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
        .context("identity must be a prefixed hash")?;
    ensure!(
        raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "identity must be a 32-byte hash"
    );
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}
