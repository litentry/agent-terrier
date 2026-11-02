use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleChainDevice {
    pub device_key_hash: String,
    pub operator_omni: String,
    pub actor_omni: String,
    pub tier: u8,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleChainScope {
    pub service_ids: Vec<String>,
    pub read_only: bool,
    pub exists: bool,
    pub per_tx: String,
    pub period_cap: String,
    pub max_total: String,
    pub period_seconds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleFleetEntry {
    pub device: ConsoleChainDevice,
    pub scope: ConsoleChainScope,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleFleet {
    pub operator_omni: String,
    pub account: String,
    pub devices: Vec<ConsoleFleetEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleContract {
    pub name: String,
    pub address: String,
    pub purpose: String,
    pub deployed_at: String,
    pub explorer_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleChainInfo {
    pub name: String,
    pub display: String,
    #[ts(type = "number")]
    pub chain_id: u64,
    pub rpc: String,
    pub wss: String,
    pub explorer: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub finality: String,
    pub contracts: Vec<ConsoleContract>,
    pub daemon_chain: String,
    pub daemon_broker: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ConsoleConfig {
    pub chain: ConsoleChainInfo,
    pub signer_url: String,
    pub config_url: String,
    pub memory_url: String,
    pub credential_url: String,
    pub audit_url: Option<String>,
    pub channel_url: String,
    pub classify_url: String,
}
