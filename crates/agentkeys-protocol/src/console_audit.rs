use crate::console::ApiAuditEvent;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleAuditQuery {
    pub cursor: Option<String>,
    pub actor_id: Option<String>,
    pub limit: Option<usize>,
    pub roots_only: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsoleAuditRecord {
    pub event: ApiAuditEvent,
    pub operator_omni: String,
    pub actor_omni: Option<String>,
    pub block_number: u64,
    pub log_index: u64,
    pub timestamp: u64,
    pub topics: Vec<String>,
    pub data: String,
    pub envelope_hash: Option<String>,
    pub merkle_root: Option<String>,
    pub entry_count: Option<u64>,
    pub op_kind: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsoleAuditPage {
    pub operator_omni: String,
    pub latest_block: u64,
    pub records: Vec<ConsoleAuditRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiAuditPage {
    pub events: Vec<ApiAuditEvent>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}
