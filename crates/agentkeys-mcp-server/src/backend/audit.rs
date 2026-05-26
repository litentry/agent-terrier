//! Audit-worker request shapes.
//!
//! Mirrors `agentkeys_worker_audit::handlers::AppendV2Request`. The
//! envelope version is pinned at 1 per `agentkeys_core::audit::ENVELOPE_VERSION`;
//! if that constant changes, this needs to change too — covered by an
//! integration smoke test.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Serialize)]
pub struct AuditAppendV2 {
    pub version: u8,
    pub ts_unix: u64,
    pub actor_omni: String,
    pub operator_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
    pub intent_commitment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditAppendV2Resp {
    pub ok: bool,
    pub envelope_hash: String,
}
