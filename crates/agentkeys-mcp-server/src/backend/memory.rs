//! Memory-worker request shapes.
//!
//! Mirrors `agentkeys_worker_memory::handlers::{PutRequest, GetRequest}`.
//! Namespace is passed at the request body level for Phase 1 (per the PR
//! plan §8.2: lifting it into a SIGNED CapPayload field is M4 follow-up).

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct MemoryPutBody {
    pub cap: Value,
    pub plaintext_b64: String,
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct MemoryGetBody {
    pub cap: Value,
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
pub struct MemoryPutResp {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct MemoryGetResp {
    pub ok: bool,
    pub plaintext_b64: String,
}
