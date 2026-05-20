//! Per-operator in-memory event queue + flush logic.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::merkle::{keccak256, merkle_proof, merkle_root, Bytes32};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 0x-prefixed 32-byte hex.
    pub actor_omni: String,
    /// 0x-prefixed 32-byte hex (keccak256(service_name)).
    pub service_hash: String,
    /// 0=STORE, 1=READ, 2=TEARDOWN.
    pub op_type: u8,
    /// 0x-prefixed 32-byte hex.
    pub payload_hash: String,
    /// Unix seconds, set server-side at queue time.
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlushResult {
    pub operator_omni: String,
    pub merkle_root_hex: String,
    pub entry_count: u64,
    pub leaves_path: String,
    pub events: Vec<AuditEvent>,
}

#[derive(Default)]
pub struct State {
    /// operator_omni (0x...) → queue of pending events.
    queues: Mutex<HashMap<String, Vec<AuditEvent>>>,
    /// Where to drop a leaves-jsonl file per flush. Defaults to /tmp.
    pub leaves_dir: String,
}

impl State {
    pub fn new(leaves_dir: String) -> Self {
        Self { queues: Mutex::new(HashMap::new()), leaves_dir }
    }

    /// Append a single event. Returns the new queue length for this operator.
    pub async fn append(&self, operator_omni: String, mut event: AuditEvent) -> usize {
        if event.timestamp == 0 {
            event.timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }
        let mut q = self.queues.lock().await;
        let v = q.entry(operator_omni).or_default();
        v.push(event);
        v.len()
    }

    /// Drain + flush a single operator's queue, computing the Merkle root.
    /// Returns `None` if the queue is empty. Writes leaves to a JSONL file
    /// under `leaves_dir` named after the root hex.
    pub async fn flush(&self, operator_omni: &str) -> anyhow::Result<Option<FlushResult>> {
        let events = {
            let mut q = self.queues.lock().await;
            q.remove(operator_omni).unwrap_or_default()
        };
        if events.is_empty() {
            return Ok(None);
        }
        let leaves: Vec<Bytes32> = events.iter().map(event_leaf).collect();
        let root = merkle_root(&leaves);
        let root_hex = format!("0x{}", hex::encode(root));

        let path = format!("{}/audit-leaves-{}.jsonl", self.leaves_dir, &root_hex[2..]);
        let mut file_content = String::new();
        for (i, e) in events.iter().enumerate() {
            let proof = merkle_proof(&leaves, i);
            let proof_hex: Vec<String> =
                proof.iter().map(|p| format!("0x{}", hex::encode(p))).collect();
            let leaf_hex = format!("0x{}", hex::encode(leaves[i]));
            let line = serde_json::json!({
                "leaf_index": i,
                "leaf": leaf_hex,
                "proof": proof_hex,
                "event": e,
            });
            file_content.push_str(&serde_json::to_string(&line)?);
            file_content.push('\n');
        }
        std::fs::write(&path, file_content)?;

        Ok(Some(FlushResult {
            operator_omni: operator_omni.to_string(),
            merkle_root_hex: root_hex,
            entry_count: events.len() as u64,
            leaves_path: path,
            events,
        }))
    }

    /// Drain + flush every operator's queue. Returns one FlushResult per
    /// non-empty operator.
    pub async fn flush_all(&self) -> anyhow::Result<Vec<FlushResult>> {
        let omnis: Vec<String> = {
            let q = self.queues.lock().await;
            q.keys().cloned().collect()
        };
        let mut out = Vec::new();
        for omni in omnis {
            if let Some(r) = self.flush(&omni).await? {
                out.push(r);
            }
        }
        Ok(out)
    }
}

/// Canonical leaf encoding: keccak256(abi.encode(actor, service, op_type,
/// payload_hash, timestamp)) — matches what an on-chain reconstruction
/// would compute for proof verification.
fn event_leaf(e: &AuditEvent) -> Bytes32 {
    let mut buf = Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    buf.extend_from_slice(&decode32(&e.actor_omni));
    buf.extend_from_slice(&decode32(&e.service_hash));
    let mut op_padded = [0u8; 32];
    op_padded[31] = e.op_type;
    buf.extend_from_slice(&op_padded);
    buf.extend_from_slice(&decode32(&e.payload_hash));
    let mut ts_padded = [0u8; 32];
    ts_padded[24..32].copy_from_slice(&e.timestamp.to_be_bytes());
    buf.extend_from_slice(&ts_padded);
    keccak256(&buf)
}

fn decode32(s: &str) -> Bytes32 {
    let stripped = s.trim_start_matches("0x");
    let v = hex::decode(stripped).unwrap_or_default();
    let mut out = [0u8; 32];
    let n = v.len().min(32);
    out[..n].copy_from_slice(&v[..n]);
    out
}

pub type SharedState = Arc<State>;

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(actor: &str, svc: &str, op: u8, payload: &str) -> AuditEvent {
        AuditEvent {
            actor_omni: format!("0x{}", hex::encode(keccak256(actor.as_bytes()))),
            service_hash: format!("0x{}", hex::encode(keccak256(svc.as_bytes()))),
            op_type: op,
            payload_hash: format!("0x{}", hex::encode(keccak256(payload.as_bytes()))),
            timestamp: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn flush_empty_returns_none() {
        let s = State::new("/tmp".to_string());
        let r = s.flush("0xabc").await.unwrap();
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn append_then_flush_drains() {
        let s = State::new("/tmp".to_string());
        s.append("0xabc".into(), ev("actor", "openrouter", 0, "blob-1")).await;
        s.append("0xabc".into(), ev("actor", "openrouter", 1, "blob-1")).await;
        let r = s.flush("0xabc").await.unwrap().expect("non-empty");
        assert_eq!(r.entry_count, 2);
        assert!(r.merkle_root_hex.starts_with("0x"));
        // Second flush is empty.
        assert!(s.flush("0xabc").await.unwrap().is_none());
        std::fs::remove_file(&r.leaves_path).ok();
    }
}
