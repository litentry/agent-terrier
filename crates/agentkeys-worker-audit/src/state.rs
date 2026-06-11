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

/// One V2 envelope queued for the tier-A on-chain anchor (#229). The leaf
/// IS the `envelope_hash` (already `keccak256(canonical_cbor(envelope))`),
/// so explorers seeing the on-chain root can verify a fetched envelope
/// against its Merkle proof directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V2QueueEntry {
    /// 0x-prefixed 64-hex envelope hash (lowercased).
    pub envelope_hash: String,
    pub op_kind: u8,
    /// 0x-prefixed 64-hex actor.
    pub actor_omni: String,
    pub ts_unix: u64,
}

/// Result of flushing one operator's V2 envelope queue — the inputs to
/// `CredentialAudit.appendRootV2(operatorOmni, merkleRoot, opKindBitmap,
/// entryCount)` per arch.md §15.3a.
#[derive(Clone, Debug, Serialize)]
pub struct FlushV2Result {
    pub operator_omni: String,
    pub merkle_root_hex: String,
    /// bytes32 hex; bit `k` (uint256 bit position, LSB = op_kind 0) set when
    /// the batch contains at least one envelope of op_kind `k` — matches the
    /// Solidity convention `bitmap |= bytes32(1 << opKind)`.
    pub op_kind_bitmap_hex: String,
    pub entry_count: u64,
    pub leaves_path: String,
    pub entries: Vec<V2QueueEntry>,
}

#[derive(Default)]
pub struct State {
    /// operator_omni (0x...) → queue of pending events.
    queues: Mutex<HashMap<String, Vec<AuditEvent>>>,
    /// Where to drop a leaves-jsonl file per flush. Defaults to /tmp.
    pub leaves_dir: String,
    /// `envelope_hash` (lowercased 0x-hex) → canonical CBOR bytes.
    /// Populated by `POST /v1/audit/append/v2`; read by `GET
    /// /v1/audit/envelope/<hash>`. Per arch.md §15.3a issue #97 phase B.
    ///
    /// In-memory for v0 — the chain commitment is the durability
    /// mechanism; if the worker restarts before a chain `appendV2` lands,
    /// callers re-emit. Persistent storage (e.g., S3
    /// `s3://<vault>/audit/envelopes/<hash>.cbor`) is tracked as a
    /// follow-up alongside the contract redeploy.
    envelopes: Mutex<HashMap<String, Vec<u8>>>,
    /// operator_omni (0x...) → V2 envelopes awaiting the tier-A on-chain
    /// anchor (`appendRootV2`). Fed by `POST /v1/audit/append/v2` (#229);
    /// drained by the same flush endpoints/timer as the V1 queues.
    v2_queues: Mutex<HashMap<String, Vec<V2QueueEntry>>>,
}

impl State {
    pub fn new(leaves_dir: String) -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            leaves_dir,
            envelopes: Mutex::new(HashMap::new()),
            v2_queues: Mutex::new(HashMap::new()),
        }
    }

    /// Store a canonical-CBOR-encoded `AuditEnvelope` keyed by its
    /// `envelope_hash`. The hash format is lowercased 0x-hex (matches the
    /// `GET` endpoint's path-arg shape).
    pub async fn store_envelope(&self, envelope_hash_hex: String, cbor: Vec<u8>) {
        let mut e = self.envelopes.lock().await;
        e.insert(envelope_hash_hex, cbor);
    }

    /// Retrieve a canonical-CBOR envelope by `envelope_hash` (lowercased
    /// 0x-hex). Returns `None` if the hash is unknown to this worker (it
    /// was committed on chain by another worker instance, or never
    /// emitted, or the worker restarted).
    pub async fn get_envelope(&self, envelope_hash_hex: &str) -> Option<Vec<u8>> {
        let e = self.envelopes.lock().await;
        e.get(envelope_hash_hex).cloned()
    }

    /// Queue a V2 envelope hash for the next tier-A anchor batch (#229).
    /// Returns the new V2 queue length for this operator.
    pub async fn queue_v2(&self, operator_omni: String, entry: V2QueueEntry) -> usize {
        let mut q = self.v2_queues.lock().await;
        let v = q.entry(operator_omni).or_default();
        v.push(entry);
        v.len()
    }

    /// Drain + flush a single operator's V2 envelope queue into the
    /// `appendRootV2` inputs: Merkle root over the envelope hashes (each
    /// leaf IS an `envelope_hash`), the op_kind bitmap, and the entry
    /// count. Returns `None` if the queue is empty. Writes a leaves JSONL
    /// (leaf + proof + entry) under `leaves_dir` named after the root.
    pub async fn flush_v2(&self, operator_omni: &str) -> anyhow::Result<Option<FlushV2Result>> {
        let entries = {
            let mut q = self.v2_queues.lock().await;
            q.remove(operator_omni).unwrap_or_default()
        };
        if entries.is_empty() {
            return Ok(None);
        }
        let leaves: Vec<Bytes32> = entries.iter().map(|e| decode32(&e.envelope_hash)).collect();
        let root = merkle_root(&leaves);
        let root_hex = format!("0x{}", hex::encode(root));
        let bitmap_hex = op_kind_bitmap_hex(entries.iter().map(|e| e.op_kind));

        let path = format!(
            "{}/audit-v2-leaves-{}.jsonl",
            self.leaves_dir,
            &root_hex[2..]
        );
        let mut file_content = String::new();
        for (i, e) in entries.iter().enumerate() {
            let proof = merkle_proof(&leaves, i);
            let proof_hex: Vec<String> = proof
                .iter()
                .map(|p| format!("0x{}", hex::encode(p)))
                .collect();
            let line = serde_json::json!({
                "leaf_index": i,
                "leaf": e.envelope_hash,
                "proof": proof_hex,
                "entry": e,
            });
            file_content.push_str(&serde_json::to_string(&line)?);
            file_content.push('\n');
        }
        std::fs::write(&path, file_content)?;

        Ok(Some(FlushV2Result {
            operator_omni: operator_omni.to_string(),
            merkle_root_hex: root_hex,
            op_kind_bitmap_hex: bitmap_hex,
            entry_count: entries.len() as u64,
            leaves_path: path,
            entries,
        }))
    }

    /// Drain + flush every operator's V2 queue.
    pub async fn flush_v2_all(&self) -> anyhow::Result<Vec<FlushV2Result>> {
        let omnis: Vec<String> = {
            let q = self.v2_queues.lock().await;
            q.keys().cloned().collect()
        };
        let mut out = Vec::new();
        for omni in omnis {
            if let Some(r) = self.flush_v2(&omni).await? {
                out.push(r);
            }
        }
        Ok(out)
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
            let proof_hex: Vec<String> = proof
                .iter()
                .map(|p| format!("0x{}", hex::encode(p)))
                .collect();
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

/// `opKindBitmap` for `appendRootV2` (arch.md §15.3a): bytes32 where bit
/// `k` — in uint256 bit position, LSB = op_kind 0 — is set when the batch
/// contains op_kind `k`. Matches Solidity `bitmap |= bytes32(1 << opKind)`.
fn op_kind_bitmap_hex(op_kinds: impl Iterator<Item = u8>) -> String {
    let mut bitmap = [0u8; 32];
    for k in op_kinds {
        bitmap[31 - (k as usize) / 8] |= 1 << (k % 8);
    }
    format!("0x{}", hex::encode(bitmap))
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
        s.append("0xabc".into(), ev("actor", "openrouter", 0, "blob-1"))
            .await;
        s.append("0xabc".into(), ev("actor", "openrouter", 1, "blob-1"))
            .await;
        let r = s.flush("0xabc").await.unwrap().expect("non-empty");
        assert_eq!(r.entry_count, 2);
        assert!(r.merkle_root_hex.starts_with("0x"));
        // Second flush is empty.
        assert!(s.flush("0xabc").await.unwrap().is_none());
        std::fs::remove_file(&r.leaves_path).ok();
    }

    fn v2(hash_byte: u8, op_kind: u8) -> V2QueueEntry {
        V2QueueEntry {
            envelope_hash: format!("0x{}", hex::encode([hash_byte; 32])),
            op_kind,
            actor_omni: format!("0x{}", "bb".repeat(32)),
            ts_unix: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn v2_queue_flush_produces_append_root_v2_inputs() {
        let s = State::new("/tmp".to_string());
        s.queue_v2("0xop".into(), v2(0x01, 1)).await; // CredFetch
        s.queue_v2("0xop".into(), v2(0x02, 11)).await; // MemoryGet
        s.queue_v2("0xop".into(), v2(0x03, 81)).await; // ConfigGet
        let r = s.flush_v2("0xop").await.unwrap().expect("non-empty");
        assert_eq!(r.entry_count, 3);
        assert!(r.merkle_root_hex.starts_with("0x"));
        // The root is over the envelope hashes directly (leaf == hash).
        let leaves: Vec<Bytes32> = r
            .entries
            .iter()
            .map(|e| decode32(&e.envelope_hash))
            .collect();
        assert_eq!(
            r.merkle_root_hex,
            format!("0x{}", hex::encode(merkle_root(&leaves)))
        );
        // Bitmap has exactly bits 1, 11, 81 set (LSB = op_kind 0).
        let bm = decode32(&r.op_kind_bitmap_hex);
        for k in [1usize, 11, 81] {
            assert_ne!(bm[31 - k / 8] & (1 << (k % 8)), 0, "bit {k} set");
        }
        let set_bits: u32 = bm.iter().map(|b| b.count_ones()).sum();
        assert_eq!(set_bits, 3, "exactly the three op_kind bits set");
        // Second flush is empty; V1 queue untouched.
        assert!(s.flush_v2("0xop").await.unwrap().is_none());
        assert!(s.flush("0xop").await.unwrap().is_none());
        std::fs::remove_file(&r.leaves_path).ok();
    }

    #[test]
    fn op_kind_bitmap_lsb_is_op_kind_zero() {
        let hexmap = op_kind_bitmap_hex([0u8].into_iter());
        assert_eq!(
            hexmap,
            format!("0x{}01", "00".repeat(31)),
            "op_kind 0 = lowest-order bit (Solidity 1 << 0)"
        );
        let hexmap = op_kind_bitmap_hex([255u8].into_iter());
        assert_eq!(hexmap, format!("0x80{}", "00".repeat(31)));
    }
}
