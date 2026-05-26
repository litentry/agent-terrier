//! Shared mock `Backend` for integration tests. Acts like a tiny
//! in-memory broker + memory worker + audit worker.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

use agentkeys_mcp_server::backend::{
    AuditAppendInput, AuditAppendResult, Backend, BackendError, CapMintOp, CapMintRequest,
    CapToken, MemoryGetInput, MemoryGetResult, MemoryPutInput, MemoryPutResult, RevokeResult,
};

#[derive(Default)]
pub struct MockBackend {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    /// (actor_omni, namespace) → plaintext
    memory: HashMap<(String, String), String>,
    cap_mints: Vec<(CapMintOp, CapMintRequest)>,
    audit: Vec<AuditAppendInput>,
    revokes: Vec<String>,
}

// Each integration-test binary includes a copy of this module; not every
// helper is exercised in every binary, which trips `dead_code` per-target.
#[allow(dead_code)]
impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_memory(&self, actor: &str, namespace: &str, content: &str) {
        let mut g = self.inner.lock().unwrap();
        g.memory.insert(
            (actor.to_string(), namespace.to_string()),
            content.to_string(),
        );
    }

    pub fn cap_mints(&self) -> Vec<(CapMintOp, CapMintRequest)> {
        self.inner.lock().unwrap().cap_mints.clone()
    }

    pub fn audit_count(&self) -> usize {
        self.inner.lock().unwrap().audit.len()
    }

    pub fn revoke_count(&self) -> usize {
        self.inner.lock().unwrap().revokes.len()
    }
}

#[async_trait]
impl Backend for MockBackend {
    async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        _session_bearer: &str,
    ) -> Result<CapToken, BackendError> {
        let mut g = self.inner.lock().unwrap();
        g.cap_mints.push((op, req.clone()));
        Ok(json!({
            "payload": {
                "operator_omni": req.operator_omni,
                "actor_omni": req.actor_omni,
                "service": req.service,
                "op": format!("{op:?}"),
                "data_class": op.data_class(),
                "device_key_hash": req.device_key_hash,
                "k3_epoch": 1,
                "issued_at": 0,
                "expires_at": req.ttl_seconds,
                "nonce": "mock-nonce",
            },
            "broker_sig": "mock-signature"
        }))
    }

    async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError> {
        self.inner.lock().unwrap().revokes.push(cap_id.to_string());
        Ok(RevokeResult {
            ok: true,
            revocation: "local_only".into(),
            note: Some("mock revoke".into()),
        })
    }

    async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        let actor = input
            .cap
            .get("payload")
            .and_then(|p| p.get("actor_omni"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let plaintext = String::from_utf8(
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &input.plaintext_b64,
            )
            .map_err(|e| BackendError::Parse(e.to_string()))?,
        )
        .map_err(|e| BackendError::Parse(e.to_string()))?;

        let mut g = self.inner.lock().unwrap();
        g.memory
            .insert((actor.clone(), input.namespace.clone()), plaintext);
        Ok(MemoryPutResult {
            ok: true,
            s3_key: format!("bots/{actor}/{}/mock.bin", input.namespace),
            envelope_size: input.plaintext_b64.len(),
            namespace: input.namespace,
        })
    }

    async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        let actor = input
            .cap
            .get("payload")
            .and_then(|p| p.get("actor_omni"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let g = self.inner.lock().unwrap();
        let content = g
            .memory
            .get(&(actor, input.namespace.clone()))
            .cloned()
            .ok_or_else(|| BackendError::Http {
                status: 404,
                body: format!("no memory in namespace `{}`", input.namespace),
            })?;

        Ok(MemoryGetResult {
            ok: true,
            plaintext_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                content.as_bytes(),
            ),
            namespace: input.namespace,
        })
    }

    async fn audit_append(
        &self,
        input: AuditAppendInput,
    ) -> Result<AuditAppendResult, BackendError> {
        let mut g = self.inner.lock().unwrap();
        g.audit.push(input.clone());
        let hash = format!(
            "0x{}",
            hex::encode([
                g.audit.len() as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ])
        );
        Ok(AuditAppendResult {
            ok: true,
            envelope_hash: hash,
        })
    }
}
