//! In-memory `Backend` for the dev-mode demo.
//!
//! Mirrors the test `MockBackend` shape but runs inside the production
//! binary so a fresh `cargo run -p agentkeys-mcp-server -- --backend
//! in-memory` is enough to walk the three-act storyboard without
//! deploying a broker, memory worker, or audit worker.
//!
//! The fixture actor / operator / device IDs are real hex32 strings
//! (matches the broker's `validate_hex32` regex `0x[0-9a-f]{64}`) so
//! payloads exercised in dev mode also wire-cleanly to a real broker.
//!
//! Each minted cap carries a unique nonce; the backend tracks minted
//! and revoked nonces so:
//!   - `cap.revoke(cap_id)` for an unknown id returns an error.
//!   - `memory.{get,put}` with a revoked or expired cap is rejected.
//!   - The smoke script can mint → revoke → retry and prove denial.

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    AuditAppendInput, AuditAppendResult, Backend, BackendError, CapMintOp, CapMintRequest,
    CapToken, MemoryGetInput, MemoryGetResult, MemoryPutInput, MemoryPutResult, RevokeResult,
};

/// Demo fixture identities — all real hex32 (`0x` + 64 hex chars) so the
/// MCP server forwards them to a real broker/worker without re-validation
/// failures.
pub const DEMO_ACTOR: &str = "0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7";
pub const DEMO_OPERATOR: &str =
    "0x07e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8";
pub const DEMO_DEVICE_KEY_HASH: &str =
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

pub struct InMemoryBackend {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    memory: HashMap<(String, String), String>,
    audit: Vec<AuditAppendInput>,
    minted: HashMap<String, MintedCap>,
    revoked: HashSet<String>,
}

struct MintedCap {
    actor: String,
    expires_at: u64,
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new_with_demo_fixture()
    }
}

impl InMemoryBackend {
    pub fn new_empty() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn new_with_demo_fixture() -> Self {
        let backend = Self::new_empty();
        backend.seed(
            DEMO_ACTOR,
            "travel",
            "Chengdu trip — Apr 12 to 16, hotpot at Yulin.",
        );
        backend.seed(
            DEMO_ACTOR,
            "family",
            "Wife's bday Aug 3 (gift idea: hiking boots).",
        );
        backend.seed(
            DEMO_ACTOR,
            "profile",
            "Allergic to shellfish. Prefers windowed flights.",
        );
        backend
    }

    pub fn seed(&self, actor: &str, namespace: &str, content: &str) {
        let mut g = self.inner.lock().unwrap();
        g.memory.insert(
            (actor.to_string(), namespace.to_string()),
            content.to_string(),
        );
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Extract `payload.nonce` from a cap-token JSON value; that's the
    /// `cap_id` we track for revocation + mint provenance.
    fn cap_id_of(cap: &Value) -> Option<String> {
        cap.get("payload")
            .and_then(|p| p.get("nonce"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

#[async_trait]
impl Backend for InMemoryBackend {
    async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        _session_bearer: &str,
    ) -> Result<CapToken, BackendError> {
        let issued_at = Self::now_unix();
        let expires_at = issued_at + req.ttl_seconds;
        let nonce = uuid::Uuid::new_v4().to_string();

        {
            let mut g = self.inner.lock().unwrap();
            g.minted.insert(
                nonce.clone(),
                MintedCap {
                    actor: req.actor_omni.clone(),
                    expires_at,
                },
            );
        }

        Ok(json!({
            "payload": {
                "operator_omni": req.operator_omni,
                "actor_omni":    req.actor_omni,
                "service":       req.service,
                "op":            format!("{op:?}"),
                "data_class":    op.data_class(),
                "device_key_hash": req.device_key_hash,
                "k3_epoch":      1,
                "issued_at":     issued_at,
                "expires_at":    expires_at,
                "nonce":         nonce
            },
            "broker_sig": "in-memory-signature"
        }))
    }

    async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError> {
        let mut g = self.inner.lock().unwrap();
        if !g.minted.contains_key(cap_id) {
            return Err(BackendError::Http {
                status: 404,
                body: format!("unknown cap_id: {cap_id}"),
            });
        }
        let newly_inserted = g.revoked.insert(cap_id.to_string());
        Ok(RevokeResult {
            ok: true,
            revocation: "in_memory".into(),
            note: Some(if newly_inserted {
                format!("dev-mode revoke; cap_id={cap_id} now denied for subsequent calls")
            } else {
                format!("dev-mode revoke; cap_id={cap_id} was already revoked (idempotent)")
            }),
        })
    }

    async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        let cap_id = Self::cap_id_of(&input.cap).ok_or_else(|| BackendError::Http {
            status: 400,
            body: "cap missing payload.nonce".into(),
        })?;
        let actor = {
            let g = self.inner.lock().unwrap();
            if g.revoked.contains(&cap_id) {
                return Err(BackendError::Http {
                    status: 403,
                    body: format!("cap revoked: cap_id={cap_id}"),
                });
            }
            let minted = g.minted.get(&cap_id).ok_or_else(|| BackendError::Http {
                status: 403,
                body: format!("cap not minted by this backend: cap_id={cap_id}"),
            })?;
            if minted.expires_at <= Self::now_unix() {
                return Err(BackendError::Http {
                    status: 403,
                    body: format!("cap expired: cap_id={cap_id}"),
                });
            }
            minted.actor.clone()
        };

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
            s3_key: format!("bots/{actor}/{}/in-memory.bin", input.namespace),
            envelope_size: input.plaintext_b64.len(),
            namespace: input.namespace,
        })
    }

    async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        let cap_id = Self::cap_id_of(&input.cap).ok_or_else(|| BackendError::Http {
            status: 400,
            body: "cap missing payload.nonce".into(),
        })?;
        let actor = {
            let g = self.inner.lock().unwrap();
            if g.revoked.contains(&cap_id) {
                return Err(BackendError::Http {
                    status: 403,
                    body: format!("cap revoked: cap_id={cap_id}"),
                });
            }
            let minted = g.minted.get(&cap_id).ok_or_else(|| BackendError::Http {
                status: 403,
                body: format!("cap not minted by this backend: cap_id={cap_id}"),
            })?;
            if minted.expires_at <= Self::now_unix() {
                return Err(BackendError::Http {
                    status: 403,
                    body: format!("cap expired: cap_id={cap_id}"),
                });
            }
            minted.actor.clone()
        };

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
        // Compute a real content-dependent SHA-256 over a deterministic
        // serialization of the input. Not the production worker's canonical
        // CBOR envelope hash, but every distinct (actor, operator, op_kind,
        // result, op_body, intent_text, ts) gets a distinct hash. Two
        // identical-content appends in different ticks differ via the
        // monotonically increasing append index.
        let ts = Self::now_unix();
        let mut g = self.inner.lock().unwrap();
        let idx = g.audit.len();
        let op_body = serde_json::to_string(&input.op_body).unwrap_or_default();
        let intent = input.intent_text.clone().unwrap_or_default();
        let preimage = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            input.actor_omni,
            input.operator_omni,
            input.op_kind,
            input.result,
            ts,
            idx,
            op_body,
            intent,
            "agentkeys-mcp-server/in-memory/v1",
        );
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        let digest = hasher.finalize();

        g.audit.push(input);

        Ok(AuditAppendResult {
            ok: true,
            envelope_hash: format!("0x{}", hex::encode(digest)),
        })
    }
}
