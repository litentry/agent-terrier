//! Production `Backend` implementation that talks to the real broker +
//! workers over HTTP. URLs come from `Config`; the bearer used for
//! broker cap-mint is forwarded from the vendor session header.

use async_trait::async_trait;
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    audit::{AuditAppendV2, AuditAppendV2Resp, ENVELOPE_VERSION},
    broker::BrokerCapRequest,
    memory::{MemoryGetBody, MemoryGetResp, MemoryPutBody, MemoryPutResp},
    AuditAppendInput, AuditAppendResult, Backend, BackendError, CapMintOp, CapMintRequest,
    CapToken, MemoryGetInput, MemoryGetResult, MemoryPutInput, MemoryPutResult, RevokeResult,
};

pub struct HttpBackend {
    pub client: Client,
    pub broker_url: Option<String>,
    pub memory_url: Option<String>,
    pub audit_url: Option<String>,
}

impl HttpBackend {
    pub fn new(
        broker_url: Option<String>,
        memory_url: Option<String>,
        audit_url: Option<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            broker_url,
            memory_url,
            audit_url,
        }
    }

    fn broker(&self) -> Result<&str, BackendError> {
        self.broker_url
            .as_deref()
            .ok_or(BackendError::NotConfigured("broker_url"))
    }

    fn memory(&self) -> Result<&str, BackendError> {
        self.memory_url
            .as_deref()
            .ok_or(BackendError::NotConfigured("memory_url"))
    }

    fn audit(&self) -> Result<&str, BackendError> {
        self.audit_url
            .as_deref()
            .ok_or(BackendError::NotConfigured("audit_url"))
    }
}

#[async_trait]
impl Backend for HttpBackend {
    async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        session_bearer: &str,
    ) -> Result<CapToken, BackendError> {
        let url = format!("{}{}", self.broker()?, op.broker_path());
        let body = BrokerCapRequest {
            operator_omni: req.operator_omni,
            actor_omni: req.actor_omni,
            service: req.service,
            device_key_hash: req.device_key_hash,
            ttl_seconds: req.ttl_seconds,
        };

        let resp = self
            .client
            .post(&url)
            .bearer_auth(session_bearer)
            .json(&body)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }

        resp.json::<CapToken>()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))
    }

    async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError> {
        // M1 stub — the broker doesn't expose `/v1/revoke/cap/:id` yet
        // (paired with vendor portal in M4 per agent-iam-strategy.md
        // §3.1 / milestones-roadmap.md M4). Return a structured "local
        // only" response so the demo + parent UI can show the verdict.
        //
        // When the broker lands the endpoint we swap this stub for a
        // real call; the tool's wire format stays the same.
        Ok(RevokeResult {
            ok: true,
            revocation: "local_only".into(),
            note: Some(format!(
                "broker revoke endpoint scheduled for M4; cap_id={cap_id} recorded locally only"
            )),
        })
    }

    async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        let url = format!("{}/v1/memory/put", self.memory()?);
        let resp = self
            .client
            .post(&url)
            .json(&MemoryPutBody {
                cap: input.cap,
                plaintext_b64: input.plaintext_b64,
                namespace: input.namespace.clone(),
            })
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }

        let parsed: MemoryPutResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;

        Ok(MemoryPutResult {
            ok: parsed.ok,
            s3_key: parsed.s3_key,
            envelope_size: parsed.envelope_size,
            namespace: input.namespace,
        })
    }

    async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        let url = format!("{}/v1/memory/get", self.memory()?);
        let resp = self
            .client
            .post(&url)
            .json(&MemoryGetBody {
                cap: input.cap,
                namespace: input.namespace.clone(),
            })
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }

        let parsed: MemoryGetResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;

        Ok(MemoryGetResult {
            ok: parsed.ok,
            plaintext_b64: parsed.plaintext_b64,
            namespace: input.namespace,
        })
    }

    async fn audit_append(
        &self,
        input: AuditAppendInput,
    ) -> Result<AuditAppendResult, BackendError> {
        let url = format!("{}/v1/audit/append/v2", self.audit()?);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let body = AuditAppendV2 {
            version: ENVELOPE_VERSION,
            ts_unix: ts,
            actor_omni: input.actor_omni,
            operator_omni: input.operator_omni,
            op_kind: input.op_kind,
            op_body: input.op_body,
            result: input.result,
            intent_text: input.intent_text,
            intent_commitment: None,
        };

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }

        let parsed: AuditAppendV2Resp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;

        Ok(AuditAppendResult {
            ok: parsed.ok,
            envelope_hash: parsed.envelope_hash,
        })
    }
}
