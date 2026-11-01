//! HTTP client for emitting `AuditEnvelope v1` to the audit-service worker
//! (`agentkeys-worker-audit`). Used by future emit sites in
//! credentials-service / memory-service / signer / broker / payment-service
//! / email-service / SidecarRegistry / K3EpochCounter.
//!
//! ## Why a client lives in core, not next to the worker
//!
//! Multiple emit sites in different crates need the same wire shape. Putting
//! the client in `agentkeys-core` makes the wire-level contract testable in
//! one place and shared by every emitter.
//!
//! ## Emit-and-forget semantics
//!
//! Audit emits are best-effort from the emitter's perspective — the chain
//! commitment is the durability mechanism, not the worker's in-memory map.
//! Emitters that need guaranteed delivery should either retry on transient
//! failure or fall back to direct on-chain `CredentialAudit.append`.

use serde::Deserialize;

use super::{AuditEnvelope, AuditError};
pub use agentkeys_web_core::audit::client::envelope_for;
use agentkeys_web_core::audit::client::envelope_to_json;

/// Response from `POST /v1/audit/append/v2`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppendV2Response {
    pub ok: bool,
    pub envelope_hash: String,
}

/// Client for the audit-service worker's V2 surface.
pub struct AuditClient {
    base_url: String,
    http: reqwest::Client,
}

impl AuditClient {
    /// Construct with a worker base URL (no trailing slash). Defaults to
    /// `$AGENTKEYS_AUDIT_WORKER_URL` then `https://audit.example.invalid`
    /// — operators override per deployment.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub fn from_env() -> Self {
        let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
            .unwrap_or_else(|_| "https://audit.example.invalid".to_string());
        Self::new(url)
    }

    /// Emit a fully-constructed envelope. Returns the `envelope_hash` the
    /// worker computed (which the caller can verify locally via
    /// `envelope.envelope_hash()`).
    pub async fn append(&self, envelope: &AuditEnvelope) -> Result<AppendV2Response, AuditError> {
        let url = format!("{}/v1/audit/append/v2", self.base_url);
        let body = envelope_to_json(envelope)?;
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AuditError::Invalid(format!("POST {url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AuditError::Invalid(format!(
                "audit worker returned {status}: {text}"
            )));
        }
        resp.json::<AppendV2Response>()
            .await
            .map_err(|e| AuditError::Invalid(format!("parse append response: {e}")))
    }

    /// Fetch an envelope by its `envelope_hash` (0x-prefixed hex). Returns
    /// `None` if the worker doesn't have it (404).
    pub async fn get_envelope(&self, envelope_hash: &str) -> Result<Option<Vec<u8>>, AuditError> {
        let url = format!("{}/v1/audit/envelope/{}", self.base_url, envelope_hash);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AuditError::Invalid(format!("GET {url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AuditError::Invalid(format!(
                "audit worker returned {status}: {text}"
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AuditError::Invalid(format!("read body: {e}")))?;
        Ok(Some(bytes.to_vec()))
    }
}
