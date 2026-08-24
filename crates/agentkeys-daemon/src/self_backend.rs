//! #612 — the sandbox delegate's SELF-SERVICE backend: per-operation credential
//! resolution and runtime-audit append on the delegate's OWN authority (its
//! chat credential + a fresh broker session), consumed by the AgentKeys dsh
//! plugin suite through the ui-bridge's `/v1/sandbox/self/*` routes.
//!
//! Authority model (spec delegate-runtime-dsh §4.2 + §6): the daemon holds the
//! delegate identity (legacy in-sandbox K10 or the #552 signer handle — the key
//! never enters the dsh process), mints per-operation caps, and the workers
//! re-verify against the chain as always. Nothing here caches secrets: a
//! credential value flows through one response and is gone; the suite's
//! provider re-resolves per operation (the dsh credentials-seam rule).
//!
//! v1 acquires a fresh broker session per request (one resolve round-trip).
//! Acceptable at chat-tool cadence; a session cache is a later optimization,
//! deliberately not premature state.

use agentkeys_backend_client::protocol::{
    normalize_omni_0x, AuditAppendInput, CapMintOp, CapMintRequest, CredFetchInput,
};
use agentkeys_backend_client::{BackendClient, BackendError};

use crate::chat_loop::{build_credential, resolve_session, ChatLoopConfig, DelegateCredential};

pub(crate) struct SelfBackend {
    pub cfg: ChatLoopConfig,
    pub credential: DelegateCredential,
    pub bearer: String,
}

/// The v1 outcome vocabulary for a self credential resolve.
pub(crate) enum SelfCredError {
    /// Not a sandbox delegate daemon / credential unavailable.
    Unavailable(String),
    /// The data plane refused (broker 403, worker 403/404…): status + body.
    Denied(u16, String),
    /// v3 envelope-only credential — client-side KEK decrypt is #91, which has
    /// not landed for delegates; fail loud instead of returning ciphertext.
    EnvelopeOnly,
    /// Transport / parse.
    Failed(String),
}

pub(crate) async fn acquire() -> Result<SelfBackend, String> {
    let cfg = ChatLoopConfig::from_env()
        .ok_or_else(|| "not a sandbox delegate daemon (no chat env)".to_string())?;
    let credential = build_credential(&cfg)
        .await
        .ok_or_else(|| "delegate credential unavailable".to_string())?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let bearer = resolve_session(&http, &cfg, &credential).await?;
    Ok(SelfBackend {
        cfg,
        credential,
        bearer,
    })
}

impl SelfBackend {
    fn client(&self) -> BackendClient {
        let cred_url = crate::ui_bridge::derive_worker_url(&self.cfg.broker_url, "cred");
        let audit_url = crate::ui_bridge::derive_worker_url(&self.cfg.broker_url, "audit");
        let client = BackendClient::new(
            Some(self.cfg.broker_url.clone()),
            None,
            audit_url,
            cred_url,
            Some(self.bearer.clone()),
            None,
            std::env::var("AGENTKEYS_VAULT_ROLE_ARN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
        );
        self.credential.configure_client(client)
    }

    /// Mint a `CredFetch` cap for `service` and fetch the vaulted value.
    /// Returns the plaintext BASE64 (the caller ships it to the suite, which
    /// decodes; nothing is persisted anywhere on this path).
    pub(crate) async fn cred_fetch_plaintext_b64(
        &self,
        service: &str,
    ) -> Result<String, SelfCredError> {
        let client = self.client();
        let cap = client
            .cap_mint(
                CapMintOp::CredFetch,
                CapMintRequest {
                    operator_omni: normalize_omni_0x(&self.cfg.operator_omni),
                    actor_omni: normalize_omni_0x(&self.cfg.actor_omni),
                    service: service.to_string(),
                    device_key_hash: self.credential.device_key_hash(),
                    ttl_seconds: 300,
                },
                &self.bearer,
            )
            .await
            .map_err(|e| match e {
                BackendError::Http { status, body } => SelfCredError::Denied(status, body),
                other => SelfCredError::Failed(format!("cap-mint: {other}")),
            })?;
        let fetched = client
            .cred_fetch(CredFetchInput { cap })
            .await
            .map_err(|e| match e {
                BackendError::Http { status, body } => SelfCredError::Denied(status, body),
                other => SelfCredError::Failed(format!("cred-fetch: {other}")),
            })?;
        if let Some(plaintext_b64) = fetched.plaintext_b64 {
            return Ok(plaintext_b64);
        }
        if fetched.envelope_b64.is_some() {
            return Err(SelfCredError::EnvelopeOnly);
        }
        Err(SelfCredError::Unavailable(
            "cred worker returned neither plaintext nor envelope".into(),
        ))
    }

    /// Append one runtime-audit row as the delegate.
    pub(crate) async fn audit_append(
        &self,
        op_kind: u8,
        op_body: serde_json::Value,
        result: u8,
        intent_text: Option<String>,
    ) -> Result<(), String> {
        self.client()
            .audit_append(AuditAppendInput {
                operator_omni: normalize_omni_0x(&self.cfg.operator_omni),
                actor_omni: normalize_omni_0x(&self.cfg.actor_omni),
                op_kind,
                op_body,
                result,
                intent_text,
            })
            .await
            .map(|_| ())
            .map_err(|e| format!("audit append: {e}"))
    }
}
