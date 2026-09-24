//! #612 — the sandbox delegate's SELF-SERVICE backend: per-operation credential
//! resolution, runtime-audit append and (2026-09-24, plan
//! `docs/plan/dsh-plugin-abstraction.md` PR 1) the delegate's two VERBS —
//! publish (#669) and propose (#573) — on the delegate's OWN authority (its
//! chat credential + a fresh broker session), consumed by the AgentKeys dsh
//! plugin suite through the ui-bridge's `/v1/sandbox/self/*` routes and by
//! the `--publish-once` / `--propose-once` one-shots (one code path each).
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
    // The chat loop's post-resolve discipline: signer custody adopts the fresh
    // J1 (newer-wins by `exp`) so every signer call on this backend rides it.
    credential.on_new_session(&bearer).await;
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

    /// #573 — push ONE proposal into the owner's inbox as the delegate: the
    /// ONE code path behind `agentkeys-daemon --propose-once` and the
    /// ui-bridge's `POST /v1/sandbox/self/propose` (the advertised
    /// `propose_to_owner` verb + the answerer's runtime ask, spec §4.4).
    /// Consumes the backend: the propose config owns the chat config.
    pub(crate) async fn propose(
        self,
        input: crate::propose::ProposalInput,
        now_unix: u64,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = crate::propose::ProposeConfig::from_chat_env(self.cfg).ok_or_else(|| {
            anyhow::anyhow!(
                "propose bridge disabled by env (AGENTKEYS_PROPOSE=0, or no memory worker \
                 URL / default namespace derivable — see the log)"
            )
        })?;
        crate::propose::propose_once(&cfg, &self.credential, &self.bearer, input, now_unix).await
    }

    /// #669 — publish ONE event to a bound slot as the delegate: the ONE code
    /// path behind `agentkeys-daemon --publish-once` and the ui-bridge's
    /// `POST /v1/sandbox/self/publish` (the advertised `publish_to_slot`
    /// verb). Consumes the backend; the resolved bearer seeds the publisher's
    /// session so no second resolve runs.
    pub(crate) async fn publish(
        self,
        input: crate::actions::PublishInput,
    ) -> anyhow::Result<serde_json::Value> {
        crate::actions::publish_once(
            std::sync::Arc::new(self.cfg),
            std::sync::Arc::new(self.credential),
            Some(self.bearer),
            input,
        )
        .await
    }
}
