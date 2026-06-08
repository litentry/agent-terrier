//! `BackendClient` — the one implementation of the broker/worker HTTP chain
//! (cap-mint → STS relay → worker put/get → audit append).
//!
//! This is the reference impl extracted out of the MCP server's
//! `HttpBackend` (issue #203). The MCP server's `HttpBackend` now delegates
//! here; the daemon's `ui_bridge` real-memory path calls it directly. There is
//! no second hand-coded chain.

use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Client;

use crate::protocol::{
    AuditAppendInput, AuditAppendResult, AuditAppendV2, AuditAppendV2Resp, BrokerCapRequest,
    CapMintOp, CapMintRequest, CapToken, CredFetchBody, CredFetchInput, CredFetchResp,
    CredFetchResult, MemoryGetBody, MemoryGetInput, MemoryGetResp, MemoryGetResult, MemoryPutBody,
    MemoryPutInput, MemoryPutResp, MemoryPutResult, RevokeResult, ENVELOPE_VERSION,
};

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("backend not configured: {0}")]
    NotConfigured(&'static str),

    #[error("backend HTTP error ({status}): {body}")]
    Http { status: u16, body: String },

    #[error("backend transport error: {0}")]
    Transport(String),

    #[error("backend response parse error: {0}")]
    Parse(String),
}

/// The broker/worker chain client. Holds the endpoint URLs + the per-actor STS
/// relay config (issue #90). Construct one and reuse it across calls — it wraps
/// a single pooled `reqwest::Client`.
pub struct BackendClient {
    pub client: Client,
    pub broker_url: Option<String>,
    pub memory_url: Option<String>,
    pub audit_url: Option<String>,
    /// Cred worker base URL (#216 agent-side vaulted-key fetch). `None` → no
    /// cred-fetch available.
    pub cred_url: Option<String>,
    /// Agent session JWT (omni == the actor). Used to mint per-actor STS creds
    /// for the worker S3 relay (issue #90). `None` → no relay (worker falls
    /// back to its own creds).
    pub agent_session_bearer: Option<String>,
    pub memory_role_arn: Option<String>,
    pub vault_role_arn: Option<String>,
    pub region: String,
    /// The caller's K10 device key, used to sign the cap-mint proof-of-possession
    /// (issue #76). `None` → `cap_mint` errors `NotConfigured("device_key")`,
    /// because a cap without a valid K10 PoP is rejected by the broker + worker
    /// (that rejection is what makes a compromised broker unable to mint caps).
    pub device_key: Option<std::sync::Arc<agentkeys_core::device_crypto::DeviceKey>>,
}

impl BackendClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        broker_url: Option<String>,
        memory_url: Option<String>,
        audit_url: Option<String>,
        cred_url: Option<String>,
        agent_session_bearer: Option<String>,
        memory_role_arn: Option<String>,
        vault_role_arn: Option<String>,
        region: String,
    ) -> Self {
        Self {
            client: Client::new(),
            broker_url,
            memory_url,
            audit_url,
            cred_url,
            agent_session_bearer,
            memory_role_arn,
            vault_role_arn,
            region,
            device_key: None,
        }
    }

    /// Attach the K10 device key used to sign the cap-mint proof-of-possession
    /// (issue #76). The caller loads it from its owner-only key file
    /// (`device_crypto::DeviceKey::load_or_generate`) and injects it here so
    /// every `cap_mint` is PoP-signed.
    pub fn with_device_key(
        mut self,
        device_key: std::sync::Arc<agentkeys_core::device_crypto::DeviceKey>,
    ) -> Self {
        self.device_key = Some(device_key);
        self
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

    fn cred(&self) -> Result<&str, BackendError> {
        self.cred_url
            .as_deref()
            .ok_or(BackendError::NotConfigured("cred_url"))
    }

    /// Mint per-actor AWS STS creds via the broker and return the three
    /// `X-Aws-*` header pairs the worker's `StsCreds` extractor reads. The
    /// agent session JWT's `omni_account` == the actor, so the broker's
    /// `/v1/mint-oidc-jwt` tags the web-identity token with
    /// `agentkeys_actor_omni`, and `AssumeRoleWithWebIdentity(role_arn)`
    /// returns creds scoped (by the bucket policy's
    /// `${aws:PrincipalTag/agentkeys_actor_omni}`) to `bots/<actor>/<class>/*`.
    /// Forwarding these to the worker is what makes per-actor S3 isolation hold
    /// at the AWS layer (arch.md §17.2). Returns `None` when the relay isn't
    /// configured (agent bearer or role ARN missing) — the worker then falls
    /// back to its own credential chain (dev/stage-1 behavior).
    pub async fn sts_headers(
        &self,
        role_arn: Option<&String>,
    ) -> Result<Option<[(&'static str, String); 3]>, BackendError> {
        let bearer = self
            .agent_session_bearer
            .as_deref()
            .filter(|b| !b.is_empty());
        let role = role_arn.map(String::as_str).filter(|r| !r.is_empty());
        match (bearer, role) {
            (Some(bearer), Some(role)) => {
                let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
                    self.broker()?,
                    bearer,
                    role,
                    &self.region,
                )
                .await
                .map_err(|e| BackendError::Transport(format!("sts relay (role {role}): {e}")))?;
                Ok(Some([
                    ("x-aws-access-key-id", creds.access_key_id),
                    ("x-aws-secret-access-key", creds.secret_access_key),
                    ("x-aws-session-token", creds.session_token),
                ]))
            }
            // Neither configured → no per-actor relay. Legitimate for the
            // legacy/--reuse-agent path, but a SILENT downgrade here is exactly
            // how a real-mode misconfig turns into a confusing worker 502
            // (issue #90), so make it loud. The worker then uses its own creds.
            (None, None) => {
                tracing::warn!(
                    "STS relay NOT configured (no agent-session-bearer + role ARN) — forwarding \
                     no X-Aws-* headers; the worker will use its own credentials. For per-actor \
                     isolation set --agent-session-bearer + --memory-role-arn/--vault-role-arn."
                );
                Ok(None)
            }
            // Exactly one set → inconsistent config; fail loud BEFORE the worker
            // call rather than silently dropping per-actor isolation.
            _ => Err(BackendError::NotConfigured(
                "STS relay partially configured — need BOTH --agent-session-bearer and the \
                 per-data-class role ARN (--memory-role-arn / --vault-role-arn), got only one",
            )),
        }
    }

    /// `POST /v1/cap/<op>` — mint a signed, data-class-explicit cap. The
    /// `session_bearer` is the operator/actor session JWT the broker checks the
    /// `agentkeys.omni_account` claim of (layer-1 isolation, issue #90).
    pub async fn cap_mint(
        &self,
        op: CapMintOp,
        req: CapMintRequest,
        session_bearer: &str,
    ) -> Result<CapToken, BackendError> {
        let url = format!("{}{}", self.broker()?, op.broker_path());

        // K10 cap-mint proof-of-possession (issue #76 — the broker-SPOF fix).
        // OPTIONAL + graceful (staged rollout): when this client holds the
        // actor's K10, sign the request — the broker validates it and the worker
        // re-verifies it independently, so a compromised broker cannot mint a
        // usable cap, and `device_key_hash` is derived from the SAME key we sign
        // with (consistent with the broker's `keccak(ecrecover)==device_key_hash`
        // check). When no K10 is configured (e.g. a master before its K10 is
        // registered), send NO PoP and the caller-supplied `device_key_hash`;
        // the worker accepts it unless AGENTKEYS_WORKER_REQUIRE_CAP_POP=1.
        let body = match self.device_key.as_ref() {
            Some(device_key) => {
                let pop = device_key
                    .cap_pop_now(
                        &req.operator_omni,
                        &req.actor_omni,
                        &req.service,
                        op.op_str(),
                        op.data_class(),
                    )
                    .map_err(|e| BackendError::Transport(format!("cap-PoP sign: {e}")))?;
                let device_key_hash = device_key
                    .device_key_hash()
                    .map_err(|e| BackendError::Transport(format!("device_key_hash: {e}")))?;
                BrokerCapRequest {
                    operator_omni: req.operator_omni,
                    actor_omni: req.actor_omni,
                    service: req.service,
                    device_key_hash,
                    ttl_seconds: req.ttl_seconds,
                    client_sig: Some(pop.client_sig),
                    client_nonce: Some(pop.client_nonce),
                    client_ts: Some(pop.client_ts),
                }
            }
            None => BrokerCapRequest {
                operator_omni: req.operator_omni,
                actor_omni: req.actor_omni,
                service: req.service,
                device_key_hash: req.device_key_hash,
                ttl_seconds: req.ttl_seconds,
                client_sig: None,
                client_nonce: None,
                client_ts: None,
            },
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

    /// M1 stub — the broker doesn't expose `/v1/revoke/cap/:id` yet (paired
    /// with the vendor portal in M4). Returns a structured "local only" verdict
    /// so the demo + parent UI can render it. The wire format stays the same
    /// when the real endpoint lands.
    pub async fn cap_revoke(&self, cap_id: &str) -> Result<RevokeResult, BackendError> {
        Ok(RevokeResult {
            ok: true,
            revocation: "local_only".into(),
            note: Some(format!(
                "broker revoke endpoint scheduled for M4; cap_id={cap_id} recorded locally only"
            )),
        })
    }

    /// cap (already minted) → STS relay → `POST /v1/memory/put`. Returns the
    /// worker's S3 key + envelope size.
    pub async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        let url = format!("{}/v1/memory/put", self.memory()?);
        let mut req = self.client.post(&url).json(&MemoryPutBody {
            cap: input.cap,
            plaintext_b64: input.plaintext_b64,
            namespace: input.namespace.clone(),
        });
        if let Some(headers) = self.sts_headers(self.memory_role_arn.as_ref()).await? {
            for (k, v) in headers {
                req = req.header(k, v);
            }
        }
        let resp = req
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

    /// cap (already minted) → STS relay → `POST /v1/memory/get`. Returns the
    /// decrypted plaintext (base64).
    pub async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        let url = format!("{}/v1/memory/get", self.memory()?);
        let mut req = self.client.post(&url).json(&MemoryGetBody {
            cap: input.cap,
            namespace: input.namespace.clone(),
        });
        if let Some(headers) = self.sts_headers(self.memory_role_arn.as_ref()).await? {
            for (k, v) in headers {
                req = req.header(k, v);
            }
        }
        let resp = req
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

    /// `POST /v1/cred/fetch` — fetch + decrypt a stored credential's plaintext
    /// (#216 agent-side vaulted-key fetch). The `cap` (a cred-fetch cap with the
    /// `service` signed inside) is minted separately via [`Self::cap_mint`]; this
    /// forwards per-actor STS creds under the VAULT role so the cred worker's S3
    /// GET is scoped to `bots/<actor>/credentials/<service>.enc`. Returns the
    /// base64 plaintext.
    pub async fn cred_fetch(&self, input: CredFetchInput) -> Result<CredFetchResult, BackendError> {
        let url = format!("{}/v1/cred/fetch", self.cred()?);
        let mut req = self
            .client
            .post(&url)
            .json(&CredFetchBody { cap: input.cap });
        if let Some(headers) = self.sts_headers(self.vault_role_arn.as_ref()).await? {
            for (k, v) in headers {
                req = req.header(k, v);
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }
        let parsed: CredFetchResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok(CredFetchResult {
            ok: parsed.ok,
            plaintext_b64: parsed.plaintext_b64,
        })
    }

    /// `POST /v1/audit/append/v2` — append a signed audit envelope. `ts_unix`
    /// is stamped here; `intent_commitment` is always `None` on this side
    /// (the broker computes it).
    pub async fn audit_append(
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
