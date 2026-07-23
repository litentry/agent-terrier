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
    CredFetchResult, CredStoreBody, CredStoreInput, CredStoreResp, CredStoreResult, DelegationPath,
    InboxDeleteBody, InboxDeleteResp, InboxGetBody, InboxGetResp, InboxItem, InboxItemMeta,
    InboxListBody, InboxListResp, MemoryGetBody, MemoryGetInput, MemoryGetResp, MemoryGetResult,
    MemoryInboxAppendBody, MemoryInboxAppendResp, MemoryPutBody, MemoryPutInput, MemoryPutResp,
    MemoryPutResult, RevokeResult, SpeechStsBody, SpeechStsResult, ENVELOPE_VERSION,
};

/// #552 — everything the client needs to have a cap-PoP signed IN the signer
/// instead of by a local key: the device-domain signer client, the ROTATING
/// J1 bearer (an `RwLock` shared with the resolve loop, which refreshes it),
/// and the signer-derived `device_key_hash` stamped into each cap request.
#[derive(Clone)]
pub struct RemoteCapPop {
    pub signer: std::sync::Arc<agentkeys_core::signer_client::DeviceSignerClient>,
    pub bearer: std::sync::Arc<tokio::sync::RwLock<String>>,
    pub device_key_hash: String,
}

/// A device→sandbox delegation the SANDBOX holds (issue #369 origination side).
/// When set on a [`BackendClient`], `cap_mint` signs the cap-PoP with the
/// sandbox's OWN ephemeral [`device_key`](BackendClient::device_key) but stamps
/// the cap with the on-chain-bound DEVICE's `device_key_hash` + the device-signed
/// `delegation_path`, so the worker accepts the cap via the delegated branch
/// (`verify_delegation`) without the K10 ever leaving the device. Obtained from
/// the broker's `/v1/agent/delegation/poll` after the device co-signs.
#[derive(Debug, Clone)]
pub struct Delegation {
    /// The on-chain-bound DEVICE's `device_key_hash` (NOT the ephemeral key's) —
    /// what the worker re-verifies the delegation signature recovers to.
    pub device_key_hash: String,
    /// The device-signed scope (space-delimited `data_class` / `service` tokens).
    pub scope: String,
    /// Unix-seconds expiry the device signed.
    pub expires_at: u64,
    /// The device's EIP-191 signature over
    /// `delegation_payload(device_key_hash, ephemeral_addr, scope, expires_at)`.
    pub delegation_sig: String,
}

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
    /// #552 — signer-side cap-PoP signing (signer-custodied delegates).
    pub remote_cap_pop: Option<RemoteCapPop>,
    /// A device→sandbox delegation (issue #369). When set, `device_key` is the
    /// sandbox's EPHEMERAL key (signs the cap-PoP) and this carries the device's
    /// bound `device_key_hash` + co-signature that the worker re-verifies. `None`
    /// = the direct #76 path (the client holds the actor's own registered K10).
    pub delegation: Option<Delegation>,
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
            remote_cap_pop: None,
            delegation: None,
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

    /// #552 — run cap-mint with the PoP signed IN the signer (device HKDF
    /// domain): for signer-custodied delegates no key exists in the sandbox,
    /// so the client generates the nonce/ts pair and asks the signer to
    /// recompute + sign the digest, authenticated by the ROTATING J1 in
    /// `bearer` (refreshed by every resolve). Takes precedence over
    /// [`Self::with_device_key`] when both are set.
    pub fn with_remote_cap_pop(mut self, remote: RemoteCapPop) -> Self {
        self.remote_cap_pop = Some(remote);
        self
    }

    /// Run cap-mint in the #369 DELEGATED mode: sign the cap-PoP with the
    /// sandbox's `ephemeral_key` and attach the device-signed `delegation`. The
    /// cap is stamped with the device's bound `device_key_hash` (from `delegation`)
    /// so the worker accepts it via the delegated branch — the K10 never leaves the
    /// device. Supersedes [`with_device_key`] for the sandbox runtime.
    pub fn with_delegation(
        mut self,
        ephemeral_key: std::sync::Arc<agentkeys_core::device_crypto::DeviceKey>,
        delegation: Delegation,
    ) -> Self {
        self.device_key = Some(ephemeral_key);
        self.delegation = Some(delegation);
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
        let body = if let Some(remote) = self.remote_cap_pop.as_ref() {
            // #552 signer custody: nonce/ts generated here (same generator as
            // the local path), digest recomputed + signed signer-side. The
            // cap's device_key_hash is the signer-derived key's — consistent
            // with the worker's keccak(ecrecover)==device_key_hash check.
            let (client_nonce, client_ts) = agentkeys_core::device_crypto::fresh_cap_pop_nonce_ts();
            let bearer_jwt = remote.bearer.read().await.clone();
            let sig = remote
                .signer
                .sign_cap_pop(
                    &agentkeys_core::signer_client::DeviceCapPopFields {
                        actor_omni: req.actor_omni.clone(),
                        operator_omni: req.operator_omni.clone(),
                        service: req.service.clone(),
                        op: op.op_str().to_string(),
                        data_class: op.data_class().to_string(),
                        client_nonce: client_nonce.clone(),
                        client_ts,
                    },
                    &bearer_jwt,
                )
                .await
                .map_err(|e| BackendError::Transport(format!("signer cap-PoP (#552): {e}")))?;
            BrokerCapRequest {
                operator_omni: req.operator_omni,
                actor_omni: req.actor_omni,
                service: req.service,
                device_key_hash: remote.device_key_hash.clone(),
                ttl_seconds: Some(req.ttl_seconds),
                client_sig: Some(sig),
                client_nonce: Some(client_nonce),
                client_ts: Some(client_ts),
                delegation_path: None,
            }
        } else {
            match self.device_key.as_ref() {
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
                    // In DELEGATED mode (#369) the cap-PoP is signed by the sandbox's
                    // ephemeral key, but the cap's `device_key_hash` is the on-chain-
                    // bound DEVICE's (the delegation proves the device authorized this
                    // ephemeral key); the worker takes the delegated verify branch. In
                    // direct mode (#76) it's the signer's OWN hash, no delegation_path.
                    let (device_key_hash, delegation_path) = match self.delegation.as_ref() {
                        Some(d) => (
                            d.device_key_hash.clone(),
                            Some(DelegationPath {
                                scope: d.scope.clone(),
                                expires_at: d.expires_at,
                                delegation_sig: d.delegation_sig.clone(),
                            }),
                        ),
                        None => (
                            device_key.device_key_hash().map_err(|e| {
                                BackendError::Transport(format!("device_key_hash: {e}"))
                            })?,
                            None,
                        ),
                    };
                    BrokerCapRequest {
                        operator_omni: req.operator_omni,
                        actor_omni: req.actor_omni,
                        service: req.service,
                        device_key_hash,
                        // Caller-side `CapMintRequest` always carries an explicit ttl,
                        // so the wire body always sends it (`Some`) — byte-identical
                        // to before the on-wire field became `Option`. Only a direct
                        // on-wire caller (the browser) may send `None` to take the
                        // broker default.
                        ttl_seconds: Some(req.ttl_seconds),
                        client_sig: Some(pop.client_sig),
                        client_nonce: Some(pop.client_nonce),
                        client_ts: Some(pop.client_ts),
                        delegation_path,
                    }
                }
                None => BrokerCapRequest {
                    operator_omni: req.operator_omni,
                    actor_omni: req.actor_omni,
                    service: req.service,
                    device_key_hash: req.device_key_hash,
                    ttl_seconds: Some(req.ttl_seconds),
                    client_sig: None,
                    client_nonce: None,
                    client_ts: None,
                    delegation_path: None,
                },
            }
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
    /// `POST /v1/cap/speech-sts` (#441) — redeem a `SpeechUse` cap (minted via
    /// [`Self::cap_mint`] with `CapMintOp::SpeechUse`, service `"speech"`) for
    /// short-TTL AWS creds valid ONLY for Transcribe streaming + Polly
    /// synthesis. The bearer is the ACTOR's own session (`agent_session_bearer`
    /// when set — the sandbox/device path — else the operator session for
    /// master-self use). No long-lived speech secret exists on this stack.
    pub async fn speech_sts(
        &self,
        cap: CapToken,
        session_bearer: &str,
    ) -> Result<SpeechStsResult, BackendError> {
        let url = format!("{}/v1/cap/speech-sts", self.broker()?);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(session_bearer)
            .json(&SpeechStsBody { cap })
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }
        resp.json::<SpeechStsResult>()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))
    }

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

    /// `POST /v1/memory/canonical-get` — delegated READ of the master's
    /// CANONICAL memory (master-hub #295 P1 distribution). The `cap` is a
    /// `CanonicalFetch`/`Memory` cap (minted via [`Self::cap_mint`] with
    /// `CapMintOp::MemoryCanonicalGet`); the worker keys the read on the
    /// OPERATOR prefix (`bots/<operator>/memory/`) for this op.
    ///
    /// §7a (A', the Codex-review fix): the read is performed SERVER-SIDE. This
    /// client sends ONLY the delegate's own session bearer + the cap, and gets
    /// back plaintext — NEVER any AWS creds. The WORKER relays the bearer to the
    /// broker's `/v1/cap/canonical-sts` for an exact-object scoped STS that never
    /// leaves the server, so the delegate cannot bypass the worker's audit/chain
    /// re-verify (it holds no creds) nor hold the operator session.
    /// `agent_session_bearer` is the DELEGATE's session.
    pub async fn memory_canonical_get(
        &self,
        input: MemoryGetInput,
    ) -> Result<MemoryGetResult, BackendError> {
        // A': send ONLY the delegate's session bearer + the cap to the worker.
        // The worker fetches the exact-object scoped STS server-side; no AWS
        // creds ever reach this client.
        let bearer = self
            .agent_session_bearer
            .as_deref()
            .filter(|b| !b.is_empty())
            .ok_or(BackendError::NotConfigured("agent_session_bearer"))?;
        let url = format!("{}/v1/memory/canonical-get", self.memory()?);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(bearer)
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

    /// `POST /v1/memory/inbox-append` — a delegate PUSHes a proposal to the
    /// master's absorption inbox (master-hub #339 P2). `cap` is an `Append`/`Memory`
    /// cap (minted via [`Self::cap_mint`] with `CapMintOp::MemoryAppend`, service
    /// `inbox:<ns>`); `key` is the proposed memory key and `plaintext_b64` the body.
    ///
    /// §8 (A', mirrors canonical-get): the write runs SERVER-SIDE. This client
    /// sends ONLY the delegate's own session bearer + the cap and gets back a
    /// receipt — NEVER any AWS creds. The WORKER relays the bearer to the broker's
    /// `/v1/cap/inbox-sts` for a PUT-only, sub-prefix-scoped STS that never leaves
    /// the server. `agent_session_bearer` is the DELEGATE's session.
    /// `kind` labels WHAT the delegate proposes (`knowledge`/`skill`/`persona`,
    /// #390 §16.2) — the worker stamps it into the stored item; the master's
    /// curate gate applies the per-kind policy (persona is never adoptable).
    pub async fn memory_inbox_append(
        &self,
        cap: CapToken,
        key: String,
        plaintext_b64: String,
        kind: agentkeys_protocol::ContextKind,
    ) -> Result<MemoryInboxAppendResp, BackendError> {
        let bearer = self
            .agent_session_bearer
            .as_deref()
            .filter(|b| !b.is_empty())
            .ok_or(BackendError::NotConfigured("agent_session_bearer"))?;
        let url = format!("{}/v1/memory/inbox-append", self.memory()?);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(bearer)
            .json(&MemoryInboxAppendBody {
                cap,
                key,
                plaintext_b64,
                kind,
            })
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BackendError::Http { status, body });
        }
        resp.json::<MemoryInboxAppendResp>()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))
    }

    /// `POST /v1/memory/inbox-list` — the MASTER lists its own inbox (the curate
    /// queue). Master-self cap (operator == actor); STS relayed under the memory
    /// role like own-memory reads. Returns the per-item provenance metadata.
    pub async fn memory_inbox_list(
        &self,
        cap: CapToken,
    ) -> Result<Vec<InboxItemMeta>, BackendError> {
        let url = format!("{}/v1/memory/inbox-list", self.memory()?);
        let mut req = self.client.post(&url).json(&InboxListBody { cap });
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
        let parsed: InboxListResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok(parsed.items)
    }

    /// `POST /v1/memory/inbox-get` — the MASTER reads one inbox proposal to review.
    pub async fn memory_inbox_get(
        &self,
        cap: CapToken,
        s3_key: String,
    ) -> Result<InboxItem, BackendError> {
        let url = format!("{}/v1/memory/inbox-get", self.memory()?);
        let mut req = self.client.post(&url).json(&InboxGetBody { cap, s3_key });
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
        let parsed: InboxGetResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok(parsed.item)
    }

    /// `POST /v1/memory/inbox-delete` — the MASTER GCs one inbox proposal after
    /// curating it (delete-on-accept / discard-on-reject). Master-self.
    pub async fn memory_inbox_delete(
        &self,
        cap: CapToken,
        s3_key: String,
    ) -> Result<bool, BackendError> {
        let url = format!("{}/v1/memory/inbox-delete", self.memory()?);
        let mut req = self
            .client
            .post(&url)
            .json(&InboxDeleteBody { cap, s3_key });
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
        let parsed: InboxDeleteResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok(parsed.deleted)
    }

    /// `POST /v1/cred/fetch` — fetch + decrypt a stored credential's plaintext
    /// (#216 agent-side vaulted-key fetch). The `cap` (a cred-fetch cap with the
    /// `service` signed inside) is minted separately via [`Self::cap_mint`]; this
    /// forwards STS creds under the VAULT role for the worker's S3 GET of
    /// `bots/<operator>/credentials/<service>.enc` — the operator's vault is the
    /// ONLY cred vault (single-vault, docs/plan/single-vault-credentials.md), so
    /// a delegated fetch requires the operator-session-minted STS the wire
    /// stages. Returns the base64 plaintext.
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

    /// `POST /v1/cred/store` — vault a credential (#216). MASTER-SELF ONLY
    /// (single-vault, docs/plan/single-vault-credentials.md): a delegated store
    /// cap is hard-rejected at both broker and worker
    /// (`cred_store_not_master_self`), so the PUT always lands in
    /// `bots/<operator>/credentials/`. The plaintext is base64 in the body
    /// (the worker encrypts with the K3 KEK).
    pub async fn cred_store(&self, input: CredStoreInput) -> Result<CredStoreResult, BackendError> {
        let url = format!("{}/v1/cred/store", self.cred()?);
        let mut req = self.client.post(&url).json(&CredStoreBody {
            cap: input.cap,
            plaintext_b64: input.plaintext_b64,
        });
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
        let parsed: CredStoreResp = resp
            .json()
            .await
            .map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok(CredStoreResult {
            ok: parsed.ok,
            s3_key: parsed.s3_key,
            envelope_size: parsed.envelope_size,
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
