//! Shared capability minting and worker transport.

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

/// Pooled client for explicit broker and worker endpoints.
pub struct BackendClient {
    pub client: Client,
    pub broker_url: Option<String>,
    pub memory_url: Option<String>,
    pub audit_url: Option<String>,
    /// Cred worker base URL (#216 agent-side vaulted-key fetch). `None` → no
    /// cred-fetch available.
    pub cred_url: Option<String>,
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
    pub fn new(
        broker_url: Option<String>,
        memory_url: Option<String>,
        audit_url: Option<String>,
        cred_url: Option<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            broker_url,
            memory_url,
            audit_url,
            cred_url,
            device_key: None,
            remote_cap_pop: None,
            delegation: None,
        }
    }

    /// Attach the K10 device key used to sign the cap-mint proof-of-possession
    /// (issue #76). The caller loads it from its owner-only key file
    /// (`device_crypto::DeviceKey::load`) and injects it here so
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

        // Workers require a fresh actor proof for every capability.
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
                None => return Err(BackendError::NotConfigured("device_key")),
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

    /// Redeem a speech capability through an explicitly configured speech service.
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

    pub async fn memory_put(&self, input: MemoryPutInput) -> Result<MemoryPutResult, BackendError> {
        let url = format!("{}/v1/memory/put", self.memory()?);
        let req = self.client.post(&url).json(&MemoryPutBody {
            cap: input.cap,
            plaintext_b64: input.plaintext_b64,
            namespace: input.namespace.clone(),
            object_key: input.object_key.clone(),
            expected_content_hash: input.expected_content_hash.clone(),
        });
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

    /// Read actor memory using the supplied capability.
    pub async fn memory_get(&self, input: MemoryGetInput) -> Result<MemoryGetResult, BackendError> {
        let url = format!("{}/v1/memory/get", self.memory()?);
        let req = self.client.post(&url).json(&MemoryGetBody {
            cap: input.cap,
            namespace: input.namespace.clone(),
            object_key: input.object_key.clone(),
        });
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

    /// Read owner canonical memory using a delegated capability.
    pub async fn memory_canonical_get(
        &self,
        input: MemoryGetInput,
    ) -> Result<MemoryGetResult, BackendError> {
        let url = format!("{}/v1/memory/canonical-get", self.memory()?);
        let resp = self
            .client
            .post(&url)
            .json(&MemoryGetBody {
                cap: input.cap,
                namespace: input.namespace.clone(),
                // Canonical stays one-object; the worker 400s a keyed read.
                object_key: input.object_key.clone(),
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

    /// Append a proposal using a delegated append capability.
    pub async fn memory_inbox_append(
        &self,
        cap: CapToken,
        key: String,
        plaintext_b64: String,
        kind: agentkeys_protocol::ContextKind,
    ) -> Result<MemoryInboxAppendResp, BackendError> {
        let url = format!("{}/v1/memory/inbox-append", self.memory()?);
        let resp = self
            .client
            .post(&url)
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

    /// List the owner inbox using an owner capability.
    pub async fn memory_inbox_list(
        &self,
        cap: CapToken,
    ) -> Result<Vec<InboxItemMeta>, BackendError> {
        let url = format!("{}/v1/memory/inbox-list", self.memory()?);
        let req = self.client.post(&url).json(&InboxListBody { cap });
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
        let req = self.client.post(&url).json(&InboxGetBody { cap, s3_key });
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
    /// curating it. Requires an owner capability minted with `CapMintOp::MemoryInboxDelete`.
    pub async fn memory_inbox_delete(
        &self,
        cap: CapToken,
        s3_key: String,
    ) -> Result<bool, BackendError> {
        let url = format!("{}/v1/memory/inbox-delete", self.memory()?);
        let req = self
            .client
            .post(&url)
            .json(&InboxDeleteBody { cap, s3_key });
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

    /// Read an authorized credential using the supplied capability.
    pub async fn cred_fetch(&self, input: CredFetchInput) -> Result<CredFetchResult, BackendError> {
        let url = format!("{}/v1/cred/fetch", self.cred()?);
        let req = self
            .client
            .post(&url)
            .json(&CredFetchBody { cap: input.cap });
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
            envelope_b64: parsed.envelope_b64,
        })
    }

    /// Store a credential using an owner capability; the local worker encrypts plaintext.
    pub async fn cred_store(&self, input: CredStoreInput) -> Result<CredStoreResult, BackendError> {
        let url = format!("{}/v1/cred/store", self.cred()?);
        // The high-level input is the legacy plaintext mode (CLI master store);
        // v3 envelope stores build `CredStoreBody` directly (daemon ui_bridge).
        let req = self.client.post(&url).json(&CredStoreBody {
            cap: input.cap,
            plaintext_b64: Some(input.plaintext_b64),
            envelope_b64: None,
        });
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

#[cfg(test)]
mod local_transport_tests {
    use super::*;
    use axum::{http::HeaderMap, routing::post, Json, Router};
    use serde_json::json;

    #[tokio::test]
    async fn cap_mint_uses_registered_key_proof_and_preserves_broker_refusal() {
        use agentkeys_core::device_crypto::DeviceKey;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let directory = tempfile::tempdir().unwrap();
        let key = Arc::new(
            DeviceKey::load_or_generate(directory.path().join("device").to_str().unwrap(), false)
                .unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let expected_key = key.clone();
        let observed_calls = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().route(
            "/v1/cap/memory-get",
            post(
                move |headers: HeaderMap, Json(body): Json<BrokerCapRequest>| {
                    let key = expected_key.clone();
                    let calls = observed_calls.clone();
                    async move {
                        assert_eq!(headers["authorization"], "Bearer synthetic-session");
                        assert_eq!(body.device_key_hash, key.device_key_hash().unwrap());
                        assert_eq!(
                            body.client_sig.as_deref(),
                            Some(
                                key.cap_pop_sig(
                                    &body.operator_omni,
                                    &body.actor_omni,
                                    &body.service,
                                    "fetch",
                                    "memory",
                                    body.client_nonce.as_deref().unwrap(),
                                    body.client_ts.unwrap(),
                                )
                                .unwrap()
                                .as_str()
                            )
                        );
                        let status = if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            axum::http::StatusCode::OK
                        } else {
                            axum::http::StatusCode::FORBIDDEN
                        };
                        (status, Json(json!({"synthetic":"capability"})))
                    }
                },
            ),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = BackendClient::new(Some(url), None, None, None).with_device_key(key);
        let request = CapMintRequest {
            operator_omni: "11".repeat(32),
            actor_omni: "22".repeat(32),
            service: "knowledge:notes".into(),
            device_key_hash: "33".repeat(32),
            ttl_seconds: 60,
        };
        client
            .cap_mint(CapMintOp::MemoryGet, request.clone(), "synthetic-session")
            .await
            .unwrap();
        let error = client
            .cap_mint(CapMintOp::MemoryGet, request, "synthetic-session")
            .await
            .unwrap_err();
        assert!(matches!(error, BackendError::Http { status: 403, .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn canonical_memory_requires_no_cloud_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/v1/memory/canonical-get",
                    post(
                        |headers: HeaderMap, Json(body): Json<MemoryGetBody>| async move {
                            assert!(!headers.contains_key("authorization"));
                            assert!(!headers
                                .keys()
                                .any(|name| name.as_str().starts_with("x-aws-")));
                            assert_eq!(body.cap, json!({"synthetic":"capability"}));
                            Json(json!({"ok":true,"plaintext_b64":"bG9jYWw="}))
                        },
                    ),
                ),
            )
            .await
            .unwrap();
        });
        let client = BackendClient::new(None, Some(url), None, None);
        let result = client
            .memory_canonical_get(MemoryGetInput {
                cap: json!({"synthetic":"capability"}),
                namespace: "notes".into(),
                object_key: None,
            })
            .await
            .unwrap();
        assert_eq!(result.plaintext_b64, "bG9jYWw=");
        server.abort();
    }

    #[tokio::test]
    async fn missing_device_proof_is_rejected_before_network() {
        let client = BackendClient::new(Some("http://127.0.0.1:1".into()), None, None, None);
        let error = client
            .cap_mint(
                CapMintOp::MemoryGet,
                CapMintRequest {
                    operator_omni: "11".repeat(32),
                    actor_omni: "22".repeat(32),
                    service: "knowledge:notes".into(),
                    device_key_hash: "33".repeat(32),
                    ttl_seconds: 60,
                },
                "synthetic-session",
            )
            .await
            .unwrap_err();
        assert!(matches!(error, BackendError::NotConfigured("device_key")));
    }
}
