//! Cap-token verification — same shape as
//! agentkeys-broker-server/src/handlers/cap.rs but flipped (verify
//! instead of sign).
//!
//! The worker MUST independently re-verify against the chain before any
//! S3 touch (arch.md §15.1). Five checks (codex review findings #3 + #4):
//!   1. `broker_sig` is a valid P-256 signature over Sha256(json(payload))
//!      under the env-injected broker pubkey.
//!   2. `payload.expires_at > now()` AND `payload.issued_at <= now()`
//!      (cap not expired AND not from the future — clock-skew check).
//!   3. `payload.op` matches the endpoint that received the request
//!      (a fetch-cap MUST NOT be honored at /store).
//!   4. On-chain `SidecarRegistry.getDevice(payload.device_key_hash)`:
//!      registeredAt > 0, revoked == false,
//!      operatorOmni == payload.operator_omni,
//!      actorOmni == payload.actor_omni,
//!      roles & ROLE_CAP_MINT != 0.
//!   5. On-chain `AgentKeysScope.isServiceInScope(operator, actor,
//!      keccak(service))` == true.
//!   6. On-chain `K3EpochCounter.currentEpoch` == `payload.k3_epoch`
//!      (rotation invalidates stale caps).

use agentkeys_protocol::DelegationPath;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapOp {
    Store,
    Fetch,
    /// Delegated READ of the master's CANONICAL memory (master-hub #295 P1
    /// distribution channel). Distinct from `Fetch` (the caller's OWN working
    /// memory) even though the omnis are identical (operator = master, actor =
    /// delegate) for both — only the resolved S3 PREFIX differs, so the
    /// discriminator MUST be the signed op (a route alone is forgeable). The
    /// memory worker resolves the read owner to `operator_omni` for this op;
    /// `operator != actor` makes `check_chain_scope` consult the on-chain
    /// `memory:<ns>` grant (the master-self skip is bypassed). See
    /// docs/plan/master-hub-topology.md §6a/§12.
    CanonicalFetch,
    /// Delegated APPEND to the master's absorption INBOX (master-hub #339 P2
    /// absorption channel / "push"). Distinct from `Store` (own working memory
    /// write) and `CanonicalFetch` (canonical read): authorizes a WRITE to
    /// `bots/<operator>/inbox/<delegate>/…` gated by a distinct on-chain
    /// `inbox:<ns>` grant (never the `memory:<ns>` read grant). `operator !=
    /// actor` makes `check_chain_scope` consult that grant (master-self skip
    /// bypassed). The memory worker performs the write SERVER-SIDE under a
    /// broker-minted, prefix-scoped operator STS (A', §8); the delegate holds no
    /// AWS creds. See docs/plan/master-hub-topology.md §6b/§8.
    Append,
    Teardown,
    /// Compute-gate op for the classifier-service worker (#178 §15.6, #207
    /// items 2-3). Authorizes a COMPILE (NL → policy) or TAG (entity →
    /// category) call — NOT an S3 touch. The storage workers reject a
    /// Classify cap via `check_op`; the classify worker accepts only this op.
    Classify,
    /// #406 channels — PUBLISH an event into a channel feed. Distinct SIGNED op
    /// from `ChannelSubscribe` (direction isolation, D2): the channel worker
    /// rejects a publish cap at `/v1/channel/poll` and a subscribe cap at
    /// `/v1/channel/publish` via `check_op`. Storage/config workers reject it.
    ChannelPublish,
    /// #406 channels — SUBSCRIBE (consume) events from a channel feed.
    ChannelSubscribe,
    /// #441 speech — compute-gate op for the broker's own speech STS relay
    /// (`/v1/cap/speech-sts`). NO worker redeems it: every storage/compute
    /// worker rejects a SpeechUse cap via `check_op` exactly like any other
    /// foreign op. The variant exists so the mirror stays byte-for-byte with
    /// the broker's enum (a Speech cap deserializes and is REJECTED, rather
    /// than failing parse with an opaque 400).
    SpeechUse,
}

impl CapOp {
    /// snake_case string used in the K10 cap-PoP preimage (issue #76). MUST
    /// match the broker's `CapOp::as_str` and the client's `CapMintOp::op_str`.
    pub fn as_str(self) -> &'static str {
        match self {
            CapOp::Store => "store",
            CapOp::Fetch => "fetch",
            CapOp::CanonicalFetch => "canonical_fetch",
            CapOp::Append => "append",
            CapOp::Teardown => "teardown",
            CapOp::Classify => "classify",
            CapOp::ChannelPublish => "channel_publish",
            CapOp::ChannelSubscribe => "channel_subscribe",
            CapOp::SpeechUse => "speech_use",
        }
    }
}

/// Data class the cap-token is bound to. Each worker MUST verify
/// `cap.payload.data_class` matches its own class before touching S3.
/// Without this, a cred-store cap could be submitted to /v1/memory/put
/// (or vice versa) and pollute the wrong bucket at the cap-authz layer.
/// The IAM PrincipalTag enforces per-actor scoping at the AWS layer
/// (defense in depth); this binding is the cryptographic per-class gate
/// at the cap layer (issue #90 followup, codified in AGENTS.md).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Credentials,
    Memory,
    /// Policy / memory-types taxonomy (#178 §7). Master-only; own bucket + role.
    /// A Config cap presented to the cred or memory worker fails check_data_class.
    Config,
    /// #406 channels data class — durable pub/sub feeds (own bucket + role).
    /// A Channel cap presented to the cred/memory/config worker fails
    /// check_data_class; the channel worker rejects every non-Channel cap.
    Channel,
    /// #441 speech compute plane — no bucket, no worker; redeemed only by the
    /// broker's `/v1/cap/speech-sts`. Presented to ANY worker it fails
    /// check_data_class like every other class mismatch.
    Speech,
}

impl DataClass {
    /// snake_case string used in the K10 cap-PoP preimage (issue #76). MUST
    /// match the broker's `DataClass::as_str` and the client's
    /// `CapMintOp::data_class`.
    pub fn as_str(self) -> &'static str {
        match self {
            DataClass::Credentials => "credentials",
            DataClass::Memory => "memory",
            DataClass::Config => "config",
            DataClass::Channel => "channel",
            DataClass::Speech => "speech",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapPayload {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub op: CapOp,
    /// Data class the cap is bound to. REQUIRED — workers reject caps
    /// whose data_class doesn't match the URL's bucket.
    pub data_class: DataClass,
    pub device_key_hash: String,
    pub k3_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapToken {
    pub payload: CapPayload,
    pub broker_sig: String,
    /// K10 cap-mint proof-of-possession (issue #76 — the broker-SPOF fix),
    /// carried alongside `broker_sig` (not inside `payload`, so `broker_sig` is
    /// untouched). `Option` for staged rollout: a pre-#76 broker omits them, and
    /// `check_client_pop` is a no-op when `AGENTKEYS_WORKER_REQUIRE_CAP_POP=0`.
    /// In prod (default `=1`) a cap lacking a valid `client_sig` is rejected —
    /// that is what makes a compromised broker unable to mint a usable cap.
    #[serde(default)]
    pub client_sig: Option<String>,
    #[serde(default)]
    pub client_nonce: Option<String>,
    #[serde(default)]
    pub client_ts: Option<u64>,
    /// Device→sandbox delegation (issue #369). Present when `client_sig` was
    /// produced by a sandbox's ephemeral key rather than the device K10 directly:
    /// the DEVICE (not the broker) signed `delegation_sig`, so the broker — which
    /// merely echoed it here — cannot forge it. [`check_client_pop`] re-verifies it
    /// against `payload.device_key_hash` + the recovered sandbox key. The SAME
    /// `agentkeys_protocol::DelegationPath` the broker echoes, so the shape can't
    /// drift (#203).
    #[serde(default)]
    pub delegation_path: Option<DelegationPath>,
}

pub const ROLE_CAP_MINT: u8 = 1;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("broker public key parse: {0}")]
    BrokerKey(String),
    #[error("signature decode (base64): {0}")]
    SigDecode(String),
    #[error("signature parse: {0}")]
    SigParse(String),
    #[error("signature verify failed")]
    SigInvalid,
    #[error("payload canonical-json encode: {0}")]
    Encode(String),
    #[error("cap expired at {expires_at} (now={now})")]
    Expired { expires_at: u64, now: u64 },
    #[error("cap issued in the future at {issued_at} (now={now})")]
    Future { issued_at: u64, now: u64 },
    #[error("cap op {got:?} does not match endpoint {expected:?}")]
    OpMismatch { expected: CapOp, got: CapOp },
    #[error("cap data_class {got:?} does not match endpoint {expected:?}")]
    DataClassMismatch { expected: DataClass, got: DataClass },
    #[error("chain RPC error: {0}")]
    ChainRpc(String),
    #[error("requested service not in agent's on-chain scope")]
    NotInScope,
    #[error("device not registered or revoked")]
    DeviceInactive,
    #[error("device binding mismatch on {field}")]
    DeviceMismatch { field: &'static str },
    #[error("device lacks CAP_MINT role (got 0x{got:02x})")]
    DeviceRoleMissing { got: u8 },
    #[error("K3 epoch mismatch (expected {expected}, got {got})")]
    K3Mismatch { expected: u64, got: u64 },
    #[error("cap K10 proof-of-possession missing (no client_sig) — broker-only caps are rejected")]
    CapPopMissing,
    #[error("cap K10 proof-of-possession invalid: {0}")]
    CapPopInvalid(String),
    #[error("cap K10 proof-of-possession stale (client_ts {client_ts}, now {now})")]
    CapPopStale { client_ts: u64, now: u64 },
    #[error("cap K10 proof-of-possession does not match device_key_hash")]
    CapPopMismatch,
    #[error("delegation expired at {expires_at} (now={now})")]
    DelegationExpired { expires_at: u64, now: u64 },
    #[error("cap (service {service}, data_class {data_class}, op {op}) outside delegation scope {scope:?}")]
    DelegationOutOfScope {
        scope: String,
        data_class: String,
        op: String,
        service: String,
    },
    #[error("delegation signature invalid: {0}")]
    DelegationInvalid(String),
}

pub fn verify_signature(pubkey_pem: &str, token: &CapToken) -> Result<(), VerifyError> {
    let canonical =
        serde_json::to_vec(&token.payload).map_err(|e| VerifyError::Encode(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&canonical);
    let digest = h.finalize();
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&token.broker_sig)
        .map_err(|e| VerifyError::SigDecode(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| VerifyError::SigParse(e.to_string()))?;
    let vk = parse_p256_pubkey_pem(pubkey_pem)?;
    vk.verify(&digest, &sig)
        .map_err(|_| VerifyError::SigInvalid)
}

pub fn check_op(token: &CapToken, expected: CapOp) -> Result<(), VerifyError> {
    if token.payload.op != expected {
        return Err(VerifyError::OpMismatch {
            expected,
            got: token.payload.op,
        });
    }
    Ok(())
}

/// Per-data-class isolation check (issue #90 followup). Workers reject
/// caps whose data_class doesn't match the URL's bucket — a cred-store
/// cap MUST NOT be honored at /v1/memory/put, even though both endpoints
/// expect the same CapOp::Store. The data_class binding is signed into
/// the cap payload by the broker, so it cannot be forged downstream.
pub fn check_data_class(token: &CapToken, expected: DataClass) -> Result<(), VerifyError> {
    if token.payload.data_class != expected {
        return Err(VerifyError::DataClassMismatch {
            expected,
            got: token.payload.data_class,
        });
    }
    Ok(())
}

/// Default freshness window for the K10 cap-PoP signature — must match the
/// broker's `cap::CAP_POP_MAX_AGE_SECS`.
pub const CAP_POP_MAX_AGE_SECS: u64 = 300;

/// Whether the worker REQUIRES a K10 cap-PoP on every cap (issue #76). Prod
/// default = enforce; set `AGENTKEYS_WORKER_REQUIRE_CAP_POP=0` only for a
/// staged rollout against a pre-#76 broker. Mirrors `AGENTKEYS_WORKER_REQUIRE_STS`.
pub fn cap_pop_required() -> bool {
    matches!(
        std::env::var("AGENTKEYS_WORKER_REQUIRE_CAP_POP").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Staged-rollout K10 cap-PoP gate (issue #76) — the ONE call the worker
/// handlers make. Policy:
///   - a supplied `client_sig` is ALWAYS verified (a present-but-invalid PoP is
///     rejected — so the agent path, which always signs, is protected even
///     before enforcement is switched on);
///   - a MISSING PoP is rejected only when `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1`
///     (default OFF during rollout — a master before its K10 is registered mints
///     no PoP). Flip the flag to enforce once every actor's K10 is registered;
///     that is the point at which the broker SPOF is fully closed.
pub fn enforce_client_pop(token: &CapToken) -> Result<(), VerifyError> {
    if token.client_sig.is_some() {
        check_client_pop(token, CAP_POP_MAX_AGE_SECS)
    } else if cap_pop_required() {
        Err(VerifyError::CapPopMissing)
    } else {
        Ok(())
    }
}

/// K10 proof-of-possession check (issue #76 — the broker-SPOF defense).
///
/// Recompute the cap-PoP preimage from the broker-signed `payload` + the
/// caller's `client_nonce`/`client_ts`, recover the K10 signer, and assert
/// `keccak(address) == payload.device_key_hash`. [`check_chain_device`]
/// independently binds that `device_key_hash` to the operator/actor on chain, so
/// together they prove the requester holds the K10 private key registered for
/// this actor. The broker never sees that key, so a **compromised broker cannot
/// forge `client_sig`** and therefore cannot mint a usable cap.
///
/// Fail-closed: a cap with no `client_sig` is rejected (`CapPopMissing`) —
/// otherwise a compromised broker would simply omit it.
pub fn check_client_pop(token: &CapToken, max_age_secs: u64) -> Result<(), VerifyError> {
    let client_sig = token
        .client_sig
        .as_deref()
        .ok_or(VerifyError::CapPopMissing)?;
    let client_nonce = token
        .client_nonce
        .as_deref()
        .ok_or(VerifyError::CapPopMissing)?;
    let client_ts = token.client_ts.ok_or(VerifyError::CapPopMissing)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if client_ts > now + 60 || now.saturating_sub(client_ts) > max_age_secs {
        return Err(VerifyError::CapPopStale { client_ts, now });
    }

    let preimage = agentkeys_core::device_crypto::cap_pop_payload(
        &token.payload.operator_omni,
        &token.payload.actor_omni,
        &token.payload.service,
        token.payload.op.as_str(),
        token.payload.data_class.as_str(),
        client_nonce,
        client_ts,
    );
    let recovered = agentkeys_core::device_crypto::ecrecover_eip191(&preimage, client_sig)
        .map_err(|e| VerifyError::CapPopInvalid(e.to_string()))?;
    let recovered_hash = agentkeys_core::device_crypto::device_key_hash(&recovered)
        .map_err(|e| VerifyError::CapPopInvalid(e.to_string()))?;
    // Direct K10 path (#76): the cap-PoP was signed by the device key bound on-chain.
    if strip_0x_lc(&recovered_hash) == strip_0x_lc(&token.payload.device_key_hash) {
        return Ok(());
    }
    // Delegated path (#369): the cap-PoP was signed by a SANDBOX key, not K10.
    // Accept iff a device-issued, unexpired, in-scope delegation authorizes EXACTLY
    // this sandbox key. `recovered` (the cap signer) is passed as the sandbox_key, so
    // the delegation is bound to the key that signed THIS cap — a delegation for key
    // A can't redeem a cap signed by key B, and a sandbox can't self-delegate (its
    // sig would have to recover to device_key_hash, which by construction it can't).
    if let Some(deleg) = &token.delegation_path {
        return check_delegation(token, &recovered, deleg, now);
    }
    Err(VerifyError::CapPopMismatch)
}

/// Verify a device→sandbox delegation backs a sandbox-signed cap (issue #369).
/// Three checks, in cheapest-first order so a bad cap is rejected before the
/// secp256k1 recover:
///
/// 1. unexpired (`now < expires_at`) — the device-signed TTL bound;
/// 2. the cap's `data_class`/`op` falls within the device-signed `scope`;
/// 3. `verify_delegation` recovers the device from `delegation_sig` and confirms
///    `keccak(device) == payload.device_key_hash`, bound to `sandbox_key`.
///
/// `payload.device_key_hash` is the on-chain-bound hash (`check_chain_device`
/// independently ties it to operator/actor), so a valid delegation chains the
/// sandbox key → the device → the on-chain actor without K10 ever leaving the device.
fn check_delegation(
    token: &CapToken,
    sandbox_key: &str,
    deleg: &DelegationPath,
    now: u64,
) -> Result<(), VerifyError> {
    if deleg.expires_at <= now {
        return Err(VerifyError::DelegationExpired {
            expires_at: deleg.expires_at,
            now,
        });
    }
    let data_class = token.payload.data_class.as_str();
    let op = token.payload.op.as_str();
    let service = token.payload.service.as_str();
    if !agentkeys_core::device_crypto::cap_in_scope(&deleg.scope, data_class, op, service) {
        return Err(VerifyError::DelegationOutOfScope {
            scope: deleg.scope.clone(),
            data_class: data_class.to_string(),
            op: op.to_string(),
            service: service.to_string(),
        });
    }
    agentkeys_core::device_crypto::verify_delegation(
        &token.payload.device_key_hash,
        sandbox_key,
        &deleg.scope,
        deleg.expires_at,
        &deleg.delegation_sig,
    )
    .map_err(|e| VerifyError::DelegationInvalid(e.to_string()))?;
    Ok(())
}

// The delegation-scope matcher is now the ONE shared
// `agentkeys_core::device_crypto::cap_in_scope` (#203), so the broker's fast-fail
// cap-mint check and this authoritative worker re-verify cannot diverge.

pub fn check_freshness(token: &CapToken) -> Result<(), VerifyError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if token.payload.expires_at <= now {
        return Err(VerifyError::Expired {
            expires_at: token.payload.expires_at,
            now,
        });
    }
    // 60s slop to absorb clock skew between broker and worker.
    if token.payload.issued_at > now + 60 {
        return Err(VerifyError::Future {
            issued_at: token.payload.issued_at,
            now,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct OnChainDevice {
    pub operator_omni: String,
    pub actor_omni: String,
    pub roles: u8,
    pub registered_at: u64,
    pub revoked: bool,
}

pub async fn check_chain_device(
    http: &reqwest::Client,
    rpc_url: &str,
    registry: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let selector = function_selector("getDevice(bytes32)");
    let arg = pad32(&token.payload.device_key_hash)?;
    let data = format!("0x{selector}{arg}");
    let raw = eth_call(http, rpc_url, registry, &data).await?;
    let device = parse_device_entry(&raw)?;
    if device.registered_at == 0 || device.revoked {
        return Err(VerifyError::DeviceInactive);
    }
    let req_operator = strip_0x_lc(&token.payload.operator_omni);
    let req_actor = strip_0x_lc(&token.payload.actor_omni);
    if device.operator_omni != req_operator {
        return Err(VerifyError::DeviceMismatch {
            field: "operator_omni",
        });
    }
    if device.actor_omni != req_actor {
        return Err(VerifyError::DeviceMismatch {
            field: "actor_omni",
        });
    }
    if (device.roles & ROLE_CAP_MINT) == 0 {
        return Err(VerifyError::DeviceRoleMissing { got: device.roles });
    }
    Ok(())
}

pub async fn check_chain_scope(
    http: &reqwest::Client,
    rpc_url: &str,
    scope_contract: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let selector = function_selector("isServiceInScope(bytes32,bytes32,bytes32)");
    let a = pad32(&token.payload.operator_omni)?;
    let b = pad32(&token.payload.actor_omni)?;
    // SKIP when operator == actor — the master accessing its OWN data. Mirrors
    // the broker cap-mint skip (handlers/cap.rs); defense-in-depth must agree, or
    // the worker would reject a cap the broker minted. Bounded-safe:
    // check_chain_device already pinned device.actor_omni == payload.actor_omni,
    // so this only ever opens bots/<O_master>/. Deliberate SKIP; the scope-grant
    // path is retained for a possible future design — see docs/arch.md §12.4.
    if a == b {
        return Ok(());
    }
    let service_hash = keccak_lc_service(&token.payload.service);
    let c = pad32(&service_hash)?;
    let data = format!("0x{selector}{a}{b}{c}");
    let raw = eth_call(http, rpc_url, scope_contract, &data).await?;
    if !parse_bool(&raw) {
        return Err(VerifyError::NotInScope);
    }
    Ok(())
}

pub async fn check_chain_k3_epoch(
    http: &reqwest::Client,
    rpc_url: &str,
    epoch_contract: &str,
    token: &CapToken,
) -> Result<(), VerifyError> {
    let selector = function_selector("currentEpoch()");
    let data = format!("0x{selector}");
    let raw = eth_call(http, rpc_url, epoch_contract, &data).await?;
    let on_chain = parse_u64(&raw)?;
    if on_chain != token.payload.k3_epoch {
        return Err(VerifyError::K3Mismatch {
            expected: on_chain,
            got: token.payload.k3_epoch,
        });
    }
    Ok(())
}

async fn eth_call(
    http: &reqwest::Client,
    rpc_url: &str,
    to: &str,
    data: &str,
) -> Result<String, VerifyError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
        "id": 1,
    });
    // Public RPCs fail eth_call transiently in two ways: Heima 500s ~12% of calls
    // (HTML error page → non-JSON body), and Base's free endpoint THROTTLES the
    // onboarding burst of reads with a JSON-RPC rate-limit error (-32016 "over rate
    // limit"). A single attempt makes every chain-verify a coin-flip → a false 502
    // (the cap looks unverifiable when the chain is fine). Retry transient failures
    // — transport error / HTTP 5xx / non-JSON body / a rate-limit JSON-RPC error —
    // with backoff; do NOT retry a DETERMINISTIC JSON-RPC error (a real revert /
    // bad-arg result). A dedicated (non-throttled) RPC is the systemic fix; this
    // keeps a burst on a public endpoint from failing onboarding.
    const ATTEMPTS: u32 = 5;
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            let ms = 150u64 * (1u64 << (attempt - 1)); // 150, 300, 600 ms
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        let resp = match http.post(rpc_url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                last = format!("eth_call POST: {e}");
                continue;
            }
        };
        if resp.status().is_server_error() {
            last = format!("eth_call HTTP {}", resp.status());
            continue;
        }
        let v: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                last = format!("eth_call json: {e}");
                continue;
            }
        };
        if let Some(err) = v.get("error") {
            // A rate-limit error is TRANSIENT (public RPCs throttle bursts), unlike a
            // revert — back off + retry it like a 5xx instead of failing the verify.
            if is_rate_limit_error(err) {
                last = format!("eth_call rate-limited: {err}");
                continue;
            }
            return Err(VerifyError::ChainRpc(format!("rpc error: {err}")));
        }
        return v
            .get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VerifyError::ChainRpc("missing 'result'".into()));
    }
    Err(VerifyError::ChainRpc(format!(
        "eth_call failed after {ATTEMPTS} attempts: {last}"
    )))
}

/// Is this JSON-RPC `error` a TRANSIENT rate-limit (retry) vs a deterministic
/// revert / bad-arg (terminal)? Covers the common public-RPC codes — Base's
/// `-32016` "over rate limit", the `-32005` / `-32029` "limit exceeded" family —
/// and any message mentioning rate limiting / too many requests.
fn is_rate_limit_error(err: &serde_json::Value) -> bool {
    if matches!(
        err.get("code").and_then(|c| c.as_i64()),
        Some(-32016) | Some(-32005) | Some(-32029)
    ) {
        return true;
    }
    err.get("message")
        .and_then(|m| m.as_str())
        .map(|m| m.to_lowercase())
        .map(|m| {
            m.contains("rate limit")
                || m.contains("too many requests")
                || m.contains("limit exceeded")
        })
        .unwrap_or(false)
}

fn parse_device_entry(raw: &str) -> Result<OnChainDevice, VerifyError> {
    let hex = raw.trim_start_matches("0x");
    // DeviceEntry post codex H1 (SidecarRegistry.sol) has 11 ABI words:
    //   word 0  operatorOmni     bytes32
    //   word 1  actorOmni        bytes32
    //   word 2  k11CredId        bytes32
    //   word 3  k11RpIdHash      bytes32  (NEW, codex H1)
    //   word 4  k11PubX          uint256  (NEW, codex H1)
    //   word 5  k11PubY          uint256  (NEW, codex H1)
    //   word 6  tier             uint8 (padded)
    //   word 7  roles            uint8 (padded)
    //   word 8  registeredAt     uint64 (padded)
    //   word 9  lastSignCount    uint32 (padded)
    //   word 10 revoked          bool (padded)
    if hex.len() < 11 * 64 {
        return Err(VerifyError::ChainRpc(format!(
            "getDevice returned {} bytes; expected ≥ 11×32 (post codex H1 struct)",
            hex.len() / 2
        )));
    }
    let operator_omni = hex[0..64].to_lowercase();
    let actor_omni = hex[64..128].to_lowercase();
    let roles = u8::from_str_radix(&hex[(7 * 64 + 62)..(7 * 64 + 64)], 16).unwrap_or(0);
    let registered_at = u64::from_str_radix(&hex[(8 * 64 + 48)..(8 * 64 + 64)], 16).unwrap_or(0);
    let revoked = hex[10 * 64..11 * 64].trim_start_matches('0').ends_with('1');
    Ok(OnChainDevice {
        operator_omni,
        actor_omni,
        roles,
        registered_at,
        revoked,
    })
}

fn parse_bool(raw: &str) -> bool {
    raw.trim_start_matches("0x")
        .trim_start_matches('0')
        .ends_with('1')
}

fn parse_u64(raw: &str) -> Result<u64, VerifyError> {
    let stripped = raw.trim_start_matches("0x");
    u64::from_str_radix(stripped, 16).map_err(|e| VerifyError::ChainRpc(format!("u64 parse: {e}")))
}

fn parse_p256_pubkey_pem(pem: &str) -> Result<VerifyingKey, VerifyError> {
    use p256::pkcs8::DecodePublicKey;
    let pk = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| VerifyError::BrokerKey(e.to_string()))?;
    Ok(VerifyingKey::from(pk))
}

fn function_selector(sig: &str) -> String {
    let mut h = sha3::Keccak256::new();
    h.update(sig.as_bytes());
    let d = h.finalize();
    hex::encode(&d[..4])
}

fn keccak_lc_service(name: &str) -> String {
    let mut h = sha3::Keccak256::new();
    h.update(name.to_lowercase().as_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}

fn pad32(s: &str) -> Result<String, VerifyError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(VerifyError::ChainRpc(format!(
            "expected 64-hex (32 bytes), got {} chars",
            stripped.len()
        )));
    }
    Ok(stripped.to_lowercase())
}

fn strip_0x_lc(s: &str) -> String {
    s.strip_prefix("0x").unwrap_or(s).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token(op: CapOp) -> CapToken {
        sample_token_with_class(op, DataClass::Credentials)
    }

    fn sample_token_with_class(op: CapOp, data_class: DataClass) -> CapToken {
        CapToken {
            payload: CapPayload {
                operator_omni: format!("0x{}", "a".repeat(64)),
                actor_omni: format!("0x{}", "b".repeat(64)),
                service: "openrouter".into(),
                op,
                data_class,
                device_key_hash: format!("0x{}", "c".repeat(64)),
                k3_epoch: 1,
                issued_at: 1,
                expires_at: u64::MAX,
                nonce: "00".repeat(16),
            },
            broker_sig: "x".into(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    #[tokio::test]
    async fn check_chain_scope_skips_when_operator_is_actor() {
        // Master accessing its OWN data (operator == actor) must SKIP the on-chain
        // scope check — proven by an UNREACHABLE rpc_url: if the skip didn't fire,
        // eth_call would error. Mirrors the broker cap-mint skip (handlers/cap.rs).
        let mut token = sample_token(CapOp::Fetch);
        token.payload.actor_omni = token.payload.operator_omni.clone();
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, "http://127.0.0.1:1", "0xscope", &token).await;
        assert!(r.is_ok(), "operator==actor must skip scope (got {r:?})");
    }

    #[tokio::test]
    async fn check_chain_scope_consults_chain_when_operator_differs() {
        // Cross-actor (operator != actor) must NOT skip — it consults the chain,
        // so an unreachable rpc_url surfaces an error, never a silent pass.
        let token = sample_token(CapOp::Fetch); // operator 0xaa…, actor 0xbb…
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, "http://127.0.0.1:1", "0xscope", &token).await;
        assert!(r.is_err(), "operator!=actor must still consult the chain");
    }

    // Minimal in-process JSON-RPC mock: one std TCP listener that answers every
    // eth_call with a fixed `result`. Uses std::net (NOT tokio::net) so it needs no
    // extra tokio feature + no new dev-dependency (keeps Cargo.lock untouched).
    fn spawn_mock_rpc(result_hex: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { return };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf); // drain the request; we don't parse it
                let json = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{result_hex}\"}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn check_chain_scope_ok_when_chain_grants() {
        // POSITIVE delegation: master GRANTED the agent scope (operator != actor,
        // chain returns true) → the agent's cap passes the scope gate. This is the
        // positive counterpart the suite previously lacked — proves "granted ->
        // success", not just "the gate is consulted".
        let url =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000001");
        let token = sample_token(CapOp::Fetch); // operator 0xaa…, actor 0xbb… (distinct)
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, &url, "0xscope", &token).await;
        assert!(r.is_ok(), "granted cross-actor scope must pass (got {r:?})");
    }

    #[tokio::test]
    async fn check_chain_scope_rejects_when_chain_denies() {
        // NEGATIVE: operator != actor, chain returns false (NOT granted) → NotInScope.
        let url =
            spawn_mock_rpc("0x0000000000000000000000000000000000000000000000000000000000000000");
        let token = sample_token(CapOp::Fetch);
        let client = reqwest::Client::new();
        let r = check_chain_scope(&client, &url, "0xscope", &token).await;
        assert!(
            matches!(r, Err(VerifyError::NotInScope)),
            "ungranted cross-actor scope must be NotInScope (got {r:?})"
        );
    }

    #[test]
    fn data_class_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&DataClass::Credentials).unwrap(),
            "\"credentials\""
        );
        assert_eq!(
            serde_json::to_string(&DataClass::Memory).unwrap(),
            "\"memory\""
        );
        assert_eq!(
            serde_json::to_string(&DataClass::Config).unwrap(),
            "\"config\""
        );
        assert_eq!(
            serde_json::to_string(&DataClass::Channel).unwrap(),
            "\"channel\""
        );
    }

    #[test]
    fn check_data_class_rejects_config_at_cred_and_memory() {
        // A Config cap (the taxonomy data class, #178) must be rejected by both
        // the cred and memory workers — it belongs only to the config worker.
        let config_cap = sample_token_with_class(CapOp::Store, DataClass::Config);
        for expected in [DataClass::Credentials, DataClass::Memory] {
            match check_data_class(&config_cap, expected) {
                Err(VerifyError::DataClassMismatch { got, .. }) => {
                    assert_eq!(got, DataClass::Config);
                }
                other => panic!("expected DataClassMismatch for {expected:?}, got {other:?}"),
            }
        }
        // And a memory cap is rejected where Config is expected (the config worker).
        let mem_cap = sample_token_with_class(CapOp::Store, DataClass::Memory);
        assert!(matches!(
            check_data_class(&mem_cap, DataClass::Config),
            Err(VerifyError::DataClassMismatch { .. })
        ));
    }

    #[test]
    fn check_data_class_accepts_match() {
        let t = sample_token_with_class(CapOp::Store, DataClass::Credentials);
        assert!(check_data_class(&t, DataClass::Credentials).is_ok());
    }

    #[test]
    fn check_data_class_rejects_cross_class() {
        // Cred-class cap submitted to memory worker (expected = Memory).
        let cred_cap = sample_token_with_class(CapOp::Store, DataClass::Credentials);
        match check_data_class(&cred_cap, DataClass::Memory) {
            Err(VerifyError::DataClassMismatch { expected, got }) => {
                assert_eq!(expected, DataClass::Memory);
                assert_eq!(got, DataClass::Credentials);
            }
            other => panic!("expected DataClassMismatch, got {:?}", other),
        }
        // Memory-class cap submitted to cred worker (expected = Credentials).
        let mem_cap = sample_token_with_class(CapOp::Store, DataClass::Memory);
        match check_data_class(&mem_cap, DataClass::Credentials) {
            Err(VerifyError::DataClassMismatch { expected, got }) => {
                assert_eq!(expected, DataClass::Credentials);
                assert_eq!(got, DataClass::Memory);
            }
            other => panic!("expected DataClassMismatch, got {:?}", other),
        }
    }

    #[test]
    fn cap_op_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&CapOp::Store).unwrap(), "\"store\"");
        assert_eq!(serde_json::to_string(&CapOp::Fetch).unwrap(), "\"fetch\"");
        assert_eq!(
            serde_json::to_string(&CapOp::CanonicalFetch).unwrap(),
            "\"canonical_fetch\""
        );
        assert_eq!(CapOp::CanonicalFetch.as_str(), "canonical_fetch");
        assert_eq!(serde_json::to_string(&CapOp::Append).unwrap(), "\"append\"");
        assert_eq!(CapOp::Append.as_str(), "append");
        assert_eq!(
            serde_json::to_string(&CapOp::Teardown).unwrap(),
            "\"teardown\""
        );
    }

    #[test]
    fn function_selector_matches_known_signatures() {
        assert_eq!(
            function_selector("isServiceInScope(bytes32,bytes32,bytes32)"),
            "13337240"
        );
        assert_eq!(function_selector("currentEpoch()"), "76671808");
    }

    #[test]
    fn keccak_service_lowercases() {
        assert_eq!(
            keccak_lc_service("OpenRouter"),
            keccak_lc_service("openrouter")
        );
    }

    #[test]
    fn pad32_accepts_with_or_without_0x() {
        assert_eq!(
            pad32(&format!("0x{}", "a".repeat(64))).unwrap(),
            "a".repeat(64)
        );
        assert_eq!(pad32(&"b".repeat(64)).unwrap(), "b".repeat(64));
    }

    #[test]
    fn pad32_rejects_short() {
        assert!(pad32("0x123").is_err());
    }

    #[test]
    fn check_freshness_rejects_past() {
        let mut t = sample_token(CapOp::Fetch);
        t.payload.expires_at = 1;
        assert!(matches!(
            check_freshness(&t),
            Err(VerifyError::Expired { .. })
        ));
    }

    #[test]
    fn check_freshness_rejects_future() {
        let mut t = sample_token(CapOp::Fetch);
        t.payload.issued_at = u64::MAX / 2; // well past now+60s
        t.payload.expires_at = u64::MAX;
        assert!(matches!(
            check_freshness(&t),
            Err(VerifyError::Future { .. })
        ));
    }

    #[test]
    fn check_op_rejects_mismatch() {
        let t = sample_token(CapOp::Store);
        assert!(matches!(
            check_op(&t, CapOp::Fetch),
            Err(VerifyError::OpMismatch {
                expected: CapOp::Fetch,
                got: CapOp::Store
            })
        ));
    }

    #[test]
    fn check_op_accepts_match() {
        let t = sample_token(CapOp::Store);
        assert!(check_op(&t, CapOp::Store).is_ok());
    }

    #[test]
    fn parse_device_entry_decodes_well_formed() {
        // 11-word post-codex-H1 DeviceEntry layout:
        //  word 0 operatorOmni  → "aaaa…" (64 hex)
        //  word 1 actorOmni     → "bbbb…"
        //  word 2 k11CredId     → 0
        //  word 3 k11RpIdHash   → 0 (codex H1)
        //  word 4 k11PubX       → 0 (codex H1)
        //  word 5 k11PubY       → 0 (codex H1)
        //  word 6 tier          → 1
        //  word 7 roles         → 7
        //  word 8 registeredAt  → 42
        //  word 9 lastSignCount → 0
        //  word 10 revoked      → 0
        let mut raw = String::from("0x");
        raw.push_str(&"a".repeat(64)); // operator
        raw.push_str(&"b".repeat(64)); // actor
        raw.push_str(&"0".repeat(64)); // k11CredId
        raw.push_str(&"0".repeat(64)); // k11RpIdHash
        raw.push_str(&"0".repeat(64)); // k11PubX
        raw.push_str(&"0".repeat(64)); // k11PubY
        raw.push_str(&format!("{:0>64x}", 1u64)); // tier
        raw.push_str(&format!("{:0>64x}", 7u64)); // roles
        raw.push_str(&format!("{:0>64x}", 42u64)); // registeredAt
        raw.push_str(&"0".repeat(64)); // lastSignCount
        raw.push_str(&"0".repeat(64)); // revoked
        let d = parse_device_entry(&raw).unwrap();
        assert_eq!(d.operator_omni, "a".repeat(64));
        assert_eq!(d.actor_omni, "b".repeat(64));
        assert_eq!(d.roles, 7);
        assert_eq!(d.registered_at, 42);
        assert!(!d.revoked);
    }

    #[test]
    fn sign_then_verify_roundtrip_with_test_keypair() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        use p256::pkcs8::EncodePublicKey;

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verify_key = signing_key.verifying_key();
        let pubkey_pem = p256::PublicKey::from(*verify_key)
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();

        let payload = sample_token(CapOp::Store).payload;
        let canonical = serde_json::to_vec(&payload).unwrap();
        let mut h = Sha256::new();
        h.update(&canonical);
        let sig: p256::ecdsa::Signature = signing_key.sign(&h.finalize());
        let token = CapToken {
            payload,
            broker_sig: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        };

        verify_signature(&pubkey_pem, &token).unwrap();
        let mut bad = token.clone();
        bad.payload.service = "different".into();
        assert!(matches!(
            verify_signature(&pubkey_pem, &bad),
            Err(VerifyError::SigInvalid)
        ));
    }

    // ── K10 cap proof-of-possession (issue #76) ──────────────────────────────

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build a token whose `client_sig` is a valid K10 PoP signed by `dk` over
    /// the token's own payload fields at time `ts`.
    fn sign_pop_into(token: &mut CapToken, dk: &agentkeys_core::device_crypto::DeviceKey, ts: u64) {
        let nonce = "0011223344556677".to_string();
        let sig = dk
            .cap_pop_sig(
                &token.payload.operator_omni,
                &token.payload.actor_omni,
                &token.payload.service,
                token.payload.op.as_str(),
                token.payload.data_class.as_str(),
                &nonce,
                ts,
            )
            .unwrap();
        token.payload.device_key_hash = dk.device_key_hash().unwrap();
        token.client_sig = Some(sig);
        token.client_nonce = Some(nonce);
        token.client_ts = Some(ts);
    }

    fn fresh_device(name: &str) -> agentkeys_core::device_crypto::DeviceKey {
        agentkeys_core::device_crypto::DeviceKey::load_or_generate(
            std::env::temp_dir().join(name).to_str().unwrap(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn check_client_pop_accepts_valid() {
        let dk = fresh_device("ak-verify-pop-ok.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        sign_pop_into(&mut token, &dk, now_secs());
        assert!(check_client_pop(&token, CAP_POP_MAX_AGE_SECS).is_ok());
    }

    #[test]
    fn check_client_pop_rejects_missing() {
        // No client_sig — what a compromised broker would present. Fail-closed.
        let token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::CapPopMissing)
        ));
    }

    #[test]
    fn check_client_pop_rejects_forged_from_other_key() {
        // A valid signature from a DIFFERENT key (the best a broker without the
        // user's K10 can do) → keccak(recovered) != device_key_hash. THE fix.
        let dk = fresh_device("ak-verify-pop-real.key");
        let other = fresh_device("ak-verify-pop-other.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        sign_pop_into(&mut token, &dk, now_secs()); // sets the real device_key_hash
                                                    // overwrite the sig with one from `other` over the same preimage
        let nonce = token.client_nonce.clone().unwrap();
        token.client_sig = Some(
            other
                .cap_pop_sig(
                    &token.payload.operator_omni,
                    &token.payload.actor_omni,
                    &token.payload.service,
                    token.payload.op.as_str(),
                    token.payload.data_class.as_str(),
                    &nonce,
                    token.client_ts.unwrap(),
                )
                .unwrap(),
        );
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::CapPopMismatch)
        ));
    }

    #[test]
    fn check_client_pop_rejects_tampered_op() {
        // Sign for Store, then flip payload.op to Fetch → recomputed preimage
        // differs → recovered address no longer matches the hash.
        let dk = fresh_device("ak-verify-pop-tamper.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        sign_pop_into(&mut token, &dk, now_secs());
        token.payload.op = CapOp::Fetch;
        assert!(check_client_pop(&token, CAP_POP_MAX_AGE_SECS).is_err());
    }

    #[test]
    fn check_client_pop_rejects_stale() {
        let dk = fresh_device("ak-verify-pop-stale.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let stale = now_secs().saturating_sub(CAP_POP_MAX_AGE_SECS + 120);
        sign_pop_into(&mut token, &dk, stale);
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::CapPopStale { .. })
        ));
    }

    #[test]
    fn is_rate_limit_error_retries_throttles_not_reverts() {
        use serde_json::json;
        // Transient throttles (Base -32016, the -32005/-32029 family, or a
        // rate-limit message) ⇒ retry.
        assert!(is_rate_limit_error(
            &json!({"code": -32016, "message": "over rate limit"})
        ));
        assert!(is_rate_limit_error(
            &json!({"code": -32005, "message": "limit exceeded"})
        ));
        assert!(is_rate_limit_error(&json!({"code": -32029})));
        assert!(is_rate_limit_error(
            &json!({"message": "Too Many Requests"})
        ));
        // A deterministic revert / bad-arg ⇒ terminal (must NOT retry).
        assert!(!is_rate_limit_error(
            &json!({"code": 3, "message": "execution reverted"})
        ));
        assert!(!is_rate_limit_error(
            &json!({"code": -32000, "message": "invalid opcode"})
        ));
    }

    // ── device→sandbox delegation (issue #369) ───────────────────────────────

    /// Sign the cap-PoP with `sandbox` (NOT the device) but stamp the on-chain-bound
    /// `device_key_hash` — i.e. exactly what a delegated sandbox presents.
    fn sign_pop_as_sandbox(
        token: &mut CapToken,
        sandbox: &agentkeys_core::device_crypto::DeviceKey,
        device_key_hash: &str,
        ts: u64,
    ) {
        let nonce = "0011223344556677".to_string();
        let sig = sandbox
            .cap_pop_sig(
                &token.payload.operator_omni,
                &token.payload.actor_omni,
                &token.payload.service,
                token.payload.op.as_str(),
                token.payload.data_class.as_str(),
                &nonce,
                ts,
            )
            .unwrap();
        token.payload.device_key_hash = device_key_hash.to_string();
        token.client_sig = Some(sig);
        token.client_nonce = Some(nonce);
        token.client_ts = Some(ts);
    }

    fn attach_delegation(
        token: &mut CapToken,
        signer: &agentkeys_core::device_crypto::DeviceKey,
        sandbox_addr: &str,
        scope: &str,
        expires_at: u64,
    ) {
        let delegation_sig = signer
            .delegation_sig(sandbox_addr, scope, expires_at)
            .unwrap();
        token.delegation_path = Some(DelegationPath {
            scope: scope.to_string(),
            expires_at,
            delegation_sig,
        });
    }

    #[test]
    fn delegation_accepts_sandbox_cap_backed_by_device() {
        // The happy path: a sandbox key signs the cap-PoP, and a device-issued,
        // unexpired, in-scope delegation authorizes that exact sandbox key.
        let device = fresh_device("ak-deleg-device.key");
        let sandbox = fresh_device("ak-deleg-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &device,
            sandbox.address(),
            "memory credentials",
            now_secs() + 3600,
        );
        assert!(check_client_pop(&token, CAP_POP_MAX_AGE_SECS).is_ok());
    }

    #[test]
    fn delegation_rejects_expired() {
        let device = fresh_device("ak-deleg-exp-device.key");
        let sandbox = fresh_device("ak-deleg-exp-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &device,
            sandbox.address(),
            "memory",
            now_secs() - 10,
        );
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::DelegationExpired { .. })
        ));
    }

    #[test]
    fn delegation_rejects_out_of_scope() {
        // The delegation grants `credentials`, but the cap is for `memory`.
        let device = fresh_device("ak-deleg-scope-device.key");
        let sandbox = fresh_device("ak-deleg-scope-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &device,
            sandbox.address(),
            "credentials",
            now_secs() + 3600,
        );
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::DelegationOutOfScope { .. })
        ));
    }

    #[test]
    fn delegation_rejects_wrong_device() {
        // A delegation signed by a DIFFERENT device than the on-chain-bound one.
        let device = fresh_device("ak-deleg-wrong-device.key");
        let other = fresh_device("ak-deleg-wrong-other.key");
        let sandbox = fresh_device("ak-deleg-wrong-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        // `other` signs the delegation, but the token claims `device`'s hash.
        attach_delegation(
            &mut token,
            &other,
            sandbox.address(),
            "memory",
            now_secs() + 3600,
        );
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::DelegationInvalid(_))
        ));
    }

    #[test]
    fn delegation_rejects_sandbox_self_delegation() {
        // THE security property: a sandbox cannot authorize ITSELF. It signs both the
        // cap-PoP AND the delegation with its own key — verify_delegation recovers the
        // sandbox, whose keccak != the device_key_hash, so it's rejected.
        let device = fresh_device("ak-deleg-self-device.key");
        let sandbox = fresh_device("ak-deleg-self-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        attach_delegation(
            &mut token,
            &sandbox,
            sandbox.address(),
            "memory",
            now_secs() + 3600,
        );
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::DelegationInvalid(_))
        ));
    }

    #[test]
    fn sandbox_cap_without_delegation_is_rejected() {
        // A sandbox-signed cap with NO delegation_path falls through to the direct
        // #76 mismatch — the delegation path never weakens the no-delegation case.
        let device = fresh_device("ak-deleg-none-device.key");
        let sandbox = fresh_device("ak-deleg-none-sandbox.key");
        let mut token = sample_token_with_class(CapOp::Store, DataClass::Memory);
        let dkh = device.device_key_hash().unwrap();
        sign_pop_as_sandbox(&mut token, &sandbox, &dkh, now_secs());
        assert!(matches!(
            check_client_pop(&token, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::CapPopMismatch)
        ));
    }

    #[test]
    fn delegation_scope_is_namespace_aware() {
        // THE #369 e2e step-4 vs step-6 distinction: a delegation can be scoped to
        // specific memory NAMESPACES (the cap `service`, e.g. `memory:travel`), not
        // just the `memory` data class — so a respawned sandbox whose delegation
        // omits travel is denied a travel recall even though its on-chain grant
        // still covers all of memory.
        let device = fresh_device("ak-deleg-ns-device.key");
        let sandbox = fresh_device("ak-deleg-ns-sandbox.key");
        let dkh = device.device_key_hash().unwrap();

        // A canonical-get of memory:travel (service = the namespace).
        let mut travel = sample_token_with_class(CapOp::CanonicalFetch, DataClass::Memory);
        travel.payload.service = "memory:travel".into();
        sign_pop_as_sandbox(&mut travel, &sandbox, &dkh, now_secs());

        // step 4 — scope INCLUDES travel → allowed.
        let mut ok = travel.clone();
        attach_delegation(
            &mut ok,
            &device,
            sandbox.address(),
            "memory:travel memory:personal",
            now_secs() + 3600,
        );
        assert!(check_client_pop(&ok, CAP_POP_MAX_AGE_SECS).is_ok());

        // step 6 — scope EXCLUDES travel (only personal/family) → denied, even
        // though the cap's data_class is "memory".
        let mut deny = travel.clone();
        attach_delegation(
            &mut deny,
            &device,
            sandbox.address(),
            "memory:personal memory:family",
            now_secs() + 3600,
        );
        assert!(matches!(
            check_client_pop(&deny, CAP_POP_MAX_AGE_SECS),
            Err(VerifyError::DelegationOutOfScope { .. })
        ));

        // A bare `memory` scope still authorizes ANY namespace (back-compat).
        let mut wide = travel.clone();
        attach_delegation(
            &mut wide,
            &device,
            sandbox.address(),
            "memory",
            now_secs() + 3600,
        );
        assert!(check_client_pop(&wide, CAP_POP_MAX_AGE_SECS).is_ok());
    }
}
