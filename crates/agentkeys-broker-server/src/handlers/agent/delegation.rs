//! `/v1/agent/delegation/*` — the device→sandbox delegation rendezvous (issue
//! #369 origination side). Four endpoints across two callers + two auth modes:
//!
//! - `POST /request` (sandbox, **J1-gated**) — opens a request for a delegation to
//!   the sandbox's ephemeral `sandbox_pubkey`. The target device is derived from
//!   the J1's `device_pubkey` claim, NEVER the body, so a sandbox cannot request a
//!   delegation for a device other than the one its session is bound to.
//! - `POST /pending` (device, **pop_sig-gated**) — the device discovers the open
//!   requests it must co-sign (their `sandbox_pubkey` + `requested_scope`).
//! - `POST /sign` (device, **pop_sig-gated**) — the device submits the K10
//!   co-signature over `delegation_payload(device_key_hash, sandbox_pubkey, scope,
//!   expires_at)`. The broker verifies it binds the stored `sandbox_pubkey`
//!   (defense-in-depth) before recording it; the worker re-verifies regardless.
//! - `POST /poll` (sandbox, **J1-gated**) — the sandbox retrieves the device-signed
//!   `{scope, expires_at, delegation_sig}` and attaches it as the cap-mint
//!   `delegation_path`.
//!
//! The broker stays UNTRUSTED throughout: it only relays the device's signature,
//! it never holds K10 and cannot forge a delegation (the #76/#369 posture).

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::{BrokerError, BrokerResult};
use crate::handlers::agent::unix_now;
use crate::handlers::grant::{random_b64url, require_session_jwt};
use crate::state::SharedState;
use crate::storage::{DelegationPoll, DelegationSign, SignTarget, DELEGATION_REQUEST_TTL_SECONDS};

/// Clamp the sandbox's requested delegation TTL. A floor stops a uselessly-short
/// delegation; the ceiling (1 day) bounds the blast radius of one bootstrap so a
/// compromised sandbox key is good for at most a day, not indefinitely.
const MIN_DELEGATION_TTL_SECONDS: u64 = 60;
const MAX_DELEGATION_TTL_SECONDS: u64 = 86_400;

/// #409 §14.11: the device→sandbox delegation-sig (#369) is a **legacy,
/// transitional** mechanism. Under the channels model a device is its own
/// channel-endpoint actor and a delegate's identity roots in its sandbox K10 —
/// so once the one-firmware-cycle migration is complete the operator flips
/// `AGENTKEYS_DELEGATION_RETIRED=1` and every `/v1/agent/delegation/*` endpoint
/// **refuses loudly** (an actionable error, not a silent 404) so a stale device
/// still on the old path learns it must re-bind. Default OFF (the path stays
/// live through the migration window).
pub fn delegation_retired() -> bool {
    matches!(
        std::env::var("AGENTKEYS_DELEGATION_RETIRED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// The loud refusal returned by every delegation endpoint once retired.
fn delegation_retired_err() -> BrokerError {
    BrokerError::Forbidden(
        "device→sandbox delegation (#369) is RETIRED on this broker \
         (AGENTKEYS_DELEGATION_RETIRED=1, #409 §14.11 migration complete). A device is now its \
         own channel-endpoint actor and a delegate roots in its sandbox K10 — re-bind this \
         device via the §10.2 pairing with channel grants (the delegation-sig path no longer \
         mints caps). See docs/spec/agent-channel-decoupling.md §11."
            .into(),
    )
}

/// Verify a device `pop_sig` (stateless) and return its `device_key_hash`. Same
/// proof the §10.2 pairing/resolve endpoints use: a bad signature touches no
/// state. Local to this module (the pairing handlers inline the same steps).
fn verify_device_pop(device_pubkey: &str, pop_sig: &str) -> BrokerResult<String> {
    let device_key_hash = agentkeys_core::device_crypto::device_key_hash(device_pubkey)
        .map_err(|e| BrokerError::BadRequest(format!("bad device_pubkey: {e}")))?;
    let pop_payload = agentkeys_core::device_crypto::agent_pop_payload(&device_key_hash);
    let recovered = agentkeys_core::device_crypto::ecrecover_eip191(&pop_payload, pop_sig)
        .map_err(|e| BrokerError::Unauthorized(format!("pop_sig verify: {e}")))?;
    if recovered.to_lowercase() != device_pubkey.to_lowercase() {
        return Err(BrokerError::Unauthorized(format!(
            "pop_sig does not recover to device_pubkey: claimed={device_pubkey}, recovered={recovered}"
        )));
    }
    Ok(device_key_hash)
}

/// The `device_key_hash` of the device a sandbox's J1 is bound to. The sandbox
/// cannot influence this — it comes from the signed session claim, so a sandbox
/// can only ever act for ITS OWN device.
fn session_device_key_hash(
    session_device_pubkey: Option<String>,
) -> BrokerResult<(String, String)> {
    let device_pubkey = session_device_pubkey.ok_or_else(|| {
        BrokerError::Unauthorized(
            "session has no device_pubkey claim — only an agent (J1) session can broker a delegation"
                .into(),
        )
    })?;
    let device_key_hash = agentkeys_core::device_crypto::device_key_hash(&device_pubkey)
        .map_err(|e| BrokerError::Internal(format!("session device_pubkey not an address: {e}")))?;
    Ok((device_pubkey, device_key_hash))
}

#[derive(Debug, Deserialize)]
pub struct DelegationRequestBody {
    /// The sandbox's OWN ephemeral EVM address (`0x` + 40 hex) to delegate to.
    pub sandbox_pubkey: String,
    /// The scope the sandbox is asking for (space-delimited `data_class` /
    /// `data_class:op` tokens). The device may narrow it when it signs.
    pub requested_scope: String,
    /// Requested delegation lifetime; clamped to `[60, 86400]`. The device sets the
    /// final `expires_at` when it signs (it may shorten further).
    #[serde(default)]
    pub requested_ttl_seconds: Option<u64>,
}

pub async fn delegation_request(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<DelegationRequestBody>,
) -> Result<impl IntoResponse, BrokerError> {
    if delegation_retired() {
        return Err(delegation_retired_err());
    }
    let session = require_session_jwt(&headers, &state)?;
    let (_device_pubkey, device_key_hash) =
        session_device_key_hash(session.agentkeys.device_pubkey)?;
    let actor_omni = session.agentkeys.omni_account;
    let operator_omni = session
        .agentkeys
        .parent_omni
        .unwrap_or_else(|| actor_omni.clone());

    // The sandbox key must be a well-formed address (device_key_hash validates the
    // 20-byte decode) — reject garbage before it reaches the device.
    agentkeys_core::device_crypto::device_key_hash(&body.sandbox_pubkey)
        .map_err(|e| BrokerError::BadRequest(format!("bad sandbox_pubkey: {e}")))?;

    let requested_ttl =
        body.requested_ttl_seconds
            .unwrap_or(3600)
            .clamp(MIN_DELEGATION_TTL_SECONDS, MAX_DELEGATION_TTL_SECONDS) as i64;
    let request_id = random_b64url(32);
    let now = unix_now()?;
    let expires_at = now + DELEGATION_REQUEST_TTL_SECONDS;

    state.agent_delegation_store.request(
        &request_id,
        &device_key_hash,
        &operator_omni,
        &actor_omni,
        &body.sandbox_pubkey,
        &body.requested_scope,
        requested_ttl,
        now,
        expires_at,
    )?;

    tracing::info!(
        actor_omni = %actor_omni,
        device_key_hash = %device_key_hash,
        sandbox = %body.sandbox_pubkey,
        "opened §369 delegation request — awaiting device co-sign"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "request_id": request_id,
            "device_key_hash": device_key_hash,
            "expires_at": expires_at,
        })),
    ))
}

#[derive(Debug, Deserialize)]
pub struct DelegationPendingBody {
    pub device_pubkey: String,
    /// EIP-191 `pop_sig` over `keccak256("agentkeys-agent-pop:" || device_key_hash)`.
    pub pop_sig: String,
}

pub async fn delegation_pending(
    State(state): State<SharedState>,
    Json(body): Json<DelegationPendingBody>,
) -> Result<impl IntoResponse, BrokerError> {
    if delegation_retired() {
        return Err(delegation_retired_err());
    }
    let device_key_hash = verify_device_pop(&body.device_pubkey, &body.pop_sig)?;
    let now = unix_now()?;
    let pending = state
        .agent_delegation_store
        .pending(&device_key_hash, now)?;
    Ok((StatusCode::OK, Json(json!({ "pending": pending }))))
}

#[derive(Debug, Deserialize)]
pub struct DelegationSignBody {
    pub device_pubkey: String,
    /// Fresh EIP-191 `pop_sig` proving K10 possession at sign time.
    pub pop_sig: String,
    /// The request the sandbox opened (from `/pending`).
    pub request_id: String,
    /// The (possibly narrowed) scope the device is co-signing.
    pub scope: String,
    /// The delegation's expiry (unix seconds) the device chose + signed.
    pub expires_at: u64,
    /// The device's EIP-191 signature over `delegation_payload(device_key_hash,
    /// sandbox_pubkey, scope, expires_at)`.
    pub delegation_sig: String,
}

pub async fn delegation_sign(
    State(state): State<SharedState>,
    Json(body): Json<DelegationSignBody>,
) -> Result<impl IntoResponse, BrokerError> {
    if delegation_retired() {
        return Err(delegation_retired_err());
    }
    let device_key_hash = verify_device_pop(&body.device_pubkey, &body.pop_sig)?;
    let now = unix_now()?;

    let sandbox_pubkey =
        match state
            .agent_delegation_store
            .sign_target(&body.request_id, &device_key_hash, now)?
        {
            SignTarget::Ready { sandbox_pubkey, .. } => sandbox_pubkey,
            SignTarget::Expired => {
                return Err(BrokerError::BadRequest(
                    "delegation request expired before the device co-signed".into(),
                ));
            }
            SignTarget::NotFoundOrSigned => {
                return Err(BrokerError::Unauthorized(
                    "unknown delegation request, already signed, or device mismatch".into(),
                ));
            }
        };

    // Defense-in-depth: the device's signature MUST bind the STORED sandbox key
    // (the one the sandbox actually requested) — so the device can't co-sign a
    // delegation for a different key than the rendezvous recorded. The worker
    // re-verifies this same signature, so this is an early reject, not the gate.
    agentkeys_core::device_crypto::verify_delegation(
        &device_key_hash,
        &sandbox_pubkey,
        &body.scope,
        body.expires_at,
        &body.delegation_sig,
    )
    .map_err(|e| {
        BrokerError::BadRequest(format!(
            "delegation_sig does not verify for (device, sandbox, scope, expires_at): {e}"
        ))
    })?;

    match state.agent_delegation_store.record_signature(
        &body.request_id,
        &device_key_hash,
        &body.scope,
        body.expires_at as i64,
        &body.delegation_sig,
        now,
    )? {
        DelegationSign::Signed => {
            tracing::info!(
                device_key_hash = %device_key_hash,
                sandbox = %sandbox_pubkey,
                request_id = %body.request_id,
                "recorded §369 device co-signature — sandbox may now mint delegated caps"
            );
            Ok((StatusCode::OK, Json(json!({ "signed": true }))))
        }
        DelegationSign::Expired => Err(BrokerError::BadRequest(
            "delegation request expired before the device co-signed".into(),
        )),
        DelegationSign::NotFoundOrSigned => Err(BrokerError::BadRequest(
            "delegation request already signed".into(),
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct DelegationPollBody {
    /// The sandbox's request ticket from `/v1/agent/delegation/request`.
    pub request_id: String,
}

pub async fn delegation_poll(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<DelegationPollBody>,
) -> Result<impl IntoResponse, BrokerError> {
    if delegation_retired() {
        return Err(delegation_retired_err());
    }
    let session = require_session_jwt(&headers, &state)?;
    let (_device_pubkey, device_key_hash) =
        session_device_key_hash(session.agentkeys.device_pubkey)?;
    let now = unix_now()?;

    match state
        .agent_delegation_store
        .poll(&body.request_id, &device_key_hash, now)?
    {
        DelegationPoll::Pending => Ok((StatusCode::OK, Json(json!({ "status": "pending" })))),
        DelegationPoll::Signed {
            scope,
            expires_at,
            delegation_sig,
        } => Ok((
            StatusCode::OK,
            Json(json!({
                "status": "signed",
                "scope": scope,
                "expires_at": expires_at,
                "delegation_sig": delegation_sig,
            })),
        )),
        DelegationPoll::Expired => Err(BrokerError::Unauthorized(
            "delegation request expired before the device co-signed — re-request".into(),
        )),
        DelegationPoll::NotFound => Err(BrokerError::Unauthorized(
            "unknown delegation request or device mismatch".into(),
        )),
    }
}
