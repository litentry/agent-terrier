//! HTTP handlers — wired into a tower service in main.rs.
//!
//! Endpoints:
//!   GET  /healthz                — service ready check
//!   POST /v1/cred/store          — verify cap (store op, MASTER-SELF ONLY) → encrypt → S3 PUT
//!   POST /v1/cred/fetch          — verify cap (fetch op) → S3 GET (operator vault) → decrypt → return
//!   POST /v1/cred/teardown       — verify cap (teardown op) → S3 DELETE prefix
//!
//! Cap verification (each request, before any S3 touch — arch.md §15.1):
//!   1. broker_sig over Sha256(json(payload))     [verify::verify_signature]
//!   2. cap.op matches endpoint                    [verify::check_op]
//!   3. issued_at <= now + 60s skip; expires_at > now [verify::check_freshness]
//!   4. on-chain getDevice → operator/actor/roles  [verify::check_chain_device]
//!   5. on-chain isServiceInScope                   [verify::check_chain_scope]
//!   6. on-chain currentEpoch == cap.k3_epoch       [verify::check_chain_k3_epoch]

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use agentkeys_core::audit::{
    AuditOpKind, AuditResult, CredFetchBody, CredStoreBody, CredTeardownBody,
};

use crate::audit::{cap_hash, keccak_hex, zero_hash};
use crate::aws_creds::{s3_for_request, OptionalStsCreds};
use crate::envelope;
use crate::errors::{err_400, err_403, err_500, err_502, err_502_s3_get, ApiError, S3FetchAttempt};
use crate::state::SharedWorkerState;
use crate::verify::{self, CapOp, CapPayload, CapToken, DataClass};

pub fn build_router(state: SharedWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/cred/store", post(cred_store))
        .route("/v1/cred/fetch", post(cred_fetch))
        .route("/v1/cred/list", post(cred_list))
        .route("/v1/cred/teardown", post(cred_teardown))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct ListRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub ok: bool,
    /// The stored credential service ids under `bots/<actor>/credentials/` (the
    /// filenames, sans `.enc`). The daemon categorizes these via the catalog so the
    /// master's credentials surface mirrors the memory category list (#207 item 2-app).
    pub services: Vec<String>,
}

/// `POST /v1/cred/list` — enumerate the credential service ids the actor has stored
/// (the per-data-class parallel to listing memory namespaces). **MASTER-ONLY**: a
/// single-service cap must NOT be able to enumerate the whole vault, so this rejects
/// any cap whose `operator != actor` (an agent lists nothing; the master lists its
/// own). Read op (`Fetch`); same cap + chain-verify chain as fetch, no decrypt.
async fn cred_list(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<ListRequest>,
) -> Result<Json<ListResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;
    if req.cap.payload.operator_omni != req.cap.payload.actor_omni {
        return Err(err_403(
            "cred list is master-only (operator must equal actor)",
            "list_not_master_self",
        ));
    }
    let prefix = s3_prefix(&req.cap.payload.actor_omni);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    let list = s3
        .list_objects_v2()
        .bucket(&state.config.vault_bucket)
        .prefix(&prefix)
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_list"))?;
    let services: Vec<String> = list
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .filter_map(|k| service_from_key(k, &prefix))
        .collect();
    Ok(Json(ListResponse { ok: true, services }))
}

/// Parse the service id out of an S3 key `bots/<actor>/credentials/<service>.enc`
/// given the prefix `bots/<actor>/credentials/`. Returns `None` for a key that
/// isn't under the prefix or lacks the `.enc` suffix (defensive).
fn service_from_key(key: &str, prefix: &str) -> Option<String> {
    key.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".enc"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub vault_bucket: String,
    pub chain_profile: String,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        vault_bucket: state.config.vault_bucket.clone(),
        chain_profile: state.config.chain_profile.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// EXACTLY ONE of `envelope_b64` / `plaintext_b64` (the #372 config recipe
/// applied to cred): `envelope_b64` is a CLIENT-encrypted v3 envelope stored
/// VERBATIM (the worker holds no key that opens it — nothing reaches this
/// process in plaintext); `plaintext_b64` is the legacy mode (worker-side
/// static stage-1 K3 encrypt) that keeps the delegated agent-fetch flow
/// working until the #91 KEK-release lands.
#[derive(Debug, Deserialize)]
pub struct StoreRequest {
    pub cap: CapToken,
    #[serde(default)]
    pub plaintext_b64: Option<String>,
    #[serde(default)]
    pub envelope_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StoreResponse {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the audit
    /// worker stored for this op — the exact 32-byte commitment
    /// `CredentialAudit.appendV2` anchors. `null` when the emit failed in
    /// best-effort mode (`AGENTKEYS_WORKER_REQUIRE_AUDIT` unset).
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FetchRequest {
    pub cap: CapToken,
}

/// EXACTLY ONE of `plaintext_b64` / `envelope_b64` is set: legacy v2 blobs
/// come back worker-decrypted; v3 blobs come back as the raw envelope for
/// CLIENT-side decrypt under the signer-derived KEK (#372 recipe — this
/// worker cannot open them). `skip_serializing_if` keeps the legacy JSON
/// byte-identical for pre-dual-mode readers.
#[derive(Debug, Serialize)]
pub struct FetchResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_b64: Option<String>,
    /// Durable-audit receipt (#229) — see [`StoreResponse::audit_envelope_hash`].
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TeardownRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct TeardownResponse {
    pub ok: bool,
    pub keys_deleted: usize,
    /// Durable-audit receipt (#229) — see [`StoreResponse::audit_envelope_hash`].
    pub audit_envelope_hash: Option<String>,
}

async fn cred_store(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<StoreRequest>,
) -> Result<Json<StoreResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Store).await?;
    // Single-vault layer-2 gate (docs/plan/single-vault-credentials.md):
    // credentials are MASTER-VAULTED ONLY — reject a delegated store cap even
    // if a (compromised) broker minted one. Defense-in-depth mirror of the
    // broker's cred_store_not_master_self gate; closes the #228 shadowing
    // hole at the worker too. Both omnis are broker-normalized 0x-lowercase.
    if req.cap.payload.operator_omni != req.cap.payload.actor_omni {
        return Err(err_403(
            "cred store is master-self only (operator must equal actor) — \
             agents cannot self-store credentials (single-vault)",
            "cred_store_not_master_self",
        ));
    }

    let outcome = cred_store_inner(&state, creds.as_ref(), &req).await;
    // Durable audit (#229): after cap-verify, before the success response.
    // payload_hash covers the stored CIPHERTEXT (never plaintext); failures
    // after cap-verify are audited too, with a zero placeholder hash.
    let audit_body = CredStoreBody {
        service: req.cap.payload.service.clone(),
        payload_hash: match &outcome {
            Ok((_, env_bytes)) => keccak_hex(env_bytes),
            Err(_) => zero_hash(),
        },
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(&req.cap, AuditOpKind::CredStore, audit_body, audit_result)
        .await;
    let (key, env_bytes) = outcome?; // op error wins over an emit error
    Ok(Json(StoreResponse {
        ok: true,
        s3_key: key,
        envelope_size: env_bytes.len(),
        audit_envelope_hash: audited?,
    }))
}

async fn cred_store_inner(
    state: &SharedWorkerState,
    creds: Option<&crate::aws_creds::StsCreds>,
    req: &StoreRequest,
) -> Result<(String, Vec<u8>), ApiError> {
    let env_bytes = resolve_store_bytes(req, &state.config.kek_hex_stage1)?;

    let key = s3_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds).await;
    s3.put_object()
        .bucket(&state.config.vault_bucket)
        .key(&key)
        .body(env_bytes.clone().into())
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_put"))?;
    Ok((key, env_bytes))
}

/// The bytes cred_store S3-PUTs, resolved from the request's mode — EXACTLY
/// ONE of `envelope_b64` / `plaintext_b64` (the config worker's #372
/// validation, mirrored). Pure (no S3) so the mode matrix is unit-testable.
fn resolve_store_bytes(req: &StoreRequest, kek_hex_stage1: &str) -> Result<Vec<u8>, ApiError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    match (&req.envelope_b64, &req.plaintext_b64) {
        (Some(_), Some(_)) => Err(err_400(
            "exactly one of envelope_b64 / plaintext_b64 (both given)",
            "store_mode_ambiguous",
        )),
        (None, None) => Err(err_400(
            "exactly one of envelope_b64 / plaintext_b64 (neither given)",
            "store_mode_missing",
        )),
        (Some(env_b64), None) => {
            // v3: CLIENT-encrypted under the signer-derived KEK — version-sniff,
            // then store VERBATIM. This worker holds no key that opens it.
            let bytes = STANDARD
                .decode(env_b64)
                .map_err(|e| err_400(e.to_string(), "envelope_b64_decode"))?;
            match envelope::version(&bytes) {
                Some(envelope::ENVELOPE_VERSION_V3) => Ok(bytes),
                Some(v) => Err(err_400(
                    format!("envelope_b64 must be a v3 envelope (got version 0x{v:02x})"),
                    "envelope_not_v3",
                )),
                None => Err(err_400(
                    format!(
                        "envelope_b64 too short to be an envelope ({} bytes)",
                        bytes.len()
                    ),
                    "envelope_truncated",
                )),
            }
        }
        (None, Some(pt_b64)) => {
            // Legacy: worker-side static stage-1 K3 encrypt (v2 envelope).
            let plaintext = STANDARD
                .decode(pt_b64)
                .map_err(|e| err_400(e.to_string(), "plaintext_b64_decode"))?;
            let aad = envelope::aad(
                &req.cap.payload.operator_omni,
                &req.cap.payload.actor_omni,
                &req.cap.payload.service,
                req.cap.payload.k3_epoch,
            );
            envelope::encrypt(kek_hex_stage1, &plaintext, &aad)
                .map_err(|e| err_500(e.to_string(), "envelope_encrypt"))
        }
    }
}

async fn cred_fetch(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;

    let outcome = cred_fetch_inner(&state, creds.as_ref(), &req).await;
    // Durable audit (#229): the secret-release record. cap_hash binds the
    // row to the exact cap that authorized this fetch; emitted BEFORE the
    // plaintext leaves the worker.
    let audit_body = CredFetchBody {
        service: req.cap.payload.service.clone(),
        cap_hash: cap_hash(&req.cap),
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(&req.cap, AuditOpKind::CredFetch, audit_body, audit_result)
        .await;
    let fetched = outcome?;
    let audit_envelope_hash = audited?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (plaintext_b64, envelope_b64) = match fetched {
        CredFetched::Plaintext(pt) => (Some(STANDARD.encode(&pt)), None),
        CredFetched::V3Envelope(env) => (None, Some(STANDARD.encode(&env))),
    };
    Ok(Json(FetchResponse {
        ok: true,
        plaintext_b64,
        envelope_b64,
        audit_envelope_hash,
    }))
}

/// What `cred_fetch_inner` hands back (the config worker's `ConfigFetched`
/// mirrored): legacy v2 blobs are worker-decrypted (static stage-1 KEK); v3
/// blobs are returned as the raw envelope for CLIENT-side decrypt under the
/// signer-derived KEK (#372 recipe — this worker holds no key that opens them).
enum CredFetched {
    Plaintext(Vec<u8>),
    V3Envelope(Vec<u8>),
}

async fn cred_fetch_inner(
    state: &SharedWorkerState,
    creds: Option<&crate::aws_creds::StsCreds>,
    req: &FetchRequest,
) -> Result<CredFetched, ApiError> {
    // Single-vault (docs/plan/single-vault-credentials.md): every credential
    // lives in the OPERATOR's vault, so a fetch reads exactly ONE prefix —
    // bots/<operator>/credentials/. A master-self cap (operator == actor) is
    // the degenerate case; a DELEGATED cap (actor != operator, #216) reads
    // the SAME vault — the cap's already-verified on-chain cred:<service>
    // scope grant IS the agent's authorization, and the S3 read runs under
    // the CALLER-relayed STS creds (reading the operator prefix requires
    // operator-tagged STS — the wire context's operator session; layer-3 IAM
    // untouched). The #228 agent-own vault and its shadowing fetch order were
    // REMOVED: store is master-self-only at both broker and worker, so an
    // actor-keyed candidate can no longer exist. The envelope AAD is keyed by
    // the vault OWNER (= the operator), matching the
    // aad(operator, actor == operator, service, epoch) written at
    // master-self store time.
    let s3 = s3_for_request(&state.s3, &state.config.region, creds).await;
    let owner = fetch_vault_owner(&req.cap.payload);
    let key = s3_key(owner, &req.cap.payload.service);
    let resp = s3
        .get_object()
        .bucket(&state.config.vault_bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| {
            // The 502 names the S3 error code (#284): NoSuchKey (service never
            // vaulted by the master) vs AccessDenied (caller relayed
            // non-operator-tagged STS) vs expired-STS — distinguishable from
            // the wire without host access.
            let attempt = S3FetchAttempt::from_sdk_err("operator", owner, &e);
            tracing::warn!(
                vault = attempt.vault,
                owner_omni = %owner,
                s3_code = %attempt.s3_code,
                bucket = %state.config.vault_bucket,
                service = %req.cap.payload.service,
                "cred fetch: S3 GetObject failed"
            );
            err_502_s3_get(&state.config.vault_bucket, vec![attempt])
        })?;
    let body = resp
        .body
        .collect()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_body"))?
        .into_bytes();

    // Version sniff: v3 blobs pass through VERBATIM (client-side decrypt under
    // the signer-derived KEK — the static worker KEK cannot open them, and
    // trying would fail loudly as an AAD/version mismatch anyway).
    if envelope::version(&body) == Some(envelope::ENVELOPE_VERSION_V3) {
        return Ok(CredFetched::V3Envelope(body.to_vec()));
    }
    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        owner,
        &req.cap.payload.service,
        req.cap.payload.k3_epoch,
    );
    envelope::decrypt(&state.config.kek_hex_stage1, &body, &aad)
        .map(CredFetched::Plaintext)
        .map_err(|e| err_500(e.to_string(), "envelope_decrypt"))
}

/// Single-vault (docs/plan/single-vault-credentials.md): the ONLY vault a
/// fetch reads — the OPERATOR's. Master-self caps are the degenerate case
/// (operator == actor). Executable decision record: if this ever returns the
/// ACTOR's omni again, the #228 shadowing hole reopens (an agent-stored key
/// silently replacing the master-authorized one) — read the plan doc before
/// changing it.
fn fetch_vault_owner(payload: &CapPayload) -> &str {
    &payload.operator_omni
}

async fn cred_teardown(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;

    let outcome = cred_teardown_inner(&state, creds.as_ref(), &req).await;
    let audit_body = CredTeardownBody {
        actor_target: req.cap.payload.actor_omni.clone(),
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(
            &req.cap,
            AuditOpKind::CredTeardown,
            audit_body,
            audit_result,
        )
        .await;
    let deleted = outcome?;
    Ok(Json(TeardownResponse {
        ok: true,
        keys_deleted: deleted,
        audit_envelope_hash: audited?,
    }))
}

async fn cred_teardown_inner(
    state: &SharedWorkerState,
    creds: Option<&crate::aws_creds::StsCreds>,
    req: &TeardownRequest,
) -> Result<usize, ApiError> {
    let prefix = s3_prefix(&req.cap.payload.actor_omni);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds).await;
    let list = s3
        .list_objects_v2()
        .bucket(&state.config.vault_bucket)
        .prefix(&prefix)
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_list"))?;
    let keys: Vec<String> = list
        .contents()
        .iter()
        .filter_map(|o| o.key().map(String::from))
        .collect();
    let mut deleted = 0usize;
    for k in &keys {
        if s3
            .delete_object()
            .bucket(&state.config.vault_bucket)
            .key(k)
            .send()
            .await
            .is_ok()
        {
            deleted += 1;
        }
    }
    Ok(deleted)
}

async fn verify_cap(
    state: &SharedWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    verify::verify_signature(&state.config.broker_pubkey_pem, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    // K10 proof-of-possession (issue #76 — broker-SPOF defense). broker_sig
    // proves the BROKER authorized this cap; the cap-PoP proves the USER's device
    // did — which a compromised broker cannot forge. A supplied PoP is always
    // verified; a MISSING PoP is rejected only under AGENTKEYS_WORKER_REQUIRE_CAP_POP=1
    // (staged rollout — see verify::enforce_client_pop).
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    verify::check_op(cap, expected_op).map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    // Per-data-class isolation gate (issue #90 followup): a memory-class
    // cap MUST NOT be honoured at the credentials worker.
    verify::check_data_class(cap, DataClass::Credentials)
        .map_err(|e| err_403(e.to_string(), "cap_data_class_mismatch"))?;
    verify::check_freshness(cap).map_err(|e| err_403(e.to_string(), "cap_freshness_failed"))?;
    verify::check_chain_device(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.registry_contract,
        cap,
    )
    .await
    .map_err(|e| match e {
        verify::VerifyError::DeviceInactive => err_403(e.to_string(), "device_inactive"),
        verify::VerifyError::DeviceMismatch { .. } => {
            err_403(e.to_string(), "device_binding_mismatch")
        }
        verify::VerifyError::DeviceRoleMissing { .. } => {
            err_403(e.to_string(), "device_role_missing")
        }
        _ => err_502(e.to_string(), "chain_rpc"),
    })?;
    verify::check_chain_scope(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.scope_contract,
        cap,
    )
    .await
    .map_err(|e| match e {
        verify::VerifyError::NotInScope => err_403(e.to_string(), "service_not_in_scope"),
        _ => err_502(e.to_string(), "chain_rpc"),
    })?;
    verify::check_chain_k3_epoch(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.epoch_contract,
        cap,
    )
    .await
    .map_err(|e| match e {
        verify::VerifyError::K3Mismatch { .. } => err_403(e.to_string(), "k3_epoch_mismatch"),
        _ => err_502(e.to_string(), "chain_rpc"),
    })?;
    Ok(())
}

fn s3_key(actor_omni: &str, service: &str) -> String {
    format!(
        "bots/{}/credentials/{}.enc",
        actor_omni.trim_start_matches("0x").to_lowercase(),
        service.to_lowercase()
    )
}

fn s3_prefix(actor_omni: &str) -> String {
    format!(
        "bots/{}/credentials/",
        actor_omni.trim_start_matches("0x").to_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(operator: &str, actor: &str) -> CapPayload {
        CapPayload {
            operator_omni: operator.to_string(),
            actor_omni: actor.to_string(),
            service: "openrouter".to_string(),
            op: CapOp::Fetch,
            data_class: DataClass::Credentials,
            device_key_hash: format!("0x{}", "c".repeat(64)),
            k3_epoch: 1,
            issued_at: 0,
            expires_at: u64::MAX,
            nonce: "n".to_string(),
        }
    }

    #[test]
    fn fetch_reads_exactly_the_operator_vault() {
        // Single-vault decision record (docs/plan/single-vault-credentials.md):
        // master-self (operator == actor) — the degenerate case…
        assert_eq!(
            fetch_vault_owner(&payload("0xmaster", "0xmaster")),
            "0xmaster"
        );
        // …and DELEGATED (#216): the agent fetches the MASTER-vaulted key from
        // the operator's prefix. Never an actor-keyed candidate — returning
        // the actor here would reopen the #228 shadowing hole.
        let delegated = payload("0xmaster", "0xagent");
        assert_eq!(fetch_vault_owner(&delegated), "0xmaster");
        assert_eq!(
            s3_key(fetch_vault_owner(&delegated), &delegated.service),
            "bots/master/credentials/openrouter.enc"
        );
    }

    #[test]
    fn s3_key_format_matches_arch_md_15_1() {
        // arch.md §15.1: s3://$VAULT_BUCKET/bots/<actor_omni_hex>/credentials/<service>.enc
        assert_eq!(
            s3_key("0xABCDEF", "openrouter"),
            "bots/abcdef/credentials/openrouter.enc"
        );
        assert_eq!(
            s3_key("abcdef", "OpenRouter"),
            "bots/abcdef/credentials/openrouter.enc"
        );
    }

    #[test]
    fn s3_prefix_matches_arch_md_15_1() {
        assert_eq!(s3_prefix("0xABCDEF"), "bots/abcdef/credentials/");
    }

    fn store_req(envelope_b64: Option<String>, plaintext_b64: Option<String>) -> StoreRequest {
        StoreRequest {
            cap: CapToken {
                payload: payload("0xmaster", "0xmaster"),
                broker_sig: "sig".to_string(),
                client_sig: None,
                client_nonce: None,
                client_ts: None,
                delegation_path: None,
            },
            plaintext_b64,
            envelope_b64,
        }
    }

    const TEST_KEK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// The e2e worker-GENERATION probe (suite-3 step 11) keys on this: a
    /// CURRENT worker must DESERIALIZE a store body carrying neither mode, so
    /// the request reaches the mode gate and answers 400 `store_mode_missing`;
    /// a pre-dual-mode worker refuses the same body at the serde layer (422,
    /// `plaintext_b64` required). If `plaintext_b64` ever becomes required
    /// again, that probe would silently misreport every current worker as
    /// "predates dual-mode" — so pin the optionality here.
    #[test]
    fn store_request_deserializes_with_neither_mode() {
        let req = store_req(None, None);
        let json = serde_json::json!({ "cap": req.cap });
        let parsed: StoreRequest =
            serde_json::from_value(json).expect("a neither-mode body must deserialize (not 422)");
        assert!(parsed.plaintext_b64.is_none());
        assert!(parsed.envelope_b64.is_none());
        // …and it is the MODE GATE that rejects it, with the reason the probe reads.
        let err = resolve_store_bytes(&parsed, TEST_KEK_HEX).unwrap_err();
        assert_eq!(err.1 .0.reason, "store_mode_missing");
    }

    #[test]
    fn store_rejects_both_modes_given() {
        let req = store_req(Some("aa".into()), Some("bb".into()));
        let err = resolve_store_bytes(&req, TEST_KEK_HEX).unwrap_err();
        assert_eq!(err.1 .0.reason, "store_mode_ambiguous");
    }

    #[test]
    fn store_rejects_neither_mode_given() {
        let req = store_req(None, None);
        let err = resolve_store_bytes(&req, TEST_KEK_HEX).unwrap_err();
        assert_eq!(err.1 .0.reason, "store_mode_missing");
    }

    #[test]
    fn store_v3_envelope_is_stored_verbatim() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        // A client-encrypted v3 envelope must land in S3 byte-identical —
        // the worker never re-wraps (it holds no key that opens it).
        let kek = [7u8; 32];
        let aad = envelope::aad_v3("0xmaster", "openrouter");
        let env = envelope::encrypt_v3(&kek, b"sk-secret", &aad).unwrap();
        let req = store_req(Some(STANDARD.encode(&env)), None);
        let stored = resolve_store_bytes(&req, TEST_KEK_HEX).unwrap();
        assert_eq!(stored, env, "v3 envelope must be stored verbatim");
        assert_eq!(
            envelope::version(&stored),
            Some(envelope::ENVELOPE_VERSION_V3)
        );
    }

    #[test]
    fn store_rejects_non_v3_envelope_version() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let kek = [7u8; 32];
        let aad = envelope::aad_v3("0xmaster", "openrouter");
        let mut env = envelope::encrypt_v3(&kek, b"sk-secret", &aad).unwrap();
        env[0] = 0x02; // masquerade as a v2 blob — the worker-side format
        let req = store_req(Some(STANDARD.encode(&env)), None);
        let err = resolve_store_bytes(&req, TEST_KEK_HEX).unwrap_err();
        assert_eq!(err.1 .0.reason, "envelope_not_v3");
    }

    #[test]
    fn store_rejects_truncated_envelope() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let req = store_req(Some(STANDARD.encode([0x03, 0x00])), None);
        let err = resolve_store_bytes(&req, TEST_KEK_HEX).unwrap_err();
        assert_eq!(err.1 .0.reason, "envelope_truncated");
    }

    #[test]
    fn store_plaintext_keeps_the_legacy_v2_path() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let req = store_req(None, Some(STANDARD.encode(b"sk-secret")));
        let stored = resolve_store_bytes(&req, TEST_KEK_HEX).unwrap();
        let aad = envelope::aad(
            &req.cap.payload.operator_omni,
            &req.cap.payload.actor_omni,
            &req.cap.payload.service,
            req.cap.payload.k3_epoch,
        );
        let pt = envelope::decrypt(TEST_KEK_HEX, &stored, &aad).unwrap();
        assert_eq!(pt, b"sk-secret", "legacy mode must stay worker-decryptable");
        assert_ne!(
            envelope::version(&stored),
            Some(envelope::ENVELOPE_VERSION_V3)
        );
    }

    #[test]
    fn service_from_key_parses_service_id() {
        let prefix = "bots/abcdef/credentials/";
        assert_eq!(
            service_from_key("bots/abcdef/credentials/openrouter.enc", prefix),
            Some("openrouter".to_string())
        );
        assert_eq!(
            service_from_key("bots/abcdef/credentials/stripe.enc", prefix),
            Some("stripe".to_string())
        );
        // not under the prefix / no .enc / empty → None (defensive)
        assert_eq!(
            service_from_key("bots/other/credentials/x.enc", prefix),
            None
        );
        assert_eq!(
            service_from_key("bots/abcdef/credentials/x.txt", prefix),
            None
        );
        assert_eq!(
            service_from_key("bots/abcdef/credentials/.enc", prefix),
            None
        );
    }
}
