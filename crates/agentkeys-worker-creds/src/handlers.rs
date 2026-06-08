//! HTTP handlers — wired into a tower service in main.rs.
//!
//! Endpoints:
//!   GET  /healthz                — service ready check
//!   POST /v1/cred/store          — verify cap (store op) → encrypt → S3 PUT
//!   POST /v1/cred/fetch          — verify cap (fetch op) → S3 GET → decrypt → return
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

use crate::aws_creds::{s3_for_request, OptionalStsCreds};
use crate::envelope;
use crate::errors::{err_400, err_403, err_500, err_502, ApiError};
use crate::state::SharedWorkerState;
use crate::verify::{self, CapOp, CapToken, DataClass};

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

#[derive(Debug, Deserialize)]
pub struct StoreRequest {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

#[derive(Debug, Serialize)]
pub struct StoreResponse {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct FetchRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    pub ok: bool,
    pub plaintext_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct TeardownRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct TeardownResponse {
    pub ok: bool,
    pub keys_deleted: usize,
}

async fn cred_store(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<StoreRequest>,
) -> Result<Json<StoreResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Store).await?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let plaintext = STANDARD
        .decode(&req.plaintext_b64)
        .map_err(|e| err_400(e.to_string(), "plaintext_b64_decode"))?;

    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        &req.cap.payload.actor_omni,
        &req.cap.payload.service,
        req.cap.payload.k3_epoch,
    );
    let env_bytes = envelope::encrypt(&state.config.kek_hex_stage1, &plaintext, &aad)
        .map_err(|e| err_500(e.to_string(), "envelope_encrypt"))?;

    let key = s3_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    s3.put_object()
        .bucket(&state.config.vault_bucket)
        .key(&key)
        .body(env_bytes.clone().into())
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_put"))?;
    Ok(Json(StoreResponse {
        ok: true,
        s3_key: key,
        envelope_size: env_bytes.len(),
    }))
}

async fn cred_fetch(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;

    let key = s3_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    let resp = s3
        .get_object()
        .bucket(&state.config.vault_bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_get"))?;
    let body = resp
        .body
        .collect()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_body"))?
        .into_bytes();

    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        &req.cap.payload.actor_omni,
        &req.cap.payload.service,
        req.cap.payload.k3_epoch,
    );
    let plaintext = envelope::decrypt(&state.config.kek_hex_stage1, &body, &aad)
        .map_err(|e| err_500(e.to_string(), "envelope_decrypt"))?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    Ok(Json(FetchResponse {
        ok: true,
        plaintext_b64: STANDARD.encode(&plaintext),
    }))
}

async fn cred_teardown(
    State(state): State<SharedWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;

    let prefix = s3_prefix(&req.cap.payload.actor_omni);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
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
    Ok(Json(TeardownResponse {
        ok: true,
        keys_deleted: deleted,
    }))
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
