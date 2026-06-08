//! Memory worker HTTP surface — mirrors credentials worker but at the
//! `memory/` prefix per arch.md §15.2 + §17 per-data-class buckets.

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedMemoryWorkerState;
use agentkeys_worker_creds::aws_creds::{s3_for_request, OptionalStsCreds};
use agentkeys_worker_creds::envelope;
use agentkeys_worker_creds::errors::{err_400, err_403, err_404, err_500, err_502, ApiError};
use agentkeys_worker_creds::verify::{self, CapOp, CapToken, DataClass};

pub fn build_router(state: SharedMemoryWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/memory/put", post(memory_put))
        .route("/v1/memory/get", post(memory_get))
        .route("/v1/memory/teardown", post(memory_teardown))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub memory_bucket: String,
    pub chain_profile: String,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedMemoryWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        memory_bucket: state.config.memory_bucket.clone(),
        chain_profile: state.config.chain_profile.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Debug, Deserialize)]
pub struct PutRequest {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

#[derive(Debug, Serialize)]
pub struct PutResponse {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct GetRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct GetResponse {
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

async fn memory_put(
    State(state): State<SharedMemoryWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<PutRequest>,
) -> Result<Json<PutResponse>, ApiError> {
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
        .bucket(&state.config.memory_bucket)
        .key(&key)
        .body(env_bytes.clone().into())
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_put"))?;
    Ok(Json(PutResponse {
        ok: true,
        s3_key: key,
        envelope_size: env_bytes.len(),
    }))
}

async fn memory_get(
    State(state): State<SharedMemoryWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;

    let key = s3_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    let resp = s3
        .get_object()
        .bucket(&state.config.memory_bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| {
            // #201 Phase 4: a missing object is 404 (not 502), so a caller can
            // distinguish "namespace never written" from an S3/transport error.
            if e.as_service_error()
                .map(|se| se.is_no_such_key())
                .unwrap_or(false)
            {
                err_404("memory object not found", "s3_no_such_key")
            } else {
                err_502(e.to_string(), "s3_get")
            }
        })?;
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
    Ok(Json(GetResponse {
        ok: true,
        plaintext_b64: STANDARD.encode(&plaintext),
    }))
}

async fn memory_teardown(
    State(state): State<SharedMemoryWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;

    let prefix = s3_prefix(&req.cap.payload.actor_omni);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    let list = s3
        .list_objects_v2()
        .bucket(&state.config.memory_bucket)
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
            .bucket(&state.config.memory_bucket)
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
    state: &SharedMemoryWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    verify::verify_signature(&state.config.broker_pubkey_pem, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    // K10 proof-of-possession (issue #76 — broker-SPOF defense). See the cred
    // worker / verify::enforce_client_pop; shared across data classes.
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    verify::check_op(cap, expected_op).map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    // Per-data-class isolation gate (issue #90 followup): a credentials-class
    // cap MUST NOT be honoured at the memory worker. Symmetric with the cred
    // worker's check, defended in both directions.
    verify::check_data_class(cap, DataClass::Memory)
        .map_err(|e| err_403(e.to_string(), "cap_data_class_mismatch"))?;
    verify::check_freshness(cap).map_err(|e| err_403(e.to_string(), "cap_freshness_failed"))?;
    verify::check_chain_device(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.registry_contract,
        cap,
    )
    .await
    .map_err(err_403_or_502)?;
    verify::check_chain_scope(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.scope_contract,
        cap,
    )
    .await
    .map_err(err_403_or_502)?;
    verify::check_chain_k3_epoch(
        &state.http,
        &state.config.chain_rpc_http,
        &state.config.epoch_contract,
        cap,
    )
    .await
    .map_err(err_403_or_502)?;
    Ok(())
}

fn err_403_or_502(e: verify::VerifyError) -> ApiError {
    match e {
        verify::VerifyError::DeviceInactive
        | verify::VerifyError::DeviceMismatch { .. }
        | verify::VerifyError::DeviceRoleMissing { .. }
        | verify::VerifyError::NotInScope
        | verify::VerifyError::K3Mismatch { .. } => err_403(e.to_string(), "chain_check_failed"),
        _ => err_502(e.to_string(), "chain_rpc"),
    }
}

/// S3 key prefix per arch.md §15.2: `bots/<actor_omni_hex>/memory/<service>.enc`.
/// Distinct from creds worker's `credentials/` prefix; same bucket-relative
/// shape so a single audit pass covers both data classes.
fn s3_key(actor_omni: &str, service: &str) -> String {
    format!(
        "bots/{}/memory/{}.enc",
        actor_omni.trim_start_matches("0x").to_lowercase(),
        service.to_lowercase()
    )
}

fn s3_prefix(actor_omni: &str) -> String {
    format!(
        "bots/{}/memory/",
        actor_omni.trim_start_matches("0x").to_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_key_uses_memory_prefix_not_credentials() {
        // arch.md §17 separation: memory worker writes to bots/<actor>/memory/...,
        // NOT bots/<actor>/credentials/... A drift here would collapse the
        // per-data-class blast-radius.
        assert_eq!(
            s3_key("0xABCDEF", "chat-history"),
            "bots/abcdef/memory/chat-history.enc"
        );
        assert!(!s3_key("0xabc", "x").contains("credentials"));
    }

    #[test]
    fn s3_prefix_uses_memory_path() {
        assert_eq!(s3_prefix("0xABCDEF"), "bots/abcdef/memory/");
    }

    #[test]
    fn namespace_folded_service_segregates_storage() {
        // Issue #147 (approach B): the MCP mints memory caps with
        // service="memory:<namespace>". Because the worker keys S3 off the
        // SIGNED service, two namespaces land at distinct keys — a
        // `memory:travel` cap physically cannot read/write the
        // `memory:personal` object. This is the namespace-isolation gate,
        // enforced by construction (signed service ⇒ key + scope + AAD).
        let travel = s3_key("0xabc", "memory:travel");
        let personal = s3_key("0xabc", "memory:personal");
        assert_ne!(travel, personal);
        assert_eq!(travel, "bots/abc/memory/memory:travel.enc");
        assert!(personal.contains("memory:personal"));
    }
}
