//! Config worker HTTP surface — mirrors memory worker but at the
//! `config/` prefix per arch.md §17.2 per-data-class buckets (#201).

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedConfigWorkerState;
use agentkeys_worker_creds::aws_creds::{s3_for_request, OptionalStsCreds};
use agentkeys_worker_creds::envelope;
use agentkeys_worker_creds::errors::{err_400, err_403, err_404, err_500, err_502, ApiError};
use agentkeys_worker_creds::verify::{self, CapOp, CapToken, DataClass};

pub fn build_router(state: SharedConfigWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/config/put", post(config_put))
        .route("/v1/config/get", post(config_get))
        .route("/v1/config/teardown", post(config_teardown))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub config_bucket: String,
    pub chain_profile: String,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedConfigWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        config_bucket: state.config.config_bucket.clone(),
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

async fn config_put(
    State(state): State<SharedConfigWorkerState>,
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
        .bucket(&state.config.config_bucket)
        .key(&key)
        .body(env_bytes.clone().into())
        .send()
        .await
        .map_err(|e| err_502(format!("s3 PutObject: {}", s3_err_detail(&e)), "s3_put"))?;
    Ok(Json(PutResponse {
        ok: true,
        s3_key: key,
        envelope_size: env_bytes.len(),
    }))
}

async fn config_get(
    State(state): State<SharedConfigWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;

    let key = s3_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    let resp = s3
        .get_object()
        .bucket(&state.config.config_bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| {
            // #201 Phase 4: a missing taxonomy/config object is 404 (not 502), so
            // the daemon can distinguish "never written" (cache fallback OK) from
            // a real config-worker failure (which must surface, not silently hide).
            if e.as_service_error()
                .map(|se| se.is_no_such_key())
                .unwrap_or(false)
            {
                err_404("config object not found", "s3_no_such_key")
            } else {
                // Surface the REAL S3 error (AccessDenied / NoSuchBucket / region
                // mismatch) instead of a generic "service error", so a broken
                // Config data class is diagnosable — the #207 init/list 502 the
                // operator sees now names the actual cause to fix.
                err_502(format!("s3 GetObject: {}", s3_err_detail(&e)), "s3_get")
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

async fn config_teardown(
    State(state): State<SharedConfigWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;

    let prefix = s3_prefix(&req.cap.payload.actor_omni);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds.as_ref()).await;
    let list = s3
        .list_objects_v2()
        .bucket(&state.config.config_bucket)
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
            .bucket(&state.config.config_bucket)
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
    state: &SharedConfigWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    verify::verify_signature(&state.config.broker_pubkey_pem, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    // K10 proof-of-possession (issue #76 — broker-SPOF defense). See the cred
    // worker / verify::enforce_client_pop; shared across data classes.
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    verify::check_op(cap, expected_op).map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    // Per-data-class isolation gate (issue #90 followup / #201): a memory- or
    // credentials-class cap MUST NOT be honoured at the config worker. Symmetric
    // with the cred + memory workers' checks, defended in all directions.
    verify::check_data_class(cap, DataClass::Config)
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
    // Config is master-only (operator == actor): check_chain_scope SKIPS the
    // on-chain isServiceInScope when operator == actor (mirrors broker cap-mint
    // + memory worker), so the master reaches only its own bots/<O_master>/config/.
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

/// Extract the REAL S3 error (code + message) from an aws SdkError so a broken
/// Config data class surfaces the actual cause — `AccessDenied` (role missing
/// S3 Get/Put/List on `bots/<actor>/config/*`, or a PrincipalTag mismatch),
/// `NoSuchBucket` (`$CONFIG_BUCKET` not provisioned), a region mismatch, etc. —
/// instead of a generic "service error" the operator can't act on.
fn s3_err_detail<E, R>(e: &aws_sdk_s3::error::SdkError<E, R>) -> String
where
    E: aws_sdk_s3::error::ProvideErrorMetadata,
{
    use aws_sdk_s3::error::ProvideErrorMetadata;
    match (e.code(), e.message()) {
        (Some(code), Some(msg)) if !msg.is_empty() => format!("{code} — {msg}"),
        (Some(code), _) => code.to_string(),
        _ => e.to_string(),
    }
}

/// S3 key per arch.md §17.2: `bots/<actor_omni_hex>/config/<service>.enc`.
/// Distinct from the memory worker's `memory/` prefix; same bucket-relative
/// shape so a single audit pass covers every data class. For config the actor
/// is the master itself (operator == actor), so this is `bots/<O_master>/config/`.
fn s3_key(actor_omni: &str, service: &str) -> String {
    format!(
        "bots/{}/config/{}.enc",
        actor_omni.trim_start_matches("0x").to_lowercase(),
        service.to_lowercase()
    )
}

fn s3_prefix(actor_omni: &str) -> String {
    format!(
        "bots/{}/config/",
        actor_omni.trim_start_matches("0x").to_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_key_uses_config_prefix_not_memory_or_credentials() {
        // arch.md §17.2 separation: config worker writes to bots/<actor>/config/...,
        // NOT bots/<actor>/memory/... nor .../credentials/... A drift here would
        // collapse the per-data-class blast-radius.
        assert_eq!(
            s3_key("0xABCDEF", "memory-taxonomy"),
            "bots/abcdef/config/memory-taxonomy.enc"
        );
        assert!(!s3_key("0xabc", "x").contains("memory/"));
        assert!(!s3_key("0xabc", "x").contains("credentials"));
    }

    #[test]
    fn s3_prefix_uses_config_path() {
        assert_eq!(s3_prefix("0xABCDEF"), "bots/abcdef/config/");
    }

    #[test]
    fn distinct_services_segregate_storage() {
        // The taxonomy and any future config object land at distinct keys —
        // a `memory-taxonomy` cap physically cannot read/write a
        // `grant-policy` object (signed service ⇒ key + AAD).
        let taxonomy = s3_key("0xabc", "memory-taxonomy");
        let grants = s3_key("0xabc", "grant-policy");
        assert_ne!(taxonomy, grants);
        assert_eq!(taxonomy, "bots/abc/config/memory-taxonomy.enc");
        assert!(grants.contains("grant-policy"));
    }
}
