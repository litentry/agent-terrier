//! Classifier worker HTTP surface — a COMPUTE gate. Same cap-verify chain as the
//! storage workers (sig → op → data-class → freshness → chain device/scope/epoch),
//! but the effect is TAG / COMPILE over the in-process catalog, not an S3 touch.

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::catalog::Classification;
use crate::classify::{self, CompileResult};
use crate::state::SharedClassifyWorkerState;
use agentkeys_worker_creds::errors::{err_403, err_502, ApiError};
use agentkeys_worker_creds::verify::{self, CapOp, CapToken, DataClass};

pub fn build_router(state: SharedClassifyWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/classify/tag", post(classify_tag))
        .route("/v1/classify/compile", post(classify_compile))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub catalog_version: u32,
    pub chain_profile: String,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedClassifyWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        catalog_version: state.catalog.version,
        chain_profile: state.config.chain_profile.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Debug, Deserialize)]
pub struct TagRequest {
    pub cap: CapToken,
    /// The data class of the entity being classified — asserted to match the
    /// cap's signed `data_class` (a Memory-classify cap can't TAG a credential).
    pub data_class: DataClass,
    pub entity: String,
}

#[derive(Debug, Serialize)]
pub struct TagResponse {
    pub ok: bool,
    pub classification: Classification,
}

async fn classify_tag(
    State(state): State<SharedClassifyWorkerState>,
    Json(req): Json<TagRequest>,
) -> Result<Json<TagResponse>, ApiError> {
    verify_classify_cap(&state, &req.cap, req.data_class).await?;
    let classification = classify::tag(&state.catalog, &req.entity);
    Ok(Json(TagResponse {
        ok: true,
        classification,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CompileRequest {
    pub cap: CapToken,
    pub data_class: DataClass,
    pub sentence: String,
}

#[derive(Debug, Serialize)]
pub struct CompileResponse {
    pub ok: bool,
    pub result: CompileResult,
}

async fn classify_compile(
    State(state): State<SharedClassifyWorkerState>,
    Json(req): Json<CompileRequest>,
) -> Result<Json<CompileResponse>, ApiError> {
    verify_classify_cap(&state, &req.cap, req.data_class).await?;
    let result = classify::compile(&state.catalog, &req.sentence);
    Ok(Json(CompileResponse { ok: true, result }))
}

/// The cap gate (isolation layers 1-2) — identical chain to the storage workers,
/// but pinned to `op=Classify` and the request's declared `data_class`. The
/// storage workers reject `op=Classify` (`check_op`); this worker rejects any
/// non-Classify cap, and rejects a Classify cap whose signed `data_class` differs
/// from what's being classified (`cap_data_class_mismatch`, symmetric with §17.5).
async fn verify_classify_cap(
    state: &SharedClassifyWorkerState,
    cap: &CapToken,
    expected_class: DataClass,
) -> Result<(), ApiError> {
    verify::verify_signature(&state.config.broker_pubkey_pem, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    // K10 proof-of-possession (issue #76 — broker-SPOF defense). Same shared
    // gate the storage workers run (verify::enforce_client_pop).
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    verify::check_op(cap, CapOp::Classify)
        .map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    verify::check_data_class(cap, expected_class)
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
    // Classify is master-driven onboarding (operator == actor), so check_chain_scope
    // SKIPS the on-chain isServiceInScope for operator == actor (mirrors the broker
    // cap-mint + storage workers).
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

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_worker_creds::verify::CapPayload;

    fn cap(op: CapOp, data_class: DataClass) -> CapToken {
        CapToken {
            payload: CapPayload {
                operator_omni: format!("0x{}", "a".repeat(64)),
                actor_omni: format!("0x{}", "a".repeat(64)),
                service: "classify:memory".into(),
                op,
                data_class,
                device_key_hash: format!("0x{}", "c".repeat(64)),
                k3_epoch: 1,
                issued_at: 1,
                expires_at: 9_999_999_999,
                nonce: "00".repeat(16),
            },
            broker_sig: String::new(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    // The two cap-layer isolation gates the classifier worker enforces BEFORE any
    // chain RPC — testable without a live chain (pure enum checks reused from
    // agentkeys_worker_creds::verify). #207 test-discipline: a new worker + cap
    // ships with its cross-isolation negatives.
    #[test]
    fn rejects_non_classify_op() {
        // A storage cap (op=Store) submitted to the classify worker → op mismatch.
        let store_cap = cap(CapOp::Store, DataClass::Memory);
        assert!(verify::check_op(&store_cap, CapOp::Classify).is_err());
        // …and a real Classify cap passes the op gate.
        let ok = cap(CapOp::Classify, DataClass::Memory);
        assert!(verify::check_op(&ok, CapOp::Classify).is_ok());
    }

    #[test]
    fn rejects_cross_data_class() {
        // A Memory-classify cap used to TAG a credential → data-class mismatch.
        let mem_cap = cap(CapOp::Classify, DataClass::Memory);
        assert!(verify::check_data_class(&mem_cap, DataClass::Credentials).is_err());
        assert!(verify::check_data_class(&mem_cap, DataClass::Memory).is_ok());
    }
}
