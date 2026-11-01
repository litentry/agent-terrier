//! Authorized catalog classification using the shared worker verifier.

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::classify::{self, CompileResult};
use crate::state::SharedClassifyWorkerState;
use agentkeys_worker_creds::errors::ApiError;
use agentkeys_worker_creds::verify::{CapOp, CapToken, DataClass};

pub fn build_router(state: SharedClassifyWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/classify/tag", post(classify_tag))
        .route("/v1/classify/compile", post(classify_compile))
        .layer(agentkeys_worker_creds::cors::browser_cors_layer(
            &state.config.browser_origins,
        ))
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

pub type TagRequest = agentkeys_protocol::classify::ClassifyTagBody<CapToken, DataClass>;
pub use agentkeys_protocol::classify::ClassifyTagResponse as TagResponse;

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

async fn verify_classify_cap(
    state: &SharedClassifyWorkerState,
    cap: &CapToken,
    expected_class: DataClass,
) -> Result<(), ApiError> {
    agentkeys_worker_creds::storage_worker::verify_authority(
        &state.config.authority,
        &state.http,
        cap,
        CapOp::Classify,
        expected_class,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_worker_creds::verify;
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
