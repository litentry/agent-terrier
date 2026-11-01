use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use crate::state::SharedConfigWorkerState;
use agentkeys_core::audit::{
    AuditOpKind, AuditResult, ConfigGetBody, ConfigPutBody, ConfigTeardownBody,
};
use agentkeys_core::object_store::ObjectError;
use agentkeys_worker_creds::audit::{cap_hash, keccak_hex, zero_hash};
use agentkeys_worker_creds::{
    envelope,
    errors::{err_403, err_409, err_500, ApiError},
    storage_worker::{self, storage_error},
    verify::{CapOp, CapToken, DataClass},
};

pub fn build_router(state: SharedConfigWorkerState) -> Router {
    let browser_origins = &state.config.browser_origins;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/config/put", post(config_put))
        .route("/v1/config/get", post(config_get))
        .route("/v1/config/teardown", post(config_teardown))
        .layer(agentkeys_worker_creds::cors::browser_cors_layer(
            browser_origins,
        ))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub data_class: DataClass,
    pub chain_profile: String,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedConfigWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        data_class: DataClass::Config,
        chain_profile: state.config.chain_profile.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub type PutRequest = agentkeys_protocol::ConfigPutBody<CapToken>;
pub type GetRequest = agentkeys_protocol::ConfigGetBody<CapToken>;
pub type TeardownRequest = agentkeys_protocol::WorkerTeardownBody<CapToken>;
pub use agentkeys_protocol::{
    ConfigGetResp as GetResponse, ConfigPutResp as PutResponse,
    WorkerTeardownResp as TeardownResponse,
};

async fn config_put(
    State(state): State<SharedConfigWorkerState>,
    Json(req): Json<PutRequest>,
) -> Result<Json<PutResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Store).await?;

    let outcome = config_put_inner(&state, &req).await;
    // Durable audit (#229): after cap-verify, before the success response.
    // payload_hash covers the stored CIPHERTEXT — never plaintext.
    let audit_body = ConfigPutBody {
        key: object_key(&req.cap.payload.actor_omni, &req.cap.payload.service),
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
        .emit(&req.cap, AuditOpKind::ConfigPut, audit_body, audit_result)
        .await;
    let (key, env_bytes) = outcome?; // op error wins over an emit error
    Ok(Json(PutResponse {
        ok: true,
        s3_key: key,
        envelope_size: env_bytes.len(),
        audit_envelope_hash: audited?,
    }))
}

async fn config_put_inner(
    state: &SharedConfigWorkerState,
    req: &PutRequest,
) -> Result<(String, Vec<u8>), ApiError> {
    let env_bytes = storage_worker::store_bytes(
        &req.cap,
        req.plaintext_b64.as_deref(),
        req.envelope_b64.as_deref(),
        state.config.development_kek.as_deref().map(String::as_str),
    )?;
    let key = object_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    state
        .storage
        .put(&req.cap, &key, &env_bytes, req.expected_revision.as_deref())
        .await
        .map_err(|error| {
            if error == ObjectError::Conflict {
                err_409(
                    "config changed since it was read; reload before saving",
                    "stale_base",
                )
            } else {
                storage_error(error)
            }
        })?;
    Ok((key, env_bytes))
}

async fn config_get(
    State(state): State<SharedConfigWorkerState>,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;

    let outcome = config_get_inner(&state, &req).await;
    // Durable audit (#229): the config-release record, emitted BEFORE the
    // plaintext leaves the worker. cap_hash binds the row to the cap that
    // authorized this read.
    let audit_body = ConfigGetBody {
        key: object_key(&req.cap.payload.actor_omni, &req.cap.payload.service),
        cap_hash: cap_hash(&req.cap),
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(&req.cap, AuditOpKind::ConfigGet, audit_body, audit_result)
        .await;
    let (fetched, revision) = outcome?;
    let audit_envelope_hash = audited?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (plaintext_b64, envelope_b64) = match fetched {
        ConfigFetched::LegacyPlaintext(pt) => (Some(STANDARD.encode(&pt)), None),
        ConfigFetched::V3Envelope(env) => (None, Some(STANDARD.encode(&env))),
    };
    Ok(Json(GetResponse {
        ok: true,
        plaintext_b64,
        envelope_b64,
        audit_envelope_hash,
        revision: Some(revision),
    }))
}

/// What `config_get_inner` hands back: legacy v2 blobs are worker-decrypted
/// (static KEK); v3 blobs are returned as the raw envelope for CLIENT-side
/// decrypt under the signer-derived KEK (#372 item 2 — the worker holds no
/// key that opens them).
enum ConfigFetched {
    LegacyPlaintext(Vec<u8>),
    V3Envelope(Vec<u8>),
}

async fn config_get_inner(
    state: &SharedConfigWorkerState,
    req: &GetRequest,
) -> Result<(ConfigFetched, String), ApiError> {
    let key = object_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    let stored = state
        .storage
        .get(&req.cap, &key)
        .await
        .map_err(storage_error)?;
    let revision = stored.revision;
    let body = stored.bytes;

    // v3 (#372 item 2): return the client-encrypted envelope verbatim —
    // decrypt happens caller-side under the signer-derived per-actor KEK.
    if envelope::version(&body) == Some(envelope::ENVELOPE_VERSION_V3) {
        return Ok((ConfigFetched::V3Envelope(body.to_vec()), revision));
    }

    // Legacy v2 blob: worker-side decrypt under the static stage-1 KEK.
    let kek_hex = state
        .config
        .development_kek
        .as_deref()
        .map(String::as_str)
        .ok_or_else(|| {
            err_500(
                "stored object requires its original development encryption key",
                "development_kek_missing",
            )
        })?;
    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        &req.cap.payload.actor_omni,
        &req.cap.payload.service,
        req.cap.payload.k3_epoch,
    );
    envelope::decrypt(kek_hex, &body, &aad)
        .map(|plaintext| (ConfigFetched::LegacyPlaintext(plaintext), revision))
        .map_err(|e| err_500(e.to_string(), "envelope_decrypt"))
}

async fn config_teardown(
    State(state): State<SharedConfigWorkerState>,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;

    let outcome = config_teardown_inner(&state, &req).await;
    let audit_body = ConfigTeardownBody {
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
            AuditOpKind::ConfigTeardown,
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

async fn config_teardown_inner(
    state: &SharedConfigWorkerState,
    req: &TeardownRequest,
) -> Result<usize, ApiError> {
    let prefix = object_prefix(&req.cap.payload.actor_omni);
    storage_worker::delete_prefix(state, &req.cap, &prefix).await
}

async fn verify_cap(
    state: &SharedConfigWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    storage_worker::verify_cap(state, cap, expected_op, DataClass::Config).await?;
    if !cap
        .payload
        .operator_omni
        .trim_start_matches("0x")
        .eq_ignore_ascii_case(cap.payload.actor_omni.trim_start_matches("0x"))
    {
        return Err(err_403(
            "configuration access is owner-only",
            "config_not_master_self",
        ));
    }
    Ok(())
}

fn object_key(actor_omni: &str, service: &str) -> String {
    format!(
        "bots/{}/config/{}.enc",
        actor_omni.trim_start_matches("0x").to_lowercase(),
        service.to_lowercase()
    )
}

fn object_prefix(actor_omni: &str) -> String {
    format!(
        "bots/{}/config/",
        actor_omni.trim_start_matches("0x").to_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_uses_config_prefix_not_memory_or_credentials() {
        // arch.md §17.2 separation: config worker writes to bots/<actor>/config/...,
        // NOT bots/<actor>/memory/... nor .../credentials/... A drift here would
        // collapse the per-data-class blast-radius.
        assert_eq!(
            object_key("0xABCDEF", "memory-taxonomy"),
            "bots/abcdef/config/memory-taxonomy.enc"
        );
        assert!(!object_key("0xabc", "x").contains("memory/"));
        assert!(!object_key("0xabc", "x").contains("credentials"));
    }

    #[test]
    fn object_prefix_uses_config_path() {
        assert_eq!(object_prefix("0xABCDEF"), "bots/abcdef/config/");
    }

    #[test]
    fn distinct_services_segregate_storage() {
        // The taxonomy and any future config object land at distinct keys —
        // a `memory-taxonomy` cap physically cannot read/write a
        // `grant-policy` object (signed service ⇒ key + AAD).
        let taxonomy = object_key("0xabc", "memory-taxonomy");
        let grants = object_key("0xabc", "grant-policy");
        assert_ne!(taxonomy, grants);
        assert_eq!(taxonomy, "bots/abc/config/memory-taxonomy.enc");
        assert!(grants.contains("grant-policy"));
    }
}
