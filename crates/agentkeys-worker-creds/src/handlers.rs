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
use crate::envelope;
use crate::errors::{err_400, err_403, err_500, err_502, ApiError};
use crate::state::SharedWorkerState;
use crate::verify::{self, CapOp, CapPayload, CapToken, DataClass};
use agentkeys_core::object_store::ObjectError;

pub fn build_router(state: SharedWorkerState) -> Router {
    let browser_origins = &state.config.browser_origins;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/cred/store", post(cred_store))
        .route("/v1/cred/fetch", post(cred_fetch))
        .route("/v1/cred/list", post(cred_list))
        .route("/v1/cred/teardown", post(cred_teardown))
        .layer(crate::cors::browser_cors_layer(browser_origins))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct ListRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub ok: bool,
    pub services: Vec<String>,
}

async fn cred_list(
    State(state): State<SharedWorkerState>,
    Json(req): Json<ListRequest>,
) -> Result<Json<ListResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;
    if req.cap.payload.operator_omni != req.cap.payload.actor_omni {
        return Err(err_403(
            "cred list is master-only (operator must equal actor)",
            "list_not_master_self",
        ));
    }
    let prefix = object_prefix(&req.cap.payload.actor_omni);
    let mut services = Vec::new();
    let mut cursor = None;
    loop {
        let page = state
            .storage
            .list(&req.cap, &prefix, cursor.as_deref())
            .await
            .map_err(storage_error)?;
        services.extend(
            page.keys
                .iter()
                .filter_map(|key| service_from_key(key, &prefix)),
        );
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(Json(ListResponse { ok: true, services }))
}

fn service_from_key(key: &str, prefix: &str) -> Option<String> {
    key.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".enc"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub data_class: DataClass,
    pub chain_profile: String,
    pub version: &'static str,
}

async fn healthz(State(state): State<SharedWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        data_class: DataClass::Credentials,
        chain_profile: state.config.chain_profile.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub type StoreRequest = agentkeys_protocol::CredStoreBody<CapToken>;
pub type FetchRequest = agentkeys_protocol::CredFetchBody<CapToken>;
pub use agentkeys_protocol::{CredFetchResp as FetchResponse, CredStoreResp as StoreResponse};

#[derive(Debug, Deserialize)]
pub struct TeardownRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct TeardownResponse {
    pub ok: bool,
    pub keys_deleted: usize,
    pub audit_envelope_hash: Option<String>,
}

async fn cred_store(
    State(state): State<SharedWorkerState>,
    Json(req): Json<StoreRequest>,
) -> Result<Json<StoreResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Store).await?;
    if req.cap.payload.operator_omni != req.cap.payload.actor_omni {
        return Err(err_403(
            "cred store is master-self only (operator must equal actor) — \
             agents cannot self-store credentials (single-vault)",
            "cred_store_not_master_self",
        ));
    }

    let outcome = cred_store_inner(&state, &req).await;
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
    req: &StoreRequest,
) -> Result<(String, Vec<u8>), ApiError> {
    let env_bytes = resolve_store_bytes(req, &state.config.development_kek)?;

    let key = object_key(&req.cap.payload.actor_omni, &req.cap.payload.service);
    state
        .storage
        .put(&req.cap, &key, &env_bytes, None)
        .await
        .map_err(storage_error)?;
    Ok((key, env_bytes))
}

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
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;

    let outcome = cred_fetch_inner(&state, &req).await;
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

enum CredFetched {
    Plaintext(Vec<u8>),
    V3Envelope(Vec<u8>),
}

async fn cred_fetch_inner(
    state: &SharedWorkerState,
    req: &FetchRequest,
) -> Result<CredFetched, ApiError> {
    let owner = fetch_vault_owner(&req.cap.payload);
    let key = object_key(owner, &req.cap.payload.service);
    let body = state
        .storage
        .get(&req.cap, &key)
        .await
        .map_err(storage_error)?
        .bytes;

    if envelope::version(&body) == Some(envelope::ENVELOPE_VERSION_V3) {
        return Ok(CredFetched::V3Envelope(body.to_vec()));
    }
    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        owner,
        &req.cap.payload.service,
        req.cap.payload.k3_epoch,
    );
    envelope::decrypt(&state.config.development_kek, &body, &aad)
        .map(CredFetched::Plaintext)
        .map_err(|e| err_500(e.to_string(), "envelope_decrypt"))
}

fn fetch_vault_owner(payload: &CapPayload) -> &str {
    &payload.operator_omni
}

async fn cred_teardown(
    State(state): State<SharedWorkerState>,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;
    if req.cap.payload.operator_omni != req.cap.payload.actor_omni {
        return Err(err_403(
            "credential teardown is owner-only",
            "teardown_not_master_self",
        ));
    }

    let outcome = cred_teardown_inner(&state, &req).await;
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
    req: &TeardownRequest,
) -> Result<usize, ApiError> {
    let prefix = object_prefix(&req.cap.payload.actor_omni);
    let mut deleted = 0;
    let mut cursor = None;
    loop {
        let page = state
            .storage
            .list(&req.cap, &prefix, cursor.as_deref())
            .await
            .map_err(storage_error)?;
        for key in &page.keys {
            state
                .storage
                .delete(&req.cap, key, None)
                .await
                .map_err(storage_error)?;
            deleted += 1;
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(deleted)
}

async fn verify_cap(
    state: &SharedWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    verify::verify_signature(&state.config.authority.broker_public_key, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    verify::check_op(cap, expected_op).map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    verify::check_data_class(cap, DataClass::Credentials)
        .map_err(|e| err_403(e.to_string(), "cap_data_class_mismatch"))?;
    verify::check_freshness(cap).map_err(|e| err_403(e.to_string(), "cap_freshness_failed"))?;
    verify::check_chain_device(
        &state.http,
        &state.config.authority.rpc_url,
        &state.config.authority.registry,
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
        &state.config.authority.rpc_url,
        &state.config.authority.scope,
        cap,
    )
    .await
    .map_err(|e| match e {
        verify::VerifyError::NotInScope => err_403(e.to_string(), "service_not_in_scope"),
        _ => err_502(e.to_string(), "chain_rpc"),
    })?;
    verify::check_chain_k3_epoch(
        &state.http,
        &state.config.authority.rpc_url,
        &state.config.authority.epoch,
        cap,
    )
    .await
    .map_err(|e| match e {
        verify::VerifyError::K3Mismatch { .. } => err_403(e.to_string(), "k3_epoch_mismatch"),
        _ => err_502(e.to_string(), "chain_rpc"),
    })?;
    Ok(())
}

fn storage_error(error: ObjectError) -> ApiError {
    use crate::errors::{err_404, err_409};
    match error {
        ObjectError::Denied => err_403(error.to_string(), "storage_denied"),
        ObjectError::NotFound => err_404(
            error.to_string(),
            agentkeys_protocol::object_store::OBJECT_NOT_FOUND,
        ),
        ObjectError::Conflict => err_409(
            error.to_string(),
            agentkeys_protocol::object_store::OBJECT_REVISION_CONFLICT,
        ),
        ObjectError::InvalidRequest => err_400(error.to_string(), "object_request_invalid"),
        ObjectError::Unavailable | ObjectError::InvalidResponse => {
            err_502(error.to_string(), "storage_unavailable")
        }
    }
}

fn object_key(actor_omni: &str, service: &str) -> String {
    format!(
        "bots/{}/credentials/{}.enc",
        actor_omni.trim_start_matches("0x").to_lowercase(),
        service.to_lowercase()
    )
}

fn object_prefix(actor_omni: &str) -> String {
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
        assert_eq!(
            fetch_vault_owner(&payload("0xmaster", "0xmaster")),
            "0xmaster"
        );
        let delegated = payload("0xmaster", "0xagent");
        assert_eq!(fetch_vault_owner(&delegated), "0xmaster");
        assert_eq!(
            object_key(fetch_vault_owner(&delegated), &delegated.service),
            "bots/master/credentials/openrouter.enc"
        );
    }

    #[test]
    fn object_key_is_actor_and_service_scoped() {
        assert_eq!(
            object_key("0xABCDEF", "openrouter"),
            "bots/abcdef/credentials/openrouter.enc"
        );
        assert_eq!(
            object_key("abcdef", "OpenRouter"),
            "bots/abcdef/credentials/openrouter.enc"
        );
    }

    #[test]
    fn object_prefix_is_actor_scoped() {
        assert_eq!(object_prefix("0xABCDEF"), "bots/abcdef/credentials/");
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

    #[test]
    fn store_request_deserializes_with_neither_mode() {
        let req = store_req(None, None);
        let json = serde_json::json!({ "cap": req.cap });
        let parsed: StoreRequest =
            serde_json::from_value(json).expect("a neither-mode body must deserialize (not 422)");
        assert!(parsed.plaintext_b64.is_none());
        assert!(parsed.envelope_b64.is_none());
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
