use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use crate::state::SharedMemoryWorkerState;
use agentkeys_core::audit::{
    AuditOpKind, AuditResult, MemoryGetBody, MemoryInboxAppendBody, MemoryPutBody,
    MemoryTeardownBody,
};
use agentkeys_core::object_store::ObjectError;
#[cfg(test)]
use agentkeys_protocol::ContextKind;
use agentkeys_protocol::{InboxItem, InboxItemMeta};
use agentkeys_worker_creds::audit::{cap_hash, keccak_hex, zero_hash};
use agentkeys_worker_creds::{
    envelope,
    errors::{err_400, err_403, err_409, err_500, ApiError},
    storage_worker::{self, storage_error},
    verify::{CapOp, CapPayload, CapToken, DataClass},
};

const MEMORY_BODY_LIMIT_BYTES: usize = 48 * 1024 * 1024;

pub fn build_router(state: SharedMemoryWorkerState) -> Router {
    let browser_origins = &state.config.browser_origins;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/memory/put", post(memory_put))
        .route("/v1/memory/get", post(memory_get))
        .route("/v1/memory/canonical-get", post(memory_canonical_get))
        .route("/v1/memory/inbox-append", post(memory_inbox_append))
        .route("/v1/memory/inbox-list", post(memory_inbox_list))
        .route("/v1/memory/inbox-get", post(memory_inbox_get))
        .route("/v1/memory/inbox-delete", post(memory_inbox_delete))
        .route("/v1/memory/teardown", post(memory_teardown))
        .layer(axum::extract::DefaultBodyLimit::max(
            MEMORY_BODY_LIMIT_BYTES,
        ))
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

async fn healthz(State(state): State<SharedMemoryWorkerState>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        data_class: DataClass::Memory,
        chain_profile: state.config.chain_profile.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub type PutRequest = agentkeys_protocol::MemoryPutBody<CapToken>;
pub type GetRequest = agentkeys_protocol::MemoryGetBody<CapToken>;
pub type TeardownRequest = agentkeys_protocol::WorkerTeardownBody<CapToken>;
pub use agentkeys_protocol::{
    MemoryGetResp as GetResponse, MemoryPutResp as PutResponse,
    WorkerTeardownResp as TeardownResponse,
};

async fn memory_put(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<PutRequest>,
) -> Result<Json<PutResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Store).await?;
    if let Some(k) = &req.object_key {
        validate_object_key(k)?;
    }
    let outcome = memory_put_inner(&state, &req).await;
    let audit_body = MemoryPutBody {
        key: storage_key(
            &req.cap.payload.actor_omni,
            &req.cap.payload.service,
            req.object_key.as_deref(),
        ),
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
        .emit(&req.cap, AuditOpKind::MemoryPut, audit_body, audit_result)
        .await;
    let (key, env_bytes) = outcome?; // op error wins over an emit error
    Ok(Json(PutResponse {
        ok: true,
        s3_key: key,
        envelope_size: env_bytes.len(),
        audit_envelope_hash: audited?,
    }))
}

async fn memory_put_inner(
    state: &SharedMemoryWorkerState,
    req: &PutRequest,
) -> Result<(String, Vec<u8>), ApiError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let plaintext = STANDARD
        .decode(&req.plaintext_b64)
        .map_err(|e| err_400(e.to_string(), "plaintext_b64_decode"))?;

    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        &req.cap.payload.actor_omni,
        &aad_service(&req.cap.payload.service, req.object_key.as_deref()),
        req.cap.payload.k3_epoch,
    );
    let env_bytes = envelope::encrypt(development_key(state)?, &plaintext, &aad)
        .map_err(|e| err_500(e.to_string(), "envelope_encrypt"))?;

    let key = storage_key(
        &req.cap.payload.actor_omni,
        &req.cap.payload.service,
        req.object_key.as_deref(),
    );
    let mut expected_revision = None;
    if let Some(expected) = req.expected_content_hash.as_deref() {
        let current = match state.storage.get(&req.cap, &key).await {
            Ok(stored) => {
                expected_revision = Some(stored.revision);
                Some(
                    envelope::decrypt(development_key(state)?, &stored.bytes, &aad)
                        .map_err(|error| err_500(error.to_string(), "envelope_decrypt"))?,
                )
            }
            Err(ObjectError::NotFound) => {
                expected_revision = Some(String::new());
                None
            }
            Err(error) => return Err(storage_error(error)),
        };
        check_expected_hash(expected, current.as_deref())?;
    }
    state
        .storage
        .put(&req.cap, &key, &env_bytes, expected_revision.as_deref())
        .await
        .map_err(|error| {
            if error == ObjectError::Conflict {
                err_409(
                    "memory changed since it was read; reload before saving",
                    "stale_base",
                )
            } else {
                storage_error(error)
            }
        })?;
    Ok((key, env_bytes))
}

fn check_expected_hash(expected: &str, current: Option<&[u8]>) -> Result<(), ApiError> {
    let actual = current.map(keccak_hex);
    let ok = match (expected, actual.as_deref()) {
        ("", None) => true,
        ("", Some(_)) => false,
        (_, None) => false,
        (e, Some(a)) => a.eq_ignore_ascii_case(e),
    };
    if ok {
        Ok(())
    } else {
        Err(err_409(
            format!(
                "stale_base: the stored plaintext is not the one you read (current {})",
                actual.as_deref().unwrap_or("absent")
            ),
            "stale_base",
        ))
    }
}

async fn memory_get(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;
    if let Some(k) = &req.object_key {
        validate_object_key(k)?;
    }
    memory_read_after_verify(&state, &req).await
}

async fn memory_canonical_get(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::CanonicalFetch).await?;
    if req.object_key.is_some() {
        return Err(err_400(
            "object_key is not supported on canonical reads".to_string(),
            "object_key_on_canonical",
        ));
    }
    memory_read_after_verify(&state, &req).await
}

async fn memory_read_after_verify(
    state: &SharedMemoryWorkerState,
    req: &GetRequest,
) -> Result<Json<GetResponse>, ApiError> {
    let outcome = memory_get_inner(state, req).await;
    let audit_body = MemoryGetBody {
        key: storage_key(
            memory_read_owner(&req.cap.payload),
            &req.cap.payload.service,
            req.object_key.as_deref(),
        ),
        cap_hash: cap_hash(&req.cap),
    };
    let audit_result = if outcome.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    let audited = state
        .audit
        .emit(&req.cap, AuditOpKind::MemoryGet, audit_body, audit_result)
        .await;
    let plaintext = outcome?;
    let audit_envelope_hash = audited?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    Ok(Json(GetResponse {
        ok: true,
        plaintext_b64: STANDARD.encode(&plaintext),
        audit_envelope_hash,
    }))
}

async fn memory_get_inner(
    state: &SharedMemoryWorkerState,
    req: &GetRequest,
) -> Result<Vec<u8>, ApiError> {
    let owner = memory_read_owner(&req.cap.payload);
    let key = storage_key(owner, &req.cap.payload.service, req.object_key.as_deref());
    let body = state
        .storage
        .get(&req.cap, &key)
        .await
        .map_err(storage_error)?
        .bytes;

    let aad = envelope::aad(
        &req.cap.payload.operator_omni,
        owner,
        &aad_service(&req.cap.payload.service, req.object_key.as_deref()),
        req.cap.payload.k3_epoch,
    );
    envelope::decrypt(development_key(state)?, &body, &aad)
        .map_err(|e| err_500(e.to_string(), "envelope_decrypt"))
}

async fn memory_teardown(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;
    enforce_master_self(&req.cap)?;

    let outcome = memory_teardown_inner(&state, &req).await;
    let audit_body = MemoryTeardownBody {
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
            AuditOpKind::MemoryTeardown,
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

async fn memory_teardown_inner(
    state: &SharedMemoryWorkerState,
    req: &TeardownRequest,
) -> Result<usize, ApiError> {
    let prefix = object_prefix(&req.cap.payload.actor_omni);
    storage_worker::delete_prefix(state, &req.cap, &prefix).await
}

const INBOX_AAD_SERVICE: &str = "inbox";

pub type InboxAppendRequest = agentkeys_protocol::MemoryInboxAppendBody<CapToken>;
pub type InboxListRequest = agentkeys_protocol::InboxListBody<CapToken>;
pub type InboxGetRequest = agentkeys_protocol::InboxGetBody<CapToken>;
pub type InboxDeleteRequest = agentkeys_protocol::InboxDeleteBody<CapToken>;
pub use agentkeys_protocol::{
    InboxDeleteResp as InboxDeleteResponse, InboxGetResp as InboxGetResponse,
    InboxListResp as InboxListResponse, MemoryInboxAppendResp as InboxAppendResponse,
};

async fn memory_inbox_append(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<InboxAppendRequest>,
) -> Result<Json<InboxAppendResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Append).await?;
    let outcome = inbox_append_inner(&state, &req).await;
    let audit_key = match &outcome {
        Ok((obj_key, _, _)) => obj_key.clone(),
        Err(_) => inbox_subprefix(
            &req.cap.payload.operator_omni,
            &req.cap.payload.actor_omni,
            &req.cap.payload.service,
        ),
    };
    let audit_body = MemoryInboxAppendBody {
        key: audit_key,
        payload_hash: match &outcome {
            Ok((_, _, env_bytes)) => keccak_hex(env_bytes),
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
        .emit(
            &req.cap,
            AuditOpKind::MemoryInboxAppend,
            audit_body,
            audit_result,
        )
        .await;
    let (obj_key, content_hash, _env_bytes) = outcome?;
    Ok(Json(InboxAppendResponse {
        ok: true,
        s3_key: obj_key,
        content_hash,
        audit_envelope_hash: audited?,
    }))
}

async fn inbox_append_inner(
    state: &SharedMemoryWorkerState,
    req: &InboxAppendRequest,
) -> Result<(String, String, Vec<u8>), ApiError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let plaintext = STANDARD
        .decode(&req.plaintext_b64)
        .map_err(|e| err_400(e.to_string(), "plaintext_b64_decode"))?;

    let operator = &req.cap.payload.operator_omni;
    let delegate = &req.cap.payload.actor_omni;
    let service = &req.cap.payload.service;
    let ns = inbox_ns_from_service(service).to_string();

    let mut preimage = Vec::new();
    preimage.extend_from_slice(ns.as_bytes());
    preimage.push(0x7c);
    preimage.extend_from_slice(req.key.as_bytes());
    preimage.push(0x7c);
    preimage.extend_from_slice(&plaintext);
    let content_hash = keccak_hex(&preimage);

    let item = InboxItem {
        source_delegate_omni: delegate.clone(),
        ns: ns.clone(),
        key: req.key.clone(),
        body_b64: req.plaintext_b64.clone(),
        content_hash: content_hash.clone(),
        ts: now_unix(),
        kind: req.kind,
    };
    let item_json =
        serde_json::to_vec(&item).map_err(|e| err_500(e.to_string(), "inbox_item_encode"))?;

    let aad = envelope::aad(
        operator,
        operator,
        INBOX_AAD_SERVICE,
        req.cap.payload.k3_epoch,
    );
    let env_bytes = envelope::encrypt(development_key(state)?, &item_json, &aad)
        .map_err(|e| err_500(e.to_string(), "envelope_encrypt"))?;

    let obj_key = inbox_object_key(operator, delegate, service, &content_hash);
    state
        .storage
        .put(&req.cap, &obj_key, &env_bytes, Some(""))
        .await
        .map_err(storage_error)?;
    Ok((obj_key, content_hash, env_bytes))
}

async fn memory_inbox_list(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<InboxListRequest>,
) -> Result<Json<InboxListResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;
    enforce_master_self(&req.cap)?;
    let operator = &req.cap.payload.operator_omni;
    let prefix = inbox_prefix(operator);
    let aad = envelope::aad(
        operator,
        operator,
        INBOX_AAD_SERVICE,
        req.cap.payload.k3_epoch,
    );
    let mut items = Vec::new();
    let mut cursor = None;
    loop {
        let page = state
            .storage
            .list(&req.cap, &prefix, cursor.as_deref())
            .await
            .map_err(storage_error)?;
        for key in &page.keys {
            let (item, bytes) = inbox_read_item(&state, &req.cap, key, &aad).await?;
            items.push(InboxItemMeta {
                s3_key: key.clone(),
                source_delegate_omni: item.source_delegate_omni,
                ns: item.ns,
                key: item.key,
                content_hash: item.content_hash,
                bytes,
                ts: item.ts,
                kind: item.kind,
            });
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(Json(InboxListResponse { ok: true, items }))
}

async fn memory_inbox_get(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<InboxGetRequest>,
) -> Result<Json<InboxGetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;
    enforce_master_self(&req.cap)?;
    let operator = &req.cap.payload.operator_omni;
    validate_inbox_key(operator, &req.s3_key)?;
    let aad = envelope::aad(
        operator,
        operator,
        INBOX_AAD_SERVICE,
        req.cap.payload.k3_epoch,
    );
    let (item, _) = inbox_read_item(&state, &req.cap, &req.s3_key, &aad).await?;
    Ok(Json(InboxGetResponse { ok: true, item }))
}

async fn memory_inbox_delete(
    State(state): State<SharedMemoryWorkerState>,
    Json(req): Json<InboxDeleteRequest>,
) -> Result<Json<InboxDeleteResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;
    enforce_master_self(&req.cap)?;
    let operator = &req.cap.payload.operator_omni;
    validate_inbox_key(operator, &req.s3_key)?;
    state
        .storage
        .delete(&req.cap, &req.s3_key, None)
        .await
        .map_err(storage_error)?;
    Ok(Json(InboxDeleteResponse {
        ok: true,
        deleted: true,
    }))
}

async fn inbox_read_item(
    state: &SharedMemoryWorkerState,
    cap: &CapToken,
    key: &str,
    aad: &[u8],
) -> Result<(InboxItem, u64), ApiError> {
    let stored = state.storage.get(cap, key).await.map_err(storage_error)?;
    let plaintext = envelope::decrypt(development_key(state)?, &stored.bytes, aad)
        .map_err(|error| err_500(error.to_string(), "envelope_decrypt"))?;
    let item = serde_json::from_slice::<InboxItem>(&plaintext)
        .map_err(|error| err_500(error.to_string(), "inbox_item_decode"))?;
    Ok((item, stored.bytes.len() as u64))
}

fn enforce_master_self(cap: &CapToken) -> Result<(), ApiError> {
    let op = strip0x_lc(&cap.payload.operator_omni);
    let ac = strip0x_lc(&cap.payload.actor_omni);
    if op != ac {
        return Err(err_403(
            "inbox management is master-self only (operator must equal actor)".to_string(),
            "inbox_not_master_self",
        ));
    }
    Ok(())
}

fn validate_inbox_key(operator: &str, s3_key: &str) -> Result<(), ApiError> {
    if !s3_key.starts_with(&inbox_prefix(operator)) || s3_key.contains("..") {
        return Err(err_400(
            "s3_key is not within the operator's inbox prefix".to_string(),
            "inbox_key_out_of_scope",
        ));
    }
    Ok(())
}

fn inbox_object_key(operator: &str, delegate: &str, service: &str, content_hash: &str) -> String {
    format!(
        "{}{}.enc",
        inbox_subprefix(operator, delegate, service),
        content_hash.trim_start_matches("0x").to_lowercase()
    )
}

fn inbox_subprefix(operator: &str, delegate: &str, service: &str) -> String {
    format!(
        "bots/{}/inbox/{}/{}/",
        strip0x_lc(operator),
        strip0x_lc(delegate),
        service.to_lowercase()
    )
}

fn inbox_prefix(operator: &str) -> String {
    format!("bots/{}/inbox/", strip0x_lc(operator))
}

fn inbox_ns_from_service(service: &str) -> &str {
    service.strip_prefix("proposal:").unwrap_or(service)
}

fn strip0x_lc(s: &str) -> String {
    s.trim_start_matches("0x").to_lowercase()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn verify_cap(
    state: &SharedMemoryWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
) -> Result<(), ApiError> {
    storage_worker::verify_cap(state, cap, expected_op, DataClass::Memory).await
}

fn development_key(state: &SharedMemoryWorkerState) -> Result<&str, ApiError> {
    state
        .config
        .development_kek
        .as_deref()
        .map(String::as_str)
        .ok_or_else(|| {
            err_500(
                "memory encryption requires an explicit protected development key",
                "development_kek_missing",
            )
        })
}

/// The signed operation selects both the object owner and encryption context.
fn memory_read_owner(payload: &CapPayload) -> &str {
    match payload.op {
        CapOp::CanonicalFetch => &payload.operator_omni,
        _ => &payload.actor_omni,
    }
}

fn object_key(actor_omni: &str, service: &str) -> String {
    format!(
        "bots/{}/memory/{}.enc",
        actor_omni.trim_start_matches("0x").to_lowercase(),
        service.to_lowercase()
    )
}

fn object_prefix(actor_omni: &str) -> String {
    format!(
        "bots/{}/memory/",
        actor_omni.trim_start_matches("0x").to_lowercase()
    )
}

fn validate_object_key(k: &str) -> Result<(), ApiError> {
    let ok = !k.is_empty()
        && k.len() <= 128
        && k.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
        });
    if ok {
        Ok(())
    } else {
        Err(err_400(
            "object_key must be 1..=128 chars of [a-z0-9._-] in non-empty '/'-separated \
             segments (no '.'/'..')"
                .to_string(),
            "object_key_invalid",
        ))
    }
}

fn storage_key(owner: &str, service: &str, requested_key: Option<&str>) -> String {
    match requested_key {
        Some(k) => format!(
            "bots/{}/memory/{}.objects/{}.enc",
            owner.trim_start_matches("0x").to_lowercase(),
            service.to_lowercase(),
            k
        ),
        None => object_key(owner, service),
    }
}

fn aad_service(service: &str, object_key: Option<&str>) -> String {
    match object_key {
        Some(k) => format!("{service}\u{1f}{k}"),
        None => service.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_uses_memory_prefix_not_credentials() {
        assert_eq!(
            object_key("0xABCDEF", "chat-history"),
            "bots/abcdef/memory/chat-history.enc"
        );
        assert!(!object_key("0xabc", "x").contains("credentials"));
    }

    #[test]
    fn object_prefix_uses_memory_path() {
        assert_eq!(object_prefix("0xABCDEF"), "bots/abcdef/memory/");
    }

    #[test]
    fn storage_key_maps_legacy_slot_and_keyed_objects() {
        assert_eq!(
            storage_key("0xABCDEF", "knowledge:watchdog", None),
            "bots/abcdef/memory/knowledge:watchdog.enc"
        );
        assert_eq!(
            storage_key(
                "0xABCDEF",
                "knowledge:watchdog",
                Some("checkpoint/dsh-home")
            ),
            "bots/abcdef/memory/knowledge:watchdog.objects/checkpoint/dsh-home.enc"
        );
        assert!(storage_key("0xab", "knowledge:x", Some("k")).starts_with(&object_prefix("0xab")));
        assert!(validate_object_key(agentkeys_protocol::CHECKPOINT_OBJECT_KEY).is_ok());
    }

    #[test]
    fn validate_object_key_rejects_traversal_and_bad_charsets() {
        for ok in ["checkpoint/dsh-home", "a", "a.b-c_d/e0", &"k".repeat(128)] {
            assert!(validate_object_key(ok).is_ok(), "{ok:?} should pass");
        }
        for bad in [
            "",
            "/lead",
            "trail/",
            "a//b",
            "a/../b",
            ".",
            "..",
            "UPPER",
            "sp ace",
            "uni\u{1f}sep",
            &"k".repeat(129),
        ] {
            assert!(validate_object_key(bad).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn compare_and_swap_verdicts() {
        let stored = b"[{\"key\":\"a\"}]";
        let h = keccak_hex(stored);
        assert!(
            check_expected_hash("", None).is_ok(),
            "absent + asserted absent"
        );
        assert!(
            check_expected_hash("", Some(stored)).is_err(),
            "asserted absent but present"
        );
        assert!(check_expected_hash(&h, Some(stored)).is_ok());
        assert!(
            check_expected_hash(&h.to_uppercase(), Some(stored)).is_ok(),
            "hex case-insensitive"
        );
        assert!(check_expected_hash(&h, None).is_err(), "vanished meanwhile");
        let (status, body) = check_expected_hash("0xdeadbeef", Some(stored)).unwrap_err();
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_eq!(body.0.reason, "stale_base");
        assert!(body.0.error.contains(&h), "the 409 names the current hash");
    }

    #[test]
    fn aad_service_domain_separates_keyed_objects() {
        let legacy = aad_service("knowledge:watchdog", None);
        let keyed = aad_service("knowledge:watchdog", Some("checkpoint/dsh-home"));
        let other = aad_service("knowledge:watchdog", Some("checkpoint/other"));
        assert_eq!(legacy, "knowledge:watchdog");
        assert_ne!(legacy, keyed);
        assert_ne!(keyed, other);
        assert!(keyed.contains('\u{1f}'));
    }

    fn sample_payload(
        op: CapOp,
        operator: &str,
        actor: &str,
        service: &str,
        epoch: u64,
    ) -> CapPayload {
        CapPayload {
            operator_omni: operator.to_string(),
            actor_omni: actor.to_string(),
            service: service.to_string(),
            op,
            data_class: DataClass::Memory,
            device_key_hash: "0x00".to_string(),
            k3_epoch: epoch,
            issued_at: 0,
            expires_at: u64::MAX,
            nonce: "n".to_string(),
        }
    }

    #[test]
    fn memory_read_owner_routes_canonical_to_operator_and_own_to_actor() {
        let master = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let delegate = "0xBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbb";
        let canon = sample_payload(
            CapOp::CanonicalFetch,
            master,
            delegate,
            "knowledge:project",
            7,
        );
        let own = sample_payload(CapOp::Fetch, master, delegate, "knowledge:project", 7);
        assert_eq!(
            memory_read_owner(&canon),
            master,
            "canonical read → master prefix"
        );
        assert_eq!(
            memory_read_owner(&own),
            delegate,
            "own read → delegate prefix"
        );
    }

    #[test]
    fn canonical_read_aad_round_trips_a_master_self_store() {
        let kek = "0".repeat(64); // 32-byte test KEK
        let master = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let delegate = "0xBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbb";
        let service = "knowledge:project";
        let epoch = 7u64;
        let plaintext: &[u8] = b"canonical project memory";

        let store_aad = envelope::aad(master, master, service, epoch);
        let blob = envelope::encrypt(&kek, plaintext, &store_aad).expect("encrypt");

        let p = sample_payload(CapOp::CanonicalFetch, master, delegate, service, epoch);
        let owner = memory_read_owner(&p);
        let read_aad = envelope::aad(&p.operator_omni, owner, service, epoch);
        let got = envelope::decrypt(&kek, &blob, &read_aad)
            .expect("delegated canonical read must decrypt the master-self blob");
        assert_eq!(got, plaintext);

        let own = sample_payload(CapOp::Fetch, master, delegate, service, epoch);
        let own_owner = memory_read_owner(&own);
        let wrong_aad = envelope::aad(master, own_owner, service, epoch);
        assert!(
            envelope::decrypt(&kek, &blob, &wrong_aad).is_err(),
            "own-read aad must not decrypt the master's canonical blob"
        );
    }

    #[test]
    fn namespace_folded_service_segregates_storage() {
        let travel = object_key("0xabc", "knowledge:travel");
        let personal = object_key("0xabc", "knowledge:personal");
        assert_ne!(travel, personal);
        assert_eq!(travel, "bots/abc/memory/knowledge:travel.enc");
        assert!(personal.contains("knowledge:personal"));
    }

    fn inbox_token(op: CapOp, operator: &str, actor: &str, service: &str, epoch: u64) -> CapToken {
        CapToken {
            payload: sample_payload(op, operator, actor, service, epoch),
            broker_sig: "x".into(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    #[test]
    fn inbox_object_key_lands_under_the_broker_policy_subprefix() {
        let master = "0xAAaa00000000000000000000000000000000aaAA";
        let delegate = "0xBBbb00000000000000000000000000000000bbBB";
        let key = inbox_object_key(master, delegate, "proposal:travel", "0xdeadBEEF");
        assert_eq!(
            key,
            "bots/aaaa00000000000000000000000000000000aaaa/inbox/bbbb00000000000000000000000000000000bbbb/proposal:travel/deadbeef.enc"
        );
        assert!(key.starts_with(&inbox_subprefix(master, delegate, "proposal:travel")));
        assert!(key.starts_with(&inbox_prefix(master)));
    }

    #[test]
    fn inbox_ns_strips_the_inbox_prefix_for_curate() {
        assert_eq!(inbox_ns_from_service("proposal:travel"), "travel");
        assert_eq!(inbox_ns_from_service("proposal:project:foo"), "project:foo");
        assert_eq!(inbox_ns_from_service("weird"), "weird");
    }

    #[test]
    fn enforce_master_self_accepts_owner_rejects_delegate() {
        let master = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let delegate = "0xBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbb";
        assert!(enforce_master_self(&inbox_token(
            CapOp::Fetch,
            master,
            &master.to_lowercase(),
            "inbox",
            1
        ))
        .is_ok());
        let err = enforce_master_self(&inbox_token(CapOp::Fetch, master, delegate, "inbox", 1))
            .unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn validate_inbox_key_rejects_out_of_prefix_and_traversal() {
        let master = "0xAAaa000000000000000000000000000000000000";
        assert!(validate_inbox_key(master, &format!("{}x/h.enc", inbox_prefix(master))).is_ok());
        assert!(validate_inbox_key(master, "bots/ffff/inbox/d/proposal:x/h.enc").is_err());
        assert!(validate_inbox_key(
            master,
            "bots/aaaa000000000000000000000000000000000000/memory/m.enc"
        )
        .is_err());
        assert!(validate_inbox_key(master, &format!("{}../x", inbox_prefix(master))).is_err());
    }

    #[test]
    fn inbox_aad_round_trips_append_to_master_read() {
        let kek = "0".repeat(64);
        let master = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let epoch = 7u64;
        let item = InboxItem {
            source_delegate_omni: "0xBBbb".into(),
            ns: "travel".into(),
            key: "night-light".into(),
            body_b64: "aGVsbG8=".into(),
            content_hash: "0xabc".into(),
            ts: 1,
            kind: ContextKind::Skill,
        };
        let item_json = serde_json::to_vec(&item).unwrap();

        let append_aad = envelope::aad(master, master, INBOX_AAD_SERVICE, epoch);
        let blob = envelope::encrypt(&kek, &item_json, &append_aad).expect("encrypt");

        let read_aad = envelope::aad(master, master, INBOX_AAD_SERVICE, epoch);
        let got = envelope::decrypt(&kek, &blob, &read_aad).expect("master read must decrypt");
        let round: InboxItem = serde_json::from_slice(&got).unwrap();
        assert_eq!(round.ns, "travel");
        assert_eq!(round.source_delegate_omni, "0xBBbb");
        assert_eq!(round.kind, ContextKind::Skill);

        let memory_aad = envelope::aad(master, master, "knowledge:travel", epoch);
        assert!(envelope::decrypt(&kek, &blob, &memory_aad).is_err());
    }
}
