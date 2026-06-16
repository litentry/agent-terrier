//! Memory worker HTTP surface — mirrors credentials worker but at the
//! `memory/` prefix per arch.md §15.2 + §17 per-data-class buckets.

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedMemoryWorkerState;
use agentkeys_core::audit::{
    AuditOpKind, AuditResult, MemoryGetBody, MemoryPutBody, MemoryTeardownBody,
};
use agentkeys_worker_creds::audit::{cap_hash, keccak_hex, zero_hash};
use agentkeys_worker_creds::aws_creds::{s3_for_request, OptionalStsCreds, StsCreds};
use agentkeys_worker_creds::envelope;
use agentkeys_worker_creds::errors::{
    err_400, err_403, err_404, err_500, err_502, err_502_s3_get, ApiError, S3FetchAttempt,
};
use agentkeys_worker_creds::verify::{self, CapOp, CapPayload, CapToken, DataClass};

pub fn build_router(state: SharedMemoryWorkerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/memory/put", post(memory_put))
        .route("/v1/memory/get", post(memory_get))
        // #295 P1 — delegated READ of the master's CANONICAL memory (distinct
        // signed cap op so it cannot be reached with an own-memory `get` cap).
        .route("/v1/memory/canonical-get", post(memory_canonical_get))
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
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the audit
    /// worker stored for this op (the `CredentialAudit.appendV2` anchor
    /// commitment). `null` when the emit failed in best-effort mode.
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GetRequest {
    pub cap: CapToken,
}

#[derive(Debug, Serialize)]
pub struct GetResponse {
    pub ok: bool,
    pub plaintext_b64: String,
    /// Durable-audit receipt (#229) — see [`PutResponse::audit_envelope_hash`].
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
    /// Durable-audit receipt (#229) — see [`PutResponse::audit_envelope_hash`].
    pub audit_envelope_hash: Option<String>,
}

async fn memory_put(
    State(state): State<SharedMemoryWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<PutRequest>,
) -> Result<Json<PutResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Store).await?;

    let outcome = memory_put_inner(&state, creds.as_ref(), &req).await;
    // Durable audit (#229): after cap-verify, before the success response.
    // payload_hash covers the stored CIPHERTEXT — never plaintext.
    let audit_body = MemoryPutBody {
        key: s3_key(&req.cap.payload.actor_omni, &req.cap.payload.service),
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
    creds: Option<&StsCreds>,
    req: &PutRequest,
) -> Result<(String, Vec<u8>), ApiError> {
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
    let s3 = s3_for_request(&state.s3, &state.config.region, creds).await;
    s3.put_object()
        .bucket(&state.config.memory_bucket)
        .key(&key)
        .body(env_bytes.clone().into())
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "s3_put"))?;
    Ok((key, env_bytes))
}

/// Read the caller's OWN working memory (`bots/<actor>/memory/`). Unchanged
/// by #295 — the active `agentkeys.memory.get` path.
async fn memory_get(
    State(state): State<SharedMemoryWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Fetch).await?;
    memory_read_after_verify(&state, creds.as_ref(), &req).await
}

/// #295 P1 — delegated READ of the master's CANONICAL memory
/// (`bots/<operator>/memory/`). Same release path as `memory_get`, but the
/// SIGNED cap op is `CanonicalFetch`, so `memory_read_owner` resolves the S3
/// prefix + envelope AAD to the OPERATOR (the master's canonical), not the
/// caller's own memory. Because `operator != actor` for a delegate,
/// `verify_cap`'s `check_chain_scope` consults the on-chain `memory:<ns>`
/// grant (the master-self skip is bypassed) — that grant IS the delegate's
/// authorization. The caller must relay OPERATOR-scoped STS (a session-policy
/// pinned to this one key — plan §7a); a delegate's own actor-tagged STS gets
/// AccessDenied on the operator prefix (layer-3 isolation intact).
async fn memory_canonical_get(
    State(state): State<SharedMemoryWorkerState>,
    headers: HeaderMap,
    Json(req): Json<GetRequest>,
) -> Result<Json<GetResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::CanonicalFetch).await?;
    // A' (#295 §7a): the read runs SERVER-SIDE. The delegate sends its OWN
    // session bearer + the cap and gets back ONLY plaintext — never S3 creds.
    // The worker relays that bearer to the broker's /v1/cap/canonical-sts, which
    // re-verifies the cap (session == cap.actor) + returns an STS scoped to
    // GetObject on this ONE object. So a compromised worker's blast radius is one
    // object per request (not the operator prefix), and the delegate cannot
    // bypass this audit + chain re-verify by hitting S3 directly (it holds no creds).
    let bearer = bearer_from_headers(&headers).ok_or_else(|| {
        err_403(
            "canonical-get requires the delegate session bearer (Authorization: Bearer …)"
                .to_string(),
            "missing_session_bearer",
        )
    })?;
    let creds = fetch_canonical_sts(&state, &bearer, &req.cap).await?;
    memory_read_after_verify(&state, Some(&creds), &req).await
}

/// Server-side canonical-read STS (A', §7a): relay the delegate's session bearer
/// plus the (already chain-verified) cap to the broker's `/v1/cap/canonical-sts`.
/// The broker re-verifies `session == cap.actor` and returns creds scoped to
/// `GetObject` on the single `bots/<operator>/memory/<ns>.enc` object — minted
/// HERE (server-side), never handed to the delegate.
async fn fetch_canonical_sts(
    state: &SharedMemoryWorkerState,
    bearer: &str,
    cap: &CapToken,
) -> Result<StsCreds, ApiError> {
    let broker_url = state.config.broker_url.trim_end_matches('/');
    if broker_url.is_empty() {
        return Err(err_500(
            "canonical-get unavailable: BROKER_URL is not set on the memory worker".to_string(),
            "broker_url_unset",
        ));
    }
    let url = format!("{broker_url}/v1/cap/canonical-sts");
    let resp = state
        .http
        .post(&url)
        .bearer_auth(bearer)
        .json(&serde_json::json!({ "cap": cap }))
        .send()
        .await
        .map_err(|e| err_502(e.to_string(), "canonical_sts_post"))?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        // Surface the broker's authz verdict (e.g. 403 cap-actor-mismatch) as a
        // 403, not a generic 502 — the caller gets the real reason.
        return Err(err_403(
            format!("broker canonical-sts {status}: {body}"),
            "canonical_sts_denied",
        ));
    }
    let creds: agentkeys_protocol::CanonicalStsResult = resp
        .json()
        .await
        .map_err(|e| err_502(e.to_string(), "canonical_sts_json"))?;
    Ok(StsCreds {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
    })
}

/// Pull a bearer token from `Authorization: Bearer …` (scheme case-insensitive).
fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let v = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Shared post-verify release path for own (`memory_get`) and canonical
/// (`memory_canonical_get`) reads. The read owner — and therefore the S3 key,
/// the envelope AAD, and the audit key — is resolved from the SIGNED cap op
/// via `memory_read_owner`, so the two paths can never key the same cap to
/// different prefixes.
async fn memory_read_after_verify(
    state: &SharedMemoryWorkerState,
    creds: Option<&StsCreds>,
    req: &GetRequest,
) -> Result<Json<GetResponse>, ApiError> {
    let outcome = memory_get_inner(state, creds, req).await;
    // Durable audit (#229): the memory-release record, emitted BEFORE the
    // plaintext leaves the worker. cap_hash binds the row to the cap that
    // authorized this read; the key reflects the prefix actually read.
    let audit_body = MemoryGetBody {
        key: s3_key(
            memory_read_owner(&req.cap.payload),
            &req.cap.payload.service,
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
    creds: Option<&StsCreds>,
    req: &GetRequest,
) -> Result<Vec<u8>, ApiError> {
    // #295 P1: the read owner is resolved from the SIGNED cap op — `actor` for
    // an own-memory `Fetch`, `operator` for `CanonicalFetch`. It drives BOTH
    // the S3 key AND the envelope AAD below, so they can never diverge.
    let owner = memory_read_owner(&req.cap.payload);
    let key = s3_key(owner, &req.cap.payload.service);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds).await;
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
                // #284: the 502 names the S3 error code (AccessDenied /
                // ExpiredToken / NoSuchBucket / ...) in body + detail, so a
                // remote caller can diagnose without a host journalctl session.
                let attempt = S3FetchAttempt::from_sdk_err("memory-owner", owner, &e);
                tracing::warn!(
                    owner_omni = %owner,
                    s3_code = %attempt.s3_code,
                    bucket = %state.config.memory_bucket,
                    service = %req.cap.payload.service,
                    "memory get: S3 GetObject failed"
                );
                err_502_s3_get(&state.config.memory_bucket, vec![attempt])
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
        owner,
        &req.cap.payload.service,
        req.cap.payload.k3_epoch,
    );
    envelope::decrypt(&state.config.kek_hex_stage1, &body, &aad)
        .map_err(|e| err_500(e.to_string(), "envelope_decrypt"))
}

async fn memory_teardown(
    State(state): State<SharedMemoryWorkerState>,
    OptionalStsCreds(creds): OptionalStsCreds,
    Json(req): Json<TeardownRequest>,
) -> Result<Json<TeardownResponse>, ApiError> {
    verify_cap(&state, &req.cap, CapOp::Teardown).await?;

    let outcome = memory_teardown_inner(&state, creds.as_ref(), &req).await;
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
    creds: Option<&StsCreds>,
    req: &TeardownRequest,
) -> Result<usize, ApiError> {
    let prefix = s3_prefix(&req.cap.payload.actor_omni);
    let s3 = s3_for_request(&state.s3, &state.config.region, creds).await;
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
    Ok(deleted)
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

/// The memory prefix a READ resolves to (master-hub #295 P1). Mirror of the
/// cred worker's `fetch_vault_owner`, but memory has TWO read spaces:
///   - `CapOp::Fetch`          → the caller's OWN working memory (`actor_omni`)
///   - `CapOp::CanonicalFetch` → the master's CANONICAL memory (`operator_omni`)
///
/// Executable decision record (read docs/plan/master-hub-topology.md §6a/§12
/// before changing): the returned owner drives BOTH the S3 key AND the
/// envelope AAD (`envelope::aad` keys on its `actor` arg). If `CanonicalFetch`
/// ever resolves to `actor_omni`, the distribution channel silently reads the
/// delegate's own (empty) prefix instead of the master's; if `Fetch` ever
/// resolves to `operator_omni`, the ACTIVE own-memory read breaks. Store +
/// teardown stay `actor_omni`-keyed (master-self for canonical content), so a
/// delegated cap can never write or wipe the master's prefix here.
fn memory_read_owner(payload: &CapPayload) -> &str {
    match payload.op {
        CapOp::CanonicalFetch => &payload.operator_omni,
        _ => &payload.actor_omni,
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
    fn bearer_from_headers_parses_scheme_case_insensitively() {
        // A' (#295 §7a): canonical-get relays the DELEGATE's session bearer to
        // the broker. Parse `Bearer`/`bearer`; reject empty/missing/scheme-less
        // so the handler 403s rather than relaying a blank bearer to the broker.
        let mk = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(axum::http::header::AUTHORIZATION, v.parse().unwrap());
            h
        };
        assert_eq!(
            bearer_from_headers(&mk("Bearer tok123")).as_deref(),
            Some("tok123")
        );
        assert_eq!(
            bearer_from_headers(&mk("bearer tok123")).as_deref(),
            Some("tok123")
        );
        assert!(bearer_from_headers(&mk("Bearer ")).is_none());
        assert!(bearer_from_headers(&mk("tok-no-scheme")).is_none());
        assert!(bearer_from_headers(&HeaderMap::new()).is_none());
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
        // #295 P1: the SAME omnis (operator=master, actor=delegate) appear on
        // both an own-read and a canonical-read cap; only the signed op decides
        // the prefix. This is why the discriminator must be the op, not the
        // omnis (and why a route alone would be forgeable).
        let master = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let delegate = "0xBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbb";
        let canon = sample_payload(CapOp::CanonicalFetch, master, delegate, "memory:project", 7);
        let own = sample_payload(CapOp::Fetch, master, delegate, "memory:project", 7);
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
        // The load-bearing AAD invariant (#295 P1, plan §6/§11 contradiction 2):
        // a master-self STORE binds the aad to the master (actor == operator).
        // A DELEGATED canonical read (op=CanonicalFetch) must recompute the SAME
        // aad — which works ONLY because memory_read_owner feeds `operator` as
        // the aad actor arg (envelope::aad keys on its actor arg). A naive port
        // keyed on the delegate's actor_omni would fetch the right object then
        // FAIL decrypt (looks like KEK corruption).
        let kek = "0".repeat(64); // 32-byte test KEK
        let master = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let delegate = "0xBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbb";
        let service = "memory:project";
        let epoch = 7u64;
        let plaintext: &[u8] = b"canonical project memory";

        // master-self store aad (operator arg ignored; actor == master is bound).
        let store_aad = envelope::aad(master, master, service, epoch);
        let blob = envelope::encrypt(&kek, plaintext, &store_aad).expect("encrypt");

        // delegated canonical read: owner resolves to master, aad recomputed.
        let p = sample_payload(CapOp::CanonicalFetch, master, delegate, service, epoch);
        let owner = memory_read_owner(&p);
        let read_aad = envelope::aad(&p.operator_omni, owner, service, epoch);
        let got = envelope::decrypt(&kek, &blob, &read_aad)
            .expect("delegated canonical read must decrypt the master-self blob");
        assert_eq!(got, plaintext);

        // a would-be own-read aad (actor=delegate) must NOT decrypt the master blob.
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
