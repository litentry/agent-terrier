//! Issue #229 acceptance: a cred fetch and a memory get each produce a
//! DURABLE audit event — off-chain feed (envelope stored + fetchable by
//! hash) + on-chain anchor inputs (the envelope hash enters the
//! `appendRootV2` Merkle batch) — with NO plaintext in the audit payload.
//!
//! Drives the real `AuditEmitter` (the exact code the cred/memory/config
//! handlers call after cap-verify) against a real `agentkeys-worker-audit`
//! instance on a loopback socket, then verifies the stored envelope and
//! the flushed anchor batch.

use std::sync::Arc;

use agentkeys_core::audit::{
    AuditEnvelope, AuditOpKind, AuditResult, ConfigGetBody, CredFetchBody, MemoryGetBody,
};
use agentkeys_worker_audit::state::State as AuditWorkerState;
use agentkeys_worker_creds::audit::{cap_hash, AuditEmitter};
use agentkeys_worker_creds::verify::{CapOp, CapPayload, CapToken, DataClass};
use sha3::{Digest, Keccak256};

const SECRET_PLAINTEXT: &str = "sk-test-THIS-MUST-NEVER-APPEAR-IN-AUDIT";

fn sample_cap(service: &str, data_class: DataClass, op: CapOp) -> CapToken {
    CapToken {
        payload: CapPayload {
            operator_omni: format!("0x{}", "aa".repeat(32)),
            actor_omni: format!("0x{}", "bb".repeat(32)),
            service: service.to_string(),
            op,
            data_class,
            device_key_hash: format!("0x{}", "cc".repeat(32)),
            k3_epoch: 1,
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_600,
            nonce: "n-229".into(),
        },
        broker_sig: "sig".into(),
        client_sig: None,
        client_nonce: None,
        client_ts: None,
    }
}

/// Bind the real audit worker on an ephemeral loopback port; return its
/// base URL.
async fn spawn_audit_worker() -> String {
    let state: agentkeys_worker_audit::state::SharedState = Arc::new(AuditWorkerState::new(
        std::env::temp_dir().to_string_lossy().to_string(),
    ));
    let app = agentkeys_worker_audit::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Fetch a stored envelope by hash and decode it; assert the off-chain
/// feed holds exactly the emitted event and the hash is the appendV2
/// anchor commitment (`keccak256(canonical_cbor)`).
async fn fetch_and_verify(base: &str, hash: &str) -> AuditEnvelope {
    let url = format!("{base}/v1/audit/envelope/{hash}");
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), 200, "envelope must be durably fetchable");
    let cbor = resp.bytes().await.unwrap().to_vec();

    let mut h = Keccak256::new();
    h.update(&cbor);
    let recomputed = format!("0x{}", hex::encode(h.finalize()));
    assert_eq!(
        recomputed, hash,
        "envelope_hash IS keccak256(canonical_cbor) — the appendV2 anchor commitment"
    );

    let raw = String::from_utf8_lossy(&cbor).to_string();
    assert!(
        !raw.contains(SECRET_PLAINTEXT) && !raw.contains("sk-test"),
        "no plaintext in the audit payload"
    );

    AuditEnvelope::from_canonical_cbor(&cbor).unwrap()
}

#[tokio::test]
async fn cred_fetch_and_memory_get_produce_durable_audit_events() {
    let base = spawn_audit_worker().await;
    // require=true: an emit failure FAILS the test (and, in the workers'
    // AGENTKEYS_WORKER_REQUIRE_AUDIT=1 mode, the data-plane op).
    let emitter = AuditEmitter::new(&base, true);

    // ── cred fetch — the secret-release record ──────────────────────────
    let cap = sample_cap("openrouter", DataClass::Credentials, CapOp::Fetch);
    let body = CredFetchBody {
        service: cap.payload.service.clone(),
        cap_hash: cap_hash(&cap),
    };
    let hash = emitter
        .emit(&cap, AuditOpKind::CredFetch, body, AuditResult::Success)
        .await
        .expect("emit must succeed")
        .expect("require mode returns the receipt");
    let env = fetch_and_verify(&base, &hash).await;
    assert_eq!(env.op_kind, AuditOpKind::CredFetch as u8);
    assert_eq!(env.result, AuditResult::Success);
    assert_eq!(env.actor_omni, [0xbb; 32]);
    assert_eq!(env.operator_omni, [0xaa; 32]);
    match env.typed_body().unwrap() {
        agentkeys_core::audit::TypedAuditBody::CredFetch(b) => {
            assert_eq!(b.service, "openrouter");
            assert_eq!(b.cap_hash, cap_hash(&cap), "row binds to the verified cap");
        }
        other => panic!("unexpected body: {other:?}"),
    }

    // ── memory get — symmetric per-data-class coverage ──────────────────
    let cap = sample_cap("memory:travel", DataClass::Memory, CapOp::Fetch);
    let body = MemoryGetBody {
        key: "bots/bb/memory/memory:travel.enc".into(),
        cap_hash: cap_hash(&cap),
    };
    let mem_hash = emitter
        .emit(&cap, AuditOpKind::MemoryGet, body, AuditResult::Success)
        .await
        .unwrap()
        .unwrap();
    let env = fetch_and_verify(&base, &mem_hash).await;
    assert_eq!(env.op_kind, AuditOpKind::MemoryGet as u8);

    // ── config get — third data class, same path (#201 symmetry) ────────
    let cap = sample_cap("memory-taxonomy", DataClass::Config, CapOp::Fetch);
    let body = ConfigGetBody {
        key: "bots/aa/config/memory-taxonomy.enc".into(),
        cap_hash: cap_hash(&cap),
    };
    let cfg_hash = emitter
        .emit(&cap, AuditOpKind::ConfigGet, body, AuditResult::Success)
        .await
        .unwrap()
        .unwrap();
    let env = fetch_and_verify(&base, &cfg_hash).await;
    assert_eq!(env.op_kind, AuditOpKind::ConfigGet as u8);

    // ── on-chain anchor tier: all three envelope hashes enter the
    //    appendRootV2 Merkle batch for the operator ────────────────────────
    let operator = format!("0x{}", "aa".repeat(32));
    let flush: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/v1/audit/flush/{operator}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let batches = flush["flushed_v2"].as_array().expect("flushed_v2 present");
    assert_eq!(batches.len(), 1, "one anchor batch for the operator");
    let batch = &batches[0];
    assert_eq!(batch["entry_count"], 3);
    assert!(batch["merkle_root_hex"].as_str().unwrap().starts_with("0x"));
    let hashes: Vec<&str> = batch["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["envelope_hash"].as_str().unwrap())
        .collect();
    for h in [&hash, &mem_hash, &cfg_hash] {
        assert!(hashes.contains(&h.as_str()), "{h} in the anchor batch");
    }
    // Bitmap marks exactly CredFetch(1) + MemoryGet(11) + ConfigGet(81).
    let bitmap = batch["op_kind_bitmap_hex"].as_str().unwrap();
    let bm = hex::decode(bitmap.trim_start_matches("0x")).unwrap();
    for k in [1usize, 11, 81] {
        assert_ne!(bm[31 - k / 8] & (1 << (k % 8)), 0, "op_kind bit {k} set");
    }
}

/// Failures after cap-verify are audited too (`result: Failure`), so a
/// denied-at-S3 / failed-decrypt path still leaves a durable record.
#[tokio::test]
async fn failure_results_are_audited_too() {
    let base = spawn_audit_worker().await;
    let emitter = AuditEmitter::new(&base, true);
    let cap = sample_cap("openrouter", DataClass::Credentials, CapOp::Fetch);
    let hash = emitter
        .emit(
            &cap,
            AuditOpKind::CredFetch,
            CredFetchBody {
                service: cap.payload.service.clone(),
                cap_hash: cap_hash(&cap),
            },
            AuditResult::Failure,
        )
        .await
        .unwrap()
        .unwrap();
    let env = fetch_and_verify(&base, &hash).await;
    assert_eq!(env.result, AuditResult::Failure);
}

/// require=true (`AGENTKEYS_WORKER_REQUIRE_AUDIT=1`) fails CLOSED when the
/// audit worker is unreachable; best-effort mode degrades to `Ok(None)`.
#[tokio::test]
async fn require_mode_fails_closed_when_audit_worker_down() {
    // Reserve a port, then drop the listener so nothing is listening.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);

    let cap = sample_cap("openrouter", DataClass::Credentials, CapOp::Fetch);
    let body = || CredFetchBody {
        service: "openrouter".into(),
        cap_hash: cap_hash(&cap),
    };

    let strict = AuditEmitter::new(&dead, true);
    let err = strict
        .emit(&cap, AuditOpKind::CredFetch, body(), AuditResult::Success)
        .await
        .expect_err("strict mode must fail closed");
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), 502);

    let best_effort = AuditEmitter::new(&dead, false);
    let receipt = best_effort
        .emit(&cap, AuditOpKind::CredFetch, body(), AuditResult::Success)
        .await
        .expect("best-effort mode must not fail the op");
    assert!(receipt.is_none(), "no receipt when the emit was dropped");
}
