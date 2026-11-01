//! `agent_admin` against a MOCK broker (an ephemeral axum server): the claim /
//! pending / ack / spawn / archive / accept client paths, with the SOFTWARE
//! P-256 passkey signing the UserOps the way headless CI does. No chain, no
//! deployed broker — the wire shapes are the protocol crate's typed responses.

mod common;
use common::development_signing;

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use agentkeys_cli::agent_admin;

const DKH: &str = "0xabababababababababababababababababababababababababababababababab";
const CHILD: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const OPERATOR: &str = "0x1212121212121212121212121212121212121212121212121212121212121212";

#[derive(Default)]
struct Seen {
    posts: Mutex<Vec<(String, Value)>>,
    bad_chain: std::sync::atomic::AtomicBool,
    bad_hash: std::sync::atomic::AtomicBool,
    bad_entry_point: std::sync::atomic::AtomicBool,
    lose_submit_response: std::sync::atomic::AtomicBool,
    operation_directory: Mutex<Option<std::path::PathBuf>>,
}

fn packed_user_op() -> agentkeys_core::erc4337::PackedUserOp {
    let mut sender = [0; 20];
    sender[19] = 1;
    agentkeys_core::erc4337::PackedUserOp {
        sender,
        nonce: [0; 32],
        init_code: Vec::new(),
        call_data: Vec::new(),
        account_gas_limits: [0; 32],
        pre_verification_gas: [0; 32],
        gas_fees: [0; 32],
        paymaster_and_data: Vec::new(),
        signature: Vec::new(),
    }
}

fn user_op() -> Value {
    serde_json::to_value(agentkeys_core::erc4337::wire_user_op_from_packed(
        &packed_user_op(),
    ))
    .unwrap()
}

fn local_chain_id() -> u64 {
    agentkeys_core::chain_profile::ChainProfile::load_builtin("anvil")
        .unwrap()
        .chain_id
}

fn operation_hash() -> String {
    let mut entry_point = [0; 20];
    entry_point[19] = 2;
    format!(
        "0x{}",
        hex::encode(packed_user_op().user_op_hash(&entry_point, local_chain_id()))
    )
}

fn claimed_hash(seen: &Seen) -> String {
    if seen.bad_hash.load(std::sync::atomic::Ordering::SeqCst) {
        format!("0x{}", "ab".repeat(32))
    } else {
        operation_hash()
    }
}

async fn record(State(seen): State<Arc<Seen>>, path: &'static str, body: Value) -> Value {
    seen.posts.lock().unwrap().push((path.to_string(), body));
    Value::Null
}

async fn mock_broker(seen: Arc<Seen>) -> String {
    let app = Router::new()
        .route(
            "/v1/agent/pairing/claim",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "claim", b.clone()).await;
                Json(json!({ "ok": true, "child_omni": CHILD, "label": b["label"], "request_id": "req-1" }))
            }),
        )
        .route(
            "/v1/agent/pending-bindings",
            get(|| async {
                Json(json!({ "pending": [ {
                    "request_id": "req-1", "label": "probe", "child_omni": CHILD,
                    "device_key_hash": DKH, "agent_pop_sig": "0x00", "requested_scope": "channel-sub:kitchen"
                } ] }))
            }),
        )
        .route(
            "/v1/agent/pending-bindings/ack",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "ack", b).await;
                Json(json!({ "ok": true }))
            }),
        )
        .route(
            "/v1/agent/spawn/build",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "spawn/build", b.clone()).await;
                Json(json!({
                    "user_op": user_op(), "user_op_hash": claimed_hash(&s), "entry_point": format!("0x{:040x}", if s.bad_entry_point.load(std::sync::atomic::Ordering::SeqCst) { 3 } else { 2 }),
                    "chain_id": if s.bad_chain.load(std::sync::atomic::Ordering::SeqCst) { 1 } else { local_chain_id() }, "actor_omni": CHILD.trim_start_matches("0x"), "device_key_hash": DKH,
                    "chat_channel_id": "opchat-probe", "memory_ns": "app-probe", "memory_inherited": false,
                    "services": ["channel-pub:opchat-probe", "channel-sub:opchat-probe", "knowledge:app-probe"],
                    "slots_used": 1, "slots_total": 3
                }))
            }),
        )
        .route(
            "/v1/agent/spawn/submit",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                if let Some(directory) = s.operation_directory.lock().unwrap().as_ref() {
                    assert!(directory.join(format!("{}.json", operation_hash())).is_file());
                }
                record(State(s.clone()), "spawn/submit", b).await;
                if s.lose_submit_response.load(std::sync::atomic::Ordering::SeqCst) {
                    return Json(json!({"error":"synthetic-private-submission-response"}));
                }
                Json(json!({ "ok": true, "user_op_hash": claimed_hash(&s), "tx_hash": "0x9b10", "block_number": "0x1" }))
            }),
        )
        .route(
            "/v1/agent/archive/build",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "archive/build", b).await;
                Json(json!({
                    "user_op": user_op(), "user_op_hash": claimed_hash(&s), "entry_point": format!("0x{:040x}", if s.bad_entry_point.load(std::sync::atomic::Ordering::SeqCst) { 3 } else { 2 }),
                    "chain_id": if s.bad_chain.load(std::sync::atomic::Ordering::SeqCst) { 1 } else { local_chain_id() }, "device_key_hash": DKH, "resources_kept": true
                }))
            }),
        )
        .route(
            "/v1/agent/archive/submit",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "archive/submit", b).await;
                Json(json!({ "ok": true, "user_op_hash": claimed_hash(&s), "tx_hash": "0x9b11", "block_number": "0x2" }))
            }),
        )
        .route(
            "/v1/accept/receipt",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "accept/receipt", b).await;
                Json(json!({"ok":true,"pending":true,"user_op_hash":claimed_hash(&s)}))
            }),
        )
        .route(
            "/v1/accept/build",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "accept/build", b).await;
                Json(json!({ "user_op": user_op(), "user_op_hash": claimed_hash(&s), "entry_point": format!("0x{:040x}", if s.bad_entry_point.load(std::sync::atomic::Ordering::SeqCst) { 3 } else { 2 }), "chain_id": if s.bad_chain.load(std::sync::atomic::Ordering::SeqCst) { 1 } else { local_chain_id() } }))
            }),
        )
        .route(
            "/v1/accept/submit",
            post(|State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                record(State(s.clone()), "accept/submit", b).await;
                Json(json!({ "ok": true, "tx_hash": "0x9b12", "block_number": "0x3", "user_op_hash": claimed_hash(&s) }))
            }),
        )
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A bearer with the omni claim `agent_spawn` reads (`agentkeys.omni_account`);
/// the signature segment is never verified client-side.
fn bearer() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload =
        URL_SAFE_NO_PAD.encode(json!({ "agentkeys": { "omni_account": OPERATOR } }).to_string());
    format!("e30.{payload}.sig")
}

fn software_key(dir: &tempfile::TempDir) -> String {
    let path = dir
        .path()
        .join("k11-software.pem")
        .to_string_lossy()
        .to_string();
    agentkeys_cli::k11_webauthn::software_webauthn_keygen(
        &development_signing(),
        &path,
        "localhost",
    )
    .expect("software passkey");
    path
}

#[tokio::test]
async fn claim_pending_and_ack_round_trip_the_rendezvous() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let body = agent_admin::agent_claim(
        &base,
        "PAIR-1234",
        "probe",
        "channel-sub:kitchen",
        &bearer(),
    )
    .await
    .expect("claim");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["child_omni"], CHILD);
    assert_eq!(v["label"], "probe");
    let pending = agent_admin::agent_pending_value(&base, &bearer())
        .await
        .expect("pending");
    assert_eq!(pending["pending"][0]["request_id"], "req-1");
    let text = agent_admin::agent_pending(&base, &bearer())
        .await
        .expect("pending text");
    assert!(text.contains("req-1"));
    agent_admin::agent_ack(&base, "req-1", &bearer())
        .await
        .expect("ack");
    let posts = seen.posts.lock().unwrap();
    let claim = posts
        .iter()
        .find(|(p, _)| p == "claim")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(claim["pairing_code"], "PAIR-1234");
    assert_eq!(claim["label"], "probe");
    assert_eq!(claim["requested_scope"], "channel-sub:kitchen");
    let ack = posts
        .iter()
        .find(|(p, _)| p == "ack")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(ack["request_id"], "req-1");
}

#[tokio::test]
async fn spawn_and_archive_sign_with_the_software_passkey_and_submit() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let key = software_key(&dir);
    let out = agent_admin::agent_spawn(
        &development_signing(),
        &base,
        "probe",
        "chef",
        "",
        false,
        &key,
        "localhost",
        &bearer(),
        None,
    )
    .await
    .expect("spawn");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["spawned"], true);
    assert_eq!(v["label"], "probe");
    assert_eq!(v["actor_omni"], CHILD.trim_start_matches("0x"));
    assert_eq!(v["device_key_hash"], DKH);
    assert_eq!(v["user_op_hash"], operation_hash());
    let out = agent_admin::agent_archive(
        &development_signing(),
        &base,
        DKH,
        true,
        "app-probe",
        &key,
        "localhost",
        &bearer(),
        None,
    )
    .await
    .expect("archive");
    assert!(out.contains(DKH), "{out}");
    let posts = seen.posts.lock().unwrap();
    let build = posts
        .iter()
        .find(|(p, _)| p == "spawn/build")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(build["label"], "probe");
    assert_eq!(build["preset_id"], "chef");
    let submit = posts
        .iter()
        .find(|(p, _)| p == "spawn/submit")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert!(
        submit["assertion"]["signature"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "{submit}"
    );
    assert_eq!(
        submit["user_op"]["sender"],
        "0x0000000000000000000000000000000000000001"
    );
    let archive = posts
        .iter()
        .find(|(p, _)| p == "archive/build")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(archive["device_key_hash"], DKH);
    assert_eq!(archive["resources_kept"], true);
    assert!(posts.iter().any(|(p, _)| p == "archive/submit"));
}

#[tokio::test]
async fn accept_signs_the_pending_binding_and_refuses_a_device_without_channels() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let key = software_key(&dir);
    // A device claim must carry ≥ 1 channel grant (D9): refused before any request.
    let err = agent_admin::agent_accept(
        &development_signing(),
        &base,
        "req-1",
        "memory",
        true,
        &key,
        "localhost",
        OPERATOR,
        &bearer(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").to_lowercase().contains("channel"),
        "{err:#}"
    );
    // An unknown request id is refused after the pending read.
    let err = agent_admin::agent_accept(
        &development_signing(),
        &base,
        "req-404",
        "channel-sub:kitchen",
        true,
        &key,
        "localhost",
        OPERATOR,
        &bearer(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("req-404"), "{err:#}");
    // The happy path: build → software assertion → submit.
    let out = agent_admin::agent_accept(
        &development_signing(),
        &base,
        "req-1",
        "channel-sub:kitchen",
        true,
        &key,
        "localhost",
        OPERATOR,
        &bearer(),
    )
    .await
    .expect("accept");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["accepted"], true);
    assert_eq!(v["is_device"], true);
    assert_eq!(v["actor_omni"], CHILD);
    assert_eq!(v["tx_hash"], "0x9b12");
    let posts = seen.posts.lock().unwrap();
    let build = posts
        .iter()
        .find(|(p, _)| p == "accept/build")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert_eq!(build["operator_omni"], OPERATOR);
    assert_eq!(build["actor_omni"], CHILD);
    assert_eq!(build["is_device"], true);
    let submit = posts
        .iter()
        .find(|(p, _)| p == "accept/submit")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert!(submit["assertion"]["authenticator_data"].as_str().is_some());
}

#[tokio::test]
async fn software_signing_rejects_foreign_chain_and_tampered_hash_before_key_access_or_submit() {
    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    for (wrong_chain, wrong_hash, wrong_entry_point, expected) in [
        (true, false, false, "different chain"),
        (false, true, false, "hash does not match"),
        (false, false, true, "different chain or EntryPoint"),
    ] {
        seen.bad_chain
            .store(wrong_chain, std::sync::atomic::Ordering::SeqCst);
        seen.bad_hash
            .store(wrong_hash, std::sync::atomic::Ordering::SeqCst);
        seen.bad_entry_point
            .store(wrong_entry_point, std::sync::atomic::Ordering::SeqCst);
        let error = agent_admin::agent_spawn(
            &development_signing(),
            &base,
            "probe",
            "chef",
            "",
            false,
            "must-not-be-read.pem",
            "localhost",
            &bearer(),
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert!(seen
            .posts
            .lock()
            .unwrap()
            .iter()
            .all(|(route, _)| !route.ends_with("submit")));
    }
}

#[tokio::test]
async fn software_signing_rejects_remote_service_before_network_or_key_access() {
    let error = agent_admin::agent_spawn(
        &development_signing(),
        "https://example.test",
        "probe",
        "chef",
        "",
        false,
        "must-not-be-read.pem",
        "localhost",
        &bearer(),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("loopback HTTP service"),
        "{error}"
    );
}

#[tokio::test]
async fn lost_submission_response_is_recovered_without_signing_or_resubmitting() {
    use agentkeys_cli::agent_operation::{AgentOperationJournal, AgentOperationRecord};
    use agentkeys_core::protected_file;
    use std::os::unix::fs::PermissionsExt;

    let seen = Arc::new(Seen::default());
    let base = mock_broker(seen.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let key = software_key(&directory);
    let key_contents = std::fs::read_to_string(&key).unwrap();
    *seen.operation_directory.lock().unwrap() = Some(directory.path().to_owned());
    seen.lose_submit_response
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let journal = AgentOperationJournal {
        directory: directory.path(),
        operator_omni: OPERATOR,
        broker_url: &base,
        request_device_key_hash: DKH,
    };
    let error = agent_admin::agent_spawn(
        &development_signing(),
        &base,
        "probe",
        "chef",
        "",
        false,
        &key,
        "localhost",
        &bearer(),
        Some(&journal),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("outcome is unknown"));
    assert!(!error.to_string().contains("synthetic-private"));
    let path = directory.path().join(format!("{}.json", operation_hash()));
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!text.contains(&bearer()) && !text.contains(&key_contents));
    let original: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(original["build"]["user_op"]["signature"], "0x");
    std::fs::remove_file(&key).unwrap();
    let record =
        AgentOperationRecord::load(path.to_str().unwrap(), &journal, &development_signing())
            .unwrap();
    assert_eq!(
        agent_admin::agent_receipt(&development_signing(), &base, &bearer(), &record)
            .await
            .unwrap()["pending"],
        true
    );
    {
        let requests = seen.posts.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|(route, _)| route.ends_with("submit"))
                .count(),
            1
        );
        let request = &requests
            .iter()
            .find(|(route, _)| route == "accept/receipt")
            .unwrap()
            .1;
        assert!(request.get("assertion").is_none());
        assert_eq!(request["user_op"]["signature"], "0x");
    }
    for (field, value) in [
        ("version", json!(999)),
        ("development_only", json!(false)),
        ("operator_omni", json!(CHILD)),
        ("broker_url", json!("http://127.0.0.1:1")),
        ("request_device_key_hash", json!(CHILD)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        protected_file::replace_atomic(&path, &serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(AgentOperationRecord::load(
            path.to_str().unwrap(),
            &journal,
            &development_signing()
        )
        .is_err());
    }
    let mut changed = original.clone();
    changed["build"]["user_op"]["call_data"] = json!("0x01");
    protected_file::replace_atomic(&path, &serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        AgentOperationRecord::load(path.to_str().unwrap(), &journal, &development_signing())
            .is_err()
    );
    protected_file::replace_atomic(&path, text.as_bytes()).unwrap();
    let error = agent_admin::agent_spawn(
        &development_signing(),
        &base,
        "probe",
        "chef",
        "",
        false,
        &key,
        "localhost",
        &bearer(),
        Some(&journal),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("save protected operation"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(
        seen.posts
            .lock()
            .unwrap()
            .iter()
            .filter(|(route, _)| route.ends_with("submit"))
            .count(),
        1
    );
}
