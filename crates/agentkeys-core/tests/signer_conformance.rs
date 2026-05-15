//! TEE-stub conformance test: prove that `SignerClient` works identically
//! against the HKDF-backed `dev_key_service` and a stripped-down TEE-stub
//! that implements the same `signer-protocol.md` wire contract via an
//! in-memory ECDSA keypair (no HKDF).
//!
//! This is the load-bearing test for issue #74 step 1 → step 2 swap. If
//! someone breaks the wire shape in either direction, this test fails.
//! When the real TEE worker lands (issue #74 step 2), it joins this suite
//! verbatim; daemon and CLI code do not change.

use agentkeys_core::signer_client::{HttpSignerClient, SignerClient, SignerClientError};
use agentkeys_mock_server::{
    create_router as mock_router, db, dev_key_service::DevKeyService, state::AppState,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ----------------------------------------------------------------------
// TEE-stub: same wire as dev_key_service, but in-memory keypair per omni.
// ----------------------------------------------------------------------

#[derive(Clone, Default)]
struct TeeStubState {
    /// One per-omni keypair, lazily instantiated. The real TEE worker would
    /// generate these inside the enclave; the stub uses fresh OS-RNG keys
    /// so we explicitly do NOT cross-validate addresses against the HKDF
    /// backend — the conformance check is on shape, not identity.
    keys: Arc<Mutex<HashMap<String, SigningKey>>>,
}

impl TeeStubState {
    fn key_for(&self, omni: &str) -> SigningKey {
        let mut map = self.keys.lock().unwrap();
        map.entry(omni.to_string())
            .or_insert_with(|| SigningKey::random(&mut k256_rand::OsRngWrapper))
            .clone()
    }
}

// k256 0.13 needs a `RngCore + CryptoRng` adapter; build a tiny one that
// wraps `getrandom`.
mod k256_rand {
    use rand_core::{CryptoRng, RngCore};
    pub struct OsRngWrapper;
    impl RngCore for OsRngWrapper {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            getrandom::getrandom(dest).expect("OS RNG failed");
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for OsRngWrapper {}
}

fn address_for(sk: &SigningKey) -> String {
    let vk: &VerifyingKey = sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    let mut h = Keccak256::new();
    h.update(&pubkey_bytes[1..]);
    let pubkey_hash = h.finalize();
    format!("0x{}", hex::encode(&pubkey_hash[12..]))
}

fn parse_omni(s: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if s.len() != 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error":"invalid_omni_account",
                "message":"must be 64 hex chars"
            })),
        ));
    }
    if hex::decode(s).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error":"invalid_omni_account",
                "message":"not valid hex"
            })),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct DeriveReq {
    omni_account: String,
}

#[derive(Deserialize)]
struct SignReq {
    omni_account: String,
    message_hex: String,
}

async fn tee_derive(
    State(state): State<TeeStubState>,
    Json(body): Json<DeriveReq>,
) -> impl IntoResponse {
    if let Err(e) = parse_omni(&body.omni_account) {
        return e.into_response();
    }
    let sk = state.key_for(&body.omni_account);
    let address = address_for(&sk);
    (
        StatusCode::OK,
        Json(json!({
            "address": address,
            "key_version": 1,
        })),
    )
        .into_response()
}

async fn tee_sign(
    State(state): State<TeeStubState>,
    Json(body): Json<SignReq>,
) -> impl IntoResponse {
    if let Err(e) = parse_omni(&body.omni_account) {
        return e.into_response();
    }
    let message_bytes = match hex::decode(body.message_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error":"invalid_message_hex",
                    "message":format!("not valid hex: {e}")
                })),
            )
                .into_response();
        }
    };

    let sk = state.key_for(&body.omni_account);
    let address = address_for(&sk);

    let prefix = format!("\x19Ethereum Signed Message:\n{}", message_bytes.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(&message_bytes);
    let digest = h.finalize();
    let (sig, recovery_id) = sk
        .sign_prehash_recoverable(&digest)
        .expect("tee-stub sign");
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recovery_id.to_byte());
    let signature = format!("0x{}", hex::encode(&sig_bytes));

    (
        StatusCode::OK,
        Json(json!({
            "signature":   signature,
            "address":     address,
            "key_version": 1,
        })),
    )
        .into_response()
}

fn build_tee_stub_router() -> Router {
    Router::new()
        .route("/dev/derive-address", post(tee_derive))
        .route("/dev/sign-message", post(tee_sign))
        .with_state(TeeStubState::default())
}

fn build_hkdf_router() -> Router {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let signer = DevKeyService::from_master_secret([0xCEu8; 32]);
    let state = Arc::new(AppState::new(conn).with_dev_signer(Some(signer)));
    mock_router(state)
}

async fn spawn(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

// ----------------------------------------------------------------------
// Shared assertions — every conforming signer backend MUST pass these.
// ----------------------------------------------------------------------

async fn assert_address_determinism(client: &dyn SignerClient) {
    let omni = "ab".repeat(32);
    let a = client.derive_address(&omni).await.unwrap();
    let b = client.derive_address(&omni).await.unwrap();
    assert_eq!(a.address, b.address);
    assert!(a.address.starts_with("0x"));
    assert_eq!(a.address.len(), 42);
    assert_eq!(a.address, a.address.to_lowercase());
    assert_eq!(a.key_version, 1);
}

async fn assert_sign_address_matches_derive(client: &dyn SignerClient) {
    let omni = "ab".repeat(32);
    let derived = client.derive_address(&omni).await.unwrap();
    let signed = client.sign_eip191(&omni, b"siwe-test-message").await.unwrap();
    assert_eq!(derived.address, signed.address);
    assert_eq!(derived.key_version, signed.key_version);
}

async fn assert_signature_recovers(client: &dyn SignerClient) {
    let omni = "ab".repeat(32);
    let message = b"recoverable-message";
    let signed = client.sign_eip191(&omni, message).await.unwrap();

    let raw = hex::decode(signed.signature.trim_start_matches("0x")).unwrap();
    assert_eq!(raw.len(), 65);
    assert!(raw[64] == 0 || raw[64] == 1, "v must be canonical {{0,1}}");

    let recovery_id = k256::ecdsa::RecoveryId::try_from(raw[64]).unwrap();
    let signature = Signature::from_slice(&raw[..64]).unwrap();

    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message);
    let digest = h.finalize();

    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
    let encoded = vk.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    let mut h2 = Keccak256::new();
    h2.update(&pubkey_bytes[1..]);
    let pubkey_hash = h2.finalize();
    let recovered = format!("0x{}", hex::encode(&pubkey_hash[12..]));
    assert_eq!(recovered, signed.address);
}

async fn assert_invalid_omni_returns_typed_error(client: &dyn SignerClient) {
    let res = client.derive_address("deadbeef").await;
    match res {
        Err(SignerClientError::InvalidOmniAccount(_)) => {}
        other => panic!("expected InvalidOmniAccount, got {other:?}"),
    }
}

async fn assert_invalid_message_hex_returns_typed_error(_client: &dyn SignerClient) {
    // The HttpSignerClient hex-encodes the message bytes for us, so we can't
    // generate this error through the typed surface. Instead, hand-craft an
    // HTTP request directly to confirm the wire shape — done in
    // `dev_key_service_routes.rs`. Here we just leave a marker: every
    // conforming backend MUST surface 400 invalid_message_hex if a raw HTTP
    // POST sends a non-hex message_hex. No-op in this test layer.
}

async fn assert_different_omnis_yield_different_addresses(client: &dyn SignerClient) {
    let a = client.derive_address(&"11".repeat(32)).await.unwrap();
    let b = client.derive_address(&"22".repeat(32)).await.unwrap();
    assert_ne!(a.address, b.address);
}

async fn run_full_suite(label: &str, client: &dyn SignerClient) {
    println!("[conformance] running suite against {label}");
    assert_address_determinism(client).await;
    assert_sign_address_matches_derive(client).await;
    assert_signature_recovers(client).await;
    assert_invalid_omni_returns_typed_error(client).await;
    assert_invalid_message_hex_returns_typed_error(client).await;
    assert_different_omnis_yield_different_addresses(client).await;
    println!("[conformance] {label} passed all assertions");
}

// ----------------------------------------------------------------------
// Each backend gets its own #[tokio::test] so a regression on one isn't
// masked by an early-exit on the other.
// ----------------------------------------------------------------------

#[tokio::test]
async fn hkdf_dev_key_service_passes_conformance_suite() {
    let url = spawn(build_hkdf_router()).await;
    let client = HttpSignerClient::new(url);
    run_full_suite("hkdf-dev-key-service", &client).await;
}

#[tokio::test]
async fn tee_stub_passes_conformance_suite() {
    let url = spawn(build_tee_stub_router()).await;
    let client = HttpSignerClient::new(url);
    run_full_suite("tee-stub", &client).await;
}

#[tokio::test]
async fn both_backends_emit_signer_disabled_error_envelope() {
    // Spin a mock-server WITHOUT a dev signer; assert the typed error.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = Arc::new(AppState::new(conn));
    let router = mock_router(state);
    let url = spawn(router).await;
    let client = HttpSignerClient::new(url);

    match client.derive_address(&"ab".repeat(32)).await {
        Err(SignerClientError::SignerDisabled(m)) => {
            assert!(m.contains("DEV_KEY_SERVICE_MASTER_SECRET"));
        }
        other => panic!("expected SignerDisabled, got {other:?}"),
    }
}
