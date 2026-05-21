//! Integration tests for `/dev/derive-address` and `/dev/sign-message`
//! per `docs/spec/signer-protocol.md`.
//!
//! These tests build the router directly (no real TCP) so the env-var seam
//! that gates the dev signer can be controlled per case without touching
//! the process environment.

use agentkeys_mock_server::{
    create_router, create_signer_router, db, dev_key_service::DevKeyService, state::AppState,
};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

// ── JWT helpers for tests ──────────────────────────────────────────────────

/// Generate a fresh P-256 keypair for use in JWT tests.
fn gen_ec_keypair() -> (EncodingKey, DecodingKey) {
    let signing_key = SigningKey::random(&mut p256_rand::OsRngWrapper);
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private key")
        .to_string();
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode public key");
    let enc = EncodingKey::from_ec_pem(private_pem.as_bytes()).expect("enc key");
    let dec = DecodingKey::from_ec_pem(public_pem.as_bytes()).expect("dec key");
    (enc, dec)
}

mod p256_rand {
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
            getrandom::getrandom(dest).expect("OS RNG");
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for OsRngWrapper {}
}

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    exp: u64,
    aud: String,
    agentkeys: AgentKeysClaims,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentKeysClaims {
    omni_account: String,
}

/// Mint a valid JWT for `omni_account` with a TTL of 300s.
fn mint_test_jwt(enc: &EncodingKey, omni_account: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = TestClaims {
        exp: now + 300,
        aud: "agentkeys:broker".to_string(),
        agentkeys: AgentKeysClaims {
            omni_account: omni_account.to_string(),
        },
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("ak-session-test".to_string());
    encode(&header, &claims, enc).expect("encode jwt")
}

/// Mint an expired JWT (exp in the past).
fn mint_expired_jwt(enc: &EncodingKey, omni_account: &str) -> String {
    let claims = TestClaims {
        exp: 1_000_000_001, // 2001 — always in the past
        aud: "agentkeys:broker".to_string(),
        agentkeys: AgentKeysClaims {
            omni_account: omni_account.to_string(),
        },
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("ak-session-test".to_string());
    encode(&header, &claims, enc).expect("encode expired jwt")
}

// ── Router helpers ─────────────────────────────────────────────────────────

fn router_without_signer() -> Router {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let state = Arc::new(AppState::new(conn));
    create_router(state)
}

fn router_with_signer(master_secret: [u8; 32]) -> Router {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let signer = DevKeyService::from_master_secret(master_secret);
    let state = Arc::new(AppState::new(conn).with_dev_signer(Some(signer)));
    create_router(state)
}

/// Build a signer-only router with JWT auth enabled.
fn router_signer_only_with_auth(
    master_secret: [u8; 32],
    dec: DecodingKey,
) -> Router {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init_schema(&conn).unwrap();
    let signer = DevKeyService::from_master_secret(master_secret);
    let state = Arc::new(
        AppState::new(conn)
            .with_dev_signer(Some(signer))
            .with_broker_session_pubkey(Some(dec)),
    );
    create_signer_router(state)
}

async fn post_json(app: Router, path: &str, body: Value) -> (StatusCode, Value) {
    post_json_with_header(app, path, body, None).await
}

async fn post_json_with_header(
    app: Router,
    path: &str,
    body: Value,
    authorization: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(auth) = authorization {
        builder = builder.header("authorization", auth);
    }
    let req = builder
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn fixed_omni() -> String {
    "ab".repeat(32)
}

// ── Original tests (no JWT auth — legacy router) ───────────────────────────

#[tokio::test]
async fn derive_address_returns_503_when_signer_disabled() {
    let app = router_without_signer();
    let (status, body) = post_json(
        app,
        "/dev/derive-address",
        json!({ "omni_account": fixed_omni() }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "signer_disabled");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("DEV_KEY_SERVICE_MASTER_SECRET"));
}

#[tokio::test]
async fn sign_message_returns_503_when_signer_disabled() {
    let app = router_without_signer();
    let (status, body) = post_json(
        app,
        "/dev/sign-message",
        json!({
            "omni_account": fixed_omni(),
            "message_hex":  hex::encode(b"hello"),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "signer_disabled");
}

#[tokio::test]
async fn derive_address_is_deterministic_across_calls() {
    let master = [0x42u8; 32];
    let omni = fixed_omni();

    let (s1, b1) = post_json(
        router_with_signer(master),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    let (s2, b2) = post_json(
        router_with_signer(master),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b1["address"], b2["address"]);
    let addr = b1["address"].as_str().unwrap();
    assert!(addr.starts_with("0x"));
    assert_eq!(addr.len(), 42);
    assert_eq!(addr, addr.to_lowercase());
    assert_eq!(b1["key_version"], 1);
}

#[tokio::test]
async fn derive_address_rejects_short_omni() {
    let app = router_with_signer([0u8; 32]);
    let (status, body) = post_json(
        app,
        "/dev/derive-address",
        json!({ "omni_account": "deadbeef" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_omni_account");
}

#[tokio::test]
async fn sign_message_address_matches_derive_response() {
    let master = [0x33u8; 32];
    let omni = fixed_omni();

    let (s1, derive) = post_json(
        router_with_signer(master),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    let (s2, sign) = post_json(
        router_with_signer(master),
        "/dev/sign-message",
        json!({
            "omni_account": omni,
            "message_hex":  hex::encode(b"siwe-test"),
        }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(derive["address"], sign["address"]);
    assert_eq!(derive["key_version"], sign["key_version"]);
}

#[tokio::test]
async fn sign_message_returns_canonical_65_byte_signature() {
    let app = router_with_signer([0u8; 32]);
    let (status, body) = post_json(
        app,
        "/dev/sign-message",
        json!({
            "omni_account": fixed_omni(),
            "message_hex":  hex::encode(b"hello"),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sig = body["signature"].as_str().unwrap();
    assert!(sig.starts_with("0x"));
    let raw = hex::decode(sig.trim_start_matches("0x")).unwrap();
    assert_eq!(raw.len(), 65);
    let v = raw[64];
    assert!(v == 0 || v == 1, "v byte must be canonical {{0,1}}, got {v}");
}

#[tokio::test]
async fn sign_message_rejects_invalid_message_hex() {
    let app = router_with_signer([0u8; 32]);
    let (status, body) = post_json(
        app,
        "/dev/sign-message",
        json!({
            "omni_account": fixed_omni(),
            "message_hex":  "not-hex-zzz",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_message_hex");
}

#[tokio::test]
async fn different_master_secrets_produce_different_addresses() {
    let omni = fixed_omni();
    let (_, a) = post_json(
        router_with_signer([0x11u8; 32]),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    let (_, b) = post_json(
        router_with_signer([0x22u8; 32]),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    assert_ne!(a["address"], b["address"]);
}

// ── JWT bearer auth tests (signer-only router) ─────────────────────────────

#[tokio::test]
async fn signer_only_missing_jwt_returns_401_unauthorized() {
    let (enc, dec) = gen_ec_keypair();
    let _ = enc; // generated but only dec used here
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let (status, body) = post_json(
        app,
        "/dev/derive-address",
        json!({ "omni_account": fixed_omni() }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
    assert!(body["message"].as_str().unwrap().contains("Authorization"));
}

#[tokio::test]
async fn signer_only_valid_jwt_matching_omni_returns_200() {
    let (enc, dec) = gen_ec_keypair();
    let omni = fixed_omni();
    let jwt = mint_test_jwt(&enc, &omni);
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let (status, body) = post_json_with_header(
        app,
        "/dev/derive-address",
        json!({ "omni_account": omni }),
        Some(&format!("Bearer {jwt}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert!(body["address"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn signer_only_wrong_jwt_returns_401() {
    let (_enc, dec) = gen_ec_keypair();
    let (wrong_enc, _wrong_dec) = gen_ec_keypair();
    let omni = fixed_omni();
    let jwt = mint_test_jwt(&wrong_enc, &omni);
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let (status, body) = post_json_with_header(
        app,
        "/dev/derive-address",
        json!({ "omni_account": omni }),
        Some(&format!("Bearer {jwt}")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
}

#[tokio::test]
async fn signer_only_expired_jwt_returns_401() {
    let (enc, dec) = gen_ec_keypair();
    let omni = fixed_omni();
    let jwt = mint_expired_jwt(&enc, &omni);
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let (status, body) = post_json_with_header(
        app,
        "/dev/derive-address",
        json!({ "omni_account": omni }),
        Some(&format!("Bearer {jwt}")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
}

#[tokio::test]
async fn signer_only_omni_mismatch_returns_401() {
    let (enc, dec) = gen_ec_keypair();
    let omni = fixed_omni();
    let different_omni = "cd".repeat(32);
    let jwt = mint_test_jwt(&enc, &different_omni); // JWT claims different omni
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let (status, body) = post_json_with_header(
        app,
        "/dev/derive-address",
        json!({ "omni_account": omni }), // body uses original omni — mismatch
        Some(&format!("Bearer {jwt}")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("omni_account"));
}

#[tokio::test]
async fn signer_only_valid_jwt_sign_message_returns_200() {
    let (enc, dec) = gen_ec_keypair();
    let omni = fixed_omni();
    let jwt = mint_test_jwt(&enc, &omni);
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let (status, body) = post_json_with_header(
        app,
        "/dev/sign-message",
        json!({
            "omni_account": omni,
            "message_hex":  hex::encode(b"test-message"),
        }),
        Some(&format!("Bearer {jwt}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert!(body["signature"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn signer_only_healthz_needs_no_jwt() {
    let (_enc, dec) = gen_ec_keypair();
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn signer_only_session_endpoint_absent() {
    let (_enc, dec) = gen_ec_keypair();
    let app = router_signer_only_with_auth([0x42u8; 32], dec);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/session/create")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // signer-only router has no /session route → 404
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── /dev/sign-typed-data tests (issue #82) ────────────────────────────────

fn usdc_permit_typed_data(value: &str) -> Value {
    json!({
        "domain": {
            "name": "USD Coin",
            "version": "2",
            "chainId": 1,
            "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        },
        "types": {
            "EIP712Domain": [
                { "name": "name",              "type": "string"  },
                { "name": "version",           "type": "string"  },
                { "name": "chainId",           "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [
                { "name": "owner",    "type": "address" },
                { "name": "spender",  "type": "address" },
                { "name": "value",    "type": "uint256" },
                { "name": "nonce",    "type": "uint256" },
                { "name": "deadline", "type": "uint256" }
            ]
        },
        "primaryType": "Permit",
        "message": {
            "owner":   "0x1111111111111111111111111111111111111111",
            "spender": "0xaaaabbbbccccddddeeeeffff0000111122223333",
            "value":   value,
            "nonce":   "0",
            "deadline": "1900000000"
        }
    })
}

#[tokio::test]
async fn sign_typed_data_returns_signature_address_digests() {
    let master = [0x44u8; 32];
    let omni = fixed_omni();

    let (status, body) = post_json(
        router_with_signer(master),
        "/dev/sign-typed-data",
        json!({
            "omni_account": omni,
            "typed_data": usdc_permit_typed_data("1500000"),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let sig = body["signature"].as_str().unwrap();
    assert!(sig.starts_with("0x"));
    assert_eq!(sig.len(), 2 + 130, "signature must be 65 bytes hex");

    let address = body["address"].as_str().unwrap();
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);

    for k in ["primary_type_hash", "domain_separator", "digest"] {
        let h = body[k].as_str().unwrap_or_else(|| panic!("missing {k}"));
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 2 + 64, "{k} must be 32 bytes hex");
    }
    assert_eq!(body["key_version"], 1);
}

#[tokio::test]
async fn sign_typed_data_address_matches_derive_response() {
    let master = [0x44u8; 32];
    let omni = fixed_omni();

    let (s1, derive) = post_json(
        router_with_signer(master),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    let (s2, sign) = post_json(
        router_with_signer(master),
        "/dev/sign-typed-data",
        json!({
            "omni_account": omni,
            "typed_data": usdc_permit_typed_data("1500000"),
        }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(derive["address"], sign["address"]);
}

#[tokio::test]
async fn sign_typed_data_rejects_unknown_primary_type() {
    let master = [0u8; 32];
    let mut td = usdc_permit_typed_data("1500000");
    td["primaryType"] = json!("NoSuchType");
    let (status, body) = post_json(
        router_with_signer(master),
        "/dev/sign-typed-data",
        json!({
            "omni_account": fixed_omni(),
            "typed_data":   td,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_typed_data");
}

#[tokio::test]
async fn sign_typed_data_rejects_out_of_range_uint() {
    let master = [0u8; 32];
    let mut td = usdc_permit_typed_data("1500000");
    // Change `value` field to `uint8` so the actual value (1_500_000) overflows.
    td["types"]["Permit"][2]["type"] = json!("uint8");
    let (status, body) = post_json(
        router_with_signer(master),
        "/dev/sign-typed-data",
        json!({
            "omni_account": fixed_omni(),
            "typed_data":   td,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_typed_data");
}

#[tokio::test]
async fn sign_typed_data_returns_503_when_signer_disabled() {
    let app = router_without_signer();
    let (status, body) = post_json(
        app,
        "/dev/sign-typed-data",
        json!({
            "omni_account": fixed_omni(),
            "typed_data":   usdc_permit_typed_data("1500000"),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "signer_disabled");
}

#[tokio::test]
async fn sign_typed_data_recovers_to_derived_address() {
    use sha3::{Digest, Keccak256};

    let master = [0x55u8; 32];
    let omni = fixed_omni();

    let (_, derive) = post_json(
        router_with_signer(master),
        "/dev/derive-address",
        json!({ "omni_account": omni }),
    )
    .await;
    let derived = derive["address"].as_str().unwrap().to_string();

    let (status, sign) = post_json(
        router_with_signer(master),
        "/dev/sign-typed-data",
        json!({
            "omni_account": omni,
            "typed_data":   usdc_permit_typed_data("42"),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Recover the signing public key from the signature + digest the signer
    // emitted, and assert it derives to the same address.
    let sig_bytes =
        hex::decode(sign["signature"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let digest_bytes =
        hex::decode(sign["digest"].as_str().unwrap().trim_start_matches("0x")).unwrap();

    let recovery_id = k256::ecdsa::RecoveryId::try_from(sig_bytes[64]).unwrap();
    let signature = k256::ecdsa::Signature::from_slice(&sig_bytes[..64]).unwrap();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&digest_bytes);
    let vk =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();

    let encoded_point = vk.to_encoded_point(false);
    let pubkey_bytes = encoded_point.as_bytes();
    let mut h = Keccak256::new();
    h.update(&pubkey_bytes[1..]);
    let pubkey_hash = h.finalize();
    let recovered = format!("0x{}", hex::encode(&pubkey_hash[12..]));

    assert_eq!(recovered, derived);
}
