//! End-to-end tests for the broker's OIDC issuer surface (Stage 7 phase 2):
//!   discovery doc, JWKS, and bearer-token-gated JWT mint.
//!
//! Mirrors the recipe operators run before `aws iam create-open-id-connect-provider`:
//!   1. fetch discovery → confirm issuer + jwks_uri
//!   2. fetch JWKS → confirm ES256 P-256 public key + kid
//!   3. mint a JWT for a real session → verify ES256 signature with the JWKS

use agentkeys_broker_server::storage::{GrantStore, IdentityLinkStore};
use std::path::PathBuf;
use std::sync::Arc;

use agentkeys_broker_server::audit::AuditLog;
use agentkeys_broker_server::config::BrokerConfig;
use agentkeys_broker_server::create_router;
use agentkeys_broker_server::identity::derive_omni_account;
use agentkeys_broker_server::jwt::issue::mint_session_jwt;
use agentkeys_broker_server::oidc::OidcKeypair;
use agentkeys_broker_server::state::AppState;
use agentkeys_broker_server::sts::{AssumedCredentials, StsClient, StubStsClient};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tempfile::TempDir;

const STUB_ROLE_ARN: &str = "arn:aws:iam::000000000000:role/agentkeys-data-role";
const TEST_ISSUER: &str = "https://oidc.test.invalid";

fn stub_creds() -> AssumedCredentials {
    AssumedCredentials {
        access_key_id: "ASIA-stub-AKID".into(),
        secret_access_key: "stub-secret".into(),
        session_token: "stub-session-token".into(),
        expiration_unix: 9_999_999_999,
    }
}

async fn spawn_broker() -> (String, Arc<AppState>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let keypair_path = tmp.path().join("oidc-keypair.json");
    let oidc = OidcKeypair::generate_and_persist(&keypair_path).unwrap();

    let sts: Arc<dyn StsClient> = Arc::new(StubStsClient::ok(stub_creds()));
    let config = BrokerConfig {
        data_role_arn: STUB_ROLE_ARN.into(),
        memory_role_arn: String::new(),
        audit_db_path: PathBuf::from(":memory:"),
        aws_region: "us-east-1".into(),
        session_duration_seconds: 3600,
        shutdown_grace_seconds: 5,
        oidc_issuer: TEST_ISSUER.into(),
        oidc_keypair_path: keypair_path,
        oidc_jwt_ttl_seconds: 300,
        dev_mode: false,
        auth_methods: "wallet_sig".into(),
        audit_anchors: "sqlite".into(),
        refuse_to_boot_strict: false,
    };

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    // Stage 7 stubs — these legacy integration tests pre-date the new
    // pluggable layer and don't exercise it. Construct the minimal valid
    // AppState by stubbing in-memory stores + a generated session keypair.
    let session_keypair = {
        let path = tmp.path().join("session-keypair.json");
        agentkeys_broker_server::jwt::SessionKeypair::generate_and_persist(&path).unwrap()
    };
    let nonce_store = std::sync::Arc::new(
        agentkeys_broker_server::storage::AuthNonceStore::open_in_memory().unwrap(),
    );
    let wallet_store = std::sync::Arc::new(
        agentkeys_broker_server::storage::WalletStore::open_in_memory().unwrap(),
    );
    let sqlite_anchor: std::sync::Arc<dyn agentkeys_broker_server::plugins::audit::AuditAnchor> =
        std::sync::Arc::new(
            agentkeys_broker_server::plugins::audit::sqlite::SqliteAnchor::open_in_memory()
                .unwrap(),
        );
    let registry = std::sync::Arc::new(agentkeys_broker_server::plugins::PluginRegistry {
        auth: std::collections::HashMap::new(),
        wallet: std::sync::Arc::new(
            agentkeys_broker_server::plugins::wallet::keystore::ClientSideKeystoreProvisioner::new(
                std::sync::Arc::clone(&wallet_store),
            ),
        ),
        audit: vec![sqlite_anchor],
    });
    let state = Arc::new(AppState {
        config,
        http,
        audit: AuditLog::open_in_memory().unwrap(),
        sts,
        oidc: Arc::new(oidc),
        session_keypair: std::sync::Arc::new(session_keypair),
        registry,
        audit_policy: agentkeys_broker_server::plugins::audit::AuditPolicy::SqlitePrimary,
        wallet_store,
        nonce_store,
        grant_store: Arc::new(GrantStore::open_in_memory().unwrap()),
        identity_link_store: Arc::new(IdentityLinkStore::open_in_memory().unwrap()),
        pairing_request_store: Arc::new(
            agentkeys_broker_server::storage::PairingRequestStore::open_in_memory().unwrap(),
        ),
        agent_delegation_store: Arc::new(
            agentkeys_broker_server::storage::AgentDelegationStore::open_in_memory().unwrap(),
        ),
        sandbox: None,
        pending_ceremonies: Arc::new(
            agentkeys_broker_server::handlers::spawn::PendingCeremonyStore::new(),
        ),
        metrics: Arc::new(agentkeys_broker_server::metrics::Metrics::new()),
        tier2: std::sync::Arc::new(agentkeys_broker_server::state::Tier2State::default()),
        #[cfg(feature = "auth-email-link")]
        email_link: None,
        #[cfg(feature = "auth-oauth2")]
        oauth2: None,
    });
    let app = create_router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{}", addr), state)
}

#[tokio::test]
async fn discovery_returns_aws_compatible_shape() {
    let (broker_url, _) = spawn_broker().await;

    let resp: Value = reqwest::Client::new()
        .get(format!("{}/.well-known/openid-configuration", broker_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["issuer"], TEST_ISSUER);
    assert_eq!(
        resp["jwks_uri"],
        format!("{}/.well-known/jwks.json", TEST_ISSUER)
    );
    assert_eq!(resp["id_token_signing_alg_values_supported"][0], "ES256");
    assert_eq!(resp["subject_types_supported"][0], "public");
    assert_eq!(resp["token_endpoint_auth_methods_supported"][0], "none");

    let claims = resp["claims_supported"]
        .as_array()
        .expect("claims_supported must be an array");
    let names: Vec<&str> = claims.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"agentkeys_user_wallet"));
    assert!(
        names.contains(&"https://aws.amazon.com/tags"),
        "discovery doc must advertise the AWS tags claim so AWS IAM expects it"
    );
    assert!(names.contains(&"sub"));
    assert!(names.contains(&"exp"));
}

#[tokio::test]
async fn jwks_returns_p256_es256_with_kid() {
    let (broker_url, state) = spawn_broker().await;

    let resp: Value = reqwest::Client::new()
        .get(format!("{}/.well-known/jwks.json", broker_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let key = &resp["keys"][0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert_eq!(key["alg"], "ES256");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["kid"], state.oidc.kid);
    assert_eq!(key["x"], state.oidc.public_x_b64);
    assert_eq!(key["y"], state.oidc.public_y_b64);
}

#[tokio::test]
async fn mint_oidc_jwt_signs_claims_for_session_wallet() {
    let (broker_url, state) = spawn_broker().await;

    // Mint a session JWT against the broker's own session keypair — the
    // same path the SIWE wallet/email/oauth2 verify handlers take. Replaces
    // the legacy `mint_session_against_backend` flow now that
    // /v1/mint-oidc-jwt verifies session JWTs locally instead of round-
    // tripping to /session/validate.
    let wallet = "0xabcdef0123456789abcdef0123456789abcdef01".to_string();
    let omni = derive_omni_account("evm", &wallet);
    let session_token = mint_session_jwt(
        &state.session_keypair,
        TEST_ISSUER,
        omni.as_str(),
        &wallet,
        "evm",
        &wallet,
        300,
    )
    .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/mint-oidc-jwt", broker_url))
        .header("Authorization", format!("Bearer {}", session_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let jwt = body["jwt"].as_str().expect("jwt must be a string");
    assert_eq!(body["wallet"], wallet);
    let exp = body["expiration"].as_i64().unwrap();
    assert!(exp > chrono_utc_now() - 5 && exp < chrono_utc_now() + 600);

    let header = decode_header(jwt).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some(state.oidc.kid.as_str()));

    let decoding_key =
        DecodingKey::from_ec_components(&state.oidc.public_x_b64, &state.oidc.public_y_b64)
            .unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["sts.amazonaws.com"]);
    validation.set_issuer(&[TEST_ISSUER]);

    let token_data: jsonwebtoken::TokenData<Value> =
        decode(jwt, &decoding_key, &validation).expect("public-key verify");
    assert_eq!(token_data.claims["agentkeys_user_wallet"], wallet);
    assert_eq!(
        token_data.claims["sub"],
        format!("agentkeys:agent:{}", wallet)
    );
    assert_eq!(token_data.claims["aud"], "sts.amazonaws.com");
    assert_eq!(token_data.claims["iss"], TEST_ISSUER);

    // Regression guard for the silent-Stage-7-isolation-failure bug: AWS STS
    // populates session tags ONLY from this magic-named claim, never from
    // arbitrary top-level claims. Without it, `${aws:PrincipalTag/...}` in
    // bucket policies expands to empty and tenant isolation is inert.
    let aws_tags = &token_data.claims["https://aws.amazon.com/tags"];
    assert_eq!(
        aws_tags["principal_tags"]["agentkeys_user_wallet"][0], wallet,
        "JWT must carry agentkeys_user_wallet as a principal_tag for STS to set the session tag"
    );
    assert_eq!(
        aws_tags["transitive_tag_keys"][0], "agentkeys_user_wallet",
        "agentkeys_user_wallet must be transitive so it survives role chaining"
    );

    let row = state.audit.last_row().unwrap().expect("audit row missing");
    assert_eq!(row.outcome, "ok");
    assert_eq!(row.requester_wallet, wallet);
    assert_eq!(row.requested_role, "oidc_jwt");
}

#[tokio::test]
async fn mint_oidc_jwt_rejects_missing_bearer() {
    let (broker_url, _) = spawn_broker().await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/mint-oidc-jwt", broker_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mint_oidc_jwt_rejects_invalid_bearer_and_audits_auth_failed() {
    let (broker_url, state) = spawn_broker().await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/mint-oidc-jwt", broker_url))
        .header("Authorization", "Bearer never-minted")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let row = state.audit.last_row().unwrap().expect("audit row missing");
    assert_eq!(row.outcome, "auth_failed");
    assert_eq!(row.requested_role, "oidc_jwt");
}

#[tokio::test]
async fn keypair_persists_across_broker_restarts() {
    // Two brokers pointed at the same on-disk keypair must serve the same
    // JWKS — otherwise an AWS OIDC provider registered against the first
    // broker breaks every restart, which would be unusable in production.
    let tmp = TempDir::new().unwrap();
    let keypair_path = tmp.path().join("oidc-keypair.json");
    let kp1 = OidcKeypair::generate_and_persist(&keypair_path).unwrap();
    let kp2 = OidcKeypair::load(&keypair_path).unwrap();
    assert_eq!(kp1.kid, kp2.kid);
    assert_eq!(kp1.public_x_b64, kp2.public_x_b64);
    assert_eq!(kp1.public_y_b64, kp2.public_y_b64);
}

fn chrono_utc_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
