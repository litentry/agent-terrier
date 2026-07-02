//! Live **end-to-end VE credential mint** — `#[ignore]`d. The full runtime-port
//! proof (docs/spec/ve-broker-runtime-port.md step 4): sign an ES256 OIDC JWT
//! with the TOS-hosted issuer's private key → `VeStsClient` exchanges it at VE
//! STS (`AssumeRoleWithOIDC`, per-actor inline session policy) → the minted
//! temp creds do a REAL TOS put/get inside `bots/<actor>/…` AND are DENIED
//! outside it (cross-actor isolation).
//!
//! Prereqs: `setup-cloud-ve.sh` steps 50-55 (buckets, issuer, provider, role).
//!
//! Run (from the repo root; sources the VE env + broker csv):
//! ```text
//! set -a; . scripts/operator-workstation.ve.env; set +a
//! AK=…; SK=…   # a VE identity allowed to call sts:AssumeRoleWithOIDC
//! VOLCENGINE_ACCESS_KEY=$AK VOLCENGINE_SECRET_KEY=$SK \
//! VE_OIDC_PRIVATE_KEY="$HOME/.agentkeys-ve/oidc/oidc-es256-private.pem" \
//! cargo test -p agentkeys-broker-server --test ve_sts_live -- --ignored --nocapture
//! ```

use agentkeys_broker_server::sts::StsClient;
use agentkeys_broker_server::ve_sts::VeStsClient;
use aws_sdk_s3::primitives::ByteStream;

fn env(k: &str) -> String {
    std::env::var(k)
        .unwrap_or_else(|_| panic!("{k} must be set (source operator-workstation.ve.env)"))
}

/// Load the issuer's ES256 key (SEC1 or PKCS#8 PEM) → jsonwebtoken EncodingKey.
/// ring (under jsonwebtoken) wants PKCS#8, openssl ecparam emits SEC1 — convert.
fn issuer_encoding_key(path: &str) -> jsonwebtoken::EncodingKey {
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let pem = std::fs::read_to_string(path).expect("read issuer private key");
    let sk = if pem.contains("BEGIN EC PRIVATE KEY") {
        p256::SecretKey::from_sec1_pem(&pem).expect("SEC1 PEM")
    } else {
        p256::SecretKey::from_pkcs8_pem(&pem).expect("PKCS#8 PEM")
    };
    let pkcs8 = sk
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("to pkcs8");
    jsonwebtoken::EncodingKey::from_ec_pem(pkcs8.as_bytes()).expect("EncodingKey")
}

/// TOS client (virtual-hosted) from minted STS creds.
async fn tos_client(
    endpoint: &str,
    region: &str,
    c: &agentkeys_broker_server::sts::AssumedCredentials,
) -> aws_sdk_s3::Client {
    let creds = aws_credential_types::Credentials::new(
        c.access_key_id.clone(),
        c.secret_access_key.clone(),
        Some(c.session_token.clone()),
        None,
        "ve-sts-e2e",
    );
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .credentials_provider(creds)
        .load()
        .await;
    let conf = aws_sdk_s3::config::Builder::from(&cfg)
        .endpoint_url(endpoint.to_string())
        .force_path_style(false) // TOS: virtual-hosted REQUIRED
        .build();
    aws_sdk_s3::Client::from_conf(conf)
}

#[tokio::test]
#[ignore = "live VE e2e: needs phase-2 provisioning + VE creds + the issuer private key"]
async fn mint_then_tos_roundtrip_with_cross_actor_denial() {
    let issuer = env("VE_OIDC_ISSUER");
    let aud = env("VE_OIDC_AUD");
    let role_trn = env("VE_DATA_ROLE_TRN");
    let provider_trn = env("VE_OIDC_PROVIDER_TRN");
    let bucket = env("VE_VAULT_BUCKET");
    let tos_endpoint = env("VE_TOS_S3_ENDPOINT");
    let key_path = env("VE_OIDC_PRIVATE_KEY");
    let region = std::env::var("VOLCENGINE_REGION").unwrap_or_else(|_| "cn-beijing".into());

    // kid MUST match the published JWKS — fetch it from the live issuer so the
    // test can never drift from what setup-cloud-ve.sh step 52 published.
    let jwks: serde_json::Value = reqwest::get(format!("{issuer}/.well-known/jwks.json"))
        .await
        .expect("fetch jwks")
        .json()
        .await
        .expect("jwks json");
    let kid = jwks["keys"][0]["kid"].as_str().expect("kid").to_string();
    println!("issuer kid: {kid}");

    // Sign the OIDC JWT exactly as the broker would (ES256, actor claim).
    let actor_a = "a1".repeat(32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": format!("agentkeys:agent:{actor_a}"),
        "aud": aud,
        "iat": now,
        "exp": now + 600,
        "agentkeys_actor_omni": actor_a,
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid);
    let jwt = jsonwebtoken::encode(&header, &claims, &issuer_encoding_key(&key_path))
        .expect("sign OIDC JWT");

    // Mint via the SHIPPING client (per-actor session policy built inside).
    let sts = VeStsClient::new(
        env("VOLCENGINE_ACCESS_KEY"),
        env("VOLCENGINE_SECRET_KEY"),
        region.clone(),
        agentkeys_broker_server::ve_sts::DEFAULT_STS_HOST,
        provider_trn,
        vec![bucket.clone()],
    )
    .expect("VeStsClient");
    let creds = sts
        .assume_role_with_web_identity(&role_trn, "ve-e2e-probe", &jwt, 900)
        .await
        .expect("AssumeRoleWithOIDC mint should succeed");
    println!(
        "minted: AK {}… expires {}",
        &creds.access_key_id[..8.min(creds.access_key_id.len())],
        creds.expiration_unix
    );

    let s3 = tos_client(&tos_endpoint, &region, &creds).await;

    // ALLOW: put + get inside the minted actor's prefix.
    let own_key = format!("bots/{actor_a}/ve-e2e-probe.txt");
    s3.put_object()
        .bucket(&bucket)
        .key(&own_key)
        .body(ByteStream::from_static(b"ve-mint-e2e-ok"))
        .send()
        .await
        .expect("PUT inside own actor prefix must be ALLOWED");
    let got = s3
        .get_object()
        .bucket(&bucket)
        .key(&own_key)
        .send()
        .await
        .expect("GET inside own actor prefix must be ALLOWED");
    let body = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(&body[..], b"ve-mint-e2e-ok");
    println!("ALLOW ✓ put+get {own_key}");

    // DENY: the same creds must NOT reach another actor's prefix.
    let actor_b = "b2".repeat(32);
    let foreign_key = format!("bots/{actor_b}/ve-e2e-probe.txt");
    let denied = s3
        .put_object()
        .bucket(&bucket)
        .key(&foreign_key)
        .body(ByteStream::from_static(b"cross-actor-write"))
        .send()
        .await;
    match denied {
        Ok(_) => {
            panic!("cross-actor PUT to {foreign_key} SUCCEEDED — session policy is not isolating!")
        }
        Err(e) => {
            let msg = format!("{e:?}");
            println!(
                "DENY ✓ cross-actor put rejected: {}",
                &msg[..msg.len().min(200)]
            );
        }
    }

    // DENY: reading another actor's prefix is refused too.
    let denied_get = s3
        .get_object()
        .bucket(&bucket)
        .key(&foreign_key)
        .send()
        .await;
    assert!(
        denied_get.is_err(),
        "cross-actor GET must be denied (got Ok)"
    );
    println!("DENY ✓ cross-actor get rejected");
    println!("E2E COMPLETE: mint → scoped TOS I/O → cross-actor denial all proven");
}
