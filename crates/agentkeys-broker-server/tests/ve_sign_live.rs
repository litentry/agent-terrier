//! Live **Volcengine Signature V4 conformance** — `#[ignore]`d. Signs a real
//! `sts:GetCallerIdentity` with `ve_sign` and asserts VE's own server accepts
//! the signature (HTTP 200 + our AccountId). This is the authoritative
//! correctness check for the signer: a valid signature is, by definition, one
//! the VE server validates — stronger than a hand-rolled fixture (same posture
//! as the TOS live proof).
//!
//! Run:
//! ```text
//! VOLCENGINE_ACCESS_KEY=…  VOLCENGINE_SECRET_KEY=…  [VOLCENGINE_REGION=cn-beijing] \
//! cargo test -p agentkeys-broker-server --test ve_sign_live -- --ignored --nocapture
//! ```

use agentkeys_broker_server::ve_sign::{self, VeSignRequest, DEFAULT_CONTENT_TYPE};

#[tokio::test]
#[ignore = "live VE: needs VOLCENGINE_ACCESS_KEY / VOLCENGINE_SECRET_KEY"]
async fn get_caller_identity_signature_accepted() {
    let ak = std::env::var("VOLCENGINE_ACCESS_KEY").expect("VOLCENGINE_ACCESS_KEY");
    let sk = std::env::var("VOLCENGINE_SECRET_KEY").expect("VOLCENGINE_SECRET_KEY");
    let region = std::env::var("VOLCENGINE_REGION").unwrap_or_else(|_| "cn-beijing".to_string());
    let host = "open.volcengineapi.com";

    // Action + Version live in the query; GetCallerIdentity has no params + no body.
    let query =
        ve_sign::canonical_query(&[("Action", "GetCallerIdentity"), ("Version", "2018-01-01")]);
    let x_date = ve_sign::now_x_date();

    let signed = ve_sign::sign(&VeSignRequest {
        access_key_id: &ak,
        secret_access_key: &sk,
        session_token: None,
        region: &region,
        service: "sts",
        host,
        method: "GET",
        path: "/",
        query: &query,
        body: b"",
        content_type: DEFAULT_CONTENT_TYPE,
        x_date: &x_date,
    });

    // Send exactly the query that was signed (verbatim, no re-encoding). reqwest
    // derives the Host header from the URL, matching the signed value.
    let url = format!("https://{host}/?{query}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Content-Type", &signed.content_type)
        .header("X-Date", &signed.x_date)
        .header("X-Content-Sha256", &signed.x_content_sha256)
        .header("Authorization", &signed.authorization)
        .send()
        .await
        .expect("request send failed");

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    println!("status={status}\nbody={body}");

    assert!(
        status.is_success(),
        "VE rejected the Signature V4: HTTP {status} — {body}"
    );
    assert!(
        body.contains("AccountId"),
        "200 but no AccountId in response: {body}"
    );
}

#[tokio::test]
#[ignore = "live VE: needs VOLCENGINE_ACCESS_KEY / VOLCENGINE_SECRET_KEY"]
async fn assume_role_with_oidc_signed_request_passes_gateway_auth() {
    // VE's OpenAPI gateway authenticates EVERY request by signature (unlike AWS,
    // whose AssumeRoleWithWebIdentity is anonymous). We can't complete a real
    // token exchange without a registered OIDC provider + a trusting role
    // (Phase-2), but a correctly SIGNED AssumeRoleWithOIDC must get PAST the
    // gateway's signature check and fail on the dummy token/role instead of
    // `InvalidCredential` — proving POST-with-body signing for the real mint
    // action. (Anonymous, unsigned → `InvalidCredential`, verified separately.)
    let ak = std::env::var("VOLCENGINE_ACCESS_KEY").expect("VOLCENGINE_ACCESS_KEY");
    let sk = std::env::var("VOLCENGINE_SECRET_KEY").expect("VOLCENGINE_SECRET_KEY");
    let region = std::env::var("VOLCENGINE_REGION").unwrap_or_else(|_| "cn-beijing".to_string());
    // AssumeRoleWithOIDC is routed by the DEDICATED STS endpoint, not the
    // universal open.volcengineapi.com gateway (which 404s InvalidActionOrVersion).
    let host = "sts.volcengineapi.com";

    let query =
        ve_sign::canonical_query(&[("Action", "AssumeRoleWithOIDC"), ("Version", "2018-01-01")]);
    // Params (incl. the long OIDC JWT) go in the form body, not the query.
    let body = ve_sign::form_encode(&[
        ("RoleTrn", "trn:iam::2127642244:role/dummy-nonexistent"),
        ("RoleSessionName", "ve-sign-probe"),
        ("OIDCProviderTrn", "trn:iam::2127642244:oidc-provider/dummy"),
        ("OIDCToken", "dummy.jwt.token"),
        ("DurationSeconds", "900"),
    ]);
    let x_date = ve_sign::now_x_date();

    let signed = ve_sign::sign(&VeSignRequest {
        access_key_id: &ak,
        secret_access_key: &sk,
        session_token: None,
        region: &region,
        service: "sts",
        host,
        method: "POST",
        path: "/",
        query: &query,
        body: body.as_bytes(),
        content_type: DEFAULT_CONTENT_TYPE,
        x_date: &x_date,
    });

    let url = format!("https://{host}/?{query}");
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Content-Type", &signed.content_type)
        .header("X-Date", &signed.x_date)
        .header("X-Content-Sha256", &signed.x_content_sha256)
        .header("Authorization", &signed.authorization)
        .body(body.clone())
        .send()
        .await
        .expect("request send failed");
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    println!("status={status}\nbody={text}");

    // 1) Signature accepted by the gateway (no InvalidCredential).
    assert!(
        !text.contains("InvalidCredential"),
        "VE rejected our SIGNED AssumeRoleWithOIDC at the gateway (signing bug): {text}"
    );
    // 2) Endpoint + Action + Version correct — no InvalidActionOrVersion (this is
    //    why the probe targets sts.volcengineapi.com, not the open gateway).
    assert!(
        !text.contains("InvalidActionOrVersion"),
        "wrong endpoint/action/version for AssumeRoleWithOIDC: {text}"
    );
    // 3) Params parsed → VE reached OIDC-token validation and rejected the DUMMY
    //    token. A real mint needs a broker-issued token + a registered OIDC
    //    provider + trusting role (Phase-2). This confirms the whole request
    //    contract short of the token exchange itself.
    assert!(
        text.contains("InvalidOIDCToken"),
        "expected InvalidOIDCToken (params parsed + token validation reached), got: {text}"
    );
}
