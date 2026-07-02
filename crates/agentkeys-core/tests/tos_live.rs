//! Live Volcano Engine **TOS** integration probe — `#[ignore]`d (needs VE
//! credentials, an opened TOS service, and a pre-created bucket). It resolves
//! the addressing open item in `docs/spec/ve-broker-runtime-port.md`: does TOS
//! object I/O want **path-style** or **virtual-hosted** addressing? aws-cli
//! can't answer it (it forces path-style whenever `--endpoint-url` is set), so
//! we probe through the real `aws-sdk-s3` path our workers use.
//!
//! Run manually:
//! ```text
//! AWS_ACCESS_KEY_ID=…  AWS_SECRET_ACCESS_KEY=…  AWS_DEFAULT_REGION=cn-beijing \
//! AGENTKEYS_TOS_ENDPOINT=https://tos-s3-cn-beijing.volces.com \
//! TOS_TEST_BUCKET=agentterrier-tos-probe-2127642244 \
//! cargo test -p agentkeys-core --test tos_live -- --ignored --nocapture
//! ```
//! Reads (never mutates) process env, so it's outside the #258/#259 ban.

use aws_sdk_s3::primitives::ByteStream;

async fn base_cfg() -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(
            std::env::var("AWS_DEFAULT_REGION").unwrap_or_else(|_| "cn-beijing".into()),
        ))
        .load()
        .await
}

/// One PUT+GET roundtrip with an explicit addressing mode. `force_path_style`
/// true ⇒ `<host>/<bucket>/<key>`; false ⇒ `<bucket>.<host>/<key>`.
async fn put_get(force_path_style: bool) -> anyhow::Result<String> {
    let ep = std::env::var("AGENTKEYS_TOS_ENDPOINT")?;
    let bkt = std::env::var("TOS_TEST_BUCKET")?;
    let conf = aws_sdk_s3::config::Builder::from(&base_cfg().await)
        .endpoint_url(ep)
        .force_path_style(force_path_style)
        .build();
    let client = aws_sdk_s3::Client::from_conf(conf);
    let key = format!(
        "rust-probe-{}.txt",
        if force_path_style { "path" } else { "virtual" }
    );
    client
        .put_object()
        .bucket(&bkt)
        .key(&key)
        .body(ByteStream::from_static(b"rust-tos-seam-ok"))
        .send()
        .await?;
    let out = client.get_object().bucket(&bkt).key(&key).send().await?;
    let data = out.body.collect().await?.into_bytes();
    Ok(String::from_utf8_lossy(&data).to_string())
}

/// The SHIPPING path: build the client via the exact helper the workers call
/// (`s3_endpoint::s3_client`, which reads `AGENTKEYS_TOS_ENDPOINT` and applies
/// the virtual-hosted config). Proves the code we actually ship, not just a
/// hand-built client.
async fn put_get_via_helper() -> anyhow::Result<String> {
    let bkt = std::env::var("TOS_TEST_BUCKET")?;
    let client = agentkeys_core::s3_endpoint::s3_client(&base_cfg().await);
    let key = "rust-probe-helper.txt";
    client
        .put_object()
        .bucket(&bkt)
        .key(key)
        .body(ByteStream::from_static(b"rust-tos-seam-ok"))
        .send()
        .await?;
    let out = client.get_object().bucket(&bkt).key(key).send().await?;
    let data = out.body.collect().await?.into_bytes();
    Ok(String::from_utf8_lossy(&data).to_string())
}

#[tokio::test]
#[ignore = "live TOS: needs VE creds + AGENTKEYS_TOS_ENDPOINT + TOS_TEST_BUCKET"]
async fn tos_addressing_probe() {
    // Diagnostic: which addressing mode does TOS accept? (Documents the finding
    // when run with --nocapture; virtual-hosted works, path-style is rejected.)
    for fps in [false, true] {
        match put_get(fps).await {
            Ok(body) => println!("force_path_style={fps}: OK roundtrip, body={body:?}"),
            Err(e) => println!("force_path_style={fps}: ERR {e:#}"),
        }
    }

    // Assertion: the shipping helper must round-trip against live TOS.
    let via_helper = put_get_via_helper()
        .await
        .expect("s3_endpoint::s3_client helper roundtrip must succeed against TOS");
    assert_eq!(via_helper, "rust-tos-seam-ok");
    println!("s3_endpoint::s3_client helper: OK roundtrip, body={via_helper:?}");
}
