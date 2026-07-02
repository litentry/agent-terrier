//! Single-owner S3 client construction that honors an optional S3-compatible
//! endpoint override (`AGENTKEYS_TOS_ENDPOINT`) — the Volcano Engine TOS storage
//! plane (docs/spec/ve-broker-runtime-port.md, the "easy half" of the VE runtime
//! port).
//!
//! When the env var is set (e.g. `https://tos-s3-cn-beijing.volces.com`), every
//! storage-plane S3 client — the core credential backend + the cred / memory /
//! config workers — targets that endpoint with **virtual-hosted-style**
//! addressing (`<bucket>.<host>`). TOS *requires* virtual-hosted for object I/O
//! and rejects path-style with `InvalidPathAccess: Forbidden path to access
//! server` — verified live 2026-07-02 (`tests/tos_live.rs`): `force_path_style
//! =false` did a real PUT+GET roundtrip, `=true` failed. This is the OPPOSITE of
//! MinIO-style stores (no wildcard DNS ⇒ path-style), so we must NOT force
//! path-style. When the var is unset the AWS path is byte-for-byte unchanged
//! (`S3Client::new`), so there is no regression for the AWS deployment.
//!
//! **Why an explicit knob and not the SDK's global `AWS_ENDPOINT_URL_S3`:** the
//! email worker deliberately does NOT route through here — SES + the inbound mail
//! bucket stay on AWS in the hybrid VE deployment. A process-global SDK endpoint
//! would silently redirect that AWS-pinned path too. Keeping the override on an
//! AgentKeys-specific var that only the storage-plane workers consult is the
//! No-silent-override-compliant choice (AGENTS.md): AWS↔TOS selection lives in
//! exactly one function, and the email path can't be caught in the blast radius.

use aws_config::SdkConfig;
use aws_sdk_s3::Client as S3Client;

/// Env var carrying the TOS S3-compatible endpoint, e.g.
/// `https://tos-s3-cn-beijing.volces.com`. Absent or empty ⇒ AWS S3.
pub const TOS_ENDPOINT_ENV: &str = "AGENTKEYS_TOS_ENDPOINT";

/// The configured TOS endpoint, or `None` on AWS. Trimmed; empty ⇒ `None`.
pub fn tos_endpoint_from_env() -> Option<String> {
    std::env::var(TOS_ENDPOINT_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Build a storage-plane S3 client from a loaded [`SdkConfig`], honoring
/// [`TOS_ENDPOINT_ENV`]. This is THE construction point for the
/// credential/memory/config storage plane — call it instead of
/// `S3Client::new(&cfg)` so the AWS↔TOS decision has a single owner.
pub fn s3_client(sdk_config: &SdkConfig) -> S3Client {
    s3_client_with_endpoint(sdk_config, tos_endpoint_from_env().as_deref())
}

/// Endpoint-explicit form (the env-free core, so tests never mutate process env —
/// the #258/#259 parallel-test flake ban). `Some(ep)` ⇒ TOS S3-compatible
/// endpoint + path-style addressing; `None`/blank ⇒ unchanged AWS S3 client.
pub fn s3_client_with_endpoint(sdk_config: &SdkConfig, endpoint: Option<&str>) -> S3Client {
    match normalize_endpoint(endpoint) {
        Some(ep) => {
            // TOS requires virtual-hosted-style (`<bucket>.<host>`) — path-style
            // is rejected with InvalidPathAccess (tests/tos_live.rs). Explicit
            // `false` documents that intent so it isn't "helpfully" set to true.
            let conf = aws_sdk_s3::config::Builder::from(sdk_config)
                .endpoint_url(ep)
                .force_path_style(false)
                .build();
            S3Client::from_conf(conf)
        }
        None => S3Client::new(sdk_config),
    }
}

/// Normalize a raw endpoint: trim, and treat empty/blank as "no override".
/// Pure + borrow-preserving so the AWS↔TOS decision is unit-testable without
/// constructing an SDK client (`aws_sdk_s3::Config` exposes no public
/// endpoint / path-style getter) or reading process env.
fn normalize_endpoint(raw: Option<&str>) -> Option<&str> {
    match raw {
        Some(ep) if !ep.trim().is_empty() => Some(ep.trim()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal SdkConfig built synchronously — no network, no credential chain,
    // no process-env reads (so these tests stay parallel-safe per the env-mutation
    // ban). Carries only what the S3 config builder needs (behavior version +
    // region).
    fn base_cfg() -> SdkConfig {
        aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("cn-beijing"))
            .build()
    }

    // The AWS↔TOS decision itself. `aws_sdk_s3::Config` exposes no public
    // endpoint / path-style getter, so we assert the (pure) decision logic
    // rather than introspecting a constructed client.
    #[test]
    fn none_and_blank_select_aws() {
        assert_eq!(normalize_endpoint(None), None);
        assert_eq!(normalize_endpoint(Some("")), None);
        assert_eq!(normalize_endpoint(Some("   ")), None);
    }

    #[test]
    fn real_endpoint_is_trimmed_and_selected() {
        assert_eq!(
            normalize_endpoint(Some("  https://tos-s3-cn-beijing.volces.com  ")),
            Some("https://tos-s3-cn-beijing.volces.com")
        );
    }

    // Both branches build a client without panicking — exercises the TOS
    // endpoint + path-style builder path and the plain-AWS path.
    #[test]
    fn both_branches_construct() {
        let _tos =
            s3_client_with_endpoint(&base_cfg(), Some("https://tos-s3-cn-beijing.volces.com"));
        let _aws = s3_client_with_endpoint(&base_cfg(), None);
    }
}
