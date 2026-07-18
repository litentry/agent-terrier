//! Volcengine **Signature V4** — a faithful port of the authoritative signer in
//! `volcengine/volc-sdk-golang` `base/sign.go`. Used by the VE STS client
//! (`AssumeRoleWithOIDC`) for the Volcano Engine broker mirror
//! (docs/spec/ve-broker-runtime-port.md, the "hard half").
//!
//! It is AWS-SigV4-*shaped* but **not** AWS-compatible — three deliberate
//! differences the port must preserve, or requests fail opaquely:
//!   1. **Key derivation has NO `"AWS4"` prefix**: `kDate = HMAC(secret, date)`
//!      directly (AWS uses `HMAC("AWS4"+secret, date)`).
//!   2. **Header names**: `X-Date` (not `X-Amz-Date`), `X-Content-Sha256` (not
//!      `X-Amz-Content-Sha256`), `X-Security-Token` for the session token.
//!   3. **Signed-header allowlist**: `content-type`, `host`, `x-content-sha256`,
//!      `x-date`, and `x-security-token` when present — lowercased + sorted.
//!
//! `sign()` is pure (the timestamp is injected) so it unit-tests without a clock
//! or network; `now_x_date()` is the production clock. Correctness is pinned by
//! a live conformance test against `sts:GetCallerIdentity` (`tests/ve_sign_live.rs`)
//! — the same "let the real server validate the signature" approach the TOS seam
//! used, which beats a hand-rolled fixture.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The default Content-Type `sign.go` sets (and signs) when none is provided.
pub const DEFAULT_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// Everything needed to sign one Volcengine OpenAPI request.
pub struct VeSignRequest<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    /// STS session token (for creds minted by AssumeRole*); `None` for static keys.
    pub session_token: Option<&'a str>,
    pub region: &'a str,  // e.g. "cn-beijing"
    pub service: &'a str, // e.g. "sts"
    pub host: &'a str,    // e.g. "open.volcengineapi.com"
    pub method: &'a str,  // "GET" | "POST"
    pub path: &'a str,    // usually "/"
    /// Canonical query string, already sorted + percent-encoded (e.g.
    /// `"Action=GetCallerIdentity&Version=2018-01-01"`). Build with
    /// [`canonical_query`].
    pub query: &'a str,
    /// Raw request body bytes (hashed as-is). Empty for parameterless GETs.
    pub body: &'a [u8],
    pub content_type: &'a str,
    /// Timestamp `YYYYMMDDTHHMMSSZ` (UTC). Injected for testability; production
    /// callers pass [`now_x_date`].
    pub x_date: &'a str,
}

/// Headers to set on the outgoing request. `host`/`content_type` are echoed so
/// the caller sets exactly the values that were signed.
pub struct VeSignedHeaders {
    pub authorization: String,
    pub x_date: String,
    pub x_content_sha256: String,
    pub host: String,
    pub content_type: String,
    pub x_security_token: Option<String>,
}

fn hmac_sha256(key: &[u8], msg: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// `sign.go` strips a default :80/:443 from the signed Host value.
fn strip_default_port(host: &str) -> String {
    if let Some((h, port)) = host.rsplit_once(':') {
        if port == "80" || port == "443" {
            return h.to_string();
        }
    }
    host.to_string()
}

/// Percent-encode one path segment per `sign.go` `encodePathFrag`/`shouldEscape`
/// (RFC 3986 unreserved `A-Za-z0-9-_.~` pass through; everything else `%XX`,
/// uppercase hex).
fn encode_path_frag(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

fn norm_uri(path: &str) -> String {
    path.split('/')
        .map(encode_path_frag)
        .collect::<Vec<_>>()
        .join("/")
}

/// Build a canonical query string from key/value pairs — sorted by key, each
/// key and value percent-encoded (RFC 3986, space→`%20`), joined by `&`. Matches
/// Go's `url.Values.Encode()` + the `+`→`%20` fix in `normquery`.
pub fn canonical_query(pairs: &[(&str, &str)]) -> String {
    let mut kv: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (encode_path_frag(k), encode_path_frag(v)))
        .collect();
    kv.sort();
    kv.into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `application/x-www-form-urlencoded` body from key/value pairs (percent-encoded,
/// space→`%20`). Used for `AssumeRoleWithOIDC` params (the long OIDC JWT goes in
/// the body, not the query). The exact bytes returned are what gets hashed +
/// sent, so encoding just needs to be self-consistent.
pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode_path_frag(k), encode_path_frag(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Current UTC timestamp in the `YYYYMMDDTHHMMSSZ` form VE expects.
pub fn now_x_date() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Produce the signed headers for `req` (Volcengine Signature V4).
pub fn sign(req: &VeSignRequest) -> VeSignedHeaders {
    let body_hash = sha256_hex(req.body);
    let date = &req.x_date[..8]; // YYYYMMDD
    let credential_scope = format!("{}/{}/{}/request", date, req.region, req.service);
    let host_value = strip_default_port(req.host);

    // Signed headers: the sign.go allowlist, lowercased + sorted.
    let mut headers: Vec<(&str, String)> = vec![
        ("content-type", req.content_type.trim().to_string()),
        ("host", host_value.clone()),
        ("x-content-sha256", body_hash.clone()),
        ("x-date", req.x_date.to_string()),
    ];
    if let Some(tok) = req.session_token {
        headers.push(("x-security-token", tok.to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let signed_headers = headers
        .iter()
        .map(|(k, _)| *k)
        .collect::<Vec<_>>()
        .join(";");
    // Each canonical header line ends with '\n'; the block is then followed by a
    // blank line before SignedHeaders (matches concat("\n", …, canonicalHeaders,
    // signedHeaders, …) where canonicalHeaders already carries a trailing '\n').
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        norm_uri(req.path),
        req.query,
        canonical_headers,
        signed_headers,
        body_hash
    );
    let hashed_canonical = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "HMAC-SHA256\n{}\n{}\n{}",
        req.x_date, credential_scope, hashed_canonical
    );

    // Signing key chain — NO "AWS4" prefix (the VE difference).
    let k_date = hmac_sha256(req.secret_access_key.as_bytes(), date);
    let k_region = hmac_sha256(&k_date, req.region);
    let k_service = hmac_sha256(&k_region, req.service);
    let k_signing = hmac_sha256(&k_service, "request");
    let signature = hex::encode(hmac_sha256(&k_signing, &string_to_sign));

    let authorization = format!(
        "HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        req.access_key_id, credential_scope, signed_headers, signature
    );

    VeSignedHeaders {
        authorization,
        x_date: req.x_date.to_string(),
        x_content_sha256: body_hash,
        host: host_value,
        content_type: req.content_type.to_string(),
        x_security_token: req.session_token.map(|s| s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_req<'a>(x_date: &'a str) -> VeSignRequest<'a> {
        VeSignRequest {
            access_key_id: "AKLTtestexampleaccesskey",
            secret_access_key: "c2VjcmV0LWtleS1leGFtcGxl",
            session_token: None,
            region: "cn-beijing",
            service: "sts",
            host: "open.volcengineapi.com",
            method: "GET",
            path: "/",
            query: "Action=GetCallerIdentity&Version=2018-01-01",
            body: b"",
            content_type: DEFAULT_CONTENT_TYPE,
            x_date,
        }
    }

    #[test]
    fn credential_scope_and_auth_shape() {
        let h = sign(&fixed_req("20260702T010203Z"));
        assert!(h.authorization.starts_with(
            "HMAC-SHA256 Credential=AKLTtestexampleaccesskey/20260702/cn-beijing/sts/request, "
        ));
        assert!(h
            .authorization
            .contains("SignedHeaders=content-type;host;x-content-sha256;x-date, "));
        assert!(h.authorization.contains(", Signature="));
        // empty-body hash is the well-known SHA-256 of "".
        assert_eq!(
            h.x_content_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn signing_is_deterministic_for_fixed_inputs() {
        let a = sign(&fixed_req("20260702T010203Z"));
        let b = sign(&fixed_req("20260702T010203Z"));
        assert_eq!(a.authorization, b.authorization);
    }

    #[test]
    fn signature_changes_with_timestamp() {
        let a = sign(&fixed_req("20260702T010203Z"));
        let b = sign(&fixed_req("20260702T010204Z"));
        assert_ne!(a.authorization, b.authorization);
    }

    #[test]
    fn session_token_adds_signed_header() {
        let mut r = fixed_req("20260702T010203Z");
        r.session_token = Some("sts-session-token");
        let h = sign(&r);
        assert!(h.authorization.contains(
            "SignedHeaders=content-type;host;x-content-sha256;x-date;x-security-token, "
        ));
        assert_eq!(h.x_security_token.as_deref(), Some("sts-session-token"));
    }

    #[test]
    fn canonical_query_sorts_and_encodes() {
        assert_eq!(
            canonical_query(&[("Version", "2018-01-01"), ("Action", "GetCallerIdentity")]),
            "Action=GetCallerIdentity&Version=2018-01-01"
        );
        // ':' and '/' in a TRN are percent-encoded (RFC 3986).
        assert_eq!(
            canonical_query(&[("RoleTrn", "trn:iam::123:role/r")]),
            "RoleTrn=trn%3Aiam%3A%3A123%3Arole%2Fr"
        );
    }

    #[test]
    fn norm_uri_keeps_root() {
        assert_eq!(norm_uri("/"), "/");
    }
}
