//! Volcano Engine STS client — `AssumeRoleWithOIDC` on the proven
//! [`ve_sign`](crate::ve_sign) Signature V4 signer (docs/spec/ve-broker-runtime-port.md).
//!
//! ## Topology difference vs AWS (why this runs IN the broker)
//!
//! AWS `AssumeRoleWithWebIdentity` is **anonymous** — clients exchange the
//! broker-issued OIDC JWT with AWS STS directly, and the broker holds zero
//! cloud credentials. VE's OpenAPI gateway authenticates **every** request by
//! signature (verified live: unsigned → `InvalidCredential`), so on VE the
//! exchange must happen **broker-side**, signed with the broker's own VE
//! identity (least-privilege, `sts:AssumeRoleWithOIDC`-only — issue #372).
//!
//! ## Isolation fork: per-actor inline session `Policy`
//!
//! AWS scopes each minted session via PrincipalTags read from the JWT's
//! `https://aws.amazon.com/tags` claim; VE has no tag-from-token mechanism.
//! Instead, every VE mint attaches an inline session policy that scopes the
//! role's permissions DOWN to the requesting actor's `bots/<actor_omni>/*`
//! prefix on the configured TOS buckets. The `agentkeys_actor_omni` claim is
//! read from the SAME token VE validates against the issuer's JWKS — a forged
//! claim fails the exchange entirely, and a replayed valid token can only
//! scope to its own prefix.
//!
//! Per the no-silent-fallback policy, a mint with no derivable actor or no
//! configured buckets is a HARD ERROR — this client never mints unscoped
//! credentials.

use async_trait::async_trait;
use base64::Engine as _;

use crate::error::{BrokerError, BrokerResult};
use crate::sts::{AssumedCredentials, StsClient};
use crate::ve_sign::{self, VeSignRequest, DEFAULT_CONTENT_TYPE};

/// STS API constants confirmed live (tests/ve_sign_live.rs): the DEDICATED STS
/// host routes `AssumeRoleWithOIDC`; the universal `open.volcengineapi.com`
/// gateway 404s it with `InvalidActionOrVersion`.
pub const DEFAULT_STS_HOST: &str = "sts.volcengineapi.com";
pub const STS_VERSION: &str = "2018-01-01";

pub struct VeStsClient {
    http: reqwest::Client,
    access_key_id: String,
    secret_access_key: String,
    region: String,
    host: String,
    /// `trn:iam::<account>:oidc-provider/<name>` — the registered provider the
    /// broker's issuer maps to.
    oidc_provider_trn: String,
    /// TOS buckets the per-actor session policy scopes down to (vault/memory/
    /// config). MUST be non-empty — see module docs.
    tos_buckets: Vec<String>,
}

impl VeStsClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
        host: impl Into<String>,
        oidc_provider_trn: impl Into<String>,
        tos_buckets: Vec<String>,
    ) -> Result<Self, String> {
        let client = Self {
            http: reqwest::Client::new(),
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            region: region.into(),
            host: host.into(),
            oidc_provider_trn: oidc_provider_trn.into(),
            tos_buckets,
        };
        if client.access_key_id.is_empty() || client.secret_access_key.is_empty() {
            return Err("VE STS client needs a non-empty AK/SK (the broker's least-priv sts:AssumeRoleWithOIDC identity)".into());
        }
        if client.oidc_provider_trn.is_empty() {
            return Err(
                "VE STS client needs the OIDC provider TRN (trn:iam::<acct>:oidc-provider/<name>)"
                    .into(),
            );
        }
        if client.tos_buckets.is_empty() {
            return Err(
                "VE STS client needs >=1 TOS bucket for the per-actor session policy — \
                 minting unscoped credentials is refused (no-silent-fallback)"
                    .into(),
            );
        }
        Ok(client)
    }

    /// Construct from the environment — read ONCE here, never re-read later.
    ///
    ///   VOLCENGINE_ACCESS_KEY / VOLCENGINE_SECRET_KEY  broker's VE identity (required)
    ///   VOLCENGINE_REGION                              default cn-beijing
    ///   AGENTKEYS_VE_STS_HOST                          default sts.volcengineapi.com
    ///   AGENTKEYS_VE_OIDC_PROVIDER_TRN                 required
    ///   AGENTKEYS_VE_TOS_BUCKETS                       comma-separated, required
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| std::env::var(k).unwrap_or_default();
        let buckets: Vec<String> = get("AGENTKEYS_VE_TOS_BUCKETS")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let region = {
            let r = get("VOLCENGINE_REGION");
            if r.is_empty() {
                "cn-beijing".to_string()
            } else {
                r
            }
        };
        let host = {
            let h = get("AGENTKEYS_VE_STS_HOST");
            if h.is_empty() {
                DEFAULT_STS_HOST.to_string()
            } else {
                h
            }
        };
        Self::new(
            get("VOLCENGINE_ACCESS_KEY"),
            get("VOLCENGINE_SECRET_KEY"),
            region,
            host,
            get("AGENTKEYS_VE_OIDC_PROVIDER_TRN"),
            buckets,
        )
    }
}

/// Extract + normalize `agentkeys_actor_omni` from the OIDC JWT payload.
/// UNVERIFIED decode by design: VE STS validates the signature against the
/// registered issuer's JWKS as part of the exchange — a tampered token fails
/// there. Normalization mirrors handlers/oidc.rs (trim, strip `0x`, lowercase)
/// so the policy prefix always matches the worker/bucket `bots/<omni>/` shape.
pub(crate) fn actor_omni_from_jwt(token: &str) -> Result<String, String> {
    let payload_b64 = token
        .split('.')
        .nth(1)
        .ok_or_else(|| "OIDC token is not a JWT (no payload segment)".to_string())?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("JWT payload is not base64url: {e}"))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("JWT payload is not JSON: {e}"))?;
    let omni = claims["agentkeys_actor_omni"]
        .as_str()
        .unwrap_or("")
        .trim()
        .trim_start_matches("0x")
        .to_lowercase();
    if omni.is_empty() {
        return Err(
            "OIDC token carries no agentkeys_actor_omni claim — refusing an unscoped VE mint"
                .into(),
        );
    }
    Ok(omni)
}

/// Per-actor inline session policy (VE policy JSON — `{"Statement":[…]}`,
/// no `Version` field, matching the canonical shape of VE system policies).
/// Scope: object I/O under `bots/<omni>/*` + prefix-conditioned ListBucket,
/// per docs/spec/ve-broker-runtime-port.md "The isolation fork".
pub(crate) fn ve_session_policy(buckets: &[String], actor_omni: &str) -> String {
    let object_resources: Vec<String> = buckets
        .iter()
        .map(|b| format!("trn:tos:::{b}/bots/{actor_omni}/*"))
        .collect();
    let bucket_resources: Vec<String> = buckets.iter().map(|b| format!("trn:tos:::{b}")).collect();
    serde_json::json!({
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["tos:GetObject", "tos:PutObject", "tos:DeleteObject"],
                "Resource": object_resources,
            },
            {
                "Effect": "Allow",
                "Action": ["tos:ListBucket"],
                "Resource": bucket_resources,
                "Condition": { "StringLike": { "tos:prefix": format!("bots/{actor_omni}/*") } },
            }
        ]
    })
    .to_string()
}

/// Parse the `AssumeRoleWithOIDC` response body into `AssumedCredentials`.
/// Errors surface as the VE `ResponseMetadata.Error {Code, Message}` pair
/// regardless of HTTP status. `ExpiredTime` is RFC-3339 (e.g.
/// `2026-07-02T10:30:00+08:00`), not a unix epoch — numeric accepted too.
pub(crate) fn parse_assume_response(body: &str) -> Result<AssumedCredentials, String> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("VE STS response is not JSON: {e} — body: {body}"))?;
    if let Some(err) = v["ResponseMetadata"]["Error"].as_object() {
        let code = err.get("Code").and_then(|c| c.as_str()).unwrap_or("?");
        let msg = err.get("Message").and_then(|m| m.as_str()).unwrap_or("?");
        return Err(format!("AssumeRoleWithOIDC failed: {code}: {msg}"));
    }
    let creds = &v["Result"]["Credentials"];
    let field = |k: &str| -> Result<String, String> {
        creds[k]
            .as_str()
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("VE STS response missing Result.Credentials.{k}: {body}"))
    };
    // Live response (2026-07-02) names the expiry `Expiration` (RFC-3339 with
    // +08:00 offset) — NOT the `ExpiredTime` some VE docs show; accept both.
    let expiry = ["Expiration", "ExpiredTime"]
        .iter()
        .find_map(|k| creds.get(*k).filter(|v| !v.is_null()));
    let expiration_unix = match expiry {
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| format!("could not parse credential expiry {s:?} as RFC-3339: {e}"))?
            .timestamp(),
        other => {
            return Err(format!(
                "no Expiration/ExpiredTime in Credentials (got {other:?}) — full body: {body}"
            ))
        }
    };
    Ok(AssumedCredentials {
        access_key_id: field("AccessKeyId")?,
        secret_access_key: field("SecretAccessKey")?,
        session_token: field("SessionToken")?,
        expiration_unix,
    })
}

impl VeStsClient {
    async fn signed_call(&self, method: &str, action: &str, body: String) -> BrokerResult<String> {
        let query = ve_sign::canonical_query(&[("Action", action), ("Version", STS_VERSION)]);
        let x_date = ve_sign::now_x_date();
        let signed = ve_sign::sign(&VeSignRequest {
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
            session_token: None,
            region: &self.region,
            service: "sts",
            host: &self.host,
            method,
            path: "/",
            query: &query,
            body: body.as_bytes(),
            content_type: DEFAULT_CONTENT_TYPE,
            x_date: &x_date,
        });
        let url = format!("https://{}/?{}", self.host, query);
        let req = match method {
            "POST" => self.http.post(&url).body(body),
            _ => self.http.get(&url),
        };
        let resp = req
            .header("Content-Type", &signed.content_type)
            .header("X-Date", &signed.x_date)
            .header("X-Content-Sha256", &signed.x_content_sha256)
            .header("Authorization", &signed.authorization)
            .send()
            .await
            .map_err(|e| BrokerError::StsError(format!("VE STS {action} send: {e}")))?;
        resp.text()
            .await
            .map_err(|e| BrokerError::StsError(format!("VE STS {action} read body: {e}")))
    }
}

#[async_trait]
impl StsClient for VeStsClient {
    /// The trait speaks AWS nouns; on VE they map 1:1 —
    /// `role_arn`→`RoleTrn`, `web_identity_token`→`OIDCToken`, plus the
    /// client-held `OIDCProviderTrn` and the derived per-actor `Policy`.
    async fn assume_role_with_web_identity(
        &self,
        role_arn: &str,
        session_name: &str,
        web_identity_token: &str,
        duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials> {
        let actor_omni = actor_omni_from_jwt(web_identity_token).map_err(BrokerError::StsError)?;
        let policy = ve_session_policy(&self.tos_buckets, &actor_omni);
        let duration = duration_seconds.to_string();
        let body = ve_sign::form_encode(&[
            ("RoleTrn", role_arn),
            ("RoleSessionName", session_name),
            ("OIDCProviderTrn", &self.oidc_provider_trn),
            ("OIDCToken", web_identity_token),
            ("DurationSeconds", &duration),
            ("Policy", &policy),
        ]);
        let text = self.signed_call("POST", "AssumeRoleWithOIDC", body).await?;
        parse_assume_response(&text).map_err(BrokerError::StsError)
    }

    async fn caller_identity_ok(&self) -> BrokerResult<()> {
        let text = self
            .signed_call("GET", "GetCallerIdentity", String::new())
            .await?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| BrokerError::StsError(format!("GetCallerIdentity non-JSON: {e}")))?;
        if let Some(err) = v["ResponseMetadata"]["Error"].as_object() {
            return Err(BrokerError::StsError(format!(
                "VE GetCallerIdentity failed: {}: {}",
                err.get("Code").and_then(|c| c.as_str()).unwrap_or("?"),
                err.get("Message").and_then(|m| m.as_str()).unwrap_or("?"),
            )));
        }
        v["Result"]["AccountId"]
            .as_i64()
            .map(|_| ())
            .or_else(|| v["Result"]["AccountId"].as_str().map(|_| ()))
            .ok_or_else(|| {
                BrokerError::StsError(format!("VE GetCallerIdentity: no AccountId in {text}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt_with_claims(claims: serde_json::Value) -> String {
        let seg = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        format!(
            "{}.{}.sig",
            seg(&serde_json::json!({"alg":"ES256","typ":"JWT"})),
            seg(&claims)
        )
    }

    #[test]
    fn actor_omni_extracted_and_normalized() {
        let omni = "AB".repeat(32);
        let jwt = jwt_with_claims(serde_json::json!({"agentkeys_actor_omni": format!("0x{omni}")}));
        assert_eq!(actor_omni_from_jwt(&jwt).unwrap(), "ab".repeat(32));
    }

    #[test]
    fn missing_omni_claim_is_a_hard_error() {
        let jwt = jwt_with_claims(serde_json::json!({"sub": "x"}));
        let err = actor_omni_from_jwt(&jwt).unwrap_err();
        assert!(err.contains("agentkeys_actor_omni"), "{err}");
    }

    #[test]
    fn session_policy_scopes_to_actor_prefix_without_version_field() {
        let omni = "a".repeat(64);
        let p = ve_session_policy(&["agentterrier-vault".into()], &omni);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert!(v.get("Version").is_none(), "VE policies carry no Version");
        assert_eq!(
            v["Statement"][0]["Resource"][0],
            format!("trn:tos:::agentterrier-vault/bots/{omni}/*")
        );
        assert_eq!(
            v["Statement"][1]["Resource"][0],
            "trn:tos:::agentterrier-vault"
        );
        // LOWERCASE `tos:prefix` — the only spelling VE's policy engine accepts
        // (uppercase `tos:Prefix` → InvalidParameter "does not support the
        // condition key"; probed live 2026-07-02).
        assert_eq!(
            v["Statement"][1]["Condition"]["StringLike"]["tos:prefix"],
            format!("bots/{omni}/*")
        );
    }

    #[test]
    fn assume_response_parses_rfc3339_expiry() {
        let body = serde_json::json!({
            "ResponseMetadata": {"Action": "AssumeRoleWithOIDC"},
            "Result": {"Credentials": {
                "AccessKeyId": "AKTP...",
                "SecretAccessKey": "sk",
                "SessionToken": "tok",
                "CurrentTime": "2026-07-02T10:00:00+08:00",
                "Expiration": "2026-07-02T10:15:00+08:00"
            }}
        })
        .to_string();
        let c = parse_assume_response(&body).unwrap();
        assert_eq!(c.access_key_id, "AKTP...");
        // 2026-07-02T10:15:00+08:00 == 02:15:00Z
        assert_eq!(
            c.expiration_unix,
            chrono::DateTime::parse_from_rfc3339("2026-07-02T02:15:00Z")
                .unwrap()
                .timestamp()
        );
    }

    #[test]
    fn assume_response_surfaces_ve_error_pair() {
        let body = serde_json::json!({
            "ResponseMetadata": {"Error": {"Code": "InvalidOIDCToken", "Message": "The ID token is invalid."}}
        })
        .to_string();
        let err = parse_assume_response(&body).unwrap_err();
        assert!(err.contains("InvalidOIDCToken"), "{err}");
    }

    #[test]
    fn unscoped_construction_is_refused() {
        // `.err().unwrap()` (not `.unwrap_err()`): VeStsClient deliberately has
        // no Debug impl — a derived one would render the secret key.
        let no_buckets =
            VeStsClient::new("ak", "sk", "cn-beijing", DEFAULT_STS_HOST, "trn", vec![])
                .err()
                .unwrap();
        assert!(no_buckets.contains("session policy"), "{no_buckets}");
        let no_provider = VeStsClient::new(
            "ak",
            "sk",
            "cn-beijing",
            DEFAULT_STS_HOST,
            "",
            vec!["b".into()],
        )
        .err()
        .unwrap();
        assert!(no_provider.contains("provider TRN"), "{no_provider}");
    }
}
