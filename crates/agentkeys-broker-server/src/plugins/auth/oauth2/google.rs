//! Google OAuth2 provider (Phase A.2 — US-021, `auth-oauth2-google` feature).
//!
//! Per plan §3.5.4. Talks to:
//!   - https://accounts.google.com/o/oauth2/v2/auth   (authorization)
//!   - https://oauth2.googleapis.com/token            (token exchange)
//!   - https://www.googleapis.com/oauth2/v3/certs     (JWKS)
//!
//! id_token verification asserts:
//!   - `iss` = "https://accounts.google.com" (or bare-host alt);
//!   - `aud` = our `client_id`;
//!   - `exp` > now and `iat` skew ≤ `max_iat_skew_seconds`;
//!   - signature valid against the JWK identified by `kid`;
//!   - `nonce` matches the value stored in `oauth2_pending` (asserted by
//!     the wrapper).

use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use url::Url;

use super::{OAuth2Error, OAuth2Provider, TokenExchangeOutcome, VerifiedIdToken};
use crate::plugins::auth::IdentityType;
use crate::plugins::Readiness;

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const JWKS_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUER: &str = "https://accounts.google.com";
/// Google issues both `https://accounts.google.com` and bare
/// `accounts.google.com` historically; we accept both.
const ISSUER_ALT: &str = "accounts.google.com";

#[derive(Debug, Clone, Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GoogleJwk {
    kid: String,
    n: String,
    e: String,
    /// JSON Web Key Type. Google publishes `"RSA"`. We require
    /// `kty == "RSA"` (or empty for forward-compat) before using a key
    /// for signature verification (Codex round-1 Vector 13 P3).
    #[serde(default)]
    kty: String,
    /// Key usage. Google publishes `"sig"`. We require `use == "sig"`
    /// (or empty for forward-compat) before using a key for signature
    /// verification — defense-in-depth against accepting an
    /// encryption-only key with a matching `kid`.
    #[serde(default, rename = "use")]
    usage: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

struct CachedJwks {
    keys: Vec<GoogleJwk>,
    fetched_at: i64,
}

pub struct GoogleOAuth2Provider {
    pub client_id: String,
    pub client_secret: String,
    pub jwks_ttl_seconds: i64,
    pub max_iat_skew_seconds: u64,
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub jwks_endpoint: String,
    pub http: reqwest::Client,
    jwks_cache: RwLock<Option<CachedJwks>>,
}

impl GoogleOAuth2Provider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            jwks_ttl_seconds: 3600,
            max_iat_skew_seconds: 60,
            auth_endpoint: AUTH_ENDPOINT.into(),
            token_endpoint: TOKEN_ENDPOINT.into(),
            jwks_endpoint: JWKS_ENDPOINT.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client build"),
            jwks_cache: RwLock::new(None),
        }
    }

    /// Override endpoints for tests / staging deployments.
    pub fn with_endpoints(
        mut self,
        auth: impl Into<String>,
        token: impl Into<String>,
        jwks: impl Into<String>,
    ) -> Self {
        self.auth_endpoint = auth.into();
        self.token_endpoint = token.into();
        self.jwks_endpoint = jwks.into();
        self
    }

    pub fn with_jwks_ttl(mut self, ttl_seconds: i64) -> Self {
        self.jwks_ttl_seconds = ttl_seconds;
        self
    }

    /// Test/seed-only: insert a list of JWKs into the cache so the next
    /// `lookup_jwk` for any of those `kid`s skips the network. Production
    /// code goes through `refresh_jwks` instead.
    #[doc(hidden)]
    pub fn seed_jwks_cache_for_tests(&self, kid: &str, n: &str, e: &str) {
        let mut guard = match self.jwks_cache.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        *guard = Some(CachedJwks {
            keys: vec![GoogleJwk {
                kid: kid.to_string(),
                n: n.to_string(),
                e: e.to_string(),
                kty: "RSA".into(),
                usage: "sig".into(),
            }],
            fetched_at: unix_now(),
        });
    }

    async fn refresh_jwks(&self) -> Result<Vec<GoogleJwk>, OAuth2Error> {
        let resp = self
            .http
            .get(&self.jwks_endpoint)
            .send()
            .await
            .map_err(|e| OAuth2Error::Network(format!("jwks fetch: {}", e)))?;
        if !resp.status().is_success() {
            return Err(OAuth2Error::Provider(format!(
                "jwks fetch returned {}",
                resp.status()
            )));
        }
        let parsed: GoogleJwks = resp
            .json()
            .await
            .map_err(|e| OAuth2Error::Provider(format!("jwks parse: {}", e)))?;
        let now = unix_now();
        let mut guard = self
            .jwks_cache
            .write()
            .map_err(|e| OAuth2Error::Internal(format!("jwks cache poisoned: {}", e)))?;
        *guard = Some(CachedJwks {
            keys: parsed.keys.clone(),
            fetched_at: now,
        });
        Ok(parsed.keys)
    }

    async fn lookup_jwk(&self, kid: &str) -> Result<GoogleJwk, OAuth2Error> {
        let now = unix_now();
        if let Ok(guard) = self.jwks_cache.read() {
            if let Some(cache) = guard.as_ref() {
                if now - cache.fetched_at < self.jwks_ttl_seconds {
                    if let Some(found) = cache.keys.iter().find(|k| jwk_matches(k, kid)) {
                        return Ok(found.clone());
                    }
                }
            }
        }
        // Cache miss / stale / kid not found → refresh.
        let keys = self.refresh_jwks().await?;
        keys.into_iter()
            .find(|k| jwk_matches(k, kid))
            .ok_or_else(|| OAuth2Error::InvalidIdToken(format!("kid {} not in JWKS", kid)))
    }
}

/// Codex round-1 Vector 13 P3 + round-2 Vector 3 P2 mitigation: tighten
/// JWK lookup so an encryption-only key with the matching `kid` cannot
/// be picked up for signature verification. Round 2 escalated the
/// fail-closed bar: `kty` MUST be exactly `"RSA"` (no empty fallback);
/// `use` may be empty OR `"sig"` (Google has historically published
/// keys without `use` fields). Round 1 originally accepted empty `kty`;
/// round 2 found that to be too permissive.
fn jwk_matches(jwk: &GoogleJwk, kid: &str) -> bool {
    if jwk.kid != kid {
        return false;
    }
    let kty_ok = jwk.kty == "RSA";
    let use_ok = jwk.usage.is_empty() || jwk.usage == "sig";
    kty_ok && use_ok
}

#[async_trait]
impl OAuth2Provider for GoogleOAuth2Provider {
    fn provider_name(&self) -> &'static str {
        "google"
    }

    fn identity_type(&self) -> IdentityType {
        IdentityType::OAuth2Google
    }

    fn authorization_url(
        &self,
        pkce_challenge: &str,
        state: &str,
        nonce: &str,
        redirect_uri: &str,
    ) -> String {
        let mut url = match Url::parse(&self.auth_endpoint) {
            Ok(u) => u,
            Err(_) => {
                // Authorization endpoint is operator-supplied + sanity-validated
                // at construction. If we ever hit this, fall back to the constant.
                Url::parse(AUTH_ENDPOINT).expect("compile-time URL valid")
            }
        };
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email")
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", nonce)
            .append_pair("prompt", "select_account")
            .append_pair("access_type", "online");
        url.to_string()
    }

    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenExchangeOutcome, OAuth2Error> {
        let params = [
            ("code", code),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", pkce_verifier),
        ];
        let resp = self
            .http
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| OAuth2Error::Network(format!("token exchange: {}", e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuth2Error::Provider(format!(
                "token exchange returned {}: {}",
                status, body
            )));
        }
        let parsed: GoogleTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuth2Error::Provider(format!("token response parse: {}", e)))?;
        Ok(TokenExchangeOutcome {
            id_token: parsed.id_token,
        })
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdToken, OAuth2Error> {
        let header = decode_header(id_token)
            .map_err(|e| OAuth2Error::InvalidIdToken(format!("bad header: {}", e)))?;
        let kid = header
            .kid
            .ok_or_else(|| OAuth2Error::InvalidIdToken("id_token missing kid".into()))?;
        let jwk = self.lookup_jwk(&kid).await?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| OAuth2Error::InvalidIdToken(format!("decode key: {}", e)))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[ISSUER, ISSUER_ALT]);
        validation.leeway = self.max_iat_skew_seconds;
        let data = decode::<IdTokenClaims>(id_token, &key, &validation).map_err(|e| {
            // jsonwebtoken's error kinds are explicit; map them to our
            // OAuth2Error so the callback handler can render the right
            // status code. Codex round-1 Vector 14 P3 mitigation: also
            // surface InvalidIssuer with a structured message rather
            // than the catch-all.
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => OAuth2Error::Expired,
                ErrorKind::InvalidAudience => OAuth2Error::WrongAud,
                ErrorKind::InvalidIssuer => {
                    OAuth2Error::InvalidIdToken("wrong issuer (iss claim)".into())
                }
                _ => OAuth2Error::InvalidIdToken(e.to_string()),
            }
        })?;
        let claims = data.claims;
        let nonce = claims.nonce.as_deref().unwrap_or("");
        if nonce != expected_nonce {
            return Err(OAuth2Error::NonceMismatch);
        }
        Ok(VerifiedIdToken {
            sub: claims.sub,
            email: claims.email,
        })
    }

    fn ready(&self) -> Readiness {
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Readiness::unready("google: client_id or client_secret missing");
        }
        let now = unix_now();
        if let Ok(guard) = self.jwks_cache.read() {
            if let Some(cache) = guard.as_ref() {
                if now - cache.fetched_at < self.jwks_ttl_seconds {
                    return Readiness::ready_with(format!(
                        "google: jwks fresh ({}s old, {} keys)",
                        now - cache.fetched_at,
                        cache.keys.len()
                    ));
                }
                return Readiness::degraded(
                    "google: jwks cache stale (>jwks_ttl_seconds since last fetch)".to_string(),
                );
            }
        }
        Readiness::degraded("google: jwks not yet fetched (will fetch on first verify)".to_string())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> GoogleOAuth2Provider {
        GoogleOAuth2Provider::new("test-client-id", "test-client-secret")
    }

    #[test]
    fn provider_name_is_stable() {
        assert_eq!(provider().provider_name(), "google");
    }

    #[test]
    fn identity_type_is_google() {
        assert_eq!(provider().identity_type(), IdentityType::OAuth2Google);
    }

    #[test]
    fn authorization_url_carries_required_params() {
        let p = provider();
        let url = p.authorization_url(
            "ch-abc-123",
            "state-xyz",
            "n-1",
            "https://broker.test/auth/oauth2/callback",
        );
        // Required OAuth2 params per plan §3.5.4
        for must_have in [
            "client_id=test-client-id",
            "response_type=code",
            "code_challenge=ch-abc-123",
            "code_challenge_method=S256",
            "state=state-xyz",
            "nonce=n-1",
            "prompt=select_account",
        ] {
            assert!(
                url.contains(must_have),
                "URL missing {}: {}",
                must_have,
                url
            );
        }
        // scope=openid+email is space-encoded in query.
        assert!(url.contains("scope=openid+email") || url.contains("scope=openid%20email"));
    }

    #[test]
    fn ready_unready_when_secret_missing() {
        let p = GoogleOAuth2Provider::new("client-id", "");
        let r = p.ready();
        assert!(r.is_unready());
    }

    #[test]
    fn ready_degraded_when_jwks_never_fetched() {
        let p = provider();
        let r = p.ready();
        assert!(r.is_degraded(), "got: {:?}", r);
    }

    #[tokio::test]
    async fn lookup_jwk_returns_cached_key() {
        let p = provider();
        // Use the test seed helper so we don't hit the network.
        p.seed_jwks_cache_for_tests("kid-1", "fake-n", "AQAB");
        let jwk = p.lookup_jwk("kid-1").await.unwrap();
        assert_eq!(jwk.kid, "kid-1");
    }

    #[test]
    fn ready_ready_when_jwks_fresh() {
        let p = provider();
        p.seed_jwks_cache_for_tests("kid-1", "n", "AQAB");
        assert!(p.ready().is_ready());
    }
}
