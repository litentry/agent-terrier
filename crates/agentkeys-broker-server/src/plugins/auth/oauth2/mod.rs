//! OAuth2 auth method (Phase A.2 — US-020/021).
//!
//! Per plan §3.5.4. Wraps a provider-specific [`OAuth2Provider`] impl
//! with shared infrastructure:
//!
//! - PKCE challenge generation (32-byte verifier + S256 challenge);
//! - state-HMAC signing/verification (binds the browser callback to the
//!   originating CLI session — defends against CSRF + state-table
//!   flooding);
//! - oauth2_pending storage (single-use rows, race-safe consume);
//! - per-IP rate limit on `/v1/auth/oauth2/start`;
//! - JWKS cache TTL is owned by each provider impl.
//!
//! The session JWT lands on the CLI's polling endpoint, never in the
//! browser response — same posture as EmailLink (§3.5.3).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plugins::auth::{
    AuthChallenge, AuthError, AuthResponse, ChallengeParams, IdentityType, UserAuthMethod,
    VerifiedIdentity,
};
use crate::plugins::Readiness;
use crate::storage::{
    EmailRateLimitStore, OAuth2PendingConsume, OAuth2PendingStatus, OAuth2PendingStore,
    RateLimitOutcome,
};

#[cfg(feature = "auth-oauth2-google")]
pub mod google;

/// State-HMAC version tag — bumped if the payload schema changes so old
/// state values are immediately rejected.
const STATE_HMAC_VERSION: &str = "v1";
/// OAuth2 flow window. CLI polls; browser must complete callback within
/// this window or the row is purged as `failed`.
const FLOW_TTL_SECONDS: i64 = 600;
/// State payload TTL — independent of the flow TTL because the state
/// signature is verifiable without DB access. Mirrors flow TTL for v0.
const STATE_TTL_SECONDS: i64 = 600;

#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error("provider error: {0}")]
    Provider(String),
    #[error("id_token expired")]
    Expired,
    #[error("id_token wrong audience")]
    WrongAud,
    #[error("id_token nonce mismatch")]
    NonceMismatch,
    #[error("invalid id_token: {0}")]
    InvalidIdToken(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<OAuth2Error> for AuthError {
    fn from(e: OAuth2Error) -> Self {
        match e {
            OAuth2Error::Expired
            | OAuth2Error::WrongAud
            | OAuth2Error::NonceMismatch
            | OAuth2Error::InvalidIdToken(_) => AuthError::Unauthorized(e.to_string()),
            OAuth2Error::Provider(_) | OAuth2Error::Network(_) => {
                AuthError::Upstream(e.to_string())
            }
            OAuth2Error::Internal(_) => AuthError::Internal(e.to_string()),
        }
    }
}

/// Output of [`OAuth2Provider::verify_id_token`].
#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    pub sub: String,
    pub email: Option<String>,
}

/// Output of [`OAuth2Provider::exchange_code`].
#[derive(Debug, Clone)]
pub struct TokenExchangeOutcome {
    pub id_token: String,
}

/// Provider-specific behavior. The shared [`OAuth2Auth`] wrapper drives
/// this trait through the start → callback → status flow.
#[async_trait]
pub trait OAuth2Provider: Send + Sync {
    /// Stable provider name — written to the `provider` column in
    /// `oauth2_pending` and used as the trait-registry key prefix
    /// (`oauth2_<provider_name>`).
    fn provider_name(&self) -> &'static str;

    /// IdentityType variant used for OmniAccount derivation.
    fn identity_type(&self) -> IdentityType;

    /// Build the provider's authorization URL given the broker-generated
    /// PKCE challenge, signed `state`, `nonce`, and the broker-configured
    /// redirect URI.
    fn authorization_url(
        &self,
        pkce_challenge: &str,
        state: &str,
        nonce: &str,
        redirect_uri: &str,
    ) -> String;

    /// Exchange the authorization `code` at the provider's token endpoint.
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenExchangeOutcome, OAuth2Error>;

    /// Verify the id_token returned by the provider. Asserts iss, aud,
    /// exp, iat skew, signature; the wrapper additionally checks the
    /// `nonce` claim matches the row stored in `oauth2_pending`.
    async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdToken, OAuth2Error>;

    /// Operational state — JWKS reachable, client_secret loaded, etc.
    fn ready(&self) -> Readiness;
}

/// Test-only stub provider. Records the `exchange_code` + `verify_id_token`
/// calls in `Mutex<Vec<…>>` and returns canned outcomes set by the test.
pub struct StubOAuth2Provider {
    pub calls_exchange: std::sync::Mutex<Vec<(String, String)>>,
    pub calls_verify: std::sync::Mutex<Vec<(String, String)>>,
    pub canned_id_token: std::sync::Mutex<Result<String, OAuth2Error>>,
    pub canned_verify_outcome: std::sync::Mutex<Result<VerifiedIdToken, OAuth2Error>>,
    pub identity_type: IdentityType,
    pub provider_name: &'static str,
    pub expected_aud: String,
}

impl StubOAuth2Provider {
    pub fn new(
        provider_name: &'static str,
        identity_type: IdentityType,
        expected_aud: impl Into<String>,
    ) -> Self {
        Self {
            calls_exchange: std::sync::Mutex::new(Vec::new()),
            calls_verify: std::sync::Mutex::new(Vec::new()),
            canned_id_token: std::sync::Mutex::new(Ok("stub-id-token".into())),
            canned_verify_outcome: std::sync::Mutex::new(Ok(VerifiedIdToken {
                sub: "stub-sub-12345".into(),
                email: Some("stub@example.com".into()),
            })),
            identity_type,
            provider_name,
            expected_aud: expected_aud.into(),
        }
    }

    /// Reset the canned outcome before each test action so the same
    /// stub can drive multiple sub-cases.
    pub fn set_canned_verify(&self, outcome: Result<VerifiedIdToken, OAuth2Error>) {
        *self.canned_verify_outcome.lock().unwrap() = outcome;
    }

    pub fn set_canned_exchange(&self, id_token: Result<String, OAuth2Error>) {
        *self.canned_id_token.lock().unwrap() = id_token;
    }

    pub fn exchange_calls(&self) -> Vec<(String, String)> {
        self.calls_exchange.lock().unwrap().clone()
    }

    pub fn verify_calls(&self) -> Vec<(String, String)> {
        self.calls_verify.lock().unwrap().clone()
    }
}

/// Clone an `OAuth2Error` by cloning its message representation. The
/// underlying enum is non-Clone (it carries a String) but for stub use
/// we want to feed the same canned outcome to multiple invocations.
fn clone_oauth2_err(e: &OAuth2Error) -> OAuth2Error {
    match e {
        OAuth2Error::Provider(s) => OAuth2Error::Provider(s.clone()),
        OAuth2Error::Expired => OAuth2Error::Expired,
        OAuth2Error::WrongAud => OAuth2Error::WrongAud,
        OAuth2Error::NonceMismatch => OAuth2Error::NonceMismatch,
        OAuth2Error::InvalidIdToken(s) => OAuth2Error::InvalidIdToken(s.clone()),
        OAuth2Error::Network(s) => OAuth2Error::Network(s.clone()),
        OAuth2Error::Internal(s) => OAuth2Error::Internal(s.clone()),
    }
}

fn clone_verify_outcome(
    r: &Result<VerifiedIdToken, OAuth2Error>,
) -> Result<VerifiedIdToken, OAuth2Error> {
    match r {
        Ok(v) => Ok(v.clone()),
        Err(e) => Err(clone_oauth2_err(e)),
    }
}

#[async_trait]
impl OAuth2Provider for StubOAuth2Provider {
    fn provider_name(&self) -> &'static str {
        self.provider_name
    }
    fn identity_type(&self) -> IdentityType {
        self.identity_type
    }
    fn authorization_url(
        &self,
        pkce_challenge: &str,
        state: &str,
        nonce: &str,
        redirect_uri: &str,
    ) -> String {
        format!(
            "https://stub.example/auth?challenge={}&state={}&nonce={}&redirect={}",
            pkce_challenge, state, nonce, redirect_uri
        )
    }
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        _redirect_uri: &str,
    ) -> Result<TokenExchangeOutcome, OAuth2Error> {
        self.calls_exchange
            .lock()
            .unwrap()
            .push((code.to_string(), pkce_verifier.to_string()));
        let canned = self.canned_id_token.lock().unwrap();
        match &*canned {
            Ok(t) => Ok(TokenExchangeOutcome {
                id_token: t.clone(),
            }),
            Err(e) => Err(clone_oauth2_err(e)),
        }
    }
    async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdToken, OAuth2Error> {
        self.calls_verify
            .lock()
            .unwrap()
            .push((id_token.to_string(), expected_nonce.to_string()));
        let outcome = self.canned_verify_outcome.lock().unwrap();
        clone_verify_outcome(&outcome)
    }
    fn ready(&self) -> Readiness {
        Readiness::ok()
    }
}

/// The OAuth2 plugin. One instance per provider — registered as
/// `oauth2_<provider_name>` in the auth registry.
pub struct OAuth2Auth {
    pub provider: Arc<dyn OAuth2Provider>,
    pub pending_store: Arc<OAuth2PendingStore>,
    pub rate_limit_store: Arc<EmailRateLimitStore>,
    pub state_hmac_key: Vec<u8>,
    pub redirect_uri: String,
    pub start_rate_limit_per_ip_minutely: i64,
    /// Cached `&'static str` for [`UserAuthMethod::name`] — built once at
    /// construction by `Box::leak`-ing a small formatted string. The leak
    /// is bounded by the number of OAuth2Auth instances (= compiled-in
    /// providers), so there is no unbounded growth.
    cached_method_name: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatePayload {
    /// Schema version. Increment any time the payload shape changes so
    /// outstanding state tokens are immediately invalidated.
    pub ver: String,
    /// `request_id` of the originating CLI session.
    pub rid: String,
    /// 16-byte CSPRNG nonce, also written to oauth2_pending.nonce. The
    /// id_token's `nonce` claim must match.
    pub n: String,
    /// Unix-seconds when the state was minted.
    pub ts: i64,
}

#[derive(Debug, Clone)]
pub struct HandleCallbackOutcome {
    pub request_id: String,
    pub sub: String,
    pub email: Option<String>,
    pub identity_type: IdentityType,
}

/// Error from [`OAuth2Auth::handle_callback`] tagged with whether THIS
/// invocation actually consumed the pending row.
///
/// Codex round-1 P1 mitigation (Vector 6, callback consume/mark_failed
/// race): the callback handler must only `mark_failed` rows it owns.
/// `owned_request_id: Some(id)` ⇒ this invocation atomically transitioned
/// the row out of `pending`, so any later failure here is OUR failure
/// and we are entitled to flip the row to `failed`. `owned_request_id:
/// None` ⇒ the failure happened pre-consume (bad state, expired flow,
/// already consumed by a concurrent callback) and we MUST NOT touch
/// any row keyed by the recovered request_id — doing so would clobber
/// a still-in-flight legitimate callback into `failed`.
#[derive(Debug)]
pub struct CallbackError {
    pub inner: AuthError,
    pub owned_request_id: Option<String>,
}

impl CallbackError {
    fn pre_consume(err: AuthError) -> Self {
        Self {
            inner: err,
            owned_request_id: None,
        }
    }

    fn post_consume(err: AuthError, request_id: String) -> Self {
        Self {
            inner: err,
            owned_request_id: Some(request_id),
        }
    }
}

impl From<CallbackError> for AuthError {
    fn from(e: CallbackError) -> Self {
        e.inner
    }
}

impl OAuth2Auth {
    pub fn new(
        provider: Arc<dyn OAuth2Provider>,
        pending_store: Arc<OAuth2PendingStore>,
        rate_limit_store: Arc<EmailRateLimitStore>,
        state_hmac_key: Vec<u8>,
        redirect_uri: impl Into<String>,
        start_rate_limit_per_ip_minutely: i64,
    ) -> Result<Self, AuthError> {
        if state_hmac_key.len() < 32 {
            return Err(AuthError::Internal(format!(
                "OAuth2 state HMAC key must be >= 32 bytes, got {}",
                state_hmac_key.len()
            )));
        }
        let cached_method_name: &'static str =
            Box::leak(format!("oauth2_{}", provider.provider_name()).into_boxed_str());
        Ok(Self {
            provider,
            pending_store,
            rate_limit_store,
            state_hmac_key,
            redirect_uri: redirect_uri.into(),
            start_rate_limit_per_ip_minutely,
            cached_method_name,
        })
    }

    /// PKCE: `(verifier, challenge)`. `verifier` is 32 random bytes
    /// base64url-encoded; `challenge` = base64url(SHA256(verifier)).
    pub fn new_pkce() -> (String, String) {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("OS RNG failed");
        let verifier = URL_SAFE_NO_PAD.encode(buf);
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(h.finalize());
        (verifier, challenge)
    }

    pub fn random_b64url(byte_len: usize) -> String {
        let mut buf = vec![0u8; byte_len];
        getrandom::getrandom(&mut buf).expect("OS RNG failed");
        URL_SAFE_NO_PAD.encode(buf)
    }

    fn compute_state_hmac(&self, msg: &[u8]) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.state_hmac_key)
            .expect("state HMAC key length validated at construction");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    /// Sign and return a state token: `<payload_b64url>.<sig_b64url>`.
    pub fn sign_state(&self, request_id: &str, nonce: &str, ts: i64) -> Result<String, AuthError> {
        let payload = serde_json::to_vec(&StatePayload {
            ver: STATE_HMAC_VERSION.to_string(),
            rid: request_id.to_string(),
            n: nonce.to_string(),
            ts,
        })
        .map_err(|e| AuthError::Internal(format!("serialize state payload: {}", e)))?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let sig = self.compute_state_hmac(payload_b64.as_bytes());
        Ok(format!("{}.{}", payload_b64, URL_SAFE_NO_PAD.encode(sig)))
    }

    /// Verify a state token: HMAC sig + version + TTL. Constant-time
    /// comparison defends against signature-recovery side channels.
    pub fn verify_state(&self, state: &str, now: i64) -> Result<StatePayload, AuthError> {
        let (payload_b64, sig_b64) = state
            .split_once('.')
            .ok_or_else(|| AuthError::Unauthorized("state: missing separator".into()))?;
        let expected_sig = self.compute_state_hmac(payload_b64.as_bytes());
        let actual_sig = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| AuthError::Unauthorized("state: sig decode failed".into()))?;
        if !constant_time_eq(&expected_sig, &actual_sig) {
            return Err(AuthError::Unauthorized("state: HMAC mismatch".into()));
        }
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AuthError::Unauthorized("state: payload decode failed".into()))?;
        let payload: StatePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|_| AuthError::Unauthorized("state: payload not JSON".into()))?;
        if payload.ver != STATE_HMAC_VERSION {
            return Err(AuthError::Unauthorized("state: wrong version".into()));
        }
        if now - payload.ts > STATE_TTL_SECONDS {
            return Err(AuthError::Expired("state: ttl expired".into()));
        }
        Ok(payload)
    }

    /// Drive the callback half of the flow: verify state, atomically
    /// consume the pending row, exchange the code, verify the id_token.
    /// Returns the (request_id, sub, email) so the HTTP handler can mint
    /// the session JWT and call `pending_store.mark_verified`.
    ///
    /// Errors are tagged with [`CallbackError::owned_request_id`]:
    /// `Some(id)` ⇒ this invocation atomically consumed the row, so the
    /// caller may safely flip the row to `failed`; `None` ⇒ the failure
    /// happened pre-consume (state, expired, already-consumed-by-concurrent),
    /// and the caller MUST NOT touch any row by id (the legitimate
    /// concurrent flow may still be in flight). Codex round-1 Vector 6 P1
    /// mitigation.
    pub async fn handle_callback(
        &self,
        code: &str,
        state: &str,
        now: i64,
    ) -> Result<HandleCallbackOutcome, CallbackError> {
        let payload = self
            .verify_state(state, now)
            .map_err(CallbackError::pre_consume)?;
        let consumed = self
            .pending_store
            .consume(&payload.rid, now)
            .map_err(CallbackError::pre_consume)?;
        let (provider, pkce_verifier, nonce) = match consumed {
            OAuth2PendingConsume::Available {
                provider,
                pkce_verifier,
                nonce,
            } => (provider, pkce_verifier, nonce),
            OAuth2PendingConsume::Expired => {
                return Err(CallbackError::pre_consume(AuthError::Expired(
                    "oauth2 flow expired".into(),
                )));
            }
            OAuth2PendingConsume::NotFoundOrConsumed => {
                // Concurrent callback won the race — DO NOT touch the row.
                return Err(CallbackError::pre_consume(AuthError::Unauthorized(
                    "oauth2 pending row not found or already consumed".into(),
                )));
            }
        };
        // From here on, this invocation OWNS the row — failures past this
        // point should be surfaced to the CLI poll via mark_failed.
        let request_id = payload.rid.clone();
        if provider != self.provider.provider_name() {
            return Err(CallbackError::post_consume(
                AuthError::InvalidRequest(format!(
                    "callback provider mismatch: pending={} current={}",
                    provider,
                    self.provider.provider_name()
                )),
                request_id,
            ));
        }
        if nonce != payload.n {
            return Err(CallbackError::post_consume(
                AuthError::Unauthorized("nonce mismatch (state ↔ pending)".into()),
                request_id,
            ));
        }
        let exchange = match self
            .provider
            .exchange_code(code, &pkce_verifier, &self.redirect_uri)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                return Err(CallbackError::post_consume(e.into(), request_id));
            }
        };
        let verified = match self
            .provider
            .verify_id_token(&exchange.id_token, &nonce)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return Err(CallbackError::post_consume(e.into(), request_id));
            }
        };
        Ok(HandleCallbackOutcome {
            request_id,
            sub: verified.sub,
            email: verified.email,
            identity_type: self.provider.identity_type(),
        })
    }
}

#[async_trait]
impl UserAuthMethod for OAuth2Auth {
    fn name(&self) -> &'static str {
        self.cached_method_name
    }

    fn ready(&self) -> Readiness {
        let provider_ready = self.provider.ready();
        if provider_ready.is_unready() {
            return provider_ready;
        }
        if !self.pending_store.writable() {
            return Readiness::unready("oauth2_pending table not writable");
        }
        // Codex round-1 Vector 10 P2 mitigation: also check rate-limit
        // store writability so a corrupt oauth2_rate_limits.sqlite
        // doesn't sneak past /readyz.
        if !self.rate_limit_store.writable() {
            return Readiness::unready("oauth2 rate-limit table not writable");
        }
        provider_ready
    }

    async fn challenge(&self, params: ChallengeParams) -> Result<AuthChallenge, AuthError> {
        let now = unix_now()?;
        // Per-IP rate limit (defends oauth2_pending table flooding +
        // gas-drain via mass row creation).
        if let Some(ip) = params.source_ip.as_deref() {
            let bucket = format!("oauth2_start_ip:{}", ip);
            if let RateLimitOutcome::Denied {
                retry_after_seconds,
            } = self.rate_limit_store.check_and_increment(
                &bucket,
                now,
                60,
                self.start_rate_limit_per_ip_minutely,
            )? {
                return Err(AuthError::RateLimited(format!(
                    "per-IP /v1/auth/oauth2/start rate limit exceeded; retry in {}s",
                    retry_after_seconds
                )));
            }
        }
        let request_id = format!("oa2-{}", Self::random_b64url(12));
        let (verifier, challenge) = Self::new_pkce();
        let nonce = Self::random_b64url(16);
        let expires_at = now + FLOW_TTL_SECONDS;
        self.pending_store.issue(
            &request_id,
            self.provider.provider_name(),
            &verifier,
            &nonce,
            now,
            expires_at,
        )?;
        let state = self.sign_state(&request_id, &nonce, now)?;
        let auth_url =
            self.provider
                .authorization_url(&challenge, &state, &nonce, &self.redirect_uri);
        Ok(AuthChallenge {
            request_id: request_id.clone(),
            expires_in_seconds: FLOW_TTL_SECONDS as u64,
            extras: serde_json::json!({
                "authorization_url": auth_url,
                "poll_url": format!("/v1/auth/oauth2/status/{}", request_id),
                "provider": self.provider.provider_name(),
            }),
        })
    }

    async fn verify(&self, response: AuthResponse) -> Result<VerifiedIdentity, AuthError> {
        match self.pending_store.peek_status(&response.request_id)? {
            OAuth2PendingStatus::Pending => Err(AuthError::Unauthorized(
                "oauth2 callback not yet completed; CLI should keep polling".into(),
            )),
            OAuth2PendingStatus::Verified { identity_value, .. } => Ok(VerifiedIdentity {
                identity_type: self.provider.identity_type(),
                identity_value,
            }),
            OAuth2PendingStatus::Failed { reason } => Err(AuthError::Unauthorized(format!(
                "oauth2 verify failed: {}",
                reason
            ))),
            OAuth2PendingStatus::Unknown => Err(AuthError::InvalidRequest(format!(
                "unknown request_id: {}",
                response.request_id
            ))),
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn unix_now() -> Result<i64, AuthError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AuthError::Internal(format!("clock before unix epoch: {}", e)))?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_plugin() -> (Arc<OAuth2Auth>, Arc<StubOAuth2Provider>) {
        let provider = Arc::new(StubOAuth2Provider::new(
            "google",
            IdentityType::OAuth2Google,
            "test-client-id",
        ));
        let pending = Arc::new(OAuth2PendingStore::open_in_memory().unwrap());
        let rl = Arc::new(EmailRateLimitStore::open_in_memory().unwrap());
        let plugin = OAuth2Auth::new(
            provider.clone() as Arc<dyn OAuth2Provider>,
            pending,
            rl,
            vec![0u8; 32],
            "https://broker.test/auth/oauth2/callback",
            30,
        )
        .unwrap();
        (Arc::new(plugin), provider)
    }

    #[tokio::test]
    async fn name_uses_provider_prefix() {
        let (p, _s) = make_plugin();
        assert_eq!(p.name(), "oauth2_google");
    }

    #[tokio::test]
    async fn pkce_pair_is_distinct_each_call() {
        let (a_v, a_c) = OAuth2Auth::new_pkce();
        let (b_v, b_c) = OAuth2Auth::new_pkce();
        assert_ne!(a_v, b_v);
        assert_ne!(a_c, b_c);
        // Verifier+challenge are base64url-no-pad.
        assert!(a_v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    }

    #[tokio::test]
    async fn challenge_returns_authorization_url_and_pending_row() {
        let (p, _s) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        assert!(challenge.request_id.starts_with("oa2-"));
        assert_eq!(challenge.expires_in_seconds, FLOW_TTL_SECONDS as u64);
        let url = challenge
            .extras
            .get("authorization_url")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(url.contains("challenge="));
        assert!(url.contains("state="));
        assert!(url.contains("nonce="));
        // Pending row is in store.
        assert_eq!(
            p.pending_store.peek_status(&challenge.request_id).unwrap(),
            OAuth2PendingStatus::Pending
        );
    }

    #[tokio::test]
    async fn happy_path_callback_returns_outcome() {
        let (p, _s) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        // Extract the state from the authorization_url (the stub copies
        // it verbatim into the URL).
        let url = challenge
            .extras
            .get("authorization_url")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let state = extract_query_arg(&url, "state").expect("state");

        let now = unix_now().unwrap();
        let outcome = p
            .handle_callback("auth-code-123", &state, now)
            .await
            .unwrap();
        assert_eq!(outcome.request_id, challenge.request_id);
        assert_eq!(outcome.sub, "stub-sub-12345");
        assert_eq!(outcome.identity_type, IdentityType::OAuth2Google);
    }

    #[tokio::test]
    async fn tampered_state_rejected_with_unauthorized() {
        let (p, _s) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        let url = challenge
            .extras
            .get("authorization_url")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let state = extract_query_arg(&url, "state").unwrap();
        // Flip a byte in the signature half. The state shape is
        // `payload.sig`; we corrupt the sig.
        let mut tampered = state.clone();
        let last = tampered.pop().unwrap_or('A');
        let next = if last == 'A' { 'B' } else { 'A' };
        tampered.push(next);

        let now = unix_now().unwrap();
        let res = p.handle_callback("auth-code-123", &tampered, now).await;
        match &res {
            Err(e) => {
                assert!(
                    matches!(e.inner, AuthError::Unauthorized(_)),
                    "got: {:?}",
                    res
                );
                assert!(
                    e.owned_request_id.is_none(),
                    "tampered state must NOT own a row"
                );
            }
            _ => panic!("expected Err, got: {:?}", res),
        }
    }

    #[tokio::test]
    async fn replayed_state_rejected_after_first_callback() {
        let (p, _s) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        let state = extract_query_arg(
            challenge
                .extras
                .get("authorization_url")
                .and_then(|v| v.as_str())
                .unwrap(),
            "state",
        )
        .unwrap();
        let now = unix_now().unwrap();
        let _first = p
            .handle_callback("auth-code-123", &state, now)
            .await
            .unwrap();
        let replay = p.handle_callback("auth-code-123", &state, now).await;
        match &replay {
            Err(e) => {
                assert!(
                    matches!(e.inner, AuthError::Unauthorized(_)),
                    "got: {:?}",
                    replay
                );
                // P1 fix: replay against an already-consumed row must NOT
                // be tagged as owned — otherwise the handler would
                // mark_failed the legitimate in-flight flow.
                assert!(
                    e.owned_request_id.is_none(),
                    "replay must NOT own a request_id (legitimate flow may still be in flight)"
                );
            }
            _ => panic!("expected replay Err, got: {:?}", replay),
        }
    }

    #[tokio::test]
    async fn expired_id_token_propagates_unauthorized() {
        let (p, s) = make_plugin();
        s.set_canned_verify(Err(OAuth2Error::Expired));
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        let state = extract_query_arg(
            challenge
                .extras
                .get("authorization_url")
                .and_then(|v| v.as_str())
                .unwrap(),
            "state",
        )
        .unwrap();
        let now = unix_now().unwrap();
        let res = p.handle_callback("c", &state, now).await;
        match &res {
            Err(e) => {
                assert!(
                    matches!(&e.inner, AuthError::Unauthorized(m) if m.contains("expired")),
                    "got: {:?}",
                    res
                );
                // expired id_token is post-consume — caller MAY mark_failed.
                assert!(
                    e.owned_request_id.is_some(),
                    "post-consume failure must own request_id"
                );
            }
            _ => panic!("expected Err, got: {:?}", res),
        }
    }

    #[tokio::test]
    async fn wrong_aud_propagates_unauthorized() {
        let (p, s) = make_plugin();
        s.set_canned_verify(Err(OAuth2Error::WrongAud));
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        let state = extract_query_arg(
            challenge
                .extras
                .get("authorization_url")
                .and_then(|v| v.as_str())
                .unwrap(),
            "state",
        )
        .unwrap();
        let now = unix_now().unwrap();
        let res = p.handle_callback("c", &state, now).await;
        match &res {
            Err(e) => {
                assert!(
                    matches!(&e.inner, AuthError::Unauthorized(m) if m.contains("audience")),
                    "got: {:?}",
                    res
                );
                assert!(
                    e.owned_request_id.is_some(),
                    "post-consume failure must own request_id"
                );
            }
            _ => panic!("expected Err, got: {:?}", res),
        }
    }

    #[tokio::test]
    async fn rate_limit_per_ip_enforced_on_start() {
        let (p, _s) = make_plugin();
        // Plugin is configured with start_rate_limit=30.
        for _ in 0..30 {
            p.challenge(ChallengeParams {
                source_ip: Some("10.0.0.1".into()),
                extras: json!({}),
            })
            .await
            .unwrap();
        }
        let res = p
            .challenge(ChallengeParams {
                source_ip: Some("10.0.0.1".into()),
                extras: json!({}),
            })
            .await;
        assert!(matches!(res, Err(AuthError::RateLimited(_))));
    }

    #[tokio::test]
    async fn verify_pending_returns_unauthorized() {
        let (p, _s) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({}),
            })
            .await
            .unwrap();
        let r = p
            .verify(AuthResponse {
                request_id: challenge.request_id,
                extras: json!({}),
            })
            .await;
        assert!(matches!(r, Err(AuthError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn verify_unknown_request_id_returns_invalid_request() {
        let (p, _s) = make_plugin();
        let r = p
            .verify(AuthResponse {
                request_id: "never-issued".into(),
                extras: json!({}),
            })
            .await;
        assert!(matches!(r, Err(AuthError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn hmac_key_too_short_rejected() {
        let provider = Arc::new(StubOAuth2Provider::new(
            "google",
            IdentityType::OAuth2Google,
            "test-aud",
        )) as Arc<dyn OAuth2Provider>;
        let pending = Arc::new(OAuth2PendingStore::open_in_memory().unwrap());
        let rl = Arc::new(EmailRateLimitStore::open_in_memory().unwrap());
        let res = OAuth2Auth::new(
            provider,
            pending,
            rl,
            vec![0u8; 16], // too short
            "https://broker.test/auth/oauth2/callback",
            30,
        );
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn state_payload_old_timestamp_rejected_as_expired() {
        let (p, _s) = make_plugin();
        // Sign with a ts more than STATE_TTL ago.
        let now = unix_now().unwrap();
        let stale = p
            .sign_state("oa2-x", "noncey", now - (STATE_TTL_SECONDS + 60))
            .unwrap();
        let res = p.verify_state(&stale, now);
        assert!(matches!(res, Err(AuthError::Expired(_))));
    }

    /// Tiny helper — extract a query-string arg from a URL string.
    /// We avoid depending on the `url` crate from inside #[cfg(test)]
    /// because callers above already have `url` available.
    fn extract_query_arg(url: &str, arg: &str) -> Option<String> {
        let q = url.split_once('?')?.1;
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                if k == arg {
                    return Some(urldecode(v));
                }
            }
        }
        None
    }

    fn urldecode(s: &str) -> String {
        let mut out = Vec::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h * 16) + l) as u8);
                    i += 3;
                    continue;
                }
            }
            if bytes[i] == b'+' {
                out.push(b' ');
            } else {
                out.push(bytes[i]);
            }
            i += 1;
        }
        String::from_utf8(out).unwrap_or_default()
    }
}
