//! `EmailLinkAuth` — Phase A.1 magic-link auth method (US-017).
//!
//! Per plan §3.5.3:
//!
//! 1. CLI calls `POST /v1/auth/email/request` (handled in US-018) which
//!    invokes this plugin's `challenge()`. We mint a 32-byte CSPRNG
//!    token, store `SHA256(token)` keyed by `request_id`, and ask the
//!    `EmailSender` to mail a magic link of the form
//!    `https://broker/auth/email/landing#t=<base64url(token)>`.
//! 2. User clicks link → broker-hosted landing page reads the fragment
//!    and POSTs to `/v1/auth/email/verify` (US-018).
//! 3. The HTTP handler invokes `consume_token` directly (NOT the trait
//!    `verify`) — the consume + mark-verified happens browser-side.
//! 4. CLI polls `/v1/auth/email/status/{request_id}` which calls the
//!    trait's `verify()` — this returns the staged `VerifiedIdentity`
//!    once the browser-side `consume_token` succeeded.
//!
//! This split (browser does consume, CLI does verify-via-poll) is the
//! load-bearing UX from plan §3.5.3 — the session JWT lands on the
//! CLI's polling endpoint, never in the browser. The trait's
//! `challenge` / `verify` methods naturally model the CLI half; the
//! browser-side `consume_token` is exposed as a public method on the
//! concrete `EmailLinkAuth` plugin so HTTP handlers can downcast or
//! the broker can carry an `Arc<EmailLinkAuth>` separately on AppState.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::json;

use crate::plugins::auth::{
    AuthChallenge, AuthError, AuthResponse, ChallengeParams, IdentityType, UserAuthMethod,
    VerifiedIdentity,
};
use crate::plugins::Readiness;
use crate::storage::{
    EmailConsumeOutcome, EmailRateLimitStore, EmailRequestStatus, EmailTokenStore, RateLimitOutcome,
};

const PLUGIN_NAME: &str = "email_link";
/// Magic-link token TTL. Plan §3.5.3 spec is 10 minutes.
const TOKEN_TTL_SECONDS: i64 = 600;

/// Trait abstracting the email-sending backend so tests don't depend on
/// real SES credentials. Production wiring (lettre + aws-sdk-sesv2)
/// lands in US-018 alongside the HTTP endpoints.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send a magic-link email. `to` is the recipient address;
    /// `landing_url` is the fully-formed URL the user will click
    /// (with the `#t=<token>` fragment already appended).
    async fn send_magic_link(&self, to: &str, landing_url: &str) -> Result<(), EmailSendError>;

    /// Verify the configured sender identity is current. The plugin
    /// caches the most-recent success timestamp on disk per the
    /// 24-hour TTL spec (plan §6 Tier-2 + Codex P2 #8 mitigation).
    async fn verify_sender_ready(&self) -> Result<(), EmailSendError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EmailSendError {
    #[error("send failed: {0}")]
    Send(String),
    #[error("verify failed: {0}")]
    Verify(String),
    #[error("config error: {0}")]
    Config(String),
}

impl From<EmailSendError> for AuthError {
    fn from(e: EmailSendError) -> Self {
        AuthError::Upstream(e.to_string())
    }
}

/// In-process stub used by tests — records sent emails in a Vec, never
/// makes a real network call.
pub struct StubEmailSender {
    pub sent: Mutex<Vec<(String, String)>>, // (to, landing_url)
    pub fail_send: bool,
    pub fail_verify: bool,
}

impl StubEmailSender {
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            fail_send: false,
            fail_verify: false,
        }
    }

    pub fn last_sent(&self) -> Option<(String, String)> {
        self.sent.lock().ok().and_then(|v| v.last().cloned())
    }
}

impl Default for StubEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailSender for StubEmailSender {
    async fn send_magic_link(&self, to: &str, landing_url: &str) -> Result<(), EmailSendError> {
        if self.fail_send {
            return Err(EmailSendError::Send("stub configured to fail send".into()));
        }
        let mut sent = self.sent.lock().unwrap();
        sent.push((to.to_string(), landing_url.to_string()));
        Ok(())
    }

    async fn verify_sender_ready(&self) -> Result<(), EmailSendError> {
        if self.fail_verify {
            return Err(EmailSendError::Verify(
                "stub configured to fail verify".into(),
            ));
        }
        Ok(())
    }
}

// ─── Real SES sender (Pass 1 of Option B) ───────────────────────────────────
//
// Production wiring of the EmailSender trait against AWS SES v2. Issued
// by `setup-broker-host.sh` via instance-profile creds; FROM is a verified
// identity in the broker host's account (typically noreply@<MAIL_DOMAIN>).
//
// Failure modes map to EmailSendError variants:
//   - SendEmail RPC fails / message rejected     → EmailSendError::Send
//   - GetEmailIdentity fails / SendingEnabled=false / VerificationStatus≠Success
//                                                → EmailSendError::Verify
//   - Constructor receives empty from_address    → EmailSendError::Config (lazy)
//
// The integration test in tests/ses_email_flow.rs exercises this against
// the real AWS account by sending to a unique magic-link-test-{uuid}@<domain>
// address that the SES inbound rule routes to the agentkeys-mail-* S3 bucket.

const SES_SUBJECT: &str = "Your AgentKeys sign-in link";

/// Plaintext template — magic link is appended verbatim. Kept simple +
/// inlined (no template engine dep) so the body is auditable at a glance.
fn ses_body_text(landing_url: &str) -> String {
    format!(
        "Click the link below to finish signing in to AgentKeys.\n\n\
         {landing_url}\n\n\
         The link is single-use and expires in 10 minutes. If you didn't \
         request this, you can ignore this message.\n",
    )
}

/// HTML template — minimal (no CSS, no images) to avoid spam-filter noise
/// and to keep the body identical in structure to the plaintext alternative.
fn ses_body_html(landing_url: &str) -> String {
    format!(
        "<p>Click the link below to finish signing in to AgentKeys.</p>\
         <p><a href=\"{landing_url}\">{landing_url}</a></p>\
         <p style=\"color:#888;font-size:0.9em\">The link is single-use \
         and expires in 10 minutes. If you didn't request this, you can \
         ignore this message.</p>",
    )
}

#[cfg(feature = "auth-email-link")]
pub struct SesEmailSender {
    client: aws_sdk_sesv2::Client,
    from_address: String,
}

#[cfg(feature = "auth-email-link")]
impl SesEmailSender {
    /// Construct from a pre-loaded SDK config + verified FROM address.
    /// Doesn't verify the address up front — `verify_sender_ready` does
    /// that on a 24h cadence (matches StubEmailSender's contract).
    pub fn new(sdk_config: &aws_config::SdkConfig, from_address: String) -> Self {
        Self {
            client: aws_sdk_sesv2::Client::new(sdk_config),
            from_address,
        }
    }

    /// Test/internal accessor — returns the FROM address. Used by the
    /// integration test to assert the constructor wired correctly.
    pub fn from_address(&self) -> &str {
        &self.from_address
    }
}

#[cfg(feature = "auth-email-link")]
#[async_trait]
impl EmailSender for SesEmailSender {
    async fn send_magic_link(&self, to: &str, landing_url: &str) -> Result<(), EmailSendError> {
        if self.from_address.is_empty() {
            return Err(EmailSendError::Config("from_address is empty".into()));
        }
        use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

        let subject = Content::builder()
            .data(SES_SUBJECT)
            .charset("UTF-8")
            .build()
            .map_err(|e| EmailSendError::Send(format!("build subject: {e}")))?;
        let text_part = Content::builder()
            .data(ses_body_text(landing_url))
            .charset("UTF-8")
            .build()
            .map_err(|e| EmailSendError::Send(format!("build text body: {e}")))?;
        let html_part = Content::builder()
            .data(ses_body_html(landing_url))
            .charset("UTF-8")
            .build()
            .map_err(|e| EmailSendError::Send(format!("build html body: {e}")))?;

        let body = Body::builder().text(text_part).html(html_part).build();
        let message = Message::builder().subject(subject).body(body).build();
        let dest = Destination::builder().to_addresses(to).build();
        let content = EmailContent::builder().simple(message).build();

        self.client
            .send_email()
            .from_email_address(&self.from_address)
            .destination(dest)
            .content(content)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| EmailSendError::Send(format!("ses SendEmail: {}", e.into_service_error())))
    }

    async fn verify_sender_ready(&self) -> Result<(), EmailSendError> {
        // Single explicit per-address lookup. The operator must register
        // the FROM identity explicitly via:
        //
        //   aws sesv2 create-email-identity \
        //     --email-identity $BROKER_EMAIL_FROM_ADDRESS
        //
        // (then click the verification link that SES routes to the inbound
        // S3 bucket). See scripts/operator/cloud/ses-verify-sender.sh for the helper.
        // We deliberately do NOT fall back to the domain identity — domain
        // verification grants sending rights but obscures intent; an
        // explicit per-address identity makes the verified sender visible
        // in `aws sesv2 list-email-identities`.
        let resp = self
            .client
            .get_email_identity()
            .email_identity(&self.from_address)
            .send()
            .await
            .map_err(|e| {
                EmailSendError::Verify(format!(
                    "ses GetEmailIdentity({}): {} — register via \
                     `aws sesv2 create-email-identity --email-identity {}` \
                     and click the verification link",
                    self.from_address,
                    e.into_service_error(),
                    self.from_address,
                ))
            })?;

        if !resp.verified_for_sending_status() {
            return Err(EmailSendError::Verify(format!(
                "{} exists in SES but verified_for_sending_status=false — \
                 click the verification link from the SES bootstrap email",
                self.from_address
            )));
        }
        Ok(())
    }
}

/// Persisted SES verification cache. Survives restart so debug-loops
/// don't burn SES API budget (Codex P2 #8 mitigation, V0.1-FOLLOWUPS R2-F8).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SesVerifyCache {
    pub last_verified_at: i64,
    pub sender_email: String,
}

impl SesVerifyCache {
    pub fn load(path: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), AuthError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| AuthError::Internal(format!("serialize ses-verify cache: {}", e)))?;
        std::fs::write(path, raw)
            .map_err(|e| AuthError::Internal(format!("write ses-verify cache: {}", e)))?;
        Ok(())
    }

    pub fn is_fresh(&self, now: i64, ttl_seconds: i64) -> bool {
        now - self.last_verified_at < ttl_seconds
    }
}

/// Plugin handle. Carries the email sender, the token store, the rate-
/// limit store, the HMAC key bytes (read from disk at boot), the
/// `from` address, and the SES-verify-cache path.
pub struct EmailLinkAuth {
    pub sender: Arc<dyn EmailSender>,
    pub token_store: Arc<EmailTokenStore>,
    pub rate_limit_store: Arc<EmailRateLimitStore>,
    pub from_address: String,
    pub landing_url_base: String, // e.g. "https://broker.example.com/auth/email/landing"
    pub ses_verify_cache_path: PathBuf,
    pub per_email_hourly_limit: i64,
    pub per_ip_minutely_limit: i64,
}

impl EmailLinkAuth {
    /// Construct from already-loaded dependencies.
    ///
    /// **No HMAC key.** Per `docs/arch.md` §5a.1.M Stage 1
    /// and the K1–K11 inventory in §3, the magic-link is stateful:
    /// the token is generated CSPRNG, `SHA256(token)` is keyed by
    /// `request_id` in `EmailTokenStore`, and the broker confirms
    /// single-use within TTL on click. No HMAC signature is needed —
    /// the security comes from token randomness, stateful TTL, and
    /// consume-once. (Earlier `hmac_key` field was vestigial — never
    /// used cryptographically — and was removed alongside the
    /// BROKER_EMAIL_HMAC_KEY_PATH env var to align with arch.md.)
    #[allow(clippy::too_many_arguments)] // 8 deps; refactoring into a builder hides nothing
    pub fn new(
        sender: Arc<dyn EmailSender>,
        token_store: Arc<EmailTokenStore>,
        rate_limit_store: Arc<EmailRateLimitStore>,
        from_address: impl Into<String>,
        landing_url_base: impl Into<String>,
        ses_verify_cache_path: PathBuf,
        per_email_hourly_limit: i64,
        per_ip_minutely_limit: i64,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            sender,
            token_store,
            rate_limit_store,
            from_address: from_address.into(),
            landing_url_base: landing_url_base.into(),
            ses_verify_cache_path,
            per_email_hourly_limit,
            per_ip_minutely_limit,
        })
    }

    /// Browser-side: consume a clicked-link token. Called by the
    /// `/v1/auth/email/verify` HTTP handler in US-018. On success, the
    /// caller mints a session JWT and calls `mark_verified`.
    pub async fn consume_token(&self, raw_token: &str) -> Result<EmailConsumeOutcome, AuthError> {
        let now = unix_now()?;
        self.token_store.consume_token(raw_token, now)
    }

    /// Browser-side: mark the request_id as verified (called after
    /// `consume_token` succeeded + session JWT minted).
    pub fn mark_verified(
        &self,
        request_id: &str,
        session_jwt: &str,
        omni_account: &str,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        self.token_store
            .mark_verified(request_id, session_jwt, omni_account, expires_at)
    }
}

#[async_trait]
impl UserAuthMethod for EmailLinkAuth {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn ready(&self) -> Readiness {
        // Three things must be true for ready:
        // 1. token store is writable
        // 2. rate-limit store is writable (proxied via token_store check;
        //    both share the same SQLite-backing semantics in dev, separate
        //    files in production)
        // 3. SES sender verified within 24h (cache file present + fresh)
        if !self.token_store.writable() {
            return Readiness::unready("email_tokens table not writable");
        }
        if let Some(cache) = SesVerifyCache::load(&self.ses_verify_cache_path) {
            let now = unix_now().unwrap_or(0);
            if cache.is_fresh(now, 24 * 3600) {
                return Readiness::ready_with(format!(
                    "email_link: SES sender {} verified ≤ 24h ago",
                    cache.sender_email
                ));
            } else {
                return Readiness::degraded(format!(
                    "email_link: SES sender {} cache stale (>{}h)",
                    cache.sender_email, 24
                ));
            }
        }
        Readiness::degraded(format!(
            "email_link: SES verification cache absent at {}",
            self.ses_verify_cache_path.display()
        ))
    }

    /// Initiate a new request. `extras` MUST carry `email` (string).
    async fn challenge(&self, params: ChallengeParams) -> Result<AuthChallenge, AuthError> {
        let email = params
            .extras
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidRequest("missing field: email".into()))?
            .trim()
            .to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(AuthError::InvalidRequest(format!(
                "malformed email: {:?}",
                email
            )));
        }
        let now = unix_now()?;

        // Rate limits — per-email per-hour AND per-IP per-minute (if IP given).
        let email_bucket = format!("email:{}", email);
        match self.rate_limit_store.check_and_increment(
            &email_bucket,
            now,
            3600,
            self.per_email_hourly_limit,
        )? {
            RateLimitOutcome::Allowed { .. } => {}
            RateLimitOutcome::Denied {
                retry_after_seconds,
            } => {
                return Err(AuthError::RateLimited(format!(
                    "per-email rate limit exceeded; retry in {}s",
                    retry_after_seconds
                )));
            }
        }
        if let Some(ip) = params.source_ip.as_deref() {
            let ip_bucket = format!("ip:{}", ip);
            if let RateLimitOutcome::Denied {
                retry_after_seconds,
            } = self.rate_limit_store.check_and_increment(
                &ip_bucket,
                now,
                60,
                self.per_ip_minutely_limit,
            )? {
                return Err(AuthError::RateLimited(format!(
                    "per-IP rate limit exceeded; retry in {}s",
                    retry_after_seconds
                )));
            }
        }

        let request_id = format!("eml-{}", random_id_hex(12));
        let token = random_token_b64url(32);
        let expires_at = now + TOKEN_TTL_SECONDS;

        self.token_store
            .issue(&token, &request_id, &email, now, expires_at)?;

        // Build the magic-link URL. Token rides in the URL fragment so
        // it never appears in the server's HTTP request line.
        let landing_url = format!("{}#t={}", self.landing_url_base, token);
        self.sender.send_magic_link(&email, &landing_url).await?;

        Ok(AuthChallenge {
            request_id: request_id.clone(),
            expires_in_seconds: TOKEN_TTL_SECONDS as u64,
            extras: json!({
                "from_address": self.from_address,
                "poll_url": format!("/v1/auth/email/status/{}", request_id),
                // For tests + offline diagnostics: surface the landing URL.
                // In production this is OPTIONAL — the runbook recommends
                // disabling via a config flag in non-dev mode (US-018).
                "_dev_landing_url": landing_url,
            }),
        })
    }

    /// CLI poll — return the staged `VerifiedIdentity` once the
    /// browser-side `consume_token` + `mark_verified` has fired.
    /// `response.extras` is unused for this method (the request_id IS
    /// the only input).
    async fn verify(&self, response: AuthResponse) -> Result<VerifiedIdentity, AuthError> {
        match self.token_store.peek_status(&response.request_id)? {
            EmailRequestStatus::Pending => Err(AuthError::Unauthorized(
                "email link not yet clicked; CLI should keep polling".into(),
            )),
            EmailRequestStatus::Verified { omni_account, .. } => {
                // The plugin's verify() returns identity_type+value; the
                // session JWT was already minted by the browser-side
                // handler so we don't re-mint here. The HTTP handler
                // (US-018) reads the session_jwt from peek_status
                // separately when wrapping for the CLI response.
                Ok(VerifiedIdentity {
                    identity_type: IdentityType::Email,
                    // Use omni_account as the canonical identity_value
                    // the broker carries forward — it preserves the
                    // email→omni mapping without re-leaking the email.
                    identity_value: omni_account,
                })
            }
            EmailRequestStatus::Failed { reason } => Err(AuthError::Unauthorized(format!(
                "email verify failed: {}",
                reason
            ))),
            EmailRequestStatus::Unknown => Err(AuthError::InvalidRequest(format!(
                "unknown request_id: {}",
                response.request_id
            ))),
        }
    }
}

fn unix_now() -> Result<i64, AuthError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AuthError::Internal(format!("clock before unix epoch: {}", e)))?
        .as_secs() as i64)
}

fn random_id_hex(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    getrandom::getrandom(&mut buf).expect("OS RNG failed");
    hex::encode(buf)
}

fn random_token_b64url(byte_len: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut buf = vec![0u8; byte_len];
    getrandom::getrandom(&mut buf).expect("OS RNG failed");
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_plugin() -> (EmailLinkAuth, Arc<StubEmailSender>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let token_store = Arc::new(EmailTokenStore::open_in_memory().unwrap());
        let rate_limit_store = Arc::new(EmailRateLimitStore::open_in_memory().unwrap());
        let sender = Arc::new(StubEmailSender::new());
        let plugin = EmailLinkAuth::new(
            sender.clone(),
            token_store,
            rate_limit_store,
            "broker@example.com",
            "https://broker.test/auth/email/landing",
            tmp.path().join("ses-verify.json"),
            5,
            30,
        )
        .unwrap();
        (plugin, sender, tmp)
    }

    #[tokio::test]
    async fn name_is_stable() {
        let (p, _s, _t) = make_plugin();
        assert_eq!(p.name(), "email_link");
    }

    #[tokio::test]
    async fn challenge_sends_email_with_fragment_token() {
        let (p, sender, _t) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({ "email": "Alice@Example.COM" }),
            })
            .await
            .unwrap();
        assert!(challenge.request_id.starts_with("eml-"));
        let (to, landing) = sender.last_sent().expect("expected an email send");
        assert_eq!(to, "alice@example.com");
        assert!(landing.contains("#t="));
        assert!(landing.starts_with("https://broker.test/"));
        // Token in fragment ONLY — never in the path/query.
        let after_fragment = landing.split_once("#t=").unwrap().1;
        assert!(!after_fragment.contains('?'));
    }

    #[tokio::test]
    async fn challenge_rejects_malformed_email() {
        let (p, _s, _t) = make_plugin();
        let res = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({ "email": "no-at-sign" }),
            })
            .await;
        assert!(matches!(res, Err(AuthError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn rate_limit_per_email_enforced() {
        let (p, _s, _t) = make_plugin();
        for _ in 0..5 {
            p.challenge(ChallengeParams {
                source_ip: None,
                extras: json!({ "email": "alice@example.com" }),
            })
            .await
            .unwrap();
        }
        let res = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({ "email": "alice@example.com" }),
            })
            .await;
        assert!(matches!(res, Err(AuthError::RateLimited(_))));
    }

    #[tokio::test]
    async fn full_flow_via_consume_token_and_verify_poll() {
        let (p, sender, _t) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({ "email": "alice@example.com" }),
            })
            .await
            .unwrap();
        let (_, landing_url) = sender.last_sent().unwrap();
        // Extract token from fragment.
        let token = landing_url.split_once("#t=").unwrap().1.to_string();

        // Browser-side: consume.
        let outcome = p.consume_token(&token).await.unwrap();
        match outcome {
            EmailConsumeOutcome::Consumed { request_id, email } => {
                assert_eq!(request_id, challenge.request_id);
                assert_eq!(email, "alice@example.com");
                p.mark_verified(&request_id, "eyJfake", "0xomni", 9_999_999_999)
                    .unwrap();
            }
            other => panic!("expected Consumed, got {:?}", other),
        }

        // CLI poll: verify resolves to the staged identity.
        let identity = p
            .verify(AuthResponse {
                request_id: challenge.request_id,
                extras: json!({}),
            })
            .await
            .unwrap();
        assert_eq!(identity.identity_type, IdentityType::Email);
        assert_eq!(identity.identity_value, "0xomni");
    }

    #[tokio::test]
    async fn replay_token_returns_not_found_or_consumed() {
        let (p, sender, _t) = make_plugin();
        p.challenge(ChallengeParams {
            source_ip: None,
            extras: json!({ "email": "alice@example.com" }),
        })
        .await
        .unwrap();
        let (_, landing) = sender.last_sent().unwrap();
        let token = landing.split_once("#t=").unwrap().1.to_string();
        let _ = p.consume_token(&token).await.unwrap();
        let replay = p.consume_token(&token).await.unwrap();
        assert_eq!(replay, EmailConsumeOutcome::NotFoundOrConsumed);
    }

    #[tokio::test]
    async fn verify_pending_returns_unauthorized() {
        let (p, _s, _t) = make_plugin();
        let challenge = p
            .challenge(ChallengeParams {
                source_ip: None,
                extras: json!({ "email": "alice@example.com" }),
            })
            .await
            .unwrap();
        // No consume, no mark_verified — status is Pending.
        let res = p
            .verify(AuthResponse {
                request_id: challenge.request_id,
                extras: json!({}),
            })
            .await;
        assert!(matches!(res, Err(AuthError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn verify_unknown_request_id_returns_invalid_request() {
        let (p, _s, _t) = make_plugin();
        let res = p
            .verify(AuthResponse {
                request_id: "never-issued".into(),
                extras: json!({}),
            })
            .await;
        assert!(matches!(res, Err(AuthError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn ready_degraded_when_cache_absent() {
        let (p, _s, _t) = make_plugin();
        // No cache file written — plugin reports Degraded.
        let r = p.ready();
        assert!(r.is_degraded(), "expected Degraded, got {:?}", r);
    }

    #[tokio::test]
    async fn ready_ready_when_cache_fresh() {
        let (p, _s, _t) = make_plugin();
        let now = unix_now().unwrap();
        let cache = SesVerifyCache {
            last_verified_at: now,
            sender_email: "broker@example.com".into(),
        };
        cache.save(&p.ses_verify_cache_path).unwrap();
        assert!(p.ready().is_ready());
    }

    #[tokio::test]
    async fn rate_limit_per_ip_enforced() {
        let (p, _s, _t) = make_plugin();
        // 30 IP requests/min — but each request is also +1 against the
        // per-email bucket. With a fresh email each time we isolate IP.
        for i in 0..30 {
            p.challenge(ChallengeParams {
                source_ip: Some("10.0.0.1".into()),
                extras: json!({ "email": format!("user{}@example.com", i) }),
            })
            .await
            .unwrap();
        }
        let res = p
            .challenge(ChallengeParams {
                source_ip: Some("10.0.0.1".into()),
                extras: json!({ "email": "user-extra@example.com" }),
            })
            .await;
        assert!(matches!(res, Err(AuthError::RateLimited(_))));
    }

    // ─── SesEmailSender body composition (US-3) ──────────────────────────
    // No AWS calls — pure string-composition checks. Guards the operator's
    // "click the link" path: if the magic link doesn't appear in both
    // alternatives, the recipient can't sign in regardless of SES delivery.

    #[test]
    fn ses_subject_is_non_empty() {
        assert!(!SES_SUBJECT.is_empty());
    }

    #[test]
    fn ses_text_body_contains_landing_url() {
        let url = "https://broker.example/auth/email/landing#t=ABC.DEF";
        let body = ses_body_text(url);
        assert!(
            body.contains(url),
            "text body must contain landing URL: {body}"
        );
        assert!(
            body.contains("AgentKeys") || body.contains("agentkeys"),
            "text body should mention the product"
        );
    }

    #[test]
    fn ses_html_body_contains_landing_url_twice() {
        // Once in href attribute, once as visible link text — keeps the
        // body usable in clients that strip <a> wrapping.
        let url = "https://broker.example/auth/email/landing#t=XYZ.123";
        let body = ses_body_html(url);
        let occurrences = body.matches(url).count();
        assert!(
            occurrences >= 2,
            "html body should contain landing URL at least twice (href + text), got {}: {}",
            occurrences,
            body
        );
    }

    #[test]
    fn ses_text_and_html_alternatives_both_present() {
        // Sanity-check: body composers don't return the same string —
        // SES wraps them as multipart/alternative so they must differ.
        let url = "https://example.test/landing#t=tok";
        assert_ne!(
            ses_body_text(url),
            ses_body_html(url),
            "text and html alternatives must differ"
        );
    }
}
