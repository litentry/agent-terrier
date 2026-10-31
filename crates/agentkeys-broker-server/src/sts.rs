use async_trait::async_trait;

use crate::error::{BrokerError, BrokerResult};

#[derive(Debug, Clone)]
pub struct AssumedCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration_unix: i64,
}

/// External credential exchange injected by an embedding application.
/// The local binary installs `UnavailableStsClient` and performs no exchange.
#[async_trait]
pub trait StsClient: Send + Sync {
    /// Exchange the signed identity token for bounded external credentials.
    async fn assume_role_with_web_identity(
        &self,
        role_arn: &str,
        session_name: &str,
        web_identity_token: &str,
        duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials>;

    /// Exchange with an optional narrowing policy owned by the adapter contract.
    async fn assume_role_scoped(
        &self,
        role: &str,
        session_name: &str,
        web_identity_token: &str,
        duration_seconds: i32,
        session_policy: Option<&str>,
    ) -> BrokerResult<AssumedCredentials>;

    /// Explicit readiness probe for an injected external adapter.
    async fn caller_identity_ok(&self) -> BrokerResult<()>;

    /// Whether the adapter supports the caller's inline narrowing policy.
    fn supports_inline_session_policy(&self) -> bool;
}

pub struct UnavailableStsClient;

#[async_trait]
impl StsClient for UnavailableStsClient {
    async fn assume_role_with_web_identity(
        &self,
        _role: &str,
        _session: &str,
        _token: &str,
        _duration: i32,
    ) -> BrokerResult<AssumedCredentials> {
        Err(BrokerError::Unavailable(
            "external credential exchange is not configured".into(),
        ))
    }

    async fn assume_role_scoped(
        &self,
        _role: &str,
        _session: &str,
        _token: &str,
        _duration: i32,
        _policy: Option<&str>,
    ) -> BrokerResult<AssumedCredentials> {
        Err(BrokerError::Unavailable(
            "external credential exchange is not configured".into(),
        ))
    }

    async fn caller_identity_ok(&self) -> BrokerResult<()> {
        Err(BrokerError::Unavailable(
            "external credential exchange is not configured".into(),
        ))
    }

    fn supports_inline_session_policy(&self) -> bool {
        false
    }
}

/// Test-only stub. Each closure is invoked per call so tests can simulate
/// transient failures, count invocations, etc.
#[cfg(any(test, feature = "test-stub"))]
pub struct StubStsClient {
    assume: Box<dyn Fn() -> BrokerResult<AssumedCredentials> + Send + Sync>,
    identity: Box<dyn Fn() -> BrokerResult<()> + Send + Sync>,
}

#[cfg(any(test, feature = "test-stub"))]
impl StubStsClient {
    pub fn ok(creds: AssumedCredentials) -> Self {
        Self {
            assume: Box::new(move || Ok(creds.clone())),
            identity: Box::new(|| Ok(())),
        }
    }

    pub fn failing(message: impl Into<String>) -> Self {
        let msg = message.into();
        let assume_msg = msg.clone();
        let identity_msg = msg;
        Self {
            assume: Box::new(move || Err(BrokerError::StsError(assume_msg.clone()))),
            identity: Box::new(move || Err(BrokerError::StsError(identity_msg.clone()))),
        }
    }

    /// Readiness succeeds while the external exchange rejects the request.
    pub fn assume_failing(message: impl Into<String>) -> Self {
        let msg = message.into();
        Self {
            assume: Box::new(move || Err(BrokerError::StsError(msg.clone()))),
            identity: Box::new(|| Ok(())),
        }
    }
}

#[cfg(any(test, feature = "test-stub"))]
#[async_trait]
impl StsClient for StubStsClient {
    async fn assume_role_with_web_identity(
        &self,
        _role_arn: &str,
        _session_name: &str,
        _web_identity_token: &str,
        _duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials> {
        (self.assume)()
    }

    async fn assume_role_scoped(
        &self,
        _role: &str,
        _session_name: &str,
        _web_identity_token: &str,
        _duration_seconds: i32,
        _session_policy: Option<&str>,
    ) -> BrokerResult<AssumedCredentials> {
        (self.assume)()
    }

    async fn caller_identity_ok(&self) -> BrokerResult<()> {
        (self.identity)()
    }

    fn supports_inline_session_policy(&self) -> bool {
        true
    }
}
