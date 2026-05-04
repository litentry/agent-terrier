use async_trait::async_trait;

use crate::error::{BrokerError, BrokerResult};

#[derive(Debug, Clone)]
pub struct AssumedCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration_unix: i64,
}

#[async_trait]
pub trait StsClient: Send + Sync {
    async fn assume_role(
        &self,
        role_arn: &str,
        session_name: &str,
        duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials>;

    async fn caller_identity_ok(&self) -> BrokerResult<()>;
}

pub struct AwsStsClient {
    client: aws_sdk_sts::Client,
}

impl AwsStsClient {
    /// Construct a client backed by *static* IAM-user keys.
    ///
    /// Legacy / explicit-config path. New deployments should prefer
    /// [`Self::with_default_chain`] so the AWS SDK can pick up credentials
    /// from a named profile (`~/.aws/credentials` + `AWS_PROFILE`), an EC2
    /// instance profile (IMDS), or another link in the default provider
    /// chain — no long-lived keys in the broker's process environment.
    pub async fn from_keys(
        access_key_id: &str,
        secret_access_key: &str,
        region: &str,
    ) -> Self {
        let creds = aws_credential_types::Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "agentkeys-broker-static",
        );
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .credentials_provider(creds)
            .load()
            .await;
        Self { client: aws_sdk_sts::Client::new(&config) }
    }

    /// Construct a client using the AWS SDK's default credential provider
    /// chain. Honors, in order: env vars (`AWS_ACCESS_KEY_ID` etc.), shared
    /// credentials file (`~/.aws/credentials` + `AWS_PROFILE`), assume-role
    /// chains in `~/.aws/config`, and (on EC2) IMDS instance profile.
    ///
    /// This is the recommended path for both local-dev (operators run
    /// `awsp agentkeys-daemon` to set `AWS_PROFILE`, then start the broker)
    /// and EC2 deployments (attach an instance profile, no env vars at all).
    pub async fn with_default_chain(region: &str) -> Self {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        Self { client: aws_sdk_sts::Client::new(&config) }
    }
}

#[async_trait]
impl StsClient for AwsStsClient {
    async fn assume_role(
        &self,
        role_arn: &str,
        session_name: &str,
        duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials> {
        let resp = self
            .client
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(session_name)
            .duration_seconds(duration_seconds)
            .send()
            .await
            .map_err(|e| BrokerError::StsError(format!("assume_role: {}", e)))?;

        let creds = resp
            .credentials
            .ok_or_else(|| BrokerError::StsError("STS returned no credentials".into()))?;

        Ok(AssumedCredentials {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration_unix: creds.expiration.secs(),
        })
    }

    async fn caller_identity_ok(&self) -> BrokerResult<()> {
        self.client
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| BrokerError::StsError(format!("get_caller_identity: {}", e)))?;
        Ok(())
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

    /// Identity check passes, but assume_role fails. Models the broker that
    /// can introspect itself (creds valid for GetCallerIdentity) yet cannot
    /// assume the agent role (e.g., missing IAM trust).
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
    async fn assume_role(
        &self,
        _role_arn: &str,
        _session_name: &str,
        _duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials> {
        (self.assume)()
    }

    async fn caller_identity_ok(&self) -> BrokerResult<()> {
        (self.identity)()
    }
}
