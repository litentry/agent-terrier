use async_trait::async_trait;

use crate::error::{BrokerError, BrokerResult};

#[derive(Debug, Clone)]
pub struct AssumedCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration_unix: i64,
}

/// STS client surface used by broker handlers.
///
/// Post-issue-#71 the only mint path is `AssumeRoleWithWebIdentity` — the
/// JWT authenticates the call, the broker holds zero AWS principals at
/// runtime for credential minting. The legacy `AssumeRole` method was
/// removed in the OIDC-only migration; the trait now mirrors the actual
/// behaviour of the broker mint flow + the optional startup probe.
#[async_trait]
pub trait StsClient: Send + Sync {
    /// `sts:AssumeRoleWithWebIdentity` — federated mint path. The JWT
    /// (signed by the broker's OIDC keypair) authenticates the call.
    /// AWS reads the `https://aws.amazon.com/tags` claim to populate
    /// session PrincipalTags, which the bucket policy uses to enforce
    /// per-user isolation.
    async fn assume_role_with_web_identity(
        &self,
        role_arn: &str,
        session_name: &str,
        web_identity_token: &str,
        duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials>;

    /// `sts:GetCallerIdentity` — used by the optional startup probe to
    /// confirm the SDK has *some* credentials available (so misconfigured
    /// hosts fail fast instead of erroring on the first mint). Skip with
    /// `--skip-startup-check` when running creds-free.
    async fn caller_identity_ok(&self) -> BrokerResult<()>;
}

pub struct AwsStsClient {
    client: aws_sdk_sts::Client,
}

impl AwsStsClient {
    /// Construct a client using the AWS SDK's default credential provider
    /// chain. Honors, in order: env vars (`AWS_ACCESS_KEY_ID` etc.), shared
    /// credentials file (`~/.aws/credentials` + `AWS_PROFILE`), assume-role
    /// chains in `~/.aws/config`, and (on EC2) IMDS instance profile.
    ///
    /// Post-issue-#71, the broker no longer needs **any** AWS credentials
    /// for the mint flow itself — `AssumeRoleWithWebIdentity` is
    /// JWT-authenticated. The default chain is still consulted for the
    /// optional `caller_identity_ok` startup probe; pass
    /// `--skip-startup-check` if running creds-free is intentional.
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
    async fn assume_role_with_web_identity(
        &self,
        role_arn: &str,
        session_name: &str,
        web_identity_token: &str,
        duration_seconds: i32,
    ) -> BrokerResult<AssumedCredentials> {
        let resp = self
            .client
            .assume_role_with_web_identity()
            .role_arn(role_arn)
            .role_session_name(session_name)
            .web_identity_token(web_identity_token)
            .duration_seconds(duration_seconds)
            .send()
            .await
            .map_err(|e| {
                // Flatten the SDK error's source chain — `DispatchFailure`
                // and friends render uselessly via `{}` alone, the real
                // cause (DNS / TCP / TLS / no-connector) is in source().
                let mut msg = format!("assume_role_with_web_identity: {e}");
                let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
                while let Some(next) = src {
                    msg.push_str(&format!(" | caused by: {next}"));
                    src = next.source();
                }
                BrokerError::StsError(msg)
            })?;

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

    /// Identity check passes, but the assume call fails. Models the broker
    /// whose default-chain creds work for `GetCallerIdentity` (so startup
    /// probe passes) yet `AssumeRoleWithWebIdentity` is rejected (e.g.
    /// JWT issuer not registered with AWS IAM, audience mismatch).
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

    async fn caller_identity_ok(&self) -> BrokerResult<()> {
        (self.identity)()
    }
}
