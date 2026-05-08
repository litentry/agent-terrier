use std::path::PathBuf;

use crate::env;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub data_role_arn: String,
    pub backend_url: String,
    pub audit_db_path: PathBuf,
    pub aws_region: String,
    pub session_duration_seconds: i32,
    /// Timeout for HTTP calls to the backend's /session/validate.
    pub backend_request_timeout_seconds: u64,
    /// Hard cap on graceful-shutdown drain time.
    pub shutdown_grace_seconds: u64,
    /// Public URL the broker advertises as the OIDC issuer.
    pub oidc_issuer: String,
    /// Path to the persisted OIDC ES256 keypair (purpose=oidc).
    pub oidc_keypair_path: PathBuf,
    /// TTL of OIDC JWTs minted for STS.
    pub oidc_jwt_ttl_seconds: u64,
}

impl BrokerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        // Issue #71 OIDC-only migration: the broker no longer accepts static
        // IAM-user credentials. AssumeRoleWithWebIdentity is JWT-authenticated
        // and the `caller_identity_ok` startup probe (when enabled) reads
        // creds from the SDK's default chain — same as before but without
        // the DAEMON_ACCESS_KEY_ID escape hatch.
        //
        // BROKER_DATA_ROLE_ARN can be derived from ACCOUNT_ID. Operator can
        // still override. BROKER_AGENT_ROLE_ARN is accepted as a legacy
        // alias for callers that haven't migrated.
        let data_role_arn = std::env::var(env::BROKER_DATA_ROLE_ARN)
            .or_else(|_| std::env::var(env::BROKER_AGENT_ROLE_ARN))
            .or_else(|_| {
                std::env::var(env::ACCOUNT_ID)
                    .map(|account_id| format!("arn:aws:iam::{}:role/agentkeys-data-role", account_id))
            })
            .map_err(|_| anyhow::anyhow!(
                "missing required env var: set {} explicitly (legacy: {}), or set {} and the broker will derive arn:aws:iam::$ACCOUNT_ID:role/agentkeys-data-role",
                env::BROKER_DATA_ROLE_ARN,
                env::BROKER_AGENT_ROLE_ARN,
                env::ACCOUNT_ID,
            ))?;

        let backend_url = required_env(env::BROKER_BACKEND_URL)?;

        let audit_db_path = std::env::var(env::BROKER_AUDIT_DB_PATH)
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_audit_db_path);

        // BROKER_AWS_REGION wins; falls back to legacy REGION before defaulting.
        let aws_region = first_env(&[env::BROKER_AWS_REGION, env::REGION])
            .unwrap_or_else(|| "us-east-1".to_string());

        let session_duration_seconds = parse_int_env_with_default(
            env::BROKER_SESSION_DURATION_SECONDS,
            3600,
        )?;
        if !(900..=43_200).contains(&session_duration_seconds) {
            anyhow::bail!(
                "{} must be between 900 and 43200, got {}",
                env::BROKER_SESSION_DURATION_SECONDS,
                session_duration_seconds
            );
        }

        let backend_request_timeout_seconds = parse_int_env_with_default(
            env::BROKER_BACKEND_TIMEOUT_SECONDS,
            10u64,
        )?;

        let shutdown_grace_seconds = parse_int_env_with_default(
            env::BROKER_SHUTDOWN_GRACE_SECONDS,
            30u64,
        )?;

        let oidc_issuer = required_env(env::BROKER_OIDC_ISSUER)?;
        let oidc_keypair_path = std::env::var(env::BROKER_OIDC_KEYPAIR_PATH)
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(crate::oidc::OidcKeypair::default_path);

        let oidc_jwt_ttl_seconds = parse_int_env_with_default(
            env::BROKER_OIDC_JWT_TTL_SECONDS,
            300u64,
        )?;
        if !(60..=3_600).contains(&oidc_jwt_ttl_seconds) {
            anyhow::bail!(
                "{} must be between 60 and 3600, got {}",
                env::BROKER_OIDC_JWT_TTL_SECONDS,
                oidc_jwt_ttl_seconds
            );
        }

        Ok(Self {
            data_role_arn,
            backend_url,
            audit_db_path,
            aws_region,
            session_duration_seconds,
            backend_request_timeout_seconds,
            shutdown_grace_seconds,
            oidc_issuer,
            oidc_keypair_path,
            oidc_jwt_ttl_seconds,
        })
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow::anyhow!("missing required env var: {}", name))
}

/// Return the value of the first env var in `names` that is set and non-empty.
fn first_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Parse an env var as `T`, defaulting if unset. Refuses to boot on parse failure.
fn parse_int_env_with_default<T>(name: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr + std::fmt::Display + Copy,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(s) => s.parse::<T>().map_err(|e| {
            anyhow::anyhow!("{}={:?} could not be parsed: {}", name, s, e)
        }),
        Err(_) => Ok(default),
    }
}

fn default_audit_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".agentkeys").join("broker").join("audit.sqlite")
}
