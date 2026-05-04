use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Optional. When *both* `daemon_access_key_id` and
    /// `daemon_secret_access_key` are set, the broker uses static IAM-user
    /// keys (legacy path). When either is unset, the broker falls back to
    /// the AWS SDK's default credential chain — picking up `AWS_PROFILE`
    /// from `~/.aws/credentials`, an EC2 instance profile via IMDS, etc.
    /// The chain path is preferred for new deployments.
    pub daemon_access_key_id: Option<String>,
    pub daemon_secret_access_key: Option<String>,
    pub data_role_arn: String,
    pub backend_url: String,
    pub audit_db_path: PathBuf,
    pub aws_region: String,
    pub session_duration_seconds: i32,
    /// Timeout for HTTP calls to the backend's /session/validate. A hung
    /// backend would otherwise pin a tokio task indefinitely.
    pub backend_request_timeout_seconds: u64,
    /// Hard cap on graceful-shutdown drain time. After SIGTERM, in-flight
    /// requests get this many seconds before the process exits anyway.
    pub shutdown_grace_seconds: u64,
    /// Public URL the broker advertises as the OIDC issuer (`iss` claim,
    /// discovery doc `issuer` field, `jwks_uri` prefix). AWS IAM
    /// `create-open-id-connect-provider` requires this to be a stable HTTPS
    /// URL in production; localhost HTTP works for local dev.
    pub oidc_issuer: String,
    /// Path to the persisted ES256 keypair (mode 0600). Defaults to
    /// `~/.agentkeys/broker/oidc-keypair.json`.
    pub oidc_keypair_path: PathBuf,
    /// Time-to-live (seconds) for minted OIDC JWTs. AWS STS requires the
    /// token to be valid at the moment of exchange but no longer than the
    /// role's max session duration; 300s mirrors the TS oidc-stub default.
    pub oidc_jwt_ttl_seconds: u64,
}

impl BrokerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        // DAEMON_ACCESS_KEY_ID / DAEMON_SECRET_ACCESS_KEY are now optional.
        // When both are present, the broker uses them directly (legacy path
        // matching scripts/stage6-demo-env.sh). When either is missing, the
        // broker delegates credential resolution to the AWS SDK's default
        // chain — `AWS_PROFILE` (from `awsp` or your shell), `~/.aws/`
        // shared files, or EC2 IMDS instance profile. The chain path is the
        // recommended one for new deployments.
        let daemon_access_key_id = first_env(&[
            "DAEMON_ACCESS_KEY_ID",
            "BROKER_DAEMON_ACCESS_KEY_ID",
        ]);
        let daemon_secret_access_key = first_env(&[
            "DAEMON_SECRET_ACCESS_KEY",
            "BROKER_DAEMON_SECRET_ACCESS_KEY",
        ]);
        if daemon_access_key_id.is_some() != daemon_secret_access_key.is_some() {
            anyhow::bail!(
                "DAEMON_ACCESS_KEY_ID and DAEMON_SECRET_ACCESS_KEY must be set together \
                 (or both unset to use the AWS SDK default credential chain via AWS_PROFILE)."
            );
        }
        // BROKER_DATA_ROLE_ARN can be derived from ACCOUNT_ID for the
        // canonical Stage 6 role name. Operator can still override.
        // BROKER_AGENT_ROLE_ARN is accepted as a fallback for callers
        // that haven't migrated yet (renamed 2026-04-28: agentkeys-agent
        // → agentkeys-data-role to disambiguate from the project's
        // "agent" terminology).
        let data_role_arn = std::env::var("BROKER_DATA_ROLE_ARN")
            .or_else(|_| std::env::var("BROKER_AGENT_ROLE_ARN"))
            .or_else(|_| {
                std::env::var("ACCOUNT_ID")
                    .map(|account_id| format!("arn:aws:iam::{}:role/agentkeys-data-role", account_id))
            })
            .map_err(|_| anyhow::anyhow!(
                "missing required env var: set BROKER_DATA_ROLE_ARN explicitly (legacy: BROKER_AGENT_ROLE_ARN), or set ACCOUNT_ID and the broker will derive arn:aws:iam::$ACCOUNT_ID:role/agentkeys-data-role"
            ))?;
        let backend_url = required_env("BROKER_BACKEND_URL")?;
        let audit_db_path = std::env::var("BROKER_AUDIT_DB_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_audit_db_path);
        // BROKER_AWS_REGION wins; falls back to REGION (which the rest of
        // the agentKeys runbook uses) before defaulting to us-east-1.
        let aws_region = first_env(&["BROKER_AWS_REGION", "REGION"])
            .unwrap_or_else(|| "us-east-1".to_string());
        let session_duration_seconds = match std::env::var("BROKER_SESSION_DURATION_SECONDS") {
            Ok(s) => s.parse::<i32>().map_err(|e| {
                anyhow::anyhow!(
                    "BROKER_SESSION_DURATION_SECONDS={:?} could not be parsed as integer: {}",
                    s,
                    e
                )
            })?,
            Err(_) => 3600,
        };

        if !(900..=43_200).contains(&session_duration_seconds) {
            anyhow::bail!(
                "BROKER_SESSION_DURATION_SECONDS must be between 900 and 43200, got {}",
                session_duration_seconds
            );
        }

        let backend_request_timeout_seconds = match std::env::var("BROKER_BACKEND_TIMEOUT_SECONDS") {
            Ok(s) => s.parse::<u64>().map_err(|e| {
                anyhow::anyhow!(
                    "BROKER_BACKEND_TIMEOUT_SECONDS={:?} could not be parsed: {}",
                    s,
                    e
                )
            })?,
            Err(_) => 10,
        };

        let shutdown_grace_seconds = match std::env::var("BROKER_SHUTDOWN_GRACE_SECONDS") {
            Ok(s) => s.parse::<u64>().map_err(|e| {
                anyhow::anyhow!(
                    "BROKER_SHUTDOWN_GRACE_SECONDS={:?} could not be parsed: {}",
                    s,
                    e
                )
            })?,
            Err(_) => 30,
        };

        let oidc_issuer = std::env::var("BROKER_OIDC_ISSUER")
            .unwrap_or_else(|_| "https://oidc.agentkeys.dev".to_string());
        let oidc_keypair_path = std::env::var("BROKER_OIDC_KEYPAIR_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(crate::oidc::OidcKeypair::default_path);
        let oidc_jwt_ttl_seconds = match std::env::var("BROKER_OIDC_JWT_TTL_SECONDS") {
            Ok(s) => s.parse::<u64>().map_err(|e| {
                anyhow::anyhow!(
                    "BROKER_OIDC_JWT_TTL_SECONDS={:?} could not be parsed: {}",
                    s,
                    e
                )
            })?,
            Err(_) => 300,
        };
        if !(60..=3_600).contains(&oidc_jwt_ttl_seconds) {
            anyhow::bail!(
                "BROKER_OIDC_JWT_TTL_SECONDS must be between 60 and 3600, got {}",
                oidc_jwt_ttl_seconds
            );
        }

        Ok(Self {
            daemon_access_key_id,
            daemon_secret_access_key,
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

fn default_audit_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".agentkeys").join("broker").join("audit.sqlite")
}
