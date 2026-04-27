use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub daemon_access_key_id: String,
    pub daemon_secret_access_key: String,
    pub agent_role_arn: String,
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
}

impl BrokerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        // DAEMON_ACCESS_KEY_ID / DAEMON_SECRET_ACCESS_KEY are the same vars
        // scripts/stage6-demo-env.sh reads — operator persists them once in
        // ~/.zshenv and both the legacy demo script and the broker pick them
        // up. BROKER_DAEMON_* names are accepted as a fallback for callers
        // that prefer the explicit prefix.
        let daemon_access_key_id = first_env(&[
            "DAEMON_ACCESS_KEY_ID",
            "BROKER_DAEMON_ACCESS_KEY_ID",
        ])
        .ok_or_else(|| {
            anyhow::anyhow!("missing required env var: DAEMON_ACCESS_KEY_ID (or BROKER_DAEMON_ACCESS_KEY_ID)")
        })?;
        let daemon_secret_access_key = first_env(&[
            "DAEMON_SECRET_ACCESS_KEY",
            "BROKER_DAEMON_SECRET_ACCESS_KEY",
        ])
        .ok_or_else(|| {
            anyhow::anyhow!("missing required env var: DAEMON_SECRET_ACCESS_KEY (or BROKER_DAEMON_SECRET_ACCESS_KEY)")
        })?;
        // BROKER_AGENT_ROLE_ARN can be derived from ACCOUNT_ID for the
        // canonical Stage 6 role name. Operator can still override.
        let agent_role_arn = std::env::var("BROKER_AGENT_ROLE_ARN").or_else(|_| {
            std::env::var("ACCOUNT_ID")
                .map(|account_id| format!("arn:aws:iam::{}:role/agentkeys-agent", account_id))
        })
        .map_err(|_| anyhow::anyhow!(
            "missing required env var: set BROKER_AGENT_ROLE_ARN explicitly, or set ACCOUNT_ID and the broker will derive arn:aws:iam::$ACCOUNT_ID:role/agentkeys-agent"
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

        Ok(Self {
            daemon_access_key_id,
            daemon_secret_access_key,
            agent_role_arn,
            backend_url,
            audit_db_path,
            aws_region,
            session_duration_seconds,
            backend_request_timeout_seconds,
            shutdown_grace_seconds,
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
