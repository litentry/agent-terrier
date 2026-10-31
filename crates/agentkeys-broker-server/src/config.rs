use std::path::PathBuf;

use crate::env;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub login_config: Option<agentkeys_protocol::auth::LoginConfig>,
    pub login_access: crate::login_access::LoginAccess,
    pub data_role_arn: String,
    /// #295 P1 §7a — the per-data-class MEMORY IAM role the broker AssumeRoles
    /// (with a read-only, exact-object inline session policy) to issue delegated
    /// canonical-memory READ credentials. Empty when `MEMORY_ROLE_ARN` is unset;
    /// `/v1/cap/canonical-sts` then returns a clear "not configured" error
    /// instead of failing boot (back-compat for brokers predating this).
    pub memory_role_arn: String,
    /// #441 — the SPEECH IAM role `/v1/cap/speech-sts` AssumeRoles (inline
    /// Transcribe/Polly-only session policy). Empty when `SPEECH_ROLE_ARN` is
    /// unset; the endpoint then returns a clear "not configured" error.
    pub speech_role_arn: String,
    /// #541 — the per-data-class CHANNEL role `/v1/cap/channel-sts` AssumeRoles
    /// (owner-scoped, channel-prefix inline policy on AWS; provider-side
    /// scope-down on VE). Empty = clear "not configured" error, same posture
    /// as `memory_role_arn`.
    pub channel_role_arn: String,
    /// #541 — the host-minted shared bearer authenticating the CHANNEL WORKER
    /// to `/v1/cap/channel-sts`. Empty = the endpoint refuses (not configured).
    pub channel_sts_token: String,
    /// The local binary accepts only `local`; embedding applications inject
    /// their own optional external credential adapter through AppState.
    pub sts_provider: String,
    pub audit_db_path: PathBuf,
    pub aws_region: String,
    pub session_duration_seconds: i32,
    /// Hard cap on graceful-shutdown drain time.
    pub shutdown_grace_seconds: u64,
    /// Public URL the broker advertises as the OIDC issuer.
    pub oidc_issuer: String,
    /// Path to the persisted OIDC ES256 keypair (purpose=oidc).
    pub oidc_keypair_path: PathBuf,
    /// TTL of OIDC JWTs minted for STS.
    pub oidc_jwt_ttl_seconds: u64,
    /// `BROKER_DEV_MODE=true` relaxes the https-only OIDC issuer rule.
    ///
    /// Read once here (like the three fields below) so boot paths never
    /// re-read process env — tests inject values via this struct instead
    /// of `std::env::set_var`, which leaks across parallel test threads
    /// (same bug class as the daemon's PR #258 deflake).
    pub dev_mode: bool,
    /// Comma-separated auth-method plugin names (`BROKER_AUTH_METHODS`).
    pub auth_methods: String,
    /// Comma-separated audit-anchor plugin names (`BROKER_AUDIT_ANCHORS`).
    pub audit_anchors: String,
    /// `BROKER_REFUSE_TO_BOOT_STRICT=true` collapses Tier-2 reachability
    /// probes into Tier-1 hard boot fails.
    pub refuse_to_boot_strict: bool,
    /// Per-stack identity namespace (#464): the `client_id` input to omni
    /// derivation (`AGENTKEYS_CLIENT_ID` env). Default `agentkeys` (AWS,
    /// unchanged by omission); the VE stack sets `agentterrier`. Logged at
    /// boot — a wrong value forks every identity on the stack.
    pub client_id: String,
    /// #510 — the `aud` claim stamped into broker-minted OIDC JWTs
    /// (`BROKER_STS_AUDIENCE`). AWS's provider registers
    /// `sts.amazonaws.com` (the historical hardcode, kept as the default);
    /// the VE provider registers its own audience (ve-broker-runtime-port
    /// follow-up 2) — config, never a code constant.
    pub sts_audience: String,
}

impl BrokerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let data_role_arn = std::env::var(env::BROKER_DATA_ROLE_ARN)
            .or_else(|_| std::env::var(env::BROKER_AGENT_ROLE_ARN))
            .unwrap_or_default();

        // #295 P1 §7a — optional. Empty disables /v1/cap/canonical-sts with a
        // clear error (not a boot failure), so brokers predating this keep booting.
        let memory_role_arn = std::env::var(env::MEMORY_ROLE_ARN).unwrap_or_default();
        // #441 — optional, same posture as memory_role_arn.
        let speech_role_arn = std::env::var(env::SPEECH_ROLE_ARN).unwrap_or_default();
        // #541 — optional pair, same posture: unset disables /v1/cap/channel-sts
        // with a clear error instead of failing boot.
        let channel_role_arn = std::env::var(env::CHANNEL_ROLE_ARN).unwrap_or_default();
        let channel_sts_token = std::env::var(env::AGENTKEYS_CHANNEL_STS_TOKEN).unwrap_or_default();
        let sts_provider = match std::env::var(env::AGENTKEYS_STS_PROVIDER)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "local" => "local".to_string(),
            other => anyhow::bail!(
                "AGENTKEYS_STS_PROVIDER={other:?} is unsupported by the local binary; external credential adapters require an embedding application"
            ),
        };

        let audit_db_path = std::env::var(env::BROKER_AUDIT_DB_PATH)
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_audit_db_path);

        // BROKER_AWS_REGION wins; falls back to legacy REGION before defaulting.
        let aws_region = first_env(&[env::BROKER_AWS_REGION, env::REGION])
            .unwrap_or_else(|| "us-east-1".to_string());

        let session_duration_seconds =
            parse_int_env_with_default(env::BROKER_SESSION_DURATION_SECONDS, 3600)?;
        if !(900..=43_200).contains(&session_duration_seconds) {
            anyhow::bail!(
                "{} must be between 900 and 43200, got {}",
                env::BROKER_SESSION_DURATION_SECONDS,
                session_duration_seconds
            );
        }

        let shutdown_grace_seconds =
            parse_int_env_with_default(env::BROKER_SHUTDOWN_GRACE_SECONDS, 30u64)?;

        let oidc_issuer = required_env(env::BROKER_OIDC_ISSUER)?;
        let oidc_keypair_path = std::env::var(env::BROKER_OIDC_KEYPAIR_PATH)
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(crate::oidc::OidcKeypair::default_path);

        let oidc_jwt_ttl_seconds =
            parse_int_env_with_default(env::BROKER_OIDC_JWT_TTL_SECONDS, 300u64)?;
        if !(60..=3_600).contains(&oidc_jwt_ttl_seconds) {
            anyhow::bail!(
                "{} must be between 60 and 3600, got {}",
                env::BROKER_OIDC_JWT_TTL_SECONDS,
                oidc_jwt_ttl_seconds
            );
        }

        let dev_mode = bool_env(env::BROKER_DEV_MODE);
        let auth_methods =
            std::env::var(env::BROKER_AUTH_METHODS).unwrap_or_else(|_| "wallet_sig".to_string());
        let audit_anchors =
            std::env::var(env::BROKER_AUDIT_ANCHORS).unwrap_or_else(|_| "sqlite".to_string());
        let refuse_to_boot_strict = bool_env(env::BROKER_REFUSE_TO_BOOT_STRICT);
        let client_id = parse_client_id(std::env::var(env::AGENTKEYS_CLIENT_ID).ok())?;
        let sts_audience = std::env::var(env::BROKER_STS_AUDIENCE)
            .unwrap_or_else(|_| "sts.amazonaws.com".to_string());

        let login_access = match std::env::var(env::BROKER_MASTER_LOGIN_ALLOWLIST) {
            Ok(spec) => {
                crate::login_access::LoginAccess::restricted(&spec).map_err(anyhow::Error::msg)?
            }
            Err(std::env::VarError::NotPresent) => Default::default(),
            Err(error) => return Err(error.into()),
        };
        let chain_id_override = crate::handlers::accept::env_profile("AGENTKEYS_CHAIN_ID")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()?;
        let profile = agentkeys_core::chain_profile::ChainProfile::resolve(
            None,
            std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
            std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
                .ok()
                .as_deref(),
        )
        .ok()
        .map(|(profile, _)| profile);
        let signer_url = std::env::var("AGENTKEYS_SIGNER_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .or_else(|| agentkeys_protocol::derive_worker_url(&oidc_issuer, "signer"));
        let login_config = configured_chain_id(chain_id_override, profile.as_ref())
            .zip(signer_url)
            .map(
                |(chain_id, signer_url)| agentkeys_protocol::auth::LoginConfig {
                    chain_id: chain_id.to_string(),
                    signer_url,
                    email_allowlist_enabled: login_access.is_restricted(),
                },
            );
        Ok(Self {
            login_config,
            login_access,
            data_role_arn,
            memory_role_arn,
            speech_role_arn,
            channel_role_arn,
            channel_sts_token,
            sts_provider,
            audit_db_path,
            aws_region,
            session_duration_seconds,
            shutdown_grace_seconds,
            oidc_issuer,
            oidc_keypair_path,
            oidc_jwt_ttl_seconds,
            dev_mode,
            auth_methods,
            audit_anchors,
            refuse_to_boot_strict,
            client_id,
            sts_audience,
        })
    }
}

/// Validate the per-stack omni-derivation namespace (#464). Unset ⇒ the
/// historical `agentkeys` (AWS unchanged by omission). Set ⇒ must be a
/// non-empty single token: the value feeds a hash, so whitespace or an
/// accidentally-quoted paste would silently fork every identity — refuse
/// to boot instead.
fn parse_client_id(raw: Option<String>) -> anyhow::Result<String> {
    let value = match raw {
        None => return Ok(crate::identity::DEFAULT_CLIENT_ID.to_string()),
        Some(v) => v,
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{} is set but empty — unset it for the default ({}) or set the stack's namespace explicitly",
            env::AGENTKEYS_CLIENT_ID,
            crate::identity::DEFAULT_CLIENT_ID,
        );
    }
    if trimmed != value
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        anyhow::bail!(
            "{}={:?} contains whitespace/quotes — a malformed namespace forks every derived identity",
            env::AGENTKEYS_CLIENT_ID,
            value,
        );
    }
    Ok(trimmed.to_string())
}

/// True iff the env var is set to exactly `"true"`.
fn bool_env(name: &str) -> bool {
    std::env::var(name).map(|v| v == "true").unwrap_or(false)
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
        Ok(s) => s
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("{}={:?} could not be parsed: {}", name, s, e)),
        Err(_) => Ok(default),
    }
}

fn default_audit_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".agentkeys")
        .join("broker")
        .join("audit.sqlite")
}

#[cfg(test)]
mod tests {
    use super::parse_client_id;

    #[test]
    fn client_id_defaults_when_unset() {
        assert_eq!(parse_client_id(None).unwrap(), "agentkeys");
    }

    #[test]
    fn client_id_accepts_stack_namespace() {
        assert_eq!(
            parse_client_id(Some("agentterrier".into())).unwrap(),
            "agentterrier"
        );
    }

    #[test]
    fn client_id_refuses_empty_and_malformed() {
        assert!(parse_client_id(Some("".into())).is_err());
        assert!(parse_client_id(Some("  ".into())).is_err());
        assert!(parse_client_id(Some("agent terrier".into())).is_err());
        assert!(parse_client_id(Some("\"agentterrier\"".into())).is_err());
        assert!(parse_client_id(Some(" agentterrier".into())).is_err());
    }
}

pub(crate) fn configured_chain_id(
    override_id: Option<u64>,
    profile: Option<&agentkeys_core::chain_profile::ChainProfile>,
) -> Option<u64> {
    override_id.or_else(|| profile.map(|profile| profile.chain_id))
}

#[cfg(test)]
mod login_chain_tests {
    use super::*;
    #[test]
    fn hosted_login_uses_the_deployed_profile_without_a_duplicate_chain_id_env() {
        let profile = agentkeys_core::chain_profile::ChainProfile::load_builtin("anvil").unwrap();
        assert_eq!(
            configured_chain_id(None, Some(&profile)),
            Some(profile.chain_id)
        );
        assert_eq!(configured_chain_id(Some(123), Some(&profile)), Some(123));
        assert_eq!(configured_chain_id(None, None), None);
    }
}
