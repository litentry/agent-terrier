//! Tiered refuse-to-boot per Stage 7 plan §6.
//!
//! Two-tier boot sequence to avoid the outage trap Codex P1 #6 flagged:
//!
//! - **Tier 1 (synchronous, before listener bind):** config-correctness
//!   only. Env vars present + parseable, types in declared bounds, files
//!   readable + parseable, OIDC issuer https in non-dev mode, plugin
//!   compile-time presence verified, SQLite migrations run cleanly,
//!   ES256 keypairs loaded with correct purpose tags. Failure → exit 1
//!   with single-line `BOOT_FAIL: <var_or_path>=<value>: <reason>; see
//!   runbook §<anchor>`.
//!
//! - **Tier 2 (async, after listener bound):** external reachability.
//!   Backend reachable, SES sender verified (when email-link enabled),
//!   EVM RPC reachable + chain_id matches (when audit-evm enabled), EVM
//!   fee-payer balance ≥ floor. These are *not* refuse-to-boot — the
//!   broker binds the port and serves /healthz=200 + /readyz=503 with
//!   structured detail until each check passes.
//!
//! `BROKER_REFUSE_TO_BOOT_STRICT=true` collapses Tier 2 into Tier 1
//! (every reachability check becomes a hard boot fail) for environments
//! that prefer fail-loud over fail-degraded.

use std::sync::Arc;

use crate::config::BrokerConfig;
use crate::env;
use crate::jwt::SessionKeypair;
use crate::oidc::OidcKeypair;
use crate::plugins::audit::{AuditAnchor, AuditPolicy};
use crate::plugins::PluginRegistry;
use crate::storage::{
    AgentDelegationStore, AuthNonceStore, GrantStore, IdentityLinkStore, PairingRequestStore,
    WalletStore,
};

/// Outcome of the synchronous Tier-1 boot phase.
pub struct BootArtifacts {
    pub registry: Arc<PluginRegistry>,
    pub oidc_keypair: Arc<OidcKeypair>,
    pub session_keypair: Arc<SessionKeypair>,
    pub audit_policy: AuditPolicy,
    pub wallet_store: Arc<WalletStore>,
    pub nonce_store: Arc<AuthNonceStore>,
    pub grant_store: Arc<GrantStore>,
    pub identity_link_store: Arc<IdentityLinkStore>,
    /// §10.2 agent-initiated pairing-request + pending-binding store (issue #144,
    /// method A).
    pub pairing_request_store: Arc<PairingRequestStore>,
    /// §369 device→sandbox delegation rendezvous store.
    pub agent_delegation_store: Arc<AgentDelegationStore>,
    /// Concrete EmailLink plugin handle (Phase A.1, US-018). Populated
    /// when `email_link` is in `BROKER_AUTH_METHODS` AND the
    /// `auth-email-link` feature is compiled in. The registry's auth
    /// HashMap also carries this plugin as an `Arc<dyn UserAuthMethod>`
    /// for the trait-driven CLI path; this field exists so the browser-
    /// side `/v1/auth/email/verify` handler can call `consume_token` +
    /// `mark_verified` on the concrete type.
    #[cfg(feature = "auth-email-link")]
    pub email_link: Option<Arc<crate::plugins::auth::EmailLinkAuth>>,
    /// Concrete OAuth2 plugin handle (Phase A.2, US-021). Populated when
    /// `oauth2_google` is in `BROKER_AUTH_METHODS` AND `auth-oauth2-google`
    /// is compiled in. Same trait-vs-concrete duality as `email_link`:
    /// the browser callback handler needs the concrete `OAuth2Auth` so
    /// it can call `handle_callback` + `pending_store.mark_verified`
    /// without going through the trait verify().
    #[cfg(feature = "auth-oauth2")]
    pub oauth2: Option<Arc<crate::plugins::auth::OAuth2Auth>>,
}

/// Format and emit a `BOOT_FAIL: …` error to stderr-bound logs and return
/// the same anyhow::Error so main can `?` it cleanly.
fn boot_fail(
    var: &str,
    value: &str,
    reason: impl std::fmt::Display,
    anchor: &str,
) -> anyhow::Error {
    let msg = format!(
        "BOOT_FAIL: {}={:?}: {}; see runbook §{}",
        var, value, reason, anchor
    );
    tracing::error!("{}", msg);
    anyhow::anyhow!(msg)
}

/// Run Tier 1 — synchronous, must succeed before the broker binds the
/// listener. Returns the constructed `BootArtifacts` (plugin registry,
/// keypairs, store handles) for `main` to wire into `AppState`.
pub fn run_tier1(config: &BrokerConfig) -> anyhow::Result<BootArtifacts> {
    // 1. Validate OIDC issuer URL (https in non-dev mode). `dev_mode` was
    //    read once into BrokerConfig — never re-read from process env here
    //    (parallel tests inject it via the config struct).
    if !config.dev_mode && !config.oidc_issuer.starts_with("https://") {
        return Err(boot_fail(
            env::BROKER_OIDC_ISSUER,
            &config.oidc_issuer,
            "must be https:// in non-dev mode (set BROKER_DEV_MODE=true to relax)",
            "oidc-issuer",
        ));
    }
    if config.dev_mode {
        tracing::warn!(
            "{}=true — relaxing https-only OIDC issuer rule. NEVER use in production.",
            env::BROKER_DEV_MODE
        );
    }

    // 2. Load OIDC keypair (purpose=oidc, refuses purpose=session).
    if !config.oidc_keypair_path.exists() {
        return Err(boot_fail(
            env::BROKER_OIDC_KEYPAIR_PATH,
            &config.oidc_keypair_path.display().to_string(),
            "OIDC keypair file does not exist (run `agentkeys-broker-server keygen --purpose oidc --out PATH` first; silent generation is disabled per plan §6)",
            "oidc-keypair",
        ));
    }
    let oidc_keypair = Arc::new(OidcKeypair::load(&config.oidc_keypair_path).map_err(|e| {
        boot_fail(
            env::BROKER_OIDC_KEYPAIR_PATH,
            &config.oidc_keypair_path.display().to_string(),
            e,
            "oidc-keypair",
        )
    })?);

    // 3. Load session keypair (purpose=session, strict no-migration).
    let session_keypair_path = match std::env::var(env::BROKER_SESSION_KEYPAIR_PATH) {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => SessionKeypair::default_path(),
    };
    if !session_keypair_path.exists() {
        return Err(boot_fail(
            env::BROKER_SESSION_KEYPAIR_PATH,
            &session_keypair_path.display().to_string(),
            "session keypair file does not exist (run `agentkeys-broker-server keygen --purpose session --out PATH` first)",
            "session-keypair",
        ));
    }
    let session_keypair = Arc::new(SessionKeypair::load(&session_keypair_path).map_err(|e| {
        boot_fail(
            env::BROKER_SESSION_KEYPAIR_PATH,
            &session_keypair_path.display().to_string(),
            e,
            "session-keypair",
        )
    })?);
    tracing::info!(
        oidc_kid = %oidc_keypair.kid,
        session_kid = %session_keypair.kid,
        "ES256 keypairs loaded (purpose-tagged)"
    );

    // 4. Open SQLite-backed stores. Each `open()` runs CREATE TABLE IF
    //    NOT EXISTS — those are our migrations for v0. Refuse-to-boot
    //    on any failure.
    let nonce_store = Arc::new(
        AuthNonceStore::open(&auth_nonces_path(config)).map_err(|e| {
            boot_fail(
                env::BROKER_AUDIT_DB_PATH,
                &config.audit_db_path.display().to_string(),
                format!("AuthNonceStore: {}", e),
                "auth-nonces-db",
            )
        })?,
    );
    let wallet_store = Arc::new(WalletStore::open(&wallets_path(config)).map_err(|e| {
        boot_fail(
            env::BROKER_AUDIT_DB_PATH,
            &config.audit_db_path.display().to_string(),
            format!("WalletStore: {}", e),
            "wallets-db",
        )
    })?);
    let grant_store = Arc::new(GrantStore::open(&grants_path(config)).map_err(|e| {
        boot_fail(
            env::BROKER_AUDIT_DB_PATH,
            &config.audit_db_path.display().to_string(),
            format!("GrantStore: {}", e),
            "grants-db",
        )
    })?);
    let identity_link_store = Arc::new(
        IdentityLinkStore::open(&identity_links_path(config)).map_err(|e| {
            boot_fail(
                env::BROKER_AUDIT_DB_PATH,
                &config.audit_db_path.display().to_string(),
                format!("IdentityLinkStore: {}", e),
                "identity-links-db",
            )
        })?,
    );
    let pairing_request_store = Arc::new(
        PairingRequestStore::open(&pairing_requests_path(config)).map_err(|e| {
            boot_fail(
                env::BROKER_AUDIT_DB_PATH,
                &config.audit_db_path.display().to_string(),
                format!("PairingRequestStore: {}", e),
                "pairing-requests-db",
            )
        })?,
    );
    let agent_delegation_store = Arc::new(
        AgentDelegationStore::open(&agent_delegations_path(config)).map_err(|e| {
            boot_fail(
                env::BROKER_AUDIT_DB_PATH,
                &config.audit_db_path.display().to_string(),
                format!("AgentDelegationStore: {}", e),
                "agent-delegations-db",
            )
        })?,
    );

    // 5. Validate + parse plugin selection. Every name in each list must
    //    resolve at compile time (i.e. the corresponding feature must be
    //    enabled). `auth_methods` + `audit_anchors` come from BrokerConfig.
    let wallet_provisioner_name = std::env::var(env::BROKER_WALLET_PROVISIONER)
        .unwrap_or_else(|_| "client_keystore".to_string());

    // 6. Audit policy.
    let audit_policy_raw =
        std::env::var(env::BROKER_AUDIT_POLICY).unwrap_or_else(|_| "dual_strict".to_string());
    let audit_policy = AuditPolicy::parse(&audit_policy_raw).map_err(|e| {
        boot_fail(
            env::BROKER_AUDIT_POLICY,
            &audit_policy_raw,
            e,
            "audit-policy",
        )
    })?;

    // 7. Build the PluginRegistry. v0 default is wallet_sig + client_keystore + sqlite.
    let built = build_registry(
        &config.auth_methods,
        &wallet_provisioner_name,
        &config.audit_anchors,
        Arc::clone(&nonce_store),
        Arc::clone(&wallet_store),
        config,
    )?;

    Ok(BootArtifacts {
        registry: Arc::new(built.registry),
        oidc_keypair,
        session_keypair,
        audit_policy,
        wallet_store,
        nonce_store,
        grant_store,
        identity_link_store,
        pairing_request_store,
        agent_delegation_store,
        #[cfg(feature = "auth-email-link")]
        email_link: built.email_link,
        #[cfg(feature = "auth-oauth2")]
        oauth2: built.oauth2,
    })
}

/// Internal struct returned by `build_registry` so we can carry both
/// the trait-object PluginRegistry AND the concrete EmailLinkAuth /
/// OAuth2Auth handles out together.
struct BuiltRegistry {
    registry: PluginRegistry,
    #[cfg(feature = "auth-email-link")]
    email_link: Option<Arc<crate::plugins::auth::EmailLinkAuth>>,
    #[cfg(feature = "auth-oauth2")]
    oauth2: Option<Arc<crate::plugins::auth::OAuth2Auth>>,
}

/// Synchronous probe of which Tier-2 reachability checks are enabled.
/// Used by main to decide what to spawn after the listener binds.
pub struct Tier2Profile {
    pub strict: bool,
    pub email_link_enabled: bool,
    pub audit_evm_enabled: bool,
}

impl Tier2Profile {
    pub fn from_config(config: &BrokerConfig) -> Self {
        Self {
            strict: config.refuse_to_boot_strict,
            email_link_enabled: config
                .auth_methods
                .split(',')
                .any(|m| m.trim() == "email_link"),
            audit_evm_enabled: config
                .audit_anchors
                .split(',')
                .any(|a| a.trim() == "evm_testnet"),
        }
    }
}

fn auth_nonces_path(config: &BrokerConfig) -> std::path::PathBuf {
    config
        .audit_db_path
        .parent()
        .map(|p| p.join("auth_nonces.sqlite"))
        .unwrap_or_else(|| std::path::PathBuf::from("auth_nonces.sqlite"))
}

fn wallets_path(config: &BrokerConfig) -> std::path::PathBuf {
    config
        .audit_db_path
        .parent()
        .map(|p| p.join("wallets.sqlite"))
        .unwrap_or_else(|| std::path::PathBuf::from("wallets.sqlite"))
}

fn grants_path(config: &BrokerConfig) -> std::path::PathBuf {
    config
        .audit_db_path
        .parent()
        .map(|p| p.join("grants.sqlite"))
        .unwrap_or_else(|| std::path::PathBuf::from("grants.sqlite"))
}

fn identity_links_path(config: &BrokerConfig) -> std::path::PathBuf {
    config
        .audit_db_path
        .parent()
        .map(|p| p.join("identity_links.sqlite"))
        .unwrap_or_else(|| std::path::PathBuf::from("identity_links.sqlite"))
}

fn pairing_requests_path(config: &BrokerConfig) -> std::path::PathBuf {
    config
        .audit_db_path
        .parent()
        .map(|p| p.join("pairing_requests.sqlite"))
        .unwrap_or_else(|| std::path::PathBuf::from("pairing_requests.sqlite"))
}

fn agent_delegations_path(config: &BrokerConfig) -> std::path::PathBuf {
    config
        .audit_db_path
        .parent()
        .map(|p| p.join("agent_delegations.sqlite"))
        .unwrap_or_else(|| std::path::PathBuf::from("agent_delegations.sqlite"))
}

#[cfg(feature = "audit-sqlite")]
fn open_sqlite_anchor(config: &BrokerConfig) -> Result<Arc<dyn AuditAnchor>, anyhow::Error> {
    use crate::plugins::audit::sqlite::SqliteAnchor;
    let anchor = SqliteAnchor::open(&config.audit_db_path).map_err(|e| {
        boot_fail(
            env::BROKER_AUDIT_DB_PATH,
            &config.audit_db_path.display().to_string(),
            format!("SqliteAnchor: {}", e),
            "audit-sqlite",
        )
    })?;
    Ok(Arc::new(anchor) as Arc<dyn AuditAnchor>)
}

fn build_registry(
    auth_methods_raw: &str,
    wallet_provisioner_name: &str,
    audit_anchors_raw: &str,
    nonce_store: Arc<AuthNonceStore>,
    wallet_store: Arc<WalletStore>,
    config: &BrokerConfig,
) -> anyhow::Result<BuiltRegistry> {
    use crate::plugins::auth::UserAuthMethod;
    use crate::plugins::wallet::WalletProvisioner;

    // Auth methods.
    let mut auth_map: std::collections::HashMap<String, Arc<dyn UserAuthMethod>> =
        std::collections::HashMap::new();
    #[cfg(feature = "auth-email-link")]
    let mut email_link_concrete: Option<Arc<crate::plugins::auth::EmailLinkAuth>> = None;
    #[cfg(feature = "auth-oauth2")]
    let mut oauth2_concrete: Option<Arc<crate::plugins::auth::OAuth2Auth>> = None;
    for method in auth_methods_raw.split(',').map(str::trim) {
        match method {
            #[cfg(feature = "auth-wallet-sig")]
            "wallet_sig" => {
                use crate::plugins::auth::wallet_sig::SiweWalletAuth;
                let domain = url_host(&config.oidc_issuer);
                let plugin = SiweWalletAuth::new(
                    Arc::clone(&nonce_store),
                    domain,
                    config.oidc_issuer.clone(),
                );
                auth_map.insert("wallet_sig".to_string(), Arc::new(plugin));
            }
            #[cfg(feature = "auth-email-link")]
            "email_link" => {
                use crate::plugins::auth::{
                    EmailLinkAuth, EmailSender, SesEmailSender, StubEmailSender,
                };
                use crate::storage::{EmailRateLimitStore, EmailTokenStore};
                // No HMAC key — magic-link is stateful (CSPRNG token →
                // SHA256(token) keyed by request_id in EmailTokenStore →
                // single-use within TTL). See arch.md §5a.1.M Stage 1 +
                // EmailLinkAuth::new doc comment for the design rationale.
                let from_address = std::env::var(env::BROKER_EMAIL_FROM_ADDRESS).map_err(|_| {
                    boot_fail(
                        env::BROKER_EMAIL_FROM_ADDRESS,
                        "(unset)",
                        "required when email_link is in BROKER_AUTH_METHODS",
                        "email-from-address",
                    )
                })?;
                // Stores: SQLite files under config.audit_db_path's parent dir.
                let parent = config
                    .audit_db_path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                let token_store = Arc::new(
                    EmailTokenStore::open(&parent.join("email_tokens.sqlite")).map_err(|e| {
                        boot_fail(
                            env::BROKER_AUDIT_DB_PATH,
                            &parent.display().to_string(),
                            format!("EmailTokenStore: {}", e),
                            "email-tokens-db",
                        )
                    })?,
                );
                let rl_store = Arc::new(
                    EmailRateLimitStore::open(&parent.join("email_rate_limits.sqlite")).map_err(
                        |e| {
                            boot_fail(
                                env::BROKER_AUDIT_DB_PATH,
                                &parent.display().to_string(),
                                format!("EmailRateLimitStore: {}", e),
                                "email-rate-limits-db",
                            )
                        },
                    )?,
                );
                // Rate-limit defaults.
                let per_email = std::env::var(env::BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(5);
                let per_ip = std::env::var(env::BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(30);
                // Landing URL base derived from oidc_issuer host. Note:
                // production deployments typically front the broker behind
                // a reverse proxy; the operator can override via a future
                // BROKER_EMAIL_LANDING_URL_BASE env var (V0.1-FOLLOWUPS).
                let landing_base = format!(
                    "{}/auth/email/landing",
                    config.oidc_issuer.trim_end_matches('/')
                );
                // SES verify cache path.
                let data_dir = std::env::var(env::BROKER_DATA_DIR)
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| parent.clone());
                let ses_cache_path = data_dir.join("ses-verify.json");
                // Email sender backend selector — `BROKER_EMAIL_SENDER` env var.
                //   "stub" (default, in-process Vec — same as v0.1)
                //   "ses"  (real aws-sdk-sesv2 SendEmail; requires verified FROM
                //          identity per scripts/ses-verify-sender.sh)
                let sender_backend =
                    std::env::var(env::BROKER_EMAIL_SENDER).unwrap_or_else(|_| "stub".to_string());
                let sender: Arc<dyn EmailSender> = match sender_backend.as_str() {
                    "stub" => {
                        tracing::info!("email_link sender backend: stub (in-process)");
                        Arc::new(StubEmailSender::new())
                    }
                    "ses" => {
                        // SesEmailSender::new takes &SdkConfig (sync), but
                        // aws_config::defaults().load() is async. We're in a
                        // sync fn called from #[tokio::main] (multi-thread),
                        // so block_in_place + block_on is the legal escape.
                        let region = std::env::var(env::BROKER_AWS_REGION)
                            .unwrap_or_else(|_| "us-east-1".to_string());
                        tracing::info!(
                            from = %from_address,
                            region = %region,
                            "email_link sender backend: ses (aws-sdk-sesv2)"
                        );
                        let sdk_config = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async {
                                aws_config::defaults(aws_config::BehaviorVersion::latest())
                                    .region(aws_config::Region::new(region))
                                    .load()
                                    .await
                            })
                        });
                        Arc::new(SesEmailSender::new(&sdk_config, from_address.clone()))
                    }
                    other => {
                        return Err(boot_fail(
                            env::BROKER_EMAIL_SENDER,
                            other,
                            "must be 'stub' or 'ses'",
                            "email-sender-backend",
                        ));
                    }
                };
                let plugin = EmailLinkAuth::new(
                    sender,
                    Arc::clone(&token_store),
                    Arc::clone(&rl_store),
                    from_address.clone(),
                    landing_base,
                    ses_cache_path,
                    per_email,
                    per_ip,
                )
                .map_err(|e| {
                    boot_fail(
                        env::BROKER_EMAIL_FROM_ADDRESS,
                        &from_address,
                        format!("EmailLinkAuth::new: {}", e),
                        "email-link-construct",
                    )
                })?;
                let plugin_arc = Arc::new(plugin);
                auth_map.insert("email_link".to_string(), plugin_arc.clone());
                email_link_concrete = Some(plugin_arc);
            }
            #[cfg(feature = "auth-oauth2-google")]
            "oauth2_google" => {
                use crate::plugins::auth::oauth2::google::GoogleOAuth2Provider;
                use crate::plugins::auth::OAuth2Auth;
                use crate::plugins::auth::OAuth2Provider;
                use crate::storage::{EmailRateLimitStore, OAuth2PendingStore};

                // Required env vars per plan §3.5.4.
                let client_id =
                    std::env::var(env::BROKER_OAUTH2_GOOGLE_CLIENT_ID).map_err(|_| {
                        boot_fail(
                            env::BROKER_OAUTH2_GOOGLE_CLIENT_ID,
                            "(unset)",
                            "required when oauth2_google is in BROKER_AUTH_METHODS",
                            "oauth2-google-client-id",
                        )
                    })?;
                let client_secret_path =
                    std::env::var(env::BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE).map_err(|_| {
                        boot_fail(
                            env::BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE,
                            "(unset)",
                            "required when oauth2_google is in BROKER_AUTH_METHODS",
                            "oauth2-google-client-secret-file",
                        )
                    })?;
                let client_secret = std::fs::read_to_string(&client_secret_path)
                    .map_err(|e| {
                        boot_fail(
                            env::BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE,
                            &client_secret_path,
                            format!("read failed: {}", e),
                            "oauth2-google-client-secret-file",
                        )
                    })?
                    .trim()
                    .to_string();
                if client_secret.is_empty() {
                    return Err(boot_fail(
                        env::BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE,
                        &client_secret_path,
                        "client secret file is empty after trim",
                        "oauth2-google-client-secret-file",
                    ));
                }
                let state_hmac_path = std::env::var(env::BROKER_OAUTH2_STATE_HMAC_KEY_PATH)
                    .map_err(|_| {
                        boot_fail(
                            env::BROKER_OAUTH2_STATE_HMAC_KEY_PATH,
                            "(unset)",
                            "required when OAuth2 is enabled",
                            "oauth2-state-hmac-key",
                        )
                    })?;
                let state_hmac_key = std::fs::read(&state_hmac_path).map_err(|e| {
                    boot_fail(
                        env::BROKER_OAUTH2_STATE_HMAC_KEY_PATH,
                        &state_hmac_path,
                        format!("read failed: {}", e),
                        "oauth2-state-hmac-key",
                    )
                })?;
                let redirect_uri =
                    std::env::var(env::BROKER_OAUTH2_REDIRECT_URI).map_err(|_| {
                        boot_fail(
                            env::BROKER_OAUTH2_REDIRECT_URI,
                            "(unset)",
                            "required when OAuth2 is enabled",
                            "oauth2-redirect-uri",
                        )
                    })?;
                let start_rate_limit =
                    std::env::var(env::BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY)
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(30);
                let jwks_ttl = std::env::var(env::BROKER_OAUTH2_JWKS_TTL_SECONDS)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(3600);

                let parent = config
                    .audit_db_path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                let pending_store = Arc::new(
                    OAuth2PendingStore::open(&parent.join("oauth2_pending.sqlite")).map_err(
                        |e| {
                            boot_fail(
                                env::BROKER_AUDIT_DB_PATH,
                                &parent.display().to_string(),
                                format!("OAuth2PendingStore: {}", e),
                                "oauth2-pending-db",
                            )
                        },
                    )?,
                );
                // Reuse the rate-limit store schema for OAuth2 buckets.
                // Phase A.1's email_rate_limits.sqlite is generic-by-bucket-id;
                // we use a separate file to keep operator visibility clean.
                let rl_store = Arc::new(
                    EmailRateLimitStore::open(&parent.join("oauth2_rate_limits.sqlite")).map_err(
                        |e| {
                            boot_fail(
                                env::BROKER_AUDIT_DB_PATH,
                                &parent.display().to_string(),
                                format!("OAuth2 rate-limit store: {}", e),
                                "oauth2-rate-limits-db",
                            )
                        },
                    )?,
                );

                let provider =
                    GoogleOAuth2Provider::new(client_id, client_secret).with_jwks_ttl(jwks_ttl);
                let provider_arc: Arc<dyn OAuth2Provider> = Arc::new(provider);
                let plugin = OAuth2Auth::new(
                    provider_arc,
                    pending_store,
                    rl_store,
                    state_hmac_key,
                    redirect_uri,
                    start_rate_limit,
                )
                .map_err(|e| {
                    boot_fail(
                        env::BROKER_OAUTH2_STATE_HMAC_KEY_PATH,
                        &state_hmac_path,
                        format!("OAuth2Auth::new: {}", e),
                        "oauth2-construct",
                    )
                })?;
                let plugin_arc = Arc::new(plugin);
                auth_map.insert("oauth2_google".to_string(), plugin_arc.clone());
                oauth2_concrete = Some(plugin_arc);
            }
            "" => {
                // Empty entry from `BROKER_AUTH_METHODS=""` or trailing comma.
                continue;
            }
            other => {
                return Err(boot_fail(
                    env::BROKER_AUTH_METHODS,
                    other,
                    "unknown or feature-gated-out auth method (compile with the matching --features flag)",
                    "auth-method-not-compiled",
                ));
            }
        }
    }
    if auth_map.is_empty() {
        return Err(boot_fail(
            env::BROKER_AUTH_METHODS,
            auth_methods_raw,
            "at least one auth method must be enabled (default `wallet_sig`)",
            "auth-method-empty",
        ));
    }

    // Wallet provisioner.
    let wallet: Arc<dyn WalletProvisioner> = match wallet_provisioner_name {
        #[cfg(feature = "wallet-keystore")]
        "client_keystore" => {
            use crate::plugins::wallet::keystore::ClientSideKeystoreProvisioner;
            Arc::new(ClientSideKeystoreProvisioner::new(Arc::clone(
                &wallet_store,
            )))
        }
        other => {
            return Err(boot_fail(
                env::BROKER_WALLET_PROVISIONER,
                other,
                "unknown or feature-gated-out wallet provisioner",
                "wallet-provisioner-not-compiled",
            ));
        }
    };

    // Audit anchors.
    let mut audit: Vec<Arc<dyn AuditAnchor>> = Vec::new();
    for anchor_name in audit_anchors_raw.split(',').map(str::trim) {
        match anchor_name {
            #[cfg(feature = "audit-sqlite")]
            "sqlite" => {
                audit.push(open_sqlite_anchor(config)?);
            }
            #[cfg(feature = "audit-evm")]
            "evm_testnet" => {
                // Phase C US-031: real alloy-driven EVM anchor lands as
                // a Phase E operator hardening task (alloy adds ~1m to
                // compile time and requires a live Base Sepolia deploy).
                // For v0 testnet the broker registers an `EvmStubAnchor`
                // that simulates round-trip behavior without network I/O
                // — operators flip BROKER_AUDIT_EVM_LIVE=true once they
                // deploy AgentKeysAudit.sol via Foundry per runbook
                // §evm-deploy. Tracked in V0.1-FOLLOWUPS as Phase E task.
                use crate::plugins::audit::EvmStubAnchor;
                let evm = std::sync::Arc::new(EvmStubAnchor::new())
                    as std::sync::Arc<dyn crate::plugins::audit::AuditAnchor>;
                audit.push(evm);
            }
            "" => continue,
            other => {
                return Err(boot_fail(
                    env::BROKER_AUDIT_ANCHORS,
                    other,
                    "unknown or feature-gated-out audit anchor",
                    "audit-anchor-not-compiled",
                ));
            }
        }
    }
    if audit.is_empty() {
        return Err(boot_fail(
            env::BROKER_AUDIT_ANCHORS,
            audit_anchors_raw,
            "at least one audit anchor must be enabled (default `sqlite`)",
            "audit-anchor-empty",
        ));
    }

    Ok(BuiltRegistry {
        registry: PluginRegistry {
            auth: auth_map,
            wallet,
            audit,
        },
        #[cfg(feature = "auth-email-link")]
        email_link: email_link_concrete,
        #[cfg(feature = "auth-oauth2")]
        oauth2: oauth2_concrete,
    })
}

/// Extract host portion from a URL like `https://broker.example.com/path` →
/// `broker.example.com`. Used for the SIWE `domain` field.
fn url_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|x| x.1).unwrap_or(url);
    after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn config_with(audit_db: PathBuf, oidc_issuer: &str, oidc_kp_path: PathBuf) -> BrokerConfig {
        BrokerConfig {
            data_role_arn: "arn:aws:iam::000:role/test".into(),
            memory_role_arn: String::new(),
            audit_db_path: audit_db,
            aws_region: "us-east-1".into(),
            session_duration_seconds: 3600,
            shutdown_grace_seconds: 30,
            oidc_issuer: oidc_issuer.to_string(),
            oidc_keypair_path: oidc_kp_path,
            oidc_jwt_ttl_seconds: 300,
            dev_mode: false,
            auth_methods: "wallet_sig".into(),
            audit_anchors: "sqlite".into(),
            refuse_to_boot_strict: false,
        }
    }

    #[test]
    fn refuse_to_boot_when_oidc_issuer_is_http_without_dev_mode() {
        let tmp = TempDir::new().unwrap();
        // Pre-generate a valid OIDC keypair so we get past that check.
        let oidc_kp = tmp.path().join("oidc.json");
        OidcKeypair::generate_and_persist(&oidc_kp).unwrap();
        let config = config_with(
            tmp.path().join("audit.sqlite"),
            "http://oidc.local",
            oidc_kp,
        );
        // config_with sets dev_mode: false explicitly — ambient
        // BROKER_DEV_MODE never reaches run_tier1, so no env mutation
        // (process env is global; set/remove_var races parallel tests).
        let res = run_tier1(&config);
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected boot failure"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("BOOT_FAIL") && msg.contains("must be https"),
            "expected https boot fail, got: {}",
            msg
        );
    }

    #[test]
    fn refuse_to_boot_on_missing_oidc_keypair() {
        let tmp = TempDir::new().unwrap();
        let config = config_with(
            tmp.path().join("audit.sqlite"),
            "https://broker.example.com",
            tmp.path().join("does-not-exist.json"),
        );
        let res = run_tier1(&config);
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected boot failure"),
        };
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn url_host_extracts_correctly() {
        assert_eq!(
            url_host("https://broker.example.com/v1"),
            "broker.example.com"
        );
        assert_eq!(url_host("http://localhost:8080"), "localhost:8080");
        assert_eq!(url_host("broker.example.com"), "broker.example.com");
    }

    #[test]
    fn tier2_profile_detects_email_link_enabled() {
        // from_config reads only BrokerConfig fields (no filesystem, no
        // process env), so dummy paths suffice and nothing is set_var'd.
        let mut config = config_with(
            PathBuf::from("unused-audit.sqlite"),
            "https://broker.example.com",
            PathBuf::from("unused-oidc.json"),
        );
        config.auth_methods = "wallet_sig,email_link".into();
        let p = Tier2Profile::from_config(&config);
        assert!(!p.strict);
        assert!(p.email_link_enabled);
        assert!(!p.audit_evm_enabled);
    }
}
