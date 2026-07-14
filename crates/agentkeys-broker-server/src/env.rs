//! Single source of truth for every environment variable name the broker reads.
//!
//! Per Stage 7 plan §1 rule 11 and §5: NO raw `BROKER_*` string literal may appear
//! in any other module. All env-var lookups go through these constants. Doc, runbook,
//! and tests reference the same constants via `all()`.
//!
//! When adding a new env var:
//! 1. Add a `pub const` here with a doc comment.
//! 2. Add an entry to `all()` with `(name, doc, group)`.
//! 3. Reference the constant from `config.rs` / `boot.rs` (never a raw string).
//! 4. Update `docs/operator-runbook-stage7.md` env-var table (auto-generated from `all()`).

#![allow(clippy::doc_markdown)]

/// Logical grouping for the runbook's auto-generated env-var table.
///
/// Operators reading the runbook see related vars together (Designer review #docs).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Group {
    /// Backend session validation, AWS region, audit DB path, etc.
    Core,
    /// OIDC issuer keypair + JWT TTL (used by AWS STS AssumeRoleWithWebIdentity).
    Oidc,
    /// Session JWT keypair + TTL (broker-internal; minted by the
    /// email-link / OAuth2 auth flows, consumed by /v1/mint-oidc-jwt).
    SessionJwt,
    /// Audit storage policy (anchor selection, multi-anchor strategy).
    Audit,
    /// EVM-specific audit anchor config (RPC, contract, fee-payer).
    AuditEvm,
    /// Auth method registration + plugin selection.
    Auth,
    /// Email-link auth specifics (SES, HMAC key, rate limits).
    AuthEmail,
    /// OAuth2 specifics (providers, client credentials, JWKS cache).
    AuthOAuth2,
    /// Per-identity / per-IP rate limit knobs.
    Limits,
    /// Legacy aliases retained for one minor version. Deprecation logged at boot.
    Legacy,
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

/// Required (or derive from `ACCOUNT_ID`). The role the broker assumes via STS for users.
pub const BROKER_DATA_ROLE_ARN: &str = "BROKER_DATA_ROLE_ARN";
/// Optional (#295 P1 §7a). The per-data-class MEMORY IAM role ARN the broker
/// AssumeRoles (with a read-only, exact-object inline session policy) to issue
/// delegated canonical-memory READ credentials. When unset, `/v1/cap/canonical-sts`
/// returns a clear "not configured" error rather than failing boot. Same value
/// the worker host uses as `MEMORY_ROLE_ARN`.
pub const MEMORY_ROLE_ARN: &str = "MEMORY_ROLE_ARN";
/// Optional. Path to the audit-log SQLite DB. Defaults to `~/.agentkeys/broker/audit.sqlite`.
pub const BROKER_AUDIT_DB_PATH: &str = "BROKER_AUDIT_DB_PATH";
/// Optional. AWS region used for STS calls. Defaults to `us-east-1`.
pub const BROKER_AWS_REGION: &str = "BROKER_AWS_REGION";
/// Optional. Lifetime in seconds of minted AWS sessions. Range \[900, 43200\]. Default 3600.
pub const BROKER_SESSION_DURATION_SECONDS: &str = "BROKER_SESSION_DURATION_SECONDS";
/// Optional. SIGTERM-to-exit grace window in seconds. Default 30.
pub const BROKER_SHUTDOWN_GRACE_SECONDS: &str = "BROKER_SHUTDOWN_GRACE_SECONDS";
/// Optional. When `true`, relaxes the HTTPS-only OIDC-issuer rule. Logged loudly. Default `false`.
pub const BROKER_DEV_MODE: &str = "BROKER_DEV_MODE";
/// Optional. When `true`, Tier-2 reachability checks become Tier-1 (refuse-to-boot). Default `false`.
pub const BROKER_REFUSE_TO_BOOT_STRICT: &str = "BROKER_REFUSE_TO_BOOT_STRICT";
/// Optional. Directory for persistent runtime caches (e.g. SES verification cache). Default `$HOME/.agentkeys/broker/data`.
pub const BROKER_DATA_DIR: &str = "BROKER_DATA_DIR";
/// Optional. Maximum HTTP request body size in bytes. Default 1 MiB.
pub const BROKER_REQUEST_BODY_LIMIT_BYTES: &str = "BROKER_REQUEST_BODY_LIMIT_BYTES";
/// Optional. Maximum tolerated NTP skew in seconds for SIWE timestamps. Default 60.
pub const BROKER_NTP_MAX_SKEW_SECONDS: &str = "BROKER_NTP_MAX_SKEW_SECONDS";
/// Optional. Enable Prometheus `/metrics` endpoint. Default `false` (Phase D).
pub const BROKER_METRICS_ENABLED: &str = "BROKER_METRICS_ENABLED";

// ---------------------------------------------------------------------------
// OIDC issuer (existing — used by AWS STS AssumeRoleWithWebIdentity)
// ---------------------------------------------------------------------------

/// Required in production. Public HTTPS URL the broker advertises as its OIDC issuer.
pub const BROKER_OIDC_ISSUER: &str = "BROKER_OIDC_ISSUER";
/// Optional. Path to the persisted OIDC ES256 keypair JSON. Default `$HOME/.agentkeys/broker/oidc-keypair.json`.
pub const BROKER_OIDC_KEYPAIR_PATH: &str = "BROKER_OIDC_KEYPAIR_PATH";
/// Optional. TTL in seconds of OIDC JWTs minted for STS. Range \[60, 3600\]. Default 300.
pub const BROKER_OIDC_JWT_TTL_SECONDS: &str = "BROKER_OIDC_JWT_TTL_SECONDS";

// ---------------------------------------------------------------------------
// Session JWT (NEW — broker-internal, separate from the OIDC issuer keypair)
// ---------------------------------------------------------------------------

/// Required (Phase 0). Path to the persisted ES256 *session* keypair JSON.
/// MUST be a different file from `BROKER_OIDC_KEYPAIR_PATH`. The on-disk JSON
/// carries `"purpose": "session"` and load-time validation refuses a key with
/// the wrong purpose tag (codex/eng review #7 footgun mitigation).
pub const BROKER_SESSION_KEYPAIR_PATH: &str = "BROKER_SESSION_KEYPAIR_PATH";
/// Optional. TTL in seconds of session JWTs minted by `/v1/auth/*/verify`.
/// Range \[60, 86400\]. Default 18000 (5 hours).
pub const BROKER_SESSION_JWT_TTL_SECONDS: &str = "BROKER_SESSION_JWT_TTL_SECONDS";

// ---------------------------------------------------------------------------
// Auth method selection
// ---------------------------------------------------------------------------

/// Optional. Comma-separated list of enabled auth methods. Default `wallet_sig`.
/// Supported names: `wallet_sig`, `email_link`, `oauth2_google`.
pub const BROKER_AUTH_METHODS: &str = "BROKER_AUTH_METHODS";
/// Optional. Wallet provisioner plug-in name. Default `client_keystore`.
pub const BROKER_WALLET_PROVISIONER: &str = "BROKER_WALLET_PROVISIONER";

// ---------------------------------------------------------------------------
// Audit anchors
// ---------------------------------------------------------------------------

/// Optional. Comma-separated list of enabled audit anchors. Default `sqlite`.
/// Supported names: `sqlite`, `evm_testnet`.
pub const BROKER_AUDIT_ANCHORS: &str = "BROKER_AUDIT_ANCHORS";
/// Optional. Multi-anchor write policy. One of: `dual_strict`, `sqlite_primary`, `evm_primary`. Default `dual_strict`.
pub const BROKER_AUDIT_POLICY: &str = "BROKER_AUDIT_POLICY";

// ---------------------------------------------------------------------------
// EVM audit anchor (Phase C)
// ---------------------------------------------------------------------------

/// Required when `audit_evm` is in `BROKER_AUDIT_ANCHORS`. JSON-RPC URL of the EVM testnet (e.g. Base Sepolia).
pub const BROKER_EVM_RPC_URL: &str = "BROKER_EVM_RPC_URL";
/// Required when `audit_evm` is in `BROKER_AUDIT_ANCHORS`. Chain ID (e.g. 84532 for Base Sepolia).
pub const BROKER_EVM_CHAIN_ID: &str = "BROKER_EVM_CHAIN_ID";
/// Required when `audit_evm` is in `BROKER_AUDIT_ANCHORS`. Deployed `AgentKeysAudit` contract address.
pub const BROKER_EVM_CONTRACT_ADDRESS: &str = "BROKER_EVM_CONTRACT_ADDRESS";
/// Required when `audit_evm` is in `BROKER_AUDIT_ANCHORS`. Path to encrypted keystore JSON for the fee-payer.
pub const BROKER_EVM_FEE_PAYER_KEYSTORE: &str = "BROKER_EVM_FEE_PAYER_KEYSTORE";
/// Required when `audit_evm` is in `BROKER_AUDIT_ANCHORS`. Path to file containing the keystore password (mode 0600).
pub const BROKER_EVM_FEE_PAYER_PASSWORD_FILE: &str = "BROKER_EVM_FEE_PAYER_PASSWORD_FILE";
/// Optional. Wei threshold below which the EVM anchor flips to `Unready` (Codex P0 #7). Default 0.001 ETH.
pub const BROKER_EVM_FEE_PAYER_MIN_BALANCE: &str = "BROKER_EVM_FEE_PAYER_MIN_BALANCE";
/// Optional. Per-identity (per OmniAccount) daily EVM-tx budget. Default 100.
pub const BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET: &str = "BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET";

// ---------------------------------------------------------------------------
// Email auth (Phase A.1)
// ---------------------------------------------------------------------------

/// Required when `email_link` is in `BROKER_AUTH_METHODS`. Verified SES sender email address.
///
/// **No HMAC key var.** Magic-link tokens are stateful (CSPRNG → SHA256 → SQLite EmailTokenStore →
/// single-use within TTL). See `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs`
/// `EmailLinkAuth::new` doc + `docs/arch.md` §5a.1.M Stage 1.
pub const BROKER_EMAIL_FROM_ADDRESS: &str = "BROKER_EMAIL_FROM_ADDRESS";
/// Optional. Email sender backend selector — `stub` (default, in-process Vec) or `ses`
/// (real `aws-sdk-sesv2` SendEmail). When `ses`, the FROM identity must be SES-verified
/// (see `scripts/operator/cloud/ses-verify-sender.sh`). Picks the SES region from `BROKER_AWS_REGION`
/// (or AWS SDK default chain).
pub const BROKER_EMAIL_SENDER: &str = "BROKER_EMAIL_SENDER";
/// Optional. Public base URL the magic-link landing page is reachable at
/// (scheme + host, no path — the broker appends `/auth/email/landing`).
/// Defaults to `BROKER_OIDC_ISSUER`, which is correct when the issuer IS the
/// broker's public host (the AWS stacks). Set it when the two diverge: on the
/// VE stack the issuer is the TOS-bucket JWKS URL, which serves no landing
/// page — there it must point at the broker vhost (`https://broker.<zone>`).
pub const BROKER_EMAIL_LANDING_URL_BASE: &str = "BROKER_EMAIL_LANDING_URL_BASE";
/// Optional. Operator URL the broker redirects to after a successful email-link verification.
/// If unset, the broker shows a minimal built-in "Verified — return to your terminal" page.
pub const BROKER_EMAIL_SUCCESS_REDIRECT_URL: &str = "BROKER_EMAIL_SUCCESS_REDIRECT_URL";
/// Optional. Per-email per-hour bucket size. Default 5.
pub const BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY: &str =
    "BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY";
/// Optional. Per-source-IP per-minute bucket size. Default 30.
pub const BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY: &str = "BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY";

// ---------------------------------------------------------------------------
// OAuth2 auth (Phase A.2)
// ---------------------------------------------------------------------------

/// Required when OAuth2 is enabled. Comma-separated list, e.g. `google`. (v0: only `google` supported.)
pub const BROKER_OAUTH2_PROVIDERS: &str = "BROKER_OAUTH2_PROVIDERS";
/// Required when OAuth2 is enabled. Public callback URL (e.g. `https://broker.example.com/auth/oauth2/callback`).
pub const BROKER_OAUTH2_REDIRECT_URI: &str = "BROKER_OAUTH2_REDIRECT_URI";
/// Required when `google` is in `BROKER_OAUTH2_PROVIDERS`. Google Cloud Console OAuth client ID.
pub const BROKER_OAUTH2_GOOGLE_CLIENT_ID: &str = "BROKER_OAUTH2_GOOGLE_CLIENT_ID";
/// Required when `google` is in `BROKER_OAUTH2_PROVIDERS`. Path to file containing the client secret (mode 0600).
pub const BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE: &str = "BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE";
/// Required when OAuth2 is enabled. Path to a 32-byte file used to HMAC-sign the OAuth2 `state` parameter.
pub const BROKER_OAUTH2_STATE_HMAC_KEY_PATH: &str = "BROKER_OAUTH2_STATE_HMAC_KEY_PATH";
/// Optional. JWKS cache TTL in seconds. Default 3600.
pub const BROKER_OAUTH2_JWKS_TTL_SECONDS: &str = "BROKER_OAUTH2_JWKS_TTL_SECONDS";
/// Optional. Per-IP per-minute rate on `/v1/auth/oauth2/start`. Default 30.
pub const BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY: &str =
    "BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY";

// ---------------------------------------------------------------------------
// Per-identity / per-IP rate limits (Phase C gas-drain mitigations)
// ---------------------------------------------------------------------------

/// Optional. Maximum mints per OmniAccount per hour. Default 30.
pub const BROKER_RATE_LIMIT_MINTS_PER_HOUR_PER_OMNI: &str =
    "BROKER_RATE_LIMIT_MINTS_PER_HOUR_PER_OMNI";
/// Optional. Maximum auth-challenge requests per source-IP per hour. Default 60.
pub const BROKER_RATE_LIMIT_CHALLENGES_PER_HOUR_PER_IP: &str =
    "BROKER_RATE_LIMIT_CHALLENGES_PER_HOUR_PER_IP";

// ---------------------------------------------------------------------------
// Recovery (Phase B)
// ---------------------------------------------------------------------------

/// Optional. Time-lock in seconds before a recovery grant becomes active. Default 0 (disabled).
pub const BROKER_RECOVERY_GRANT_DELAY_SECONDS: &str = "BROKER_RECOVERY_GRANT_DELAY_SECONDS";

// ---------------------------------------------------------------------------
// Legacy aliases (kept for one minor version, deprecation logged at boot)
// ---------------------------------------------------------------------------

/// Legacy. Pre-2026-04-28 alias of `BROKER_DATA_ROLE_ARN` (renamed to disambiguate from project "agent" terminology).
pub const BROKER_AGENT_ROLE_ARN: &str = "BROKER_AGENT_ROLE_ARN";
/// Legacy. AWS account ID; broker derives `BROKER_DATA_ROLE_ARN` if both are set and only this is provided.
pub const ACCOUNT_ID: &str = "ACCOUNT_ID";
/// Legacy. Alias of `BROKER_AWS_REGION`.
pub const REGION: &str = "REGION";

// ---------------------------------------------------------------------------
// Registry — used by docs generator and runbook drift check
// ---------------------------------------------------------------------------

/// Returns every env-var name the broker recognizes, with a doc string and group.
///
/// Used by:
/// - the runbook env-var table (auto-generated from this list);
/// - `e2e/stage-7-done.sh`'s drift check (greps each name against the runbook);
/// - tests that assert no raw `BROKER_*` literal exists outside this module.
pub const fn all() -> &'static [(&'static str, &'static str, Group)] {
    &[
        // Core
        (
            BROKER_DATA_ROLE_ARN,
            "Role the broker assumes via STS for users.",
            Group::Core,
        ),
        (
            BROKER_AUDIT_DB_PATH,
            "Path to audit-log SQLite DB.",
            Group::Core,
        ),
        (BROKER_AWS_REGION, "AWS region for STS calls.", Group::Core),
        (
            BROKER_SESSION_DURATION_SECONDS,
            "Lifetime in seconds of minted AWS sessions [900, 43200].",
            Group::Core,
        ),
        (
            BROKER_SHUTDOWN_GRACE_SECONDS,
            "SIGTERM-to-exit grace window seconds.",
            Group::Core,
        ),
        (
            BROKER_DEV_MODE,
            "Relaxes HTTPS-only OIDC-issuer rule (logged loudly).",
            Group::Core,
        ),
        (
            BROKER_REFUSE_TO_BOOT_STRICT,
            "Promotes Tier-2 reachability to Tier-1 refuse-to-boot.",
            Group::Core,
        ),
        (
            BROKER_DATA_DIR,
            "Directory for persistent runtime caches.",
            Group::Core,
        ),
        (
            BROKER_REQUEST_BODY_LIMIT_BYTES,
            "Maximum HTTP request body size in bytes.",
            Group::Core,
        ),
        (
            BROKER_NTP_MAX_SKEW_SECONDS,
            "Maximum tolerated NTP skew for SIWE timestamps.",
            Group::Core,
        ),
        (
            BROKER_METRICS_ENABLED,
            "Enable Prometheus /metrics endpoint.",
            Group::Core,
        ),
        // OIDC
        (BROKER_OIDC_ISSUER, "Public HTTPS issuer URL.", Group::Oidc),
        (
            BROKER_OIDC_KEYPAIR_PATH,
            "Path to the persisted OIDC ES256 keypair (purpose=oidc).",
            Group::Oidc,
        ),
        (
            BROKER_OIDC_JWT_TTL_SECONDS,
            "TTL of OIDC JWTs minted for STS [60, 3600].",
            Group::Oidc,
        ),
        // Session JWT
        (
            BROKER_SESSION_KEYPAIR_PATH,
            "Path to the persisted session ES256 keypair (purpose=session).",
            Group::SessionJwt,
        ),
        (
            BROKER_SESSION_JWT_TTL_SECONDS,
            "TTL of session JWTs [60, 86400].",
            Group::SessionJwt,
        ),
        // Auth method selection
        (
            BROKER_AUTH_METHODS,
            "Comma list of enabled auth methods.",
            Group::Auth,
        ),
        (
            BROKER_WALLET_PROVISIONER,
            "Wallet provisioner plug-in name.",
            Group::Auth,
        ),
        // Audit
        (
            BROKER_AUDIT_ANCHORS,
            "Comma list of enabled audit anchors.",
            Group::Audit,
        ),
        (
            BROKER_AUDIT_POLICY,
            "Multi-anchor write policy.",
            Group::Audit,
        ),
        // Audit / EVM
        (BROKER_EVM_RPC_URL, "EVM JSON-RPC URL.", Group::AuditEvm),
        (BROKER_EVM_CHAIN_ID, "EVM chain ID.", Group::AuditEvm),
        (
            BROKER_EVM_CONTRACT_ADDRESS,
            "Deployed AgentKeysAudit contract address.",
            Group::AuditEvm,
        ),
        (
            BROKER_EVM_FEE_PAYER_KEYSTORE,
            "Path to encrypted fee-payer keystore JSON.",
            Group::AuditEvm,
        ),
        (
            BROKER_EVM_FEE_PAYER_PASSWORD_FILE,
            "Path to fee-payer keystore password file (mode 0600).",
            Group::AuditEvm,
        ),
        (
            BROKER_EVM_FEE_PAYER_MIN_BALANCE,
            "Wei threshold below which EVM anchor → Unready.",
            Group::AuditEvm,
        ),
        (
            BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET,
            "Per-OmniAccount daily EVM-tx budget.",
            Group::AuditEvm,
        ),
        // Auth / email
        (
            BROKER_EMAIL_FROM_ADDRESS,
            "Verified SES sender email.",
            Group::AuthEmail,
        ),
        (
            BROKER_EMAIL_SENDER,
            "Email backend: 'stub' (default) or 'ses' (real aws-sdk-sesv2).",
            Group::AuthEmail,
        ),
        (
            BROKER_EMAIL_LANDING_URL_BASE,
            "Public base URL serving /auth/email/landing (default: the OIDC issuer).",
            Group::AuthEmail,
        ),
        (
            BROKER_EMAIL_SUCCESS_REDIRECT_URL,
            "Optional operator success-page redirect URL.",
            Group::AuthEmail,
        ),
        (
            BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY,
            "Per-email per-hour bucket.",
            Group::AuthEmail,
        ),
        (
            BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY,
            "Per-IP per-minute bucket.",
            Group::AuthEmail,
        ),
        // Auth / OAuth2
        (
            BROKER_OAUTH2_PROVIDERS,
            "Comma list of enabled providers (v0: google).",
            Group::AuthOAuth2,
        ),
        (
            BROKER_OAUTH2_REDIRECT_URI,
            "Public callback URL.",
            Group::AuthOAuth2,
        ),
        (
            BROKER_OAUTH2_GOOGLE_CLIENT_ID,
            "Google OAuth client ID.",
            Group::AuthOAuth2,
        ),
        (
            BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE,
            "Path to Google client secret file (mode 0600).",
            Group::AuthOAuth2,
        ),
        (
            BROKER_OAUTH2_STATE_HMAC_KEY_PATH,
            "Path to 32-byte file for OAuth2 state HMAC.",
            Group::AuthOAuth2,
        ),
        (
            BROKER_OAUTH2_JWKS_TTL_SECONDS,
            "JWKS cache TTL in seconds.",
            Group::AuthOAuth2,
        ),
        (
            BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY,
            "Per-IP per-minute on /v1/auth/oauth2/start.",
            Group::AuthOAuth2,
        ),
        // Limits
        (
            BROKER_RATE_LIMIT_MINTS_PER_HOUR_PER_OMNI,
            "Maximum mints per OmniAccount per hour.",
            Group::Limits,
        ),
        (
            BROKER_RATE_LIMIT_CHALLENGES_PER_HOUR_PER_IP,
            "Maximum auth-challenge requests per IP per hour.",
            Group::Limits,
        ),
        // Recovery
        (
            BROKER_RECOVERY_GRANT_DELAY_SECONDS,
            "Time-lock seconds before recovery grant activates.",
            Group::Limits,
        ),
        // Legacy
        (
            BROKER_AGENT_ROLE_ARN,
            "Legacy alias of BROKER_DATA_ROLE_ARN.",
            Group::Legacy,
        ),
        (
            ACCOUNT_ID,
            "Legacy AWS account ID; derives BROKER_DATA_ROLE_ARN.",
            Group::Legacy,
        ),
        (REGION, "Legacy alias of BROKER_AWS_REGION.", Group::Legacy),
    ]
}

/// Print the env-var table as Markdown for the operator runbook.
///
/// Output is grouped by `Group` in declaration order, with one row per env var:
/// `| name | group | doc |`. Used by the runbook generator + `stage-7-done.sh`
/// drift check.
pub fn print_table() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("| Env var | Group | Description |\n");
    out.push_str("|---|---|---|\n");
    for (name, doc, group) in all() {
        let _ = writeln!(out, "| `{}` | {:?} | {} |", name, group, doc);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_unique_names() {
        let mut names: Vec<&str> = all().iter().map(|(n, _, _)| *n).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate env-var name in env::all()");
    }

    #[test]
    fn all_doc_strings_non_empty() {
        for (name, doc, _) in all() {
            assert!(!doc.is_empty(), "{} has empty doc", name);
        }
    }

    #[test]
    fn all_includes_required_phase0_vars() {
        let names: Vec<&str> = all().iter().map(|(n, _, _)| *n).collect();
        for required in [
            BROKER_DATA_ROLE_ARN,
            BROKER_OIDC_ISSUER,
            BROKER_OIDC_KEYPAIR_PATH,
            BROKER_SESSION_KEYPAIR_PATH,
            BROKER_AUTH_METHODS,
            BROKER_AUDIT_ANCHORS,
        ] {
            assert!(
                names.contains(&required),
                "Phase-0 required var {} missing from env::all()",
                required
            );
        }
    }

    #[test]
    fn print_table_renders_one_row_per_var() {
        let table = print_table();
        let row_count = table.lines().filter(|l| l.starts_with("| `")).count();
        assert_eq!(row_count, all().len(), "row count must match all() length");
    }

    #[test]
    fn group_variants_cover_all_entries() {
        // Sanity: every entry has a group; this also serves as a compile-time
        // check that the Group enum stays in sync with all() entries.
        for (name, _, group) in all() {
            // Match exhaustively to force update if a Group variant is removed.
            match group {
                Group::Core
                | Group::Oidc
                | Group::SessionJwt
                | Group::Audit
                | Group::AuditEvm
                | Group::Auth
                | Group::AuthEmail
                | Group::AuthOAuth2
                | Group::Limits
                | Group::Legacy => {
                    assert!(!name.is_empty());
                }
            }
        }
    }
}
