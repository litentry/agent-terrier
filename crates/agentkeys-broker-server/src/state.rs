use std::sync::Arc;

use crate::audit::AuditLog;
use crate::config::BrokerConfig;
use crate::jwt::SessionKeypair;
use crate::metrics::Metrics;
use crate::oidc::OidcKeypair;
use crate::plugins::audit::AuditPolicy;
use crate::plugins::PluginRegistry;
use crate::storage::{
    AuthNonceStore, GrantStore, IdentityLinkStore, PairingRequestStore, WalletStore,
};
use crate::sts::StsClient;

/// Tier-2 reachability state shared with the /readyz handler.
///
/// Each field flips to `true` once its corresponding async probe in
/// `boot::run_tier2` has succeeded. /readyz aggregates these into the
/// returned 200/503 status.
#[derive(Default, Debug)]
pub struct Tier2State {
    pub ses_verified: std::sync::atomic::AtomicBool,
    pub evm_rpc_reachable: std::sync::atomic::AtomicBool,
    pub evm_fee_payer_funded: std::sync::atomic::AtomicBool,
}

pub struct AppState {
    pub config: BrokerConfig,
    pub http: reqwest::Client,
    /// Legacy single-table audit log carried during the transition until
    /// US-011 retires it. New mints write through the AuditAnchor trait
    /// in `registry.audit`.
    pub audit: AuditLog,
    pub sts: Arc<dyn StsClient>,
    pub oidc: Arc<OidcKeypair>,
    /// Stage 7 additions:
    pub session_keypair: Arc<SessionKeypair>,
    pub registry: Arc<PluginRegistry>,
    pub audit_policy: AuditPolicy,
    pub wallet_store: Arc<WalletStore>,
    pub nonce_store: Arc<AuthNonceStore>,
    /// Capability grants (Phase B, US-025/026/027). Backs the
    /// `/v1/grant/{create,list,revoke}` CRUD endpoints. The mint-time
    /// `try_consume` enforcement point disappeared with mint_v2 in PR #96
    /// (issue #72); grants are kept in-tree for master-managed audit and
    /// potential future re-introduction at the JWT-mint site.
    pub grant_store: Arc<GrantStore>,
    /// §10.2 agent-initiated pairing requests + pending-binding records (issue
    /// #144, method A). `/v1/agent/pairing/request` opens an unbound request
    /// (capturing device_pubkey + pop_sig); `/v1/agent/pairing/claim` binds it to
    /// the claiming master (HDKD child omni); `/v1/agent/pairing/poll` mints
    /// `J1_agent` once claimed; `/v1/agent/pending-bindings` lets the master pull
    /// claimed-but-unbound rows to approve.
    pub pairing_request_store: Arc<PairingRequestStore>,
    /// Identity links (Phase B, US-028). Maps verified identities
    /// (email, oauth2 sub, secondary EVM wallet) to their owning master
    /// OmniAccount. Recovery flow consults this to find which master
    /// should sign the recovery grant.
    pub identity_link_store: Arc<IdentityLinkStore>,
    /// Atomic counters surfaced via /metrics (Phase D-rest, US-036).
    pub metrics: Arc<Metrics>,
    pub tier2: Arc<Tier2State>,
    /// Concrete handle to the EmailLink plugin (Phase A.1, US-018).
    /// `None` when `auth-email-link` feature is disabled OR when
    /// `BROKER_AUTH_METHODS` doesn't include `email_link`. The trait-
    /// object form is also registered in `registry.auth["email_link"]`
    /// for the trait-driven CLI poll path; this concrete reference
    /// exists so the browser-side `/v1/auth/email/verify` handler can
    /// call `consume_token` + `mark_verified` directly.
    #[cfg(feature = "auth-email-link")]
    pub email_link: Option<Arc<crate::plugins::auth::EmailLinkAuth>>,
    /// Concrete handle to the OAuth2 plugin (Phase A.2, US-021).
    /// Populated when `auth-oauth2-google` is compiled in AND
    /// `BROKER_AUTH_METHODS` includes `oauth2_google`. The browser-
    /// facing `/auth/oauth2/callback` handler needs the concrete
    /// `OAuth2Auth` (not just the trait object) to call
    /// `handle_callback` + `pending_store.mark_verified` directly.
    /// Phase A.2 ships v0 with one provider; Phase B+ may carry a
    /// `HashMap<String, Arc<OAuth2Auth>>` if multiple providers ever
    /// land at the same time.
    #[cfg(feature = "auth-oauth2")]
    pub oauth2: Option<Arc<crate::plugins::auth::OAuth2Auth>>,
}

pub type SharedState = Arc<AppState>;
