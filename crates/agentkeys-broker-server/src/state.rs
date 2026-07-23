use std::sync::Arc;

use crate::audit::AuditLog;
use crate::config::BrokerConfig;
use crate::jwt::SessionKeypair;
use crate::metrics::Metrics;
use crate::oidc::OidcKeypair;
use crate::plugins::audit::AuditPolicy;
use crate::plugins::PluginRegistry;
use crate::storage::{
    AgentDelegationStore, AuthNonceStore, IdentityLinkStore, PairingRequestStore,
    SpawnContextStore, WalletStore,
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
    /// #546 — durable delegate spawn context (label, `opchat-<label>` feed id,
    /// K10) keyed by device_key_hash: written at ceremony confirm, read by
    /// EVERY sandbox-create path so a re-created runtime is never chat-silent,
    /// deleted on confirmed revoke. Registered exception E2 in arch.md §1a —
    /// scope bound + revert path (#552) live there and in
    /// `storage::spawn_contexts`. (The former `grant_store` slot — the
    /// unenforced-since-mint_v2 `/v1/grant` SQLite CRUD — was removed, #547.)
    pub spawn_context_store: Arc<SpawnContextStore>,
    /// §10.2 agent-initiated pairing requests + pending-binding records (issue
    /// #144, method A). `/v1/agent/pairing/request` opens an unbound request
    /// (capturing device_pubkey + pop_sig); `/v1/agent/pairing/claim` binds it to
    /// the claiming master (HDKD child omni); `/v1/agent/pairing/poll` mints
    /// `J1_agent` once claimed; `/v1/agent/pending-bindings` lets the master pull
    /// claimed-but-unbound rows to approve.
    pub pairing_request_store: Arc<PairingRequestStore>,
    /// §369 device→sandbox delegation rendezvous. `/v1/agent/delegation/request`
    /// (sandbox, J1-gated) opens a request; `/v1/agent/delegation/{pending,sign}`
    /// (device, pop_sig-gated) let the device discover + co-sign it with K10;
    /// `/v1/agent/delegation/poll` (sandbox, J1-gated) retrieves the device-signed
    /// `delegation_path` the sandbox attaches to its cap-mints. The broker only
    /// relays — the worker re-verifies the device signature.
    pub agent_delegation_store: Arc<AgentDelegationStore>,
    /// Identity links (Phase B, US-028). Maps verified identities
    /// (email, oauth2 sub, secondary EVM wallet) to their owning master
    /// OmniAccount. Recovery flow consults this to find which master
    /// should sign the recovery grant.
    pub identity_link_store: Arc<IdentityLinkStore>,
    /// #377/#440 broker-driven sandbox lifecycle (one hermes-sandbox per
    /// delegate device, spawned on pair/resolve, killed on unpair) behind the
    /// per-cloud [`SandboxBackend`](crate::sandbox_backend::SandboxBackend)
    /// seam (veFaaS on VE, ECS/Fargate on AWS). `None` when the host carries
    /// no sandbox config, and every hook site is then a no-op.
    pub sandbox: Option<Arc<crate::sandbox_backend::SandboxBackend>>,
    /// #427 spawn/archive ceremony context, build → submit (IN-MEMORY by
    /// design — the pending-spawn row carries the delegate K10 secret, which
    /// must never sit at rest; see `handlers::spawn`).
    pub pending_ceremonies: Arc<crate::handlers::spawn::PendingCeremonyStore>,
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
