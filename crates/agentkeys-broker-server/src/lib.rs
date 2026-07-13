pub mod accept_assertion;
pub mod audit;
pub mod auth;
pub mod boot;
pub mod config;
pub mod env;
pub mod error;
pub mod gate_admin;
pub mod handlers;
pub mod identity;
pub mod jwt;
pub mod metrics;
pub mod oidc;
pub mod plugins;
pub mod sponsor;
pub mod sponsored_accept;
pub mod state;
pub mod storage;
pub mod sts;
pub mod ve_faas;
pub mod ve_sign;
pub mod ve_sts;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};

use state::SharedState;

/// Default request-body size limit when `BROKER_REQUEST_BODY_LIMIT_BYTES`
/// is unset. 1 MiB matches the existing env-var doc default and is large
/// enough for any plausible mint payload.
const DEFAULT_REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;

pub fn create_router(state: SharedState) -> Router {
    let body_limit = std::env::var(env::BROKER_REQUEST_BODY_LIMIT_BYTES)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_REQUEST_BODY_LIMIT_BYTES);
    Router::new()
        .route("/healthz", get(handlers::broker_status::healthz))
        .route("/readyz", get(handlers::broker_status::readyz))
        .route("/metrics", get(handlers::metrics::metrics_handler))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        .route("/.well-known/jwks.json", get(handlers::oidc::jwks))
        .route("/v1/mint-oidc-jwt", post(handlers::oidc::mint_oidc_jwt))
        // v2 stage-1 cap-mint endpoints (arch.md §12.4 + §15.1). Workers
        // (credentials-service per arch.md §15.1) consume these caps and
        // independently re-verify the on-chain scope + K3 epoch before
        // doing any AES-256-GCM encrypt/decrypt + S3 PUT/GET.
        .route("/v1/cap/cred-store", post(handlers::cap::cap_cred_store))
        .route("/v1/cap/cred-fetch", post(handlers::cap::cap_cred_fetch))
        // Per-data-class memory caps (issue #90 followup). Same shape +
        // auth as cred caps but mints with data_class=Memory so the
        // memory worker accepts and the cred worker rejects.
        .route("/v1/cap/memory-put", post(handlers::cap::cap_memory_put))
        .route("/v1/cap/memory-get", post(handlers::cap::cap_memory_get))
        // #295 P1 — delegated canonical-memory READ (the master-hub
        // distribution channel): mints a CanonicalFetch/Memory cap, gated by
        // the on-chain memory:<ns> grant when operator != actor.
        .route(
            "/v1/cap/memory-canonical-get",
            post(handlers::cap::cap_memory_canonical_get),
        )
        // #295 P1 §7a — broker-brokered scoped STS for a delegated canonical
        // read: the delegate presents its CanonicalFetch cap + its OWN session
        // and gets back read-only, exact-object creds; it never holds the
        // operator session bearer (Codex critical fix).
        .route(
            "/v1/cap/canonical-sts",
            post(handlers::canonical_sts::mint_canonical_sts),
        )
        // #339 P2 — delegated absorption-inbox APPEND (the master-hub "push"
        // channel): mints an Append/Memory cap, gated by the on-chain inbox:<ns>
        // grant (a DISTINCT service-id from the memory:<ns> read grant).
        .route(
            "/v1/cap/memory-append",
            post(handlers::cap::cap_memory_append),
        )
        // #339 P2 §8 — broker-brokered scoped STS for a delegated inbox append
        // (the write-side twin of canonical-sts): the worker presents the
        // delegate's Append cap + the delegate's OWN session and gets back
        // PUT-only creds scoped to the single delegate's inbox sub-prefix.
        .route(
            "/v1/cap/inbox-sts",
            post(handlers::inbox_sts::mint_inbox_sts),
        )
        // Per-data-class CONFIG caps (#178 P1 / config-data-class-memory-list).
        // data_class=Config — the policy / memory-types taxonomy; master-only.
        .route(
            "/v1/cap/config-store",
            post(handlers::cap::cap_config_store),
        )
        .route(
            "/v1/cap/config-fetch",
            post(handlers::cap::cap_config_fetch),
        )
        // Classifier-service compute-gate cap (#178 §15.6, #207 items 2-3).
        // op=Classify; data_class comes from the request body (spans data classes).
        .route("/v1/cap/classify", post(handlers::cap::cap_classify))
        // Per-data-class CHANNEL caps (#406 channels phase 1). data_class=Channel;
        // the route fixes the DIRECTION — channel-pub mints ChannelPublish,
        // channel-sub mints ChannelSubscribe (distinct on-chain grants). The
        // channel worker rejects a cross-direction or cross-class cap.
        .route("/v1/cap/channel-pub", post(handlers::cap::cap_channel_pub))
        .route("/v1/cap/channel-sub", post(handlers::cap::cap_channel_sub))
        // #225 / #164 E7 — Touch-ID-gated agent accept: assemble the sponsored
        // executeBatch([registerAgentDevice, setScope]) UserOp + return the userOpHash.
        .route("/v1/accept/build", post(handlers::accept::accept_build))
        .route("/v1/accept/submit", post(handlers::accept::accept_submit))
        // #248 — Touch-ID-gated scope re-grant for an ALREADY-bound agent:
        // executeBatch([setScope]) only (set-replace; empty services = revoke all).
        // Submit reuses the accept relay — the assertion→signature→bundler hop
        // carries nothing accept-specific.
        .route("/v1/scope/build", post(handlers::scope::scope_build))
        .route("/v1/scope/submit", post(handlers::accept::accept_submit))
        // Touch-ID-gated agent unpair: executeBatch([revokeAgentDevice]). The
        // registry requires msg.sender == operatorMasterWallet, so for an
        // account-master operator the revoke MUST be a master-account UserOp
        // (no EOA — incl. the deployer script — can sign it).
        .route("/v1/revoke/build", post(handlers::revoke::revoke_build))
        .route("/v1/revoke/submit", post(handlers::accept::accept_submit))
        // #427 (epic #425) — the delegate SPAWN + ARCHIVE ceremonies: ONE
        // Touch ID over executeBatch([registerDelegate, setScope]) (spawn,
        // slot-consuming) / executeBatch([revokeAgentDevice]) (archive, slot-
        // freeing). Submits reuse the shared relay; the ceremony finalization
        // (gate provision/deprovision, sandbox spawn, DelegateSpawn/Archive
        // anchors) rides its confirmed-batch hook.
        // #428 — the broker-served preset catalog: static compiled-in product
        // content (unauthenticated by design — handlers/presets.rs header).
        .route("/v1/presets", get(handlers::presets::list_presets))
        .route("/v1/presets/:id", get(handlers::presets::get_preset))
        .route("/v1/agent/spawn/build", post(handlers::spawn::spawn_build))
        .route(
            "/v1/agent/spawn/submit",
            post(handlers::accept::accept_submit),
        )
        .route(
            "/v1/agent/archive/build",
            post(handlers::spawn::archive_build),
        )
        .route(
            "/v1/agent/archive/submit",
            post(handlers::accept::accept_submit),
        )
        // #278 D6 — the ONE sponsored master-register UserOp (initCode +
        // executeBatch([registerFirstMasterDevice])). submit reuses the accept
        // relay verbatim, exactly as scope/revoke do.
        .route(
            "/v1/register/build",
            post(handlers::register::register_build),
        )
        .route("/v1/register/submit", post(handlers::accept::accept_submit))
        // Stage 7 §3.5 — pluggable auth surface.
        .route(
            "/v1/auth/wallet/start",
            post(handlers::auth::wallet_start::wallet_start),
        )
        .route(
            "/v1/auth/wallet/verify",
            post(handlers::auth::wallet_verify::wallet_verify),
        )
        // #242 master passkey re-auth: the bound K11 signs a broker challenge;
        // the CHAIN (operatorMasterWallet + the account's live signer set +
        // K11Verifier.verifyAssertion as a view call) is the credential
        // registry. Mints a session JWT scoped to the chain-verified omni —
        // the no-email re-login the web onboarding offers after a logout.
        .route(
            "/v1/auth/passkey/start",
            post(handlers::auth::passkey_start::passkey_start),
        )
        .route(
            "/v1/auth/passkey/verify",
            post(handlers::auth::passkey_verify::passkey_verify),
        )
        // §10.2 agent-initiated pairing ceremony (issue #144, method A). The
        // agent opens an unbound request (proving K10 possession) + displays a
        // pairing_code; the master claims the code → derives the HDKD child omni;
        // the agent polls → J1_agent; the master pulls pending bindings to approve.
        .route(
            "/v1/agent/pairing/request",
            post(handlers::agent::request::pairing_request),
        )
        .route(
            "/v1/agent/pairing/claim",
            post(handlers::agent::claim::pairing_claim),
        )
        .route(
            "/v1/agent/pairing/decline",
            post(handlers::agent::decline::pairing_decline),
        )
        .route(
            "/v1/agent/pairing/poll",
            post(handlers::agent::poll::pairing_poll),
        )
        // #367 piece 1 — a bound device re-resolves {J1_agent, agent_url} each boot
        // (pop_sig-gated; reads the durable on-chain binding, long after the §10.2
        // request rows expire).
        .route(
            "/v1/agent/resolve",
            post(handlers::agent::resolve::agent_resolve),
        )
        // #369 device→sandbox delegation rendezvous. The sandbox opens a request
        // (J1-gated) + polls for the signed delegation; the device discovers it via
        // /pending + co-signs with K10 (pop_sig-gated). The broker only relays — the
        // worker re-verifies the device signature before any S3 touch.
        .route(
            "/v1/agent/delegation/request",
            post(handlers::agent::delegation::delegation_request),
        )
        .route(
            "/v1/agent/delegation/pending",
            post(handlers::agent::delegation::delegation_pending),
        )
        .route(
            "/v1/agent/delegation/sign",
            post(handlers::agent::delegation::delegation_sign),
        )
        .route(
            "/v1/agent/delegation/poll",
            post(handlers::agent::delegation::delegation_poll),
        )
        .route(
            "/v1/agent/pending-bindings",
            get(handlers::agent::pending::pending_bindings),
        )
        .route(
            "/v1/agent/pending-bindings/ack",
            post(handlers::agent::pending::ack_binding),
        )
        // Phase B grant endpoints (US-026).
        .route(
            "/v1/grant/create",
            post(handlers::grant::create::grant_create),
        )
        .route(
            "/v1/grant/revoke",
            post(handlers::grant::revoke::grant_revoke),
        )
        .route("/v1/grant/list", get(handlers::grant::list::grant_list))
        // Phase B wallet endpoints (US-028).
        .route("/v1/wallet/link", post(handlers::wallet::link::wallet_link))
        .route(
            "/v1/wallet/links",
            get(handlers::wallet::links_list::wallet_links_list),
        )
        .route(
            "/v1/wallet/recover/lookup",
            post(handlers::wallet::recover_lookup::wallet_recover_lookup),
        )
        .pipe(register_email_link_routes)
        .pipe(register_oauth2_routes)
        // Phase D-rest US-037: enforce request body size limit per
        // BROKER_REQUEST_BODY_LIMIT_BYTES (Codex P2 R2-F18).
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

/// Email-link routes — feature-gated via `auth-email-link`. Defined as
/// a free function (rather than inline) so the no-feature build still
/// compiles cleanly.
#[cfg(feature = "auth-email-link")]
fn register_email_link_routes(router: Router<state::SharedState>) -> Router<state::SharedState> {
    router
        .route(
            "/v1/auth/email/request",
            post(handlers::auth::email_request::email_request),
        )
        .route(
            "/v1/auth/email/verify",
            post(handlers::auth::email_verify::email_verify)
                .get(handlers::auth::email_verify::email_verify_method_not_allowed),
        )
        .route(
            "/v1/auth/email/status/:request_id",
            get(handlers::auth::email_status::email_status),
        )
        .route(
            "/auth/email/landing",
            get(handlers::auth::email_landing::email_landing),
        )
}

#[cfg(not(feature = "auth-email-link"))]
fn register_email_link_routes(router: Router<state::SharedState>) -> Router<state::SharedState> {
    router
}

/// OAuth2 routes — feature-gated via `auth-oauth2`. Same `pipe` pattern
/// as email-link so the no-feature build is a no-op.
#[cfg(feature = "auth-oauth2")]
fn register_oauth2_routes(router: Router<state::SharedState>) -> Router<state::SharedState> {
    router
        .route(
            "/v1/auth/oauth2/start",
            post(handlers::auth::oauth2_start::oauth2_start),
        )
        .route(
            "/auth/oauth2/callback",
            get(handlers::auth::oauth2_callback::oauth2_callback),
        )
        .route(
            "/v1/auth/oauth2/status/:request_id",
            get(handlers::auth::oauth2_status::oauth2_status),
        )
}

#[cfg(not(feature = "auth-oauth2"))]
fn register_oauth2_routes(router: Router<state::SharedState>) -> Router<state::SharedState> {
    router
}

/// Tiny helper trait that lets `create_router` chain `pipe(...)` over
/// the email-link route registration without a noisy intermediate let-binding.
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R;
}

impl<T> Pipe for T {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
