pub mod audit;
pub mod auth;
pub mod boot;
pub mod config;
pub mod env;
pub mod error;
pub mod handlers;
pub mod identity;
pub mod jwt;
pub mod metrics;
pub mod oidc;
pub mod plugins;
pub mod state;
pub mod storage;
pub mod sts;

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
        // Stage 7 §3.5 — pluggable auth surface.
        .route(
            "/v1/auth/wallet/start",
            post(handlers::auth::wallet_start::wallet_start),
        )
        .route(
            "/v1/auth/wallet/verify",
            post(handlers::auth::wallet_verify::wallet_verify),
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
