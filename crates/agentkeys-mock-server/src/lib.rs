pub mod auth;
pub mod db;
pub mod dev_key_service;
pub mod error;
pub mod handlers;
pub mod state;
pub mod test_client;

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use state::SharedState;

/// Signer-only router: serves `/dev/*` + `/healthz` exclusively.
/// Used when `--signer-only` is set, so that the dedicated signer listener
/// (`signer.example.invalid` → :8092) never accidentally serves session/credential
/// endpoints. JWT bearer auth is enforced when `state.broker_session_pubkey`
/// is set.
pub fn create_signer_router(state: SharedState) -> Router {
    Router::new()
        .route(
            "/dev/derive-address",
            post(handlers::dev_keys::derive_address),
        )
        .route("/dev/sign-message", post(handlers::dev_keys::sign_message))
        // Issue #82 — EIP-712 typed-data signing. Same JWT auth path as
        // `/dev/sign-message`; signer parses typed_data itself + emits
        // digests alongside the signature.
        .route(
            "/dev/sign-typed-data",
            post(handlers::dev_keys::sign_typed_data),
        )
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

pub fn create_router(state: SharedState) -> Router {
    Router::new()
        // Session
        .route("/session/create", post(handlers::session::create_session))
        .route(
            "/session/child",
            post(handlers::session::create_child_session),
        )
        .route("/session/revoke", post(handlers::session::revoke_session))
        .route("/session/recover", post(handlers::session::recover_session))
        .route(
            "/session/validate",
            get(handlers::session::validate_session_endpoint),
        )
        // Credential
        .route(
            "/credential/store",
            post(handlers::credential::store_credential),
        )
        .route(
            "/credential/read",
            get(handlers::credential::read_credential),
        )
        .route(
            "/credential/list",
            get(handlers::credential::list_credentials),
        )
        .route(
            "/credential/teardown",
            delete(handlers::credential::teardown_agent),
        )
        // Shielding key
        .route("/shielding-key", get(handlers::audit::shielding_key))
        // Rendezvous
        .route(
            "/rendezvous/register",
            post(handlers::rendezvous::register_rendezvous),
        )
        .route(
            "/rendezvous/poll",
            get(handlers::rendezvous::poll_rendezvous),
        )
        .route(
            "/rendezvous/deliver",
            post(handlers::rendezvous::deliver_rendezvous),
        )
        // Auth request
        .route(
            "/auth-request/open",
            post(handlers::auth_request::open_auth_request),
        )
        .route(
            "/auth-request/fetch",
            get(handlers::auth_request::fetch_auth_request),
        )
        .route(
            "/auth-request/approve",
            post(handlers::auth_request::approve_auth_request),
        )
        .route(
            "/auth-request/await",
            get(handlers::auth_request::await_auth_decision),
        )
        // Session scope
        .route("/session/scope", get(handlers::session::get_session_scope))
        .route("/session/scope", put(handlers::session::update_scope))
        // Inbox
        .route(
            "/mock/inbox/provision",
            post(handlers::inbox::provision_inbox),
        )
        .route("/mock/inbox/deliver", post(handlers::inbox::deliver_inbox))
        .route("/mock/inbox/messages", get(handlers::inbox::list_messages))
        .route("/mock/inbox/list", get(handlers::inbox::list_inboxes))
        // Dev key service (signer edge — see docs/spec/signer-protocol.md).
        // 503 `signer_disabled` when `DEV_KEY_SERVICE_MASTER_SECRET` is unset.
        // Issue #74 step 2 replaces this with a TEE worker; wire shape stays.
        .route(
            "/dev/derive-address",
            post(handlers::dev_keys::derive_address),
        )
        .route("/dev/sign-message", post(handlers::dev_keys::sign_message))
        // Issue #82 — EIP-712 typed-data sign endpoint. Documented in
        // `signer-protocol.md`. TEE-worker swap-in preserves the same path.
        .route(
            "/dev/sign-typed-data",
            post(handlers::dev_keys::sign_typed_data),
        )
        // `/healthz` (Kubernetes convention) — what the broker's Tier-2
        // reachability probe hits. Single endpoint, single name across the
        // codebase. Pre-Stage-7 `/health` alias was dropped; any caller that
        // wired itself to `/health` should curl `/healthz` instead.
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}
