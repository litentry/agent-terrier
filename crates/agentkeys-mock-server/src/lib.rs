pub mod auth;
pub mod db;
pub mod error;
pub mod handlers;
pub mod state;
pub mod test_client;

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use state::SharedState;

pub fn create_router(state: SharedState) -> Router {
    Router::new()
        // Session
        .route("/session/create", post(handlers::session::create_session))
        .route("/session/child", post(handlers::session::create_child_session))
        .route("/session/revoke", post(handlers::session::revoke_session))
        .route("/session/recover", post(handlers::session::recover_session))
        .route("/session/validate", get(handlers::session::validate_session_endpoint))
        // Credential
        .route("/credential/store", post(handlers::credential::store_credential))
        .route("/credential/read", get(handlers::credential::read_credential))
        .route("/credential/list", get(handlers::credential::list_credentials))
        .route("/credential/teardown", delete(handlers::credential::teardown_agent))
        // Audit
        .route("/audit/query", get(handlers::audit::query_audit))
        // Shielding key
        .route("/shielding-key", get(handlers::audit::shielding_key))
        // Rendezvous
        .route("/rendezvous/register", post(handlers::rendezvous::register_rendezvous))
        .route("/rendezvous/poll", get(handlers::rendezvous::poll_rendezvous))
        .route("/rendezvous/deliver", post(handlers::rendezvous::deliver_rendezvous))
        // Auth request
        .route("/auth-request/open", post(handlers::auth_request::open_auth_request))
        .route("/auth-request/fetch", get(handlers::auth_request::fetch_auth_request))
        .route("/auth-request/approve", post(handlers::auth_request::approve_auth_request))
        .route("/auth-request/await", get(handlers::auth_request::await_auth_decision))
        // Session scope
        .route("/session/scope", get(handlers::session::get_session_scope))
        .route("/session/scope", put(handlers::session::update_scope))
        // Identity
        .route("/identity/link", post(handlers::identity::link_identity))
        .route("/identity/resolve", get(handlers::identity::resolve_identity))
        // Inbox
        .route("/mock/inbox/provision", post(handlers::inbox::provision_inbox))
        .route("/mock/inbox/deliver", post(handlers::inbox::deliver_inbox))
        .route("/mock/inbox/messages", get(handlers::inbox::list_messages))
        .route("/mock/inbox/list", get(handlers::inbox::list_inboxes))
        // `/healthz` (Kubernetes convention) — what the broker's Tier-2
        // reachability probe hits. Single endpoint, single name across the
        // codebase. Pre-Stage-7 `/health` alias was dropped; any caller that
        // wired itself to `/health` should curl `/healthz` instead.
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}
