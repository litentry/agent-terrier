pub mod auth;
pub mod db;
pub mod error;
pub mod handlers;
pub mod state;
pub mod test_client;

use axum::{
    Router,
    routing::{delete, get, post},
};
use std::sync::Arc;

use state::SharedState;

pub fn create_router(state: SharedState) -> Router {
    Router::new()
        // Session
        .route("/session/create", post(handlers::session::create_session))
        .route("/session/child", post(handlers::session::create_child_session))
        .route("/session/revoke", post(handlers::session::revoke_session))
        .route("/session/recover", post(handlers::session::recover_session))
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
        // Identity
        .route("/identity/link", post(handlers::identity::link_identity))
        .route("/identity/resolve", get(handlers::identity::resolve_identity))
        // Health
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}
