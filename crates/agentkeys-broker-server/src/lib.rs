pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod oidc;
pub mod state;
pub mod sts;

use axum::{routing::{get, post}, Router};

use state::SharedState;

pub fn create_router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/readyz", get(handlers::health::readyz))
        .route("/v1/mint-aws-creds", post(handlers::mint::mint_aws_creds))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        .route("/.well-known/jwks.json", get(handlers::oidc::jwks))
        .route("/v1/mint-oidc-jwt", post(handlers::oidc::mint_oidc_jwt))
        .with_state(state)
}
