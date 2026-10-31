use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::DecodingKey;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

use crate::dev_key_service::DevKeyService;

pub struct AppState {
    pub db: Mutex<Connection>,
    pub shielding_signing_key: SigningKey,
    pub shielding_public_key: VerifyingKey,
    /// Dev signer for `/dev/derive-address` and `/dev/sign-message`.
    /// `None` when `DEV_KEY_SERVICE_MASTER_SECRET` is unset; the handlers
    /// then return 503 `signer_disabled` per `signer-protocol.md`.
    pub dev_signer: Option<DevKeyService>,
    /// Broker session keypair public key for JWT bearer verification on `/dev/*`.
    /// `None` in legacy mock-server mode (no auth on `/dev/*`).
    /// When set (signer-only mode), every `/dev/*` request MUST carry a valid
    /// session JWT signed by the broker.
    pub broker_session_pubkey: Option<DecodingKey>,
}

impl AppState {
    pub fn new(conn: Connection) -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Self {
            db: Mutex::new(conn),
            shielding_signing_key: signing_key,
            shielding_public_key: verifying_key,
            dev_signer: None,
            broker_session_pubkey: None,
        }
    }

    /// Builder: attach a dev signer (or leave it `None` to keep the `/dev/*`
    /// endpoints disabled).
    pub fn with_dev_signer(mut self, signer: Option<DevKeyService>) -> Self {
        self.dev_signer = signer;
        self
    }

    /// Builder: attach the broker session pubkey for JWT bearer verification.
    /// When set, every `/dev/*` request must carry a valid session JWT.
    /// When `None` (default), JWT verification is skipped (legacy/test mode).
    pub fn with_broker_session_pubkey(mut self, key: Option<DecodingKey>) -> Self {
        self.broker_session_pubkey = key;
        self
    }
}

pub type SharedState = Arc<AppState>;
