use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub db: Mutex<Connection>,
    pub shielding_signing_key: SigningKey,
    pub shielding_public_key: VerifyingKey,
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
        }
    }
}

pub type SharedState = Arc<AppState>;
