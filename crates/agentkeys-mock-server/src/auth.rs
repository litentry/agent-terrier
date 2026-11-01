use crate::{error::AppError, state::AppState};
use rusqlite::{params, Connection};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct ValidatedSession {
    pub token: String,
    pub wallet_address: String,
    pub scope_json: Option<String>,
}

pub fn validate_session(state: &AppState, token: &str) -> Result<ValidatedSession, AppError> {
    let db = state.db.lock().unwrap();
    let result = db.query_row(
        "SELECT token, wallet_address, scope_json, created_at, ttl_seconds, revoked
         FROM sessions WHERE token = ?1",
        params![token],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    );

    match result {
        Err(_) => Err(AppError::unauthorized("session not found")),
        Ok((token, wallet, scope_json, created_at, ttl_seconds, revoked)) => {
            if revoked != 0 {
                return Err(AppError::unauthorized("session revoked"));
            }
            let now = now_secs();
            if now > created_at + ttl_seconds {
                return Err(AppError::unauthorized("session expired"));
            }
            Ok(ValidatedSession {
                token,
                wallet_address: wallet,
                scope_json,
            })
        }
    }
}

/// Returns true if `caller_wallet` owns or is a parent of `agent_wallet`.
/// Ownership means: the agent's session was created with parent_token tracing
/// back to a session whose wallet_address == caller_wallet, OR they are the same wallet.
pub fn is_owner_of(conn: &Connection, caller_wallet: &str, agent_wallet: &str) -> bool {
    if caller_wallet == agent_wallet {
        return true;
    }
    // Check if there exists a session for agent_wallet whose parent_token chain
    // leads back to a session owned by caller_wallet.
    let result: bool = conn
        .query_row(
            "SELECT 1 FROM sessions AS child
             WHERE child.wallet_address = ?1
               AND child.parent_token IN (
                   SELECT token FROM sessions WHERE wallet_address = ?2
               )
             LIMIT 1",
            params![agent_wallet, caller_wallet],
            |_| Ok(true),
        )
        .unwrap_or(false);
    result
}

pub fn extract_bearer_token(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

pub fn generate_wallet_address() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 20] = rng.gen();
    format!("0x{}", hex::encode(bytes))
}

pub fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

pub fn generate_nonce() -> [u8; 32] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}

pub fn derive_pair_code_from_nonce(nonce: &[u8]) -> String {
    hex::encode(&nonce[..4]).to_uppercase()
}
