use agentkeys_types::{Session, WalletAddress};

pub fn build_session_from_token(token: String) -> Session {
    Session {
        token,
        wallet: WalletAddress("local".into()),
        scope: None,
        created_at: 0,
        ttl_seconds: 86400,
    }
}
