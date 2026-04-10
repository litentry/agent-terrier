use rusqlite::{Connection, Result};

pub fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS accounts (
            wallet_address TEXT PRIMARY KEY,
            auth_token TEXT NOT NULL,
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            wallet_address TEXT NOT NULL REFERENCES accounts(wallet_address),
            parent_token TEXT,
            scope_json TEXT,
            created_at INTEGER NOT NULL,
            ttl_seconds INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS credentials (
            wallet_address TEXT NOT NULL,
            service_name TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (wallet_address, service_name)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_wallet TEXT NOT NULL,
            agent_wallet TEXT NOT NULL,
            service_name TEXT NOT NULL,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rendezvous_registrations (
            pair_code TEXT PRIMARY KEY,
            registration_token TEXT NOT NULL,
            daemon_pubkey BLOB NOT NULL,
            payload BLOB,
            delivered INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            ttl_seconds INTEGER NOT NULL DEFAULT 300
        );

        CREATE TABLE IF NOT EXISTS auth_requests (
            id TEXT PRIMARY KEY,
            pair_code TEXT NOT NULL,
            request_type TEXT NOT NULL,
            request_details BLOB NOT NULL,
            child_pubkey BLOB NOT NULL,
            parent_wallet TEXT,
            otp TEXT NOT NULL,
            nonce BLOB NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            signature BLOB,
            session_json TEXT,
            wallet_address TEXT,
            created_at INTEGER NOT NULL,
            ttl_seconds INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS identity_links (
            wallet_address TEXT NOT NULL,
            identity_type TEXT NOT NULL,
            identity_value TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (wallet_address, identity_type, identity_value)
        );
        ",
    )
}
