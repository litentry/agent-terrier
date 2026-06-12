use rusqlite::params;

/// Shared typed identity → wallet resolver (Issue #13, AGENTS.md Backend Design Principles).
/// Called from `approve_auth_request` Recover branch and `recover_session` handler.
///
/// `identity_type` must be one of `"alias"`, `"email"`, `"ens"`, `"wallet"`.
/// - `"alias"`, `"email"`, `"ens"` query `identity_links` for the matching row.
/// - `"wallet"` validates hex format AND confirms the wallet exists in `accounts`
///   before returning it (prevents 500 on later FK constraint in `sessions`).
pub fn resolve_identity_typed(
    db: &rusqlite::Connection,
    identity_type: &str,
    identity_value: &str,
) -> Result<String, crate::error::AppError> {
    match identity_type {
        "alias" | "email" | "ens" => db
            .query_row(
                "SELECT wallet_address FROM identity_links WHERE identity_type = ?1 AND identity_value = ?2",
                params![identity_type, identity_value],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| {
                crate::error::AppError::not_found(format!(
                    "no identity found for type={} value={}",
                    identity_type, identity_value
                ))
            }),
        "wallet" => {
            if !identity_value.starts_with("0x")
                || !identity_value[2..].chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(crate::error::AppError::bad_request(format!(
                    "invalid wallet address format: {}",
                    identity_value
                )));
            }
            let exists: bool = db
                .query_row(
                    "SELECT 1 FROM accounts WHERE wallet_address = ?1",
                    params![identity_value],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if !exists {
                return Err(crate::error::AppError::not_found(format!(
                    "no account found for wallet {}",
                    identity_value
                )));
            }
            Ok(identity_value.to_string())
        }
        other => Err(crate::error::AppError::bad_request(format!(
            "unknown identity_type '{}'. Use 'alias', 'email', 'ens', or 'wallet'.",
            other
        ))),
    }
}
