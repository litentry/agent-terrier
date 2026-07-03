//! Caller authentication: `Authorization: Bearer <relay key>` → the key
//! record carrying the attribution triple (user, device, key-id).
//!
//! v1 keys come from the operator's keys file; broker-minted keys at
//! sandbox-spawn (tied to #369 delegation) are the tracked follow-up in #384.

use crate::config::{GateConfig, RelayKey};
use crate::error::{GateError, GateResult};

/// Constant-time byte comparison — a plain `==` on secrets leaks a timing
/// oracle on the matching prefix length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn bearer(header: Option<&str>) -> GateResult<&str> {
    let raw = header.ok_or_else(|| GateError::Unauthorized("missing Authorization".into()))?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or_else(|| GateError::Unauthorized("Authorization is not a Bearer token".into()))?
        .trim();
    if token.is_empty() {
        return Err(GateError::Unauthorized("empty bearer token".into()));
    }
    Ok(token)
}

/// Resolve a bearer token to its relay key record.
pub fn authenticate<'a>(config: &'a GateConfig, header: Option<&str>) -> GateResult<&'a RelayKey> {
    let token = bearer(header)?;
    config
        .keys
        .iter()
        .find(|k| ct_eq(k.key.as_bytes(), token.as_bytes()))
        .ok_or_else(|| GateError::Unauthorized("unknown relay key".into()))
}

/// True when the bearer matches the operator admin token.
pub fn is_admin(config: &GateConfig, header: Option<&str>) -> bool {
    match (&config.admin_token, bearer(header)) {
        (Some(admin), Ok(token)) if !admin.is_empty() => ct_eq(admin.as_bytes(), token.as_bytes()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamConfig;

    fn cfg(keys: Vec<RelayKey>, admin: Option<&str>) -> GateConfig {
        GateConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: UpstreamConfig {
                base_url: "http://127.0.0.1:1/v1".into(),
                api_key: "upstream".into(),
                model_override: None,
            },
            keys,
            user_budgets: Default::default(),
            default_budget_tokens: None,
            admin_token: admin.map(str::to_string),
            audit_url: None,
            require_audit: false,
            aws_region: "us-east-1".into(),
        }
    }

    fn key(secret: &str) -> RelayKey {
        RelayKey {
            key: secret.into(),
            key_id: "k1".into(),
            user_omni: format!("0x{}", "aa".repeat(32)),
            device_id: "esp32-01".into(),
            label: String::new(),
        }
    }

    #[test]
    fn known_key_resolves_unknown_401s() {
        let c = cfg(vec![key("gk_secret")], None);
        assert_eq!(
            authenticate(&c, Some("Bearer gk_secret")).unwrap().key_id,
            "k1"
        );
        assert!(matches!(
            authenticate(&c, Some("Bearer nope")),
            Err(GateError::Unauthorized(_))
        ));
        assert!(matches!(
            authenticate(&c, None),
            Err(GateError::Unauthorized(_))
        ));
        assert!(matches!(
            authenticate(&c, Some("Basic gk_secret")),
            Err(GateError::Unauthorized(_))
        ));
    }

    #[test]
    fn admin_token_matches_only_itself() {
        let c = cfg(vec![key("gk_secret")], Some("admintok"));
        assert!(is_admin(&c, Some("Bearer admintok")));
        assert!(!is_admin(&c, Some("Bearer gk_secret")));
        assert!(!is_admin(&c, None));
        let no_admin = cfg(vec![], None);
        assert!(!is_admin(&no_admin, Some("Bearer anything")));
    }
}
