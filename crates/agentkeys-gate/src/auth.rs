//! Caller authentication: `Authorization: Bearer <relay key>` → the key
//! record carrying the attribution triple (user, device, key-id).
//!
//! #427: key RESOLUTION moved to the live registry (`keys::KeyStore` — one
//! auth path; the boot snapshot in `GateConfig.keys` never authenticates a
//! request directly, so broker-minted keys work and disabled keys refuse).
//! This module keeps the bearer parse + the operator admin-token check.

use crate::config::GateConfig;
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

    fn cfg(admin: Option<&str>) -> GateConfig {
        GateConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: UpstreamConfig {
                base_url: "http://127.0.0.1:1/v1".into(),
                api_key: "upstream".into(),
                model_override: None,
            },
            keys: vec![],
            user_budgets: Default::default(),
            default_budget_tokens: None,
            admin_token: admin.map(str::to_string),
            keys_file: None,
            audit_url: None,
            require_audit: false,
            aws_region: "us-east-1".into(),
            speech_asr: None,
            speech_tts: None,
        }
    }

    #[test]
    fn bearer_parses_and_rejects_non_bearer_forms() {
        assert_eq!(bearer(Some("Bearer tok")).unwrap(), "tok");
        assert!(matches!(bearer(None), Err(GateError::Unauthorized(_))));
        assert!(matches!(
            bearer(Some("Basic tok")),
            Err(GateError::Unauthorized(_))
        ));
        assert!(matches!(
            bearer(Some("Bearer ")),
            Err(GateError::Unauthorized(_))
        ));
    }

    #[test]
    fn admin_token_matches_only_itself() {
        let c = cfg(Some("admintok"));
        assert!(is_admin(&c, Some("Bearer admintok")));
        assert!(!is_admin(&c, Some("Bearer gk_secret")));
        assert!(!is_admin(&c, None));
        let no_admin = cfg(None);
        assert!(!is_admin(&no_admin, Some("Bearer anything")));
    }
}
