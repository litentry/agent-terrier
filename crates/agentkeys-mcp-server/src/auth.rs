//! Bearer + per-actor auth for the HTTP transport.
//!
//! Vendors deploy this MCP server behind a per-vendor bearer token. The
//! `Authorization: Bearer <token>` header authenticates the vendor; the
//! `X-AgentKeys-Actor` header binds the call to a specific actor omni.
//!
//! Acceptance criterion #3 (issue #107): wrong token → 401, missing
//! actor header → 403, tool params naming a different actor than the
//! header → 403 (audit row required).
//!
//! Stdio transport has no headers — the parent process is implicitly
//! trusted to set the actor via tool params.

use crate::config::Config;
use crate::errors::{McpError, McpResult};

/// What the HTTP layer extracted from the request headers.
#[derive(Debug, Clone)]
pub struct CallerContext {
    pub vendor_id: String,
    pub actor_omni: String,
}

impl CallerContext {
    pub fn new(vendor_id: impl Into<String>, actor_omni: impl Into<String>) -> Self {
        Self {
            vendor_id: vendor_id.into(),
            actor_omni: actor_omni.into(),
        }
    }

    /// Stdio mode synthesizes a trusted-local caller. The actor still
    /// has to be passed in tool params; this just lets tool dispatch
    /// not branch on transport.
    pub fn local_stdio() -> Self {
        Self {
            vendor_id: "local".into(),
            actor_omni: "*".into(),
        }
    }
}

/// Validate `Authorization: Bearer <token>` against the configured vendor map.
/// Returns the matched `vendor_id` on success.
pub fn check_bearer(config: &Config, header_value: Option<&str>) -> McpResult<String> {
    let header = header_value
        .ok_or_else(|| McpError::Unauthorized("missing Authorization header".to_string()))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            McpError::Unauthorized(
                "malformed Authorization header (expected `Bearer <token>`)".to_string(),
            )
        })?
        .trim();

    if token.is_empty() {
        return Err(McpError::Unauthorized("empty bearer token".to_string()));
    }

    for (vendor_id, expected) in &config.vendor_tokens {
        if constant_time_eq(expected.as_bytes(), token.as_bytes()) {
            return Ok(vendor_id.clone());
        }
    }

    Err(McpError::Unauthorized(
        "bearer token not recognized".to_string(),
    ))
}

/// Validate `X-AgentKeys-Actor: <omni>` header. Returns the actor omni.
/// Returning `Forbidden` (not `Unauthorized`) matches the acceptance
/// criterion in issue #107 ("no-header → 403").
pub fn check_actor_header(header_value: Option<&str>) -> McpResult<String> {
    let actor = header_value
        .ok_or_else(|| McpError::Forbidden("missing X-AgentKeys-Actor header".to_string()))?
        .trim();
    if actor.is_empty() {
        return Err(McpError::Forbidden(
            "empty X-AgentKeys-Actor header".to_string(),
        ));
    }
    Ok(actor.to_string())
}

/// Cross-check the actor named in the tool params against the header-bound
/// actor. Per issue #107 acceptance: a vendor cannot operate on actor A
/// while presenting a header for actor B.
pub fn check_actor_param(header_actor: &str, param_actor: &str) -> McpResult<()> {
    if header_actor == param_actor {
        Ok(())
    } else {
        Err(McpError::Forbidden(format!(
            "actor mismatch: header={header_actor}, param={param_actor}"
        )))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::for_tests().with_vendor_token("vendor-a", "tok-a")
    }

    #[test]
    fn bearer_missing_header_is_401() {
        let err = check_bearer(&cfg(), None).unwrap_err();
        assert!(matches!(err, McpError::Unauthorized(_)));
    }

    #[test]
    fn bearer_wrong_token_is_401() {
        let err = check_bearer(&cfg(), Some("Bearer nope")).unwrap_err();
        assert!(matches!(err, McpError::Unauthorized(_)));
    }

    #[test]
    fn bearer_correct_token_returns_vendor() {
        let v = check_bearer(&cfg(), Some("Bearer tok-a")).unwrap();
        assert_eq!(v, "vendor-a");
    }

    #[test]
    fn bearer_malformed_prefix_is_401() {
        let err = check_bearer(&cfg(), Some("Token tok-a")).unwrap_err();
        assert!(matches!(err, McpError::Unauthorized(_)));
    }

    #[test]
    fn actor_header_missing_is_403() {
        let err = check_actor_header(None).unwrap_err();
        assert!(matches!(err, McpError::Forbidden(_)));
    }

    #[test]
    fn actor_param_mismatch_is_403() {
        let err = check_actor_param("O_alice", "O_bob").unwrap_err();
        assert!(matches!(err, McpError::Forbidden(_)));
    }

    #[test]
    fn actor_param_match_ok() {
        assert!(check_actor_param("O_alice", "O_alice").is_ok());
    }
}
