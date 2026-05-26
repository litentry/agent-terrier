//! Schema-only stubs — `delegation.grant`, `delegation.revoke`,
//! `approval.request`. They exist so vendors integrating in M1 see the
//! full API shape; the wire format will not change when M4 lights them
//! up.
//!
//! Per issue #107 acceptance criterion #2: response shape is fixed and
//! exact — `{"error": "not_implemented_in_v1", "scheduled_for": "M4",
//! "spec_url": "..."}`.

use crate::errors::McpError;

pub const SPEC_URL: &str =
    "https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/milestones-roadmap.md#m4";

pub fn not_implemented_v1() -> McpError {
    McpError::NotImplementedV1 {
        scheduled_for: "M4",
        spec_url: SPEC_URL,
    }
}
