//! The broker/worker wire protocol — the **single owner** of every request
//! and response shape the cap-mint + worker chain serializes (issue #203).
//!
//! Before this crate the same JSON was hand-typed in three places (the MCP
//! `HttpBackend`, the daemon `ui_bridge`, and bash `jq -n` bodies in the
//! harness), which is the structural cause of the drift bugs #200 fixed
//! (`evm_address` vs `{address,chain_id}`, bare-vs-`0x` omni, per-namespace
//! field shapes). Re-typing one of these in a second place is now either a
//! compile error (Rust callers share these types) or a fixture mismatch (the
//! harness gate diffs bash bodies against [`crate::fixtures`]).
//!
//! Naming follows arch.md's canonical-names rule: the field names here MUST
//! match what `agentkeys_broker_server::handlers::cap` and the
//! `agentkeys_worker_*` handlers deserialize. We mirror by hand (not a shared
//! struct dep) because the broker/worker are heavy binaries — but the mirror
//! is now in ONE place, exercised end-to-end in the MCP server's
//! `tests/three_acts.rs` and pinned by [`crate::fixtures`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Op discriminator that maps onto the four broker cap-mint endpoints. The
/// route is the source of truth for the cap's `data_class` — the broker
/// statically derives the `DataClass` variant from which endpoint was hit, so
/// a `Memory` cap can never be minted from a `/v1/cap/cred-*` request (issue
/// #90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapMintOp {
    CredStore,
    CredFetch,
    MemoryPut,
    MemoryGet,
    /// #201 config data class — master-only taxonomy/config object. A third
    /// `DataClass::Config` with its own bucket + IAM role (arch.md §17.2); the
    /// cred + memory workers reject a Config cap via `verify::check_data_class`.
    ConfigStore,
    ConfigFetch,
}

impl CapMintOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cred_store" => Some(Self::CredStore),
            "cred_fetch" => Some(Self::CredFetch),
            "memory_put" => Some(Self::MemoryPut),
            "memory_get" => Some(Self::MemoryGet),
            "config_store" => Some(Self::ConfigStore),
            "config_fetch" => Some(Self::ConfigFetch),
            _ => None,
        }
    }

    pub fn broker_path(self) -> &'static str {
        match self {
            Self::CredStore => "/v1/cap/cred-store",
            Self::CredFetch => "/v1/cap/cred-fetch",
            Self::MemoryPut => "/v1/cap/memory-put",
            Self::MemoryGet => "/v1/cap/memory-get",
            Self::ConfigStore => "/v1/cap/config-store",
            Self::ConfigFetch => "/v1/cap/config-fetch",
        }
    }

    pub fn data_class(self) -> &'static str {
        match self {
            Self::CredStore | Self::CredFetch => "credentials",
            Self::MemoryPut | Self::MemoryGet => "memory",
            Self::ConfigStore | Self::ConfigFetch => "config",
        }
    }
}

/// The cap-mint request as the *caller* constructs it (omni's, service,
/// device hash, TTL). [`BrokerCapRequest`] is the on-the-wire serialization;
/// they have the same fields today but stay distinct so a caller-side concept
/// (e.g. a future client-only field) can't silently leak onto the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapMintRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    pub ttl_seconds: u64,
}

/// Broker cap-mint request body — the exact JSON
/// `agentkeys_broker_server::handlers::cap` deserializes for all four
/// `/v1/cap/*` endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerCapRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    pub ttl_seconds: u64,
}

impl From<CapMintRequest> for BrokerCapRequest {
    fn from(r: CapMintRequest) -> Self {
        Self {
            operator_omni: r.operator_omni,
            actor_omni: r.actor_omni,
            service: r.service,
            device_key_hash: r.device_key_hash,
            ttl_seconds: r.ttl_seconds,
        }
    }
}

/// Opaque cap-token blob — the broker signs it and the worker verifies the
/// signature; this side never inspects the inside, so a JSON `Value` is the
/// right type.
pub type CapToken = Value;

// ── memory worker (`/v1/memory/{put,get}`) ──────────────────────────────────

/// Memory-worker `/v1/memory/put` request body. Mirrors
/// `agentkeys_worker_memory::handlers::PutRequest`. `namespace` rides at the
/// body level for Phase 1 (lifting it into a SIGNED CapPayload field is an M4
/// follow-up per the wire-real-paths plan §8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
    pub namespace: String,
}

/// Memory-worker `/v1/memory/get` request body. Mirrors
/// `agentkeys_worker_memory::handlers::GetRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetBody {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryPutResp {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryGetResp {
    pub ok: bool,
    pub plaintext_b64: String,
}

// ── config worker (`/v1/config/{put,get}`) — #201 config data class ──────────

/// Config-worker `/v1/config/put` request body. Mirrors
/// `agentkeys_worker_config::handlers::PutRequest`. Config is a single
/// master-only object (the memory-types taxonomy), so — unlike `MemoryPutBody`
/// — there is NO `namespace` field; the object's identity is the signed cap
/// `service` (`memory-taxonomy`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPutBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

/// Config-worker `/v1/config/get` request body. Mirrors
/// `agentkeys_worker_config::handlers::GetRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGetBody {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigGetResp {
    pub ok: bool,
    pub plaintext_b64: String,
}

// ── audit worker (`/v1/audit/append/v2`) ────────────────────────────────────

/// Audit envelope version, pinned to `agentkeys_core::audit::ENVELOPE_VERSION`.
/// If that constant changes this must change too — covered by the MCP server's
/// integration smoke test.
pub const ENVELOPE_VERSION: u8 = 1;

/// Audit-worker `/v1/audit/append/v2` request body. Mirrors
/// `agentkeys_worker_audit::handlers::AppendV2Request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendV2 {
    pub version: u8,
    pub ts_unix: u64,
    pub actor_omni: String,
    pub operator_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
    pub intent_commitment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditAppendV2Resp {
    pub ok: bool,
    pub envelope_hash: String,
}

// ── high-level inputs / results (what the trait/callers pass + get back) ─────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutInput {
    pub cap: CapToken,
    pub namespace: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetInput {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutResult {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetResult {
    pub ok: bool,
    pub plaintext_b64: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendInput {
    pub operator_omni: String,
    pub actor_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendResult {
    pub ok: bool,
    pub envelope_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResult {
    pub ok: bool,
    pub revocation: String,
    /// Present when `revocation != "online_immediate"` — tells the caller what
    /// kind of revocation actually happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ── shared protocol helpers (the omni-normalization bug site, centralized) ───

/// Build the signed cap **service** string for a memory namespace —
/// `memory:<ns>`. The broker binds this into the cap's signed `service` field
/// (issue #150), so every caller MUST spell it identically; hand-formatting
/// `format!("memory:{ns}")` in a second place is exactly the per-namespace
/// drift this crate exists to kill.
pub fn service_memory(namespace: &str) -> String {
    format!("memory:{namespace}")
}

/// Normalize an omni to the broker's expected `0x`-prefixed lower-hex shape.
///
/// The broker cap-mint input-validates that `operator_omni`/`actor_omni` start
/// with `0x`, but several upstream sources (the daemon onboarding session, JWT
/// claims) store the omni **bare**. This was the `0x`/bare drift bug #200
/// fixed by normalizing inline in the daemon — now there is ONE normalizer so
/// the next caller can't reintroduce it. Already-`0x` input is returned
/// unchanged (case preserved; the broker lower-cases on its side).
pub fn normalize_omni_0x(omni: &str) -> String {
    if omni.starts_with("0x") || omni.starts_with("0X") {
        omni.to_string()
    } else {
        format!("0x{omni}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_mint_op_roundtrips_paths_and_classes() {
        for (s, path, class) in [
            ("cred_store", "/v1/cap/cred-store", "credentials"),
            ("cred_fetch", "/v1/cap/cred-fetch", "credentials"),
            ("memory_put", "/v1/cap/memory-put", "memory"),
            ("memory_get", "/v1/cap/memory-get", "memory"),
            ("config_store", "/v1/cap/config-store", "config"),
            ("config_fetch", "/v1/cap/config-fetch", "config"),
        ] {
            let op = CapMintOp::parse(s).unwrap();
            assert_eq!(op.broker_path(), path);
            assert_eq!(op.data_class(), class);
        }
        assert!(CapMintOp::parse("bogus").is_none());
    }

    #[test]
    fn service_memory_is_namespace_prefixed() {
        assert_eq!(service_memory("travel"), "memory:travel");
        assert_eq!(service_memory("webparity"), "memory:webparity");
    }

    #[test]
    fn normalize_omni_adds_prefix_once() {
        assert_eq!(normalize_omni_0x("abcd"), "0xabcd");
        assert_eq!(normalize_omni_0x("0xabcd"), "0xabcd");
        assert_eq!(normalize_omni_0x("0Xabcd"), "0Xabcd");
    }
}
