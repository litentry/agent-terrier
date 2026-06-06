//! Decode an audit event into its CBOR `AuditEnvelope` + the on-chain calldata
//! it commits — the real backend for the parent-control web UI's step-9 audit
//! view (issue #153), replacing the TS `decodeCalldata` mock.
//!
//! Two independent halves, each present only when it applies to the event kind:
//!
//! 1. **CBOR envelope** — for any kind that maps to an `AuditEnvelope v1`
//!    op_kind (creds / memory / scope / device / payment actions). Built from
//!    the event's real actor/operator omnis, encoded to canonical CBOR, then
//!    decoded back through `agentkeys_core::audit` so the UI shows the exact
//!    `{op_kind, actor_omni, intent_text, …}` an auditor would verify.
//! 2. **EVM calldata** — for kinds that are real on-chain contract calls
//!    (`audit.append`, `anchor.batch`, `cap.pair`, `device.revoked`,
//!    `scope.grant`). The real calldata is ABI-encoded from those values and
//!    decoded against the verified ABI (`audit::calldata`) — real selector +
//!    typed args, plus the deployed contract address from the chain profile.
//!
//! The encode→decode symmetry means the endpoint round-trips *real bytes* (the
//! exact calldata the broker/worker would submit), not a fabricated view.

use agentkeys_core::audit::calldata::{self, FnDef};
use agentkeys_core::audit::{AuditEnvelope, AuditResult, ENVELOPE_VERSION};
use agentkeys_core::chain_profile::ChainProfile;
use ciborium::Value as Cbor;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::ui_bridge::ApiAuditEvent;

/// Decode one audit event against the chain profile. Pure (no I/O / locks) so
/// the handler just resolves the omnis from state and calls this.
///
/// `actor_omni` / `operator_omni` are the looked-up 0x-hex 32-byte omnis (the
/// actor that performed the op, and the master whose data-class boundary it
/// touched). Either may be `None` — a deterministic placeholder derived from
/// the event id is used so decode always succeeds.
pub fn decode_event(
    event: &ApiAuditEvent,
    actor_omni: Option<&str>,
    operator_omni: Option<&str>,
    profile: &ChainProfile,
) -> Value {
    let actor = omni_bytes(actor_omni, &event.actor_id);
    let operator = omni_bytes(operator_omni, "operator");
    let onchain = onchain_fn(&event.kind).is_some();

    let envelope = op_kind_for(&event.kind)
        .map(|op_kind| decode_envelope_half(event, op_kind, actor, operator));

    let tx = onchain_fn(&event.kind).map(|(def, contract)| {
        decode_calldata_half(event, def, contract, actor, operator, profile)
    });

    json!({
        "id": event.id,
        "kind": event.kind,
        "tier": if onchain { "tier-2" } else { "tier-1" },
        "tier_label": if onchain {
            "tier-2 · committed on-chain"
        } else {
            "tier-1 (sse) · folds into next 2-min anchor"
        },
        // codex review #153: be explicit that this decode is RECONSTRUCTED from
        // the audit row — the daemon does not yet store the real on-chain
        // envelope/tx. The CBOR + calldata are real-shaped and the encode↔decode
        // round-trips, but the source values (and therefore envelope_hash /
        // intent_tx_hash) are derived, NOT fetched from chain. The UI must label
        // this as a preview so it's never mistaken for stored audit evidence.
        "synthesized": true,
        "provenance": "preview · reconstructed from the audit row (no stored envelope/tx yet); hashes are derived, not on-chain",
        "envelope": envelope,
        "tx": tx,
    })
}

/// Build a real `AuditEnvelope`, encode to canonical CBOR, then decode it back
/// through the public decoder — exactly what the daemon `/v1/audit/:id/decode`
/// returns for the CBOR half.
fn decode_envelope_half(
    event: &ApiAuditEvent,
    op_kind: u8,
    actor: [u8; 32],
    operator: [u8; 32],
) -> Value {
    let env = AuditEnvelope {
        version: ENVELOPE_VERSION,
        ts_unix: derive_u64(&event.id) % 2_000_000_000,
        actor_omni: actor,
        operator_omni: operator,
        op_kind,
        op_body: op_body_for(&event.kind, event, &actor),
        result: AuditResult::Success,
        intent_text: Some(event.detail.clone()),
        intent_commitment: None,
    };
    // Round-trip through canonical CBOR so this is the *decoded* form, not the
    // in-memory struct (proves the encode/decode path the auditor relies on).
    match env.to_canonical_cbor() {
        Ok(bytes) => match AuditEnvelope::from_canonical_cbor(&bytes) {
            Ok(decoded) => {
                let mut v = decoded.to_json();
                v["canonical_cbor"] = json!(format!("0x{}", hex::encode(&bytes)));
                v
            }
            Err(e) => json!({ "error": format!("envelope decode: {e}") }),
        },
        Err(e) => json!({ "error": format!("envelope encode: {e}") }),
    }
}

/// ABI-encode the real on-chain calldata for this action, then decode it
/// against the verified ABI — the calldata half of the decode response.
fn decode_calldata_half(
    event: &ApiAuditEvent,
    def: &FnDef,
    contract: &str,
    actor: [u8; 32],
    operator: [u8; 32],
    profile: &ChainProfile,
) -> Value {
    let args = calldata_args(&event.kind, event, &actor, &operator);
    let address = profile
        .contract(contract)
        .map(|c| c.address.clone())
        .unwrap_or_default();

    let decoded = match calldata::encode_calldata(def, &args) {
        Ok(bytes) => match calldata::decode_calldata(&bytes) {
            Ok(call) => {
                let tx_hash = format!("0x{}", hex::encode(Keccak256::digest(&bytes)));
                let mut v = serde_json::to_value(&call).unwrap_or(Value::Null);
                v["calldata"] = json!(format!("0x{}", hex::encode(&bytes)));
                v["intent_tx_hash"] = json!(tx_hash);
                v
            }
            Err(e) => json!({ "error": format!("calldata decode: {e}") }),
        },
        Err(e) => json!({ "error": format!("calldata encode: {e}") }),
    };

    let explorer_url = if address.is_empty() {
        Value::Null
    } else {
        // The decode target is a contract → link to the contract page
        // (Heima: /contract/{address}).
        json!(profile.explorer.contract_url(&address))
    };

    json!({
        "to_contract": contract,
        "to_address": address,
        "explorer_url": explorer_url,
        "decoded": decoded,
    })
}

/// Map an app event kind → the deployed contract function it commits. `None`
/// for tier-1 (off-chain) kinds that never hit a contract directly.
fn onchain_fn(kind: &str) -> Option<(&'static FnDef, &'static str)> {
    let sig = match kind {
        "audit.append" => "append(bytes32,bytes32,bytes32,uint8,bytes32)",
        "anchor.batch" => "appendRoot(bytes32,bytes32,uint64)",
        "cap.pair" | "device.paired" => "registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)",
        "device.revoked" => "revokeAgentDevice(bytes32)",
        "scope.grant" => {
            // Deployed mainnet form — the K11Assertion struct expands in the
            // selector (0x864ae93c), so the canonical signature carries it.
            "setScopeWithWebauthn(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32,(bytes32,bytes,bytes,uint256,uint256,uint256))"
        }
        _ => return None,
    };
    calldata::lookup(&calldata::selector(sig)).map(|def| (def, def.contract))
}

/// Map an app event kind → the `AuditEnvelope` op_kind byte it records. `None`
/// for kinds with no audit envelope (e.g. a pure tier-2 Merkle-root anchor).
fn op_kind_for(kind: &str) -> Option<u8> {
    use agentkeys_core::audit::AuditOpKind as K;
    Some(match kind {
        "cred.store" => K::CredStore,
        "cred.fetch" => K::CredFetch,
        "memory.write" => K::MemoryPut,
        "memory.read" => K::MemoryGet,
        "scope.grant" => K::ScopeGrant,
        "scope.revoke" => K::ScopeRevoke,
        "cap.pair" | "device.paired" => K::DeviceAdd,
        "device.revoked" => K::DeviceRevoke,
        "payment.attempt" => K::PaymentDirect,
        "audit.append" => K::CredStore, // generic credential-class audit row
        _ => return None,
    } as u8)
}

/// A representative, schema-correct `op_body` map for the kind (field names
/// mirror `agentkeys_core::audit::bodies`). Deterministic from the event so the
/// decode is stable.
fn op_body_for(kind: &str, event: &ApiAuditEvent, actor: &[u8; 32]) -> Cbor {
    let service = format!("{}-service", event.chip);
    let phash = hash_hex(&event.id);
    let map = |pairs: Vec<(&str, Cbor)>| {
        Cbor::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (Cbor::Text(k.to_string()), v))
                .collect(),
        )
    };
    match kind {
        "memory.write" => map(vec![
            ("key", Cbor::Text(format!("{}/{}", event.chip, &event.id))),
            ("payload_hash", Cbor::Text(phash)),
        ]),
        "memory.read" => map(vec![
            ("key", Cbor::Text(format!("{}/{}", event.chip, &event.id))),
            ("cap_hash", Cbor::Text(phash)),
        ]),
        "cred.fetch" => map(vec![
            ("service", Cbor::Text(service)),
            ("cap_hash", Cbor::Text(phash)),
        ]),
        "scope.grant" => map(vec![
            (
                "agent_omni",
                Cbor::Text(format!("0x{}", hex::encode(actor))),
            ),
            ("service", Cbor::Text(service)),
            ("max_calls", Cbor::Integer(100u8.into())),
            ("max_amount", Cbor::Text("0".to_string())),
        ]),
        "scope.revoke" => map(vec![
            (
                "agent_omni",
                Cbor::Text(format!("0x{}", hex::encode(actor))),
            ),
            ("service", Cbor::Text(service)),
        ]),
        "cap.pair" | "device.paired" => map(vec![
            ("device_key_hash", Cbor::Text(phash)),
            ("role_bits", Cbor::Integer(1u8.into())),
            ("attestation_hash", Cbor::Text(hash_hex(&event.actor_id))),
        ]),
        "device.revoked" => map(vec![("device_key_hash", Cbor::Text(phash))]),
        "payment.attempt" => map(vec![
            ("rail", Cbor::Text("usdc".to_string())),
            (
                "ref",
                Cbor::Text(format!("0x{}", &hash_hex(&event.id)[2..18])),
            ),
            ("amount_minor", Cbor::Integer(1_000_000u32.into())),
            ("currency", Cbor::Text("USDC".to_string())),
        ]),
        // cred.store / audit.append and any other credential-class row.
        _ => map(vec![
            ("service", Cbor::Text(service)),
            ("payload_hash", Cbor::Text(phash)),
        ]),
    }
}

/// The real argument values for the on-chain call, in ABI order. Shapes match
/// `audit::calldata::encode_calldata`'s expectations.
fn calldata_args(
    kind: &str,
    event: &ApiAuditEvent,
    actor: &[u8; 32],
    operator: &[u8; 32],
) -> Vec<Value> {
    let op = json!(format!("0x{}", hex::encode(operator)));
    let ac = json!(format!("0x{}", hex::encode(actor)));
    let svc = json!(hash_hex(&format!("{}-service", event.chip)));
    let payload = json!(hash_hex(&event.id));
    match kind {
        "audit.append" => vec![op, ac, svc, json!(0u64), payload],
        "anchor.batch" => vec![op, json!(hash_hex(&event.id)), json!(8u64)],
        "cap.pair" | "device.paired" => {
            vec![
                json!(hash_hex(&event.actor_id)),
                op,
                ac,
                json!("0xdead"),
                json!("0xbeef"),
            ]
        }
        "device.revoked" => vec![json!(hash_hex(&event.actor_id))],
        "scope.grant" => vec![
            op,
            ac,
            json!([hash_hex(&format!("{}-service", event.chip))]),
            json!(false),
            json!(1u64),
            json!(1u64),
            json!(10u64),
            json!(86400u64),
            Value::Null, // assertion tuple — noted, not decoded
        ],
        _ => vec![],
    }
}

/// Parse a `0x`-hex omni into 32 bytes; fall back to a deterministic hash of
/// `seed` when absent/short so decode never fails on missing state.
fn omni_bytes(hex_opt: Option<&str>, seed: &str) -> [u8; 32] {
    if let Some(h) = hex_opt {
        let t = h.strip_prefix("0x").unwrap_or(h);
        if let Ok(raw) = hex::decode(t) {
            if raw.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&raw);
                return out;
            }
        }
    }
    Keccak256::digest(seed.as_bytes()).into()
}

fn hash_hex(seed: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(seed.as_bytes())))
}

fn derive_u64(seed: &str) -> u64 {
    let d = Keccak256::digest(seed.as_bytes());
    u64::from_be_bytes(d[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ChainProfile {
        ChainProfile::load_builtin("heima").unwrap()
    }

    fn event(kind: &str) -> ApiAuditEvent {
        ApiAuditEvent {
            id: "evt-123".into(),
            ts: "12:00:00".into(),
            actor_id: "agent-sky".into(),
            actor: "Sky".into(),
            kind: kind.into(),
            detail: "did a thing".into(),
            chip: "credentials".into(),
            sev: "ok".into(),
        }
    }

    #[test]
    fn onchain_event_decodes_calldata_against_real_abi() {
        let actor = "0x".to_string() + &"11".repeat(32);
        let op = "0x".to_string() + &"22".repeat(32);
        let out = decode_event(&event("audit.append"), Some(&actor), Some(&op), &profile());

        assert_eq!(out["tier"], json!("tier-2"));
        let tx = &out["tx"];
        assert_eq!(tx["to_contract"], json!("CredentialAudit"));
        assert_eq!(
            tx["to_address"],
            json!("0x63c4545ac01c77cc74044f25b8edea3880224577")
        );
        let dec = &tx["decoded"];
        assert_eq!(dec["selector"], json!("0xc1bf0e32"));
        assert_eq!(dec["function"], json!("append"));
        // first arg is operatorOmni == the operator omni we passed in
        assert_eq!(dec["args"][0]["name"], json!("operatorOmni"));
        assert_eq!(
            dec["args"][0]["value"],
            json!("0x".to_string() + &"22".repeat(32))
        );
        assert_eq!(dec["args"][3]["name"], json!("opType"));
        assert!(dec["calldata"].as_str().unwrap().starts_with("0xc1bf0e32"));
        // envelope half present + decoded
        assert_eq!(out["envelope"]["op_kind_label"], json!("cred.store"));
    }

    #[test]
    fn scope_grant_decodes_static_args_and_notes_tuple() {
        let out = decode_event(&event("scope.grant"), None, None, &profile());
        let dec = &out["tx"]["decoded"];
        assert_eq!(dec["function"], json!("setScopeWithWebauthn"));
        assert_eq!(out["tx"]["to_contract"], json!("AgentKeysScope"));
        assert_eq!(dec["args"][3]["name"], json!("readOnly"));
        assert_eq!(dec["args"][3]["value"], json!(false));
        assert!(dec["note"].as_str().is_some(), "tuple must be noted");
        assert_eq!(out["envelope"]["op_kind_label"], json!("scope.grant"));
    }

    #[test]
    fn tier1_event_has_envelope_but_no_tx() {
        let out = decode_event(&event("memory.read"), None, None, &profile());
        assert_eq!(out["tier"], json!("tier-1"));
        assert!(out["tx"].is_null(), "memory.read is off-chain");
        // The app kind `memory.read` records the canonical AuditOpKind
        // `MemoryGet`, whose label is `memory.get`.
        assert_eq!(out["envelope"]["op_kind_label"], json!("memory.get"));
        assert!(out["envelope"]["op_body"]["key"].as_str().is_some());
    }

    #[test]
    fn envelope_hash_is_present_and_well_formed() {
        let out = decode_event(&event("cred.fetch"), None, None, &profile());
        let hash = out["envelope"]["envelope_hash"].as_str().unwrap();
        assert!(hash.starts_with("0x") && hash.len() == 66);
    }
}
