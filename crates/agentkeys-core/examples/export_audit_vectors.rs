//! Cross-language canonical-CBOR test-vector exporter for `AuditEnvelope v1`
//! (issue #12 Artifact 3 — the load-bearing drift guard against re-ported
//! decoders, e.g. `litentry/subscan-essentials/internal/agentkeys`).
//!
//! Emits a JSON array to stdout. Each element is one vector:
//!
//! ```json
//! {
//!   "op_kind": 21,
//!   "op_kind_label": "sign.eip712",
//!   "envelope_json": { ...9 envelope-level fields, op_body nested... },
//!   "canonical_cbor_hex": "0x...",   // bytes encode_canonical() produced
//!   "envelope_hash_hex":  "0x..."    // keccak256(canonical_cbor_hex)
//! }
//! ```
//!
//! A conforming decoder in any language MUST, for every vector:
//!   1. build canonical CBOR from `envelope_json` and match `canonical_cbor_hex`
//!      byte-for-byte (RFC 8949 §4.2.1 deterministic encoding — recursive
//!      map-key sort by encoded-byte order);
//!   2. `keccak256(bytes)` and match `envelope_hash_hex`.
//!
//! Note on `intent_commitment`: these vectors carry a FIXED opaque 32-byte
//! value (`0xcc..cc`) when present — they exercise envelope-level CBOR
//! encoding determinism only. The commitment-derivation check
//! (`keccak256(intent_text || 0x7c || op_payload_digest)`) is a separate
//! concern (issue #12 Artifact 2), independent of byte-level CBOR stability.
//!
//! Regenerate:
//! ```bash
//! cargo run -p agentkeys-core --example export_audit_vectors
//! ```

use agentkeys_core::audit::{
    AuditEnvelope, AuditOpKind, AuditResult, CredFetchBody, CredStoreBody, DeviceAddBody,
    K3EpochAdvanceBody, MemoryPutBody, PaymentDirectBody, PaymentEscrowRedeemBody, ScopeGrantBody,
    SignEip191Body, SignEip712Body, ENVELOPE_VERSION,
};
use serde::Serialize;
use serde_json::{json, Value};

const ACTOR: [u8; 32] = [0x11; 32];
const OPERATOR: [u8; 32] = [0x22; 32];
const TS_UNIX: u64 = 1_700_000_000;
const FIXED_COMMITMENT: [u8; 32] = [0xcc; 32];

fn vector<B: Serialize>(op_kind: AuditOpKind, body: B, intent_text: Option<&str>) -> Value {
    let body_json = serde_json::to_value(&body).expect("serialize op_body");
    let intent = intent_text.map(str::to_string);
    let commitment = intent.as_ref().map(|_| FIXED_COMMITMENT);

    let mut env = agentkeys_core::audit::envelope_for(
        ACTOR,
        OPERATOR,
        op_kind,
        body,
        AuditResult::Success,
        intent.clone(),
        commitment,
    )
    .expect("build envelope");
    env.ts_unix = TS_UNIX; // envelope_for sets 0 (worker fills); pin for determinism

    finalize(
        op_kind as u8,
        op_kind.label(),
        &env,
        body_json,
        intent,
        commitment,
    )
}

/// Unknown / future-reserved op_kind canary (non-break invariant #1+#4): no
/// typed body struct exists, so build the envelope directly with an opaque
/// `op_body` map. A v1 decoder MUST still decode every envelope-level field
/// and render `Unknown(byte)`.
fn unknown_vector(op_kind_byte: u8) -> Value {
    let op_body = ciborium::Value::Map(vec![(
        ciborium::Value::Text("future_field_only_v2_knows".into()),
        ciborium::Value::Text("opaque".into()),
    )]);
    let op_body_json = json!({ "future_field_only_v2_knows": "opaque" });
    let env = AuditEnvelope {
        version: ENVELOPE_VERSION,
        ts_unix: TS_UNIX,
        actor_omni: ACTOR,
        operator_omni: OPERATOR,
        op_kind: op_kind_byte,
        op_body,
        result: AuditResult::Success,
        intent_text: None,
        intent_commitment: None,
    };
    finalize(op_kind_byte, "unknown", &env, op_body_json, None, None)
}

fn finalize(
    op_kind_byte: u8,
    label: &str,
    env: &AuditEnvelope,
    op_body_json: Value,
    intent: Option<String>,
    commitment: Option<[u8; 32]>,
) -> Value {
    let cbor = env.to_canonical_cbor().expect("encode canonical cbor");
    let hash = env.envelope_hash().expect("envelope hash");
    let envelope_json = json!({
        "version": env.version,
        "ts_unix": env.ts_unix,
        "actor_omni": hex0x(&env.actor_omni),
        "operator_omni": hex0x(&env.operator_omni),
        "op_kind": op_kind_byte,
        "op_body": op_body_json,
        "result": AuditResult::Success as u8,
        "intent_text": intent,
        "intent_commitment": commitment.map(|c| hex0x(&c)),
    });
    json!({
        "op_kind": op_kind_byte,
        "op_kind_label": label,
        "envelope_json": envelope_json,
        "canonical_cbor_hex": hex0x(&cbor),
        "envelope_hash_hex": hex0x(&hash),
    })
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn main() {
    let vectors = vec![
        vector(
            AuditOpKind::CredStore,
            CredStoreBody {
                service: "openrouter".into(),
                payload_hash: hex0x(&[0xab; 32]),
            },
            Some("Store credential for openrouter"),
        ),
        vector(
            AuditOpKind::CredFetch,
            CredFetchBody {
                service: "openrouter".into(),
                cap_hash: hex0x(&[0x1c; 32]),
            },
            None,
        ),
        vector(
            AuditOpKind::MemoryPut,
            MemoryPutBody {
                key: "profile/preferences".into(),
                payload_hash: hex0x(&[0x10; 32]),
            },
            None,
        ),
        vector(
            AuditOpKind::SignEip191,
            SignEip191Body {
                message_digest: hex0x(&[0x19; 32]),
                wallet: "0x1111111111111111111111111111111111111111".into(),
            },
            Some("Sign login challenge"),
        ),
        vector(
            AuditOpKind::SignEip712,
            SignEip712Body {
                chain_id: 212013,
                verifying_contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
                primary_type: "Permit".into(),
                type_hash: hex0x(&[0xde; 32]),
                domain_separator: hex0x(&[0xad; 32]),
                digest: hex0x(&[0xbe; 32]),
            },
            Some("Approve USDC 1000 to Uniswap v4 router"),
        ),
        vector(
            AuditOpKind::PaymentEscrowRedeem,
            PaymentEscrowRedeemBody {
                escrow_addr: "0x2222222222222222222222222222222222222222".into(),
                amount: "1000000000000000000000".into(),
                recipient: "0x3333333333333333333333333333333333333333".into(),
                chain_id: 212013,
            },
            None,
        ),
        vector(
            AuditOpKind::PaymentDirect,
            PaymentDirectBody {
                rail: "usdc".into(),
                r#ref: "0xabc".into(),
                amount_minor: 1_000_000,
                currency: "USDC".into(),
            },
            None,
        ),
        vector(
            AuditOpKind::ScopeGrant,
            ScopeGrantBody {
                agent_omni: hex0x(&[0x40; 32]),
                service: "openrouter".into(),
                max_calls: 100,
                max_amount: "0".into(),
            },
            None,
        ),
        vector(
            AuditOpKind::DeviceAdd,
            DeviceAddBody {
                device_key_hash: hex0x(&[0x50; 32]),
                role_bits: 1,
                attestation_hash: hex0x(&[0x51; 32]),
            },
            None,
        ),
        vector(
            AuditOpKind::K3EpochAdvance,
            K3EpochAdvanceBody {
                old_epoch: 4,
                new_epoch: 5,
                gov_tx: hex0x(&[0x70; 32]),
            },
            None,
        ),
        unknown_vector(250),
    ];

    let out = Value::Array(vectors);
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialize vectors")
    );
}
