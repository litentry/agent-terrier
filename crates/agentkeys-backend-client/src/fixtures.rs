//! Canonical protocol fixtures — the bridge between the Rust wire types and
//! the harness's hand-rolled bash bodies (issue #203, enforce step).
//!
//! Each fixture is a **sample request body serialized from the real serde
//! type** in [`crate::protocol`], so its JSON keys are exactly what goes on the
//! wire — you cannot edit a struct field without changing the fixture. The
//! `dump-protocol-fixtures` bin writes these to
//! `e2e/fixtures/backend-protocol/*.json`; the bash gate
//! (`scripts/utils/check-backend-fixture-drift.sh`) diffs the key-set of every
//! hand-rolled `jq -n` cap/worker body against them. A drifted bash body
//! (added/renamed/dropped field) then fails CI instead of surfacing as a
//! runtime 4xx.
//!
//! Values are placeholders — the gate only compares **keys**. The frozen
//! key-set tests below catch a Rust-side rename the moment it happens (same
//! discipline as `actor_omni.rs`'s pinned digests).

use serde_json::{json, Value};

use crate::protocol::{
    AcceptAssertion, AuditAppendV2, BrokerCapRequest, BuildAcceptUserOpRequest,
    BuildArchiveUserOpRequest, BuildRegisterUserOpRequest, BuildRevokeUserOpRequest,
    BuildScopeUserOpRequest, BuildSpawnUserOpRequest, ChannelEventKind, ChannelPollBody,
    ChannelPublishBody, ConfigGetBody, ConfigPutBody, MemoryGetBody, MemoryPutBody,
    SubmitAcceptUserOpRequest, WireUserOp, ENVELOPE_VERSION,
};

/// One canonical fixture: the on-disk file stem + the sample body.
pub struct Fixture {
    pub name: &'static str,
    pub body: Value,
}

/// Every request shape that a bash body might hand-roll, serialized from its
/// real serde type. The `dump-protocol-fixtures` bin writes one `<name>.json`
/// per entry.
pub fn canonical_fixtures() -> Vec<Fixture> {
    // The canonical minimal cap-mint body — the K10 cap-PoP (issue #76) is
    // OPTIONAL (None here), so the fixture is the no-PoP shape that pre-#76
    // hand-rolled bash bodies still match. A PoP-signed body adds the optional
    // client_sig/client_nonce/client_ts keys.
    let cap = BrokerCapRequest {
        operator_omni: "0x<operator_omni>".into(),
        actor_omni: "0x<actor_omni>".into(),
        service: "memory:<namespace>".into(),
        device_key_hash: "0x<device_key_hash>".into(),
        ttl_seconds: Some(300),
        client_sig: None,
        client_nonce: None,
        client_ts: None,
        // None + skip_serializing_if → the serialized fixture (and its frozen key
        // set) is unchanged by the #369 delegation_path field.
        delegation_path: None,
    };
    let memory_put = MemoryPutBody {
        cap: json!("<cap-token>"),
        plaintext_b64: "<base64-plaintext>".into(),
        namespace: "<namespace>".into(),
    };
    let memory_get = MemoryGetBody {
        cap: json!("<cap-token>"),
        namespace: "<namespace>".into(),
    };
    let config_put = ConfigPutBody {
        cap: json!("<cap-token>"),
        // Canonical shape = the v3 client-encrypted envelope (#372 item 2);
        // the deprecated legacy plaintext_b64 is None + skip_serializing_if,
        // so it stays out of the fixture and its frozen key set.
        plaintext_b64: None,
        envelope_b64: Some("<base64-v3-envelope>".into()),
    };
    let config_get = ConfigGetBody {
        cap: json!("<cap-token>"),
    };
    let audit = AuditAppendV2 {
        version: ENVELOPE_VERSION,
        ts_unix: 0,
        actor_omni: "0x<actor_omni>".into(),
        operator_omni: "0x<operator_omni>".into(),
        op_kind: 0,
        op_body: json!({}),
        result: 0,
        intent_text: Some("<intent>".into()),
        intent_commitment: None,
    };
    let build_accept = BuildAcceptUserOpRequest {
        operator_omni: "0x<operator_omni>".into(),
        actor_omni: "0x<actor_omni>".into(),
        device_key_hash: "0x<device_key_hash>".into(),
        agent_pop_sig: "0x<agent_pop_sig>".into(),
        link_code_redemption: "0x<link_code_redemption>".into(),
        services: vec!["memory:<namespace>".into()],
        read_only: true,
        max_per_call: "0".into(),
        max_per_period: "0".into(),
        max_total: "0".into(),
        period_seconds: 0,
        // #408: false = a delegate accept (skip_serializing_if keeps the fixture
        // + frozen key-set byte-identical to the pre-#408 shape).
        is_device: false,
    };
    let wire_user_op = WireUserOp {
        sender: "0x<sender>".into(),
        nonce: "0x<nonce>".into(),
        init_code: "0x".into(),
        call_data: "0x<executeBatch>".into(),
        account_gas_limits: "0x<account_gas_limits>".into(),
        pre_verification_gas: "0x<pre_verification_gas>".into(),
        gas_fees: "0x<gas_fees>".into(),
        paymaster_and_data: "0x<paymaster_and_data>".into(),
        signature: "0x<k11_assertion>".into(),
    };
    let submit_accept = SubmitAcceptUserOpRequest {
        user_op: wire_user_op.clone(),
        assertion: AcceptAssertion {
            authenticator_data: "<authenticator_data_b64url>".into(),
            client_data_json: "<client_data_json_b64url>".into(),
            signature: "<der_signature_b64url>".into(),
            credential_id: "<credential_id_b64url>".into(),
        },
    };
    let build_scope = BuildScopeUserOpRequest {
        operator_omni: "0x<operator_omni>".into(),
        actor_omni: "0x<actor_omni>".into(),
        services: vec!["memory:<namespace>".into()],
        preserve_service_ids: vec!["0x<service_id_keccak32>".into()],
        read_only: true,
        max_per_call: "0".into(),
        max_per_period: "0".into(),
        max_total: "0".into(),
        period_seconds: 0,
    };
    let build_revoke = BuildRevokeUserOpRequest {
        operator_omni: "0x<operator_omni>".into(),
        device_key_hashes: vec!["0x<device_key_hash>".into()],
    };
    let build_register = BuildRegisterUserOpRequest {
        operator_omni: "0x<operator_omni>".into(),
        owner_pubkey_x: "0x<owner_pubkey_x>".into(),
        owner_pubkey_y: "0x<owner_pubkey_y>".into(),
        rpid_hash: "0x<rpid_hash>".into(),
        roles: 0,
    };
    // #427 spawn/archive ceremonies. The canonical spawn shape names the
    // memory namespace explicitly; `memory_inherited` is false +
    // skip_serializing_if (an INHERIT body adds that one key — annotate such a
    // negative-path curl accordingly). Archive: `resources_kept`/`memory_ns`
    // are the optional keep-choice keys, omitted in the minimal shape.
    let build_spawn = BuildSpawnUserOpRequest {
        operator_omni: "0x<operator_omni>".into(),
        label: "<label>".into(),
        preset_id: "<preset_id>".into(),
        memory_ns: Some("<namespace>".into()),
        memory_inherited: false,
    };
    let build_archive = BuildArchiveUserOpRequest {
        operator_omni: "0x<operator_omni>".into(),
        device_key_hash: "0x<device_key_hash>".into(),
        resources_kept: false,
        memory_ns: None,
    };
    // #406 channels: the canonical publish body carries an inline base64 payload
    // (body_ref None + skip_serializing_if, so it stays out of the fixture); poll
    // carries the cursor + long-poll wait.
    let channel_publish = ChannelPublishBody {
        cap: json!("<cap-token>"),
        kind: ChannelEventKind::Text,
        direction: crate::protocol::ChannelDirection::In,
        body_b64: Some("<base64-plaintext>".into()),
        body_ref: None,
        correlation: None,
    };
    let channel_poll = ChannelPollBody {
        cap: json!("<cap-token>"),
        after: "<feed-cursor>".into(),
        wait_seconds: 25,
    };
    vec![
        Fixture {
            name: "cap_mint_request",
            body: serde_json::to_value(&cap).expect("cap serializes"),
        },
        Fixture {
            name: "memory_put_body",
            body: serde_json::to_value(&memory_put).expect("memory_put serializes"),
        },
        Fixture {
            name: "memory_get_body",
            body: serde_json::to_value(&memory_get).expect("memory_get serializes"),
        },
        Fixture {
            name: "config_put_body",
            body: serde_json::to_value(&config_put).expect("config_put serializes"),
        },
        Fixture {
            name: "config_get_body",
            body: serde_json::to_value(&config_get).expect("config_get serializes"),
        },
        Fixture {
            name: "audit_append_v2",
            body: serde_json::to_value(&audit).expect("audit serializes"),
        },
        Fixture {
            name: "build_accept_userop_request",
            body: serde_json::to_value(&build_accept).expect("build_accept serializes"),
        },
        Fixture {
            name: "wire_user_op",
            body: serde_json::to_value(&wire_user_op).expect("wire_user_op serializes"),
        },
        Fixture {
            name: "submit_accept_userop_request",
            body: serde_json::to_value(&submit_accept).expect("submit_accept serializes"),
        },
        Fixture {
            name: "build_scope_userop_request",
            body: serde_json::to_value(&build_scope).expect("build_scope serializes"),
        },
        Fixture {
            name: "build_revoke_userop_request",
            body: serde_json::to_value(&build_revoke).expect("build_revoke serializes"),
        },
        Fixture {
            name: "build_register_userop_request",
            body: serde_json::to_value(&build_register).expect("build_register serializes"),
        },
        Fixture {
            name: "build_spawn_userop_request",
            body: serde_json::to_value(&build_spawn).expect("build_spawn serializes"),
        },
        Fixture {
            name: "build_archive_userop_request",
            body: serde_json::to_value(&build_archive).expect("build_archive serializes"),
        },
        Fixture {
            name: "channel_publish_body",
            body: serde_json::to_value(&channel_publish).expect("channel_publish serializes"),
        },
        Fixture {
            name: "channel_poll_body",
            body: serde_json::to_value(&channel_poll).expect("channel_poll serializes"),
        },
    ]
}

/// Sorted top-level keys of a fixture body — what the bash gate compares.
pub fn fixture_keys(body: &Value) -> Vec<String> {
    let mut keys: Vec<String> = body
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_of(name: &str) -> Vec<String> {
        let f = canonical_fixtures()
            .into_iter()
            .find(|f| f.name == name)
            .expect("fixture exists");
        fixture_keys(&f.body)
    }

    /// Frozen key-sets. A field rename/add/drop on any wire struct trips the
    /// matching assertion here — the Rust-side half of the drift gate. If you
    /// change a shape intentionally, update this AND regenerate the on-disk
    /// fixtures (`cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures`).
    #[test]
    fn cap_mint_request_keys_frozen() {
        // The canonical (minimal) cap-mint body — PoP fields are OPTIONAL
        // (issue #76) and omitted here; a PoP-signed body adds client_sig/
        // client_nonce/client_ts.
        assert_eq!(
            keys_of("cap_mint_request"),
            vec![
                "actor_omni",
                "device_key_hash",
                "operator_omni",
                "service",
                "ttl_seconds",
            ]
        );
    }

    #[test]
    fn memory_put_body_keys_frozen() {
        assert_eq!(
            keys_of("memory_put_body"),
            vec!["cap", "namespace", "plaintext_b64"]
        );
    }

    #[test]
    fn memory_get_body_keys_frozen() {
        assert_eq!(keys_of("memory_get_body"), vec!["cap", "namespace"]);
    }

    #[test]
    fn config_put_body_keys_frozen() {
        assert_eq!(keys_of("config_put_body"), vec!["cap", "envelope_b64"]);
    }

    #[test]
    fn config_get_body_keys_frozen() {
        assert_eq!(keys_of("config_get_body"), vec!["cap"]);
    }

    #[test]
    fn channel_publish_body_keys_frozen() {
        // #406: the canonical publish body — body_ref + correlation are OPTIONAL
        // (skip_serializing_if) and omitted here; the inline body_b64 is the
        // canonical small-payload shape.
        assert_eq!(
            keys_of("channel_publish_body"),
            vec!["body_b64", "cap", "direction", "kind"]
        );
    }

    #[test]
    fn channel_poll_body_keys_frozen() {
        assert_eq!(
            keys_of("channel_poll_body"),
            vec!["after", "cap", "wait_seconds"]
        );
    }

    #[test]
    fn audit_append_v2_keys_frozen() {
        assert_eq!(
            keys_of("audit_append_v2"),
            vec![
                "actor_omni",
                "intent_commitment",
                "intent_text",
                "op_body",
                "op_kind",
                "operator_omni",
                "result",
                "ts_unix",
                "version",
            ]
        );
    }

    #[test]
    fn build_accept_userop_request_keys_frozen() {
        assert_eq!(
            keys_of("build_accept_userop_request"),
            vec![
                "actor_omni",
                "agent_pop_sig",
                "device_key_hash",
                "link_code_redemption",
                "max_per_call",
                "max_per_period",
                "max_total",
                "operator_omni",
                "period_seconds",
                "read_only",
                "services",
            ]
        );
    }

    #[test]
    fn wire_user_op_keys_frozen() {
        assert_eq!(
            keys_of("wire_user_op"),
            vec![
                "account_gas_limits",
                "call_data",
                "gas_fees",
                "init_code",
                "nonce",
                "paymaster_and_data",
                "pre_verification_gas",
                "sender",
                "signature",
            ]
        );
    }

    #[test]
    fn submit_accept_userop_request_keys_frozen() {
        assert_eq!(
            keys_of("submit_accept_userop_request"),
            vec!["assertion", "user_op"]
        );
    }

    #[test]
    fn build_scope_userop_request_keys_frozen() {
        assert_eq!(
            keys_of("build_scope_userop_request"),
            vec![
                "actor_omni",
                "max_per_call",
                "max_per_period",
                "max_total",
                "operator_omni",
                "period_seconds",
                "preserve_service_ids",
                "read_only",
                "services",
            ]
        );
    }

    #[test]
    fn build_revoke_userop_request_keys_frozen() {
        assert_eq!(
            keys_of("build_revoke_userop_request"),
            vec!["device_key_hashes", "operator_omni"]
        );
    }

    #[test]
    fn build_register_userop_request_keys_frozen() {
        assert_eq!(
            keys_of("build_register_userop_request"),
            vec![
                "operator_omni",
                "owner_pubkey_x",
                "owner_pubkey_y",
                "roles",
                "rpid_hash",
            ]
        );
    }

    #[test]
    fn build_spawn_userop_request_keys_frozen() {
        // #427: memory_inherited is false + skip_serializing_if — the INHERIT
        // variant adds that single key.
        assert_eq!(
            keys_of("build_spawn_userop_request"),
            vec!["label", "memory_ns", "operator_omni", "preset_id"]
        );
    }

    #[test]
    fn build_archive_userop_request_keys_frozen() {
        // #427: the minimal shape — resources_kept/memory_ns ride only on the
        // keep-choice variant (both skip_serializing_if their defaults).
        assert_eq!(
            keys_of("build_archive_userop_request"),
            vec!["device_key_hash", "operator_omni"]
        );
    }
}
