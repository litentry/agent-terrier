//! Per-op_kind `op_body` schemas (arch.md §15.3a canonical table).
//!
//! These are the **typed** views of `op_body` that builds of the code
//! recognizing the op_kind can decode into. The envelope's actual
//! `op_body` field is a `ciborium::Value` — unknown op_kinds keep it as
//! opaque CBOR so old readers don't break (non-break invariant #4).
//!
//! Hex-byte fields use the `0x<hex>` string form in JSON for human
//! readability. CBOR encoding of these structs (via `ciborium`) preserves
//! the same JSON-shape — keys are text, values are text/integer per the
//! `serde` derives below.

use serde::{Deserialize, Serialize};

// ── 0..9 — creds family ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredStoreBody {
    /// Service name (e.g., `"openrouter"`). Free-form string per arch.md
    /// §17.5 — the worker uses this verbatim as the S3 object key suffix.
    pub service: String,
    /// `keccak256(envelope_ciphertext)` — proves the worker stored the
    /// exact bytes the auditor can later verify.
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredFetchBody {
    pub service: String,
    /// `keccak256(cap_token_canonical_bytes)` — binds the audit row to
    /// the cap-token that authorized the fetch. Auditors looking at "who
    /// read service X at time T" can cross-reference against the broker's
    /// cap-mint log.
    pub cap_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredTeardownBody {
    /// 32-byte hex (`0x<64 hex>`). The actor whose credentials were torn
    /// down — distinct from the actor performing the teardown (which is
    /// envelope-level `actor_omni`).
    pub actor_target: String,
}

// ── 10..19 — memory family ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryPutBody {
    pub key: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryGetBody {
    pub key: String,
    pub cap_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryTeardownBody {
    pub actor_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryInboxAppendBody {
    /// S3 object key written (`bots/<operator>/inbox/<delegate>/<ns>/<hash>.enc`)
    /// — the path itself is the worker-stamped provenance (#339 P2 §8: source
    /// delegate + namespace come from the cap, never a delegate-supplied field).
    pub key: String,
    /// `keccak256(envelope_ciphertext)` — the stored bytes, never plaintext.
    pub payload_hash: String,
}

// ── 20..29 — signs family ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignEip191Body {
    /// `keccak256("\x19Ethereum Signed Message:\n<len>" || message)` —
    /// the digest the signer signed over. Auditor verifies the signature
    /// against this digest + the signer's known address.
    pub message_digest: String,
    /// 20-byte EVM address (`0x<40 hex>`) — the K4-derived wallet that
    /// produced the signature.
    pub wallet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignEip712Body {
    /// Chain ID from `typed_data.domain.chainId`. `0` if absent.
    pub chain_id: u64,
    /// 20-byte EVM address (`0x<40 hex>`). The contract this sign is
    /// scoped to. `0x0000…0000` if not in domain.
    pub verifying_contract: String,
    /// `typed_data.primaryType` — the struct name (e.g. `"Permit"`).
    pub primary_type: String,
    /// `keccak256(encodeType(primary_type))` — useful for explorers to
    /// match against an ERC-7730 metadata file pinned to the same type
    /// hash.
    pub type_hash: String,
    /// `keccak256(encodeData(EIP712Domain, domain))` — the EIP-712
    /// domain separator.
    pub domain_separator: String,
    /// `keccak256("\x19\x01" || domain_separator || hashStruct(primary,
    /// message))` — the final EIP-712 digest signed.
    pub digest: String,
}

// ── 30..39 — payments family ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentEscrowRedeemBody {
    /// Escrow contract address (`0x<40 hex>`).
    pub escrow_addr: String,
    /// Amount in the chain's native units — string-encoded to support
    /// U256 (JSON numbers max out at i53 safe).
    pub amount: String,
    /// Recipient address (`0x<40 hex>`).
    pub recipient: String,
    pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentDirectBody {
    /// Rail label (e.g. `"stripe"`, `"usdc"`, `"sol"`, `"fiat"`).
    pub rail: String,
    /// Provider-side reference (e.g. Stripe charge ID, USDC tx hash).
    pub r#ref: String,
    /// Amount in the smallest unit of the currency (cents for USD,
    /// satoshi for BTC, etc.).
    pub amount_minor: u64,
    /// ISO-4217 (USD, EUR) or token symbol (USDC, BTC).
    pub currency: String,
}

// ── 40..49 — scope family ──────────────────────────────────────────────
//
// Bodies mirror the post-#164/#225 on-chain `setScope(bytes32,bytes32,
// bytes32[],bool,uint128,uint128,uint128,uint32)` — set-replace semantics:
// a grant carries the FULL replacement service set; an empty set is the
// revoke-all. (Aligned before first emit — bytes 40/41 were never emitted
// under the pre-cutover per-service schema, so this is not a break.)

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeGrantBody {
    /// 32-byte hex — the agent whose scope was just granted.
    pub agent_omni: String,
    /// The FULL replacement set of on-chain service ids (`0x<64 hex>` each,
    /// `keccak256(service_name)` — names are hashed on-chain and not
    /// recoverable here). Auditors diff consecutive grants for per-service
    /// changes.
    pub service_ids: Vec<String>,
    pub read_only: bool,
    /// u128 caps, string-encoded (JSON numbers are only i53-safe).
    /// `"0"` = unlimited.
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeRevokeBody {
    /// 32-byte hex — the agent whose ENTIRE grant was revoked (`setScope`
    /// with an empty service set, or `revokeScope`). There is no
    /// per-service revoke in the set-replace model.
    pub agent_omni: String,
}

// ── 50..59 — device family ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAddBody {
    /// `keccak256(K10_pubkey || 0x01)` — the on-chain device identifier
    /// per arch.md §10.1.
    pub device_key_hash: String,
    /// Bitfield of CAP_MINT=1, RECOVERY=2, SCOPE_MGMT=4 (arch.md §10.1).
    pub role_bits: u8,
    /// `keccak256(WebAuthn attestation object)` — empty hash if the
    /// add is the bootstrap (first master) where no prior K11 exists.
    pub attestation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevokeBody {
    pub device_key_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K10RotateBody {
    pub old_device_key_hash: String,
    pub new_device_key_hash: String,
}

/// #377 — the broker spawned a veFaaS hermes-sandbox instance for a delegate
/// device (create-on-pair at §10.2 poll, or ensure-on-resolve at #367 boot).
/// Emitted only when an instance was actually CREATED — an idempotent ensure
/// that found an existing live instance is a no-op and emits nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxSpawnBody {
    /// `keccak256(K10_pubkey || 0x01)` — the delegate the instance is keyed to
    /// (the `agentkeys_device_key_hash` Metadata label on the instance).
    pub device_key_hash: String,
    /// The veFaaS `SandboxId` of the spawned instance.
    pub sandbox_id: String,
    /// The sandbox application (`FunctionId`) the instance runs under.
    pub function_id: String,
}

/// #377 — the broker killed a delegate's sandbox instance. Today's only
/// broker-driven reason is `"unpair"` (a confirmed `revokeAgentDevice`);
/// veFaaS-side timeout expiry is not broker-observed and emits nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxTeardownBody {
    pub device_key_hash: String,
    pub sandbox_id: String,
    pub reason: String,
}

// ── 60..69 — email family ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailSendBody {
    /// `keccak256(to_address.as_bytes())` — hashed for privacy at the
    /// audit-row layer. Original address available via the email-service
    /// worker's S3 `sent/` log under the same `message_id`.
    pub to_hash: String,
    pub subject_hash: String,
    /// SES `MessageId`.
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailReceiveBody {
    pub from_hash: String,
    pub message_id: String,
    /// `keccak256(MIME-encoded message bytes)`.
    pub payload_hash: String,
}

// ── 70..79 — K3 family ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K3EpochAdvanceBody {
    pub old_epoch: u64,
    pub new_epoch: u64,
    /// `keccak256(governance multisig tx canonical bytes)` — the on-chain
    /// proof of authorization to advance the epoch.
    pub gov_tx: String,
}

// ── 80..89 — config family (#201 data class, audited per #229) ─────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigPutBody {
    /// S3 object key the config worker wrote (`bots/<actor>/config/<service>.enc`).
    pub key: String,
    /// `keccak256(envelope_ciphertext)` — the stored bytes, never plaintext.
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigGetBody {
    pub key: String,
    /// `keccak256(cap payload canonical bytes)` — binds the read to the
    /// cap-token that authorized it.
    pub cap_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigTeardownBody {
    pub actor_target: String,
}

// ── 90..99 — gate family (#384 metered key-custody LLM-egress relay) ───
//
// Emitted by `agentkeys-gate` once per proxied LLM turn. The envelope-level
// `actor_omni`/`operator_omni` both carry the OWNING USER's omni — usage
// always accumulates to one user (#384); the per-device / per-api-key
// attribution that rolls up into the user summary lives here in the body.
// Token counters come from the upstream's `usage` field (#332); `cached` and
// `reasoning` tokens are recorded separately because they are priced
// differently from plain completion tokens.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateTurnBody {
    /// Device the turn is attributed to (from the relay key record).
    pub device_id: String,
    /// Relay api-key id the caller authenticated with (never the secret).
    pub api_key_id: String,
    /// Upstream model / Ark endpoint id the turn ran against.
    pub model: String,
    /// Whether the turn was streamed (usage then comes from the final SSE
    /// chunk via `stream_options.include_usage`).
    pub streamed: bool,
    /// `"ok"`, `"denied:budget_exceeded"`, or `"upstream_error"`.
    pub outcome: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// `usage.prompt_tokens_details.cached_tokens` (0 when absent).
    pub cached_tokens: u64,
    /// `usage.completion_tokens_details.reasoning_tokens` (0 when absent).
    pub reasoning_tokens: u64,
}

// ── 100..109 — channel family (#406 channels data class, audited per #229) ─
//
// Emitted by `agentkeys-worker-channel` once per publish/subscribe/teardown.
// Provenance (who produced/consumed) is the envelope-level `actor_omni` from
// the cap-signed identity — NEVER a body field (§4.1 worker-stamped rule). The
// body carries only the channel + event coordinates and content hashes, never
// plaintext (the same posture as the config/cred bodies).

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelPublishBody {
    /// Feed S3 object key the worker wrote (`bots/<owner>/channel/<id>/<event>.enc`).
    pub key: String,
    /// The channel the event was published into.
    pub channel_id: String,
    /// The worker-assigned event id (feed key tail).
    pub event_id: String,
    /// `keccak256(envelope_ciphertext)` — the stored bytes, never plaintext.
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelSubscribeBody {
    pub channel_id: String,
    /// The cursor the subscriber read from (feed key it passed as `after`).
    pub cursor: String,
    /// Number of events released to the subscriber on this poll.
    pub event_count: u64,
    /// `keccak256(cap payload canonical bytes)` — binds the read to the cap.
    pub cap_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelTeardownBody {
    pub channel_id: String,
    /// The owner-actor whose channel feed was torn down.
    pub actor_target: String,
}

/// #407 — one gateway relay turn. The contact is the provenance (worker-stamped,
/// never a body-supplied actor); the family member's message text NEVER lands in
/// the audit row (D13 privacy — only the routing decision + a content hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRelayBody {
    pub transport: String,
    /// The registry contact id (NOT the raw openid — that stays in the registry).
    pub contact_id: String,
    pub tier: String,
    /// The routed agent alias, or empty when the turn was refused at L3.
    pub target_alias: String,
    /// The L3 decision reason code (`ok` / `unknown_contact` / `out_of_reach` / …).
    pub decision: String,
    /// `keccak256(message bytes)` — proves what was relayed without storing the
    /// third-party personal text (D13).
    pub message_hash: String,
}

/// #407 — a contact bind write (pending → bound / declined) AFTER the master's
/// confirm. `tier`/`reach_count` are the CONFIRMED values (the model's proposal
/// is advisory and never audited as authoritative).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactBindBody {
    pub transport: String,
    pub contact_id: String,
    /// `bound` or `declined`.
    pub outcome: String,
    pub tier: String,
    pub reach_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every body struct deserializes from the JSON shape its `serde`
    /// fields imply. Catches accidental field renames or type drift
    /// against the arch.md canonical table.
    #[test]
    fn cred_store_body_deserializes() {
        let json = serde_json::json!({
            "service": "openrouter",
            "payload_hash": "0xabcd1234",
        });
        let body: CredStoreBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.service, "openrouter");
    }

    #[test]
    fn sign_eip712_body_carries_all_digests() {
        let json = serde_json::json!({
            "chain_id": 1,
            "verifying_contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "primary_type": "Permit",
            "type_hash": "0x".to_string() + &"de".repeat(32),
            "domain_separator": "0x".to_string() + &"ad".repeat(32),
            "digest": "0x".to_string() + &"be".repeat(32),
        });
        let body: SignEip712Body = serde_json::from_value(json).unwrap();
        assert_eq!(body.chain_id, 1);
        assert_eq!(body.primary_type, "Permit");
    }

    /// §15.3b step-5 worker test for the config family (#229): canonical
    /// CBOR encode + decode roundtrip, typed_body decodes, label matches.
    #[test]
    fn config_family_cbor_roundtrip_and_typed_decode() {
        use crate::audit::{envelope_for, AuditEnvelope, AuditOpKind, AuditResult, TypedAuditBody};

        let body = ConfigGetBody {
            key: "bots/abc/config/memory-taxonomy.enc".into(),
            cap_hash: format!("0x{}", "ab".repeat(32)),
        };
        let env = envelope_for(
            [0x11; 32],
            [0x11; 32],
            AuditOpKind::ConfigGet,
            body.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let cbor = env.to_canonical_cbor().unwrap();
        let decoded = AuditEnvelope::from_canonical_cbor(&cbor).unwrap();
        assert_eq!(decoded.op_kind, AuditOpKind::ConfigGet as u8);
        assert_eq!(AuditOpKind::ConfigGet.label(), "config.get");
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ConfigGet(b) => assert_eq!(b, body),
            other => panic!("unexpected typed body: {other:?}"),
        }

        let put = ConfigPutBody {
            key: "bots/abc/config/memory-taxonomy.enc".into(),
            payload_hash: format!("0x{}", "cd".repeat(32)),
        };
        let env = envelope_for(
            [0x11; 32],
            [0x11; 32],
            AuditOpKind::ConfigPut,
            put.clone(),
            AuditResult::Failure,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ConfigPut(b) => assert_eq!(b, put),
            other => panic!("unexpected typed body: {other:?}"),
        }

        let td = ConfigTeardownBody {
            actor_target: format!("0x{}", "11".repeat(32)),
        };
        let env = envelope_for(
            [0x11; 32],
            [0x11; 32],
            AuditOpKind::ConfigTeardown,
            td.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ConfigTeardown(b) => assert_eq!(b, td),
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    /// §15.3b step-5 worker test for the channel + gateway family (#406/#407):
    /// canonical CBOR roundtrip + typed decode for the pub/sub feed rows and the
    /// gateway relay/bind rows.
    #[test]
    fn channel_and_gateway_family_cbor_roundtrip_and_typed_decode() {
        use crate::audit::{envelope_for, AuditEnvelope, AuditOpKind, AuditResult, TypedAuditBody};

        let pubb = ChannelPublishBody {
            key: "bots/abc/channel/cam-frontdoor/0000000001-0.enc".into(),
            channel_id: "cam-frontdoor".into(),
            event_id: "0000000001-0000000000000000".into(),
            payload_hash: format!("0x{}", "ab".repeat(32)),
        };
        let env = envelope_for(
            [0x22; 32],
            [0x22; 32],
            AuditOpKind::ChannelPublish,
            pubb.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        assert_eq!(AuditOpKind::ChannelPublish.label(), "channel.publish");
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ChannelPublish(b) => assert_eq!(b, pubb),
            other => panic!("unexpected typed body: {other:?}"),
        }

        let relay = GatewayRelayBody {
            transport: "weixin".into(),
            contact_id: "c-owner".into(),
            tier: "owner".into(),
            target_alias: "chef".into(),
            decision: "ok".into(),
            message_hash: format!("0x{}", "cd".repeat(32)),
        };
        let env = envelope_for(
            [0x22; 32],
            [0x22; 32],
            AuditOpKind::GatewayRelay,
            relay.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        assert_eq!(AuditOpKind::GatewayRelay.label(), "gateway.relay");
        match decoded.typed_body().unwrap() {
            TypedAuditBody::GatewayRelay(b) => assert_eq!(b, relay),
            other => panic!("unexpected typed body: {other:?}"),
        }

        let bind = ContactBindBody {
            transport: "weixin".into(),
            contact_id: "c-kid".into(),
            outcome: "bound".into(),
            tier: "kid".into(),
            reach_count: 1,
        };
        let env = envelope_for(
            [0x22; 32],
            [0x22; 32],
            AuditOpKind::ContactBind,
            bind.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ContactBind(b) => assert_eq!(b, bind),
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    /// §15.3b step-5 worker test for the scope family (#97 control-plane
    /// wiring): canonical CBOR roundtrip + typed decode for the set-replace
    /// grant/revoke shapes.
    #[test]
    fn scope_family_cbor_roundtrip_and_typed_decode() {
        use crate::audit::{envelope_for, AuditEnvelope, AuditOpKind, AuditResult, TypedAuditBody};

        let grant = ScopeGrantBody {
            agent_omni: format!("0x{}", "33".repeat(32)),
            service_ids: vec![
                format!("0x{}", "c1".repeat(32)),
                format!("0x{}", "c2".repeat(32)),
            ],
            read_only: true,
            max_per_call: "1000".into(),
            max_per_period: "0".into(),
            max_total: "340282366920938463463374607431768211455".into(), // u128::MAX
            period_seconds: 86400,
        };
        let env = envelope_for(
            [0x33; 32],
            [0x22; 32],
            AuditOpKind::ScopeGrant,
            grant.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        assert_eq!(AuditOpKind::ScopeGrant.label(), "scope.grant");
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ScopeGrant(b) => assert_eq!(b, grant),
            other => panic!("unexpected typed body: {other:?}"),
        }

        let revoke = ScopeRevokeBody {
            agent_omni: format!("0x{}", "33".repeat(32)),
        };
        let env = envelope_for(
            [0x33; 32],
            [0x22; 32],
            AuditOpKind::ScopeRevoke,
            revoke.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        match decoded.typed_body().unwrap() {
            TypedAuditBody::ScopeRevoke(b) => assert_eq!(b, revoke),
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    /// §15.3b step-5 worker test for the device family (#97 control-plane
    /// wiring): DeviceAdd (agent bind — ROLE_CAP_MINT, zero attestation) +
    /// DeviceRevoke roundtrip.
    #[test]
    fn device_family_cbor_roundtrip_and_typed_decode() {
        use crate::audit::{envelope_for, AuditEnvelope, AuditOpKind, AuditResult, TypedAuditBody};

        let add = DeviceAddBody {
            device_key_hash: format!("0x{}", "11".repeat(32)),
            role_bits: 1, // SidecarRegistry.ROLE_CAP_MINT — what agent binds get
            attestation_hash: format!("0x{}", "00".repeat(32)),
        };
        let env = envelope_for(
            [0x33; 32],
            [0x22; 32],
            AuditOpKind::DeviceAdd,
            add.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        assert_eq!(AuditOpKind::DeviceAdd.label(), "device.add");
        match decoded.typed_body().unwrap() {
            TypedAuditBody::DeviceAdd(b) => assert_eq!(b, add),
            other => panic!("unexpected typed body: {other:?}"),
        }

        let rev = DeviceRevokeBody {
            device_key_hash: format!("0x{}", "11".repeat(32)),
        };
        let env = envelope_for(
            [0x22; 32],
            [0x22; 32],
            AuditOpKind::DeviceRevoke,
            rev.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        match decoded.typed_body().unwrap() {
            TypedAuditBody::DeviceRevoke(b) => assert_eq!(b, rev),
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    /// §15.3b step-5 test for the gate family (#384): canonical CBOR
    /// roundtrip + typed decode of the metered-relay turn row.
    #[test]
    fn gate_family_cbor_roundtrip_and_typed_decode() {
        use crate::audit::{envelope_for, AuditEnvelope, AuditOpKind, AuditResult, TypedAuditBody};

        let body = GateTurnBody {
            device_id: "esp32-lcd4b-01".into(),
            api_key_id: "gk-kid-tablet".into(),
            model: "ep-2026-doubao".into(),
            streamed: true,
            outcome: "ok".into(),
            prompt_tokens: 1200,
            completion_tokens: 340,
            total_tokens: 1540,
            cached_tokens: 800,
            reasoning_tokens: 120,
        };
        let env = envelope_for(
            [0x44; 32],
            [0x44; 32],
            AuditOpKind::GateTurn,
            body.clone(),
            AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let decoded =
            AuditEnvelope::from_canonical_cbor(&env.to_canonical_cbor().unwrap()).unwrap();
        assert_eq!(decoded.op_kind, AuditOpKind::GateTurn as u8);
        assert_eq!(AuditOpKind::GateTurn.label(), "gate.turn");
        match decoded.typed_body().unwrap() {
            TypedAuditBody::GateTurn(b) => assert_eq!(b, body),
            other => panic!("unexpected typed body: {other:?}"),
        }
    }

    #[test]
    fn payment_direct_body_uses_ref_as_field_name() {
        // Sanity check: `ref` is a Rust reserved word, so the field is
        // `r#ref` in code; JSON sees plain `"ref"` per the serde derive.
        let json = serde_json::json!({
            "rail": "usdc",
            "ref": "0xabc",
            "amount_minor": 1_000_000,
            "currency": "USDC",
        });
        let body: PaymentDirectBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.r#ref, "0xabc");
    }
}
