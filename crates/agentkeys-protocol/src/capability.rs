//! Signed capability schema. Issuers and independent verifiers share these wire types.
use crate::DelegationPath;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapOp {
    Store,
    Fetch,
    CanonicalFetch,
    Append,
    Teardown,
    Classify,
    ChannelPublish,
    ChannelSubscribe,
    SpeechUse,
}

impl CapOp {
    pub fn as_u8(self) -> u8 {
        match self {
            CapOp::Store => 0,
            CapOp::Fetch => 1,
            CapOp::Teardown => 2,
            CapOp::Classify => 3,
            CapOp::CanonicalFetch => 4,
            CapOp::Append => 5,
            CapOp::ChannelPublish => 6,
            CapOp::ChannelSubscribe => 7,
            CapOp::SpeechUse => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CapOp::Store => "store",
            CapOp::Fetch => "fetch",
            CapOp::CanonicalFetch => "canonical_fetch",
            CapOp::Append => "append",
            CapOp::Teardown => "teardown",
            CapOp::Classify => "classify",
            CapOp::ChannelPublish => "channel_publish",
            CapOp::ChannelSubscribe => "channel_subscribe",
            CapOp::SpeechUse => "speech_use",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Credentials,
    Memory,
    Config,
    Channel,
    Speech,
}

impl DataClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DataClass::Credentials => "credentials",
            DataClass::Memory => "memory",
            DataClass::Config => "config",
            DataClass::Channel => "channel",
            DataClass::Speech => "speech",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapPayload {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub op: CapOp,
    pub data_class: DataClass,
    pub device_key_hash: String,
    pub k3_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapToken {
    pub payload: CapPayload,
    pub broker_sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_path: Option<DelegationPath>,
}

pub(crate) fn deserialize_optional_ttl<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

pub const DEFAULT_CAP_TTL_SECONDS: u64 = 300;

pub fn default_ttl_seconds() -> u64 {
    DEFAULT_CAP_TTL_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SIGNED_PAYLOAD: &str = r#"{"operator_omni":"synthetic-owner","actor_omni":"synthetic-actor","service":"knowledge:example","op":"fetch","data_class":"memory","device_key_hash":"synthetic-device","k3_epoch":2,"issued_at":100,"expires_at":400,"nonce":"synthetic-nonce"}"#;

    #[test]
    fn signed_payload_bytes_and_required_authority_fields_stay_stable() {
        let payload: CapPayload = serde_json::from_str(SIGNED_PAYLOAD).unwrap();
        assert_eq!(serde_json::to_string(&payload).unwrap(), SIGNED_PAYLOAD);
        for field in [
            "operator_omni",
            "actor_omni",
            "service",
            "op",
            "data_class",
            "device_key_hash",
            "k3_epoch",
            "issued_at",
            "expires_at",
            "nonce",
        ] {
            let mut malformed: serde_json::Value = serde_json::from_str(SIGNED_PAYLOAD).unwrap();
            malformed.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<CapPayload>(malformed).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn optional_proof_fields_accept_legacy_null_but_use_the_issuer_wire_shape() {
        let payload: CapPayload = serde_json::from_str(SIGNED_PAYLOAD).unwrap();
        let legacy = json!({"payload":payload,"broker_sig":"synthetic-signature","client_sig":null,"client_nonce":null,"client_ts":null,"delegation_path":null});
        let parsed: CapToken = serde_json::from_value(legacy).unwrap();
        let serialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 2);
        assert_eq!(
            serde_json::to_string(&parsed.payload).unwrap(),
            SIGNED_PAYLOAD
        );
        let with_proof = CapToken {
            client_sig: Some("synthetic-proof".into()),
            client_nonce: Some("synthetic-client-nonce".into()),
            client_ts: Some(100),
            ..parsed
        };
        let roundtrip: CapToken =
            serde_json::from_slice(&serde_json::to_vec(&with_proof).unwrap()).unwrap();
        assert_eq!(roundtrip.client_sig, with_proof.client_sig);
        assert_eq!(roundtrip.client_nonce, with_proof.client_nonce);
        assert_eq!(roundtrip.client_ts, with_proof.client_ts);
    }

    #[test]
    fn broker_request_preserves_omission_default_and_rejects_explicit_invalid_ttl() {
        let body = json!({"operator_omni":"synthetic-owner","actor_omni":"synthetic-actor","service":"knowledge:example","device_key_hash":"synthetic-device"});
        let request: crate::BrokerCapRequest = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(request.ttl_seconds.unwrap_or_else(default_ttl_seconds), 300);
        assert_eq!(serde_json::to_value(request).unwrap(), body);
        for invalid in [json!(null), json!(-1), json!("300")] {
            let mut malformed = body.clone();
            malformed["ttl_seconds"] = invalid;
            assert!(serde_json::from_value::<crate::BrokerCapRequest>(malformed).is_err());
        }
        let mut explicit = body;
        explicit["ttl_seconds"] = json!(900);
        assert_eq!(
            serde_json::from_value::<crate::BrokerCapRequest>(explicit)
                .unwrap()
                .ttl_seconds,
            Some(900)
        );
    }
}
