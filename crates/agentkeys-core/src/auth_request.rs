use agentkeys_types::{
    AgentIdentity, AuthRequestType, CanonicalBytes, Scope, ServiceName, WalletAddress,
};
use ciborium::Value;

#[derive(Debug)]
pub enum CborError {
    Serialization(String),
    Deserialization(String),
}

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborError::Serialization(msg) => write!(f, "CBOR serialization error: {}", msg),
            CborError::Deserialization(msg) => write!(f, "CBOR deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for CborError {}

fn scope_to_value(scope: &Scope) -> Value {
    let services: Vec<Value> = scope
        .services
        .iter()
        .map(|s| Value::Text(s.0.clone()))
        .collect();
    let mut map = vec![
        (
            Value::Text("read_only".into()),
            Value::Bool(scope.read_only),
        ),
        (Value::Text("services".into()), Value::Array(services)),
    ];
    map.sort_by(|(a, _), (b, _)| {
        let a_key = cbor_key_bytes(a);
        let b_key = cbor_key_bytes(b);
        a_key.cmp(&b_key)
    });
    Value::Map(map)
}

fn agent_identity_to_value(identity: &AgentIdentity) -> Value {
    let (tag, inner) = match identity {
        AgentIdentity::Alias(s) => ("Alias", Value::Text(s.clone())),
        AgentIdentity::Email(s) => ("Email", Value::Text(s.clone())),
        AgentIdentity::Ens(s) => ("Ens", Value::Text(s.clone())),
        AgentIdentity::WalletAddress(WalletAddress(s)) => ("WalletAddress", Value::Text(s.clone())),
        AgentIdentity::OAuth2 { provider, sub } => (
            "OAuth2",
            // Deterministic CBOR map: keys ASCII-sorted ("provider" < "sub").
            Value::Map(vec![
                (
                    Value::Text("provider".into()),
                    Value::Text(provider.clone()),
                ),
                (Value::Text("sub".into()), Value::Text(sub.clone())),
            ]),
        ),
    };
    Value::Map(vec![
        (Value::Text("type".into()), Value::Text(tag.into())),
        (Value::Text("value".into()), inner),
    ])
}

fn wallet_to_value(wallet: &WalletAddress) -> Value {
    Value::Text(wallet.0.clone())
}

fn service_to_value(service: &ServiceName) -> Value {
    Value::Text(service.0.clone())
}

fn cbor_key_bytes(key: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(key, &mut buf).unwrap_or_default();
    buf
}

fn sort_map(map: &mut [(Value, Value)]) {
    map.sort_by(|(a, _), (b, _)| {
        let a_bytes = cbor_key_bytes(a);
        let b_bytes = cbor_key_bytes(b);
        a_bytes.cmp(&b_bytes)
    });
}

pub fn canonical_bytes(request_type: &AuthRequestType) -> Result<CanonicalBytes, CborError> {
    let value = match request_type {
        AuthRequestType::Pair { requested_scope } => {
            let mut map = vec![
                (Value::Text("type".into()), Value::Text("Pair".into())),
                (
                    Value::Text("requested_scope".into()),
                    scope_to_value(requested_scope),
                ),
            ];
            sort_map(&mut map);
            Value::Map(map)
        }
        AuthRequestType::Recover {
            agent_identity,
            new_daemon_pubkey,
        } => {
            let pubkey_bytes: Vec<Value> = new_daemon_pubkey
                .iter()
                .map(|b| Value::Integer((*b).into()))
                .collect();
            let mut map = vec![
                (Value::Text("type".into()), Value::Text("Recover".into())),
                (
                    Value::Text("agent_identity".into()),
                    agent_identity_to_value(agent_identity),
                ),
                (
                    Value::Text("new_daemon_pubkey".into()),
                    Value::Bytes(new_daemon_pubkey.clone()),
                ),
            ];
            sort_map(&mut map);
            let _ = pubkey_bytes;
            Value::Map(map)
        }
        AuthRequestType::ScopeChange {
            agent_id,
            new_scope,
        } => {
            let mut map = vec![
                (
                    Value::Text("type".into()),
                    Value::Text("ScopeChange".into()),
                ),
                (Value::Text("agent_id".into()), wallet_to_value(agent_id)),
                (Value::Text("new_scope".into()), scope_to_value(new_scope)),
            ];
            sort_map(&mut map);
            Value::Map(map)
        }
        AuthRequestType::HighValueRelease {
            agent_id,
            service,
            estimated_cost_cents,
        } => {
            let mut map = vec![
                (
                    Value::Text("type".into()),
                    Value::Text("HighValueRelease".into()),
                ),
                (Value::Text("agent_id".into()), wallet_to_value(agent_id)),
                (Value::Text("service".into()), service_to_value(service)),
                (
                    Value::Text("estimated_cost_cents".into()),
                    Value::Integer((*estimated_cost_cents).into()),
                ),
            ];
            sort_map(&mut map);
            Value::Map(map)
        }
        AuthRequestType::KeyRotate {
            agent_id,
            new_pubkey,
        } => {
            let mut map = vec![
                (Value::Text("type".into()), Value::Text("KeyRotate".into())),
                (Value::Text("agent_id".into()), wallet_to_value(agent_id)),
                (
                    Value::Text("new_pubkey".into()),
                    Value::Bytes(new_pubkey.clone()),
                ),
            ];
            sort_map(&mut map);
            Value::Map(map)
        }
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf).map_err(|e| CborError::Serialization(e.to_string()))?;
    Ok(CanonicalBytes(buf))
}

pub fn decode_value(bytes: &[u8]) -> Result<Value, CborError> {
    ciborium::from_reader(bytes).map_err(|e| CborError::Deserialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_types::{AgentIdentity, AuthRequestType, Scope, ServiceName};

    fn pair_request() -> AuthRequestType {
        AuthRequestType::Pair {
            requested_scope: Scope {
                services: vec![ServiceName("openrouter".into())],
                read_only: false,
            },
        }
    }

    fn recover_request() -> AuthRequestType {
        AuthRequestType::Recover {
            agent_identity: AgentIdentity::Email("bot@example.com".into()),
            new_daemon_pubkey: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    #[test]
    fn cbor_determinism() {
        let req = pair_request();
        let bytes1 = canonical_bytes(&req).unwrap();
        let bytes2 = canonical_bytes(&req).unwrap();
        assert_eq!(bytes1.0, bytes2.0);
    }

    #[test]
    fn cbor_vectors() {
        let pair_bytes = canonical_bytes(&pair_request()).unwrap();
        assert!(!pair_bytes.0.is_empty());

        let recover_bytes = canonical_bytes(&recover_request()).unwrap();
        assert!(!recover_bytes.0.is_empty());

        // Pair and Recover produce different bytes
        assert_ne!(pair_bytes.0, recover_bytes.0);

        // Both round-trip through CBOR without error
        let pair_val = decode_value(&pair_bytes.0).unwrap();
        assert!(matches!(pair_val, Value::Map(_)));

        let recover_val = decode_value(&recover_bytes.0).unwrap();
        assert!(matches!(recover_val, Value::Map(_)));
    }
}
