use serde::{Deserialize, Serialize};

pub mod provision;

pub use provision::{ProvisionErrorCode, ProvisionEvent, TripwireKind};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WalletAddress(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub token: String,
    pub wallet: WalletAddress,
    pub scope: Option<Scope>,
    pub created_at: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub services: Vec<ServiceName>,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ServiceName(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthToken {
    GoogleOAuth(String),
    Passkey(Vec<u8>),
    Mock(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryMethod {
    MasterApproval,
    Passkey,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairCode(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthRequestId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentIdentity {
    Alias(String),
    Email(String),
    Ens(String),
    WalletAddress(WalletAddress),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthRequestType {
    Pair { requested_scope: Scope },
    Recover { agent_identity: AgentIdentity, new_daemon_pubkey: Vec<u8> },
    ScopeChange { agent_id: WalletAddress, new_scope: Scope },
    HighValueRelease { agent_id: WalletAddress, service: ServiceName, estimated_cost_cents: u64 },
    KeyRotate { agent_id: WalletAddress, new_pubkey: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey(pub Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationToken(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairPayload(pub Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPairPayload(pub Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalBytes(pub Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedAuthRequest {
    pub id: AuthRequestId,
    pub otp: String,
    pub pair_code: PairCode,
    pub ttl_seconds: u64,
    pub nonce_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub id: AuthRequestId,
    pub request_type: AuthRequestType,
    pub child_pubkey: PublicKey,
    pub otp: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuthDecision {
    pub request_id: AuthRequestId,
    pub approved: bool,
    pub signature: Vec<u8>,
    pub session: Option<Session>,
    pub wallet: Option<WalletAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditFilter {
    pub owner: Option<WalletAddress>,
    pub agent: Option<WalletAddress>,
    pub service: Option<ServiceName>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub owner: WalletAddress,
    pub agent: WalletAddress,
    pub service: ServiceName,
    pub action: String,
    pub result: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentLayer {
    SystemGas,
    ServicePayment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Amount {
    pub value: u64,
    pub decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: String,
    pub amount: Amount,
    pub layer: PaymentLayer,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpendFilter {
    pub wallet: Option<WalletAddress>,
    pub layer: Option<PaymentLayer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendEvent {
    pub wallet: WalletAddress,
    pub amount: Amount,
    pub layer: PaymentLayer,
    pub reason: String,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_serialize_roundtrip() {
        let session = Session {
            token: "test-token".into(),
            wallet: WalletAddress("0x1234".into()),
            scope: Some(Scope {
                services: vec![ServiceName("openrouter".into())],
                read_only: true,
            }),
            created_at: 1000,
            ttl_seconds: 3600,
        };
        let json = serde_json::to_string(&session).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(session, back);
    }

    #[test]
    fn recovery_method_serialize_roundtrip() {
        for method in [RecoveryMethod::MasterApproval, RecoveryMethod::Passkey, RecoveryMethod::Email] {
            let json = serde_json::to_string(&method).unwrap();
            let back: RecoveryMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, back);
        }
    }

    #[test]
    fn agent_identity_variants() {
        let alias = AgentIdentity::Alias("my-bot".into());
        let email = AgentIdentity::Email("bot@example.com".into());
        let ens = AgentIdentity::Ens("mybot.eth".into());
        let wallet = AgentIdentity::WalletAddress(WalletAddress("0xabc".into()));

        for variant in [&alias, &email, &ens, &wallet] {
            let json = serde_json::to_string(variant).unwrap();
            let back: AgentIdentity = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, &back);
        }
    }
}
