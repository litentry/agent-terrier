use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRequest {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct EmailChallenge {
    pub request_id: String,
    #[ts(type = "number")]
    pub expires_in_seconds: u64,
    pub poll_url: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EmailStatus {
    Pending,
    Verified {
        session_jwt: String,
        omni_account: String,
        expires_at: u64,
    },
    Failed {
        reason: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStart {
    pub address: String,
    pub chain_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletChallenge {
    pub request_id: String,
    pub siwe_message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletVerify {
    pub request_id: String,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct MasterSession {
    pub session_jwt: String,
    pub omni_account: String,
    pub wallet_address: String,
    #[ts(type = "number")]
    pub expires_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct MasterSessionInfo {
    pub omni_account: String,
    pub wallet_address: String,
    #[ts(type = "number")]
    pub expires_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginConfig {
    pub chain_id: String,
    pub signer_url: String,
    pub email_allowlist_enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveAddressRequest {
    pub omni_account: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub omni_account: String,
    pub message_hex: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedAddress {
    pub address: String,
    pub key_version: u8,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub address: String,
    pub signature: String,
    pub key_version: u8,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletLink {
    pub identity_type: String,
    pub identity_value: String,
}
