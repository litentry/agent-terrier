use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProvisionKeyRequest {
    pub key_id: String,
    pub user_omni: String,
    #[serde(default)]
    pub delegate_omni: Option<String>,
    pub device_id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u64>,
}

#[derive(Deserialize, Serialize)]
pub struct ProvisionedKey {
    pub key_id: String,
    pub secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DisableKeyResponse {
    pub key_id: String,
    pub disabled: bool,
}
