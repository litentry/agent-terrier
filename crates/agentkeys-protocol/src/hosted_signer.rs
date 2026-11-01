use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const HOSTED_SIGNER_TTL_SECONDS: u64 = 600;
pub const HOSTED_SIGNER_CAP_MINT_ROLE: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct BrowserAssertion {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub credential_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
#[serde(deny_unknown_fields)]
pub struct HostedSignerStartRequest {
    pub credential_id: String,
    pub public_key_x: String,
    pub public_key_y: String,
    pub origin: String,
    pub rp_id: String,
    pub device_key_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
#[serde(deny_unknown_fields)]
pub struct HostedSignerIntent {
    pub operator_omni: String,
    pub account: String,
    #[ts(type = "number")]
    pub chain_id: u64,
    pub credential_id: String,
    pub public_key_x: String,
    pub public_key_y: String,
    pub origin: String,
    pub rp_id: String,
    pub device_key_hash: String,
    pub operator_nonce: String,
    #[ts(type = "number")]
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedSignerChallenge {
    pub intent: HostedSignerIntent,
    pub challenge: String,
    pub recovery_challenge: String,
    pub attesting_device_key_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedRecoveryAssertion {
    pub attesting_device_key_hash: String,
    pub assertion: BrowserAssertion,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
#[serde(deny_unknown_fields)]
pub struct HostedSignerBuildRequest {
    pub intent: HostedSignerIntent,
    pub proof: BrowserAssertion,
    pub device_proof: String,
    pub recovery_assertion: HostedRecoveryAssertion,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedSignerStatusRequest {
    pub credential_id: String,
    pub device_key_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedSignerStatus {
    pub account: String,
    pub credential_id_hash: String,
    pub active: bool,
    pub device_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
#[serde(deny_unknown_fields)]
pub struct HostedSignerApproval {
    pub enrollment: HostedSignerChallenge,
    pub proof: BrowserAssertion,
    pub device_proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedPasskeyStart {
    pub omni_account: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedPasskeyChallenge {
    pub challenge: String,
    #[ts(type = "number")]
    pub expires_in_seconds: u64,
    pub account: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedPasskeyVerify {
    pub challenge: String,
    pub assertion: BrowserAssertion,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedPasskeySession {
    pub session_jwt: String,
    pub omni_account: String,
    pub expires_at: u64,
    pub account: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedSignerRequest {
    pub id: String,
    pub approval: HostedSignerApproval,
}
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedSignerPending {
    pub requests: Vec<HostedSignerRequest>,
}
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedSignerRequestId {
    pub id: String,
}
