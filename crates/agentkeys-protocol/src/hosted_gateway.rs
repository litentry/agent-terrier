use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    ContactRegistry, GatewayApproveRequest, GatewayBindInviteRequest, GatewayBindRejectRequest,
    GatewayChannelUpdateRequest, GatewayContactRevokeRequest, GatewayContactUpdateRequest,
    GatewayContactWelcomeRequest, GatewayLoginVerifyRequest, GatewayRouterSettingsRequest,
};

pub const BROKER_GATEWAY_ROUTE: &str = "/v1/master/gateway";
pub const GATEWAY_CONSOLE_ROUTE: &str = "/v1/gateway/console";

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedGatewayLoginStart {
    #[serde(default)]
    pub contact_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct HostedGatewayPage {
    #[serde(default)]
    #[ts(type = "number | null")]
    pub before: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// The management surface is closed: no arbitrary URL, method, owner or force import.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum HostedGatewayRequest {
    Status,
    DeviceStatus,
    Contacts,
    Channels,
    BindPending,
    Router,
    Monitor {
        #[ts(type = "number")]
        after: u64,
    },
    History(HostedGatewayPage),
    Activity(HostedGatewayPage),
    LoginStart(HostedGatewayLoginStart),
    LoginStatus {
        login_id: String,
    },
    LoginVerify(GatewayLoginVerifyRequest),
    LoginDisconnect,
    BindInvite(GatewayBindInviteRequest),
    BindApprove(GatewayApproveRequest),
    BindReject(GatewayBindRejectRequest),
    ContactsUpdate(GatewayContactUpdateRequest),
    ContactsRevoke(GatewayContactRevokeRequest),
    ContactsWelcome(GatewayContactWelcomeRequest),
    ChannelsUpdate(Box<GatewayChannelUpdateRequest>),
    RouterSettings(GatewayRouterSettingsRequest),
    RegistryExport,
    RegistryRestore {
        #[ts(type = "unknown")]
        registry: Box<ContactRegistry>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_gateway_rejects_routes_and_owner_injection() {
        for body in [
            r#"{"operation":"admin","payload":{"path":"/anything"}}"#,
            r#"{"operation":"status","operator_omni":"attacker"}"#,
            r#"{"operation":"login_start","payload":{"operator_omni":"attacker"}}"#,
            r#"{"operation":"login_start","payload":{"contact_id":null,"contact_id":"other"}}"#,
            r#"{"operation":"status","operation":"registry_export"}"#,
        ] {
            assert!(
                serde_json::from_str::<HostedGatewayRequest>(body).is_err(),
                "{body}"
            );
        }
    }
}
