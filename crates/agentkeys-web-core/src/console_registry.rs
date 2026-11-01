use crate::{
    broker::BrokerClient,
    console::{broker_error, decode, invalid},
    console_documents::ConsoleDocuments,
    data::{DataClient, DataError, DataSession, VersionedConfig},
};
use agentkeys_protocol::{
    console::*, console_chain::ConsoleFleet, hosted_gateway::HostedGatewayRequest,
    GatewayChannelUpdateRequest,
};
use serde_json::{json, Value};
fn error(status: u16, message: &str) -> DataError {
    DataError::Http {
        status,
        body: json!({"error":message}).to_string(),
    }
}
fn holders(fleet: &ConsoleFleet, id: &str) -> Vec<String> {
    let hashes = [format!("channel-pub:{id}"), format!("channel-sub:{id}")].map(|service| {
        format!(
            "0x{}",
            hex::encode(agentkeys_device_core::keccak256(service.as_bytes()))
        )
    });
    fleet
        .devices
        .iter()
        .filter(|row| {
            !row.device.revoked
                && row
                    .scope
                    .service_ids
                    .iter()
                    .any(|service| hashes.contains(service))
        })
        .map(|row| row.device.actor_omni.clone())
        .collect()
}
pub async fn request(
    broker: &BrokerClient,
    data: &DataClient,
    session: &DataSession<'_>,
    method: &str,
    path: &str,
    body: Value,
) -> Result<Option<Value>, DataError> {
    if path != "/v1/channels" && !path.starts_with("/v1/channels/") {
        return Ok(None);
    }
    let documents = ConsoleDocuments::new(data.clone());
    let mut registry: VersionedConfig<ChannelRegistry> = documents
        .config_read(session, CHANNEL_REGISTRY_SERVICE)
        .await?;
    if method == "GET" && path == "/v1/channels" {
        return Ok(Some(json!({"channels":registry.channels,"storage":"ok"})));
    }
    if method != "POST" {
        return Ok(None);
    }
    let result = if path == "/v1/channels" {
        let request: CreateChannelRequest = decode(body)?;
        let id = request.id.trim().to_ascii_lowercase();
        let name = request.name.trim().to_string();
        if !valid_channel_id(&id) || name.is_empty() {
            return Err(error(400, "channel needs a valid id and nonempty name"));
        }
        if registry.channels.iter().any(|row| row.id == id) {
            return Err(error(409, "channel already exists"));
        }
        let channel = ApiChannel {
            id,
            name,
            note: request
                .note
                .map(|note| note.trim().to_string())
                .filter(|note| !note.is_empty()),
            created_at: session.now_unix_seconds,
            kind: request.kind,
            endpoint_actor_omni: request
                .endpoint_actor_omni
                .map(|actor| actor.trim().to_string())
                .filter(|actor| !actor.is_empty()),
        };
        registry.channels.push(channel.clone());
        json!({"channel":channel,"storage":"ok"})
    } else if path == "/v1/channels/clear-orphaned" || path.ends_with("/delete") {
        let fleet: ConsoleFleet = broker
            .get_json("/v1/console/fleet", Some(session.bearer))
            .await
            .map_err(broker_error)?;
        let removed: Vec<String> = if path.ends_with("/delete") {
            let id = path
                .trim_start_matches("/v1/channels/")
                .trim_end_matches("/delete");
            if !registry.channels.iter().any(|row| row.id == id) {
                return Err(error(404, "channel not found"));
            }
            let owners = holders(&fleet, id);
            if !owners.is_empty() {
                return Err(DataError::Http{status:409,body:json!({"error":"channel is in use — revoke its grants first","holders":owners}).to_string()});
            }
            vec![id.into()]
        } else {
            registry
                .channels
                .iter()
                .filter(|row| holders(&fleet, &row.id).is_empty())
                .map(|row| row.id.clone())
                .collect()
        };
        registry.channels.retain(|row| !removed.contains(&row.id));
        json!({"ok":true,"removed":removed,"kept":registry.channels.iter().map(|row|&row.id).collect::<Vec<_>>(),"storage":"ok"})
    } else {
        let id = path.trim_start_matches("/v1/channels/");
        let request: UpdateChannelRequest = decode(body)?;
        let row = registry
            .channels
            .iter_mut()
            .find(|row| row.id == id)
            .ok_or_else(|| error(404, "channel not found"))?;
        if let Some(name) = request.name {
            let name = name.trim();
            if name.is_empty() {
                return Err(error(400, "channel name must not be empty"));
            }
            row.name = name.into();
        }
        if let Some(note) = request.note {
            row.note = (!note.trim().is_empty()).then(|| note.trim().into());
        }
        if let Some(kind) = request.kind {
            row.kind = Some(kind);
        }
        if let Some(actor) = request.endpoint_actor_omni {
            row.endpoint_actor_omni = (!actor.trim().is_empty()).then(|| actor.trim().into());
        }
        json!({"channel":row,"storage":"ok"})
    };
    documents
        .config_write(session, CHANNEL_REGISTRY_SERVICE, &registry)
        .await?;
    if path != "/v1/channels" && !path.ends_with("/delete") && path != "/v1/channels/clear-orphaned"
    {
        let row: ApiChannel = decode(result["channel"].clone())?;
        if row.kind == Some(agentkeys_protocol::ChannelEndpointKind::Messaging) {
            let _: Value = broker
                .post_json(
                    "/v1/master/gateway",
                    Some(session.bearer),
                    &HostedGatewayRequest::ChannelsUpdate(Box::new(GatewayChannelUpdateRequest {
                        channel_id: row.id,
                        name: Some(row.name),
                        purpose: row.note,
                        ..Default::default()
                    })),
                )
                .await
                .map_err(|error| {
                    invalid(format!("Channel saved; gateway update failed: {error}"))
                })?;
        }
    }
    Ok(Some(result))
}
#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::console_chain::*;
    #[test]
    fn channel_removal_checks_live_chain_grants() {
        let mut fleet = ConsoleFleet {
            operator_omni: "owner".into(),
            account: "account".into(),
            devices: vec![ConsoleFleetEntry {
                device: ConsoleChainDevice {
                    device_key_hash: "hash".into(),
                    operator_omni: "owner".into(),
                    actor_omni: "actor".into(),
                    tier: 3,
                    revoked: false,
                },
                scope: ConsoleChainScope {
                    service_ids: vec![format!(
                        "0x{}",
                        hex::encode(agentkeys_device_core::keccak256(b"channel-sub:kitchen"))
                    )],
                    ..Default::default()
                },
            }],
        };
        assert_eq!(holders(&fleet, "kitchen"), vec!["actor"]);
        assert!(holders(&fleet, "other").is_empty());
        fleet.devices[0].device.revoked = true;
        assert!(holders(&fleet, "kitchen").is_empty());
    }
}
