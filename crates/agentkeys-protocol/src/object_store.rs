use crate::capability::{CapOp, CapPayload, CapToken, DataClass};
use serde::{Deserialize, Serialize};

pub const MAX_OBJECT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;
pub const MAX_LIST_KEYS: usize = 500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAction {
    Get,
    Put,
    Delete,
    List,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRequest {
    pub cap: CapToken,
    pub action: ObjectAction,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
}

pub fn authorize_key(
    payload: &CapPayload,
    action: ObjectAction,
    key: &str,
) -> Result<(), &'static str> {
    let operator = omni(&payload.operator_omni)?;
    let actor = omni(&payload.actor_omni)?;
    let service = payload.service.to_ascii_lowercase();
    if service.is_empty()
        || service.len() > 128
        || service == "."
        || service == ".."
        || !service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
    {
        return Err("storage_service_invalid");
    }
    validate_key(key, action == ObjectAction::List)?;
    let owner = operator == actor;
    let class = payload.data_class.as_str();
    let actor_prefix = format!("bots/{actor}/{class}/");
    let operator_prefix = format!("bots/{operator}/{class}/");
    let exact = |prefix: &str| key == format!("{prefix}{service}.enc");
    let own_slot =
        || exact(&actor_prefix) || key.starts_with(&format!("{actor_prefix}{service}.objects/"));
    let read = matches!(action, ObjectAction::Get | ObjectAction::List);
    let allowed = match (payload.data_class, payload.op) {
        (DataClass::Credentials, CapOp::Store) | (DataClass::Config, CapOp::Store) => {
            owner && matches!(action, ObjectAction::Get | ObjectAction::Put) && exact(&actor_prefix)
        }
        (DataClass::Credentials, CapOp::Fetch) => {
            (action == ObjectAction::Get && exact(&operator_prefix))
                || (owner && action == ObjectAction::List && key == operator_prefix)
        }
        (DataClass::Config, CapOp::Fetch) => {
            owner && action == ObjectAction::Get && exact(&actor_prefix)
        }
        (DataClass::Memory, CapOp::Store) => {
            matches!(action, ObjectAction::Get | ObjectAction::Put) && own_slot()
        }
        (DataClass::Memory, CapOp::Fetch) => {
            read && ((own_slot() && (action != ObjectAction::List || !exact(&actor_prefix)))
                || (owner
                    && service == "inbox"
                    && key.starts_with(&format!("bots/{operator}/inbox/"))))
        }
        (DataClass::Memory, CapOp::CanonicalFetch) => {
            action == ObjectAction::Get
                && service.starts_with("knowledge:")
                && exact(&operator_prefix)
        }
        (DataClass::Memory, CapOp::Append) => {
            action == ObjectAction::Put
                && service.starts_with("proposal:")
                && key.starts_with(&format!("bots/{operator}/inbox/{actor}/{service}/"))
        }
        (DataClass::Channel, CapOp::ChannelPublish | CapOp::ChannelSubscribe) => {
            let (service_prefix, action_allowed) = match payload.op {
                CapOp::ChannelPublish => ("channel-pub:", action == ObjectAction::Put),
                _ => ("channel-sub:", read),
            };
            let channel = service
                .strip_prefix(service_prefix)
                .ok_or("storage_service_invalid")?;
            let valid_channel = !channel.is_empty()
                && channel.len() <= 48
                && !channel.starts_with('-')
                && !channel.ends_with('-')
                && channel
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
            valid_channel
                && action_allowed
                && key.starts_with(&format!("{operator_prefix}{channel}/"))
        }
        (
            DataClass::Credentials | DataClass::Config | DataClass::Memory | DataClass::Channel,
            CapOp::Teardown,
        ) => {
            owner
                && matches!(action, ObjectAction::Delete | ObjectAction::List)
                && (key.starts_with(&actor_prefix)
                    || (payload.data_class == DataClass::Memory
                        && service == "inbox"
                        && key.starts_with(&format!("bots/{operator}/inbox/"))))
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err("storage_scope_denied")
    }
}

fn omni(value: &str) -> Result<String, &'static str> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("storage_actor_invalid");
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_key(value: &str, prefix: bool) -> Result<(), &'static str> {
    let path = if prefix {
        value.strip_suffix('/').unwrap_or(value)
    } else {
        value
    };
    if value.is_empty()
        || value.len() > MAX_OBJECT_KEY_BYTES
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":._-".contains(&byte)
                })
        })
    {
        return Err("storage_key_invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(class: DataClass, op: CapOp, service: &str) -> CapPayload {
        CapPayload {
            operator_omni: "11".repeat(32),
            actor_omni: "22".repeat(32),
            service: service.into(),
            op,
            data_class: class,
            device_key_hash: "33".repeat(32),
            k3_epoch: 1,
            issued_at: 1,
            expires_at: 2,
            nonce: String::new(),
        }
    }

    #[test]
    fn own_memory_is_bound_to_actor_namespace_and_action() {
        let mut cap = payload(DataClass::Memory, CapOp::Store, "knowledge:notes");
        let key = format!("bots/{}/memory/knowledge:notes.enc", cap.actor_omni);
        assert!(authorize_key(&cap, ObjectAction::Put, &key).is_ok());
        for denied in [
            key.replace(&cap.actor_omni, &cap.operator_omni),
            key.replace("memory", "credentials"),
            key.replace("notes", "other"),
        ] {
            assert_eq!(
                authorize_key(&cap, ObjectAction::Put, &denied),
                Err("storage_scope_denied")
            );
        }
        assert!(authorize_key(&cap, ObjectAction::Delete, &key).is_err());
        cap.op = CapOp::Fetch;
        assert!(authorize_key(&cap, ObjectAction::Get, &key).is_ok());
        assert!(authorize_key(&cap, ObjectAction::Put, &key).is_err());
        for invalid in [
            key.replace(".enc", "/../secret"),
            key.replace(".enc", "%2fsecret"),
            key.replace(".enc", "/./secret"),
        ] {
            assert_eq!(
                authorize_key(&cap, ObjectAction::Get, &invalid),
                Err("storage_key_invalid")
            );
        }
    }

    #[test]
    fn owner_data_requires_the_correct_grant_direction() {
        let mut cap = payload(DataClass::Memory, CapOp::CanonicalFetch, "knowledge:notes");
        let canonical = format!("bots/{}/memory/knowledge:notes.enc", cap.operator_omni);
        assert!(authorize_key(&cap, ObjectAction::Get, &canonical).is_ok());
        assert!(authorize_key(&cap, ObjectAction::Put, &canonical).is_err());
        cap.op = CapOp::Append;
        cap.service = "proposal:notes".into();
        let inbox = format!(
            "bots/{}/inbox/{}/proposal:notes/item.enc",
            cap.operator_omni, cap.actor_omni
        );
        assert!(authorize_key(&cap, ObjectAction::Put, &inbox).is_ok());
        assert!(authorize_key(&cap, ObjectAction::Get, &inbox).is_err());
        assert!(authorize_key(
            &cap,
            ObjectAction::Put,
            &inbox.replace(&cap.actor_omni, &"44".repeat(32))
        )
        .is_err());
        cap.data_class = DataClass::Credentials;
        cap.op = CapOp::Fetch;
        cap.service = "example".into();
        let vault = format!("bots/{}/credentials/example.enc", cap.operator_omni);
        assert!(authorize_key(&cap, ObjectAction::Get, &vault).is_ok());
        cap.op = CapOp::Store;
        assert!(authorize_key(&cap, ObjectAction::Put, &vault).is_err());
        cap.actor_omni = cap.operator_omni.clone();
        assert!(authorize_key(&cap, ObjectAction::Put, &vault).is_ok());
    }

    #[test]
    fn channels_keep_publish_subscribe_and_owner_boundaries() {
        let mut cap = payload(
            DataClass::Channel,
            CapOp::ChannelPublish,
            "channel-pub:room",
        );
        let key = format!("bots/{}/channel/room/event.enc", cap.operator_omni);
        assert!(authorize_key(&cap, ObjectAction::Put, &key).is_ok());
        assert!(authorize_key(&cap, ObjectAction::Get, &key).is_err());
        assert!(authorize_key(&cap, ObjectAction::Delete, &key).is_err());
        cap.op = CapOp::ChannelSubscribe;
        cap.service = "channel-sub:room".into();
        assert!(authorize_key(&cap, ObjectAction::Get, &key).is_ok());
        assert!(authorize_key(&cap, ObjectAction::Put, &key).is_err());
        assert!(authorize_key(&cap, ObjectAction::Get, &key.replace("room", "other")).is_err());
    }
}
