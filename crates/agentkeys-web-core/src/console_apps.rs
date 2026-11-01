use crate::{
    broker::{
        BrokerClient, ChannelWorkerClient, PairingClaimRequest, PairingRequestBody, ResolveBody,
    },
    console::{broker_error, decode, encode, invalid},
    console_documents::ConsoleDocuments,
    data::{DataClient, DataError, DataSession, VersionedConfig},
    device::DeviceIdentity,
    document_helpers::{blob_hash, content_hash_for},
};
use agentkeys_protocol::{
    console::*, console_apps::*, console_chain::*, hosted_gateway::HostedGatewayRequest, *,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};
mod channels;
mod lifecycle;
mod resources;

const RESOURCE_UPLOAD_MAX_BYTES: usize = 5 * 1024 * 1024;

pub struct ConsoleApps {
    broker: BrokerClient,
    data: DataClient,
    config: ConsoleConfig,
    documents: ConsoleDocuments,
    pending: RefCell<HashMap<String, PendingApp>>,
}
#[derive(Clone)]
struct PendingApp {
    operator: String,
    route: String,
    build: Value,
    row: Option<AppInstanceRow>,
    previous: Option<AppInstanceRow>,
    label: String,
    enrollments: Vec<(EndpointEnrollment, String)>,
    resources_kept: bool,
    seals: Vec<(AppInstanceRow, ContextSeal)>,
    receipt: Option<Value>,
}
fn norm(value: &str) -> String {
    value.trim_start_matches("0x").to_ascii_lowercase()
}
fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str, DataError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing {field}")))
}
fn http_error(status: u16, value: Value) -> DataError {
    DataError::Http {
        status,
        body: value.to_string(),
    }
}
fn today(now: u64) -> String {
    chrono::DateTime::from_timestamp(now as i64, 0)
        .map(|time| time.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}
fn operation_key(value: &Value) -> Result<String, DataError> {
    let mut operation = value
        .get("user_op")
        .cloned()
        .ok_or_else(|| invalid("missing user_op"))?;
    operation
        .as_object_mut()
        .ok_or_else(|| invalid("invalid user_op"))?
        .remove("signature");
    serde_json::to_string(&operation).map_err(invalid)
}
impl ConsoleApps {
    pub fn new(broker: BrokerClient, data: DataClient, config: ConsoleConfig) -> Self {
        Self {
            broker,
            documents: ConsoleDocuments::new(data.clone()),
            data,
            config,
            pending: RefCell::new(HashMap::new()),
        }
    }
    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        session: &DataSession<'_>,
        path: &str,
        body: &B,
    ) -> Result<T, DataError> {
        self.broker
            .post_json(path, Some(session.bearer), body)
            .await
            .map_err(broker_error)
    }
    async fn fleet(&self, session: &DataSession<'_>) -> Result<ConsoleFleet, DataError> {
        self.broker
            .get_json("/v1/console/fleet", Some(session.bearer))
            .await
            .map_err(broker_error)
    }
    async fn apps(
        &self,
        session: &DataSession<'_>,
    ) -> Result<VersionedConfig<AppRegistryDoc>, DataError> {
        self.documents
            .config_read(session, APP_REGISTRY_SERVICE)
            .await
    }
    async fn app(
        &self,
        session: &DataSession<'_>,
        label: &str,
    ) -> Result<AppInstanceRow, DataError> {
        self.apps(session)
            .await?
            .find(label)
            .cloned()
            .ok_or_else(|| http_error(404, json!({"error":"app not found"})))
    }
    async fn gateway(
        &self,
        session: &DataSession<'_>,
        request: HostedGatewayRequest,
    ) -> Result<Value, DataError> {
        self.post(session, hosted_gateway::BROKER_GATEWAY_ROUTE, &request)
            .await
    }
    async fn console_actor(
        &self,
        session: &DataSession<'_>,
        device: Option<&DeviceIdentity>,
    ) -> Result<Option<String>, DataError> {
        let Some(device) = device else {
            return Ok(None);
        };
        let hash = device.device_key_hash().map_err(invalid)?;
        Ok(self
            .fleet(session)
            .await?
            .devices
            .into_iter()
            .find(|entry| {
                norm(&entry.device.device_key_hash) == norm(&hash)
                    && !entry.device.revoked
                    && entry.device.tier == 3
            })
            .map(|entry| entry.device.actor_omni))
    }
    pub async fn request(
        &self,
        session: &DataSession<'_>,
        console_device: Option<&DeviceIdentity>,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<Value>, DataError> {
        if let Some(result) = self
            .resources_request(session, method, path, body.clone())
            .await?
        {
            return Ok(Some(result));
        }
        if let Some(result) = self
            .channels_request(session, console_device, method, path, body.clone())
            .await?
        {
            return Ok(Some(result));
        }
        let result = match (method, path) {
            ("GET", "/v1/master/apps") => {
                json!({"apps":self.apps(session).await?.document.apps,"storage":"ok","console_device":self.console_actor(session,console_device).await?})
            }
            ("POST", "/v1/master/apps/install/build") => {
                self.install_build(session, console_device, decode(body)?)
                    .await?
            }
            (
                "POST",
                "/v1/master/apps/install/submit"
                | "/v1/agent/spawn/submit"
                | "/v1/agent/archive/submit"
                | "/v1/master/apps/anchors/seal/submit",
            ) => self.submit(session, path, body).await?,
            ("POST", "/v1/agent/spawn/build") => {
                self.spawn_build(session, console_device, body).await?
            }
            ("POST", "/v1/agent/archive/build") => {
                self.archive_build(session, body, None, console_device)
                    .await?
            }
            ("POST", "/v1/master/apps/anchors/seal/build") => {
                self.seal_build(session, decode(body)?).await?
            }
            ("POST", "/v1/master/apps/rehydrate") => self.rehydrate(session, decode(body)?).await?,
            _ if path.starts_with("/v1/master/apps/") => {
                let tail = path.trim_start_matches("/v1/master/apps/");
                let (label, operation) = tail.split_once('/').unwrap_or((tail, ""));
                if label.is_empty() || label.contains(['?', '%', '\\']) {
                    return Err(invalid("invalid app label"));
                }
                match (method, operation) {
                    ("GET", "") => self.dashboard(session, console_device, label).await?,
                    ("GET", "context") => self.context(session, label).await?,
                    ("POST", "command") => {
                        self.command(session, console_device, label, decode(body)?)
                            .await?
                    }
                    ("POST", "uninstall/build") => {
                        let request: AppUninstallBuildRequest = decode(body)?;
                        let row = self.app(session, label).await?;
                        self.archive_build(session,json!({"device_key_hash":row.device_key_hash,"memory_ns":row.memory_ns,"resources_kept":request.resources_kept}),Some(row),console_device).await?
                    }
                    ("POST", "rebind/build") => {
                        self.rebind_build(session, console_device, label, decode(body)?)
                            .await?
                    }
                    ("POST", "uninstall/submit" | "rebind/submit") => {
                        self.submit(session, path, body).await?
                    }
                    _ => return Ok(None),
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(result))
    }
}

pub use channels::{annotations_for, fold_display_feed, inheritable_namespaces, DisplayFeedView};

#[cfg(test)]
mod tests;
