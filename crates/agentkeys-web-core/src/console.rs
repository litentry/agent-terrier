use crate::{
    broker::BrokerClient,
    data::{DataClient, DataEndpoints, DataError, DataSession},
    device::DeviceIdentity,
};
use agentkeys_protocol::{console::*, console_chain::*, *};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

pub struct ConsoleService {
    pub broker: BrokerClient,
    pub data: DataClient,
    pub config: ConsoleConfig,
    apps: crate::console_apps::ConsoleApps,
    pending: RefCell<HashMap<String, PendingMutation>>,
}

#[derive(Clone)]
struct PendingMutation {
    manifest: BindingManifestEntry,
    request_id: Option<String>,
    operator: String,
    route: String,
    receipt: Option<SubmitAcceptUserOpResponse>,
    submitted: bool,
}

pub fn broker_error(error: crate::broker::BrokerError) -> DataError {
    match error {
        crate::broker::BrokerError::Rejected { status, body, .. } => {
            DataError::Http { status, body }
        }
        error => DataError::Transport(error.to_string()),
    }
}
pub fn invalid(error: impl std::fmt::Display) -> DataError {
    DataError::Invalid(error.to_string())
}
pub fn encode(value: impl Serialize) -> Result<Value, DataError> {
    serde_json::to_value(value).map_err(invalid)
}
pub fn decode<T: DeserializeOwned>(value: Value) -> Result<T, DataError> {
    serde_json::from_value(value).map_err(invalid)
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, DataError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing {name}")))
}
fn norm(value: &str) -> String {
    manifest_norm(value)
}
fn operation_key(operation: &impl Serialize) -> Result<String, DataError> {
    let mut operation = encode(operation)?;
    operation
        .as_object_mut()
        .ok_or_else(|| invalid("invalid user operation"))?
        .remove("signature");
    serde_json::to_string(&operation).map_err(invalid)
}
fn service_hash(value: &str) -> String {
    format!(
        "0x{}",
        hex::encode(agentkeys_device_core::keccak256(
            value.to_ascii_lowercase().as_bytes()
        ))
    )
}

fn merge_confirmed_manifest(
    manifest: &mut BindingManifest,
    requested: &BindingManifestEntry,
    chain: &ConsoleFleetEntry,
) {
    let mut row = manifest
        .entry_for(&requested.actor_omni, "")
        .cloned()
        .unwrap_or_else(|| requested.clone());
    let mut names = row.granted_service_names.clone();
    names.extend(requested.granted_service_names.iter().cloned());
    names.retain(|name| chain.scope.service_ids.contains(&service_hash(name)));
    names.sort();
    names.dedup();
    row.device_key_hash = chain.device.device_key_hash.clone();
    row.granted_service_names = names;
    row.updated_at = requested.updated_at;
    if row.label.is_empty() {
        row.label = requested.label.clone();
    }
    if row.kind.is_empty() {
        row.kind = requested.kind.clone();
    }
    manifest.upsert(row);
}

impl ConsoleService {
    pub fn new(broker_url: String, config: ConsoleConfig) -> Self {
        let data = DataClient::new(DataEndpoints {
            broker_url: broker_url.clone(),
            signer_url: config.signer_url.clone(),
            config_url: config.config_url.clone(),
            memory_url: config.memory_url.clone(),
            credential_url: config.credential_url.clone(),
            audit_url: config.audit_url.clone(),
            classify_url: Some(config.classify_url.clone()),
        });
        let broker = BrokerClient::new(broker_url);
        let apps =
            crate::console_apps::ConsoleApps::new(broker.clone(), data.clone(), config.clone());
        Self {
            broker,
            data,
            config,
            apps,
            pending: RefCell::new(HashMap::new()),
        }
    }

    pub async fn configuration(broker: &BrokerClient) -> Result<ConsoleConfig, DataError> {
        broker
            .get_json("/v1/console/config", None)
            .await
            .map_err(broker_error)
    }
    pub async fn fleet(&self, session: &DataSession<'_>) -> Result<ConsoleFleet, DataError> {
        self.broker
            .get_json("/v1/console/fleet", Some(session.bearer))
            .await
            .map_err(broker_error)
    }
    pub async fn read_config<T: DeserializeOwned + Default>(
        &self,
        session: &DataSession<'_>,
        service: &str,
    ) -> Result<(T, String), DataError> {
        match self.data.config_get(session, service).await? {
            Some(document) => Ok((
                serde_json::from_slice(&document.plaintext).map_err(invalid)?,
                document.revision,
            )),
            None => Ok((T::default(), String::new())),
        }
    }
    pub async fn actors(&self, session: &DataSession<'_>) -> Result<Vec<ApiActor>, DataError> {
        let fleet = self.fleet(session).await?;
        let (manifest, _) = self
            .read_config::<BindingManifest>(session, BINDING_MANIFEST_SERVICE)
            .await?;
        let (taxonomy, _) = self
            .read_config::<MemoryTaxonomy>(session, TAXONOMY_SERVICE)
            .await?;
        let (channels, _) = self
            .read_config::<ChannelRegistry>(session, CHANNEL_REGISTRY_SERVICE)
            .await?;
        Ok(fleet_actors(&fleet, &manifest, &taxonomy, &channels))
    }
    async fn persist_mutation(
        &self,
        session: &DataSession<'_>,
        mutation: &PendingMutation,
    ) -> Result<(), DataError> {
        let fleet = self.fleet(session).await?;
        let device = fleet
            .devices
            .iter()
            .find(|entry| {
                norm(&entry.device.actor_omni) == norm(&mutation.manifest.actor_omni)
                    && norm(&entry.device.device_key_hash)
                        == norm(&mutation.manifest.device_key_hash)
                    && !entry.device.revoked
            })
            .ok_or_else(|| invalid("confirmed operation is not reflected in the chain fleet"))?;
        for service in &mutation.manifest.granted_service_names {
            if !device.scope.service_ids.contains(&service_hash(service)) {
                return Err(invalid("confirmed scope differs from requested services"));
            }
        }
        let (mut manifest, revision) = self
            .read_config::<BindingManifest>(session, BINDING_MANIFEST_SERVICE)
            .await?;
        merge_confirmed_manifest(&mut manifest, &mutation.manifest, device);
        self.data
            .config_put(
                session,
                BINDING_MANIFEST_SERVICE,
                &serde_json::to_vec(&manifest).map_err(invalid)?,
                &revision,
            )
            .await?;
        if let Some(request_id) = &mutation.request_id {
            self.broker
                .ack_binding(session.bearer, request_id)
                .await
                .map_err(broker_error)?;
        }
        Ok(())
    }
    pub async fn request(
        &self,
        session: &DataSession<'_>,
        console_device: Option<&DeviceIdentity>,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Value, DataError> {
        if method == "POST" && path == "/v1/master/apps/channel-defaults/refresh" {
            let request: console_apps::ChannelDefaultsRefreshRequest = decode(body)?;
            self.apps
                .refresh_channel_defaults(session, &request.channel_id)
                .await?;
            return Ok(json!({"ok": true}));
        }
        if method == "GET" && path == "/v1/chain/info" {
            return encode(&self.config.chain);
        }
        if method == "GET" && path == "/v1/chain/list" {
            return Ok(
                json!({"active":self.config.chain.name,"chains":[{"name":self.config.chain.name,"display":self.config.chain.display,"chainId":self.config.chain.chain_id,"active":true}]}),
            );
        }
        if method == "GET" && path == "/v1/stack/list" {
            return Ok(
                json!({"active":self.config.chain.name,"stacks":[{"name":self.config.chain.name,"chain":self.config.chain.name,"broker_url":self.config.chain.daemon_broker,"active":true,"healthy":true}]}),
            );
        }
        let audit = crate::console_audit::ConsoleAudit::new(
            self.broker.clone(),
            self.data.clone(),
            self.config.clone(),
        );
        if let Some(value) = audit.request(session, method, path).await? {
            return Ok(value);
        }
        let documents = crate::console_documents::ConsoleDocuments::new(self.data.clone());
        if let Some(mut value) = documents
            .request(session, method, path, body.clone())
            .await?
        {
            if method == "POST"
                && matches!(path, "/v1/master/persona" | "/v1/master/persona/rollback")
            {
                let actor = text(&value, "delegate_omni")?;
                let persona = text(&value, "body")?;
                let version = decode(
                    value
                        .get("version")
                        .cloned()
                        .ok_or_else(|| invalid("persona version missing"))?,
                )?;
                return encode(
                    crate::console_runtime::apply_persona(
                        &self.broker,
                        session,
                        actor,
                        persona,
                        version,
                    )
                    .await,
                );
            }
            if method == "GET" && path.starts_with("/v1/master/persona?") {
                let actor = text(&value, "delegate_omni")?;
                value["sandbox_configured"] =
                    json!(self.fleet(session).await?.devices.iter().any(|entry| !entry
                        .device
                        .revoked
                        && entry.device.tier == 2
                        && norm(&entry.device.actor_omni) == norm(actor)));
            }
            return Ok(value);
        }
        if let Some(value) = crate::console_inbox::ConsoleInbox::new(self.data.clone())
            .request(session, method, path, body.clone())
            .await?
        {
            return Ok(value);
        }
        if let Some(value) = crate::console_registry::request(
            &self.broker,
            &self.data,
            session,
            method,
            path,
            body.clone(),
        )
        .await?
        {
            return Ok(value);
        }
        let runtime_body = if method == "GET" && path.starts_with("/v1/master/agent/context?") {
            let url = reqwest::Url::parse(&self.config.chain.daemon_broker)
                .map_err(invalid)?
                .join(path)
                .map_err(invalid)?;
            json!({"actor_omni":url.query_pairs().find(|(key,_)|key=="actor").map(|(_,value)|value.into_owned())})
        } else {
            body.clone()
        };
        if let Some(value) = crate::console_runtime::request(
            &self.broker,
            &self.data,
            session,
            method,
            path,
            runtime_body,
        )
        .await?
        {
            return Ok(value);
        }
        if let Some(value) = self
            .apps
            .request(session, console_device, method, path, body.clone())
            .await?
        {
            return Ok(value);
        }
        match (method, path) {
            ("GET", "/v1/actors") => Ok(json!({"actors":self.actors(session).await?})),
            ("GET", "/v1/master/register/state") => {
                let fleet = self.fleet(session).await?;
                let bound = norm(&fleet.account) != "0".repeat(40);
                Ok(
                    json!({"operator_omni":fleet.operator_omni,"bound":bound,"master_account":if bound {Some(fleet.account)} else {None},"probe":"chain"}),
                )
            }
            ("GET", "/v1/agent/pairing/pending") => {
                let response: Value = self
                    .broker
                    .get_json("/v1/agent/pending-bindings", Some(session.bearer))
                    .await
                    .map_err(broker_error)?;
                let pending = response
                    .get("pending")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("pending bindings missing"))?;
                Ok(
                    json!({"requests":pending.iter().map(pending_binding_to_request).collect::<Vec<_>>()}),
                )
            }
            ("POST", "/v1/agent/pairing/claim") => self
                .broker
                .post_json(path, Some(session.bearer), &body)
                .await
                .map_err(broker_error),
            ("POST", "/v1/agent/pairing/decline") => self
                .broker
                .post_json("/v1/agent/decline-binding", Some(session.bearer), &body)
                .await
                .map_err(broker_error),
            ("POST", "/v1/agent/pairing/ack") => self
                .broker
                .post_json("/v1/agent/ack-binding", Some(session.bearer), &body)
                .await
                .map_err(broker_error),
            ("POST", "/v1/master/hosted-signer/prepare") => {
                let request: hosted_signer::HostedSignerApproval = decode(body)?;
                self.broker
                    .post_json("/v1/hosted/signer/prepare", Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            ("POST", "/v1/master/hosted-signer/build") => {
                let request: hosted_signer::HostedSignerBuildRequest = decode(body)?;
                self.broker
                    .post_json("/v1/hosted/signer/build", Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            ("POST", "/v1/master/hosted-signer/submit") => {
                let request: SubmitAcceptUserOpRequest = decode(body)?;
                self.broker
                    .post_json("/v1/accept/submit", Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            ("GET", "/v1/presets") => self
                .broker
                .get_json(path, Some(session.bearer))
                .await
                .map_err(broker_error),
            ("POST", "/v1/master/gateway") => {
                let request: hosted_gateway::HostedGatewayRequest = decode(body)?;
                self.broker
                    .post_json(path, Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            ("POST", "/v1/accept/build") => {
                let request_id = text(&body, "request_id")?;
                let binding = self
                    .broker
                    .pending_bindings(session.bearer)
                    .await
                    .map_err(broker_error)?
                    .into_iter()
                    .find(|binding| binding.request_id == request_id)
                    .ok_or_else(|| invalid("pairing request expired or was already accepted"))?;
                if norm(&binding.operator_omni) != norm(session.operator_omni) {
                    return Err(invalid("pairing belongs to another account"));
                }
                let services: Vec<String> = decode(
                    body.get("services")
                        .cloned()
                        .ok_or_else(|| invalid("services missing"))?,
                )?;
                let request = BuildAcceptUserOpRequest {
                    operator_omni: normalize_omni_0x(session.operator_omni),
                    actor_omni: binding.child_omni.clone(),
                    device_key_hash: binding.device_key_hash.clone(),
                    agent_pop_sig: binding.pop_sig,
                    link_code_redemption: String::new(),
                    services: services.clone(),
                    read_only: body
                        .get("read_only")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| invalid("read_only missing"))?,
                    max_per_call: text(&body, "max_per_call")?.into(),
                    max_per_period: text(&body, "max_per_period")?.into(),
                    max_total: text(&body, "max_total")?.into(),
                    period_seconds: decode(
                        body.get("period_seconds")
                            .cloned()
                            .ok_or_else(|| invalid("period_seconds missing"))?,
                    )?,
                    is_device: body
                        .get("is_device")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                };
                let build: BuildAcceptUserOpResponse = self
                    .broker
                    .post_json(path, Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)?;
                self.pending.borrow_mut().insert(
                    operation_key(&build.user_op)?,
                    PendingMutation {
                        manifest: BindingManifestEntry {
                            actor_omni: binding.child_omni,
                            device_key_hash: binding.device_key_hash,
                            label: binding.label,
                            kind: if request.is_device {
                                "device"
                            } else {
                                "delegate"
                            }
                            .into(),
                            granted_service_names: services,
                            updated_at: session.now_unix_seconds,
                            ..Default::default()
                        },
                        request_id: Some(request_id.into()),
                        operator: norm(session.operator_omni),
                        route: "/v1/accept/submit".into(),
                        receipt: None,
                        submitted: false,
                    },
                );
                encode(build)
            }
            ("POST", "/v1/scope/build") => {
                let actor = text(&body, "actor_omni")?;
                let fleet = self.fleet(session).await?;
                let entry = fleet
                    .devices
                    .iter()
                    .find(|entry| {
                        norm(&entry.device.actor_omni) == norm(actor)
                            && !entry.device.revoked
                            && entry.device.tier != 1
                    })
                    .ok_or_else(|| invalid("active actor not found"))?;
                let services: Vec<String> = decode(
                    body.get("services")
                        .cloned()
                        .ok_or_else(|| invalid("services missing"))?,
                )?;
                let preserved: Vec<String> = decode(
                    body.get("preserve_service_ids")
                        .cloned()
                        .unwrap_or(json!([])),
                )?;
                let request = BuildScopeUserOpRequest {
                    operator_omni: normalize_omni_0x(session.operator_omni),
                    actor_omni: actor.into(),
                    services: services.clone(),
                    preserve_service_ids: preserved,
                    read_only: body
                        .get("read_only")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| invalid("read_only missing"))?,
                    max_per_call: entry.scope.per_tx.clone(),
                    max_per_period: entry.scope.period_cap.clone(),
                    max_total: entry.scope.max_total.clone(),
                    period_seconds: entry.scope.period_seconds,
                };
                let build: BuildAcceptUserOpResponse = self
                    .broker
                    .post_json(path, Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)?;
                let (manifest, _) = self
                    .read_config::<BindingManifest>(session, BINDING_MANIFEST_SERVICE)
                    .await?;
                let mut row = manifest
                    .bindings
                    .into_iter()
                    .find(|row| norm(&row.actor_omni) == norm(actor))
                    .unwrap_or_else(|| BindingManifestEntry {
                        actor_omni: actor.into(),
                        device_key_hash: entry.device.device_key_hash.clone(),
                        ..Default::default()
                    });
                let mut names = services;
                names.extend(
                    row.granted_service_names
                        .iter()
                        .filter(|name| request.preserve_service_ids.contains(&service_hash(name)))
                        .cloned(),
                );
                names.sort();
                names.dedup();
                row.device_key_hash = entry.device.device_key_hash.clone();
                row.granted_service_names = names;
                row.updated_at = session.now_unix_seconds;
                self.pending.borrow_mut().insert(
                    operation_key(&build.user_op)?,
                    PendingMutation {
                        manifest: row,
                        request_id: None,
                        operator: norm(session.operator_omni),
                        route: "/v1/scope/submit".into(),
                        receipt: None,
                        submitted: false,
                    },
                );
                encode(build)
            }
            ("POST", "/v1/accept/submit" | "/v1/scope/submit") => {
                let request: SubmitAcceptUserOpRequest = decode(body)?;
                let key = operation_key(&request.user_op)?;
                let mutation = self.pending.borrow().get(&key).cloned().ok_or_else(|| {
                    invalid("rebuild the approval in this session before submitting")
                })?;
                if mutation.operator != norm(session.operator_omni) || mutation.route != path {
                    return Err(invalid("approval belongs to another session or operation"));
                }
                let result = if let Some(receipt) = mutation
                    .receipt
                    .clone()
                    .filter(|receipt| receipt.pending != Some(true))
                {
                    receipt
                } else if mutation.submitted {
                    self.broker
                        .post_json(
                            "/v1/accept/receipt",
                            Some(session.bearer),
                            &console_apps::AcceptReceiptRequest {
                                user_op: request.user_op.clone(),
                                context_docs: Vec::new(),
                            },
                        )
                        .await
                        .map_err(broker_error)?
                } else {
                    if let Some(pending) = self.pending.borrow_mut().get_mut(&key) {
                        pending.submitted = true;
                    }
                    match self
                        .broker
                        .post_json::<_, SubmitAcceptUserOpResponse>(
                            path,
                            Some(session.bearer),
                            &request,
                        )
                        .await
                    {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            if matches!(
                                &error,
                                crate::broker::BrokerError::Rejected {
                                    status: 400 | 401 | 403 | 404 | 422,
                                    ..
                                }
                            ) {
                                if let Some(pending) = self.pending.borrow_mut().get_mut(&key) {
                                    pending.submitted = false;
                                }
                            }
                            return Err(broker_error(error));
                        }
                    }
                };
                if let Some(pending) = self.pending.borrow_mut().get_mut(&key) {
                    pending.receipt = Some(result.clone());
                }
                if result.pending == Some(true) {
                    return encode(result);
                }
                if !result.ok || result.tx_hash.is_empty() {
                    return Err(invalid("transaction was not confirmed"));
                }
                self.persist_mutation(session, &mutation)
                    .await
                    .map_err(|error| {
                        invalid(format!(
                            "chain transaction confirmed; metadata save failed: {error}"
                        ))
                    })?;
                self.pending.borrow_mut().remove(&key);
                encode(result)
            }
            ("POST", "/v1/revoke/build") => {
                let request = BuildRevokeUserOpRequest {
                    operator_omni: normalize_omni_0x(session.operator_omni),
                    device_key_hashes: decode(
                        body.get("device_key_hashes")
                            .cloned()
                            .ok_or_else(|| invalid("device_key_hashes missing"))?,
                    )?,
                };
                self.broker
                    .post_json(path, Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            ("POST", "/v1/accept/receipt") => {
                let request: console_apps::AcceptReceiptRequest = decode(body)?;
                self.broker
                    .post_json(path, Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            ("POST", "/v1/revoke/submit") => {
                let request: SubmitAcceptUserOpRequest = decode(body)?;
                self.broker
                    .post_json(path, Some(session.bearer), &request)
                    .await
                    .map_err(broker_error)
            }
            _ if method == "POST"
                && path.starts_with("/v1/actors/")
                && path.ends_with("/revoke") =>
            {
                let actor = path
                    .trim_start_matches("/v1/actors/")
                    .trim_end_matches("/revoke");
                if body.get("onchain").and_then(Value::as_bool) != Some(true) {
                    return Err(invalid(
                        "approve the revoke with your account passkey first",
                    ));
                }
                let fleet = self.fleet(session).await?;
                let target = fleet
                    .devices
                    .iter()
                    .find(|entry| norm(&entry.device.actor_omni) == norm(actor))
                    .ok_or_else(|| invalid("actor does not belong to this account"))?;
                if !target.device.revoked {
                    return Err(invalid("device remains active on chain"));
                }
                Ok(json!({"ok":true}))
            }
            _ if method == "GET" && path.starts_with("/v1/actors/") => {
                let actor_id = path.trim_start_matches("/v1/actors/");
                let actor = self
                    .actors(session)
                    .await?
                    .into_iter()
                    .find(|actor| actor.id == actor_id)
                    .ok_or_else(|| invalid("actor not found"))?;
                encode(actor)
            }
            _ => Err(invalid(format!(
                "console route has no handler: {method} {path}"
            ))),
        }
    }
}

pub fn fleet_actors(
    fleet: &ConsoleFleet,
    manifest: &BindingManifest,
    taxonomy: &MemoryTaxonomy,
    channels: &ChannelRegistry,
) -> Vec<ApiActor> {
    let mut actors = Vec::new();
    let mut seen = HashSet::new();
    for entry in fleet.devices.iter().filter(|entry| !entry.device.revoked) {
        let device = &entry.device;
        let master = device.tier == 1;
        if !seen.insert(norm(&device.actor_omni)) {
            continue;
        }
        let binding = manifest
            .bindings
            .iter()
            .find(|row| norm(&row.actor_omni) == norm(&device.actor_omni));
        let mut names = Vec::new();
        if let Some(binding) = binding {
            names.extend(binding.granted_service_names.clone());
        }
        for category in &taxonomy.categories {
            for prefix in ["knowledge", "proposal"] {
                names.push(format!("{prefix}:{}", category.ns));
            }
        }
        for channel in &channels.channels {
            for prefix in ["channel-pub", "channel-sub"] {
                names.push(format!("{prefix}:{}", channel.id));
            }
        }
        names.extend(TOOL_CLASSES.iter().map(|class| format!("tool:{class}")));
        names.sort();
        names.dedup();
        let services: Vec<String> = names
            .into_iter()
            .filter(|name| entry.scope.service_ids.contains(&service_hash(name)))
            .collect();
        let mut scope: HashMap<String, ApiScopeBits> = HashMap::new();
        for service in &services {
            if let Some(ns) = service.strip_prefix("knowledge:") {
                scope.entry(ns.into()).or_default().read = true;
            }
            if let Some(ns) = service.strip_prefix("proposal:") {
                scope.entry(ns.into()).or_default().write = true;
            }
        }
        let memory_ids: HashSet<String> = services
            .iter()
            .filter(|service| service.starts_with("knowledge:") || service.starts_with("proposal:"))
            .map(|service| service_hash(service))
            .collect();
        let unknown: Vec<String> = entry
            .scope
            .service_ids
            .iter()
            .filter(|hash| !memory_ids.contains(*hash))
            .cloned()
            .collect();
        let channel_ids = services
            .iter()
            .filter(|service| {
                service.starts_with("channel-pub:") || service.starts_with("channel-sub:")
            })
            .map(|service| service_hash(service))
            .collect();
        let capability_ids = services
            .iter()
            .filter(|service| service.starts_with("tool:") || service.starts_with("plugin:"))
            .map(|service| service_hash(service))
            .collect();
        let label = if master {
            "Master".into()
        } else {
            binding
                .map(|row| row.label.clone())
                .filter(|label| !label.is_empty())
                .unwrap_or_else(|| device.actor_omni.clone())
        };
        actors.push(ApiActor {
            id: if master {
                "master".into()
            } else {
                device.actor_omni.clone()
            },
            omni: device.actor_omni.clone(),
            omni_hex: device.actor_omni.clone(),
            label: label.clone(),
            role: if master { "master" } else { "agent" }.into(),
            parent: (!master).then(|| "master".into()),
            derivation: if master {
                "/".into()
            } else {
                format!("//{label}")
            },
            device: if master { "passkey" } else { "bound device" }.into(),
            device_pubkey: device.device_key_hash.clone(),
            last_active: String::new(),
            status: "ok".into(),
            vendor: String::new(),
            k11: master,
            device_key_hash: Some(device.device_key_hash.clone()),
            kind: match device.tier {
                2 => Some("delegate".into()),
                3 => Some("device".into()),
                _ => None,
            },
            scope: (!master).then_some(scope),
            scope_unknown_service_ids: (!master).then_some(unknown),
            scope_channel_service_ids: (!master).then_some(channel_ids),
            scope_capability_service_ids: (!master).then_some(capability_ids),
            payment_cap: None,
            time_window: None,
            services: (!master).then_some(services),
            account_address: master.then(|| fleet.account.clone()),
            account_type: Some(if master { "p256account" } else { "device" }.into()),
            preset_id: binding.and_then(|row| row.preset_id.clone()),
            memory_ns: binding.and_then(|row| row.memory_ns.clone()),
            runtime: binding.and_then(|row| row.runtime.clone()),
        });
    }
    actors.sort_by_key(|actor| (actor.role != "master", actor.label.clone()));
    actors
}

pub fn pending_binding_to_request(b: &serde_json::Value) -> serde_json::Value {
    let field = |k: &str| {
        b.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let request_id = field("request_id");
    let label = field("label");
    let device_pubkey = field("device_pubkey");
    let device_key_hash = field("device_key_hash");
    let pop_sig = field("pop_sig");
    let requested_scope = field("requested_scope");
    let pairing_code = field("pairing_code");
    // created_at: broker unix seconds (the agent's /request). The UI formats it.
    let created_at = b
        .get("created_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    // #224 expires_at: broker unix seconds the request expires — the SAME value the
    // agent's `--request-pairing` prints. The UI renders a live countdown so a stale
    // card (already past expiry / an old start) is visibly the one to refuse.
    let expires_at = b
        .get("expires_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    // char-safe head…tail elision for long hex handles.
    let short = |v: &str| -> String {
        let n = v.chars().count();
        if n > 18 {
            let head: String = v.chars().take(10).collect();
            let tail: String = v.chars().skip(n - 6).collect();
            format!("{head}…{tail}")
        } else {
            v.to_string()
        }
    };
    // requested_scope: comma-separated "<service>:<ns>" tokens → RequestedPerm[].
    let requested: Vec<serde_json::Value> = requested_scope
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|tok| {
            let (cap, ns) = match tok.split_once(':') {
                Some((c, n)) => (
                    c.to_string(),
                    vec![serde_json::Value::String(n.to_string())],
                ),
                None => (tok.to_string(), Vec::new()),
            };
            serde_json::json!({ "cap": cap, "ns": ns, "reason": "requested at pairing" })
        })
        .collect();
    // #408 D6 — a claim whose scope is ONLY channel-pub/sub grants is a channel-
    // endpoint DEVICE bind (same predicate the broker's poll uses for the D9
    // no-spawn). The web app routes device claims to the channel section and
    // sandbox-delegate claims to the pairing section on this flag.
    let is_device = agentkeys_protocol::scope_is_device_only(&requested_scope);
    // The declared column is self-reported placeholder context either way
    // (never a basis for approval) — but the sandbox wording is WRONG for a
    // device claim, so vary it by the derived kind.
    let (device_lbl, machine_lbl, runtime_lbl) = if is_device {
        (
            "channel-endpoint device (K10)",
            "device",
            "none — channel endpoint (no runtime)",
        )
    } else {
        ("sandbox device (K10)", "aiosandbox", "hermes")
    };
    serde_json::json!({
        "id": request_id,
        "agent": label,
        "vendor": if is_device { "device" } else { "agent" },
        "device": device_lbl,
        "machine": machine_lbl,
        "runtime": runtime_lbl,
        "isDevice": is_device,
        "dpub": short(&device_pubkey),
        "dpubFull": device_pubkey,
        // #224: the operator cross-checks `deviceKeyHash` (+ `dpubFull`, both printed
        // by the agent's `--request-pairing`) before `accept · Touch ID`. `id` is the
        // full request_id (the master-side handle). `pairCode` is now the agent's REAL
        // one-time code (the master claimed by it) — shown so the operator can confirm
        // it matches the code on the agent device.
        "deviceKeyHash": device_key_hash.clone(),
        "deviceKeyHashShort": short(&device_key_hash),
        "pairCode": pairing_code,
        "derivation": format!("//{label}"),
        "requested": requested,
        "requestedAt": created_at,
        "expiresAt": expires_at,
        "attestation": format!("PoP verified · {}", short(&pop_sig)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmed_grants_preserve_concurrent_readable_metadata() {
        let mut manifest = BindingManifest::default();
        manifest.upsert(BindingManifestEntry {
            actor_omni: "0xab".into(),
            device_key_hash: "0xold".into(),
            label: "Renamed".into(),
            kind: "delegate".into(),
            preset_id: Some("new-preset".into()),
            granted_service_names: vec!["tool:web".into(), "knowledge:removed".into()],
            ..Default::default()
        });
        let requested = BindingManifestEntry {
            actor_omni: "ab".into(),
            label: "Old label".into(),
            preset_id: Some("old-preset".into()),
            granted_service_names: vec!["knowledge:recipes".into()],
            updated_at: 123,
            ..Default::default()
        };
        let chain = ConsoleFleetEntry {
            device: ConsoleChainDevice {
                actor_omni: "0xab".into(),
                device_key_hash: "0xnew".into(),
                operator_omni: "0xowner".into(),
                tier: 2,
                revoked: false,
            },
            scope: ConsoleChainScope {
                service_ids: vec![service_hash("tool:web"), service_hash("knowledge:recipes")],
                ..Default::default()
            },
        };
        merge_confirmed_manifest(&mut manifest, &requested, &chain);
        let row = &manifest.bindings[0];
        assert_eq!(row.label, "Renamed");
        assert_eq!(row.preset_id.as_deref(), Some("new-preset"));
        assert_eq!(row.device_key_hash, "0xnew");
        assert_eq!(
            row.granted_service_names,
            vec!["knowledge:recipes", "tool:web"]
        );
    }
}
